// Package secret is the domain layer: it turns HTTP-shaped requests into
// storage operations, and owns the rules about what may be revealed when.
package secret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fortionnet/onetime/internal/blob"
	"github.com/fortionnet/onetime/internal/config"
	"github.com/fortionnet/onetime/internal/crypto"
	"github.com/fortionnet/onetime/internal/store"
)

// Service orchestrates the secret lifecycle.
type Service struct {
	cfg     *config.Config
	store   *store.Redis
	blobs   *blob.Store
	deriver *crypto.Deriver
	now     func() time.Time
	events  Events
}

// Events lets the caller observe outcomes for metrics without this package
// depending on a metrics library.
type Events struct {
	Created  func(kind, source string, size int64)
	Revealed func(kind, result string)
	Burned   func(by string)
	PassFail func()
}

// New builds the service.
func New(cfg *config.Config, st *store.Redis, blobs *blob.Store, deriver *crypto.Deriver) *Service {
	return &Service{cfg: cfg, store: st, blobs: blobs, deriver: deriver, now: time.Now}
}

// SetClock overrides the clock, for tests.
func (s *Service) SetClock(fn func() time.Time) { s.now = fn }

// SetEvents registers metric callbacks.
func (s *Service) SetEvents(e Events) { s.events = e }

// Created is the result of storing a new secret. It carries the two links the
// caller needs and nothing else: the plaintext is never echoed back.
type Created struct {
	SecretURL        string
	ReceiptURL       string
	Kind             string
	Filename         string
	Size             int64
	HasPassphrase    bool
	ExpiresAt        time.Time
	ReceiptExpiresAt time.Time
	TTLDays          int
}

// CreateTextRequest describes a new text secret.
type CreateTextRequest struct {
	Text       []byte
	Passphrase crypto.Passphrase
	TTLDays    int
	Source     string // web | api | generate, for metrics only
}

// CreateText stores a text secret.
func (s *Service) CreateText(ctx context.Context, req CreateTextRequest) (*Created, error) {
	if s.cfg.ReadOnly {
		return nil, ErrReadOnly
	}
	if len(req.Text) == 0 {
		return nil, ErrEmpty
	}
	if int64(len(req.Text)) > s.cfg.MaxTextBytes {
		return nil, ErrTooLarge
	}

	b, err := s.newBuild(req.TTLDays, req.Passphrase)
	if err != nil {
		return nil, err
	}

	size := int64(len(req.Text))
	if size <= s.cfg.MaxTextInlineBytes {
		sealed, err := crypto.SealBytes(b.dek, req.Text, b.payloadAAD())
		if err != nil {
			return nil, err
		}
		b.secret.Payload = sealed
		b.secret.EncSize = int64(len(sealed))
	} else {
		// Long text takes the same path as a file so that there is exactly one
		// streaming code path to get right and to test.
		if err := s.writeBlob(ctx, b, func(w io.Writer) error {
			_, err := w.Write(req.Text)
			return err
		}); err != nil {
			return nil, err
		}
	}
	b.secret.PlainSize = size
	b.receipt.PlainSize = size

	if err := s.commit(ctx, b); err != nil {
		return nil, err
	}
	s.emitCreated(store.KindText, req.Source, size)
	return b.created(s.cfg.BaseURL), nil
}

// CreateFileRequest describes a new file secret.
type CreateFileRequest struct {
	Filename   string
	Passphrase crypto.Passphrase
	TTLDays    int
	Source     string
	// Declared is the client-declared length, used to reject an oversized
	// upload before reading any of it.
	Declared int64
}

// CreateFile stores a file secret, streaming it to the volume.
//
// Nothing is buffered whole: a 50 MB upload costs a 64 KiB buffer, and the
// limit is enforced by the reader the caller wraps around the request body.
func (s *Service) CreateFile(ctx context.Context, req CreateFileRequest, body io.Reader) (*Created, error) {
	if s.cfg.ReadOnly {
		return nil, ErrReadOnly
	}
	if !s.cfg.EnableFiles {
		return nil, ErrFilesDisabled
	}
	if req.Declared > s.cfg.MaxFileBytes {
		return nil, ErrTooLarge
	}
	if err := s.checkSpace(); err != nil {
		return nil, err
	}

	b, err := s.newBuild(req.TTLDays, req.Passphrase)
	if err != nil {
		return nil, err
	}
	b.secret.Kind = store.KindFile
	b.receipt.Kind = store.KindFile

	name := sanitizeFilename(req.Filename)
	if name != "" {
		meta, err := json.Marshal(fileMeta{Filename: name})
		if err != nil {
			return nil, fmt.Errorf("secret: marshal file metadata: %w", err)
		}
		sealed, err := crypto.SealSmall(b.dek, meta, b.metaAAD())
		if err != nil {
			return nil, err
		}
		b.secret.MetaCT = sealed
		b.filename = name
	}

	var written int64
	if err := s.writeBlob(ctx, b, func(w io.Writer) error {
		n, err := io.Copy(w, body)
		written = n
		return err
	}); err != nil {
		return nil, err
	}
	if written == 0 {
		_, _ = s.blobs.Delete(b.secret.Blob)
		return nil, ErrEmpty
	}
	b.secret.PlainSize = written
	b.receipt.PlainSize = written

	if err := s.commit(ctx, b); err != nil {
		_, _ = s.blobs.Delete(b.secret.Blob)
		return nil, err
	}
	s.emitCreated(store.KindFile, req.Source, written)
	return b.created(s.cfg.BaseURL), nil
}

// Info is what a peek reports: enough for the recipient page to describe what
// is waiting, without consuming anything.
//
// The filename is deliberately absent. Returning it would mean unwrapping the
// data key on every page load, which turns a cheap lookup into an Argon2id
// invocation an attacker can trigger at will.
type Info struct {
	Kind          string
	State         string
	HasPassphrase bool
	Size          int64
	ExpiresAt     time.Time
}

// Peek reports a secret's state without consuming it.
func (s *Service) Peek(ctx context.Context, keyStr string) (*Info, error) {
	key, sec, err := s.load(ctx, keyStr)
	if err != nil {
		return nil, err
	}
	if err := stateError(sec.State); err != nil {
		return nil, err
	}
	if sec.ReceiptID != "" {
		if err := s.store.MarkPeeked(ctx, sec.ReceiptID, s.now()); err != nil {
			// The sender losing a "delivered" timestamp is not worth failing
			// the recipient's page load over.
			_ = err
		}
	}
	_ = key
	return &Info{
		Kind:          sec.Kind,
		State:         sec.State,
		HasPassphrase: sec.HasPass,
		Size:          sec.PlainSize,
		ExpiresAt:     sec.Expires,
	}, nil
}

// Revealed is a consumed secret. Exactly one of Text or the file fields is set.
type Revealed struct {
	Kind       string
	Text       crypto.Plaintext
	Filename   string
	Size       int64
	Ticket     string
	TicketTTL  time.Duration
	RevealedAt time.Time
}

// RevealRequest describes an attempt to read a secret.
type RevealRequest struct {
	Key        string
	Passphrase crypto.Passphrase
	// Confirm must be true. It is the explicit human action that separates a
	// person clicking "show me" from a chat client fetching a link preview.
	Confirm bool
}

// Reveal consumes a secret and returns its contents.
//
// The ordering here carries the security of the whole feature. Everything that
// can fail — wrong state, missing confirmation, wrong passphrase — is checked
// and returned before the claim, so none of those paths burns the secret. The
// claim itself is the last thing that happens, and it is atomic, so concurrent
// reveals produce one winner and no partial states.
func (s *Service) Reveal(ctx context.Context, req RevealRequest) (*Revealed, error) {
	key, sec, err := s.load(ctx, req.Key)
	if err != nil {
		s.emitRevealed("", "not_found")
		return nil, err
	}
	if err := stateError(sec.State); err != nil {
		s.emitRevealed(sec.Kind, "already")
		return nil, err
	}
	if !req.Confirm {
		return nil, ErrConfirmationRequired
	}
	if sec.HasPass && req.Passphrase.Empty() {
		return nil, ErrPassphraseRequired
	}

	sid := key.SecretID()
	if sec.HasPass {
		fails, err := s.store.PassFailCount(ctx, sid)
		if err != nil {
			return nil, err
		}
		if fails >= s.cfg.PassphraseWindowFails {
			return nil, ErrTooManyAttempts
		}
	}

	params := s.deriver.Params()
	if sec.KDFParams != "" {
		if p, err := crypto.ParseKDFParams(sec.KDFParams); err == nil {
			params = p
		}
	}
	kek, err := s.deriver.KEK(sec.KeyID, key, req.Passphrase, sec.Salt, params)
	if err != nil {
		if errors.Is(err, crypto.ErrUnknownKeyID) {
			// The master key this record was written under is gone from the
			// ring. Nothing can recover it, so present it as a dead link rather
			// than a server error, and let the metric raise the alarm.
			s.emitRevealed(sec.Kind, "unknown_key_id")
			return nil, ErrNotFound
		}
		return nil, err
	}

	dek, err := crypto.UnwrapDEK(kek, sec.WrappedDEK, crypto.AAD("wrap", sid, sec.KeyID))
	if err != nil {
		return nil, s.recordPassphraseFailure(ctx, sid, sec)
	}

	claim, err := s.store.ClaimSecret(ctx, sid, sec.ReceiptID, store.StateConsumed, s.now(), s.cfg.TombstoneTTL)
	if err != nil {
		return nil, err
	}
	if !claim.Found {
		s.emitRevealed(sec.Kind, "not_found")
		return nil, ErrNotFound
	}
	if !claim.Won {
		// Another request got here first in the moment we spent deriving keys.
		s.emitRevealed(sec.Kind, "already")
		return nil, stateOrRevealed(claim.State)
	}

	s.emitRevealed(claim.Kind, "ok")
	if claim.Kind == store.KindFile {
		return s.fileReveal(ctx, sid, sec.KeyID, dek, claim)
	}
	return s.textReveal(sid, sec.KeyID, dek, claim)
}

func (s *Service) textReveal(sid, keyID string, dek crypto.DEK, claim *store.Claim) (*Revealed, error) {
	aad := crypto.AAD("payload", sid, keyID)
	var sealed []byte
	if len(claim.Payload) > 0 {
		sealed = claim.Payload
	} else if claim.Blob != "" {
		f, err := s.blobs.Open(claim.Blob)
		if err != nil {
			return nil, fmt.Errorf("secret: open payload: %w", err)
		}
		defer func() { _ = f.Close() }()
		sealed, err = io.ReadAll(io.LimitReader(f, s.cfg.MaxTextBytes+crypto.EncryptedSize(s.cfg.MaxTextBytes)))
		if err != nil {
			return nil, fmt.Errorf("secret: read payload: %w", err)
		}
		_, _ = s.blobs.Delete(claim.Blob)
	}
	text, err := crypto.OpenBytes(dek, sealed, aad)
	if err != nil {
		return nil, err
	}
	return &Revealed{
		Kind:       store.KindText,
		Text:       text,
		Size:       int64(len(text)),
		RevealedAt: s.now(),
	}, nil
}

func (s *Service) fileReveal(ctx context.Context, sid, keyID string, dek crypto.DEK, claim *store.Claim) (*Revealed, error) {
	name := ""
	if len(claim.MetaCT) > 0 {
		raw, err := crypto.OpenSmall(dek, claim.MetaCT, crypto.AAD("meta", sid, keyID))
		if err == nil {
			var meta fileMeta
			if json.Unmarshal(raw, &meta) == nil {
				name = meta.Filename
			}
		}
	}

	ticket, err := crypto.NewTicket(dek)
	if err != nil {
		return nil, err
	}
	var nameCT []byte
	if name != "" {
		nameCT, err = crypto.SealSmall(dek, []byte(name), ticketAAD(ticket.ID()))
		if err != nil {
			return nil, err
		}
	}
	rec := &store.Ticket{
		Blob:       claim.Blob,
		FilenameCT: nameCT,
		// The download path has no secret record left to derive this from, so
		// the association carries in the ticket instead.
		PayloadAAD: crypto.AAD("payload", sid, keyID),
		PlainSize:  claim.PlainSize,
	}
	if err := s.store.PutTicket(ctx, ticket.ID(), rec, s.cfg.DownloadTicketTTL); err != nil {
		return nil, err
	}
	// The secret is gone, so the file's only remaining purpose is this ticket.
	// Pull its collection deadline in to just past the ticket's life.
	deadline := s.now().Add(s.cfg.DownloadTicketTTL + 30*time.Second)
	if err := s.store.AdvanceBlobDeadline(ctx, claim.Blob, deadline); err != nil {
		return nil, err
	}

	return &Revealed{
		Kind:       store.KindFile,
		Filename:   name,
		Size:       claim.PlainSize,
		Ticket:     ticket.Encode(),
		TicketTTL:  s.cfg.DownloadTicketTTL,
		RevealedAt: s.now(),
	}, nil
}

// Download is an authorised file transfer in progress.
type Download struct {
	Filename string
	Size     int64
	Body     io.ReadCloser
	// Done must be called once the transfer finishes, successfully or not.
	Done func(completed bool)
}

// OpenDownload validates a ticket and returns a decrypting stream.
func (s *Service) OpenDownload(ctx context.Context, ticketStr string) (*Download, error) {
	ticket, err := crypto.ParseTicket(ticketStr)
	if err != nil {
		return nil, ErrNotFound
	}
	tid := ticket.ID()
	rec, err := s.store.ClaimTicket(ctx, tid, s.cfg.DownloadAttempts)
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrTicketExhausted) {
		return nil, ErrTicketExpired
	}
	if err != nil {
		return nil, err
	}

	f, err := s.blobs.Open(rec.Blob)
	if errors.Is(err, blob.ErrNotFound) {
		return nil, ErrTicketExpired
	}
	if err != nil {
		return nil, err
	}

	name := ""
	if len(rec.FilenameCT) > 0 {
		if raw, err := crypto.OpenSmall(ticket.DEK, rec.FilenameCT, ticketAAD(tid)); err == nil {
			name = string(raw)
		}
	}

	reader, err := crypto.NewStreamReader(ticket.DEK, f, rec.PayloadAAD)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Download{
		Filename: name,
		Size:     rec.PlainSize,
		Body:     readCloser{Reader: reader, closer: f},
		Done: func(completed bool) {
			if !completed {
				return
			}
			// Only remove the file once a transfer actually finished, so a
			// dropped connection can still be retried within the ticket's life.
			if freed, err := s.blobs.Delete(rec.Blob); err == nil {
				_ = s.store.AddDiskUsage(ctx, -freed)
				_ = s.store.ForgetBlob(ctx, rec.Blob)
			}
			_ = s.store.DeleteTicket(ctx, tid)
		},
	}, nil
}

// Status is what the sender sees on their receipt page.
type Status struct {
	State            string
	Kind             string
	Size             int64
	HasPassphrase    bool
	CreatedAt        time.Time
	SecretExpiresAt  time.Time
	PeekedAt         time.Time
	ConsumedAt       time.Time
	PassphraseFails  int
	ReceiptExpiresAt time.Time
}

// ReceiptStatus reports what happened to a secret, for its sender.
func (s *Service) ReceiptStatus(ctx context.Context, metaKey string) (*Status, error) {
	rec, err := s.loadReceipt(ctx, metaKey)
	if err != nil {
		return nil, err
	}
	return receiptStatus(rec, s.now()), nil
}

// Burn lets the sender invalidate a secret before anyone reads it.
//
// The sender holds the receipt key, which identifies the secret but cannot
// decrypt it — that needs the fragment key, which only the recipient's link
// carries. So this destroys the secret without ever showing it to the person
// destroying it.
func (s *Service) Burn(ctx context.Context, metaKey string) (*Status, error) {
	key, err := crypto.ParseKey(metaKey)
	if err != nil {
		return nil, ErrNotFound
	}
	mid := key.ReceiptID()
	rec, err := s.store.LoadReceipt(ctx, mid)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if rec.State == store.StateNew {
		claim, err := s.store.ClaimSecret(ctx, rec.SecretID, mid, store.StateBurned, s.now(), s.cfg.TombstoneTTL)
		if err != nil {
			return nil, err
		}
		if claim.Won {
			if claim.Blob != "" {
				if freed, err := s.blobs.Delete(claim.Blob); err == nil {
					_ = s.store.AddDiskUsage(ctx, -freed)
					_ = s.store.ForgetBlob(ctx, claim.Blob)
				}
			}
			if s.events.Burned != nil {
				s.events.Burned("sender")
			}
		}
		// Whether or not the claim won, the receipt is the source of truth for
		// what the sender is shown next.
		rec, err = s.store.LoadReceipt(ctx, mid)
		if err != nil {
			return nil, err
		}
	}
	return receiptStatus(rec, s.now()), nil
}

func (s *Service) load(ctx context.Context, keyStr string) (crypto.Key, *store.Secret, error) {
	key, err := crypto.ParseKey(strings.TrimSpace(keyStr))
	if err != nil {
		return crypto.Key{}, nil, ErrNotFound
	}
	sec, err := s.store.LoadSecret(ctx, key.SecretID())
	if errors.Is(err, store.ErrNotFound) {
		return crypto.Key{}, nil, ErrNotFound
	}
	if err != nil {
		return crypto.Key{}, nil, err
	}
	return key, sec, nil
}

func (s *Service) loadReceipt(ctx context.Context, metaKey string) (*store.Receipt, error) {
	key, err := crypto.ParseKey(strings.TrimSpace(metaKey))
	if err != nil {
		return nil, ErrNotFound
	}
	rec, err := s.store.LoadReceipt(ctx, key.ReceiptID())
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// recordPassphraseFailure notes a wrong guess and, once someone has clearly
// settled in to brute force the thing, destroys the secret rather than leaving
// it available for an unbounded number of further attempts.
func (s *Service) recordPassphraseFailure(ctx context.Context, sid string, sec *store.Secret) error {
	if s.events.PassFail != nil {
		s.events.PassFail()
	}
	_, total, err := s.store.PassFail(ctx, sid, sec.ReceiptID, s.cfg.PassphraseWindow, time.Until(sec.Expires))
	if err != nil {
		return err
	}
	if total >= s.cfg.PassphraseTotalFails {
		claim, err := s.store.ClaimSecret(ctx, sid, sec.ReceiptID, store.StateDestroyed, s.now(), s.cfg.TombstoneTTL)
		if err != nil {
			return err
		}
		if claim.Won {
			if claim.Blob != "" {
				if freed, delErr := s.blobs.Delete(claim.Blob); delErr == nil {
					_ = s.store.AddDiskUsage(ctx, -freed)
					_ = s.store.ForgetBlob(ctx, claim.Blob)
				}
			}
			if s.events.Burned != nil {
				s.events.Burned("bruteforce")
			}
		}
		return ErrDestroyed
	}
	return ErrBadPassphrase
}

func (s *Service) checkSpace() error {
	space, err := s.blobs.Space()
	if err != nil {
		return nil // an unreadable statfs is not a reason to refuse uploads
	}
	if space.UsedRatio()*100 >= float64(s.cfg.DiskHighWatermarkPct) {
		return ErrStorageFull
	}
	return nil
}

func receiptStatus(rec *store.Receipt, now time.Time) *Status {
	state := rec.State
	// Redis reclaims the secret at its deadline without telling the receipt,
	// so an untouched record past its expiry is reported as expired.
	if state == store.StateNew && !rec.SecretExpires.IsZero() && now.After(rec.SecretExpires) {
		state = "expired"
	}
	return &Status{
		State:            state,
		Kind:             rec.Kind,
		Size:             rec.PlainSize,
		HasPassphrase:    rec.HasPass,
		CreatedAt:        rec.Created,
		SecretExpiresAt:  rec.SecretExpires,
		PeekedAt:         rec.PeekedAt,
		ConsumedAt:       rec.ConsumedAt,
		PassphraseFails:  rec.PassFails,
		ReceiptExpiresAt: rec.Expires,
	}
}

func stateError(state string) error {
	switch state {
	case store.StateNew:
		return nil
	case store.StateBurned:
		return ErrBurned
	case store.StateDestroyed:
		return ErrDestroyed
	default:
		return ErrAlreadyRevealed
	}
}

func stateOrRevealed(state string) error {
	if err := stateError(state); err != nil {
		return err
	}
	return ErrAlreadyRevealed
}

func (s *Service) emitCreated(kind, source string, size int64) {
	if s.events.Created != nil {
		s.events.Created(kind, source, size)
	}
}

func (s *Service) emitRevealed(kind, result string) {
	if s.events.Revealed != nil {
		s.events.Revealed(kind, result)
	}
}

type fileMeta struct {
	Filename string `json:"filename"`
}

// ticketAAD binds a sealed filename to the ticket it belongs to. Both the seal
// and the open derive it from the ticket id alone, which is all the download
// path knows.
func ticketAAD(ticketID string) []byte { return crypto.AAD("ticket", ticketID, "") }

type readCloser struct {
	io.Reader
	closer io.Closer
}

func (r readCloser) Close() error { return r.closer.Close() }

// ChargeUpload records bytes against a client's daily allowance and reports the
// running total. Quota accounting lives here rather than in the HTTP layer so
// that the store stays private to this package.
func (s *Service) ChargeUpload(ctx context.Context, identity string, size int64) (int64, error) {
	if s.cfg.DailyBytesPerIP <= 0 {
		return 0, nil
	}
	return s.store.AddDailyBytes(ctx, identity, s.now().UTC().Format("20060102"), size)
}

// QuotaExceeded reports whether a client has already used its daily upload
// allowance. It is checked before accepting a file, so the refusal costs
// nothing rather than arriving after 50 MB has crossed the wire.
func (s *Service) QuotaExceeded(ctx context.Context, identity string) bool {
	if s.cfg.DailyBytesPerIP <= 0 {
		return false
	}
	total, err := s.ChargeUpload(ctx, identity, 0)
	if err != nil {
		return false // an unreachable counter must not block legitimate use
	}
	return total > s.cfg.DailyBytesPerIP
}
