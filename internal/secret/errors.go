package secret

import "errors"

// Domain errors. Each maps to one HTTP status and one stable machine-readable
// code, so the API, the web UI and the CLI documentation all describe the same
// failure in the same words.
var (
	// ErrNotFound means no record exists: a mistyped link, or one whose
	// retention already elapsed and was reclaimed by Redis.
	ErrNotFound = errors.New("secret: not found")

	// ErrAlreadyRevealed means someone opened it first. This is deliberately
	// distinguishable from ErrNotFound: with 256 bits of entropy in the link,
	// telling a visitor "someone already read this" gives an attacker nothing
	// and tells a legitimate recipient something they very much need to know.
	ErrAlreadyRevealed = errors.New("secret: already revealed")

	// ErrBurned means the sender cancelled it before anyone read it.
	ErrBurned = errors.New("secret: cancelled by the sender")

	// ErrDestroyed means it was destroyed after too many failed passphrase
	// attempts.
	ErrDestroyed = errors.New("secret: destroyed after repeated failed attempts")

	// ErrPassphraseRequired means the record is passphrase-protected and none
	// was supplied. Returning this does not consume the secret.
	ErrPassphraseRequired = errors.New("secret: passphrase required")

	// ErrBadPassphrase means the supplied passphrase did not unwrap the data
	// key. Returning this does not consume the secret.
	ErrBadPassphrase = errors.New("secret: incorrect passphrase")

	// ErrTooManyAttempts means passphrase guessing is being rate limited.
	ErrTooManyAttempts = errors.New("secret: too many failed attempts")

	// ErrConfirmationRequired means a reveal arrived without an explicit
	// confirmation. This is the gate that keeps link preview bots from burning
	// a secret before the recipient ever sees it.
	ErrConfirmationRequired = errors.New("secret: explicit confirmation required")

	// ErrTooLarge means the payload exceeded the configured limit.
	ErrTooLarge = errors.New("secret: payload too large")

	// ErrEmpty means nothing was supplied to share.
	ErrEmpty = errors.New("secret: nothing to share")

	// ErrStorageFull means the volume is too full to accept another file.
	// Text secrets keep working when this is returned.
	ErrStorageFull = errors.New("secret: storage full")

	// ErrFilesDisabled means file sharing is switched off.
	ErrFilesDisabled = errors.New("secret: file sharing is disabled")

	// ErrReadOnly means the service is accepting reads but not new secrets.
	ErrReadOnly = errors.New("secret: service is read-only")

	// ErrQuotaExceeded means the client exhausted its daily upload allowance.
	ErrQuotaExceeded = errors.New("secret: daily upload quota exceeded")

	// ErrTicketExpired means a download authorisation is no longer usable.
	ErrTicketExpired = errors.New("secret: download link expired")

	// ErrBadTTL means the requested retention was outside the allowed range.
	ErrBadTTL = errors.New("secret: retention out of range")
)
