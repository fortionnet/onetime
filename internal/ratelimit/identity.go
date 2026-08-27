// Package ratelimit throttles anonymous callers.
//
// The service has no accounts, so the client's network address is the only
// identity available. That makes getting it right load-bearing: read the wrong
// header and every caller shares one bucket, or worse, each caller can forge a
// fresh one.
package ratelimit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Identity derives a stable, non-reversible client identifier.
//
// Two details matter more than they look. The forwarded-for chain is walked
// from the right, skipping hops we run ourselves, because anything further left
// is attacker-controlled — taking the leftmost entry, as most examples do, lets
// a client mint unlimited identities with one header. And IPv6 is grouped by
// /64 rather than the full address, because a single subscriber is routinely
// handed a whole /64 and would otherwise have 2^64 buckets to cycle through.
//
// The result is an HMAC rather than the address itself, so a dump of Redis
// never reveals who has been using the service.
func Identity(r *http.Request, trusted []netip.Prefix, pepper []byte) string {
	addr := clientAddr(r, trusted)
	if !addr.IsValid() {
		return hash(pepper, []byte("unknown"))
	}
	if addr.Is4() || addr.Is4In6() {
		v4 := addr.Unmap()
		return hash(pepper, v4.AsSlice())
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return hash(pepper, addr.AsSlice())
	}
	return hash(pepper, prefix.Addr().AsSlice())
}

// ClientIP returns the caller's address for logging, already narrowed to the
// first hop we do not control.
func ClientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	return clientAddr(r, trusted)
}

func clientAddr(r *http.Request, trusted []netip.Prefix) netip.Addr {
	remote := parseAddr(r.RemoteAddr)
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remote
	}
	// Only trust the chain at all if the immediate peer is one of our proxies.
	if !isTrusted(remote, trusted) {
		return remote
	}
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr := parseAddr(strings.TrimSpace(hops[i]))
		if !addr.IsValid() {
			continue
		}
		if isTrusted(addr, trusted) {
			continue
		}
		return addr
	}
	return remote
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	if !addr.IsValid() {
		return false
	}
	if addr.IsLoopback() {
		return true
	}
	for _, p := range trusted {
		if p.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

func parseAddr(s string) netip.Addr {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func hash(pepper, material []byte) string {
	mac := hmac.New(sha256.New, pepper)
	mac.Write(material)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:22]
}

// ForwardedIgnored reports that a request carried a forwarding header which was
// discarded because the immediate peer is not a configured proxy.
//
// This is worth surfacing because the resulting misconfiguration is completely
// silent. Everything keeps working, but every request is attributed to the
// ingress controller's own address, so the per-address quota and the passphrase
// throttle become one bucket shared by every user at once — the first person to
// upload a few files locks out everybody else, and nothing in the logs says why.
func ForwardedIgnored(r *http.Request, trusted []netip.Prefix) bool {
	if r.Header.Get("X-Forwarded-For") == "" {
		return false
	}
	return !isTrusted(parseAddr(r.RemoteAddr), trusted)
}
