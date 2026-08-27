package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

func request(remote, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/secret", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

// TestForwardedChainIsWalkedFromTheRight pins the detail that makes per-IP
// limiting meaningful at all. Taking the leftmost entry, which is the usual
// advice, lets any client mint unlimited identities by sending the header
// themselves.
func TestForwardedChainIsWalkedFromTheRight(t *testing.T) {
	trusted := mustPrefixes(t, "10.0.0.0/8")

	got := ClientIP(request("10.0.0.5:1234", "1.2.3.4, 203.0.113.9, 10.0.0.7"), trusted)
	if got.String() != "203.0.113.9" {
		t.Fatalf("client address = %s, want 203.0.113.9 (the first untrusted hop from the right)", got)
	}

	// A spoofed header from an untrusted peer must be ignored entirely.
	got = ClientIP(request("198.51.100.20:1234", "1.2.3.4"), trusted)
	if got.String() != "198.51.100.20" {
		t.Fatalf("client address = %s, want the peer address when the header is untrusted", got)
	}
}

func TestSpoofedHeaderCannotMintIdentities(t *testing.T) {
	trusted := mustPrefixes(t, "10.0.0.0/8")
	pepper := []byte("pepper")

	base := Identity(request("198.51.100.20:1234", ""), trusted, pepper)
	for _, spoof := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3, 4.4.4.4"} {
		got := Identity(request("198.51.100.20:1234", spoof), trusted, pepper)
		if got != base {
			t.Fatalf("an untrusted peer changed its identity with X-Forwarded-For: %q", spoof)
		}
	}
}

// TestIPv6GroupsBySubnet covers the other way per-IP limiting is routinely
// defeated: a single subscriber is handed a whole /64, so counting full
// addresses would give one attacker 2^64 buckets.
func TestIPv6GroupsBySubnet(t *testing.T) {
	pepper := []byte("pepper")
	a := Identity(request("[2001:db8:1:2::1]:1234", ""), nil, pepper)
	b := Identity(request("[2001:db8:1:2::dead:beef]:1234", ""), nil, pepper)
	if a != b {
		t.Fatal("two addresses in the same /64 got different identities")
	}

	c := Identity(request("[2001:db8:1:3::1]:1234", ""), nil, pepper)
	if a == c {
		t.Fatal("addresses in different /64s share an identity")
	}
}

func TestIPv4IdentitiesAreDistinct(t *testing.T) {
	pepper := []byte("pepper")
	a := Identity(request("198.51.100.1:1", ""), nil, pepper)
	b := Identity(request("198.51.100.2:1", ""), nil, pepper)
	if a == b {
		t.Fatal("two different IPv4 addresses share an identity")
	}
}

// TestIdentityHidesTheAddress matters because these identifiers are written to
// Redis. A dump of the database must not reveal who has been using a service
// whose whole premise is not keeping records.
func TestIdentityHidesTheAddress(t *testing.T) {
	id := Identity(request("198.51.100.42:1234", ""), nil, []byte("pepper"))
	if id == "" {
		t.Fatal("Identity returned nothing")
	}
	for _, fragment := range []string{"198", "51.100", "42"} {
		if contains(id, fragment) {
			t.Fatalf("identity %q contains part of the address", id)
		}
	}
}

func TestDifferentPeppersGiveDifferentIdentities(t *testing.T) {
	r := request("198.51.100.42:1234", "")
	if Identity(r, nil, []byte("one")) == Identity(r, nil, []byte("two")) {
		t.Fatal("the pepper does not affect the identity; identities would be portable between deployments")
	}
}

func TestPolicyInterval(t *testing.T) {
	for _, tc := range []struct {
		perHour int
		want    time.Duration
	}{
		{3600, time.Second},
		{60, time.Minute},
		{0, 0},
	} {
		if got := (Policy{PerHour: tc.perHour}).Interval(); got != tc.want {
			t.Errorf("Policy{%d}.Interval() = %v, want %v", tc.perHour, got, tc.want)
		}
	}
}

func TestDefaultPoliciesCoverEveryAction(t *testing.T) {
	policies := DefaultPolicies()
	for _, action := range []Action{
		ActionCreateText, ActionCreateFile, ActionGenerate, ActionPeek,
		ActionReveal, ActionDownload, ActionReceipt, ActionBurn, ActionPage,
	} {
		p, ok := policies[action]
		if !ok {
			t.Errorf("no default policy for %q", action)
			continue
		}
		if p.PerHour <= 0 || p.Burst <= 0 {
			t.Errorf("policy for %q is not usable: %+v", action, p)
		}
	}
	// Uploading files must be tighter than posting text, or the service turns
	// into free hosting.
	if policies[ActionCreateFile].PerHour >= policies[ActionCreateText].PerHour {
		t.Error("file uploads are not limited more tightly than text secrets")
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		})()
}
