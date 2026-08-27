// Package store is the Redis persistence layer.
//
// Every Redis key in the system is built here and nowhere else. That is worth
// the indirection: the key names encode a security property (a record is
// addressed by a hash of the fragment key, never by the key itself), and
// scattering fmt.Sprintf calls across handlers is how that property quietly
// erodes.
package store

import "strconv"

const prefix = "ots:"

// SecretKey addresses a secret record. id is crypto.Key.SecretID().
func SecretKey(id string) string { return prefix + "s:" + id }

// ReceiptKey addresses a sender's receipt record.
func ReceiptKey(id string) string { return prefix + "m:" + id }

// TicketKey addresses a short-lived file download ticket.
func TicketKey(id string) string { return prefix + "dl:" + id }

// PassFailKey counts recent failed passphrase attempts within a rolling window.
func PassFailKey(id string) string { return prefix + "pf:" + id }

// PassFailTotalKey counts failed passphrase attempts over a secret's lifetime.
func PassFailTotalKey(id string) string { return prefix + "pft:" + id }

// RateLimitKey addresses a GCRA bucket for one action and one client identity.
func RateLimitKey(action, identity string) string { return prefix + "rl:" + action + ":" + identity }

// DailyBytesKey counts bytes uploaded by one client identity on one day.
func DailyBytesKey(identity, yyyymmdd string) string {
	return prefix + "q:b:" + identity + ":" + yyyymmdd
}

// BlobGCKey is the sorted set of blobs due for deletion, scored by deadline.
func BlobGCKey() string { return prefix + "gc:blobs" }

// DiskUsageKey holds the running total of bytes stored on the volume.
func DiskUsageKey() string { return prefix + "stat:disk" }

// ActiveKeyIDKey records which master key id the running instance last used, so
// startup can shout if it changed unexpectedly.
func ActiveKeyIDKey() string { return prefix + "cfg:key_id" }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
