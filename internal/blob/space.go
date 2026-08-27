//go:build linux || darwin

package blob

import (
	"fmt"
	"math"
	"syscall"
)

// Space describes free and total capacity of the volume.
type Space struct {
	FreeBytes  int64
	TotalBytes int64
}

// UsedRatio is the fraction of the volume in use, from 0 to 1.
func (s Space) UsedRatio() float64 {
	if s.TotalBytes <= 0 {
		return 0
	}
	return float64(s.TotalBytes-s.FreeBytes) / float64(s.TotalBytes)
}

// Space reports capacity of the filesystem holding the blob directory. It is
// what stands between a full volume and a stream that dies halfway through a
// user's upload.
func (s *Store) Space() (Space, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(s.dir, &st); err != nil {
		return Space{}, fmt.Errorf("blob: statfs %s: %w", s.dir, err)
	}
	bsize := toInt64(st.Bsize)
	return Space{
		FreeBytes:  mulBytes(toInt64(st.Bavail), bsize),
		TotalBytes: mulBytes(toInt64(st.Blocks), bsize),
	}, nil
}

// toInt64 widens a statfs field.
//
// The field types differ between platforms — Bsize is int64 on Linux and uint32
// on Darwin — so this generic is the single place that difference is absorbed,
// and taking the field directly means no call site needs a conversion that
// would be redundant on one platform and unsafe on the other.
//
// A value that does not fit is reported as zero rather than wrapped. Zero
// propagates to UsedRatio, which already treats a non-positive total as
// "unknown" and returns 0; a wrapped negative would instead look like a volume
// with impossible free space and wave uploads through onto a full disk.
func toInt64[T int32 | int64 | uint32 | uint64](v T) int64 {
	// A negative result means either a field that was genuinely negative or an
	// unsigned value past the int64 ceiling; neither is a usable byte count.
	out := int64(v)
	if out < 0 {
		return 0
	}
	return out
}

// mulBytes multiplies a block count by a block size, saturating instead of
// overflowing. A volume large enough to overflow int64 bytes does not exist
// today, but reporting math.MaxInt64 keeps the arithmetic monotonic if one ever
// does, where wrapping would report it as nearly empty.
func mulBytes(blocks, size int64) int64 {
	if blocks <= 0 || size <= 0 {
		return 0
	}
	if blocks > math.MaxInt64/size {
		return math.MaxInt64
	}
	return blocks * size
}
