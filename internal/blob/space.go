//go:build linux || darwin

package blob

import (
	"fmt"
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
	bsize := int64(st.Bsize)
	return Space{
		FreeBytes:  int64(st.Bavail) * bsize,
		TotalBytes: int64(st.Blocks) * bsize,
	}, nil
}
