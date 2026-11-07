//go:build linux || darwin

package osfs

import "golang.org/x/sys/unix"

// diskStats reports the size of the filesystem holding path, in units of
// blockSize bytes.
func diskStats(path string) (s diskUsage, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return s, err
	}
	return diskUsage{
		blockSize: statfsBlockSize(&st),
		blocks:    st.Blocks,
		free:      st.Bfree,
		avail:     st.Bavail,
		files:     st.Files,
		freeFiles: uint64(st.Ffree),
	}, nil
}
