package osfs

import "golang.org/x/sys/unix"

// f_blocks/f_bfree/f_bavail are counted in fragment size units.
func statfsBlockSize(st *unix.Statfs_t) uint64 {
	if st.Frsize > 0 {
		return uint64(st.Frsize)
	}
	return uint64(st.Bsize)
}
