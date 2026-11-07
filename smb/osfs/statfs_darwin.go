package osfs

import "golang.org/x/sys/unix"

func statfsBlockSize(st *unix.Statfs_t) uint64 {
	return uint64(st.Bsize)
}
