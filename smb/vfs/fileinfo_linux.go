//go:build linux

package vfs

import (
	"os"
	"syscall"
	"time"
)

func CompatStat(stat os.FileInfo) (Stat, bool) {
	sysStat, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		return Stat{}, false
	}

	mtime := time.Unix(int64(sysStat.Mtim.Sec), int64(sysStat.Mtim.Nsec))
	ctime := time.Unix(int64(sysStat.Ctim.Sec), int64(sysStat.Ctim.Nsec))
	// stat(2) has no birth time. Like Samba without statx btime, report the
	// earlier of mtime and ctime instead of 1970-01-01, which Windows shows
	// as the creation date.
	btime := mtime
	if ctime.Before(btime) {
		btime = ctime
	}

	s := Stat{
		Ino:     sysStat.Ino,
		Blocks:  sysStat.Blocks,
		BlkSize: int32(sysStat.Blksize),
		Mode:    sysStat.Mode,
		Uid:     sysStat.Uid,
		Gid:     sysStat.Gid,
		Nlink:   uint32(sysStat.Nlink),
		Atime:   time.Unix(int64(sysStat.Atim.Sec), int64(sysStat.Atim.Nsec)),
		Mtime:   mtime,
		Ctime:   ctime,
		Btime:   btime,
	}

	return s, true
}
