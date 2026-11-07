//go:build linux || darwin

package osfs

import (
	"fmt"
	"strings"

	"github.com/sambam/sambam/smb/vfs"
	"golang.org/x/sys/unix"
)

// withXattrFd runs fn on the open file's descriptor. Extended attributes are
// accessed through the descriptor rather than by path so that a symlink can
// never redirect the operation to a file outside the share. Handles opened
// as O_PATH (symlinks themselves) get EBADF from the kernel, which is fine:
// user.* xattrs are not supported on symlinks anyway.
func (fs *PassthroughFS) withXattrFd(handle vfs.VfsHandle, fn func(fd int) error) error {
	open, err := fs.loadOpen(handle)
	if err != nil {
		return err
	}
	if open.f == nil {
		return fmt.Errorf("bad handle")
	}
	rc, err := open.f.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	if err := rc.Control(func(fd uintptr) { opErr = fn(int(fd)) }); err != nil {
		return err
	}
	return opErr
}

func (fs *PassthroughFS) Listxattr(handle vfs.VfsHandle) ([]string, error) {
	var names []string
	err := fs.withXattrFd(handle, func(fd int) error {
		sz, err := unix.Flistxattr(fd, nil)
		if err != nil || sz == 0 {
			return err
		}
		buf := make([]byte, sz)
		sz, err = unix.Flistxattr(fd, buf)
		if err != nil {
			return err
		}
		for _, name := range strings.Split(string(buf[:sz]), "\x00") {
			// Strip "user." prefix for SMB stream names
			if strings.HasPrefix(name, "user.") {
				names = append(names, name[5:])
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return names, nil
}

// Getxattr returns the attribute size when val is nil, otherwise reads the
// value into val.
func (fs *PassthroughFS) Getxattr(handle vfs.VfsHandle, key string, val []byte) (int, error) {
	var n int
	err := fs.withXattrFd(handle, func(fd int) error {
		var err error
		n, err = unix.Fgetxattr(fd, "user."+key, val)
		return err
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (fs *PassthroughFS) Setxattr(handle vfs.VfsHandle, key string, val []byte) error {
	return fs.withXattrFd(handle, func(fd int) error {
		return unix.Fsetxattr(fd, "user."+key, val, 0)
	})
}

func (fs *PassthroughFS) Removexattr(handle vfs.VfsHandle, key string) error {
	return fs.withXattrFd(handle, func(fd int) error {
		return unix.Fremovexattr(fd, "user."+key)
	})
}
