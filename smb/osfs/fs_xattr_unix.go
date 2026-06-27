//go:build linux || darwin

package osfs

import (
	"fmt"
	"strings"

	"github.com/sambam/sambam/smb/vfs"
	"golang.org/x/sys/unix"
)

func (fs *PassthroughFS) xattrPath(handle vfs.VfsHandle) (string, error) {
	if handle == 0 {
		return "", fmt.Errorf("bad handle")
	}
	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return "", fmt.Errorf("bad handle")
	}
	return v.(*OpenFile).path, nil
}

func (fs *PassthroughFS) Listxattr(handle vfs.VfsHandle) ([]string, error) {
	p, err := fs.xattrPath(handle)
	if err != nil {
		return nil, err
	}
	sz, err := unix.Listxattr(p, nil)
	if err != nil || sz == 0 {
		return nil, err
	}
	buf := make([]byte, sz)
	sz, err = unix.Listxattr(p, buf)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, name := range strings.Split(string(buf[:sz]), "\x00") {
		if name == "" {
			continue
		}
		// Strip "user." prefix for SMB stream names
		if strings.HasPrefix(name, "user.") {
			names = append(names, name[5:])
		}
	}
	return names, nil
}

func (fs *PassthroughFS) Getxattr(handle vfs.VfsHandle, key string, val []byte) (int, error) {
	p, err := fs.xattrPath(handle)
	if err != nil {
		return 0, err
	}
	attr := "user." + key
	if val == nil {
		// Size query
		sz, err := unix.Getxattr(p, attr, nil)
		if err != nil {
			return 0, err
		}
		return sz, nil
	}
	n, err := unix.Getxattr(p, attr, val)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (fs *PassthroughFS) Setxattr(handle vfs.VfsHandle, key string, val []byte) error {
	p, err := fs.xattrPath(handle)
	if err != nil {
		return err
	}
	return unix.Setxattr(p, "user."+key, val, 0)
}

func (fs *PassthroughFS) Removexattr(handle vfs.VfsHandle, key string) error {
	p, err := fs.xattrPath(handle)
	if err != nil {
		return err
	}
	return unix.Removexattr(p, "user."+key)
}
