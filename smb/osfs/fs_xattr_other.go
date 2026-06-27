//go:build !linux && !darwin

package osfs

import (
	"fmt"

	"github.com/sambam/sambam/smb/vfs"
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
	return []string{}, nil
}

func (fs *PassthroughFS) Getxattr(handle vfs.VfsHandle, key string, val []byte) (int, error) {
	return 0, nil
}

func (fs *PassthroughFS) Setxattr(handle vfs.VfsHandle, key string, val []byte) error {
	return nil
}

func (fs *PassthroughFS) Removexattr(handle vfs.VfsHandle, key string) error {
	return nil
}
