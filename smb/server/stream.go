package smb2

import (
	"errors"
	"syscall"

	. "github.com/sambam/sambam/smb/internal/erref"
	"github.com/sambam/sambam/smb/vfs"
)

// maxStreamSize caps an alternate data stream. Streams are stored as
// extended attributes, and filesystems allow far less than this (Linux: at
// most 64 KiB per value, ext4 without ea_inode about one block), so the cap
// only protects the server's memory from client-chosen offsets and sizes.
const maxStreamSize = 1 << 20

var errStreamTooLarge = errors.New("stream exceeds maximum size")

// readStream returns the current content of a stream. A stream that cannot
// be read is treated as empty; writing it back reports real errors.
func (t *fileTree) readStream(h vfs.VfsHandle, key string) []byte {
	size, err := t.fs.Getxattr(h, key, nil)
	if err != nil || size <= 0 {
		return nil
	}
	buf := make([]byte, size)
	n, err := t.fs.Getxattr(h, key, buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

// writeStream writes data at offset off into the stream, extending it with
// zeros if needed. (Each WRITE used to replace the whole stream with its own
// chunk and ignore errors, so multi-chunk streams kept only the last chunk.)
func (t *fileTree) writeStream(h vfs.VfsHandle, key string, off uint64, data []byte) error {
	end := off + uint64(len(data))
	if end < off || end > maxStreamSize {
		return errStreamTooLarge
	}
	cur := t.readStream(h, key)
	if uint64(len(cur)) < end {
		grown := make([]byte, end)
		copy(grown, cur)
		cur = grown
	}
	copy(cur[off:], data)
	return t.fs.Setxattr(h, key, cur)
}

// resizeStream truncates or zero-extends the stream to size bytes, keeping
// its content (it used to be replaced by zeros).
func (t *fileTree) resizeStream(h vfs.VfsHandle, key string, size int64) error {
	if size < 0 || size > maxStreamSize {
		return errStreamTooLarge
	}
	cur := t.readStream(h, key)
	if int64(len(cur)) >= size {
		cur = cur[:size]
	} else {
		grown := make([]byte, size)
		copy(grown, cur)
		cur = grown
	}
	return t.fs.Setxattr(h, key, cur)
}

// streamWriteStatus maps a failed stream write to an NT status. Running out
// of xattr space is reported as a full disk, so clients see the failure
// instead of losing the data silently.
func streamWriteStatus(err error) uint32 {
	switch {
	case errors.Is(err, errStreamTooLarge),
		errors.Is(err, syscall.E2BIG),
		errors.Is(err, syscall.ENOSPC),
		errors.Is(err, syscall.ERANGE):
		return uint32(STATUS_DISK_FULL)
	}
	return uint32(STATUS_IO_DEVICE_ERROR)
}
