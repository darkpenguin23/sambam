package smb2

import (
	"errors"
	"io/fs"
	"syscall"

	. "github.com/sambam/sambam/smb/internal/erref"
)

// renameErrorStatus maps a failed rename to the status Windows itself
// returns. Clients act on it: PowerShell's Move-Item -Force only replaces the
// target after STATUS_OBJECT_NAME_COLLISION, on STATUS_ACCESS_DENIED it
// treats the file as protected and gives up.
func renameErrorStatus(err error) NtStatus {
	switch {
	case errors.Is(err, syscall.ENOTEMPTY), errors.Is(err, syscall.EISDIR):
		// Windows never replaces a directory.
		return STATUS_ACCESS_DENIED
	case errors.Is(err, fs.ErrExist):
		return STATUS_OBJECT_NAME_COLLISION
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		return STATUS_OBJECT_PATH_NOT_FOUND
	case errors.Is(err, syscall.EXDEV):
		return STATUS_NOT_SAME_DEVICE
	}
	return STATUS_ACCESS_DENIED
}
