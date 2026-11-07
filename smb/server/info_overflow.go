package smb2

import (
	. "github.com/sambam/sambam/smb/internal/smb2"
)

// truncateFileInfo returns the part of info that fits into outLen bytes, for
// the variable-length classes where Windows answers a too small buffer with
// STATUS_BUFFER_OVERFLOW and partial data (MS-FSA 2.1.5.11) instead of
// failing. Callers rely on that: FindFirstStreamW (PowerShell's
// Get-Item -Stream, Explorer) starts with a 32-byte buffer and grows it on
// STATUS_BUFFER_OVERFLOW, while STATUS_INFO_LENGTH_MISMATCH ends the call.
// ok is false when outLen cannot even hold the fixed part.
func truncateFileInfo(class uint8, info Encoder, outLen int) (Encoder, bool) {
	switch class {
	case FileStreamInformation:
		items, isItems := info.(FileStreamInformationInfoItems)
		if !isItems || outLen < 24 {
			return nil, false
		}
		// Only whole entries; the client asks again with a bigger buffer.
		fit := FileStreamInformationInfoItems{}
		used := 0
		for _, it := range items {
			if used+it.Size() > outLen {
				break
			}
			used += it.Size()
			fit = append(fit, it)
		}
		return fit, true
	case FileAllInformation, FileNameInformation, FileNormalizedNameInformation, FileAlternateNameInformation:
		// Fixed part, then the name, which may be cut (its length field
		// keeps the full length, as on NTFS).
		fixed := 4
		if class == FileAllInformation {
			fixed = 100
		}
		if outLen < fixed {
			return nil, false
		}
		buf := make([]byte, info.Size())
		info.Encode(buf)
		return rawInfo(buf[:outLen]), true
	}
	return nil, false
}

// rawInfo is already encoded information.
type rawInfo []byte

func (b rawInfo) Size() int       { return len(b) }
func (b rawInfo) Encode(p []byte) { copy(p, b) }
