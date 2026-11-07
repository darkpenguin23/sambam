package smb2

import (
	"time"

	. "github.com/sambam/sambam/smb/internal/smb2"
	"github.com/sambam/sambam/smb/vfs"
)

// basicInfoTime decodes a time of FileBasicInformation (MS-FSA 2.1.5.15.1):
// 0 leaves the time unchanged; -1 and -2 switch the automatic update of that
// time off and on for the handle and leave it unchanged as well. Windows'
// CopyFile sends -1 for the source's LastAccessTime, which used to be stored
// as a date in the year 2185. Values below -2 are invalid.
func basicInfoTime(ft *Filetime) (t time.Time, set, valid bool) {
	v := int64(uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime))
	switch {
	case v < -2:
		return time.Time{}, false, false
	case v <= 0:
		return time.Time{}, false, true
	}
	const unixEpoch = 116444736000000000 // 1970-01-01 in 100ns units since 1601
	d := v - unixEpoch
	return time.Unix(d/1e7, (d%1e7)*100), true, true
}

// readOnlyMode maps FILE_ATTRIBUTE_READONLY to the Unix mode the way it is
// reported (PermissionsFromVfs: read-only means no write bit at all):
// setting it removes all write bits, clearing it gives the owner write
// permission back. Directories are left alone - Windows uses the flag on
// folders only to mark them as customized.
func readOnlyMode(cur *vfs.Attributes, attrs uint32) (mode uint32, change bool) {
	if cur.GetFileType() != vfs.FileTypeRegularFile {
		return 0, false
	}
	m, ok := cur.GetUnixMode()
	if !ok {
		return 0, false
	}
	m &= 0o7777
	if attrs&FILE_ATTRIBUTE_READONLY != 0 {
		if m&0o222 == 0 {
			return 0, false
		}
		return m &^ 0o222, true
	}
	if m&0o222 != 0 {
		return 0, false
	}
	return m | 0o200, true
}
