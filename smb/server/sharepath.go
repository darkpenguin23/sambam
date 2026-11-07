package smb2

import "strings"

// shareRelativePath converts a client-supplied SMB path (backslash separated,
// relative to the share root) into the slash-separated form used by the VFS.
//
// It rejects any ".." component, including one carrying a stream suffix such
// as "..:name". Real clients resolve ".." before sending a path, so such a
// request is malformed at best and an attempt to leave the share at worst.
// The VFS enforces confinement on its own as well (see osfs); this check
// additionally keeps ".." out of logs, change-notify watchers and callbacks.
func shareRelativePath(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	for _, part := range strings.Split(name, "/") {
		if part == ".." || strings.HasPrefix(part, "..:") {
			return "", false
		}
	}
	return name, true
}
