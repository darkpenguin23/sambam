package osfs

import (
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"unicode"
)

// Windows clients treat names as case-insensitive: the server reports
// FILE_CASE_PRESERVED_NAMES without FILE_CASE_SENSITIVE_SEARCH, programs
// open "readme.txt" for README.TXT, and Explorer creates "New folder" and
// then refers to it as "new folder". Linux filesystems are case-sensitive,
// so a name that does not exist as given is looked up in its directory
// ignoring case (as Samba does). The lookup costs one directory scan, and
// only for names that are not found as given - mostly files about to be
// created; on case-insensitive filesystems (macOS, Windows) every name that
// exists is found directly.

// ResolveCase implements vfs.CaseResolver.
func (fs *PassthroughFS) ResolveCase(p string) string {
	r, err := fs.openRoot()
	if err != nil {
		return p
	}
	rel := relName(p)
	if rel == "." {
		return p
	}
	resolved, changed := resolveRel(r, rel)
	if !changed {
		return p
	}
	return resolved
}

// resolveRel resolves a root-relative name (as produced by relName)
// component by component. It reports whether any component was replaced.
func resolveRel(r *os.Root, rel string) (string, bool) {
	if rel == "." {
		return rel, false
	}
	if _, err := r.Lstat(rel); err == nil || !errors.Is(err, os.ErrNotExist) {
		return rel, false
	}
	parts := strings.Split(rel, "/")
	cur := "."
	changed := false
	for i, part := range parts {
		next := path.Join(cur, part)
		_, err := r.Lstat(next)
		if err == nil {
			cur = next
			continue
		}
		if errors.Is(err, os.ErrNotExist) {
			if match, ok := findFold(r, cur, part); ok {
				cur = path.Join(cur, match)
				changed = true
				continue
			}
		}
		// Not there in any spelling (or not a directory): keep the rest.
		return path.Join(append([]string{cur}, parts[i:]...)...), changed
	}
	return cur, changed
}

// findFold looks for an entry of dir whose name equals name ignoring case.
// If several entries match (possible on Linux), the smallest name wins so
// the result does not depend on directory order.
func findFold(r *os.Root, dir, name string) (string, bool) {
	if !hasCase(name) {
		return "", false
	}
	d, err := r.Open(dir)
	if err != nil {
		return "", false
	}
	defer d.Close()
	match, found := "", false
	for {
		names, err := d.Readdirnames(1024)
		for _, n := range names {
			if strings.EqualFold(n, name) && (!found || n < match) {
				match, found = n, true
			}
		}
		if err != nil {
			if err != io.EOF {
				return "", false
			}
			break
		}
		if len(names) == 0 {
			break
		}
	}
	return match, found
}

// hasCase reports whether another spelling of name can be equal to it
// under case folding; names such as "2024" or "._" need no directory scan.
func hasCase(name string) bool {
	for _, c := range name {
		if unicode.SimpleFold(c) != c {
			return true
		}
	}
	return false
}
