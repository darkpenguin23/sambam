package osfs

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"
)

// newCaseFS returns a share on a case-sensitive filesystem (the tests make
// no sense on a case-insensitive one such as the macOS default).
func newCaseFS(t *testing.T) (*PassthroughFS, string) {
	t.Helper()
	fs, share, _ := newTestFS(t, false)
	writeFile(t, filepath.Join(share, "probe"), "")
	if _, err := os.Stat(filepath.Join(share, "PROBE")); err == nil {
		t.Skip("TMPDIR is on a case-insensitive filesystem")
	}
	os.Remove(filepath.Join(share, "probe"))
	return fs, share
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range des {
		names = append(names, d.Name())
	}
	sort.Strings(names)
	return names
}

func TestResolveCase(t *testing.T) {
	fs, share := newCaseFS(t)
	if err := os.MkdirAll(filepath.Join(share, "Docs", "Reports 2026"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(share, "Docs", "Reports 2026", "Q3.XLSX"), "q3")
	writeFile(t, filepath.Join(share, "Docs", "Ärger.txt"), "")
	writeFile(t, filepath.Join(share, "both"), "")
	writeFile(t, filepath.Join(share, "BOTH"), "")

	for in, want := range map[string]string{
		"docs/reports 2026/q3.xlsx": "Docs/Reports 2026/Q3.XLSX",
		"/DOCS/REPORTS 2026/":       "Docs/Reports 2026",
		"docs/ärger.TXT":            "Docs/Ärger.txt",
		"DOCS/new/file.txt":         "Docs/new/file.txt", // missing tail kept as given
		"docs/NEW.TXT":              "Docs/NEW.TXT",
		// Unchanged when nothing needs replacing.
		"Docs/Reports 2026/Q3.XLSX": "Docs/Reports 2026/Q3.XLSX",
		"missing/x":                 "missing/x",
		"/":                         "/",
		// Exact matches win; otherwise the smallest name, independent of
		// directory order.
		"both": "both",
		"BOTH": "BOTH",
		"Both": "BOTH",
		// A component that is a file ends the lookup.
		"docs/ärger.txt/x": "Docs/Ärger.txt/x",
	} {
		if got := fs.ResolveCase(in); got != want {
			t.Errorf("ResolveCase(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOpenCaseInsensitive(t *testing.T) {
	fs, share := newCaseFS(t)
	writeFile(t, filepath.Join(share, "sub", "README.TXT"), "readme")
	h, err := fs.Open(fs.ResolveCase("SUB/readme.txt"), os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _ := fs.Read(h, buf, 0, 0)
	fs.Close(h)
	if string(buf[:n]) != "readme" {
		t.Fatalf("read %q", buf[:n])
	}
	// Creating through a differently spelled directory uses the existing one.
	h, err = fs.Open(fs.ResolveCase("SUB/new.txt"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fs.Close(h)
	if got := entries(t, share); len(got) != 1 || got[0] != "sub" {
		t.Fatalf("share root after create: %v", got)
	}
	if _, err := os.Stat(filepath.Join(share, "sub", "new.txt")); err != nil {
		t.Fatal(err)
	}
}

func TestRenameCaseInsensitive(t *testing.T) {
	fs, share := newCaseFS(t)
	open := func(name string) func(to string, replace int) error {
		h, err := fs.Open(name, os.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { fs.Close(h) })
		return func(to string, replace int) error { return fs.Rename(h, to, replace) }
	}

	// Case-only rename changes the name on disk.
	writeFile(t, filepath.Join(share, "case.txt"), "case")
	if err := open("case.txt")("CASE.txt", 0); err != nil {
		t.Fatalf("case-only rename: %v", err)
	}
	if got := entries(t, share); !equal(got, []string{"CASE.txt", "sub"}) {
		t.Fatalf("after case-only rename: %v", got)
	}

	// The target directory is found in any spelling.
	if err := open("CASE.txt")("SUB/moved.txt", 0); err != nil {
		t.Fatalf("rename into SUB: %v", err)
	}
	if got := entries(t, filepath.Join(share, "sub")); !equal(got, []string{"doc.txt", "moved.txt"}) {
		t.Fatalf("sub after rename: %v", got)
	}
	if got := entries(t, share); !equal(got, []string{"sub"}) {
		t.Fatalf("share root after rename: %v", got)
	}

	// A file spelled differently is a collision ...
	writeFile(t, filepath.Join(share, "a.txt"), "new")
	writeFile(t, filepath.Join(share, "target.txt"), "old")
	rename := open("a.txt")
	if err := rename("TARGET.TXT", 0); !errors.Is(err, os.ErrExist) {
		t.Fatalf("rename onto target.txt as TARGET.TXT: %v, want ErrExist", err)
	}
	// ... and replacing it leaves one file, spelled as requested.
	if err := rename("TARGET.TXT", 1); err != nil {
		t.Fatalf("replacing rename: %v", err)
	}
	if got := entries(t, share); !equal(got, []string{"TARGET.TXT", "sub"}) {
		t.Fatalf("after replacing rename: %v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(share, "TARGET.TXT")); string(b) != "new" {
		t.Fatalf("TARGET.TXT = %q", b)
	}
	// The handle follows the file.
	if err := rename("final.txt", 0); err != nil {
		t.Fatalf("rename after replacing rename: %v", err)
	}

	// A directory spelled differently is never replaced.
	writeFile(t, filepath.Join(share, "f.txt"), "")
	if err := open("f.txt")("Sub", 1); !errors.Is(err, syscall.EISDIR) {
		t.Fatalf("replace directory sub as Sub: %v, want EISDIR", err)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
