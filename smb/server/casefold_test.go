package smb2

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	. "github.com/sambam/sambam/smb/internal/erref"
	. "github.com/sambam/sambam/smb/internal/smb2"
)

// The server announces case-insensitive names (FILE_CASE_PRESERVED_NAMES
// without FILE_CASE_SENSITIVE_SEARCH), but on Linux `type Z:\upper.txt`
// failed for UPPER.TXT and creating "SUB\x" next to a folder "sub" created a
// second folder.

func skipCaseInsensitiveFS(t *testing.T, dir string) {
	t.Helper()
	p := filepath.Join(dir, "case-probe")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(p)
	if _, err := os.Stat(filepath.Join(dir, "CASE-PROBE")); err == nil {
		t.Skip("TMPDIR is on a case-insensitive filesystem")
	}
}

func (e *handleEnv) createDisp(name string, disp, options uint32) (*compoundContext, NtStatus) {
	e.t.Helper()
	ctx := newChain()
	e.ft.create(ctx, e.encode(&CreateRequest{
		ImpersonationLevel: 2,
		DesiredAccess:      FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | DELETE,
		ShareAccess:        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		CreateDisposition:  disp,
		CreateOptions:      options,
		Name:               name,
	}, false))
	st := statusOf(ctx.rsp[0])
	if st == 0 {
		e.t.Cleanup(func() { e.closeOn(ctx) })
	}
	return ctx, st
}

func (e *handleEnv) tree(t *testing.T) string {
	t.Helper()
	var all []string
	filepath.WalkDir(e.share, func(p string, d os.DirEntry, err error) error {
		if err == nil && p != e.share {
			rel, _ := filepath.Rel(e.share, p)
			all = append(all, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(all)
	return strings.Join(all, " ")
}

func TestCreateIgnoresCase(t *testing.T) {
	e := newHandleEnv(t)
	skipCaseInsensitiveFS(t, e.share)
	e.writeFile("UPPER.TXT", "data")
	if err := os.Mkdir(filepath.Join(e.share, "Sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, st := e.createDisp("upper.txt", FILE_OPEN, 0); st != 0 {
		t.Errorf("FILE_OPEN upper.txt for UPPER.TXT: %v", st)
	}
	if _, st := e.createDisp(`SUB`, FILE_OPEN, FILE_DIRECTORY_FILE); st != 0 {
		t.Errorf("FILE_OPEN directory SUB for Sub: %v", st)
	}
	if _, st := e.createDisp("Upper.Txt", FILE_CREATE, 0); st != STATUS_OBJECT_NAME_COLLISION {
		t.Errorf("FILE_CREATE Upper.Txt next to UPPER.TXT: %v, want STATUS_OBJECT_NAME_COLLISION", st)
	}
	if _, st := e.createDisp("sub", FILE_CREATE, FILE_DIRECTORY_FILE); st != STATUS_OBJECT_NAME_COLLISION {
		t.Errorf("mkdir sub next to Sub: %v, want STATUS_OBJECT_NAME_COLLISION", st)
	}
	if _, st := e.createDisp(`SUB\New.txt`, FILE_OPEN_IF, 0); st != 0 {
		t.Errorf(`FILE_OPEN_IF SUB\New.txt: %v`, st)
	}
	if _, st := e.createDisp("upper.txt", FILE_OVERWRITE_IF, 0); st != 0 {
		t.Errorf("FILE_OVERWRITE_IF upper.txt: %v", st)
	}
	if got, want := e.tree(t), "Sub Sub/New.txt UPPER.TXT"; got != want {
		t.Fatalf("share contains %q, want %q", got, want)
	}
	if got := e.readFile("UPPER.TXT"); got != "" {
		t.Fatalf("UPPER.TXT after overwrite through upper.txt: %q", got)
	}

	// Rename into a directory spelled differently, and a case-only rename.
	ctx := e.open("upper.txt")
	if st := e.setInfoOn(ctx, FileRenameInformation, rename(`sub\Moved.txt`, false)); st != 0 {
		t.Fatalf(`rename to sub\Moved.txt: %v`, st)
	}
	if st := e.setInfoOn(ctx, FileRenameInformation, rename(`sub\MOVED.TXT`, false)); st != 0 {
		t.Fatalf("case-only rename: %v", st)
	}
	e.closeOn(ctx)
	if got, want := e.tree(t), "Sub Sub/MOVED.TXT Sub/New.txt"; got != want {
		t.Fatalf("after renames the share contains %q, want %q", got, want)
	}
}

// FindFirstFile with a plain name (`dir Z:\upper.txt`, Explorer) must find
// the file and report the name stored on disk.
func TestQueryDirectoryPlainNameIgnoresCase(t *testing.T) {
	e := newQueryDirEnv(t)
	skipCaseInsensitiveFS(t, e.share)
	e.touch("UPPER.TXT", "Sub/Inner.txt")

	st, names := e.query(e.openDir("/"), "upper.txt", RESTART_SCANS)
	if st != 0 || len(names) != 1 || names[0] != "UPPER.TXT" {
		t.Errorf("query upper.txt in /: %v %q, want [UPPER.TXT]", st, names)
	}
	st, names = e.query(e.openDir("Sub"), "INNER.TXT", RESTART_SCANS)
	if st != 0 || len(names) != 1 || names[0] != "Inner.txt" {
		t.Errorf("query INNER.TXT in Sub: %v %q, want [Inner.txt]", st, names)
	}
	if st, _ := e.query(e.openDir("/"), "missing.txt", RESTART_SCANS); st != STATUS_NO_SUCH_FILE {
		t.Errorf("query missing.txt: %v, want STATUS_NO_SUCH_FILE", st)
	}
}
