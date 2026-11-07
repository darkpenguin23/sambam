package smb2

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	. "github.com/sambam/sambam/smb/internal/erref"
	. "github.com/sambam/sambam/smb/internal/smb2"
	"github.com/sambam/sambam/smb/internal/utf16le"
	"github.com/sambam/sambam/smb/osfs"
)

type queryDirEnv struct {
	t     *testing.T
	share string
	ft    *fileTree
	srv   *Server
}

func newQueryDirEnv(t *testing.T) *queryDirEnv {
	t.Helper()
	share := t.TempDir()
	srv := &Server{opens: map[uint64]*Open{}}
	ft := fuzzFileTreeIoctlHarness()
	ft.fs = osfs.NewPassthroughFS(share, false)
	ft.session.conn.serverCtx = srv
	return &queryDirEnv{t: t, share: share, ft: ft, srv: srv}
}

func (e *queryDirEnv) touch(names ...string) {
	e.t.Helper()
	for _, n := range names {
		p := filepath.Join(e.share, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			e.t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			e.t.Fatal(err)
		}
	}
}

// openDir opens a directory handle the way CREATE does.
func (e *queryDirEnv) openDir(name string) FileId {
	e.t.Helper()
	h, err := e.ft.fs.OpenDir(name)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { e.ft.fs.Close(h) })
	e.srv.addOpen(&Open{fileId: uint64(h), pathName: name})
	var fid FileId
	fid.SetHandleId(uint64(h))
	return fid
}

// query sends one QUERY_DIRECTORY (FileNamesInformation) and returns the
// response status and the names it carried.
func (e *queryDirEnv) query(fid FileId, pattern string, flags uint8) (NtStatus, []string) {
	e.t.Helper()
	req := &QueryDirectoryRequest{
		FileInfoClass:      FileNamesInformation,
		Flags:              flags,
		FileId:             &fid,
		OutputBufferLength: 65536,
		FileName:           pattern,
	}
	pkt := make([]byte, req.Size())
	req.Encode(pkt)

	// A compound context whose last message id never matches makes
	// sendPacket keep the encoded response instead of sending it.
	ctx := &compoundContext{lastMsgId: ^uint64(0)}
	if err := e.ft.queryDirectory(ctx, pkt); err != nil {
		e.t.Fatalf("queryDirectory: %v", err)
	}
	if len(ctx.rsp) == 0 {
		e.t.Fatal("no response")
	}
	rsp := ctx.rsp[len(ctx.rsp)-1]
	status := NtStatus(PacketCodec(rsp).Status())
	if status != 0 {
		return status, nil
	}
	buf := QueryDirectoryResponseDecoder(rsp[64:]).OutputBuffer()
	var names []string
	for len(buf) >= 12 {
		next := binary.LittleEndian.Uint32(buf[0:])
		n := binary.LittleEndian.Uint32(buf[8:])
		names = append(names, utf16le.DecodeToString(buf[12:12+n]))
		if next == 0 {
			break
		}
		buf = buf[next:]
	}
	return status, names
}

// listAll queries until the server reports the end, like a real client.
func (e *queryDirEnv) listAll(fid FileId, pattern string) (NtStatus, []string) {
	e.t.Helper()
	var all []string
	flags := uint8(RESTART_SCANS)
	for i := 0; ; i++ {
		if i > 1000 {
			e.t.Fatalf("pattern %q: enumeration does not terminate (%d entries so far)", pattern, len(all))
		}
		st, names := e.query(fid, pattern, flags)
		flags = 0
		if st == STATUS_NO_MORE_FILES {
			sort.Strings(all)
			return 0, all
		}
		if st != 0 {
			return st, all
		}
		all = append(all, names...)
	}
}

func TestQueryDirectoryPlainNameIsReturnedOnce(t *testing.T) {
	e := newQueryDirEnv(t)
	e.touch("keep.txt")
	fid := e.openDir("/")

	st, names := e.query(fid, "keep.txt", RESTART_SCANS)
	if st != 0 || len(names) != 1 || names[0] != "keep.txt" {
		t.Fatalf("first query: %v %q", st, names)
	}
	if st, names := e.query(fid, "keep.txt", 0); st != STATUS_NO_MORE_FILES {
		t.Fatalf("second query: %v %q, want STATUS_NO_MORE_FILES", st, names)
	}
	if st, names := e.query(fid, "keep.txt", RESTART_SCANS); st != 0 || len(names) != 1 {
		t.Fatalf("query after RESTART_SCANS: %v %q", st, names)
	}
	if st, _ := e.query(fid, "missing.txt", RESTART_SCANS); st != STATUS_NO_SUCH_FILE {
		t.Fatalf("missing name: %v, want STATUS_NO_SUCH_FILE", st)
	}
}

func TestQueryDirectoryPatterns(t *testing.T) {
	e := newQueryDirEnv(t)
	e.touch("a.txt", "abctxt", "UPPER.TXT", "photo (1).jpg", "README", "b.txt.bak")
	fid := e.openDir("/")

	cases := []struct {
		pattern string
		want    []string
	}{
		{"*.txt", []string{"UPPER.TXT", "a.txt"}},
		{"<.txt", []string{"UPPER.TXT", "a.txt"}}, // Windows `dir *.txt`
		{"photo (1)*", []string{"photo (1).jpg"}},
		{`<"`, []string{".", "..", "README", "abctxt"}}, // Windows `dir *.`: names without extension
		{"*", []string{".", "..", "README", "UPPER.TXT", "a.txt", "abctxt", "b.txt.bak", "photo (1).jpg"}},
		{"", []string{".", "..", "README", "UPPER.TXT", "a.txt", "abctxt", "b.txt.bak", "photo (1).jpg"}},
	}
	for _, c := range cases {
		st, got := e.listAll(fid, c.pattern)
		if st != 0 || fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("pattern %q: %v %q, want %q", c.pattern, st, got, c.want)
		}
	}
	if st, _ := e.query(fid, "*.none", RESTART_SCANS); st != STATUS_NO_SUCH_FILE {
		t.Errorf("pattern without match: %v, want STATUS_NO_SUCH_FILE", st)
	}
}

// A wildcard query must keep reading until it finds a match; a batch of
// 1000 directory entries without one used to end the listing with
// STATUS_NO_SUCH_FILE.
func TestQueryDirectoryMatchBeyondFirstBatch(t *testing.T) {
	e := newQueryDirEnv(t)
	dir := filepath.Join(e.share, "big")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5000; i++ {
		e.touch(fmt.Sprintf("big/data-%05d.dat", i))
	}
	// Place the only .txt file well behind the first batch in getdents
	// order (the order the server reads in), renaming until it lands there.
	needle := ""
	for try := 0; try < 200 && needle == ""; try++ {
		name := fmt.Sprintf("needle-%d.txt", try)
		e.touch("big/" + name)
		f, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		order, _ := f.Readdirnames(-1)
		f.Close()
		for i, n := range order {
			if n == name && i > 1200 {
				needle = name
			}
		}
		if needle == "" {
			os.Remove(filepath.Join(dir, name))
		}
	}
	if needle == "" {
		t.Skip("could not place a file behind the first ReadDir batch on this filesystem")
	}

	fid := e.openDir("big")
	st, got := e.listAll(fid, "*.txt")
	if st != 0 || len(got) != 1 || got[0] != needle {
		t.Fatalf("*.txt in 5001-entry directory: %v %q, want [%s]", st, got, needle)
	}
}
