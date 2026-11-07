//go:build linux

package smb2_test

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	client "github.com/hirochachacha/go-smb2"
	"golang.org/x/sys/unix"
)

// openFilesUnder counts this process's file descriptors that refer to files
// below dir (the server runs in-process, so these are the server's).
func openFilesUnder(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	n := 0
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err == nil && strings.HasPrefix(target, dir+string(filepath.Separator)) {
			n++
		}
	}
	return n
}

// A client that drops the connection while holding open files must not leave
// file descriptors behind in the server (which runs in this process).
func TestE2EDisconnectReleasesHandles(t *testing.T) {
	e := startServer(t)
	for i := 0; i < 20; i++ {
		if err := os.WriteFile(fmt.Sprintf("%s/f%02d.txt", e.share, i), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if n := openFilesUnder(t, e.share); n != 0 {
		t.Fatalf("%d files of the share are open before the test", n)
	}

	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	d := &client.Dialer{Initiator: &client.NTLMInitiator{User: "alice", Password: "alicepw"}}
	sess, err := d.Dial(conn)
	if err != nil {
		t.Fatal(err)
	}
	share, err := sess.Mount("docs")
	if err != nil {
		t.Fatal(err)
	}
	// Keep the files referenced: go-smb2 closes unreachable files from a
	// finalizer, which would send a regular CLOSE.
	var files []*client.File
	for i := 0; i < 20; i++ {
		f, err := share.Open(fmt.Sprintf("f%02d.txt", i))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if n := openFilesUnder(t, e.share); n != 20 {
		t.Fatalf("expected 20 open files in the share, have %d", n)
	}
	conn.Close() // drop the connection without CLOSE/LOGOFF
	runtime.KeepAlive(files)

	deadline := time.Now().Add(5 * time.Second)
	for {
		n := openFilesUnder(t, e.share)
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server still holds %d files of the share open after the client disconnected", n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Alternate data streams (stored as xattrs) must keep data written in
// several chunks, and a stream that does not fit must fail visibly.
func TestE2EStreamWrites(t *testing.T) {
	e := startServer(t)
	probe := filepath.Join(e.share, "probe")
	if err := os.WriteFile(probe, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(probe, "user.probe", []byte("x"), 0); err != nil {
		t.Skipf("filesystem of TMPDIR does not support user xattrs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(e.share, "f.txt"), []byte("main"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := e.mustMount(t, "alice", "alicepw")
	// Read a stream until STATUS_END_OF_FILE, like go-smb2's ReadFile. (The
	// server used to answer success with 0 bytes at the end, which made such
	// clients loop forever - hence the timeout.)
	readStream := func(name string) []byte {
		t.Helper()
		type result struct {
			data []byte
			err  error
		}
		done := make(chan result, 1)
		go func() {
			data, err := fs.ReadFile(name)
			done <- result{data, err}
		}()
		select {
		case r := <-done:
			if r.err != nil {
				t.Fatalf("read %s: %v", name, r.err)
			}
			return r.data
		case <-time.After(10 * time.Second):
			t.Fatalf("reading %s until EOF does not terminate", name)
		}
		return nil
	}

	f, err := fs.OpenFile("f.txt:meta", os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	first := bytes.Repeat([]byte("A"), 1000)
	second := bytes.Repeat([]byte("B"), 2000)
	if _, err := f.WriteAt(first, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(second, 1000); err != nil {
		t.Fatal(err)
	}
	f.Close()
	got := readStream("f.txt:meta")
	if want := append(append([]byte{}, first...), second...); !bytes.Equal(got, want) {
		t.Fatalf("stream after two chunked writes: %d bytes, want %d (prefix %q)", len(got), len(want), got[:min(len(got), 8)])
	}

	// Truncating keeps the remaining content.
	f, err = fs.OpenFile("f.txt:meta", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1500); err != nil {
		t.Fatalf("truncate stream: %v", err)
	}
	f.Close()
	got = readStream("f.txt:meta")
	if want := append(append([]byte{}, first...), second[:500]...); !bytes.Equal(got, want) {
		t.Fatalf("stream after truncate: %d bytes, want %d", len(got), len(want))
	}

	// A stream larger than any xattr can hold must report an error.
	big := bytes.Repeat([]byte("C"), 200_000)
	if err := fs.WriteFile("f.txt:huge", big, 0o644); err == nil {
		if back := readStream("f.txt:huge"); !bytes.Equal(back, big) {
			t.Fatalf("200 KB stream write reported success but reads back %d bytes", len(back))
		}
	}
	if main, _ := fs.ReadFile("f.txt"); string(main) != "main" {
		t.Fatalf("main data stream changed: %q", main)
	}
}
