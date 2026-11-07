//go:build linux

package smb2_test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	client "github.com/hirochachacha/go-smb2"
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
