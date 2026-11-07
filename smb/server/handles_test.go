package smb2

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/sambam/sambam/smb/internal/erref"
	. "github.com/sambam/sambam/smb/internal/smb2"
	"github.com/sambam/sambam/smb/osfs"
	"github.com/sambam/sambam/smb/vfs"
)

type handleEnv struct {
	t     *testing.T
	share string
	ft    *fileTree
	srv   *Server
	msgId uint64
}

func newHandleEnv(t *testing.T) *handleEnv {
	t.Helper()
	share := t.TempDir()
	srv := &Server{opens: map[uint64]*Open{}, opensByGuid: map[Guid]*Open{}}
	ft := fuzzFileTreeIoctlHarness()
	ft.fs = osfs.NewPassthroughFS(share, false)
	ft.session.conn.serverCtx = srv
	ft.session.username = "alice"
	return &handleEnv{t: t, share: share, ft: ft, srv: srv}
}

func (e *handleEnv) touch(name string) {
	e.t.Helper()
	p := filepath.Join(e.share, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *handleEnv) encode(req Packet, related bool) []byte {
	e.msgId++
	req.Header().MessageId = e.msgId
	if related {
		req.Header().Flags |= SMB2_FLAGS_RELATED_OPERATIONS
	}
	pkt := make([]byte, req.Size())
	req.Encode(pkt)
	return pkt
}

func (e *handleEnv) createPkt(name string, access, options uint32) []byte {
	return e.encode(&CreateRequest{
		ImpersonationLevel: 2,
		DesiredAccess:      access,
		ShareAccess:        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		CreateDisposition:  FILE_OPEN,
		CreateOptions:      options,
		Name:               name,
	}, false)
}

// relatedFileId is what clients put into related requests: "use the handle
// of the previous request".
var relatedFileId = FileId{
	Persistent: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	Volatile:   [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
}

func statusOf(rsp []byte) NtStatus { return NtStatus(PacketCodec(rsp).Status()) }

// newChain returns a compound context that collects every response
// (its last message id never matches, so nothing is sent).
func newChain() *compoundContext { return &compoundContext{lastMsgId: ^uint64(0)} }

// A failing request in the middle of a compound chain must not stop the
// CLOSE at its end. Linux cifs sends CREATE + SET_INFO(delete) + CLOSE for
// rmdir; on a non-empty directory the SET_INFO fails, and the skipped CLOSE
// leaked one handle (and file descriptor) per call.
func TestCompoundCloseRunsAfterFailedSetInfo(t *testing.T) {
	e := newHandleEnv(t)
	e.touch("full/f.txt")
	ctx := newChain()

	if err := e.ft.create(ctx, e.createPkt("full", DELETE|FILE_READ_ATTRIBUTES, FILE_DIRECTORY_FILE)); err != nil {
		t.Fatal(err)
	}
	if ctx.fileId == nil || statusOf(ctx.rsp[0]) != 0 {
		t.Fatalf("CREATE failed: %v", statusOf(ctx.rsp[0]))
	}
	h := ctx.fileId.HandleId()

	setInfo := e.encode(&SetInfoRequest{
		InfoType:      SMB2_0_INFO_FILE,
		FileInfoClass: FileDispositionInformation,
		FileId:        &relatedFileId,
		Input:         fuzzInput{1}, // DeletePending = 1
	}, true)
	if _, failed := ctx.relatedCreateFailure(PacketCodec(setInfo)); failed {
		t.Fatal("SET_INFO after a successful CREATE was short-circuited")
	}
	e.ft.setInfo(ctx, setInfo)
	if st := statusOf(ctx.rsp[1]); st != STATUS_DIRECTORY_NOT_EMPTY {
		t.Fatalf("SET_INFO status = %v, want STATUS_DIRECTORY_NOT_EMPTY", st)
	}

	closePkt := e.encode(&CloseRequest{FileId: &relatedFileId}, true)
	if _, failed := ctx.relatedCreateFailure(PacketCodec(closePkt)); failed {
		t.Fatal("CLOSE was skipped because an earlier SET_INFO failed")
	}
	e.ft.close(ctx, closePkt)
	if st := statusOf(ctx.rsp[2]); st != 0 {
		t.Errorf("CLOSE status = %v, want success (the SET_INFO error is not the CLOSE's)", st)
	}
	if e.srv.getOpen(h) != nil {
		t.Error("open is still registered after CLOSE")
	}
	if _, err := e.ft.fs.GetAttr(vfs.VfsHandle(h)); err == nil {
		t.Error("VFS handle is still open after CLOSE")
	}
	if _, err := os.Stat(filepath.Join(e.share, "full")); err != nil {
		t.Error("non-empty directory was deleted")
	}
}

// After a failed CREATE, related requests have no handle and must get the
// CREATE's error; unrelated requests in the same chain run normally.
func TestCompoundFailedCreatePropagatesToRelatedRequests(t *testing.T) {
	e := newHandleEnv(t)
	ctx := newChain()
	e.ft.create(ctx, e.createPkt("missing.txt", FILE_READ_DATA, 0))
	if st := statusOf(ctx.rsp[0]); st != STATUS_NO_SUCH_FILE {
		t.Fatalf("CREATE status = %v", st)
	}
	related := e.encode(&CloseRequest{FileId: &relatedFileId}, true)
	if st, failed := ctx.relatedCreateFailure(PacketCodec(related)); !failed || NtStatus(st) != STATUS_NO_SUCH_FILE {
		t.Fatalf("related request after failed CREATE: %v %v", NtStatus(st), failed)
	}
	unrelated := e.encode(&CloseRequest{FileId: &relatedFileId}, false)
	if _, failed := ctx.relatedCreateFailure(PacketCodec(unrelated)); failed {
		t.Fatal("unrelated request was failed with the CREATE's error")
	}
}

// Handles left open when a client disconnects are released, and a pending
// delete-on-close is carried out.
func TestReleaseOpensOnDisconnect(t *testing.T) {
	e := newHandleEnv(t)
	e.touch("a.txt")
	e.touch("b.txt")

	ctxA := newChain()
	e.ft.create(ctxA, e.createPkt("a.txt", FILE_READ_DATA, 0))
	ctxB := newChain()
	e.ft.create(ctxB, e.createPkt("b.txt", FILE_READ_DATA|DELETE, FILE_DELETE_ON_CLOSE))
	if ctxA.fileId == nil || ctxB.fileId == nil {
		t.Fatal("CREATE failed")
	}
	ha, hb := ctxA.fileId.HandleId(), ctxB.fileId.HandleId()

	e.ft.session.conn.releaseOpens("disconnect", func(*Open) bool { return true })

	for _, h := range []uint64{ha, hb} {
		if e.srv.getOpen(h) != nil {
			t.Errorf("open %x still registered", h)
		}
		if _, err := e.ft.fs.GetAttr(vfs.VfsHandle(h)); err == nil {
			t.Errorf("VFS handle %x still open", h)
		}
	}
	if _, err := os.Stat(filepath.Join(e.share, "a.txt")); err != nil {
		t.Error("a.txt was removed")
	}
	if _, err := os.Stat(filepath.Join(e.share, "b.txt")); !os.IsNotExist(err) {
		t.Error("delete-on-close of b.txt was not carried out on disconnect")
	}
}

func encodeChain(t *testing.T, related []bool, reqs ...Packet) []byte {
	t.Helper()
	var chain []byte
	for i, req := range reqs {
		h := req.Header()
		h.MessageId = uint64(100 + i)
		if related[i] {
			h.Flags |= SMB2_FLAGS_RELATED_OPERATIONS
		}
		size := req.Size()
		if i < len(reqs)-1 {
			size = Align(size, 8)
			h.NextCommand = uint32(size)
		}
		pkt := make([]byte, size)
		req.Encode(pkt)
		chain = append(chain, pkt...)
	}
	return chain
}

func TestCompoundLastMsgId(t *testing.T) {
	mk := func() []Packet {
		return []Packet{
			&CreateRequest{Name: "a"},
			&SetInfoRequest{FileId: &relatedFileId, Input: fuzzInput{1}},
			&CloseRequest{FileId: &relatedFileId},
		}
	}
	if got := compoundLastMsgId(encodeChain(t, []bool{false, true, true}, mk()...)); got != 102 {
		t.Errorf("related chain: last msg id = %d, want 102", got)
	}
	// The second request starts a new chain: the first one is never closed.
	if got := compoundLastMsgId(encodeChain(t, []bool{false, false, true}, mk()...)); got != 0 {
		t.Errorf("chain interrupted by a new first request: %d, want 0", got)
	}
	if got := compoundLastMsgId([]byte{1, 2, 3}); got != 0 {
		t.Errorf("garbage: %d", got)
	}
}
