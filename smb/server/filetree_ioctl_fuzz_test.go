package smb2

import (
	"context"
	"testing"

	. "github.com/sambam/sambam/smb/internal/smb2"
)

type fuzzInput []byte

func (f fuzzInput) Size() int { return len(f) }
func (f fuzzInput) Encode(pkt []byte) {
	copy(pkt, f)
}

func mustNotPanicServer(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("fileTree.ioctl panicked: %v", r)
		}
	}()
	fn()
}

func makeIoctlPacket(ctl uint32, fileID FileId, input []byte) []byte {
	req := &IoctlRequest{
		CtlCode:           ctl,
		FileId:            &fileID,
		MaxInputResponse:  1024,
		MaxOutputResponse: 4096,
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
		Input:             fuzzInput(input),
	}
	pkt := make([]byte, req.Size())
	req.Encode(pkt)
	return pkt
}

func fuzzFileTreeIoctlHarness() *fileTree {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // force sendPacket to take context-done path (no transport needed)

	c := &conn{
		ctx:            ctx,
		account:        openAccount(32),
		sessions:       map[uint64]*session{},
		treeMapByName:  map[string]treeOps{},
		treeMapById:    map[uint32]treeOps{},
		serverState:    STATE_SESSION_ACTIVE,
		sequenceWindow: 1,
	}
	s := &session{
		conn:         c,
		sessionId:    1,
		sessionFlags: SMB2_SESSION_FLAG_IS_GUEST, // avoid signing/encryption in protectPacket
	}
	c.session = s

	return &fileTree{
		treeConn: treeConn{
			session: s,
			treeId:  1,
		},
	}
}

func FuzzFileTreeIoctlDispatchNoPanic(f *testing.F) {
	invalidID := INVALID_GUID
	validID := FileId{
		Persistent: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Volatile:   [8]byte{8, 7, 6, 5, 4, 3, 2, 1},
	}

	f.Add(makeIoctlPacket(0xdeadbeef, validID, []byte{0x01, 0x02, 0x03}))
	f.Add(makeIoctlPacket(FSCTL_GET_REPARSE_POINT, invalidID, nil))
	f.Add(makeIoctlPacket(FSCTL_DELETE_REPARSE_POINT, invalidID, nil))
	f.Add(makeIoctlPacket(FSCTL_CREATE_OR_GET_OBJECT_ID, invalidID, nil))
	f.Add(makeIoctlPacket(FSCTL_SET_REPARSE_POINT, invalidID, []byte{0x00, 0x00, 0x00, 0x00}))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, pkt []byte) {
		if len(pkt) > maxDirectTCPSize+1024 {
			t.Skip()
		}

		ft := fuzzFileTreeIoctlHarness()

		mustNotPanicServer(t, func() {
			_ = ft.ioctl(nil, pkt)
		})
	})
}
