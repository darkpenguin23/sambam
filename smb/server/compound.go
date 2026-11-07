package smb2

import (
	. "github.com/sambam/sambam/smb/internal/smb2"
)

type compoundContext struct {
	treeId     uint64
	sessionId  uint64
	fileId     *FileId
	lastStatus uint32
	lastMsgId  uint64
	// createStatus is the error of a CREATE that failed earlier in this
	// chain. Only that error is carried over to the related requests that
	// follow (MS-SMB2 3.3.5.2.7.2): they have no valid handle. A failure of
	// any other request must not stop the rest of the chain - in particular
	// its CLOSE, which would otherwise leak the handle.
	createStatus uint32

	rsp [][]byte
}

// compoundLastMsgId returns the message id of the request that ends the
// related chain starting at chain[0]: the responses of the chain are
// collected up to that request and sent together. It is computed before any
// request of the chain is dispatched. (It used to be assigned only when the
// receiver reached the last request, while the request loop was already
// reading it in sendPacket for the earlier ones: a data race.)
// It returns 0 if the chain has no such request, as before.
func compoundLastMsgId(chain []byte) uint64 {
	cur := chain
	for i := 0; ; i++ {
		p := PacketCodec(cur)
		if p.IsInvalid() {
			return 0
		}
		if i > 0 && p.IsCompoundFirst() {
			return 0 // a new chain starts before this one was closed
		}
		if p.IsCompoundLast() {
			return p.MessageId()
		}
		off := int(p.NextCommand())
		if off == 0 || off >= len(cur) {
			return 0
		}
		cur = cur[off:]
	}
}

// relatedCreateFailure returns the status a request has to be answered with
// because it is related to a CREATE that failed earlier in the chain.
func (ctx *compoundContext) relatedCreateFailure(p PacketCodec) (uint32, bool) {
	if ctx == nil || ctx.createStatus == 0 || p.Flags()&SMB2_FLAGS_RELATED_OPERATIONS == 0 {
		return 0, false
	}
	return ctx.createStatus, true
}

func (ctx *compoundContext) isEmpty() bool {
	return len(ctx.rsp) == 0
}

func (ctx *compoundContext) addResponse(pkt []byte) {
	ctx.rsp = append(ctx.rsp, pkt)
}

func (ctx *compoundContext) Size() int {
	s := 0
	for i, pkt := range ctx.rsp {
		if i != len(ctx.rsp)-1 {
			s += Align(len(pkt), 8)
		} else {
			s += len(pkt)
		}
	}
	return s
}

func (ctx *compoundContext) Encode(buf []byte) {
	off := 0
	for _, p := range ctx.rsp {
		pkt := PacketCodec(p)
		l := Align(len(p), 8)
		copy(buf[off:], pkt)
		off += l
	}
}
