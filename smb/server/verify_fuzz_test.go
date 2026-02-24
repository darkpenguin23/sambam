package smb2

import (
	"crypto/sha256"
	"testing"

	. "github.com/sambam/sambam/smb/internal/smb2"
)

func seedVerifySinglePacket() []byte {
	b := make([]byte, 64)
	p := PacketCodec(b)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(SMB2_ECHO)
	p.SetMessageId(1)
	p.SetSessionId(0x1234)
	return b
}

func seedVerifyCompoundPacket() []byte {
	b := make([]byte, 128)

	p1 := PacketCodec(b[:64])
	p1.SetProtocolId()
	p1.SetStructureSize()
	p1.SetCommand(SMB2_ECHO)
	p1.SetMessageId(1)
	p1.SetSessionId(0x1234)
	p1.SetNextCommand(64)

	p2 := PacketCodec(b[64:])
	p2.SetProtocolId()
	p2.SetStructureSize()
	p2.SetCommand(SMB2_ECHO)
	p2.SetMessageId(2)
	p2.SetSessionId(0x1234)

	return b
}

func walkCompound(frame []byte, fn func(seg []byte)) {
	cur := frame
	for {
		p := PacketCodec(cur)
		if p.IsInvalid() {
			return
		}
		off := p.NextCommand()
		if off == 0 {
			fn(cur)
			return
		}
		fn(cur[:off])
		cur = cur[off:]
	}
}

func FuzzCompoundChainAndSignatureVerification(f *testing.F) {
	f.Add(seedVerifySinglePacket(), uint8(0), uint8(0), uint8(0))
	f.Add(seedVerifyCompoundPacket(), uint8(1), uint8(1), uint8(0))
	f.Add([]byte{}, uint8(0), uint8(0), uint8(0))

	f.Fuzz(func(t *testing.T, data []byte, require uint8, guest uint8, encrypted uint8) {
		if len(data) > maxDirectTCPSize+1024 {
			t.Skip()
		}

		// Never panic on malformed compound chains.
		if err := validateSMB2CompoundFrame(data); err != nil {
			return
		}

		c := &conn{
			requireSigning: require%2 == 1,
			sessions:       map[uint64]*session{},
		}

		walkCompound(data, func(seg []byte) {
			p := PacketCodec(seg)
			if p.IsInvalid() {
				return
			}

			flags := uint16(0)
			if guest%2 == 1 {
				flags = SMB2_SESSION_FLAG_IS_GUEST
			}

			c.sessions[p.SessionId()] = &session{
				sessionId:      p.SessionId(),
				sessionFlags:   flags,
				verifier:       sha256.New(),
				treeConnTables: map[uint32]*treeConn{},
			}

			// Exercise both signed and unsigned paths using fuzz-controlled bit.
			if require&2 == 2 {
				p.SetFlags(p.Flags() | SMB2_FLAGS_SIGNED)
			}

			_ = c.tryVerify(seg, encrypted%2 == 1)
		})
	})
}
