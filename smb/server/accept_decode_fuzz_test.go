package smb2

import (
	"testing"

	. "github.com/sambam/sambam/smb/internal/erref"
	. "github.com/sambam/sambam/smb/internal/smb2"
)

func seedAcceptPacket(cmd uint16, status uint32, serverToRedir bool) []byte {
	b := make([]byte, 64)
	p := PacketCodec(b)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(cmd)
	p.SetStatus(status)
	if serverToRedir {
		p.SetFlags(SMB2_FLAGS_SERVER_TO_REDIR)
	}
	return b
}

func seedAcceptCompound() []byte {
	b := make([]byte, 128)
	p1 := PacketCodec(b[:64])
	p1.SetProtocolId()
	p1.SetStructureSize()
	p1.SetCommand(SMB2_ECHO)
	p1.SetNextCommand(64)

	p2 := PacketCodec(b[64:])
	p2.SetProtocolId()
	p2.SetStructureSize()
	p2.SetCommand(SMB2_ECHO)
	return b
}

func fuzzDecodeByCommand(cmd uint16, data []byte) {
	switch cmd {
	case SMB2_NEGOTIATE:
		_ = NegotiateRequestDecoder(data).IsInvalid()
		_ = NegotiateResponseDecoder(data).IsInvalid()
	case SMB2_SESSION_SETUP:
		_ = SessionSetupRequestDecoder(data).IsInvalid()
		_ = SessionSetupResponseDecoder(data).IsInvalid()
	case SMB2_LOGOFF:
		_ = LogoffRequestDecoder(data).IsInvalid()
		_ = LogoffResponseDecoder(data).IsInvalid()
	case SMB2_TREE_CONNECT:
		_ = TreeConnectRequestDecoder(data).IsInvalid()
		_ = TreeConnectResponseDecoder(data).IsInvalid()
	case SMB2_TREE_DISCONNECT:
		_ = TreeDisconnectRequestDecoder(data).IsInvalid()
		_ = TreeDisconnectResponseDecoder(data).IsInvalid()
	case SMB2_CREATE:
		_ = CreateRequestDecoder(data).IsInvalid()
		_ = CreateResponseDecoder(data).IsInvalid()
	case SMB2_CLOSE:
		_ = CloseRequestDecoder(data).IsInvalid()
		_ = CloseResponseDecoder(data).IsInvalid()
	case SMB2_FLUSH:
		_ = FlushRequestDecoder(data).IsInvalid()
		_ = FlushResponseDecoder(data).IsInvalid()
	case SMB2_READ:
		_ = ReadRequestDecoder(data).IsInvalid()
		_ = ReadResponseDecoder(data).IsInvalid()
	case SMB2_WRITE:
		_ = WriteRequestDecoder(data).IsInvalid()
		_ = WriteResponseDecoder(data).IsInvalid()
	case SMB2_IOCTL:
		_ = IoctlRequestDecoder(data).IsInvalid()
		_ = IoctlResponseDecoder(data).IsInvalid()
	case SMB2_CANCEL:
		_ = CancelRequestDecoder(data).IsInvalid()
	case SMB2_QUERY_DIRECTORY:
		_ = QueryDirectoryRequestDecoder(data).IsInvalid()
		_ = QueryDirectoryResponseDecoder(data).IsInvalid()
	case SMB2_CHANGE_NOTIFY:
		_ = ChangeNotifyRequestDecoder(data).IsInvalid()
	case SMB2_QUERY_INFO:
		_ = QueryInfoRequestDecoder(data).IsInvalid()
		_ = QueryInfoResponseDecoder(data).IsInvalid()
	case SMB2_SET_INFO:
		_ = SetInfoRequestDecoder(data).IsInvalid()
		_ = SetInfoResponseDecoder(data).IsInvalid()
	}
}

func FuzzAcceptAndCommandDecoders(f *testing.F) {
	f.Add(seedAcceptPacket(SMB2_ECHO, 0, false), uint8(0))
	f.Add(seedAcceptPacket(SMB2_NEGOTIATE, 0, false), uint8(1))
	f.Add(seedAcceptPacket(SMB2_SESSION_SETUP, uint32(STATUS_MORE_PROCESSING_REQUIRED), true), uint8(2))
	f.Add(seedAcceptCompound(), uint8(3))
	f.Add([]byte{}, uint8(0))
	f.Add([]byte{0xfe, 'S', 'M', 'B'}, uint8(4))

	cmds := []uint16{
		SMB2_NEGOTIATE,
		SMB2_SESSION_SETUP,
		SMB2_LOGOFF,
		SMB2_TREE_CONNECT,
		SMB2_TREE_DISCONNECT,
		SMB2_CREATE,
		SMB2_CLOSE,
		SMB2_FLUSH,
		SMB2_READ,
		SMB2_WRITE,
		SMB2_IOCTL,
		SMB2_CANCEL,
		SMB2_QUERY_DIRECTORY,
		SMB2_CHANGE_NOTIFY,
		SMB2_QUERY_INFO,
		SMB2_SET_INFO,
		SMB2_ECHO,
	}

	f.Fuzz(func(t *testing.T, data []byte, cmdSel uint8) {
		if len(data) > maxDirectTCPSize+1024 {
			t.Skip()
		}

		// Walk/validate compound shape first; malformed frames are expected.
		_ = validateSMB2CompoundFrame(data)

		cmd := cmds[int(cmdSel)%len(cmds)]
		_, _ = accept(cmd, data)

		// Decoder entry-point safety for first packet segment.
		p := PacketCodec(data)
		if p.IsInvalid() {
			return
		}
		reqCmd := p.Command()
		fuzzDecodeByCommand(reqCmd, p.Data())
		fuzzDecodeByCommand(cmd, p.Data())
	})
}
