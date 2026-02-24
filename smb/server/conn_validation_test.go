package smb2

import (
	"testing"

	. "github.com/sambam/sambam/smb/internal/smb2"
)

func makeHeaderPacket(size int, cmd uint16) []byte {
	b := make([]byte, size)
	p := PacketCodec(b)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(cmd)
	return b
}

func TestValidateSMB2CompoundFrameSinglePacket(t *testing.T) {
	pkt := makeHeaderPacket(64, SMB2_ECHO)
	if err := validateSMB2CompoundFrame(pkt); err != nil {
		t.Fatalf("expected valid single packet, got error: %v", err)
	}
}

func TestValidateSMB2CompoundFrameInvalidNextOffset(t *testing.T) {
	pkt := makeHeaderPacket(128, SMB2_ECHO)
	p := PacketCodec(pkt)
	p.SetNextCommand(64)

	// Corrupt second segment so the tail is not a valid SMB2 packet.
	copy(pkt[64:68], []byte{0, 0, 0, 0})

	if err := validateSMB2CompoundFrame(pkt); err == nil {
		t.Fatalf("expected invalid compound frame error")
	}
}

func makeTransformPacket(sessionID uint64, size int) []byte {
	b := make([]byte, size)
	t := TransformCodec(b)
	t.SetProtocolId()
	t.SetSessionId(sessionID)
	t.SetOriginalMessageSize(64)
	return b
}

func TestTryDecryptRejectsSMB311WithoutEncryptedFlag(t *testing.T) {
	c := &conn{
		dialect: SMB311,
		sessions: map[uint64]*session{
			42: {sessionId: 42},
		},
	}
	pkt := makeTransformPacket(42, 52+64)
	// SMB3.1.1 requires the encrypted flag in bytes 42:44.
	TransformCodec(pkt).SetFlags(0)

	_, err, _ := c.tryDecrypt(pkt)
	if err == nil {
		t.Fatalf("expected decrypt validation error for missing encrypted flag")
	}
}

func TestTryDecryptRejectsUnsupportedTransformAlgorithm(t *testing.T) {
	c := &conn{
		dialect: SMB300,
		sessions: map[uint64]*session{
			7: {sessionId: 7},
		},
	}
	pkt := makeTransformPacket(7, 52+64)
	TransformCodec(pkt).SetEncryptionAlgorithm(0x9999)

	_, err, _ := c.tryDecrypt(pkt)
	if err == nil {
		t.Fatalf("expected decrypt validation error for unsupported algorithm")
	}
}

func TestTryDecryptRejectsTransformAlgorithmMismatch(t *testing.T) {
	c := &conn{
		dialect: SMB300,
		sessions: map[uint64]*session{
			9: {sessionId: 9, cipherId: AES128GCM},
		},
	}
	pkt := makeTransformPacket(9, 52+64)
	TransformCodec(pkt).SetEncryptionAlgorithm(AES128CCM)

	_, err, _ := c.tryDecrypt(pkt)
	if err == nil {
		t.Fatalf("expected decrypt validation error for algorithm mismatch")
	}
}
