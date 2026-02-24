package smb2

import "testing"

func makeValidSMB2Packet(size int) PacketCodec {
	p := make([]byte, size)
	c := PacketCodec(p)
	c.SetProtocolId()
	c.SetStructureSize()
	c.SetCommand(SMB2_ECHO)
	return c
}

func TestPacketCodecIsInvalidNextCommandTooSmall(t *testing.T) {
	p := makeValidSMB2Packet(128)
	p.SetNextCommand(8)
	if !p.IsInvalid() {
		t.Fatalf("expected packet with NextCommand < 64 to be invalid")
	}
}

func TestPacketCodecIsInvalidNextCommandLeavesShortTail(t *testing.T) {
	p := makeValidSMB2Packet(128)
	p.SetNextCommand(72) // 56-byte tail < SMB2 header size.
	if !p.IsInvalid() {
		t.Fatalf("expected packet with short next segment to be invalid")
	}
}

func TestTransformCodecIsInvalidShortPayload(t *testing.T) {
	b := make([]byte, 52+10)
	tp := TransformCodec(b)
	tp.SetProtocolId()
	tp.SetOriginalMessageSize(64)
	if !tp.IsInvalid() {
		t.Fatalf("expected transform with short payload to be invalid")
	}
}

func TestTransformCodecIsInvalidSmallOriginalSize(t *testing.T) {
	b := make([]byte, 52+64)
	tp := TransformCodec(b)
	tp.SetProtocolId()
	tp.SetOriginalMessageSize(32)
	if !tp.IsInvalid() {
		t.Fatalf("expected transform with small original size to be invalid")
	}
}
