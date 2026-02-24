package smb2

import "testing"

func TestQueryDirectoryRequestDecoderShortInputSafeAccessors(t *testing.T) {
	var r QueryDirectoryRequestDecoder = []byte{}

	if got := r.FileInfoClass(); got != 0 {
		t.Fatalf("FileInfoClass short input: got %d, want 0", got)
	}
	if got := r.Flags(); got != 0 {
		t.Fatalf("Flags short input: got %d, want 0", got)
	}
	if got := r.FileIndex(); got != 0 {
		t.Fatalf("FileIndex short input: got %d, want 0", got)
	}
	if got := r.OutputBufferLength(); got != 0 {
		t.Fatalf("OutputBufferLength short input: got %d, want 0", got)
	}
	if got := r.FileName(); got != "" {
		t.Fatalf("FileName short input: got %q, want empty", got)
	}
}

func TestQueryDirectoryRequestDecoderFileNameOffsetUnderflowSafe(t *testing.T) {
	// 32-byte header with valid structure size but invalid FileNameOffset (<64).
	b := make([]byte, 32)
	r := QueryDirectoryRequestDecoder(b)
	le.PutUint16(b[:2], 33)
	le.PutUint16(b[24:26], 10) // underflow if treated as uint16 - 64
	le.PutUint16(b[26:28], 4)

	if got := r.FileName(); got != "" {
		t.Fatalf("FileName underflow case: got %q, want empty", got)
	}
}
