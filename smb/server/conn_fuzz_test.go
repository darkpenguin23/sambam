package smb2

import (
	"crypto/cipher"
	"errors"
	"testing"

	. "github.com/sambam/sambam/smb/internal/smb2"
)

type fuzzAEAD struct{}

func (fuzzAEAD) NonceSize() int { return 11 }
func (fuzzAEAD) Overhead() int  { return 16 }
func (fuzzAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return append(dst, plaintext...)
}
func (fuzzAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return nil, errors.New("fuzz decrypt stub")
}

var _ cipher.AEAD = fuzzAEAD{}

func seedSMB2Packet() []byte {
	b := make([]byte, 64)
	p := PacketCodec(b)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(SMB2_ECHO)
	return b
}

func seedSMB311Transform() []byte {
	b := make([]byte, 52+64)
	t := TransformCodec(b)
	t.SetProtocolId()
	t.SetSessionId(0x1111)
	t.SetOriginalMessageSize(64)
	t.SetFlags(Encrypted)
	return b
}

func seedSMB300Transform() []byte {
	b := make([]byte, 52+64)
	t := TransformCodec(b)
	t.SetProtocolId()
	t.SetSessionId(0x2222)
	t.SetOriginalMessageSize(64)
	t.SetEncryptionAlgorithm(AES128CCM)
	return b
}

func FuzzValidateCompoundAndTransformMetadata(f *testing.F) {
	f.Add(seedSMB2Packet(), uint8(0))
	f.Add(seedSMB311Transform(), uint8(1))
	f.Add(seedSMB300Transform(), uint8(2))
	f.Add([]byte{}, uint8(0))
	f.Add([]byte{0xfd, 'S', 'M', 'B'}, uint8(1))

	f.Fuzz(func(t *testing.T, data []byte, mode uint8) {
		if len(data) > maxDirectTCPSize+1024 {
			t.Skip()
		}

		// Must never panic regardless of malformed frame input.
		_ = validateSMB2CompoundFrame(data)

		dialect := uint16(SMB311)
		switch mode % 3 {
		case 1:
			dialect = uint16(SMB300)
		case 2:
			dialect = uint16(SMB302)
		}

		c := &conn{
			dialect:  dialect,
			sessions: map[uint64]*session{},
		}

		// If input looks like a transform header, provision a matching session
		// so tryDecrypt can traverse metadata checks and decrypt path safely.
		tp := TransformCodec(data)
		if !tp.IsInvalid() {
			c.sessions[tp.SessionId()] = &session{
				sessionId:    tp.SessionId(),
				cipherId:     AES128CCM,
				decrypter:    fuzzAEAD{},
				sessionFlags: SMB2_SESSION_FLAG_ENCRYPT_DATA,
			}
		}

		_, _, _ = c.tryDecrypt(data)
	})
}
