package smb2

import (
	"bytes"
	"crypto/cipher"
	"hash"
	"math/rand"

	. "github.com/sambam/sambam/smb/internal/smb2"
)

var zero [16]byte

type session struct {
	conn                      *conn
	treeConnTables            map[uint32]*treeConn
	sessionFlags              uint16
	sessionId                 uint64
	username                  string
	cipherId                  uint16
	preauthIntegrityHashValue [64]byte

	signer    hash.Hash
	verifier  hash.Hash
	encrypter cipher.AEAD
	decrypter cipher.AEAD

	// applicationKey []byte
}

func (s *session) sign(pkt []byte) []byte {
	p := PacketCodec(pkt)

	p.SetFlags(p.Flags() | SMB2_FLAGS_SIGNED)

	h := s.signer

	h.Reset()

	h.Write(pkt)

	p.SetSignature(h.Sum(nil))

	return pkt
}

func (s *session) verify(pkt []byte) (ok bool) {
	p := PacketCodec(pkt)

	signature := append([]byte{}, p.Signature()...)

	p.SetSignature(zero[:])

	if s.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) == 0 {
		if s.verifier == nil {
			return false
		}
		h := s.verifier

		h.Reset()

		h.Write(pkt)

		p.SetSignature(h.Sum(nil))
	}

	return bytes.Equal(signature, p.Signature())
}

func (s *session) encrypt(pkt []byte) ([]byte, error) {
	nonce := make([]byte, s.encrypter.NonceSize())

	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	c := make([]byte, 52+len(pkt)+16)

	t := TransformCodec(c)

	t.SetProtocolId()
	t.SetNonce(nonce)
	t.SetOriginalMessageSize(uint32(len(pkt)))
	if s.conn != nil && s.conn.dialect == SMB311 {
		t.SetFlags(Encrypted)
	} else {
		t.SetEncryptionAlgorithm(s.cipherId)
	}
	t.SetSessionId(s.sessionId)

	s.encrypter.Seal(c[:52], nonce, pkt, t.AssociatedData())

	t.SetSignature(c[len(c)-16:])

	c = c[:len(c)-16]

	return c, nil
}

func (s *session) decrypt(pkt []byte) ([]byte, error) {
	t := TransformCodec(pkt)

	c := append(t.EncryptedData(), t.Signature()...)

	return s.decrypter.Open(
		c[:0],
		t.Nonce()[:s.decrypter.NonceSize()],
		c,
		t.AssociatedData(),
	)
}
