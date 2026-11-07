package smb2

import (
	"encoding/asn1"

	"github.com/sambam/sambam/smb/internal/ntlm"
	"github.com/sambam/sambam/smb/internal/spnego"
)

type Authenticator interface {
	oid() asn1.ObjectIdentifier
	challenge(sc []byte) ([]byte, error)
	authenticate(sc []byte) (string, error)
	sum(bs []byte) []byte // GSS_getMIC
	sessionKey() []byte   // QueryContextAttributes(ctx, SECPKG_ATTR_SESSION_KEY, &out)
	// clone returns an authenticator with the same configuration and fresh
	// handshake state. Authenticators are stateful (challenge, session key),
	// so every authentication exchange must run on its own clone.
	clone() Authenticator
}

// NTLMAuthenticator implements session-setup through NTLMv2.
// It doesn't support NTLMv1. You can use Hash instead of Password.
type NTLMAuthenticator struct {
	UserPassword map[string]string
	TargetSPN    string
	NbDomain     string
	NbName       string
	DnsName      string
	DnsDomain    string
	AllowGuest   bool

	ntlm   *ntlm.Server
	seqNum uint32
}

func (i *NTLMAuthenticator) clone() Authenticator {
	return &NTLMAuthenticator{
		UserPassword: i.UserPassword, // read-only after server start
		TargetSPN:    i.TargetSPN,
		NbDomain:     i.NbDomain,
		NbName:       i.NbName,
		DnsName:      i.DnsName,
		DnsDomain:    i.DnsDomain,
		AllowGuest:   i.AllowGuest,
	}
}

func (i *NTLMAuthenticator) oid() asn1.ObjectIdentifier {
	return spnego.NlmpOid
}

func (i *NTLMAuthenticator) challenge(sc []byte) ([]byte, error) {
	i.ntlm = ntlm.NewServer(i.TargetSPN, i.NbName, i.NbDomain, i.DnsName, i.DnsDomain)
	for u, p := range i.UserPassword {
		i.ntlm.AddAccount(u, p)
	}
	if i.AllowGuest {
		i.ntlm.AllowGuest()
	}

	nmsg, err := i.ntlm.Challenge(sc)
	if err != nil {
		return nil, err
	}
	return nmsg, nil
}

func (i *NTLMAuthenticator) authenticate(sc []byte) (string, error) {
	err := i.ntlm.Authenticate(sc)
	if err == nil {
		return i.ntlm.Session().User(), nil
	}
	return "", err
}

func (i *NTLMAuthenticator) sum(bs []byte) []byte {
	mic, _ := i.ntlm.Session().Sum(bs, i.seqNum)
	return mic
}

func (i *NTLMAuthenticator) sessionKey() []byte {
	return i.ntlm.Session().SessionKey()
}

func (i *NTLMAuthenticator) infoMap() *ntlm.InfoMap {
	return i.ntlm.Session().InfoMap()
}
