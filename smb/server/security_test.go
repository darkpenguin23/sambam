package smb2

import (
	"bytes"
	"testing"

	"github.com/sambam/sambam/smb/internal/ntlm"
)

func TestShareRelativePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{`file.txt`, "file.txt", true},
		{`dir\sub\file.txt`, "dir/sub/file.txt", true},
		{`dir\file.txt:stream`, "dir/file.txt:stream", true},
		{`..file`, "..file", true},
		{`dir\..x\file`, "dir/..x/file", true},
		{`.\file`, "./file", true},
		{`..`, "", false},
		{`..\secret`, "", false},
		{`dir\..\..\secret`, "", false},
		{`dir/../secret`, "", false},
		{`\..\secret`, "", false},
		{`..:stream`, "", false},
	}
	for _, c := range cases {
		got, ok := shareRelativePath(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("shareRelativePath(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// Two authentication exchanges created from the same template authenticator
// must not share handshake state, even when their steps interleave. With the
// former server-wide authenticator the second challenge replaced the first,
// so the first client's response was checked against the wrong challenge.
func TestSpnegoExchangesAreIsolated(t *testing.T) {
	tmpl := &NTLMAuthenticator{
		UserPassword: map[string]string{"alice": "pw-alice", "bob": "pw-bob"},
		NbName:       "SRV",
		NbDomain:     "SRV",
		DnsName:      "srv.local",
		DnsDomain:    ".local",
	}
	a := newSpnegoServer([]Authenticator{tmpl})
	b := newSpnegoServer([]Authenticator{tmpl})
	ca := &ntlm.Client{User: "alice", Password: "pw-alice"}
	cb := &ntlm.Client{User: "bob", Password: "pw-bob"}

	na, err := ca.Negotiate()
	if err != nil {
		t.Fatal(err)
	}
	nb, err := cb.Negotiate()
	if err != nil {
		t.Fatal(err)
	}
	// Both challenges are issued before either client answers.
	chA, err := a.challenge(na)
	if err != nil {
		t.Fatal(err)
	}
	chB, err := b.challenge(nb)
	if err != nil {
		t.Fatal(err)
	}
	amA, err := ca.Authenticate(chA)
	if err != nil {
		t.Fatal(err)
	}
	amB, err := cb.Authenticate(chB)
	if err != nil {
		t.Fatal(err)
	}

	if _, user, err := a.authenticate(amA); err != nil || user != "alice" {
		t.Fatalf("exchange A: user=%q err=%v", user, err)
	}
	if _, user, err := b.authenticate(amB); err != nil || user != "bob" {
		t.Fatalf("exchange B: user=%q err=%v", user, err)
	}
	if bytes.Equal(a.sessionKey(), b.sessionKey()) {
		t.Fatal("both exchanges ended up with the same session key")
	}
	if tmpl.ntlm != nil {
		t.Fatal("template authenticator was mutated")
	}
}

func TestSpnegoAuthenticateWithoutChallengeFails(t *testing.T) {
	s := newSpnegoServer([]Authenticator{&NTLMAuthenticator{}})
	mustNotPanicServer(t, func() {
		if _, _, err := s.authenticate([]byte("NTLMSSP\x00\x03\x00\x00\x00")); err == nil {
			t.Fatal("authenticate without challenge succeeded")
		}
	})
}
