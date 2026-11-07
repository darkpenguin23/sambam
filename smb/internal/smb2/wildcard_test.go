package smb2

import (
	"strings"
	"testing"
	"time"
)

func TestMatchWildcard(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		// Plain wildcards
		{"*", "anything.txt", true},
		{"*", "", true},
		{"*.txt", "a.txt", true},
		{"*.txt", "a.b.txt", true},
		{"*.txt", "abctxt", false}, // '.' is literal, not "any character"
		{"*.txt", "a.txt.bak", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		// Case-insensitive like Windows
		{"*.txt", "UPPER.TXT", true},
		{"README*", "readme.md", true},
		{"ÄBC*", "äbc.txt", true},
		// Regex metacharacters are literal
		{"photo (1)*", "photo (1).jpg", true},
		{"a+b*", "a+b.txt", true},
		{"a+b*", "aab.txt", false},
		{"[x]*", "[x].txt", true},
		{"[x]*", "x.txt", false},
		{"$HOME^", "$home^", true},
		{"a|b", "a", false},
		// DOS_STAR '<' (Windows `dir *.txt` sends "<.txt")
		{"<.txt", "a.txt", true},
		{"<.txt", "a.b.txt", true},
		{"<.txt", "a.txt.bak", false},
		{"<.txt", "atxt", false},
		// DOS_QM '>' (Windows `dir a?c.txt` sends "a>c.txt")
		{"a>c.txt", "abc.txt", true},
		{"a>c.txt", "a.c.txt", false},
		{"abc>>>", "abc", true}, // '>' matches nothing at the end
		{"abc>.txt", "abc.txt", true},
		// DOS_DOT '"' (Windows `dir *.` sends `<"`: names without extension)
		{`<"`, "README", true},
		{`<"`, "a.txt", false},
		{`abc"txt`, "abc.txt", true},
		{`abc"`, "abc", true},
	}
	for _, c := range cases {
		if got := MatchWildcard(c.name, c.pattern); got != c.want {
			t.Errorf("MatchWildcard(%q, %q) = %v, want %v", c.name, c.pattern, got, c.want)
		}
	}
}

func TestMatchWildcardHostilePatternIsFast(t *testing.T) {
	pattern := strings.Repeat("*a", 60) + "*b"
	name := strings.Repeat("a", 250)
	start := time.Now()
	if MatchWildcard(name, pattern) {
		t.Fatal("unexpected match")
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("hostile pattern took %v", d)
	}
}

func TestContainsWildcard(t *testing.T) {
	for _, s := range []string{"*", "a?b", "<.txt", "a>c", `abc"`} {
		if !ContainsWildcard(s) {
			t.Errorf("ContainsWildcard(%q) = false", s)
		}
	}
	for _, s := range []string{"", "file.txt", "photo (1).jpg", "a+b"} {
		if ContainsWildcard(s) {
			t.Errorf("ContainsWildcard(%q) = true", s)
		}
	}
}
