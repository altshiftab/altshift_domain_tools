package wordlist

import (
	"slices"
	"strings"
	"testing"
)

// TestNames holds what the brute force relies on: the list is non-empty, carries leading labels
// rather than whole names, and has nothing in it that would be asked about verbatim.
func TestNames(t *testing.T) {
	t.Parallel()

	names := slices.Collect(Names())

	if len(names) < 1000 {
		t.Fatalf("expected a substantial list, got %d names", len(names))
	}

	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" {
			t.Error("the list carries an empty name, which would ask about the domain itself")
		}
		if strings.ContainsAny(name, " \t\r") {
			t.Errorf("the name %q carries whitespace", name)
		}
		// A whole hostname rather than a leading label would ask about
		// "ferrari.fortwayne.com.example.com", which is nobody's host. Multi-label prefixes are
		// wanted -- "www.blog", "autodiscover.blog" -- and so is a two-label one whose second half
		// reads like a top level domain, because "www.info.example.com" is a host someone may well
		// have. What gives an escaped hostname away is having three or more labels and ending in a
		// real one.
		if labels := strings.Split(name, "."); len(labels) >= 3 {
			switch labels[len(labels)-1] {
			case "com", "net", "org", "edu", "gov":
				t.Errorf("the name %q is a whole hostname rather than a leading label", name)
			}
		}
		if _, ok := seen[name]; ok {
			t.Errorf("the name %q appears more than once, which costs a lookup for nothing", name)
		}
		seen[name] = struct{}{}
	}

	// The most common names should be in it, or it is not the list it claims to be.
	for _, expected := range []string{"www", "mail", "ftp", "smtp"} {
		if !slices.Contains(names, expected) {
			t.Errorf("expected the list to carry %q", expected)
		}
	}
}

func TestLen(t *testing.T) {
	t.Parallel()

	if got, expected := Len(), len(slices.Collect(Names())); got != expected {
		t.Errorf("expected %d, got %d", expected, got)
	}
}

// TestNamesCanBeStoppedEarly holds that the sequence is lazy: a caller that stops reading is not
// made to walk the whole list.
func TestNamesCanBeStoppedEarly(t *testing.T) {
	t.Parallel()

	count := 0
	for range Names() {
		count++
		if count == 3 {
			break
		}
	}

	if count != 3 {
		t.Errorf("expected the sequence to stop when the caller does, got %d", count)
	}
}
