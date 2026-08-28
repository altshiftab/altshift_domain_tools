// Package wordlist carries the subdomain names the brute force asks about.
//
// The list is embedded rather than read from a path so that a caller needs nothing beside the
// binary. A caller with a list of its own passes that instead: brute.Lookup takes a sequence, and
// this is only the default one.
package wordlist

import (
	_ "embed"
	"iter"
	"strings"
)

// subdomains is the default list: the most common leading labels, most frequent first, so a run cut
// short by a deadline has still asked about the names most likely to exist.
//
//go:embed subdomains.txt
var subdomains string

// Names iterates the default list. It is a sequence rather than a slice so the brute force streams
// it: the list is thousands of names, and nothing needs them all in hand at once.
func Names() iter.Seq[string] {
	return func(yield func(string) bool) {
		for line := range strings.SplitSeq(subdomains, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !yield(line) {
				return
			}
		}
	}
}

// Len is how many names the default list holds.
func Len() int {
	count := 0
	for range Names() {
		count++
	}

	return count
}
