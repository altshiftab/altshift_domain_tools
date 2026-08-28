package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
)

// commands is every subcommand the program declares, built fresh so a test cannot see another's
// parsed values.
func commands(t *testing.T) []*command {
	t.Helper()

	return []*command{newSubdomainsCommand(), newRelatedCommand(), newRangesCommand()}
}

// TestParsersValidate holds what Validate is for: a duplicated option name, a group naming an
// option that does not exist, or a choice the option cannot read is a mistake in this program
// rather than in what the user typed, and should surface at startup rather than on the parse that
// happens to reach it.
func TestParsersValidate(t *testing.T) {
	t.Parallel()

	for _, subcommand := range commands(t) {
		t.Run(subcommand.GetCommand(), func(t *testing.T) {
			t.Parallel()

			if err := subcommand.parser.Validate(); err != nil {
				t.Errorf("%s: %v", subcommand.GetCommand(), err)
			}
		})
	}

	root := &argument_parser.Parser{ProgramName: programName, Description: "d"}
	if err := root.Validate(); err != nil {
		t.Errorf("root: %v", err)
	}
}

// TestRootDispatches holds that a run knows which of three things was asked for. The parser fills
// in the values bound to it, which says what was asked but not which subcommand asked it.
func TestRootDispatches(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		args   []string
		expect string
	}{
		{name: "subdomains", args: []string{"subdomains", "example.com"}, expect: "subdomains"},
		{name: "related", args: []string{"related", "example.com"}, expect: "related"},
		{name: "ranges", args: []string{"ranges", "example.com"}, expect: "ranges"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			subcommands := commands(t)

			parsers := make([]argument_parser.Subparser, 0, len(subcommands))
			for _, subcommand := range subcommands {
				parsers = append(parsers, subcommand)
			}

			parser := &argument_parser.Parser{ProgramName: programName, Parsers: parsers}

			if err := parser.ParseArgs(testCase.args); err != nil {
				t.Fatalf("%s: %v", testCase.name, err)
			}

			chosen := make([]string, 0, 1)
			for _, subcommand := range subcommands {
				if subcommand.chosen {
					chosen = append(chosen, subcommand.GetCommand())
				}
			}

			if !slices.Equal(chosen, []string{testCase.expect}) {
				t.Errorf("%s: expected only %q to run, got %v", testCase.name, testCase.expect, chosen)
			}
		})
	}
}

func TestSubdomainsParsing(t *testing.T) {
	t.Parallel()

	settings := &subdomainsSettings{}
	subcommand := newSubdomainsCommandWith(settings)

	if err := subcommand.parser.ParseArgs([]string{"-b", "-c", "8", "-r", "9.9.9.9:53", "example.com"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if settings.domain != "example.com" || !settings.brute {
		t.Errorf("expected the domain and the brute flag, got %+v", settings)
	}
	if settings.concurrency != 8 || settings.resolver != "9.9.9.9:53" {
		t.Errorf("expected the given resolver and concurrency, got %+v", settings)
	}
}

// TestSubdomainsDefaults holds that the wordlist pass is opt-in. It is visible in the target's
// logs, so a run that did not ask for it must not do it.
func TestSubdomainsDefaults(t *testing.T) {
	t.Parallel()

	settings := &subdomainsSettings{}
	subcommand := newSubdomainsCommandWith(settings)

	if err := subcommand.parser.ParseArgs([]string{"example.com"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if settings.brute {
		t.Error("expected the wordlist pass to be off unless asked for")
	}
	if settings.resolver == "" || settings.concurrency == 0 {
		t.Errorf("expected the declared defaults to be applied, got %+v", settings)
	}
}

// TestNoOptionTakesAKeyDirectly holds the reason the key options take a path. An argument is
// visible in the process table to every user on the machine, which is a poor place for a
// credential that bills to an account.
func TestNoOptionTakesAKeyDirectly(t *testing.T) {
	t.Parallel()

	for _, subcommand := range commands(t) {
		for _, declared := range subcommand.parser.Options {
			name := declared.GetLongName()
			if !strings.Contains(name, "key") && !strings.Contains(name, "token") {
				continue
			}

			if !strings.HasSuffix(name, "-file") {
				t.Errorf(
					"%s: option %q takes a credential as an argument; it should take a path",
					subcommand.GetCommand(), name,
				)
			}
		}
	}
}

//nolint:paralleltest // t.Setenv sets the process environment, which no parallel test may do.
func TestReadKey(t *testing.T) {
	// A file is the first place looked, and its whitespace is not part of the key: a key written
	// with a trailing newline is the ordinary case.
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("  the-key\n"), 0o600); err != nil {
		t.Fatalf("could not write the key file: %v", err)
	}

	key, err := readKey(path, "ADT_TEST_KEY_UNSET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "the-key" {
		t.Errorf("expected the key trimmed, got %q", key)
	}

	// Without a file the environment answers.
	t.Setenv("ADT_TEST_KEY", "from-the-environment")
	key, err = readKey("", "ADT_TEST_KEY")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "from-the-environment" {
		t.Errorf("expected the environment to be read, got %q", key)
	}

	// Neither is not an error here: the caller decides whether a missing key matters, because one
	// source having none does not stop the other.
	key, err = readKey("", "ADT_TEST_KEY_UNSET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "" {
		t.Errorf("expected nothing, got %q", key)
	}

	// A file that is not there is an error rather than an empty key, because a caller that named
	// one meant it.
	if _, err := readKey(filepath.Join(t.TempDir(), "absent"), "ADT_TEST_KEY_UNSET"); err == nil {
		t.Error("expected a missing key file to be an error")
	}
}
