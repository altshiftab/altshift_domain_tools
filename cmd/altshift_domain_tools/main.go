// Command altshift_domain_tools reports what can be learned about a domain from outside it.
//
// Three subcommands, one per question the library answers: what hangs off this domain, what else
// its owner has, and what address space its owner holds. They are one program rather than three
// because they are usually run together against the same domain, and because a caller reaching for
// one commonly wants to know the others exist.
//
// Output is one item per line by default, so a run pipes into whatever comes next the way the shell
// scripts this replaces did. Everything the library knows -- how each result was found, and how
// much that is worth -- is on --json, because a line of text has nowhere to put it.
package main

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
)

// programName is what the usage message and the error prefixes call this.
const programName = "altshift_domain_tools"

// command is one subcommand: a parser, and what to run once it has parsed.
//
// It wraps a parser rather than being one so that a run knows which subcommand was chosen. The
// parser dispatches by filling in the values bound to it, which tells the caller what was asked for
// but not which of three things was asked.
type command struct {
	parser *argument_parser.Parser
	run    func(context.Context) error
	chosen bool
}

func (subcommand *command) GetCommand() string {
	return subcommand.parser.Command
}

// GetDescription lets the root parser describe this subcommand in its own help.
func (subcommand *command) GetDescription() string {
	return subcommand.parser.Description
}

// GetParser says what this wraps, so a completion can see the subcommand's options rather than only
// its name.
func (subcommand *command) GetParser() *argument_parser.Parser {
	return subcommand.parser
}

func (subcommand *command) ParseArgs(arguments []string) error {
	subcommand.chosen = true

	return subcommand.parser.ParseArgs(arguments)
}

// emit writes the value as indented JSON, which is what --json produces.
func emit(value any) error {
	data, err := json.Marshal(value, jsontext.WithIndent("  "))
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}

	if _, err := fmt.Fprintf(os.Stdout, "%s\n", data); err != nil {
		return fmt.Errorf("fprintf: %w", err)
	}

	return nil
}

// emitLines writes one item per line, which is the default and what a pipeline wants.
func emitLines(lines []string) error {
	for _, line := range lines {
		if _, err := fmt.Fprintln(os.Stdout, line); err != nil {
			return fmt.Errorf("fprintln: %w", err)
		}
	}

	return nil
}

func main() {
	subcommands := []*command{newSubdomainsCommand(), newRelatedCommand(), newRangesCommand()}

	parsers := make([]argument_parser.Subparser, 0, len(subcommands))
	for _, subcommand := range subcommands {
		parsers = append(parsers, subcommand)

		// A subcommand's own declaration being wrong is a mistake in this program rather than in
		// what the user typed, so it is caught at startup rather than on the parse that happens to
		// reach it.
		if err := subcommand.parser.Validate(); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"%s: error: the %s parser's own declaration is wrong: %v\n",
				programName, subcommand.parser.Command, err,
			)
			os.Exit(2)
		}
	}

	parser := &argument_parser.Parser{
		ProgramName: programName,
		Description: "Report what can be learned about a domain from outside it.",
		Parsers:     parsers,
	}

	if err := parser.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: the parser's own declaration is wrong: %v\n", programName, err)
		os.Exit(2)
	}

	// --completion is answered inside ParseOrExit, which leaves through status 0 the way --help
	// does, so nothing here has to know about it.
	parser.ParseOrExit()

	var chosen *command
	for _, subcommand := range subcommands {
		if subcommand.chosen {
			chosen = subcommand
			break
		}
	}

	// No subcommand at all is not an error the parser catches, because the root declares no
	// options of its own; the help is the useful answer.
	if chosen == nil {
		if err := parser.ParseArgs([]string{"--help"}); err != nil {
			fmt.Fprintf(os.Stderr, "%s: error: %v\n", programName, err)
		}
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := chosen.run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s: error: %v\n", programName, chosen.parser.Command, err)
		os.Exit(1)
	}
}
