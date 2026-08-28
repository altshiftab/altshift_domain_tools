package main

import (
	"context"
	"fmt"

	"github.com/altshiftab/altshift_domain_tools/pkg/network_range/finder"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
)

type rangesSettings struct {
	domain string
	asJson bool
}

func newRangesCommand() *command {
	settings := &rangesSettings{}

	subcommand := &command{
		parser: &argument_parser.Parser{
			ProgramName: programName + " ranges",
			Command:     "ranges",
			Description: "Find the address space a domain's owner holds.",
			Options: []option.Option{
				option.NewBoolOption(
					'j',
					"json",
					"Write the whole result as JSON, with the reasoning behind each range.",
					false,
					&settings.asJson,
				),
			},
			Positionals: []option.Option{
				option.WithMetavar(
					option.NewStringOption(0, "", "The domain to search.", true, &settings.domain),
					"DOMAIN",
				),
			},
		},
	}

	subcommand.run = func(ctx context.Context) error { return runRanges(ctx, settings) }

	return subcommand
}

func runRanges(ctx context.Context, settings *rangesSettings) error {
	if settings.domain == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	// Neither source needs a credential, so this is the one subcommand that runs with nothing
	// configured at all.
	ranges, err := finder.NewFinder().Find(ctx, settings.domain)
	if err != nil {
		return fmt.Errorf("find: %w", err)
	}

	if settings.asJson {
		return emit(ranges)
	}

	lines := make([]string, 0, len(ranges))
	for _, item := range ranges {
		lines = append(lines, item.Network)
	}

	return emitLines(lines)
}
