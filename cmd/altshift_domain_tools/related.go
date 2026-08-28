package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/altshiftab/altshift_domain_tools/pkg/related"
	"github.com/altshiftab/altshift_domain_tools/pkg/related/related_config"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
)

// The environment variables the keys are read from when no file is given.
const (
	whoisXmlKeyEnvName     = "WHOISXML_API_KEY"     //nolint:gosec // G101: the name of a variable, not a key.
	hackerTargetKeyEnvName = "HACKERTARGET_API_KEY" //nolint:gosec // G101: the name of a variable, not a key.
)

type relatedSettings struct {
	domain              string
	whoisXmlKeyFile     string
	hackerTargetKeyFile string
	historical          bool
	asJson              bool
}

func newRelatedCommand() *command {
	settings := &relatedSettings{}

	subcommand := &command{
		parser: &argument_parser.Parser{
			ProgramName: programName + " related",
			Command:     "related",
			Description: "Find the other domains a domain's owner has.",
			Options: []option.Option{
				option.WithMetavar(
					option.NewStringOption(
						'w',
						"whoisxml-key-file",
						"A file holding the WhoisXML key. Without it, "+whoisXmlKeyEnvName+" is read.",
						false,
						&settings.whoisXmlKeyFile,
					),
					"PATH",
				),
				option.WithMetavar(
					option.NewStringOption(
						't',
						"hackertarget-key-file",
						"A file holding the HackerTarget key. Without it, "+hackerTargetKeyEnvName+" is read.",
						false,
						&settings.hackerTargetKeyFile,
					),
					"PATH",
				),
				option.NewBoolOption(
					'H',
					"historical",
					"Search registrations as they once were rather than as they stand.",
					false,
					&settings.historical,
				),
				option.NewBoolOption(
					'j',
					"json",
					"Write the whole result as JSON, with the reasoning behind each domain.",
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

	subcommand.run = func(ctx context.Context) error { return runRelated(ctx, settings) }

	return subcommand
}

// readKey reads a credential from a file, or failing that from the environment.
//
// There is deliberately no flag that takes the key itself: an argument is visible in the process
// table to every user on the machine, which is a poor place for a credential that bills to an
// account.
func readKey(path string, envName string) (string, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", altshiftErrors.NewWithTrace(fmt.Errorf("os read file: %w", err), path)
		}

		return strings.TrimSpace(string(data)), nil
	}

	return strings.TrimSpace(os.Getenv(envName)), nil
}

func runRelated(ctx context.Context, settings *relatedSettings) error {
	if settings.domain == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	whoisXmlKey, err := readKey(settings.whoisXmlKeyFile, whoisXmlKeyEnvName)
	if err != nil {
		return fmt.Errorf("read key (whoisxml): %w", err)
	}

	hackerTargetKey, err := readKey(settings.hackerTargetKeyFile, hackerTargetKeyEnvName)
	if err != nil {
		return fmt.Errorf("read key (hackertarget): %w", err)
	}

	// Neither source is anonymous, and a run with no key at all would only report that twice.
	if whoisXmlKey == "" && hackerTargetKey == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("api keys"))
	}

	finder := related.NewFinder(
		related_config.WithWhoisXmlApiKey(whoisXmlKey),
		related_config.WithHackerTargetApiKey(hackerTargetKey),
	)

	found := make([]*related.Domain, 0)

	// The two sources are independent, so one without a key does not stop the other.
	if whoisXmlKey != "" {
		domains, err := finder.ReverseWhois(ctx, settings.domain, settings.historical)
		if err != nil {
			return fmt.Errorf("reverse whois: %w", err)
		}
		found = append(found, domains...)
	}

	if hackerTargetKey != "" {
		domains, err := finder.ReverseIp(ctx, settings.domain)
		if err != nil {
			return fmt.Errorf("reverse ip: %w", err)
		}
		found = append(found, domains...)
	}

	merged := related.Merge(found...)

	if settings.asJson {
		return emit(merged)
	}

	lines := make([]string, 0, len(merged))
	for _, domain := range merged {
		lines = append(lines, domain.Domain)
	}

	return emitLines(lines)
}
