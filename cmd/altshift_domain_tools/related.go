package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/altshiftab/altshift_domain_tools/pkg/related"
	"github.com/altshiftab/altshift_domain_tools/pkg/related/related_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
)

// The answers --search-type takes. "both" is not one of the API's own search types but a request
// for each of them, so it is spelled out here rather than passed through.
const (
	searchTypeCurrent  = whoisxml.SearchTypeCurrent
	searchTypeHistoric = whoisxml.SearchTypeHistoric
	searchTypeBoth     = "both"
)

// searchTypes is what the chosen answer asks the library for.
func searchTypes(chosen string) []string {
	if chosen == searchTypeBoth {
		return []string{whoisxml.SearchTypeCurrent, whoisxml.SearchTypeHistoric}
	}
	if chosen == "" {
		return nil
	}

	return []string{chosen}
}

// The environment variables the keys are read from when no file is given.
const (
	whoisXmlKeyEnvName     = "WHOISXML_API_KEY"     //nolint:gosec // G101: the name of a variable, not a key.
	hackerTargetKeyEnvName = "HACKERTARGET_API_KEY" //nolint:gosec // G101: the name of a variable, not a key.
)

type relatedSettings struct {
	domain              string
	whoisXmlKeyFile     string
	hackerTargetKeyFile string
	organization        string
	searchType          string
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
				option.WithMetavar(
					option.NewStringOption(
						'o',
						"organization",
						"The party's registered name, for the search that finds what a redacted "+
							"address cannot. Without it, the domain's own label is tried.",
						false,
						&settings.organization,
					),
					"NAME",
				),
				// A choice rather than a flag, because there are three answers and they cost
				// differently. The historic records hold what redaction has since taken out of the
				// current ones, and are worth sweeping once for a domain; the current records are
				// what a repeated run should ask for, and are the default for that reason.
				option.WithChoices(
					option.WithDefault(
						option.WithMetavar(
							option.NewStringOption(
								's',
								"search-type",
								"Which registration records to read. Each is a search of its own and "+
									"bills as one.",
								false,
								&settings.searchType,
							),
							"TYPE",
						),
						searchTypeCurrent,
					),
					searchTypeCurrent, searchTypeHistoric, searchTypeBoth,
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
		chosen := searchTypes(settings.searchType)

		domains, err := finder.ReverseWhois(ctx, settings.domain, chosen)
		if err != nil {
			return fmt.Errorf("reverse whois: %w", err)
		}
		found = append(found, domains...)

		// The party's own name, which finds what a redacted registrant address cannot. It runs
		// after the address search rather than beside it because the two share a rate limit that
		// counts wildcard searches by the minute, and because a domain both of them found should
		// carry both reasons rather than whichever arrived first.
		organizationDomains, err := finder.ReverseWhoisOrganization(
			ctx,
			settings.domain,
			settings.organization,
			chosen,
		)
		if err != nil {
			return fmt.Errorf("reverse whois organization: %w", err)
		}
		found = append(found, organizationDomains...)
	}

	if hackerTargetKey != "" {
		domains, err := finder.ReverseIp(ctx, settings.domain)
		if err != nil {
			return fmt.Errorf("reverse ip: %w", err)
		}
		found = append(found, domains...)
	}

	merged := related.Merge(found...)

	// What the DNS says about the domains the registration searches turned up. It reaches no
	// registry and spends nothing, and it is the one check available on an answer that arrives as a
	// list of bare names: a domain served from the same nameservers as the searched domain, or from
	// a set a group of the others share, has been placed there by something other than the search
	// that found it. It adds no domains and removes none.
	merged, err = finder.Corroborate(ctx, settings.domain, merged)
	if err != nil {
		return fmt.Errorf("corroborate: %w", err)
	}

	if settings.asJson {
		return emit(merged)
	}

	lines := make([]string, 0, len(merged))
	for _, domain := range merged {
		lines = append(lines, domain.Domain)
	}

	return emitLines(lines)
}
