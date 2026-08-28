package main

import (
	"context"
	"fmt"

	"github.com/altshiftab/altshift_domain_tools/pkg/resolver"
	"github.com/altshiftab/altshift_domain_tools/pkg/subdomain/finder"
	"github.com/altshiftab/altshift_domain_tools/pkg/subdomain/finder/finder_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/subdomain/wordlist"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
)

type subdomainsSettings struct {
	domain      string
	brute       bool
	resolver    string
	concurrency int
	asJson      bool
}

func newSubdomainsCommand() *command {
	return newSubdomainsCommandWith(&subdomainsSettings{})
}

func newSubdomainsCommandWith(settings *subdomainsSettings) *command {
	subcommand := &command{
		parser: &argument_parser.Parser{
			ProgramName: programName + " subdomains",
			Command:     "subdomains",
			Description: "Find the hosts under a domain.",
			Options: []option.Option{
				option.NewBoolOption(
					'b',
					"brute",
					"Also try a wordlist against the resolver. Visible in the target's logs, and skipped anyway where the domain answers to every name.",
					false,
					&settings.brute,
				),
				option.WithDefault(
					option.WithMetavar(
						option.NewStringOption(
							'r',
							"resolver",
							"The resolver the wordlist pass asks, as host:port.",
							false,
							&settings.resolver,
						),
						"ADDRESS",
					),
					"1.1.1.1:53",
				),
				option.WithDefault(
					option.WithMetavar(
						option.NewIntOption(
							'c',
							"concurrency",
							"How many lookups the wordlist pass runs at once.",
							false,
							&settings.concurrency,
						),
						"N",
					),
					"32",
				),
				option.NewBoolOption('j', "json", "Write the whole result as JSON.", false, &settings.asJson),
			},
			Positionals: []option.Option{
				option.WithMetavar(
					option.NewStringOption(0, "", "The domain to search.", true, &settings.domain),
					"DOMAIN",
				),
			},
		},
	}

	subcommand.run = func(ctx context.Context) error { return runSubdomains(ctx, settings) }

	return subcommand
}

func runSubdomains(ctx context.Context, settings *subdomainsSettings) error {
	if settings.domain == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	options := []finder_config.Option{finder_config.WithConcurrency(settings.concurrency)}

	// Without a resolver the finder runs the passive sources alone, which is what makes the
	// wordlist pass opt-in rather than something a careless run does to someone else's DNS.
	if settings.brute {
		domainResolver, err := resolver.New(settings.resolver)
		if err != nil {
			return altshiftErrors.New(fmt.Errorf("resolver new: %w", err), settings.resolver)
		}

		options = append(options, finder_config.WithResolver(domainResolver))
	}

	result, err := finder.NewFinder(options...).Find(ctx, settings.domain, wordlist.Names())
	if err != nil {
		return fmt.Errorf("find: %w", err)
	}
	if result == nil {
		return nil
	}

	if settings.asJson {
		return emit(result)
	}

	return emitLines(result.Names)
}
