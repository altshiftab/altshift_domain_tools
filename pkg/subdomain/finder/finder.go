// Package finder finds the subdomains of a domain, passively and actively.
//
// The passive sources -- certificate transparency and HackerTarget's host search -- ask third
// parties what they already know, and cost the target nothing. The active pass asks the resolver
// about names from a list, which finds hosts nobody has indexed at the cost of being visible.
//
// The two feed each other: a name found passively under one domain is a name worth trying under
// every other, so the passive results are folded into the active pass's list rather than being
// returned beside it.
package finder

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/crtsh"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/hackertarget"
	"github.com/altshiftab/altshift_domain_tools/pkg/subdomain/brute"
	"github.com/altshiftab/altshift_domain_tools/pkg/subdomain/finder/finder_config"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

// Result is what a run found.
type Result struct {
	// Names are the subdomains found, lower-cased and distinct.
	Names []string `json:"names"`
	// Bruted says whether the active pass ran. It is false where the domain answers to every name,
	// which makes brute forcing meaningless -- and a caller reading an empty Names without this
	// could not tell that from a domain with no subdomains.
	Bruted bool `json:"bruted"`
}

// Finder holds the source clients and the settings a run uses.
type Finder struct {
	crtsh        *crtsh.Client
	hackerTarget *hackertarget.Client
	config       *finder_config.Config
}

// NewFinder builds a finder. A source the caller did not provide is built with its own defaults, so
// the zero-option call is the ordinary one.
func NewFinder(options ...finder_config.Option) *Finder {
	config := finder_config.New(options...)

	crtshClient := config.Crtsh
	if crtshClient == nil {
		crtshClient = crtsh.NewClient()
	}

	hackerTargetClient := config.HackerTarget
	if hackerTargetClient == nil {
		hackerTargetClient = hackertarget.NewClient()
	}

	return &Finder{crtsh: crtshClient, hackerTarget: hackerTargetClient, config: config}
}

// Passive returns the subdomains the third-party sources know about.
//
// A source that fails is logged and skipped rather than failing the run: they are independent, and
// one being down or out of quota should not cost the answers of the other.
func (finder *Finder) Passive(ctx context.Context, domain string, options ...fetch_config.Option) []string {
	if finder == nil || domain == "" {
		return []string{}
	}

	// slices.Concat rather than append: the two sources run concurrently off this slice, and
	// appending into a shared slice's spare capacity would have them overwrite one another's.
	fetchOptions := slices.Concat(finder.config.FetchOptions, options)

	var (
		names     = make(map[string]struct{})
		namesLock sync.Mutex
		waitGroup sync.WaitGroup
	)

	add := func(found []string) {
		namesLock.Lock()
		defer namesLock.Unlock()

		for _, name := range found {
			names[name] = struct{}{}
		}
	}

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()

		results, err := finder.crtsh.Query(ctx, domain, fetchOptions...)
		if err != nil {
			slog.ErrorContext(
				altshiftContext.WithError(ctx, altshiftErrors.New(fmt.Errorf("crtsh query: %w", err), domain)),
				"An error occurred when querying the certificate transparency logs.",
			)

			return
		}

		add(crtsh.Names(results, domain))
	}()

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()

		response, err := finder.hackerTarget.Query(ctx, domain, fetchOptions...)
		if err != nil {
			slog.ErrorContext(
				altshiftContext.WithError(ctx, altshiftErrors.New(fmt.Errorf("hackertarget query: %w", err), domain)),
				"An error occurred when querying the host search.",
			)

			return
		}

		add(hackertarget.Names(response, domain))
	}()

	waitGroup.Wait()

	found := make([]string, 0, len(names))
	for name := range names {
		found = append(found, name)
	}
	slices.Sort(found)

	return found
}

// Find returns the subdomains of the domain from every source.
//
// names is the list the active pass asks about, carrying leading labels rather than whole names;
// wordlist.Names is the default one. A nil list, or a finder built without a resolver, runs the
// passive sources alone.
func (finder *Finder) Find(
	ctx context.Context,
	domain string,
	names iter.Seq[string],
	options ...fetch_config.Option,
) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if finder == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("finder"))
	}

	if domain == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	passive := finder.Passive(ctx, domain, options...)

	// Without a resolver there is no active pass, and the passive answer stands on its own.
	domainResolver := finder.config.Resolver
	if domainResolver == nil || names == nil {
		return &Result{Names: passive, Bruted: false}, nil
	}

	canBrute, err := brute.CanBrute(ctx, domain, domainResolver)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("brute can brute: %w", err), domain)
	}
	if !canBrute {
		return &Result{Names: passive, Bruted: false}, nil
	}

	// What the passive sources found becomes part of what the active pass asks about, under this
	// domain and any other it is later run against. The leading label is what the list holds, so
	// the domain is trimmed off.
	suffix := "." + domain
	combined := make(map[string]struct{})
	for _, name := range passive {
		if label := strings.TrimSuffix(name, suffix); label != "" && label != name {
			combined[label] = struct{}{}
		}
	}
	for name := range names {
		if name = strings.TrimSpace(name); name != "" {
			combined[name] = struct{}{}
		}
	}

	labels := make([]string, 0, len(combined))
	for label := range combined {
		labels = append(labels, label)
	}
	slices.Sort(labels)

	active, err := brute.Lookup(ctx, domain, slices.Values(labels), domainResolver, finder.config.Concurrency)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("brute lookup: %w", err), domain)
	}

	// The active pass confirms what resolves. A name the logs know but nothing resolves is kept
	// too: it existed once, which is worth reporting, and dropping it would lose what certificate
	// transparency is good at.
	all := make(map[string]struct{}, len(passive)+len(active))
	for _, name := range passive {
		all[name] = struct{}{}
	}
	for _, name := range active {
		all[name] = struct{}{}
	}

	found := make([]string, 0, len(all))
	for name := range all {
		found = append(found, name)
	}
	slices.Sort(found)

	return &Result{Names: found, Bruted: true}, nil
}
