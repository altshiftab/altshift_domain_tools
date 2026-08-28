// Package brute finds subdomains by asking the resolver about names from a list.
//
// It is the noisy half of subdomain finding: the passive sources ask a third party what it already
// knows, and this asks the target's resolver thousands of questions. It finds what the passive
// sources cannot -- a host that never had a public certificate and is in nobody's index -- at the
// cost of being visible in the resolver's logs.
package brute

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"strings"
	"sync"

	"github.com/altshiftab/altshift_domain_tools/pkg/resolver"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

// DefaultConcurrency is how many lookups run at once when none is given. It is a compromise: high
// enough that a five thousand name list finishes in seconds, low enough that a resolver does not
// take it for an attack.
const DefaultConcurrency = 32

// ErrNonPositiveConcurrency is a concurrency that would run nothing.
var ErrNonPositiveConcurrency = errors.New("non-positive concurrency")

// wildcardProbe is the name the wildcard check asks about. It has to be one nobody would register,
// because the whole question is whether a name that should not exist answers anyway.
const wildcardProbe = "wildcardcheck-altshift-domain-tools"

// CanBrute reports whether brute forcing the domain can tell anything.
//
// A domain with a wildcard record resolves every name under it, so every name in the list would
// come back as a hit and none of them would mean anything. Asking about a name that cannot exist
// says which kind of domain this is, and a caller that skips this check produces thousands of
// findings that are all false.
func CanBrute(ctx context.Context, domain string, domainResolver resolver.Resolver) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("context err: %w", err)
	}

	if domain == "" {
		return false, altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	if domainResolver == nil {
		return false, altshiftErrors.NewWithTrace(nil_error.New("resolver"))
	}

	exists, err := domainResolver.DomainExists(ctx, wildcardProbe+"."+domain)
	if err != nil {
		return false, altshiftErrors.New(fmt.Errorf("domain exists: %w", err), domain)
	}

	return !exists, nil
}

// Lookup returns the names from the sequence that resolve under the domain.
//
// The sequence carries the leading labels rather than whole names -- "www", not "www.example.com" --
// so one list serves every domain.
//
// A lookup that fails is logged and skipped rather than failing the run: a brute force of thousands
// of names will have some fail, and losing the whole answer to one timeout would make it useless. A
// resolver that refuses is the exception, and stops the run: it will refuse the rest too, and
// working through the list being told no finds nothing and looks like an attack.
func Lookup(
	ctx context.Context,
	domain string,
	names iter.Seq[string],
	domainResolver resolver.Resolver,
	concurrency int,
) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if domain == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	if names == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("names"))
	}

	if domainResolver == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("resolver"))
	}

	if concurrency == 0 {
		concurrency = DefaultConcurrency
	}
	if concurrency < 0 {
		return nil, altshiftErrors.NewWithTrace(ErrNonPositiveConcurrency, concurrency)
	}

	lookupCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// A buffered channel is the semaphore. It needs no dependency, and a token is a slot.
	tokens := make(chan struct{}, concurrency)

	var (
		found     []string
		foundLock sync.Mutex
		waitGroup sync.WaitGroup
	)

namesLoop:
	for name := range names {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}

		select {
		case <-lookupCtx.Done():
			break namesLoop
		case tokens <- struct{}{}:
		}

		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			defer func() { <-tokens }()

			candidate := name + "." + domain

			exists, err := domainResolver.DomainExists(lookupCtx, candidate)
			if err != nil {
				if resolver.IsRefused(err) {
					// The resolver has stopped answering. Nothing further is worth asking.
					cancel()
					return
				}

				// A cancelled lookup is the run ending, not a failure of this name.
				if errors.Is(err, context.Canceled) {
					return
				}

				slog.ErrorContext(
					altshiftContext.WithError(lookupCtx, altshiftErrors.New(fmt.Errorf("domain exists: %w", err), candidate)),
					"An error occurred when looking a domain up.",
				)

				return
			}

			if !exists {
				return
			}

			foundLock.Lock()
			defer foundLock.Unlock()
			found = append(found, candidate)
		}()
	}

	waitGroup.Wait()

	if found == nil {
		found = []string{}
	}

	return found, nil
}
