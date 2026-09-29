// Package registration tells whether a domain is registered now.
//
// A reverse whois search that includes the historic records answers with every domain whose
// registration ever matched, which includes the ones that have since lapsed. A lapsed domain is not
// anybody's asset, so a caller proposing assets asks this first.
//
// The registry is asked over RDAP, which answers a lookup of a registered domain and turns away one
// of a domain it does not hold; IANA publishes which server answers for which top-level domain. Some
// registries run no RDAP server, and for those the DNS is asked instead: a registered domain is
// delegated, and a name the registry does not hold does not exist. That misreads a registered domain
// with no delegation -- one on hold, say -- as unregistered, which for the question being asked is
// the right answer anyway.
//
// Any answer short of a registry's or a resolver's word is StatusUnknown. A caller that drops lapsed
// domains drops only those it was told are unregistered, so a registry that is down costs a
// proposal nothing.
package registration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/altshiftab/altshift_domain_tools/pkg/registration/registration_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/resolver"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftHttpErrors "github.com/altshiftab/utils_go/pkg/http/errors"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	altshiftHttpUtils "github.com/altshiftab/utils_go/pkg/http/utils"
	"github.com/altshiftab/utils_go/pkg/utils"
)

// Status is what is known about a domain's registration.
type Status int

const (
	// StatusUnknown is no answer: the registry or the resolver could not be asked.
	StatusUnknown Status = iota
	// StatusRegistered is a domain the registry holds.
	StatusRegistered
	// StatusUnregistered is a domain nobody holds.
	StatusUnregistered
)

func (status Status) String() string {
	switch status {
	case StatusRegistered:
		return "registered"
	case StatusUnregistered:
		return "unregistered"
	default:
		return "unknown"
	}
}

// DefaultBootstrapUrl is IANA's list of the registries' RDAP servers (RFC 9224).
const DefaultBootstrapUrl = "https://data.iana.org/rdap/dns.json"

// ContentType is what an RDAP server answers with.
const ContentType = "application/rdap+json"

// bootstrap is the shape of the list: each service is the top-level domains it answers for, then
// its base URLs.
type bootstrap struct {
	Services [][][]string `json:"services"`
}

// Checker tells whether domains are registered. It is safe for concurrent use.
type Checker struct {
	config *registration_config.Config

	mutex sync.Mutex
	// servers is each top-level domain's RDAP base URL, read from the bootstrap list once it has been
	// read successfully. A failed read is not kept, so the next call tries again.
	servers map[string]*url.URL
}

// NewChecker builds a checker.
func NewChecker(options ...registration_config.Option) *Checker {
	return &Checker{config: registration_config.New(options...)}
}

func (checker *Checker) fetchOptions() []fetch_config.Option {
	return slices.Concat(
		[]fetch_config.Option{fetch_config.WithHeaders(map[string]string{"Accept": ContentType})},
		checker.config.FetchOptions,
	)
}

func (checker *Checker) resolver() (resolver.Resolver, error) {
	if configured := checker.config.Resolver; !utils.IsNil(configured) {
		return configured, nil
	}

	client, err := resolver.New("")
	if err != nil {
		return nil, fmt.Errorf("resolver new: %w", err)
	}

	return client, nil
}

// readServers returns each top-level domain's RDAP base URL, reading the list the first time.
func (checker *Checker) readServers(ctx context.Context) (map[string]*url.URL, error) {
	checker.mutex.Lock()
	defer checker.mutex.Unlock()

	if checker.servers != nil {
		return checker.servers, nil
	}

	bootstrapUrl := DefaultBootstrapUrl
	if configured := checker.config.BootstrapUrl; configured != nil {
		bootstrapUrl = configured.String()
	}

	_, list, err := altshiftHttpUtils.FetchJson[*bootstrap](ctx, bootstrapUrl, checker.config.FetchOptions...)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), bootstrapUrl)
	}
	if list == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("bootstrap"), bootstrapUrl)
	}

	servers := make(map[string]*url.URL)
	for _, service := range list.Services {
		if len(service) < 2 || len(service[1]) == 0 {
			continue
		}

		// A registry may list several addresses. The HTTPS one is preferred where there is one.
		base := service[1][0]
		for _, candidate := range service[1] {
			if strings.HasPrefix(candidate, "https://") {
				base = candidate
				break
			}
		}

		baseUrl, err := url.Parse(base)
		if err != nil {
			continue
		}
		if !strings.HasSuffix(baseUrl.Path, "/") {
			baseUrl.Path += "/"
		}

		for _, topLevelDomain := range service[0] {
			servers[strings.ToLower(topLevelDomain)] = baseUrl
		}
	}

	checker.servers = servers

	return servers, nil
}

// Status tells whether the domain is registered.
//
// The error says why the answer is StatusUnknown; a known answer comes with none.
func (checker *Checker) Status(ctx context.Context, domain string) (Status, error) {
	if err := ctx.Err(); err != nil {
		return StatusUnknown, fmt.Errorf("context err: %w", err)
	}

	if checker == nil {
		return StatusUnknown, altshiftErrors.NewWithTrace(nil_error.New("checker"))
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return StatusUnknown, altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	servers, err := checker.readServers(ctx)
	if err != nil {
		return StatusUnknown, fmt.Errorf("read servers: %w", err)
	}

	server, ok := servers[topLevelDomainOf(domain)]
	if !ok {
		return checker.statusFromDns(ctx, domain)
	}

	record, err := checker.lookup(ctx, server, domain)
	if err != nil {
		return StatusUnknown, fmt.Errorf("lookup: %w", err)
	}
	if record == nil {
		return StatusUnregistered, nil
	}

	return StatusRegistered, nil
}

// ErrNoRdap is a domain whose registry runs no RDAP server, which is the only party that can say what
// state the registration is in.
var ErrNoRdap = errors.New("the registry runs no RDAP server")

// ErrNotRegistered is a domain the registry does not hold.
var ErrNotRegistered = errors.New("the domain is not registered")

// domainRecord is the part of an RDAP domain object read here.
type domainRecord struct {
	// Status is the registration's states (RFC 9083), written as RFC 8056 maps the EPP codes: "client
	// transfer prohibited" for clientTransferProhibited.
	Status []string `json:"status"`
}

func topLevelDomainOf(domain string) string {
	return domain[strings.LastIndex(domain, ".")+1:]
}

// lookup asks the registry for the domain. A domain the registry does not hold is nil and no error.
func (checker *Checker) lookup(ctx context.Context, server *url.URL, domain string) (*domainRecord, error) {
	lookupUrl := server.JoinPath("domain", domain).String()

	_, record, err := altshiftHttpUtils.FetchJson[*domainRecord](ctx, lookupUrl, checker.fetchOptions()...)
	if err != nil {
		if statusError, ok := errors.AsType[*altshiftHttpErrors.Non2xxStatusCodeError](err); ok &&
			statusError != nil && statusError.StatusCode == http.StatusNotFound {
			return nil, nil
		}

		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), lookupUrl)
	}
	if record == nil {
		return &domainRecord{}, nil
	}

	return record, nil
}

// Statuses returns the states the registry records the domain in -- the locks against transfer,
// update and deletion among them -- as the registry writes them. A domain whose registry runs no RDAP
// server is ErrNoRdap, and one the registry does not hold is ErrNotRegistered: neither has states to
// read, and the DNS cannot supply them.
func (checker *Checker) Statuses(ctx context.Context, domain string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if checker == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("checker"))
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	servers, err := checker.readServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("read servers: %w", err)
	}

	server, ok := servers[topLevelDomainOf(domain)]
	if !ok {
		return nil, altshiftErrors.NewWithTrace(ErrNoRdap, domain)
	}

	record, err := checker.lookup(ctx, server, domain)
	if err != nil {
		return nil, fmt.Errorf("lookup: %w", err)
	}
	if record == nil {
		return nil, altshiftErrors.NewWithTrace(ErrNotRegistered, domain)
	}

	return record.Status, nil
}

// statusFromDns answers for a domain whose registry runs no RDAP server.
func (checker *Checker) statusFromDns(ctx context.Context, domain string) (Status, error) {
	domainResolver, err := checker.resolver()
	if err != nil {
		return StatusUnknown, fmt.Errorf("resolver: %w", err)
	}

	exists, err := domainResolver.DomainExists(ctx, domain)
	if err != nil {
		return StatusUnknown, fmt.Errorf("domain exists: %w", err)
	}

	if exists {
		return StatusRegistered, nil
	}

	return StatusUnregistered, nil
}
