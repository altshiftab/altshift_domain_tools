// Package ripe queries the RIPE database for the address space a party holds.
//
// It answers in two steps, which is what makes it worth having. A full-text search finds the person
// objects registered at a domain, and an inverse search finds the ranges those people administer.
// Starting from the domain rather than from an address is the point: it finds space the party holds
// but is not currently using, which nothing that begins with a hostname can see.
//
// RIPE covers Europe, the Middle East and Central Asia. A party whose space is registered with
// ARIN, APNIC, AFRINIC or LACNIC will not be found here, and an empty answer is therefore not
// evidence that a party holds nothing.
package ripe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripe/ripe_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftHttpErrors "github.com/altshiftab/utils_go/pkg/http/errors"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	altshiftHttpUtils "github.com/altshiftab/utils_go/pkg/http/utils"
)

// Domain is the public RIPE REST API.
const Domain = "rest.db.ripe.net"

var defaultBaseUrl = &url.URL{Scheme: "https", Host: Domain}

// The paths the two searches are served at.
const (
	FullTextSearchPath = "/fulltextsearch/select.json"
	SearchPath         = "/search.json"
)

// DefaultMaxPersons bounds how many person objects a domain search reads.
//
// The two steps multiply: every handle found becomes a query of its own. A domain matching a
// hundred people would be a hundred requests against a database that asks callers to be gentle,
// and the ranges behind the hundredth match are not better evidence than those behind the first.
const DefaultMaxPersons = 25

// ErrMalformedRange is an inetnum that is not the "start - end" the database documents.
var ErrMalformedRange = errors.New("malformed range")

// Person is a registered contact.
type Person struct {
	// NicHandle is the database's identifier for the contact, which is what the ranges reference.
	NicHandle string `json:"nic_handle,omitzero"`
	Name      string `json:"name,omitzero"`
	Email     string `json:"email,omitzero"`
}

// Range is one registered allocation.
type Range struct {
	// Inetnum is the range as the database writes it, "start - end".
	Inetnum string `json:"inetnum,omitzero"`
	NetName string `json:"netname,omitzero"`
	Status  string `json:"status,omitzero"`
	Country string `json:"country,omitzero"`
	// Networks is the range expressed as CIDR. An arbitrary range is not one prefix, so this is
	// often several.
	Networks []string `json:"networks,omitzero"`
}

// The shapes the two searches answer with. They are unexported because they are the database's
// rendering rather than anything a caller should hold: attributes arrive as name/value pairs, which
// is convenient for RIPE and for nobody else.
type (
	fullTextResponse struct {
		Result *fullTextResult `json:"result,omitzero"`
	}

	fullTextResult struct {
		NumFound int            `json:"numFound,omitzero"`
		Docs     []*fullTextDoc `json:"docs,omitzero"`
	}

	fullTextDoc struct {
		Doc *fullTextInner `json:"doc,omitzero"`
	}

	fullTextInner struct {
		Strs []*fullTextStr `json:"strs,omitzero"`
	}

	fullTextStr struct {
		Str *nameValue `json:"str,omitzero"`
	}

	nameValue struct {
		Name  string `json:"name,omitzero"`
		Value string `json:"value,omitzero"`
	}

	searchResponse struct {
		Objects *searchObjects `json:"objects,omitzero"`
	}

	searchObjects struct {
		Object []*searchObject `json:"object,omitzero"`
	}

	searchObject struct {
		Attributes *searchAttributes `json:"attributes,omitzero"`
	}

	searchAttributes struct {
		Attribute []*nameValue `json:"attribute,omitzero"`
	}
)

type Client struct {
	baseUrl *url.URL
	config  *ripe_config.Config
}

// NewClient builds a client. Without a base URL it talks to the public database.
func NewClient(options ...ripe_config.Option) *Client {
	config := ripe_config.New(options...)

	baseUrl := config.BaseUrl
	if baseUrl == nil {
		baseUrl = defaultBaseUrl
	}
	clientUrl := *baseUrl

	return &Client{baseUrl: &clientUrl, config: config}
}

func (client *Client) maxPersons() int {
	if maxPersons := client.config.MaxPersons; maxPersons > 0 {
		return maxPersons
	}

	return DefaultMaxPersons
}

// fetchOptions is the client's options with the call's appended.
//
// slices.Concat rather than append: the client's options are shared by every call, and appending
// into that slice's spare capacity would have concurrent calls overwrite one another's.
func (client *Client) fetchOptions(options []fetch_config.Option) []fetch_config.Option {
	return slices.Concat(client.config.FetchOptions, options)
}

// values reads a doc's attributes into a map, which is how the database's name/value pairs become
// something addressable.
func values(pairs []*nameValue) map[string]string {
	found := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		if pair == nil || pair.Name == "" {
			continue
		}

		// The first wins. An object can repeat an attribute -- several e-mail lines, several
		// admin-c -- and for the fields read here the first is the one meant.
		if _, ok := found[pair.Name]; !ok {
			found[pair.Name] = pair.Value
		}
	}

	return found
}

// emailAtDomain reports whether the address is at the domain or a subdomain of it.
//
// The full-text search matches the domain anywhere in an object, so a person whose postal address
// or remarks happen to mention it comes back alongside the ones whose e-mail is actually there.
// Attributing a stranger's address space to a customer on that basis would be a serious error, so
// the matches are checked rather than trusted.
func emailAtDomain(email string, domain string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	domain = strings.ToLower(strings.TrimSpace(domain))

	if email == "" || domain == "" {
		return false
	}

	_, host, found := strings.Cut(email, "@")
	if !found || host == "" {
		return false
	}

	return host == domain || strings.HasSuffix(host, "."+domain)
}

// Persons returns the contacts registered with an address at the domain.
func (client *Client) Persons(
	ctx context.Context,
	domain string,
	options ...fetch_config.Option,
) ([]*Person, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if domain == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	requestUrl := *client.baseUrl
	requestUrl.Path += FullTextSearchPath
	requestUrl.RawQuery = url.Values{
		"q":  []string{fmt.Sprintf("(%s) AND (object-type:person)", domain)},
		"wt": []string{"json"},
	}.Encode()

	requestUrlString := requestUrl.String()

	_, response, err := altshiftHttpUtils.FetchJson[*fullTextResponse](
		ctx,
		requestUrlString,
		client.fetchOptions(options)...,
	)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), requestUrlString)
	}

	if response == nil || response.Result == nil {
		return []*Person{}, nil
	}

	persons := make([]*Person, 0, len(response.Result.Docs))
	seen := make(map[string]struct{})

	for _, doc := range response.Result.Docs {
		if doc == nil || doc.Doc == nil {
			continue
		}

		pairs := make([]*nameValue, 0, len(doc.Doc.Strs))
		for _, str := range doc.Doc.Strs {
			if str != nil && str.Str != nil {
				pairs = append(pairs, str.Str)
			}
		}

		attributes := values(pairs)

		handle := attributes["nic-hdl"]
		email := attributes["e-mail"]

		// The search matched the domain somewhere in the object; only an address at the domain
		// says the person belongs to it.
		if handle == "" || !emailAtDomain(email, domain) {
			continue
		}

		if _, ok := seen[handle]; ok {
			continue
		}
		seen[handle] = struct{}{}

		persons = append(persons, &Person{NicHandle: handle, Name: attributes["person"], Email: email})

		if len(persons) >= client.maxPersons() {
			break
		}
	}

	return persons, nil
}

// Ranges returns the allocations the contact administers.
func (client *Client) Ranges(
	ctx context.Context,
	nicHandle string,
	options ...fetch_config.Option,
) ([]*Range, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if nicHandle == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("nic handle"))
	}

	requestUrl := *client.baseUrl
	requestUrl.Path += SearchPath
	requestUrl.RawQuery = url.Values{
		"query-string": []string{nicHandle},
		// Both roles, because a party administering a range and a party operating it are equally
		// good evidence that the space is theirs.
		"inverse-attribute": []string{"admin-c", "tech-c"},
		"type-filter":       []string{"inetnum"},
		// Without this the database returns every object referenced by each match, which is a great
		// deal of data none of it needs.
		"flags": []string{"no-referenced"},
	}.Encode()

	requestUrlString := requestUrl.String()

	_, response, err := altshiftHttpUtils.FetchJson[*searchResponse](
		ctx,
		requestUrlString,
		client.fetchOptions(options)...,
	)
	if err != nil {
		// A handle with no ranges is answered with a 404 rather than an empty result, which is an
		// answer rather than a failure.
		if statusError, ok := errors.AsType[*altshiftHttpErrors.Non2xxStatusCodeError](err); ok &&
			statusError != nil && statusError.StatusCode == http.StatusNotFound {
			return []*Range{}, nil
		}

		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), requestUrlString)
	}

	if response == nil || response.Objects == nil {
		return []*Range{}, nil
	}

	ranges := make([]*Range, 0, len(response.Objects.Object))

	for _, object := range response.Objects.Object {
		if object == nil || object.Attributes == nil {
			continue
		}

		attributes := values(object.Attributes.Attribute)

		inetnum := attributes["inetnum"]
		if inetnum == "" {
			inetnum = attributes["inet6num"]
		}
		if inetnum == "" {
			continue
		}

		networks, err := Networks(inetnum)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("networks: %w", err), inetnum)
		}

		ranges = append(
			ranges,
			&Range{
				Inetnum:  inetnum,
				NetName:  attributes["netname"],
				Status:   attributes["status"],
				Country:  attributes["country"],
				Networks: networks,
			},
		)
	}

	return ranges, nil
}

// Networks expresses an inetnum as CIDR.
//
// The database writes an allocation as a first and last address, and an arbitrary range of
// addresses is not one prefix: 10.0.0.1 - 10.0.0.6 is a /32, a /30 and a /31. So this returns
// however many prefixes it takes to cover the range exactly, rather than the one that would have to
// be too large.
func Networks(inetnum string) ([]string, error) {
	first, last, found := strings.Cut(inetnum, "-")
	if !found {
		// A single address, or already a prefix.
		if _, network, err := net.ParseCIDR(strings.TrimSpace(inetnum)); err == nil && network != nil {
			return []string{network.String()}, nil
		}

		return nil, altshiftErrors.NewWithTrace(ErrMalformedRange, inetnum)
	}

	start := net.ParseIP(strings.TrimSpace(first))
	end := net.ParseIP(strings.TrimSpace(last))
	if start == nil || end == nil {
		return nil, altshiftErrors.NewWithTrace(ErrMalformedRange, inetnum)
	}

	startIpv4 := start.To4()
	endIpv4 := end.To4()
	if startIpv4 == nil || endIpv4 == nil {
		// IPv6 ranges are left as they were written rather than expanded: the arithmetic below is
		// 32-bit, and a v6 allocation is already a prefix in practice.
		return nil, nil
	}

	startValue := binary.BigEndian.Uint32(startIpv4)
	endValue := binary.BigEndian.Uint32(endIpv4)

	if startValue > endValue {
		return nil, altshiftErrors.NewWithTrace(ErrMalformedRange, inetnum)
	}

	networks := make([]string, 0)

	for {
		// The largest block that starts here and does not run past the end. The first term is what
		// the start address is aligned to; the second is what is left to cover.
		size := uint32(1)
		for size<<1 != 0 && startValue&(size<<1-1) == 0 && startValue+(size<<1)-1 <= endValue {
			size <<= 1
		}

		ones := 32
		for bit := size; bit > 1; bit >>= 1 {
			ones--
		}

		address := make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(address, startValue)
		networks = append(networks, fmt.Sprintf("%s/%d", address.String(), ones))

		next := startValue + size
		// The range reached the top of the address space, so there is nothing after it.
		if next < startValue || next > endValue {
			break
		}
		startValue = next
	}

	return networks, nil
}
