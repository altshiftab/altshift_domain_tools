// Package whois queries a registry's whois service over port 43.
//
// It is here for one thing the web APIs cannot do. The registries that run RIPE's database software
// -- APNIC and AFRINIC among them -- answer inverse queries, which ask not "what is this object"
// but "which objects reference this value", and that is the search a walk from a domain to address
// space is made of. RDAP has no such search: RFC 9082 defines exactly two searchable properties for
// an entity, its name and its handle, and the reverse search of RFC 9536 is offered by none of them
// for addresses.
//
// The way in is the abuse mailbox. Both registries refuse an inverse search on e-mail -- "e-mail is
// not an inverse searchable attribute", the same removal RIPE made -- but both allow one on
// abuse-mailbox, and an abuse contact is conventionally at the party's own domain. So abuse@<domain>
// finds the contacts, and the contacts are followed to the ranges that reference them.
//
// The convention is a convention rather than a rule, which bounds what this can find: a party whose
// registered abuse contact is at its provider's domain, or is a named individual, is not found this
// way. It fails closed -- the address either is at the domain or is not -- so what it does find is
// no less trustworthy for it.
//
// The protocol is a line of text in and a document out, with no status code, no content type and no
// length. What structure there is comes from RPSL: attributes written "name: value", one object to a
// blank-line-separated block, and errors announced in comments.
package whois

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/altshiftab/altshift_domain_tools/pkg/cidr"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whois/whois_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

// The hosts this is known to work against. Both run RIPE's database software, which is what makes
// the inverse search available.
const (
	ApnicHost   = "whois.apnic.net"
	AfrinicHost = "whois.afrinic.net"
)

// DefaultPort is the well-known whois port.
const DefaultPort = "43"

// DefaultTimeout bounds a single query.
//
// The protocol carries no length, so a server that accepts a connection and then says nothing would
// otherwise hold the query open for as long as the caller's context allows.
const DefaultTimeout = 30 * time.Second

// DefaultInverseAttributes are the references a range is looked for under.
//
// Administrative and technical contact, and no more, because those two are the only ones both
// registries agree to search in reverse: AFRINIC refuses abuse-c, which APNIC allows.
var DefaultInverseAttributes = []string{"admin-c", "tech-c"}

// DefaultMaxContacts bounds how many contacts found at a domain are followed to their ranges. Every
// one of them is a query of its own against a database that asks callers to be gentle.
const DefaultMaxContacts = 10

// DefaultMaxResponseBytes bounds what one answer may be. An inverse search on a large maintainer
// returns tens of thousands of objects, and nothing here needs to read them all to be wrong.
const DefaultMaxResponseBytes = 8 << 20

// The object types a range is written as.
const (
	TypeInetnum  = "inetnum"
	TypeInet6num = "inet6num"
)

// The codes the database announces in its comments that are answers rather than failures.
const (
	// noEntriesFound is a search that matched nothing.
	noEntriesFound = 101
	// attributeNotSearchable is the database refusing to search on the attribute at all, which is
	// how it answers an inverse search on e-mail. It says the walk cannot go this way here, rather
	// than that anything went wrong.
	attributeNotSearchable = 105
)

// ResponseError is an error the database answered with, rather than a failure to reach it.
//
// It matters because the two are not the same to a caller: a rejected query is a bug in what was
// asked, and a refused connection is the registry being down.
type ResponseError struct {
	Code    int
	Message string
}

func (responseError *ResponseError) Error() string {
	if responseError == nil {
		return "whois response error"
	}

	return fmt.Sprintf("whois response error %d: %s", responseError.Code, responseError.Message)
}

// Attribute is one "name: value" line, with the continuation lines folded in.
type Attribute struct {
	Name  string `json:"name,omitzero"`
	Value string `json:"value,omitzero"`
}

// Object is one RPSL object, its attributes in the order they were written.
//
// The order is kept because the first attribute is the object's type and key -- an inetnum object
// begins with an inetnum attribute -- which is the only thing that says what a block is.
type Object struct {
	Attributes []*Attribute `json:"attributes,omitzero"`
}

// Type is what the object is, and Key what it is called.
func (object *Object) Type() (string, string) {
	if object == nil || len(object.Attributes) == 0 || object.Attributes[0] == nil {
		return "", ""
	}

	return object.Attributes[0].Name, object.Attributes[0].Value
}

// Value is the first value written for the attribute, or the empty string.
//
// The first rather than all of them: an object repeats an attribute freely -- several descr lines,
// several admin-c -- and for a field read as one thing the first is the one meant.
func (object *Object) Value(name string) string {
	if object == nil {
		return ""
	}

	for _, attribute := range object.Attributes {
		if attribute != nil && attribute.Name == name {
			return attribute.Value
		}
	}

	return ""
}

// Values is every value written for the attribute.
func (object *Object) Values(name string) []string {
	if object == nil {
		return nil
	}

	values := make([]string, 0)
	for _, attribute := range object.Attributes {
		if attribute != nil && attribute.Name == name {
			values = append(values, attribute.Value)
		}
	}

	return values
}

// Range is one registered allocation.
type Range struct {
	// Inetnum is the range as the database writes it, "start - end".
	Inetnum string `json:"inetnum,omitzero"`
	NetName string `json:"net_name,omitzero"`
	Status  string `json:"status,omitzero"`
	Country string `json:"country,omitzero"`
	// Contact is the handle the range was reached through.
	Contact string `json:"contact,omitzero"`
	// Networks is the range expressed as CIDR.
	Networks []string `json:"networks,omitzero"`
}

type Client struct {
	host   string
	config *whois_config.Config
}

// NewClient builds a client for one registry's database.
//
// The host is an argument rather than an option because there is no sensible default: unlike the
// clients that speak to one named service, this one speaks a protocol that several registries
// answer, and which of them is being asked is the whole of what distinguishes two clients.
func NewClient(host string, options ...whois_config.Option) *Client {
	return &Client{host: host, config: whois_config.New(options...)}
}

// Host is the database the client asks.
func (client *Client) Host() string {
	if client == nil {
		return ""
	}

	return client.host
}

func (client *Client) port() string {
	if port := client.config.Port; port != "" {
		return port
	}

	return DefaultPort
}

func (client *Client) timeout() time.Duration {
	if timeout := client.config.Timeout; timeout > 0 {
		return timeout
	}

	return DefaultTimeout
}

func (client *Client) inverseAttributes() []string {
	if attributes := client.config.InverseAttributes; len(attributes) != 0 {
		return attributes
	}

	return DefaultInverseAttributes
}

func (client *Client) maxContacts() int {
	if maxContacts := client.config.MaxContacts; maxContacts > 0 {
		return maxContacts
	}

	return DefaultMaxContacts
}

func (client *Client) maxResponseBytes() int {
	if maxResponseBytes := client.config.MaxResponseBytes; maxResponseBytes > 0 {
		return maxResponseBytes
	}

	return DefaultMaxResponseBytes
}

func (client *Client) dial(ctx context.Context, address string) (net.Conn, error) {
	if dial := client.config.Dial; dial != nil {
		connection, err := dial(ctx, address)
		if err != nil {
			return nil, fmt.Errorf("dial: %w", err)
		}

		return connection, nil
	}

	dialer := &net.Dialer{Timeout: client.timeout()}

	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("dial context: %w", err), address)
	}

	return connection, nil
}

// safeTerm reports whether the value can be sent as part of a query.
//
// The protocol is one line of text, and every part of a query is separated by spaces, so a value
// holding a newline would be a second query and a value beginning with a dash would be read as a
// flag. Neither is something a handle or an address ever needs.
func safeTerm(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}

	return !strings.ContainsAny(value, " \t\r\n")
}

// Query sends one query and returns the objects the database answered with.
func (client *Client) Query(ctx context.Context, query string) ([]*Object, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if client.host == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("host"))
	}

	if query == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("query"))
	}

	if strings.ContainsAny(query, "\r\n") {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: a query is one line", altshiftErrors.ErrValidationError),
			query,
		)
	}

	address := net.JoinHostPort(client.host, client.port())

	connection, err := client.dial(ctx, address)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("dial: %w", err), address)
	}
	defer func() {
		_ = connection.Close()
	}()

	// The connection is closed when the context is done, which is what makes a read abortable: the
	// protocol has no way to say "stop", so there is nothing to do but hang up. Stop releases the
	// hook, so a query that finished does not leave one behind.
	stop := context.AfterFunc(ctx, func() {
		_ = connection.Close()
	})
	defer stop()

	if err := connection.SetDeadline(time.Now().Add(client.timeout())); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("set deadline: %w", err), address)
	}

	if _, err := io.WriteString(connection, query+"\r\n"); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("write string: %w", err), query)
	}

	// One byte past the bound, so that a document sitting exactly on it is told from one that ran
	// over.
	body, err := io.ReadAll(io.LimitReader(connection, int64(client.maxResponseBytes())+1))
	if err != nil {
		// A context that ended closed the connection out from under the read, which is the caller
		// stopping rather than the database failing.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("context err: %w", ctxErr)
		}

		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("read all: %w", err), query)
	}

	if len(body) > client.maxResponseBytes() {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the answer ran past the bound", altshiftErrors.ErrParseError),
			query,
			client.maxResponseBytes(),
		)
	}

	objects, err := Parse(string(body))
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("parse: %w", err), query)
	}

	return objects, nil
}

// Parse reads a whois document into the objects it holds.
//
// An object is a run of "name: value" lines, one object to a block, blocks separated by blank
// lines. A line beginning with a space, a tab or a plus continues the attribute before it, and a
// line beginning with a percent or a hash is a comment -- which is also where the database announces
// that it has nothing, or that it will not answer.
func Parse(document string) ([]*Object, error) {
	objects := make([]*Object, 0)
	attributes := make([]*Attribute, 0)

	finish := func() {
		if len(attributes) != 0 {
			objects = append(objects, &Object{Attributes: attributes})
			attributes = make([]*Attribute, 0)
		}
	}

	scanner := bufio.NewScanner(strings.NewReader(document))
	// A remarks line can be long, and the default limit would end the scan in the middle of an
	// object rather than at the end of one.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")

		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			if responseError := parseResponseError(line); responseError != nil {
				// Nothing found is an answer, and the document says so where a search matched
				// nothing rather than answering with an empty one.
				if responseError.Code == noEntriesFound {
					continue
				}

				return nil, altshiftErrors.NewWithTrace(responseError, line)
			}

			continue
		}

		if strings.TrimSpace(line) == "" {
			finish()

			continue
		}

		// A continuation belongs to the attribute before it. One arriving with nothing before it is
		// a stray, and is dropped rather than invented into an attribute of its own.
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "+") {
			if len(attributes) == 0 {
				continue
			}

			continued := strings.TrimSpace(strings.TrimPrefix(line, "+"))
			if continued == "" {
				continue
			}

			last := attributes[len(attributes)-1]
			if last.Value == "" {
				last.Value = continued
			} else {
				last.Value += " " + continued
			}

			continue
		}

		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}

		attributes = append(
			attributes,
			&Attribute{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)},
		)
	}

	if err := scanner.Err(); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("scanner err: %w", err))
	}

	// A document that ends without a blank line still ends an object.
	finish()

	return objects, nil
}

// parseResponseError reads a comment announcing that the database will not answer, or has nothing.
//
// The line is "%ERROR:105: attribute is not searchable", the code being what distinguishes a
// rejected query from an empty result.
func parseResponseError(line string) *ResponseError {
	rest, found := strings.CutPrefix(strings.TrimSpace(strings.TrimLeft(line, "%#")), "ERROR:")
	if !found {
		return nil
	}

	code, message, found := strings.Cut(rest, ":")
	if !found {
		return nil
	}

	number, err := strconv.Atoi(strings.TrimSpace(code))
	if err != nil {
		return nil
	}

	return &ResponseError{Code: number, Message: strings.TrimSpace(message)}
}

// Inverse returns the objects referencing the value in one of the attributes.
//
// It is the search RDAP does not offer, and the one a walk from a domain is made of: a handle is
// worth nothing on its own, and everything as the thing a range points at.
func (client *Client) Inverse(
	ctx context.Context,
	attributes []string,
	value string,
	types []string,
) ([]*Object, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if len(attributes) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("attributes"))
	}

	if !safeTerm(value) {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: not a query term", altshiftErrors.ErrValidationError),
			value,
		)
	}

	for _, attribute := range slices.Concat(attributes, types) {
		if !safeTerm(attribute) {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: not a query term", altshiftErrors.ErrValidationError),
				attribute,
			)
		}
	}

	query := "-i " + strings.Join(attributes, ",")
	if len(types) != 0 {
		query += " -T " + strings.Join(types, ",")
	}
	query += " " + value

	objects, err := client.Query(ctx, query)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("query: %w", err), query)
	}

	return objects, nil
}

// Contacts returns the handles of the contacts whose abuse mailbox is at the domain.
//
// The abuse mailbox is the way in because it is the only address the database will search on. An
// inverse search on e-mail is refused outright -- "e-mail is not an inverse searchable attribute" --
// so the conventional abuse@<domain> is what stands in for it.
func (client *Client) Contacts(ctx context.Context, domain string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if domain == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	objects, err := client.Inverse(ctx, []string{"abuse-mailbox"}, AbuseMailbox(domain), nil)
	if err != nil {
		// A database that will not search on the attribute has said so, and there is nothing here
		// to fall back on: the walk ends rather than the run failing. Only that one code, because
		// the others -- an access denied, a caller asked to slow down -- are the database saying
		// something a caller needs to hear rather than that the domain has no contacts.
		if responseError, ok := errors.AsType[*ResponseError](err); ok && responseError != nil &&
			responseError.Code == attributeNotSearchable {
			return []string{}, nil
		}

		return nil, altshiftErrors.New(fmt.Errorf("inverse: %w", err), domain)
	}

	handles := make([]string, 0, len(objects))

	for _, object := range objects {
		// A contact is a person or a role, named by its nic-hdl; an incident response team is named
		// by the irt attribute that opens it. Both are referenced by ranges.
		for _, handle := range slices.Concat(object.Values("nic-hdl"), object.Values("irt")) {
			if handle = strings.TrimSpace(handle); handle != "" {
				handles = append(handles, handle)
			}
		}
	}

	slices.Sort(handles)

	return slices.Compact(handles), nil
}

// AbuseMailbox is the address a party's abuse contact is conventionally at.
func AbuseMailbox(domain string) string {
	return "abuse@" + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// Ranges returns the address space registered to the contacts whose abuse mailbox is at the domain.
func (client *Client) Ranges(ctx context.Context, domain string) ([]*Range, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if domain == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	handles, err := client.Contacts(ctx, domain)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("contacts: %w", err), domain)
	}

	ranges := make([]*Range, 0)
	seen := make(map[string]struct{})

	for index, handle := range handles {
		if index >= client.maxContacts() {
			break
		}

		objects, err := client.Inverse(
			ctx,
			client.inverseAttributes(),
			handle,
			[]string{TypeInetnum, TypeInet6num},
		)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("inverse: %w", err), handle)
		}

		for _, object := range objects {
			objectType, key := object.Type()
			if objectType != TypeInetnum && objectType != TypeInet6num {
				continue
			}

			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			networks, err := Networks(key)
			if err != nil {
				return nil, altshiftErrors.New(fmt.Errorf("networks: %w", err), key)
			}

			ranges = append(
				ranges,
				&Range{
					Inetnum:  key,
					NetName:  object.Value("netname"),
					Status:   object.Value("status"),
					Country:  object.Value("country"),
					Contact:  handle,
					Networks: networks,
				},
			)
		}
	}

	return ranges, nil
}

// Networks expresses a range as CIDR.
//
// A v4 allocation is written as a first and last address and a v6 one as a prefix, so both forms
// have to be read.
func Networks(value string) ([]string, error) {
	first, last, found := strings.Cut(value, "-")
	if !found {
		networks, err := cidr.Prefixes(value)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("prefixes: %w", err), value)
		}

		return networks, nil
	}

	networks, err := cidr.CoverText(first, last)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("cover text: %w", err), value)
	}

	return networks, nil
}
