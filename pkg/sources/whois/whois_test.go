package whois

import (
	"bufio"
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whois/whois_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

// server stands a whois service up on a port of the operating system's choosing.
//
// A real listener rather than a stubbed dial, because the protocol is the thing under test: the
// query is a line the client has to terminate, and the answer ends when the connection does.
type server struct {
	answer func(query string) string

	asked []string
	lock  sync.Mutex
}

func (fake *server) queries() []string {
	fake.lock.Lock()
	defer fake.lock.Unlock()

	return slices.Clone(fake.asked)
}

func serverClient(t *testing.T, answer func(query string) string, options ...whois_config.Option) (*Client, *server) {
	t.Helper()

	fake := &server{answer: answer}

	listenConfig := &net.ListenConfig{}

	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer func() {
					_ = connection.Close()
				}()

				query, err := bufio.NewReader(connection).ReadString('\n')
				if err != nil {
					return
				}
				query = strings.TrimRight(query, "\r\n")

				fake.lock.Lock()
				fake.asked = append(fake.asked, query)
				fake.lock.Unlock()

				_, _ = connection.Write([]byte(fake.answer(query)))
			}()
		}
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("could not split the address: %v", err)
	}

	return NewClient(host, slices.Concat([]whois_config.Option{whois_config.WithPort(port)}, options)...), fake
}

// database is a live run reduced to what the walk needs: a contact whose abuse mailbox is at the
// domain, and the ranges that reference it.
func database(query string) string {
	switch {
	case strings.HasPrefix(query, "-i abuse-mailbox"):
		return `% comment
irt:            IRT-EXAMPLE
abuse-mailbox:  abuse@example.com

role:           Example Technical Contact
nic-hdl:        ETC1-EXAMPLE
abuse-mailbox:  abuse@example.com
`
	case strings.Contains(query, "IRT-EXAMPLE"):
		return `inetnum:        192.0.2.0 - 192.0.2.255
netname:        EXAMPLE-NET
country:        SE
status:         ALLOCATED PORTABLE
`
	case strings.Contains(query, "ETC1-EXAMPLE"):
		// The same object under the other contact -- both contacts are on it, so both searches
		// answer with it -- and one only this contact reaches.
		return `inetnum:        192.0.2.0 - 192.0.2.255
netname:        EXAMPLE-NET
country:        SE
status:         ALLOCATED PORTABLE

inet6num:       2001:db8::/32
netname:        EXAMPLE-V6
country:        SE
`
	}

	return "%ERROR:101: no entries found\n"
}

func TestRanges(t *testing.T) {
	t.Parallel()

	client, _ := serverClient(t, database)

	ranges, err := client.Ranges(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	networks := make([]string, 0)
	for _, item := range ranges {
		networks = append(networks, item.Networks...)
	}

	// The v4 range once, though two contacts reach it, and the v6 allocation the second one adds.
	if !slices.Equal(networks, []string{"192.0.2.0/24", "2001:db8::/32"}) {
		t.Fatalf("expected both ranges, the shared one once, got %v", networks)
	}

	if ranges[0].NetName != "EXAMPLE-NET" || ranges[0].Country != "SE" {
		t.Errorf("expected the registry's detail kept, got %+v", ranges[0])
	}
	// The handle it was reached through, which is what lets an operator check the reasoning.
	if ranges[0].Contact != "ETC1-EXAMPLE" && ranges[0].Contact != "IRT-EXAMPLE" {
		t.Errorf("expected the contact kept, got %q", ranges[0].Contact)
	}
}

// TestContactsAsksForTheAbuseMailbox holds the way in. An inverse search on e-mail is refused, so
// the conventional abuse address is what stands in for it.
func TestContactsAsksForTheAbuseMailbox(t *testing.T) {
	t.Parallel()

	client, fake := serverClient(t, database)

	handles, err := client.Contacts(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(handles, []string{"ETC1-EXAMPLE", "IRT-EXAMPLE"}) {
		t.Errorf("expected both a role and an incident response team, got %v", handles)
	}

	queries := fake.queries()
	if len(queries) == 0 || queries[0] != "-i abuse-mailbox abuse@example.com" {
		t.Errorf("expected the abuse mailbox asked for, got %v", queries)
	}
}

// TestContactsWhereTheAttributeIsRefused holds the one answer that is not a failure. A database that
// will not search the attribute has said the walk cannot go this way, which is not the run breaking.
func TestContactsWhereTheAttributeIsRefused(t *testing.T) {
	t.Parallel()

	client, _ := serverClient(t, func(string) string {
		return "%ERROR:105: attribute is not searchable\n%\n% \"e-mail\" is not an inverse searchable attribute.\n"
	})

	handles, err := client.Contacts(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("expected a refusal to be an answer, got %v", err)
	}
	if len(handles) != 0 {
		t.Errorf("expected nothing, got %v", handles)
	}
}

// TestQuerySurfacesOtherResponseErrors holds the other side of it: a caller asked to slow down, or
// refused access, has been told something it needs to hear rather than that the domain has nothing.
func TestQuerySurfacesOtherResponseErrors(t *testing.T) {
	t.Parallel()

	client, _ := serverClient(t, func(string) string {
		return "%ERROR:201: access denied\n"
	})

	_, err := client.Contacts(t.Context(), "example.com")
	if err == nil {
		t.Fatal("expected an access denial to be an error")
	}

	responseError, ok := errors.AsType[*ResponseError](err)
	if !ok || responseError == nil || responseError.Code != 201 {
		t.Errorf("expected the response error kept, got %v", err)
	}
}

// TestRangesIsBounded holds why the bound is there: every contact found at a domain is a query of
// its own against a database that asks callers to be gentle.
func TestRangesIsBounded(t *testing.T) {
	t.Parallel()

	client, fake := serverClient(t, database, whois_config.WithMaxContacts(1))

	if _, err := client.Ranges(t.Context(), "example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The abuse mailbox, and the one contact the bound allowed.
	if got := len(fake.queries()); got != 2 {
		t.Errorf("expected two queries, got %d: %v", got, fake.queries())
	}
}

// TestQueryRejectsASecondLine holds what a query is. The protocol is one line of text, so a term
// holding a newline would be a second query, and one beginning with a dash would be read as a flag.
func TestQueryRejectsASecondLine(t *testing.T) {
	t.Parallel()

	client, fake := serverClient(t, database)

	for _, value := range []string{"AA1\r\n-i mnt-by SOMETHING", "AA1\nmore", "-i", "-flag", "a b", ""} {
		if _, err := client.Inverse(t.Context(), []string{"admin-c"}, value, nil); err == nil {
			t.Errorf("expected %q to be rejected", value)
		} else if !errors.Is(err, altshiftErrors.ErrValidationError) {
			t.Errorf("expected %q to fail validation, got %v", value, err)
		}
	}

	// Rejected before anything was sent, which is the point of rejecting it.
	if got := len(fake.queries()); got != 0 {
		t.Errorf("expected nothing asked, got %v", fake.queries())
	}
}

// TestQueryBoundsTheAnswer holds that an answer is not read forever. An inverse search on a large
// maintainer returns tens of thousands of objects.
func TestQueryBoundsTheAnswer(t *testing.T) {
	t.Parallel()

	client, _ := serverClient(
		t,
		func(string) string {
			return strings.Repeat("inetnum: 192.0.2.0 - 192.0.2.255\n\n", 1000)
		},
		whois_config.WithMaxResponseBytes(64),
	)

	if _, err := client.Query(t.Context(), "anything"); err == nil {
		t.Error("expected an answer past the bound to be an error")
	} else if !errors.Is(err, altshiftErrors.ErrParseError) {
		t.Errorf("expected a parse error, got %v", err)
	}
}

// TestParse holds the shape of the documents. What structure the protocol has comes from RPSL, and
// the awkward parts are the continuations and the comments the database announces itself in.
func TestParse(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		document    string
		expect      []map[string]string
		expectError bool
	}{
		{
			name:     "one object",
			document: "inetnum: 192.0.2.0 - 192.0.2.255\nnetname: EXAMPLE\n",
			expect:   []map[string]string{{"inetnum": "192.0.2.0 - 192.0.2.255", "netname": "EXAMPLE"}},
		},
		{
			name:     "two objects, separated by a blank line",
			document: "inetnum: 192.0.2.0 - 192.0.2.255\n\ninetnum: 198.51.100.0 - 198.51.100.255\n",
			expect: []map[string]string{
				{"inetnum": "192.0.2.0 - 192.0.2.255"},
				{"inetnum": "198.51.100.0 - 198.51.100.255"},
			},
		},
		{
			// A value too long for one line is written across several, and the continuation belongs
			// to the attribute before it rather than being an attribute of its own.
			name:     "a continued value",
			document: "descr: Example Ltd\n       Second line\n+      Third line\nnetname: EXAMPLE\n",
			expect:   []map[string]string{{"descr": "Example Ltd Second line Third line", "netname": "EXAMPLE"}},
		},
		{
			name:     "comments are not attributes",
			document: "% this is a comment\ninetnum: 192.0.2.0 - 192.0.2.255\n# so is this\n",
			expect:   []map[string]string{{"inetnum": "192.0.2.0 - 192.0.2.255"}},
		},
		{
			// Nothing found is an answer, and the database says so in a comment rather than by
			// answering with an empty document.
			name:     "no entries found",
			document: "%ERROR:101: no entries found\n%\n% No entries found in source APNIC.\n",
			expect:   []map[string]string{},
		},
		{
			name:        "a refused query",
			document:    "%ERROR:105: attribute is not searchable\n",
			expectError: true,
		},
		{name: "an empty document", document: "", expect: []map[string]string{}},
		{
			// A stray continuation with nothing before it is dropped rather than invented into an
			// attribute of its own.
			name:     "a stray continuation",
			document: "   orphaned\ninetnum: 192.0.2.0 - 192.0.2.255\n",
			expect:   []map[string]string{{"inetnum": "192.0.2.0 - 192.0.2.255"}},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			objects, err := Parse(testCase.document)

			if testCase.expectError {
				var responseError *ResponseError
				if !errors.As(err, &responseError) {
					t.Fatalf("%s: expected a response error, got %v", testCase.name, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}

			if len(objects) != len(testCase.expect) {
				t.Fatalf("%s: expected %d objects, got %d", testCase.name, len(testCase.expect), len(objects))
			}

			for index, want := range testCase.expect {
				for name, value := range want {
					if got := objects[index].Value(name); got != value {
						t.Errorf("%s: object %d %s: expected %q, got %q", testCase.name, index, name, value, got)
					}
				}
			}
		})
	}
}

// TestObjectAccessors holds that the first attribute is what says what a block is, which is the only
// thing distinguishing an inetnum from a role in a document that marks neither.
func TestObjectAccessors(t *testing.T) {
	t.Parallel()

	objects, err := Parse("inetnum: 192.0.2.0 - 192.0.2.255\ndescr: one\ndescr: two\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(objects) != 1 {
		t.Fatalf("expected one object, got %d", len(objects))
	}

	objectType, key := objects[0].Type()
	if objectType != TypeInetnum || key != "192.0.2.0 - 192.0.2.255" {
		t.Errorf("expected the type and key, got %q and %q", objectType, key)
	}

	// The first, an object being free to repeat an attribute.
	if got := objects[0].Value("descr"); got != "one" {
		t.Errorf("expected the first value, got %q", got)
	}
	if got := objects[0].Values("descr"); !slices.Equal(got, []string{"one", "two"}) {
		t.Errorf("expected both values, got %v", got)
	}
	if got := objects[0].Value("absent"); got != "" {
		t.Errorf("expected nothing for an absent attribute, got %q", got)
	}

	var nilObject *Object
	if objectType, key := nilObject.Type(); objectType != "" || key != "" {
		t.Error("expected a nil object to have no type")
	}
	if nilObject.Value("inetnum") != "" || nilObject.Values("inetnum") != nil {
		t.Error("expected a nil object to have no values")
	}
}

func TestNetworks(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		value       string
		expect      []string
		expectError bool
	}{
		// A v4 allocation is written as two addresses and a v6 one as a prefix, so both forms have
		// to be read.
		{name: "a v4 range", value: "192.0.2.0 - 192.0.2.255", expect: []string{"192.0.2.0/24"}},
		{name: "a v6 prefix", value: "2001:db8::/32", expect: []string{"2001:db8::/32"}},
		{name: "a single address", value: "192.0.2.1", expect: []string{"192.0.2.1/32"}},
		{name: "nonsense", value: "not a range", expectError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := Networks(testCase.value)

			if testCase.expectError {
				if err == nil {
					t.Fatalf("%s: expected an error", testCase.name)
				}

				return
			}

			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}
			if !slices.Equal(got, testCase.expect) {
				t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expect, got)
			}
		})
	}
}

func TestAbuseMailbox(t *testing.T) {
	t.Parallel()

	if got := AbuseMailbox("Example.COM."); got != "abuse@example.com" {
		t.Errorf("expected the address lowered and rooted, got %q", got)
	}
}

func TestResponseErrorMessage(t *testing.T) {
	t.Parallel()

	responseError := &ResponseError{Code: 105, Message: "attribute is not searchable"}
	if got := responseError.Error(); !strings.Contains(got, "105") {
		t.Errorf("expected the code in the message, got %q", got)
	}

	var nilError *ResponseError
	if nilError.Error() == "" {
		t.Error("expected a nil error to have a message")
	}
}

func TestArgumentChecks(t *testing.T) {
	t.Parallel()

	var nilClient *Client
	if _, err := nilClient.Query(t.Context(), "anything"); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if _, err := nilClient.Inverse(t.Context(), []string{"admin-c"}, "AA1", nil); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if _, err := nilClient.Contacts(t.Context(), "example.com"); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if _, err := nilClient.Ranges(t.Context(), "example.com"); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if nilClient.Host() != "" {
		t.Error("expected a nil client to have no host")
	}

	client := NewClient(ApnicHost)
	if _, err := client.Query(t.Context(), ""); err == nil {
		t.Error("expected an empty query to be an error")
	}
	if _, err := client.Query(t.Context(), "one\ntwo"); err == nil {
		t.Error("expected a two-line query to be an error")
	}
	if _, err := client.Inverse(t.Context(), nil, "AA1", nil); err == nil {
		t.Error("expected no attributes to be an error")
	}
	if _, err := client.Contacts(t.Context(), ""); err == nil {
		t.Error("expected an empty domain to be an error")
	}
	if _, err := client.Ranges(t.Context(), ""); err == nil {
		t.Error("expected an empty domain to be an error")
	}
	if client.Host() != ApnicHost {
		t.Errorf("expected the host, got %q", client.Host())
	}

	// A client with no host has no database to ask, and says so rather than dialling nothing.
	if _, err := NewClient("").Query(t.Context(), "anything"); err == nil {
		t.Error("expected an empty host to be an error")
	}
}

// TestQueryStopsWithTheContext holds that a query is abortable. The protocol has no way to say
// "stop", so there is nothing to do but hang up.
func TestQueryStopsWithTheContext(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	client, _ := serverClient(t, func(string) string {
		// Never answers, so only the context can end this.
		<-release

		return ""
	})

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		_, err := client.Query(ctx, "anything")
		done <- err
	}()

	cancel()

	if err := <-done; err == nil {
		t.Error("expected a cancelled context to end the query")
	}
}
