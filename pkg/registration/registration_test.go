package registration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/registration/registration_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

var errFakeResolver = errors.New("fake resolver")

type fakeResolver struct {
	exists bool
	err    error
	calls  atomic.Int32
}

func (fake *fakeResolver) DomainExists(_ context.Context, _ string) (bool, error) {
	fake.calls.Add(1)
	return fake.exists, fake.err
}

// newServer stands in for both IANA and one registry: the bootstrap list names the server itself as
// the registry for .com, and .se is listed nowhere.
func newServer(t *testing.T, bootstrapStatus *atomic.Int32) *httptest.Server {
	t.Helper()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/dns.json":
			if status := int(bootstrapStatus.Load()); status != http.StatusOK {
				writer.WriteHeader(status)
				return
			}

			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"services":[[["com","net"],["` + server.URL + `/com/v1"]]]}`))
		case request.URL.Path == "/com/v1/domain/registered.com":
			writer.Header().Set("Content-Type", ContentType)
			_, _ = writer.Write([]byte(`{"objectClassName":"domain","ldhName":"registered.com"}`))
		case request.URL.Path == "/com/v1/domain/lapsed.com":
			writer.WriteHeader(http.StatusNotFound)
		case strings.HasPrefix(request.URL.Path, "/com/v1/domain/"):
			writer.WriteHeader(http.StatusTooManyRequests)
		default:
			writer.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func newChecker(t *testing.T, server *httptest.Server, domainResolver *fakeResolver) *Checker {
	t.Helper()

	bootstrapUrl, err := url.Parse(server.URL + "/dns.json")
	if err != nil {
		t.Fatalf("url parse: %v", err)
	}

	return NewChecker(
		registration_config.WithBootstrapUrl(bootstrapUrl),
		registration_config.WithResolver(domainResolver),
		registration_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
	)
}

func TestStatus(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		domain         string
		resolverExists bool
		resolverErr    error
		expected       Status
		expectErr      bool
		expectResolver bool
	}{
		{name: "the registry holds it", domain: "registered.com", expected: StatusRegistered},
		{name: "written with a trailing dot and capitals", domain: "Registered.COM.", expected: StatusRegistered},
		{name: "the registry turns it away", domain: "lapsed.com", expected: StatusUnregistered},
		{name: "the registry cannot be asked", domain: "throttled.com", expected: StatusUnknown, expectErr: true},
		{
			name:           "no RDAP server, and the name exists",
			domain:         "kivra.se",
			resolverExists: true,
			expected:       StatusRegistered,
			expectResolver: true,
		},
		{
			name:           "no RDAP server, and the name does not exist",
			domain:         "lapsed.se",
			expected:       StatusUnregistered,
			expectResolver: true,
		},
		{
			name:           "no RDAP server, and the resolver fails",
			domain:         "kivra.se",
			resolverErr:    errFakeResolver,
			expected:       StatusUnknown,
			expectErr:      true,
			expectResolver: true,
		},
		{name: "empty", domain: "", expected: StatusUnknown, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			bootstrapStatus := &atomic.Int32{}
			bootstrapStatus.Store(http.StatusOK)

			domainResolver := &fakeResolver{exists: testCase.resolverExists, err: testCase.resolverErr}
			checker := newChecker(t, newServer(t, bootstrapStatus), domainResolver)

			status, err := checker.Status(t.Context(), testCase.domain)
			if (err != nil) != testCase.expectErr {
				t.Fatalf("got error %v, expected an error: %v", err, testCase.expectErr)
			}
			if status != testCase.expected {
				t.Errorf("got %s, expected %s", status, testCase.expected)
			}
			if asked := domainResolver.calls.Load() > 0; asked != testCase.expectResolver {
				t.Errorf("resolver asked: %v, expected %v", asked, testCase.expectResolver)
			}
		})
	}
}

// TestStatusRetriesTheBootstrap asserts that a list that could not be read is read again next time,
// rather than every later answer being unknown for the life of the checker.
func TestStatusRetriesTheBootstrap(t *testing.T) {
	t.Parallel()

	bootstrapStatus := &atomic.Int32{}
	bootstrapStatus.Store(http.StatusServiceUnavailable)

	checker := newChecker(t, newServer(t, bootstrapStatus), &fakeResolver{})

	status, err := checker.Status(t.Context(), "lapsed.com")
	if err == nil || status != StatusUnknown {
		t.Fatalf("got %s and error %v, expected unknown with an error", status, err)
	}

	bootstrapStatus.Store(http.StatusOK)

	status, err = checker.Status(t.Context(), "lapsed.com")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status != StatusUnregistered {
		t.Errorf("got %s, expected %s", status, StatusUnregistered)
	}
}
