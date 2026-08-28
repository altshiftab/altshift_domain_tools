package resolver

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNew(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		address     string
		expect      string
		expectError bool
	}{
		{name: "an empty address is the default", address: "", expect: DefaultAddress},
		{name: "an address with a port", address: "9.9.9.9:53", expect: "9.9.9.9:53"},
		{name: "an address with no port is an error", address: "9.9.9.9", expectError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			client, err := New(testCase.address)

			if testCase.expectError {
				if err == nil {
					t.Fatalf("%s: expected an error, got none", testCase.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}

			if client.address() != testCase.expect {
				t.Errorf("%s: expected %q, got %q", testCase.name, testCase.expect, client.address())
			}
		})
	}
}

func TestDefaults(t *testing.T) {
	t.Parallel()

	client := &Client{}
	if client.timeout() != DefaultTimeout {
		t.Errorf("expected the default timeout, got %v", client.timeout())
	}
	if client.address() != DefaultAddress {
		t.Errorf("expected the default address, got %q", client.address())
	}

	// A negative timeout would mean a deadline already passed, so it is refused rather than applied.
	if (&Client{Timeout: -time.Second}).timeout() != DefaultTimeout {
		t.Error("expected a non-positive timeout to fall back to the default")
	}
}

// TestDomainExistsReadsTheResponseCode holds the reason this is here rather than over net.Resolver:
// the response code is what tells a name that does not exist from a resolver that has stopped
// answering, and the standard library does not report it.
func TestDomainExistsReadsTheResponseCode(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		rcode       int
		expect      bool
		expectError bool
		expectRefus bool
	}{
		{name: "NOERROR is a name that exists", rcode: dns.RcodeSuccess, expect: true},
		{
			// The common answer during a brute force, and not a failure.
			name:   "NXDOMAIN is a name that does not",
			rcode:  dns.RcodeNameError,
			expect: false,
		},
		{
			name:        "REFUSED is the resolver declining",
			rcode:       dns.RcodeRefused,
			expectError: true,
			expectRefus: true,
		},
		{
			name:        "SERVFAIL is treated the same way",
			rcode:       dns.RcodeServerFailure,
			expectError: true,
			expectRefus: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			server, address := newDnsServer(t, testCase.rcode)
			defer func() {
				_ = server.Shutdown()
			}()

			client := &Client{Address: address, Timeout: 3 * time.Second}

			exists, err := client.DomainExists(t.Context(), "example.com")

			if testCase.expectError {
				if err == nil {
					t.Fatalf("%s: expected an error, got none", testCase.name)
				}
				if testCase.expectRefus && !IsRefused(err) {
					t.Errorf("%s: expected a refusal, got %v", testCase.name, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}

			if exists != testCase.expect {
				t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expect, exists)
			}
		})
	}
}

// newDnsServer starts a UDP resolver that answers everything with the given response code.
func newDnsServer(t *testing.T, rcode int) (*dns.Server, string) {
	t.Helper()

	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetRcode(request, rcode)
		_ = writer.WriteMsg(response)
	})

	ready := make(chan struct{})
	server := &dns.Server{
		Addr:              "127.0.0.1:0",
		Net:               "udp",
		Handler:           handler,
		NotifyStartedFunc: func() { close(ready) },
	}

	go func() {
		_ = server.ListenAndServe()
	}()

	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("the test resolver did not start")
	}

	// NotifyStartedFunc fires once the listener is up, so the connection is there; nilaway cannot
	// see that through the callback, and a nil here would mean the library broke its own contract.
	packetConn := server.PacketConn
	if packetConn == nil {
		t.Fatal("the test resolver started without a connection")
	}

	localAddress := packetConn.LocalAddr()
	if localAddress == nil {
		t.Fatal("the test resolver's connection has no address")
	}

	return server, localAddress.String()
}

var (
	errUnrelated = errors.New("something else")
	errContext   = errors.New("context")
)

func TestIsRefused(t *testing.T) {
	t.Parallel()

	if IsRefused(nil) {
		t.Error("expected no error not to be a refusal")
	}
	if IsRefused(errUnrelated) {
		t.Error("expected an unrelated error not to be a refusal")
	}
	if !IsRefused(&RefusedError{Domain: "example.com", Rcode: dns.RcodeRefused}) {
		t.Error("expected a refusal to be recognised")
	}
	// It has to be found through a wrapping, which is how it reaches the brute force.
	if !IsRefused(errors.Join(errContext, &RefusedError{Domain: "example.com"})) {
		t.Error("expected a wrapped refusal to be recognised")
	}
}

func TestDomainExistsArgumentChecks(t *testing.T) {
	t.Parallel()

	if _, err := (&Client{}).DomainExists(t.Context(), ""); err == nil {
		t.Error("expected an empty domain to be an error")
	}
}
