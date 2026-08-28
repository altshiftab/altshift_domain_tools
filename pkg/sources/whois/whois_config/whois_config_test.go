package whois_config

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	t.Parallel()

	// No options is the ordinary call: the client fills in the well-known port and its own bounds,
	// so the config leaving them zero is what says "unset" rather than "no port" or "no contacts".
	empty := New()
	if empty == nil {
		t.Fatal("expected a config, got nil")
	}
	if empty.Port != "" || empty.Timeout != 0 || empty.MaxContacts != 0 ||
		empty.MaxResponseBytes != 0 || len(empty.InverseAttributes) != 0 || empty.Dial != nil {
		t.Errorf("expected everything unset, got %+v", empty)
	}

	// A nil option is skipped rather than panicking, so a caller can pass one conditionally.
	if New(nil) == nil {
		t.Error("expected a nil option to be skipped")
	}

	dial := func(_ context.Context, _ string) (net.Conn, error) { return nil, nil }

	config := New(
		WithPort("4343"),
		WithTimeout(5*time.Second),
		WithMaxContacts(3),
		WithMaxResponseBytes(1024),
		WithInverseAttributes("admin-c"),
		// Replacing rather than accumulating: which attributes to search is one setting, and a
		// caller narrowing it means the narrower list rather than both.
		WithInverseAttributes("admin-c", "tech-c", "abuse-c"),
		WithDial(dial),
	)

	if config.Port != "4343" || config.Timeout != 5*time.Second {
		t.Errorf("expected the port and timeout taken, got %+v", config)
	}
	// The bounds matter because every contact found at a domain is a query of its own.
	if config.MaxContacts != 3 || config.MaxResponseBytes != 1024 {
		t.Errorf("expected the bounds taken, got %+v", config)
	}
	if !slices.Equal(config.InverseAttributes, []string{"admin-c", "tech-c", "abuse-c"}) {
		t.Errorf("expected the attributes replaced, got %v", config.InverseAttributes)
	}
	if config.Dial == nil {
		t.Error("expected the dial to be taken")
	}
}
