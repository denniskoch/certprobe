package resolver

import (
	"context"
	"testing"
	"time"
)

func TestResolve_System(t *testing.T) {
	ctx := context.Background()

	opts := Options{
		System:   true,
		IPv4:     true,
		IPv6:     true,
		Timeout:  5 * time.Second,
		MaxCNAME: 5,
	}

	ips, err := Resolve(ctx, "www.google.com", opts)
	if err != nil {
		t.Fatalf("resolve(system) returned error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatalf("resolve(system) returned zero IPs")
	}
}

func TestResolve_GooglePublicDNS(t *testing.T) {
	ctx := context.Background()

	opts := Options{
		System:   false,
		Servers:  []string{"8.8.8.8:53"},
		IPv4:     true,
		IPv6:     true,
		Timeout:  5 * time.Second,
		MaxCNAME: 5,
	}

	ips, err := Resolve(ctx, "www.google.com", opts)
	if err != nil {
		t.Fatalf("resolve(8.8.8.8) returned error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatalf("resolve(8.8.8.8) returned zero IPs")
	}
}
