package resolver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

type Options struct {
	// If true, use the system resolver (net.DefaultResolver). If false, use Servers via miekg/dns.
	System   bool
	Servers  []string // list of "ip" or "ip:port" (port defaults to 53)
	IPv4     bool
	IPv6     bool
	Timeout  time.Duration
	MaxCNAME int // how many CNAME hops to follow; if 0 -> default 5
}

func Resolve(ctx context.Context, name string, opt Options) ([]string, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = 3 * time.Second
	}
	if opt.MaxCNAME <= 0 {
		opt.MaxCNAME = 5
	}

	if opt.System {
		return resolveSystem(ctx, name, opt)
	}

	client := &dns.Client{
		Net:     "udp",
		Timeout: opt.Timeout,
	}

	server := opt.Servers[0]
	msg := new(dns.Msg)

	// TODO IPv6 and both
	msg.SetQuestion(dns.Fqdn(name), dns.TypeA)
	msg.RecursionDesired = true
	in, _, err := client.Exchange(msg, server)

	if err != nil {
		return nil, fmt.Errorf("dns query to %s failed: %w", server, err)
	}

	var out []string
	for _, rr := range in.Answer {
		switch t := rr.(type) {
		case *dns.A:
			out = append(out, t.A.String())
		case *dns.AAAA:
			out = append(out, t.AAAA.String())
		}
	}

	return unique(out), nil
}

func resolveSystem(ctx context.Context, name string, opt Options) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	var nets []string

	switch {
	case opt.IPv4 && !opt.IPv6:
		nets = []string{"ip4"}
	case opt.IPv6 && !opt.IPv4:
		nets = []string{"ip6"}
	default:
		nets = []string{"ip4", "ip6"}
	}

	var out []string
	for _, netw := range nets {
		ips, err := net.DefaultResolver.LookupIP(ctx, netw, name)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip != nil {
				out = append(out, ip.String())
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("system resolver: no addresses for %q", name)
	}
	return unique(out), nil
}

func unique(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))

	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	return out
}
