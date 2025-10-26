package resolver

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func ParseResolversFromFlag(flag string) (bool, []string, error) {
	r := strings.TrimSpace(flag)
	if r == "" {
		return false, nil, fmt.Errorf("resolver flag cannot be empty")
	}

	// Use system resolver
	if strings.EqualFold(r, "system") {
		return true, nil, nil
	}

	// Split on comma for multiple resolvers
	parts := strings.Split(r, ",")
	out := make([]string, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return false, nil, fmt.Errorf("empty resolver in list")
		}

		// Case: "IP:port"
		if host, port, err := net.SplitHostPort(p); err == nil {
			if _, err := netip.ParseAddr(host); err != nil {
				return false, nil, fmt.Errorf("invalid resolver address %q", host)
			}
			if _, err := strconv.Atoi(port); err != nil {
				return false, nil, fmt.Errorf("invalid port %q in resolver", port)
			}
			out = append(out, p)
			continue
		}

		// Case: plain "IP" (port will be added later in resolver)
		if _, err := netip.ParseAddr(p); err != nil {
			return false, nil, fmt.Errorf("invalid resolver address %q (expect IP or IP:port)", p)
		}

		out = append(out, p)
	}

	return false, out, nil
}
