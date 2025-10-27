package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"
)

type Result struct {
	PeerCertificates []*x509.Certificate
	TLSVersion       string
	CipherSuite      string
	OCSPStapled      bool
}

func GetCertificate(ctx context.Context, hostname, addr string, port int, timeout time.Duration) (*Result, error) {
	//start := time.Now()
	target := net.JoinHostPort(addr, strconv.Itoa(port))

	slog.Debug("tls: dial start",
		"target", target,
		"sni", hostname,
		"timeout", timeout)

	td := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostname,
		},
	}

	conn, err := td.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("TLS connect failed: %w", err)
	}
	defer conn.Close()

	cs := conn.(*tls.Conn).ConnectionState()

	return &Result{
		PeerCertificates: cs.PeerCertificates,
		TLSVersion:       tlsVersionString(cs.Version),
		CipherSuite:      tls.CipherSuiteName(cs.CipherSuite),
		OCSPStapled:      len(cs.OCSPResponse) > 0,
	}, nil
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}
