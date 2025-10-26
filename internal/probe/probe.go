package probe

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
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

func GetCertificate(hostname, addr string, port int, timeout time.Duration) (*Result, error) {
	target := net.JoinHostPort(addr, strconv.Itoa(port))

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, &tls.Config{
		InsecureSkipVerify: true, // 🔥 still required to fetch untrusted certs
		ServerName:         hostname,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connect failed: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()

	return &Result{
		PeerCertificates: state.PeerCertificates,
		TLSVersion:       tlsVersionString(state.Version),
		CipherSuite:      tls.CipherSuiteName(state.CipherSuite),
		OCSPStapled:      len(state.OCSPResponse) > 0,
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
