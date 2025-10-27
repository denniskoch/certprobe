// internal/format/summary.go
package format

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/denniskoch/certprobe/internal/probe"
)

type Options struct {
	Host string // original hostname (SNI/verify target)
	Addr string // probed IP
	//WarnDays    int      // threshold for "expiring soon" (e.g., 60)
	//Verbose     bool     // print a bit more detail
	//JSON        bool     // print machine output instead of text
	//Color       bool     // (optional) colorize statuses if you want
	//ExtraFields []string // reserved for future
}

func RenderSummary(ctx context.Context, res *probe.Result, opt Options) error {

	// Text mode (aligned, friendly)
	w := os.Stdout
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "Target:\t%s (%s)\n", opt.Host, opt.Addr)
	fmt.Fprintf(tw, "TLS:\t%s / %s\n", res.TLSVersion, res.CipherSuite)
	fmt.Fprintf(tw, "\n")

	for i, cert := range res.PeerCertificates {
		fmt.Fprintf(tw, "Cert #%d:\n", i)
		fmt.Fprintf(tw, "\tCommon Name (CN)\t%s\n", cert.Subject.CommonName)
		fmt.Fprintf(tw, "\tsubjectAltName (SAN)\t%s\n", formatSubjectAltName(cert))
		fmt.Fprintf(tw, "\tCertificate Validity (UTC)\t%s\n", formatValidity(cert))
		fmt.Fprintf(tw, "\tSignature Algorithm\t%s\n", cert.SignatureAlgorithm)
		fmt.Fprintf(tw, "\tKey Usage\t%s\n", formatKeyUsage(cert))
		fmt.Fprintf(tw, "\tExtended Key Usage\t%s\n", formatExtKeyUsage(cert))
		fmt.Fprintf(tw, "\tSerial\t%s\n", formatSerial(cert))
		fmt.Fprintf(tw, "\tFingerprint (SHA-1)\t%s\n", formatFingerprint(cert, "sha1"))
		fmt.Fprintf(tw, "\t\t%s\n", formatFingerprint(cert, "sha256"))
		fmt.Fprintf(tw, "\tIssuer\t%s\n", cert.Issuer.CommonName)

		fmt.Fprintf(tw, "\n")
	}
	//fmt.Fprintf(tw, "Hostname:\t%v\n", ver != nil && ver.HostnameOK)
	//fmt.Fprintf(tw, "Trusted (Chain):\t%v\n", ver != nil && ver.ChainOK)
	//fmt.Fprintf(tw, "Expires In:\t%d days\n", zeroIfNil(ver, func(v *verify.Verdict) int { return v.DaysRemaining }))
	//fmt.Fprintf(tw, "Leaf CN:\t%s\n", leafCN(res))
	//fmt.Fprintf(tw, "Issuer:\t%s\n", leafIssuer(res))
	//fmt.Fprintf(tw, "OCSP Stapled:\t%v\n", res.OCSPStapled)

	_ = tw.Flush()

	return nil
}

func formatValidity(cert *x509.Certificate) string {
	const warnDays = 60
	notBefore := cert.NotBefore.UTC()
	notAfter := cert.NotAfter.UTC()

	now := time.Now().UTC()
	remaining := int(notAfter.Sub(now).Hours() / 24)

	status := ">="
	if remaining < warnDays {
		status = "<"
	}

	validity := fmt.Sprintf("%d %s %d days (%s --> %s)",
		remaining,
		status,
		warnDays,
		notBefore.Format("2006-01-02 15:04"),
		notAfter.Format("2006-01-02 15:04"),
	)

	return validity
}

// GetSANs returns all Subject Alternative Names (SANs) from the cert.
func formatSubjectAltName(cert *x509.Certificate) string {
	var sans []string

	sans = append(sans, cert.DNSNames...)
	sans = append(sans, cert.EmailAddresses...)

	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	for _, u := range cert.URIs {
		sans = append(sans, u.String())
	}

	return strings.Join(sans, ", ")
}

func formatKeyUsage(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	usages := []string{}
	m := map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature:  "Digital Signature",
		x509.KeyUsageContentCommitment: "Content Commitment",
		x509.KeyUsageKeyEncipherment:   "Key Encipherment",
		x509.KeyUsageDataEncipherment:  "Data Encipherment",
		x509.KeyUsageKeyAgreement:      "Key Agreement",
		x509.KeyUsageCertSign:          "Cert Sign",
		x509.KeyUsageCRLSign:           "CRL Sign",
		x509.KeyUsageEncipherOnly:      "Encipher Only",
		x509.KeyUsageDecipherOnly:      "Decipher Only",
	}

	for bit, label := range m {
		if cert.KeyUsage&bit != 0 {
			usages = append(usages, label)
		}
	}

	if len(usages) == 0 {
		return "–"
	}
	return strings.Join(usages, ", ")
}

func formatExtKeyUsage(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	if len(cert.ExtKeyUsage) == 0 {
		return "–"
	}

	m := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth:      "TLS Web Server Authentication",
		x509.ExtKeyUsageClientAuth:      "TLS Web Client Authentication",
		x509.ExtKeyUsageCodeSigning:     "Code Signing",
		x509.ExtKeyUsageEmailProtection: "Email Protection",
		x509.ExtKeyUsageTimeStamping:    "Time Stamping",
		x509.ExtKeyUsageOCSPSigning:     "OCSP Signing",
	}

	out := []string{}
	for _, usage := range cert.ExtKeyUsage {
		if label, ok := m[usage]; ok {
			out = append(out, label)
		} else {
			out = append(out, fmt.Sprintf("ExtKeyUsage(%d)", usage))
		}
	}

	return strings.Join(out, ", ")
}

func formatSerial(cert *x509.Certificate) string {
	hexStr := fmt.Sprintf("%X", cert.SerialNumber)
	// Optional: pad to even length if odd
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	return hexStr
}

func formatFingerprint(cert *x509.Certificate, algo string) string {
	switch algo {
	case "sha1":
		h := sha1.Sum(cert.Raw)
		return "SHA1 " + strings.ToUpper(hex.EncodeToString(h[:]))
	case "sha256":
		h := sha256.Sum256(cert.Raw)
		return "SHA256 " + strings.ToUpper(hex.EncodeToString(h[:]))
	default:
		return ""
	}
}
