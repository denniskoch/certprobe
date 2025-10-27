// internal/format/summary.go
package format

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"

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

	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', tabwriter.StripEscape)

	fmt.Fprintf(tw, "Target:\t%s (%s)\n", opt.Host, opt.Addr)
	fmt.Fprintf(tw, "TLS:\t%s / %s\n", res.TLSVersion, res.CipherSuite)
	if res.OCSPStapled {
		fmt.Fprintf(tw, "OCSP Stapling:\tYes\n")
	} else {
		fmt.Fprintf(tw, "OCSP Stapling:\tNo\n")
	}
	fmt.Fprintln(tw)

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		slog.Debug("system pool not available; using empty root pool", "err", err)
		roots = x509.NewCertPool()
	}

	inter := x509.NewCertPool()
	if len(res.PeerCertificates) > 1 {
		for _, ic := range res.PeerCertificates[1:] {
			inter.AddCert(ic)
		}
	}

	for i, cert := range res.PeerCertificates {

		if i > 0 {
			fmt.Fprintf(tw, "- Certificate %d \n", i)
		} else {
			fmt.Fprintf(tw, "- Certificate %d (Leaf)\n", i)
		}
		fmt.Fprintf(tw, "\tCommon Name (CN)\t%s\n", cert.Subject.CommonName)
		fmt.Fprintf(tw, "\tsubjectAltName (SAN)\t%s\n", formatSubjectAltName(cert))
		fmt.Fprintf(tw, "\tTrust\t%s\n", formatTrust(cert, roots, inter))
		fmt.Fprintf(tw, "\tCertificate Validity (UTC)\t%s\n", formatValidity(cert))
		fmt.Fprintf(tw, "\tSignature Algorithm\t%s\n", formatSignatureAlgorithm(cert))
		fmt.Fprintf(tw, "\tKey Usage\t%s\n", formatKeyUsage(cert))
		fmt.Fprintf(tw, "\tExtended Key Usage\t%s\n", formatExtKeyUsage(cert))
		fmt.Fprintf(tw, "\tSerial\t%s\n", formatSerial(cert))
		fmt.Fprintf(tw, "\tFingerprint\t%s\n", formatFingerprint(cert, "sha1"))
		fmt.Fprintf(tw, "\t\t%s\n", formatFingerprint(cert, "sha256"))
		fmt.Fprintf(tw, "\tIssuer\t%s\n", cert.Issuer.CommonName+" ("+cert.Issuer.Organization[0]+")")

		fmt.Fprintf(tw, "\n")
	}

	_ = tw.Flush()

	return nil
}

func formatTrust(cert *x509.Certificate, roots, inter *x509.CertPool) string {

	opts := x509.VerifyOptions{
		Roots:         roots, // trust anchors
		Intermediates: inter, // any intermediate certs
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := cert.Verify(opts)
	if err != nil {
		return color.New(color.FgYellow).Sprint("Not Trusted")
	}

	return color.New(color.FgGreen).Sprint("OK")
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

	d := fmt.Sprintf("%d %s %d days",
		remaining,
		status,
		warnDays,
	)

	switch {
	case remaining < 0:
		d = color.New(color.FgRed).Sprint(d)
	case remaining <= warnDays:
		d = color.New(color.FgYellow).Sprint(d)
	default:
		d = color.New(color.FgGreen).Sprint(d)
	}

	validity := fmt.Sprintf("%s (%s --> %s)",
		d,
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

func formatSignatureAlgorithm(cert *x509.Certificate) string {
	alg := cert.SignatureAlgorithm
	switch alg {
	case x509.SHA256WithRSA:
		return color.New(color.FgGreen).Sprint("SHA-256 with RSA")
	case x509.SHA384WithRSA:
		return color.New(color.FgGreen).Sprint("SHA-384 with RSA")
	case x509.SHA512WithRSA:
		return color.New(color.FgGreen).Sprint("SHA-512 with RSA")
	case x509.SHA1WithRSA:
		return color.New(color.FgYellow).Sprint("SHA-1 with RSA (legacy)")
	case x509.ECDSAWithSHA256:
		return "ECDSA with SHA-256"
	case x509.ECDSAWithSHA384:
		return "ECDSA with SHA-384"
	case x509.ECDSAWithSHA512:
		return "ECDSA with SHA-512"
	case x509.PureEd25519:
		return "Ed25519"
	case x509.DSAWithSHA1:
		return color.New(color.FgYellow).Sprint("DSA with SHA-1 (legacy)")
	case x509.DSAWithSHA256:
		return "DSA with SHA-256"
	default:
		return alg.String()
	}
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
