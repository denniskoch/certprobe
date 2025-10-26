package cmd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/denniskoch/certprobe/internal/probe"
	"github.com/denniskoch/certprobe/internal/resolver"
	"github.com/denniskoch/certprobe/internal/version"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"
)

const (
	colorGreen  = "34"
	colorYellow = "220"
	colorRed    = "196"
	colorGray   = "250"
)

var (
	host      string
	hostAddr  string
	port      int
	resolvers string
	forceIPv4 bool
	forceIPv6 bool
	verbose   bool
	debug     bool

	logger *slog.Logger
)

var p = termenv.ColorProfile()

var rootCmd = &cobra.Command{
	Use:   "certprobe",
	Short: "certprobe - inspect SSL/TLS certificates",
	Long: `certprobe connects to a host and displays certificate information
	such as issuer, expiry, and chain details.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		logger.Info("starting certprobe",
			"host", host,
			"port", port,
			"resolvers", resolvers,
		)

		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid --port %d (must be 1..65535)", port)
		}

		if hostAddr != "" {
			// handle ip specified in cmd
		} else {
			system, resolvers, err := resolver.ParseResolversFromFlag(resolvers)
			if err != nil {
				return fmt.Errorf("invalid --resolvers value: %w", err)
			}

			ips, err := resolver.Resolve(cmd.Context(), host, resolver.Options{
				System:   system,
				Servers:  resolvers,
				IPv4:     forceIPv4 || !forceIPv6, // default both if neither set
				IPv6:     forceIPv6 || !forceIPv4,
				Timeout:  3 * time.Second,
				MaxCNAME: 5,
			})

			if err != nil {
				return fmt.Errorf("resolve %s failed: %w", host, err)
			}

			if len(ips) == 0 {
				return fmt.Errorf("no IPs returned for %q", host)
			}
		}

		_, err := probe.GetCertificate(host, hostAddr, port, 5*time.Second)
		if err != nil {
			return err
		}

		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Version = fmt.Sprintf("%s (%s, %s)", version.Version, version.Commit, version.Date)
	rootCmd.Flags().StringVarP(&host, "host", "t", "", "Hostname to scan (required)")
	_ = rootCmd.MarkFlagRequired("host")
	rootCmd.Flags().StringVar(&hostAddr, "addr", "", "Target network address (bypasses DNS if set)")
	rootCmd.Flags().IntVarP(&port, "port", "p", 443, "Port to connect to (1-65535)")
	rootCmd.Flags().StringVarP(&resolvers, "resolvers", "r", "system",
		"Comma-separated resolvers (e.g., 'system' or '8.8.8.8,8.8.4.4')")
	rootCmd.Flags().BoolVarP(&forceIPv4, "ipv4", "4", false, "Force IPv4 queries only (no AAAA lookups)")
	rootCmd.Flags().BoolVarP(&forceIPv6, "ipv6", "6", false, "Force IPv6 queries only (no A lookups)")
	rootCmd.MarkFlagsMutuallyExclusive("ipv4", "ipv6")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "V", false, "Enable verbose output (info level)")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging (overrides --verbose)")
	rootCmd.Flags().SortFlags = false
	rootCmd.PersistentFlags().SortFlags = false

	cobra.OnInitialize(initLogger)
}

func initLogger() {

	var level slog.Level

	switch {
	case debug:
		level = slog.LevelDebug
	case verbose:
		level = slog.LevelInfo
	default:
		level = slog.LevelWarn // only warnings/errors
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	logger = slog.New(handler)

	logger.Debug("logger initialized", "level", level.String())
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

	var color string

	switch {
	case remaining < 0:
		color = colorRed
	case remaining < warnDays:
		color = colorYellow
	default:
		color = colorGreen
	}

	validity := fmt.Sprintf("%d %s %d days (%s --> %s)",
		remaining,
		status,
		warnDays,
		notBefore.Format("2006-01-02 15:04"),
		notAfter.Format("2006-01-02 15:04"),
	)

	return colorize(validity, color, false)
}

func serverKeyString(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits (exponent is %d)", pub.Size()*8, pub.E)
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", pub.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("Unknown key type (%T)", pub)
	}
}

func serverKeyUsageString(cert *x509.Certificate) string {
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

func serverExtKeyUsageString(cert *x509.Certificate) string {
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

func colorize(s, color string, italic bool) string {
	out := termenv.String(s).Foreground(p.Color(color))
	if italic {
		out = out.Italic()
	}
	return out.String()
}

func printField(label string, value any) {
	const labelWidth = 30
	fmt.Printf(" %-*s %v\n", labelWidth, label, value)
}

func formatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}
