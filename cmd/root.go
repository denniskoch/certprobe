package cmd

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/denniskoch/certprobe/internal/format"
	"github.com/denniskoch/certprobe/internal/probe"
	"github.com/denniskoch/certprobe/internal/resolver"
	"github.com/denniskoch/certprobe/internal/version"
	"github.com/spf13/cobra"
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

var rootCmd = &cobra.Command{
	Use:   "certprobe",
	Short: "certprobe - inspect SSL/TLS certificates",
	Long: `certprobe connects to a host and displays certificate information
	such as issuer, expiry, and chain details.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		ctx := cmd.Context()

		logger.Debug("starting certprobe",
			"host", host,
			"port", port,
			"resolvers", resolvers,
		)

		if host == "" && hostAddr == "" {
			return fmt.Errorf("either --host or --addr is required")
		}
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid --port %d (must be 1..65535)", port)
		}

		if hostAddr == "" {
			system, resolvers, err := resolver.ParseResolversFromFlag(resolvers)
			if err != nil {
				return fmt.Errorf("invalid --resolvers value: %w", err)
			}

			ips, err := resolver.Resolve(ctx, host, resolver.Options{
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

			hostAddr = ips[0]
			slog.Debug("dns: selected address", "host", host, "addr", hostAddr)
		}

		if net.ParseIP(hostAddr) == nil {
			return fmt.Errorf("invalid --addr %q (must be an IP literal)", hostAddr)
		}

		res, err := probe.GetCertificate(ctx, host, hostAddr, port, 5*time.Second)
		if err != nil {
			return err
		}

		return format.RenderSummary(ctx, res, format.Options{
			Host: host,
			Addr: hostAddr,
		})
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
		level = slog.LevelWarn
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	logger = slog.New(handler)

	logger.Debug("logger initialized", "level", level.String())
}
