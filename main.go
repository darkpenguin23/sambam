package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/sevlyar/go-daemon"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	smb2 "github.com/sambam/sambam/smb/server"
	"github.com/sambam/sambam/smb/vfs"
)

// Share represents a named share with its path
type Share struct {
	Name string
	Path string
}

// Config represents sambam configuration values loaded from rc files.
type Config struct {
	Listen       string            `toml:"listen"`
	Readonly     bool              `toml:"readonly"`
	Verbose      bool              `toml:"verbose"`
	VerboseLevel int               `toml:"verbose_level"`
	Debug        bool              `toml:"debug"` // backward compatibility: maps to verbose_level=3
	Trace        bool              `toml:"trace"`
	Allow        []string          `toml:"allow"`
	HideDotfiles bool              `toml:"hide_dotfiles"`
	Username     string            `toml:"username"`
	Password     string            `toml:"password"`
	Expire       string            `toml:"expire"`
	PidFile      string            `toml:"pidfile"`
	LogFile      string            `toml:"logfile"`
	Shares       map[string]string `toml:"shares"`
}

type ConfigLoadInfo struct {
	SystemPath   string
	SystemLoaded bool
	HomePath     string
	HomeLoaded   bool
	LocalPath    string
	LocalLoaded  bool
	CustomPaths  []string
	CustomLoaded []string
	SettingSrc   map[string]string
}

func decodeConfigFile(path string) (*Config, toml.MetaData, error) {
	var config Config
	md, err := toml.DecodeFile(path, &config)
	if err != nil {
		return nil, md, err
	}
	return &config, md, nil
}

func applyConfigOverrides(dst *Config, src *Config, md toml.MetaData) {
	if md.IsDefined("listen") {
		dst.Listen = src.Listen
	}
	if md.IsDefined("readonly") {
		dst.Readonly = src.Readonly
	}
	if md.IsDefined("verbose") {
		dst.Verbose = src.Verbose
	}
	if md.IsDefined("verbose_level") {
		dst.VerboseLevel = src.VerboseLevel
	}
	if md.IsDefined("debug") {
		dst.Debug = src.Debug
	}
	if md.IsDefined("trace") {
		dst.Trace = src.Trace
	}
	if md.IsDefined("allow") {
		dst.Allow = append([]string(nil), src.Allow...)
	}
	if md.IsDefined("hide_dotfiles") {
		dst.HideDotfiles = src.HideDotfiles
	}
	if md.IsDefined("username") {
		dst.Username = src.Username
	}
	if md.IsDefined("password") {
		dst.Password = src.Password
	}
	if md.IsDefined("expire") {
		dst.Expire = src.Expire
	}
	if md.IsDefined("pidfile") {
		dst.PidFile = src.PidFile
	}
	if md.IsDefined("logfile") {
		dst.LogFile = src.LogFile
	}
	if md.IsDefined("shares") {
		if dst.Shares == nil {
			dst.Shares = map[string]string{}
		}
		for name, path := range src.Shares {
			dst.Shares[name] = path
		}
	}
}

func recordConfigSources(info *ConfigLoadInfo, md toml.MetaData, src string, cfg *Config) {
	record := func(key string) {
		info.SettingSrc[key] = src
	}
	if md.IsDefined("listen") {
		record("listen")
	}
	if md.IsDefined("readonly") {
		record("readonly")
	}
	if md.IsDefined("verbose") {
		record("verbose")
	}
	if md.IsDefined("verbose_level") {
		record("verbose_level")
	}
	if md.IsDefined("debug") {
		record("debug")
	}
	if md.IsDefined("trace") {
		record("trace")
	}
	if md.IsDefined("allow") {
		record("allow")
	}
	if md.IsDefined("hide_dotfiles") {
		record("hide_dotfiles")
	}
	if md.IsDefined("username") {
		record("username")
	}
	if md.IsDefined("password") {
		record("password")
	}
	if md.IsDefined("expire") {
		record("expire")
	}
	if md.IsDefined("pidfile") {
		record("pidfile")
	}
	if md.IsDefined("logfile") {
		record("logfile")
	}
	if md.IsDefined("shares") {
		record("shares")
		for name := range cfg.Shares {
			record("shares." + name)
		}
	}
}

func configValueString(cfg *Config, key string) string {
	if cfg == nil {
		return "<unset>"
	}
	switch key {
	case "listen":
		return cfg.Listen
	case "readonly":
		return strconv.FormatBool(cfg.Readonly)
	case "verbose":
		return strconv.FormatBool(cfg.Verbose)
	case "verbose_level":
		return strconv.Itoa(cfg.VerboseLevel)
	case "debug":
		return strconv.FormatBool(cfg.Debug)
	case "trace":
		return strconv.FormatBool(cfg.Trace)
	case "allow":
		return strings.Join(cfg.Allow, ",")
	case "hide_dotfiles":
		return strconv.FormatBool(cfg.HideDotfiles)
	case "username":
		return cfg.Username
	case "password":
		if cfg.Password == "" {
			return ""
		}
		return "<set>"
	case "expire":
		return cfg.Expire
	case "pidfile":
		return cfg.PidFile
	case "logfile":
		return cfg.LogFile
	case "shares":
		return strconv.Itoa(len(cfg.Shares))
	default:
		if strings.HasPrefix(key, "shares.") {
			name := strings.TrimPrefix(key, "shares.")
			if cfg.Shares == nil {
				return ""
			}
			return cfg.Shares[name]
		}
	}
	return "<unknown>"
}

// loadConfig loads configuration in order:
// /etc/sambamrc -> ~/.sambamrc -> ./.sambamrc -> custom files (-c, repeatable)
func loadConfig(customPaths []string) (*Config, ConfigLoadInfo, error) {
	var merged Config
	hasConfig := false
	info := ConfigLoadInfo{
		SystemPath:  "/etc/sambamrc",
		HomePath:    filepath.Join(os.Getenv("HOME"), ".sambamrc"),
		LocalPath:   ".sambamrc",
		CustomPaths: customPaths,
		SettingSrc:  map[string]string{},
	}

	loadLayer := func(path, src string, required bool, setLoaded func()) error {
		if _, err := os.Stat(path); err != nil {
			if required {
				if os.IsNotExist(err) {
					return fmt.Errorf("config file not found: %s", path)
				}
				return fmt.Errorf("failed to stat config file %s: %w", path, err)
			}
			return nil
		}
		cfg, md, err := decodeConfigFile(path)
		if err != nil {
			if required {
				return fmt.Errorf("error reading %s: %w", path, err)
			}
			fmt.Fprintf(os.Stderr, "Warning: Error reading %s: %v\n", path, err)
			return nil
		}
		if !hasConfig {
			merged = *cfg
			hasConfig = true
		} else {
			applyConfigOverrides(&merged, cfg, md)
		}
		setLoaded()
		recordConfigSources(&info, md, src, cfg)
		return nil
	}

	// Base: system config.
	_ = loadLayer(info.SystemPath, "system", false, func() {
		info.SystemLoaded = true
	})

	// Overlay: user config.
	home, err := os.UserHomeDir()
	if err == nil {
		configPath := filepath.Join(home, ".sambamrc")
		info.HomePath = configPath
		_ = loadLayer(configPath, "home", false, func() { info.HomeLoaded = true })
	}

	// Overlay: project-local config.
	_ = loadLayer(info.LocalPath, "local", false, func() { info.LocalLoaded = true })

	// Overlay: explicit custom config files (repeatable, required to exist).
	for _, p := range customPaths {
		path := p
		if !filepath.IsAbs(path) {
			path = filepath.Clean(path)
		}
		if err := loadLayer(path, "custom:"+path, true, func() {
			info.CustomLoaded = append(info.CustomLoaded, path)
		}); err != nil {
			return nil, info, err
		}
	}

	if !hasConfig {
		return nil, info, nil
	}
	return &merged, info, nil
}

// logFormatter formats logrus entries to match sambam output style:
//
//	16:47:19 authenticated: guest
type logFormatter struct {
	showLevel bool
}

func (f *logFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	ts := Dim(entry.Time.Format("15:04:05"))
	if !f.showLevel {
		return []byte(fmt.Sprintf("  %s %s\n", ts, entry.Message)), nil
	}

	level := strings.ToUpper(entry.Level.String())
	levelTag := "[" + level + "]"
	switch entry.Level {
	case logrus.TraceLevel:
		levelTag = Dim("[TRC]")
	case logrus.DebugLevel:
		levelTag = Cyan("[DBG]")
	case logrus.InfoLevel:
		levelTag = Green("[INF]")
	case logrus.WarnLevel:
		levelTag = Yellow("[WRN]")
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		levelTag = Red("[ERR]")
	}

	return []byte(fmt.Sprintf("  %s %s %s\n", ts, levelTag, entry.Message)), nil
}

// generatePassword creates a random alphanumeric password
func generatePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[n.Int64()]
	}
	return string(result)
}

var (
	version = "1.4.18"
)

func main() {
	// Check for stop subcommand before flag parsing
	if len(os.Args) > 1 && os.Args[1] == "stop" {
		stopDaemon()
		return
	}

	// CLI flags
	shareSpecs := pflag.StringArrayP("name", "n", []string{}, "Share specification (name:path or just name)")
	listenAddr := pflag.StringP("listen", "l", "0.0.0.0:445", "Address to listen on")
	allowAddrs := pflag.StringArrayP("allow", "a", []string{}, "Allow client IP/CIDR (repeatable)")
	readOnly := pflag.BoolP("readonly", "r", false, "Make share read-only")
	showVersion := pflag.BoolP("version", "V", false, "Show version")
	showHelp := pflag.BoolP("help", "h", false, "Show help")

	// Daemon mode flags
	daemonMode := pflag.BoolP("daemon", "d", false, "Run as background daemon")
	pidFile := pflag.StringP("pidfile", "P", "/tmp/sambam.pid", "PID file location (daemon mode)")
	logFile := pflag.StringP("logfile", "L", "", "Log file path (default /tmp/sambam.log when value is omitted)")
	pflag.Lookup("logfile").NoOptDefVal = "/tmp/sambam.log"
	configFiles := pflag.StringArrayP("config", "c", []string{}, "Additional config file (repeatable, applied after defaults)")

	// Verbosity flags
	verbose := pflag.CountP("verbose", "v", "Show connections and file activity (-vv extended, -vvv full trace)")

	// Hidden files flag
	hideDotfiles := pflag.BoolP("hide-dotfiles", "H", false, "Hide files starting with '.'")

	// Authentication flags
	username := pflag.StringP("username", "u", "", "Require authentication with this username")
	password := pflag.StringP("password", "p", "", "Password for authentication (random if not specified)")

	// Auto-expire flag
	expireStr := pflag.StringP("expire", "e", "", "Auto-shutdown after duration (e.g., 30m, 1h, 2h30m)")
	generateConfigPath := pflag.StringP("gen-config", "G", "", "Generate config TOML and exit (optional path)")
	pflag.Lookup("gen-config").NoOptDefVal = ".sambamrc"

	os.Args = normalizeCLIArgs(os.Args)
	pflag.Parse()

	// Load config file(s)
	config, configInfo, err := loadConfig(*configFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Apply config file values where CLI flags weren't explicitly set
	if config != nil {
		if !pflag.CommandLine.Changed("listen") && config.Listen != "" {
			*listenAddr = config.Listen
		}
		if !pflag.CommandLine.Changed("readonly") && config.Readonly {
			*readOnly = true
		}
		if !pflag.CommandLine.Changed("verbose") {
			if config.VerboseLevel > 0 {
				*verbose = config.VerboseLevel
			} else if config.Verbose {
				*verbose = 1
			} else if config.Debug {
				*verbose = 3
			}
		}
		if !pflag.CommandLine.Changed("allow") && len(config.Allow) > 0 {
			*allowAddrs = append([]string(nil), config.Allow...)
		}
		if !pflag.CommandLine.Changed("username") && config.Username != "" {
			*username = config.Username
		}
		if !pflag.CommandLine.Changed("password") && config.Password != "" {
			*password = config.Password
		}
		if !pflag.CommandLine.Changed("expire") && config.Expire != "" {
			*expireStr = config.Expire
		}
		if !pflag.CommandLine.Changed("hide-dotfiles") && config.HideDotfiles {
			*hideDotfiles = true
		}
		if !pflag.CommandLine.Changed("pidfile") && config.PidFile != "" {
			*pidFile = config.PidFile
		}
		if !pflag.CommandLine.Changed("logfile") && config.LogFile != "" {
			*logFile = config.LogFile
		}
	}

	// Password requires username (applies to normal run and config generation).
	if *password != "" && *username == "" {
		fmt.Fprintln(os.Stderr, "Error: password requires username. Use -u/--username together with -p/--password.")
		os.Exit(1)
	}
	allowNets, err := parseAllowedNetworks(*allowAddrs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid allow rule: %v\n", err)
		os.Exit(1)
	}

	// Build effective settings view for debug logging (after config + CLI precedence).
	effectiveConfig := Config{}
	if config != nil {
		effectiveConfig = *config
		if config.Allow != nil {
			effectiveConfig.Allow = append([]string(nil), config.Allow...)
		}
		if config.Shares != nil {
			effectiveConfig.Shares = make(map[string]string, len(config.Shares))
			for k, v := range config.Shares {
				effectiveConfig.Shares[k] = v
			}
		}
	}
	effectiveConfig.Listen = *listenAddr
	effectiveConfig.Readonly = *readOnly
	effectiveConfig.HideDotfiles = *hideDotfiles
	effectiveConfig.Username = *username
	effectiveConfig.Password = *password
	effectiveConfig.Expire = *expireStr
	effectiveConfig.PidFile = *pidFile
	effectiveConfig.LogFile = *logFile
	effectiveConfig.Allow = append([]string(nil), *allowAddrs...)
	if *verbose <= 0 {
		effectiveConfig.Verbose = false
		effectiveConfig.VerboseLevel = 0
	} else if *verbose == 1 {
		effectiveConfig.Verbose = true
		effectiveConfig.VerboseLevel = 0
	} else {
		effectiveConfig.Verbose = false
		effectiveConfig.VerboseLevel = *verbose
	}
	effectiveSrc := map[string]string{}
	for k, v := range configInfo.SettingSrc {
		effectiveSrc[k] = v
	}
	markCLI := func(key string) { effectiveSrc[key] = "cli" }
	if pflag.CommandLine.Changed("listen") {
		markCLI("listen")
	}
	if pflag.CommandLine.Changed("readonly") {
		markCLI("readonly")
	}
	if pflag.CommandLine.Changed("verbose") {
		if *verbose <= 1 {
			markCLI("verbose")
			if _, ok := configInfo.SettingSrc["verbose_level"]; ok {
				markCLI("verbose_level")
			}
		} else {
			markCLI("verbose_level")
			if _, ok := configInfo.SettingSrc["verbose"]; ok {
				markCLI("verbose")
			}
		}
	}
	if pflag.CommandLine.Changed("allow") {
		markCLI("allow")
	}
	if pflag.CommandLine.Changed("hide-dotfiles") {
		markCLI("hide_dotfiles")
	}
	if pflag.CommandLine.Changed("username") {
		markCLI("username")
	}
	if pflag.CommandLine.Changed("password") {
		markCLI("password")
	}
	if pflag.CommandLine.Changed("expire") {
		markCLI("expire")
	}
	if pflag.CommandLine.Changed("pidfile") {
		markCLI("pidfile")
	}
	if pflag.CommandLine.Changed("logfile") {
		markCLI("logfile")
	}

	// Generate config and exit without starting the server.
	if pflag.CommandLine.Changed("gen-config") {
		target := *generateConfigPath
		if target == "" {
			target = ".sambamrc"
		}
		written, err := writeGeneratedConfig(target, *listenAddr, *allowAddrs, *readOnly, *verbose, *hideDotfiles, *username, *password, *expireStr, *pidFile, *logFile, *shareSpecs, pflag.Args())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s %s\n", Green("Generated config:"), Cyan(target))
		if len(written) > 0 {
			fmt.Println(Green("Set values:"))
			for _, line := range written {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					fmt.Printf("  %s %s %s\n", Cyan(parts[0]), Dim("="), Yellow(parts[1]))
				} else {
					fmt.Printf("  %s\n", line)
				}
			}
		}
		os.Exit(0)
	}

	// Set log level and formatter
	if !pflag.CommandLine.Changed("verbose") && config != nil && config.Trace && *verbose < 3 {
		*verbose = 3
	}
	if *verbose >= 3 {
		logrus.SetLevel(logrus.TraceLevel)
		logrus.SetFormatter(&logFormatter{showLevel: true})
	} else if *verbose >= 2 {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.SetFormatter(&logFormatter{showLevel: true})
	} else if *verbose > 0 {
		logrus.SetLevel(logrus.InfoLevel)
		logrus.SetFormatter(&logFormatter{showLevel: true})
	} else {
		logrus.SetLevel(logrus.ErrorLevel)
	}

	// Allow logfile usage in foreground mode as well.
	if *logFile != "" && !*daemonMode {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening logfile %s: %v\n", *logFile, err)
			os.Exit(1)
		}
		defer f.Close()
		logrus.SetOutput(io.MultiWriter(os.Stdout, f))
		log.SetOutput(io.MultiWriter(os.Stderr, f))
	}

	// When --listen is explicitly set on CLI, require a literal IP
	// (with optional port) to avoid late DNS/listener failures.
	if pflag.CommandLine.Changed("listen") {
		host, port := parseHostPort(*listenAddr)
		if host == "" || net.ParseIP(host) == nil {
			fmt.Fprintf(os.Stderr, "Invalid listen address %q: expected IP or IP:port\n", *listenAddr)
			os.Exit(1)
		}
		if port != "" {
			p, err := strconv.Atoi(port)
			if err != nil || p < 1 || p > 65535 {
				fmt.Fprintf(os.Stderr, "Invalid listen port in %q: expected 1-65535\n", *listenAddr)
				os.Exit(1)
			}
		}
	}

	extraVerbose := *verbose >= 2
	fullVerbose := *verbose >= 3
	actualPassword := *password
	if *username != "" && actualPassword == "" {
		actualPassword = generatePassword(10)
	}

	if *showHelp {
		printUsage()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("sambam %s (built with AI assistance)\n", version)
		os.Exit(0)
	}

	configLogsPrinted := false
	printConfigLogs := func() {
		if configLogsPrinted || *verbose <= 0 {
			return
		}
		configLogsPrinted = true
		if configInfo.SystemLoaded || configInfo.HomeLoaded || configInfo.LocalLoaded || len(configInfo.CustomLoaded) > 0 {
			logrus.Infof(
				"config: system=%t (%s), home=%t (%s), local=%t (%s), custom=%d",
				configInfo.SystemLoaded, configInfo.SystemPath,
				configInfo.HomeLoaded, configInfo.HomePath,
				configInfo.LocalLoaded, configInfo.LocalPath,
				len(configInfo.CustomLoaded),
			)
			if len(configInfo.CustomLoaded) > 0 {
				logrus.Infof("config custom: %s", strings.Join(configInfo.CustomLoaded, ", "))
			}
		} else {
			logrus.Infof(
				"config: no config file loaded (checked %s, %s, %s, custom=%d)",
				configInfo.SystemPath, configInfo.HomePath, configInfo.LocalPath, len(configInfo.CustomPaths),
			)
		}
		if *verbose >= 2 && len(effectiveSrc) > 0 {
			keys := make([]string, 0, len(effectiveSrc))
			for k := range effectiveSrc {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				msg := fmt.Sprintf("config setting: %s=%q <- %s", k, configValueString(&effectiveConfig, k), effectiveSrc[k])
				if baseSrc, ok := configInfo.SettingSrc[k]; ok && effectiveSrc[k] == "cli" && baseSrc != "cli" {
					msg += fmt.Sprintf(" (%s overridden by cli)", baseSrc)
				}
				logrus.Debug(msg)
			}
		}
	}

	// Parse shares.
	// Merge default-config shares with CLI shares. CLI shares override same-name entries.
	args := pflag.Args()
	shareMap := map[string]Share{}

	// Base shares from config.
	if config != nil && len(config.Shares) > 0 {
		for name, path := range config.Shares {
			absPath, err := filepath.Abs(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving path for '%s': %v\n", name, err)
				os.Exit(1)
			}
			shareMap[name] = Share{Name: name, Path: absPath}
		}
	}

	// CLI shares are additive and override by name.
	if len(*shareSpecs) == 0 && len(args) > 0 {
		absPath, err := filepath.Abs(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
			os.Exit(1)
		}
		name := shareName(absPath)
		shareMap[name] = Share{Name: name, Path: absPath}
	} else if len(*shareSpecs) > 0 {
		for _, spec := range *shareSpecs {
			var name, path string
			if strings.Contains(spec, ":") {
				parts := strings.SplitN(spec, ":", 2)
				name = parts[0]
				path = parts[1]
			} else {
				name = spec
				if len(args) > 0 {
					path = args[0]
				} else {
					path = "."
				}
			}
			absPath, err := filepath.Abs(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving path for '%s': %v\n", name, err)
				os.Exit(1)
			}
			shareMap[name] = Share{Name: name, Path: absPath}
		}
	}

	// Fallback default when neither config nor CLI provided shares.
	if len(shareMap) == 0 {
		absPath, err := filepath.Abs(".")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
			os.Exit(1)
		}
		name := shareName(absPath)
		shareMap[name] = Share{Name: name, Path: absPath}
	}

	var shares []Share
	shareNames := make([]string, 0, len(shareMap))
	for name := range shareMap {
		shareNames = append(shareNames, name)
	}
	sort.Strings(shareNames)
	for _, name := range shareNames {
		shares = append(shares, shareMap[name])
	}

	// Verify all share directories exist
	for _, share := range shares {
		info, err := os.Stat(share.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if !info.IsDir() {
			fmt.Fprintf(os.Stderr, "Error: %s is not a directory\n", share.Path)
			os.Exit(1)
		}
	}

	// Handle daemon mode
	if *daemonMode {
		// Set log output to file if specified
		logFileName := *logFile
		if logFileName == "" {
			logFileName = "/dev/null"
		} else {
			// Start each daemon run with a fresh logfile.
			f, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening logfile %s: %v\n", logFileName, err)
				os.Exit(1)
			}
			f.Close()
		}

		// Get current working directory to preserve it in daemon
		cwd, _ := os.Getwd()

		ctx := &daemon.Context{
			PidFileName: *pidFile,
			PidFilePerm: 0644,
			LogFileName: logFileName,
			LogFilePerm: 0640,
			WorkDir:     cwd,
			Umask:       027,
		}

		child, err := ctx.Reborn()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to start daemon: %v\n", err)
			os.Exit(1)
		}

		if child != nil {
			// Parent process
			// Show connection details even in daemon mode.
			listenHost, listenPort := parseHostPort(*listenAddr)
			if listenPort == "" {
				listenPort = "445"
			}
			fullListenAddr := net.JoinHostPort(listenHost, listenPort)
			var displayIPs []string
			if listenHost == "0.0.0.0" || listenHost == "" {
				displayIPs = getLocalIPs()
			} else {
				displayIPs = []string{listenHost}
			}
			portSuffix := ""
			if listenPort != "445" {
				portSuffix = ":" + listenPort
			}
			printBanner(shares, *readOnly, fullListenAddr, displayIPs, portSuffix, *allowAddrs, *username, actualPassword, *expireStr, true, extraVerbose)
			printConfigLogs()

			fmt.Println()
			fmt.Printf("  %-12s %s\n", "Status", Green("daemon started"))
			fmt.Printf("  %-12s %d\n", "PID", child.Pid)
			fmt.Printf("  %-12s %s\n", "PID file", *pidFile)
			if *logFile != "" {
				fmt.Printf("  %-12s %s\n", "Log file", *logFile)
			}
			fmt.Printf("  %-12s %s\n", "Control", Cyan("sambam stop"))
			os.Exit(0)
		}

		// Child process continues
		defer ctx.Release()

		// Disable colors in daemon mode (no terminal)
		DisableColors()

		// Setup logging
		if *logFile != "" {
			var shareNames []string
			for _, s := range shares {
				shareNames = append(shareNames, s.Name)
			}
			log.Printf("sambam daemon started, sharing: %s", strings.Join(shareNames, ", "))
		}
	}

	// Create filesystems for all shares
	vfsShares := make(map[string]vfs.VFSFileSystem)
	for _, share := range shares {
		fs := NewPassthroughFS(share.Path, *readOnly)

		// Setup filesystem callbacks for verbose mode
		if *verbose > 0 {
			fs.OnCreate = func(path string, isDir bool) {
				typeStr := "file"
				if isDir {
					typeStr = "dir"
				}
				logrus.Infof("create: %s %s", typeStr, path)
			}
			fs.OnOverwrite = func(path string) {
				logrus.Infof("replace: %s", path)
			}
			fs.OnDelete = func(path string) {
				logrus.Infof("delete: %s", path)
			}
		}
		if extraVerbose {
			fs.OnOpen = func(path string, mode string) {
				path = normalizeLogPath(path)
				logrus.Infof("open: %s (%s)", path, mode)
			}
			fs.OnDirRead = func(path string) {
				path = normalizeLogPath(path)
				logrus.Infof("dir read: %s", path)
			}
			fs.OnRead = func(path string) {
				path = normalizeLogPath(path)
				logrus.Infof("read: %s", path)
			}
			fs.OnClose = func(path string, mode string, readBytes uint64, writeBytes uint64) {
				path = normalizeLogPath(path)
				summary := fmt.Sprintf("r=%s w=%s", formatBytes(readBytes), formatBytes(writeBytes))
				logrus.Infof("close: %s (%s) %s", path, mode, summary)
			}
			fs.OnSlowOp = func(op string, path string, duration time.Duration, size int) {
				path = normalizeLogPath(path)
				logrus.Warnf("slow: %s %s took %s size=%d", op, path, duration.Round(time.Millisecond), size)
			}
		}
		if fullVerbose {
			fs.OnDirOpen = func(path string) {
				path = normalizeLogPath(path)
				logrus.Infof("dir open: %s", path)
			}
		}

		vfsShares[share.Name] = fs
	}

	// Get hostname for NTLM
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "SAMBAM"
	}

	// Setup verbose/debug callbacks
	var onConnect func(string)
	var onRename func(string, string)
	var onDetect func(string, string)
	var onAuthFail func(string, string)
	if *verbose > 0 {
		onConnect = func(remoteAddr string) {
			logrus.Infof("connect: %s", remoteAddr)
		}
		onRename = func(from, to string) {
			logrus.Infof("rename: %s -> %s", from, to)
		}
		onDetect = func(action, path string) {
			logrus.Infof("detected: %s %s", action, path)
		}
	}
	if extraVerbose {
		onAuthFail = func(remoteAddr, username string) {
			if username == "" {
				username = "<unknown>"
			}
			logrus.Warnf("auth fail: %s user=%s", remoteAddr, username)
		}
	}

	// Setup authentication
	userPassword := map[string]string{}
	allowGuest := true

	if *username != "" {
		allowGuest = false
		userPassword[*username] = actualPassword
	}

	// Create server
	srv := smb2.NewServer(
		&smb2.ServerConfig{
			AllowGuest:   allowGuest,
			Xatrrs:       true,
			HideDotfiles: *hideDotfiles,
			AllowConn: func(remoteAddr string) bool {
				return isRemoteAllowed(remoteAddr, allowNets)
			},
			OnReject: func(remoteAddr string) {
				logrus.Warnf("reject: %s (not in allow list)", remoteAddr)
			},
			OnConnect:  onConnect,
			OnRename:   onRename,
			OnDetect:   onDetect,
			OnAuthFail: onAuthFail,
		},
		&smb2.NTLMAuthenticator{
			TargetSPN:    "",
			NbDomain:     hostname,
			NbName:       hostname,
			DnsName:      hostname + ".local",
			DnsDomain:    ".local",
			UserPassword: userPassword,
			AllowGuest:   allowGuest,
		},
		vfsShares,
	)

	// Parse listen address and add default port if needed
	listenHost, listenPort := parseHostPort(*listenAddr)
	if listenPort == "" {
		listenPort = "445"
	}
	fullListenAddr := net.JoinHostPort(listenHost, listenPort)

	// Get IPs for display
	var displayIPs []string
	if listenHost == "0.0.0.0" || listenHost == "" {
		displayIPs = getLocalIPs()
	} else {
		displayIPs = []string{listenHost}
	}

	// Format connection string with port if non-standard
	portSuffix := ""
	if listenPort != "445" {
		portSuffix = ":" + listenPort
	}

	// Print banner in foreground mode.
	if !*daemonMode {
		printBanner(shares, *readOnly, fullListenAddr, displayIPs, portSuffix, *allowAddrs, *username, actualPassword, *expireStr, false, extraVerbose)
		printConfigLogs()
	}

	// Start server in goroutine
	go func() {
		if err := srv.Serve(fullListenAddr); err != nil {
			if *daemonMode && *logFile != "" {
				log.Printf("Server error: %v", err)
			} else if !*daemonMode {
				fmt.Println()
				fmt.Printf("  %s %s\n", Red("Error:"), Red(err.Error()))
				if os.Geteuid() != 0 && listenPort == "445" && strings.Contains(strings.ToLower(err.Error()), "permission denied") {
					fmt.Printf("  %s\n", Red("Port 445 requires root privileges on Linux."))
					fmt.Printf("  %-12s %s\n", "Try", Cyan("sudo sambam ..."))
				}
			}
			os.Exit(1)
		}
	}()

	// Wait for interrupt or expiry
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Setup expiry timer if specified
	var expireTimer *time.Timer
	var expireTime time.Time
	if *expireStr != "" {
		duration, err := time.ParseDuration(*expireStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid expire duration: %v\n", err)
			os.Exit(1)
		}
		expireTime = time.Now().Add(duration)
		expireTimer = time.NewTimer(duration)

		// Start countdown display goroutine (only in foreground mode)
		if !*daemonMode {
			go func() {
				ticker := time.NewTicker(1 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						remaining := time.Until(expireTime)
						if remaining > 0 {
							// Move cursor up and clear line, then print countdown
							fmt.Printf("\r  %s %s   ", Dim("Expires in"), Yellow(formatDuration(remaining)))
						}
					case <-sigChan:
						return
					}
				}
			}()
		}
	}

	// Wait for signal or expiry
	if expireTimer != nil {
		select {
		case <-sigChan:
		case <-expireTimer.C:
			if *daemonMode && *logFile != "" {
				log.Println("Expire time reached, shutting down...")
			} else if !*daemonMode {
				fmt.Println("\n\n  Time expired!")
			}
		}
	} else {
		<-sigChan
	}

	if *daemonMode && *logFile != "" {
		log.Println("Shutting down...")
	} else if !*daemonMode {
		fmt.Println("\nShutting down...")
	}
	srv.Shutdown()
}

// formatDuration formats a duration as a human-readable string
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	} else if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func normalizeLogPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func printBanner(shares []Share, readOnly bool, listenAddr string, displayIPs []string, portSuffix string, allowAddrs []string, username string, password string, expireStr string, daemonMode bool, extendedConnect bool) {
	fmt.Println()
	fmt.Printf("  %s %s\n", CyanBold("sambam v"+version), Dim("(built with AI assistance)"))
	fmt.Println()

	// Show shares
	if len(shares) == 1 {
		fmt.Printf("  %-12s %s\n", "Sharing", Green(shares[0].Path))
		fmt.Printf("  %-12s %s\n", "Share", Yellow(shares[0].Name))
	} else {
		// Find longest share name for alignment
		maxLen := 0
		for _, share := range shares {
			if len(share.Name) > maxLen {
				maxLen = len(share.Name)
			}
		}
		if maxLen < 12 {
			maxLen = 12
		}
		fmt.Printf("  %s\n", "Shares:")
		for _, share := range shares {
			padding := strings.Repeat(" ", maxLen-len(share.Name))
			fmt.Printf("    %s%s %s %s\n", Yellow(share.Name), padding, Dim("→"), Green(share.Path))
		}
	}

	listenHost, _ := parseHostPort(listenAddr)
	listenColored := Yellow(listenAddr)
	if listenHost == "" || listenHost == "0.0.0.0" || listenHost == "::" {
		listenColored = Dim(listenAddr)
	}
	fmt.Printf("  %-12s %s\n", "Listen", listenColored)

	modeStr := "read-write"
	if readOnly {
		modeStr = Green("read-only")
	} else {
		modeStr = Red("read-write")
	}
	fmt.Printf("  %-12s %s\n", "Mode", modeStr)

	if username != "" {
		fmt.Printf("  %-12s %s\n", "Auth", Yellow(username)+Dim(":")+Yellow(password))
	} else {
		fmt.Printf("  %-12s %s\n", "Auth", Dim("anonymous"))
	}
	allowText := "all"
	allowTextColored := Dim("all")
	if len(allowAddrs) > 0 {
		allowText = strings.Join(allowAddrs, ", ")
		allowTextColored = Yellow(allowText)
	}
	fmt.Printf("  %-12s %s\n", "Allowlist", allowTextColored)

	// Extract port number from portSuffix (":8888" -> "8888")
	nonStdPort := portSuffix != ""
	portNum := ""
	if nonStdPort {
		portNum = portSuffix[1:] // strip leading ":"
	}

	firstIP := displayIPs[0]
	firstShare := shares[0].Name
	comboCount := len(displayIPs) * len(shares)

	fmt.Println()
	fmt.Println("  Connect:")
	if nonStdPort {
		fmt.Printf("  %-12s %s\n", "Windows", Cyan("\\\\localhost\\"+firstShare)+" "+Dim("(SSH tunnel)"))
		fmt.Printf("  %-12s %s\n", "macOS", Cyan("smb://localhost/"+firstShare)+" "+Dim("(SSH tunnel)"))
	} else {
		fmt.Printf("  %-12s %s\n", "Windows", Cyan(fmt.Sprintf("\\\\%s\\%s", firstIP, firstShare)))
		fmt.Printf("  %-12s %s\n", "macOS", Cyan(fmt.Sprintf("smb://%s/%s", firstIP, firstShare)))
	}
	authOpt := "guest"
	if username != "" {
		authOpt = "username=" + username + ",password=" + password
	}
	portOpt := ""
	if nonStdPort {
		portOpt = ",port=" + portNum
	}
	fmt.Printf("  %-12s %s\n", "Linux", Cyan(fmt.Sprintf("sudo mount -t cifs //%s/%s /mnt -o %s%s", firstIP, firstShare, authOpt, portOpt)))
	if comboCount > 1 && !extendedConnect {
		fmt.Printf("  %-12s %s\n", "", Dim(fmt.Sprintf("(%d additional share/ip combinations; use -vv to show all)", comboCount-1)))
	}

	if extendedConnect {
		fmt.Printf("  %-12s %s %s\n", "", Cyan(fmt.Sprintf("sudo mount -t cifs //%s/%s /mnt -o %s%s,vers=3.1.1,posix,cifsacl", firstIP, firstShare, authOpt, portOpt)), Dim("# POSIX"))

		if nonStdPort {
			fmt.Println()
			fmt.Println("  SSH tunnel:")
			for _, ip := range displayIPs {
				fmt.Printf("    %s\n", Cyan(fmt.Sprintf("ssh -L 445:%s:%s user@%s", ip, portNum, ip)))
			}
		}

		if comboCount > 1 {
			fmt.Println()
			fmt.Println("  All endpoints:")
			if nonStdPort {
				for _, share := range shares {
					fmt.Printf("  %-12s %s\n", "Windows", Cyan("\\\\localhost\\"+share.Name)+" "+Dim("(SSH tunnel)"))
					fmt.Printf("  %-12s %s\n", "macOS", Cyan("smb://localhost/"+share.Name)+" "+Dim("(SSH tunnel)"))
				}
			} else {
				for _, share := range shares {
					for _, ip := range displayIPs {
						fmt.Printf("  %-12s %s\n", "Windows", Cyan(fmt.Sprintf("\\\\%s\\%s", ip, share.Name)))
						fmt.Printf("  %-12s %s\n", "macOS", Cyan(fmt.Sprintf("smb://%s/%s", ip, share.Name)))
					}
				}
			}
			for _, share := range shares {
				for _, ip := range displayIPs {
					fmt.Printf("  %-12s %s\n", "Linux", Cyan(fmt.Sprintf("sudo mount -t cifs //%s/%s /mnt -o %s%s", ip, share.Name, authOpt, portOpt)))
				}
			}
		}
	}
	fmt.Println()
	if daemonMode {
		fmt.Printf("  %s\n", Red("Daemon mode: running in background"))
	} else if expireStr != "" {
		fmt.Printf("  %s\n", Dim("Press Ctrl+C to stop, or wait for expiry"))
		fmt.Println()
		// Initial expires line - no newline so countdown can overwrite
		fmt.Printf("  %s %s   ", Dim("Expires in"), Yellow(expireStr))
	} else {
		fmt.Printf("  %s\n", Dim("Press Ctrl+C to stop"))
	}
}

func printUsage() {
	fmt.Println()
	fmt.Printf("  %s %s\n", CyanBold("sambam v"+version), Dim("(built with AI assistance)"))
	fmt.Println()
	fmt.Println(Dim("  Instant SMB/CIFS file sharing for Windows clients"))
	fmt.Println()
	fmt.Println(Bold("  Usage:"))
	fmt.Printf("    %s [options] [directory]\n", Cyan("sambam"))
	fmt.Printf("    %s\n", Cyan("sambam stop"))
	fmt.Println()
	fmt.Println(Bold("  Options:"))
	printOpt := func(label, desc string) {
		const colWidth = 22
		pad := colWidth - len(label)
		if pad < 2 {
			pad = 2
		}
		fmt.Printf("    %s%s%s\n", Green(label), strings.Repeat(" ", pad), desc)
	}

	printOpt("-n, --name", "Share name or name:path "+Dim("(repeatable)"))
	printOpt("-l, --listen", "Address to listen on "+Dim("(default: 0.0.0.0:445)"))
	printOpt("-a, --allow", "Allow client IP/CIDR "+Dim("(repeatable, default: allow all)"))
	printOpt("-r, --readonly", "Make share read-only")
	printOpt("-u, --username", "Require authentication")
	printOpt("-p, --password", "Password "+Dim("(random if not set)"))
	printOpt("-e, --expire", "Auto-shutdown after duration "+Dim("(e.g., 30m, 1h)"))
	printOpt("-v, --verbose", "Show connections and file activity "+Dim("(-vv extended, -vvv full trace)"))
	printOpt("-H, --hide-dotfiles", "Hide files starting with '.'")
	printOpt("-d, --daemon", "Run as background daemon")
	printOpt("-P, --pidfile", "PID file location "+Dim("(default: /tmp/sambam.pid)"))
	printOpt("-L, --logfile", "Log file path "+Dim("(default /tmp/sambam.log when omitted)"))
	printOpt("-c, --config", "Additional config file "+Dim("(repeatable, applied last)"))
	printOpt("-G, --gen-config", "Generate config TOML and exit "+Dim("(default: ./.sambamrc)"))
	printOpt("-V, --version", "Show version")
	printOpt("-h, --help", "Show help")
	fmt.Println()
	fmt.Println(Bold("  Examples:"))
	printExample := func(cmd, desc string) {
		const cmdWidth = 64
		fmt.Printf("    %s  %s\n", Cyan(fmt.Sprintf("%-*s", cmdWidth, cmd)), Dim("# "+desc))
	}
	printExample("sambam", "Share current directory")
	printExample("sambam -n docs:/docs -n pics:/photos -r", "Multi-share read-only")
	printExample("sambam -d -l 10.23.22.13:445 -u admin -p secret /data", "Daemon + auth + custom listen")
	fmt.Println()
}

func normalizeCLIArgs(args []string) []string {
	if len(args) < 3 {
		return args
	}
	out := make([]string, 0, len(args))
	out = append(out, args[0])
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "-L" || arg == "--logfile" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				out = append(out, "--logfile=/tmp/sambam.log")
				continue
			}
		}
		if (arg == "-G" || arg == "--gen-config" || arg == "--generate-config") && i+1 < len(args) {
			next := args[i+1]
			if !strings.HasPrefix(next, "-") {
				out = append(out, "--gen-config="+next)
				i++
				continue
			}
		}
		out = append(out, arg)
	}
	return out
}

func writeGeneratedConfig(target, listen string, allowAddrs []string, readOnly bool, verbose int, hideDotfiles bool, username, password, expire, pidFile, logFile string, shareSpecs []string, args []string) ([]string, error) {
	var b bytes.Buffer
	written := []string{}
	b.WriteString("# sambam generated configuration\n")
	b.WriteString("# CLI flags override these settings.\n\n")

	writeString := func(key, value string) {
		fmt.Fprintf(&b, "%s = %s\n", key, strconv.Quote(value))
		written = append(written, fmt.Sprintf("%s=%q", key, value))
	}
	writeBool := func(key string, value bool) {
		fmt.Fprintf(&b, "%s = %t\n", key, value)
		written = append(written, fmt.Sprintf("%s=%t", key, value))
	}
	writeInt := func(key string, value int) {
		fmt.Fprintf(&b, "%s = %d\n", key, value)
		written = append(written, fmt.Sprintf("%s=%d", key, value))
	}
	writeStringArray := func(key string, values []string) {
		quoted := make([]string, 0, len(values))
		for _, v := range values {
			quoted = append(quoted, strconv.Quote(v))
		}
		fmt.Fprintf(&b, "%s = [%s]\n", key, strings.Join(quoted, ", "))
		written = append(written, fmt.Sprintf("%s=%s", key, strings.Join(values, ",")))
	}

	if pflag.CommandLine.Changed("listen") {
		writeString("listen", listen)
	}
	if pflag.CommandLine.Changed("allow") {
		writeStringArray("allow", allowAddrs)
	}
	if pflag.CommandLine.Changed("readonly") {
		writeBool("readonly", readOnly)
	}
	if pflag.CommandLine.Changed("verbose") {
		if verbose <= 1 {
			writeBool("verbose", verbose > 0)
		} else {
			writeInt("verbose_level", verbose)
		}
	}
	if pflag.CommandLine.Changed("hide-dotfiles") {
		writeBool("hide_dotfiles", hideDotfiles)
	}
	if pflag.CommandLine.Changed("username") {
		writeString("username", username)
	}
	if pflag.CommandLine.Changed("password") {
		writeString("password", password)
	}
	if pflag.CommandLine.Changed("expire") {
		writeString("expire", expire)
	}
	if pflag.CommandLine.Changed("pidfile") {
		writeString("pidfile", pidFile)
	}
	if pflag.CommandLine.Changed("logfile") {
		writeString("logfile", logFile)
	}

	shares := buildSharesForConfig(shareSpecs, args)
	if len(shares) > 0 {
		b.WriteString("\n[shares]\n")
		names := make([]string, 0, len(shares))
		for name := range shares {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(&b, "%s = %s\n", name, strconv.Quote(shares[name]))
			written = append(written, fmt.Sprintf("shares.%s=%q", name, shares[name]))
		}
	}

	if err := os.WriteFile(target, b.Bytes(), 0644); err != nil {
		return nil, err
	}
	return written, nil
}

func buildSharesForConfig(shareSpecs []string, args []string) map[string]string {
	shares := map[string]string{}
	absOrOriginal := func(path string) string {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return path
		}
		return absPath
	}
	if len(shareSpecs) == 0 {
		if len(args) == 0 {
			return shares
		}
		path := absOrOriginal(args[0])
		shares[shareName(path)] = path
		return shares
	}

	for _, spec := range shareSpecs {
		var name, path string
		if strings.Contains(spec, ":") {
			parts := strings.SplitN(spec, ":", 2)
			name = parts[0]
			path = parts[1]
		} else {
			name = spec
			if len(args) > 0 {
				path = args[0]
			} else {
				path = "."
			}
		}
		path = absOrOriginal(path)
		shares[name] = path
	}
	return shares
}

// shareName returns a valid share name for the given path.
// filepath.Base("/") returns "/" which is not a valid share name,
// so we fall back to "root" for the filesystem root.
func shareName(path string) string {
	name := filepath.Base(path)
	if name == "/" || name == "." {
		return "root"
	}
	return name
}

func parseHostPort(addr string) (host, port string) {
	// Try to split as host:port
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// No port specified, treat entire string as host
		return addr, ""
	}
	return host, port
}

func parseAllowedNetworks(values []string) ([]*net.IPNet, error) {
	if len(values) == 0 {
		return nil, nil
	}
	nets := make([]*net.IPNet, 0, len(values))
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if strings.Contains(v, "/") {
			_, n, err := net.ParseCIDR(v)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid CIDR", raw)
			}
			nets = append(nets, n)
			continue
		}

		ip := net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("%q is not a valid IP or CIDR", raw)
		}
		if ip4 := ip.To4(); ip4 != nil {
			nets = append(nets, &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
		} else {
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
		}
	}
	return nets, nil
}

func isRemoteAllowed(remoteAddr string, allowNets []*net.IPNet) bool {
	if len(allowNets) == 0 {
		return true
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	for _, n := range allowNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func getLocalIPs() []string {
	var ips []string

	// Get actual network interface IPs
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			// Skip loopback and down interfaces
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				// Only IPv4 for simplicity
				if ip != nil && ip.To4() != nil {
					ips = append(ips, ip.String())
				}
			}
		}
	}

	if len(ips) == 0 {
		ips = append(ips, "<your-ip>")
	}

	return ips
}

func stopDaemon() {
	// Allow custom PID file via -P flag after "stop"
	pidFilePath := "/tmp/sambam.pid"
	if len(os.Args) > 2 {
		// Check for -P or --pidfile flag
		for i := 2; i < len(os.Args); i++ {
			if os.Args[i] == "-P" || os.Args[i] == "-p" || os.Args[i] == "--pidfile" {
				if i+1 < len(os.Args) {
					pidFilePath = os.Args[i+1]
				}
				break
			}
		}
	}

	// Read PID file
	data, err := os.ReadFile(pidFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "No daemon running (PID file not found: %s)\n", pidFilePath)
		} else {
			fmt.Fprintf(os.Stderr, "Error reading PID file: %v\n", err)
		}
		os.Exit(1)
	}

	// Parse PID
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid PID in file: %v\n", err)
		os.Exit(1)
	}

	// Find the process
	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Process not found: %v\n", err)
		os.Exit(1)
	}

	// Send SIGTERM
	fmt.Printf("Stopping sambam daemon (PID %d)...\n", pid)
	err = process.Signal(syscall.SIGTERM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending signal: %v\n", err)
		os.Exit(1)
	}

	// Wait for process to exit (with timeout)
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		// Check if process is still running
		err = process.Signal(syscall.Signal(0))
		if err != nil {
			// Process is gone
			fmt.Println("Daemon stopped")
			// Clean up PID file if it still exists
			os.Remove(pidFilePath)
			return
		}
	}

	fmt.Fprintln(os.Stderr, "Warning: Daemon may not have stopped cleanly")
}
