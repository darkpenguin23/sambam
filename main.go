package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/grandcat/zeroconf"
	"github.com/sevlyar/go-daemon"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	smb2 "github.com/sambam/sambam/smb/server"
	"github.com/sambam/sambam/smb/vfs"
)

// Share represents a named share with its path
type Share struct {
	Name       string
	Path       string
	ReadOnly   bool
	Guest      bool
	AllowUsers []string
}

type ShareConfig struct {
	Path       string   `toml:"path"`
	Readonly   bool     `toml:"readonly"`
	AllowUsers []string `toml:"allow_users"`
}

type shareFieldMask struct {
	Path       bool
	Readonly   bool
	AllowUsers bool
}

type UserConfig struct {
	Name     string `toml:"name"`
	Password string `toml:"password"`
	Readonly bool   `toml:"readonly"`
}

type userFieldMask struct {
	Password bool
	Readonly bool
}

// Config represents sambam configuration values loaded from rc files.
type Config struct {
	Listen            string
	ListenAddrs       []string
	Advertise         bool
	DiscoveryNameMDNS string
	DiscoveryNameWSD  string
	Readonly          bool
	Verbose           bool
	VerboseLevel      int
	Debug             bool // backward compatibility: maps to verbose_level=3
	Trace             bool
	Allow             []string
	HideDotfiles      bool
	Users             []UserConfig
	Expire            string
	PidFile           string
	LogFile           string
	Shares            map[string]ShareConfig
	userMask          map[string]userFieldMask
	shareMask         map[string]shareFieldMask
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

type daemonStatus struct {
	PID        int      `json:"pid"`
	PIDFile    string   `json:"pid_file"`
	LogFile    string   `json:"log_file"`
	Shares     []Share  `json:"shares"`
	Listen     string   `json:"listen"`
	Auth       string   `json:"auth"`
	AllowAddrs []string `json:"allow_addrs"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	UpdatedAt  string   `json:"updated_at"`
}

type discoveryAdvertiser struct {
	mdns *zeroconf.Server
	wsd  *wsDiscoveryService
}

func (d *discoveryAdvertiser) Shutdown() {
	if d == nil {
		return
	}
	if d.mdns != nil {
		d.mdns.Shutdown()
	}
	if d.wsd != nil {
		d.wsd.Shutdown()
	}
}

type wsDiscoveryService struct {
	conn            *net.UDPConn
	httpServer      *http.Server
	multicastAddr   *net.UDPAddr
	endpointAddress string
	endpointUUID    string
	xaddr           string
	xaddrs          []string
	friendlyName    string
	manufacturer    string
	workgroup       string
	scopes          string
	metadataVersion int
	sequenceID      string
	messageNumber   uint64
	stop            chan struct{}
	wg              sync.WaitGroup
}

func decodeConfigFile(path string) (*Config, toml.MetaData, error) {
	type rawConfig struct {
		Global toml.Primitive            `toml:"global"`
		User   map[string]toml.Primitive `toml:"user"`
		Share  map[string]toml.Primitive `toml:"share"`
	}

	var raw rawConfig
	md, err := toml.DecodeFile(path, &raw)
	if err != nil {
		return nil, md, err
	}

	legacyRoots := []string{
		"listen", "listen_addrs", "allow", "advertise", "discovery_name_mdns", "discovery_name_wsd", "readonly",
		"verbose", "verbose_level", "debug", "trace", "hide_dotfiles",
		"expire", "pidfile", "logfile", "users", "shares", "username", "password",
	}
	for _, k := range legacyRoots {
		if md.IsDefined(k) {
			return nil, md, fmt.Errorf("legacy key %q is no longer supported; use [global], [user.<name>], and [share.<name>]", k)
		}
	}

	cfg := &Config{
		Users:     []UserConfig{},
		Shares:    map[string]ShareConfig{},
		userMask:  map[string]userFieldMask{},
		shareMask: map[string]shareFieldMask{},
	}

	parseStringOrArray := func(v interface{}, key string) ([]string, error) {
		switch vv := v.(type) {
		case string:
			if strings.TrimSpace(vv) == "" {
				return nil, fmt.Errorf("%s must not be empty", key)
			}
			return []string{vv}, nil
		case []interface{}:
			out := make([]string, 0, len(vv))
			for i, item := range vv {
				s, ok := item.(string)
				if !ok {
					return nil, fmt.Errorf("%s[%d] must be a string", key, i)
				}
				if strings.TrimSpace(s) == "" {
					return nil, fmt.Errorf("%s[%d] must not be empty", key, i)
				}
				out = append(out, s)
			}
			return out, nil
		case []string:
			out := make([]string, 0, len(vv))
			for i, s := range vv {
				if strings.TrimSpace(s) == "" {
					return nil, fmt.Errorf("%s[%d] must not be empty", key, i)
				}
				out = append(out, s)
			}
			return out, nil
		default:
			return nil, fmt.Errorf("%s must be a string or array of strings", key)
		}
	}

	if md.IsDefined("global") {
		var gmap map[string]interface{}
		if err := md.PrimitiveDecode(raw.Global, &gmap); err != nil {
			return nil, md, fmt.Errorf("invalid [global] section")
		}
		type globalConfig struct {
			Advertise         bool   `toml:"advertise"`
			DiscoveryNameMDNS string `toml:"discovery_name_mdns"`
			DiscoveryNameWSD  string `toml:"discovery_name_wsd"`
			Readonly          bool   `toml:"readonly"`
			Verbose           bool   `toml:"verbose"`
			VerboseLevel      int    `toml:"verbose_level"`
			Debug             bool   `toml:"debug"`
			Trace             bool   `toml:"trace"`
			HideDotfiles      bool   `toml:"hide_dotfiles"`
			Expire            string `toml:"expire"`
			PidFile           string `toml:"pidfile"`
			LogFile           string `toml:"logfile"`
		}
		var gcfg globalConfig
		if err := md.PrimitiveDecode(raw.Global, &gcfg); err != nil {
			return nil, md, fmt.Errorf("invalid [global] section")
		}
		cfg.Advertise = gcfg.Advertise
		cfg.DiscoveryNameMDNS = gcfg.DiscoveryNameMDNS
		cfg.DiscoveryNameWSD = gcfg.DiscoveryNameWSD
		cfg.Readonly = gcfg.Readonly
		cfg.Verbose = gcfg.Verbose
		cfg.VerboseLevel = gcfg.VerboseLevel
		cfg.Debug = gcfg.Debug
		cfg.Trace = gcfg.Trace
		cfg.HideDotfiles = gcfg.HideDotfiles
		cfg.Expire = gcfg.Expire
		cfg.PidFile = gcfg.PidFile
		cfg.LogFile = gcfg.LogFile
		if rawListen, ok := gmap["listen"]; ok {
			listenVals, err := parseStringOrArray(rawListen, "global.listen")
			if err != nil {
				return nil, md, err
			}
			if len(listenVals) == 1 {
				cfg.Listen = listenVals[0]
				cfg.ListenAddrs = nil
			} else {
				cfg.Listen = listenVals[0]
				cfg.ListenAddrs = append([]string(nil), listenVals...)
			}
		}
		if rawAllow, ok := gmap["allow"]; ok {
			allowVals, err := parseStringOrArray(rawAllow, "global.allow")
			if err != nil {
				return nil, md, err
			}
			cfg.Allow = append([]string(nil), allowVals...)
		}
		if _, ok := gmap["discovery_name"]; ok {
			return nil, md, fmt.Errorf("global.discovery_name is no longer supported; use global.discovery_name_mdns and/or global.discovery_name_wsd")
		}
	}

	for name, prim := range raw.Share {
		var rawShare map[string]interface{}
		if err := md.PrimitiveDecode(prim, &rawShare); err != nil {
			return nil, md, fmt.Errorf("invalid share.%s table", name)
		}
		var share ShareConfig
		if err := md.PrimitiveDecode(prim, &share); err != nil {
			return nil, md, fmt.Errorf("invalid share.%s table", name)
		}
		cfg.Shares[name] = share
		mask := shareFieldMask{}
		if _, ok := rawShare["path"]; ok {
			mask.Path = true
		}
		if _, ok := rawShare["readonly"]; ok {
			mask.Readonly = true
		}
		if _, ok := rawShare["allow_users"]; ok {
			mask.AllowUsers = true
		}
		if _, ok := rawShare["guest"]; ok {
			return nil, md, fmt.Errorf("share.%s.guest is no longer supported; use allow_users = [\"guest\"]", name)
		}
		cfg.shareMask[name] = mask
	}

	for name, prim := range raw.User {
		var rawUser map[string]interface{}
		if err := md.PrimitiveDecode(prim, &rawUser); err != nil {
			return nil, md, fmt.Errorf("invalid user.%s table", name)
		}
		type userTable struct {
			Name     string `toml:"name"`
			Password string `toml:"password"`
			Readonly bool   `toml:"readonly"`
		}
		var ut userTable
		if err := md.PrimitiveDecode(prim, &ut); err != nil {
			return nil, md, fmt.Errorf("invalid user.%s table", name)
		}
		if strings.TrimSpace(ut.Name) != "" {
			return nil, md, fmt.Errorf("user.%s must not define name; the table key is the username", name)
		}
		cfg.Users = append(cfg.Users, UserConfig{
			Name:     name,
			Password: ut.Password,
			Readonly: ut.Readonly,
		})
		um := userFieldMask{}
		if _, ok := rawUser["password"]; ok {
			um.Password = true
		}
		if _, ok := rawUser["readonly"]; ok {
			um.Readonly = true
		}
		cfg.userMask[name] = um
	}
	sort.Slice(cfg.Users, func(i, j int) bool {
		return strings.ToLower(cfg.Users[i].Name) < strings.ToLower(cfg.Users[j].Name)
	})

	return cfg, md, nil
}

func applyConfigOverrides(dst *Config, src *Config, md toml.MetaData) {
	if md.IsDefined("global", "listen") {
		dst.Listen = src.Listen
		dst.ListenAddrs = append([]string(nil), src.ListenAddrs...)
	}
	if md.IsDefined("global", "advertise") {
		dst.Advertise = src.Advertise
	}
	if md.IsDefined("global", "discovery_name_mdns") {
		dst.DiscoveryNameMDNS = src.DiscoveryNameMDNS
	}
	if md.IsDefined("global", "discovery_name_wsd") {
		dst.DiscoveryNameWSD = src.DiscoveryNameWSD
	}
	if md.IsDefined("global", "readonly") {
		dst.Readonly = src.Readonly
	}
	if md.IsDefined("global", "verbose") {
		dst.Verbose = src.Verbose
	}
	if md.IsDefined("global", "verbose_level") {
		dst.VerboseLevel = src.VerboseLevel
	}
	if md.IsDefined("global", "debug") {
		dst.Debug = src.Debug
	}
	if md.IsDefined("global", "trace") {
		dst.Trace = src.Trace
	}
	if md.IsDefined("global", "allow") {
		dst.Allow = append([]string(nil), src.Allow...)
	}
	if md.IsDefined("global", "hide_dotfiles") {
		dst.HideDotfiles = src.HideDotfiles
	}
	if md.IsDefined("global", "expire") {
		dst.Expire = src.Expire
	}
	if md.IsDefined("global", "pidfile") {
		dst.PidFile = src.PidFile
	}
	if md.IsDefined("global", "logfile") {
		dst.LogFile = src.LogFile
	}
	if md.IsDefined("user") {
		if dst.userMask == nil {
			dst.userMask = map[string]userFieldMask{}
		}
		existing := map[string]UserConfig{}
		for _, u := range dst.Users {
			existing[strings.ToLower(u.Name)] = u
		}
		for _, user := range src.Users {
			key := strings.ToLower(user.Name)
			mask := src.userMask[user.Name]
			cur := existing[key]
			if cur.Name == "" {
				cur.Name = user.Name
			}
			if mask.Password {
				cur.Password = user.Password
			}
			if mask.Readonly {
				cur.Readonly = user.Readonly
			}
			existing[key] = cur
			dstMask := dst.userMask[cur.Name]
			dstMask.Password = dstMask.Password || mask.Password
			dstMask.Readonly = dstMask.Readonly || mask.Readonly
			dst.userMask[cur.Name] = dstMask
		}
		users := make([]UserConfig, 0, len(existing))
		for _, u := range existing {
			users = append(users, u)
		}
		sort.Slice(users, func(i, j int) bool {
			return strings.ToLower(users[i].Name) < strings.ToLower(users[j].Name)
		})
		dst.Users = users
	}
	if md.IsDefined("share") {
		if dst.Shares == nil {
			dst.Shares = map[string]ShareConfig{}
		}
		if dst.shareMask == nil {
			dst.shareMask = map[string]shareFieldMask{}
		}
		for name, share := range src.Shares {
			mask := src.shareMask[name]
			cur := dst.Shares[name]
			dstMask := dst.shareMask[name]
			if mask.Path {
				cur.Path = share.Path
			}
			if mask.Readonly {
				cur.Readonly = share.Readonly
			}
			if mask.AllowUsers {
				cur.AllowUsers = append([]string(nil), share.AllowUsers...)
			}
			dst.Shares[name] = cur
			dstMask.Path = dstMask.Path || mask.Path
			dstMask.Readonly = dstMask.Readonly || mask.Readonly
			dstMask.AllowUsers = dstMask.AllowUsers || mask.AllowUsers
			dst.shareMask[name] = dstMask
		}
	}
}

func recordConfigSources(info *ConfigLoadInfo, md toml.MetaData, src string, cfg *Config) {
	record := func(key string) {
		info.SettingSrc[key] = src
	}
	if md.IsDefined("global", "listen") {
		record("listen")
	}
	if md.IsDefined("global", "advertise") {
		record("advertise")
	}
	if md.IsDefined("global", "discovery_name_mdns") {
		record("discovery_name_mdns")
	}
	if md.IsDefined("global", "discovery_name_wsd") {
		record("discovery_name_wsd")
	}
	if md.IsDefined("global", "readonly") {
		record("readonly")
	}
	if md.IsDefined("global", "verbose") {
		record("verbose")
	}
	if md.IsDefined("global", "verbose_level") {
		record("verbose_level")
	}
	if md.IsDefined("global", "debug") {
		record("debug")
	}
	if md.IsDefined("global", "trace") {
		record("trace")
	}
	if md.IsDefined("global", "allow") {
		record("allow")
	}
	if md.IsDefined("global", "hide_dotfiles") {
		record("hide_dotfiles")
	}
	if md.IsDefined("user") {
		record("users")
		for _, user := range cfg.Users {
			mask := cfg.userMask[user.Name]
			if mask.Password {
				record("user." + user.Name + ".password")
			}
			if mask.Readonly {
				record("user." + user.Name + ".readonly")
			}
		}
	}
	if md.IsDefined("global", "expire") {
		record("expire")
	}
	if md.IsDefined("global", "pidfile") {
		record("pidfile")
	}
	if md.IsDefined("global", "logfile") {
		record("logfile")
	}
	if md.IsDefined("share") {
		record("shares")
		for name := range cfg.Shares {
			mask := cfg.shareMask[name]
			if mask.Path {
				record("share." + name + ".path")
			}
			if mask.AllowUsers {
				record("share." + name + ".allow_users")
			}
			if mask.Readonly {
				record("share." + name + ".readonly")
			}
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
	case "advertise":
		return strconv.FormatBool(cfg.Advertise)
	case "discovery_name_mdns":
		return cfg.DiscoveryNameMDNS
	case "discovery_name_wsd":
		return cfg.DiscoveryNameWSD
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
	case "users":
		return strconv.Itoa(len(cfg.Users))
	case "expire":
		return cfg.Expire
	case "pidfile":
		return cfg.PidFile
	case "logfile":
		return cfg.LogFile
	case "shares":
		return strconv.Itoa(len(cfg.Shares))
	default:
		if strings.HasPrefix(key, "share.") {
			rest := strings.TrimPrefix(key, "share.")
			name := rest
			field := ""
			if i := strings.Index(rest, "."); i >= 0 {
				name = rest[:i]
				field = rest[i+1:]
			}
			if cfg.Shares == nil {
				return ""
			}
			share := cfg.Shares[name]
			switch field {
			case "", "path":
				return share.Path
			case "readonly":
				return strconv.FormatBool(share.Readonly)
			case "allow_users":
				return strings.Join(share.AllowUsers, ",")
			}
			return share.Path
		}
		if strings.HasPrefix(key, "user.") {
			rest := strings.TrimPrefix(key, "user.")
			name := rest
			field := ""
			if i := strings.Index(rest, "."); i >= 0 {
				name = rest[:i]
				field = rest[i+1:]
			}
			for _, u := range cfg.Users {
				if u.Name != name {
					continue
				}
				switch field {
				case "password":
					return u.Password
				case "readonly":
					return strconv.FormatBool(u.Readonly)
				}
			}
			return ""
		}
	}
	return "<unknown>"
}

// loadConfig loads configuration.
// Default mode: /etc/sambamrc -> ~/.sambamrc -> ./.sambamrc
// Explicit mode (-c): only custom files, in the order passed.
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

	if len(customPaths) > 0 {
		// Explicit config mode: only load -c files.
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
	} else {
		// Default discovery mode.
		_ = loadLayer(info.SystemPath, "system", false, func() {
			info.SystemLoaded = true
		})

		home, err := os.UserHomeDir()
		if err == nil {
			configPath := filepath.Join(home, ".sambamrc")
			info.HomePath = configPath
			_ = loadLayer(configPath, "home", false, func() { info.HomeLoaded = true })
		}

		_ = loadLayer(info.LocalPath, "local", false, func() { info.LocalLoaded = true })
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
	clientTag := ""
	if c, ok := entry.Data["client"]; ok {
		if s, ok := c.(string); ok && s != "" {
			clientTag = Dim(" [" + s + "]")
		}
	}
	if !f.showLevel {
		return []byte(fmt.Sprintf("  %s%s %s\n", ts, clientTag, entry.Message)), nil
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

	return []byte(fmt.Sprintf("  %s%s %s %s\n", ts, clientTag, levelTag, entry.Message)), nil
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
	version = "1.4.33"
)

func main() {
	// Check subcommands before flag parsing.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "stop":
			stopDaemon()
			return
		case "status":
			statusDaemon()
			return
		}
	}

	// CLI flags
	shareSpecs := pflag.StringArrayP("name", "n", []string{}, "Share specification (name:path or just name)")
	listenAddrs := pflag.StringArrayP("listen", "l", []string{}, "Address or @interface to listen on (repeatable)")
	allowAddrs := pflag.StringArrayP("allow", "a", []string{}, "Allow client IP/CIDR (repeatable)")
	noAdvertise := pflag.BoolP("no-advertise", "x", false, "Disable share advertisement")
	readOnly := pflag.BoolP("readonly", "r", false, "Make share read-only")
	showVersion := pflag.BoolP("version", "V", false, "Show version")
	showHelp := pflag.BoolP("help", "h", false, "Show help")

	// Daemon mode flags
	daemonMode := pflag.BoolP("daemon", "d", false, "Run as background daemon")
	pidFile := pflag.StringP("pidfile", "P", "/tmp/sambam.pid", "PID file location (daemon mode)")
	logFile := pflag.StringP("logfile", "L", "", "Log file path (default /tmp/sambam.log when value is omitted)")
	pflag.Lookup("logfile").NoOptDefVal = "/tmp/sambam.log"
	configFiles := pflag.StringArrayP("config", "c", []string{}, "Config file (repeatable, disables default config discovery)")

	// Verbosity flags
	verbose := pflag.CountP("verbose", "v", "Show connections and file activity (-vv extended, -vvv full trace)")

	// Hidden files flag
	hideDotfiles := pflag.BoolP("hide-dotfiles", "H", false, "Hide files starting with '.'")

	// Authentication flags
	userSpecs := pflag.StringArrayP("username", "u", []string{}, "Require authentication (user or user:password, repeatable)")
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
		if !pflag.CommandLine.Changed("listen") {
			if len(config.ListenAddrs) > 1 {
				*listenAddrs = append([]string(nil), config.ListenAddrs...)
			} else if config.Listen != "" {
				*listenAddrs = []string{config.Listen}
			}
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

	if len(*listenAddrs) == 0 {
		*listenAddrs = []string{"0.0.0.0:445"}
	}
	advertiseEnabled := true
	if config != nil {
		if _, ok := configInfo.SettingSrc["advertise"]; ok {
			advertiseEnabled = config.Advertise
		}
	}
	if *noAdvertise {
		advertiseEnabled = false
	}
	authUsers, err := buildAuthUsers(*userSpecs, *password, pflag.CommandLine.Changed("username"), pflag.CommandLine.Changed("password"), config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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
			effectiveConfig.Shares = make(map[string]ShareConfig, len(config.Shares))
			for k, v := range config.Shares {
				effectiveConfig.Shares[k] = v
			}
		}
	}
	if len(*listenAddrs) == 1 {
		effectiveConfig.Listen = (*listenAddrs)[0]
		effectiveConfig.ListenAddrs = nil
	} else {
		effectiveConfig.Listen = (*listenAddrs)[0]
		effectiveConfig.ListenAddrs = append([]string(nil), *listenAddrs...)
	}
	effectiveConfig.Readonly = *readOnly
	effectiveConfig.Advertise = advertiseEnabled
	effectiveConfig.HideDotfiles = *hideDotfiles
	if len(authUsers) > 1 {
		effectiveConfig.Users = authUsersToConfig(authUsers)
	} else if len(authUsers) == 1 {
		effectiveConfig.Users = authUsersToConfig(authUsers)
	} else {
		effectiveConfig.Users = nil
	}
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
	if pflag.CommandLine.Changed("no-advertise") {
		markCLI("advertise")
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
		markCLI("users")
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

	// Validate listen values (IP[:port] or @iface[:port]) before doing anything else.
	for _, listenAddr := range *listenAddrs {
		host, port := parseHostPort(listenAddr)
		if strings.HasPrefix(host, "@") {
			ifaceName := strings.TrimPrefix(host, "@")
			if ifaceName == "" {
				fmt.Fprintf(os.Stderr, "Invalid listen address %q: expected @<interface>[:port]\n", listenAddr)
				os.Exit(1)
			}
		} else if host == "" || net.ParseIP(host) == nil {
			fmt.Fprintf(os.Stderr, "Invalid listen address %q: expected IP, IP:port, or @<interface>[:port]\n", listenAddr)
			os.Exit(1)
		}
		if port != "" {
			p, err := strconv.Atoi(port)
			if err != nil || p < 1 || p > 65535 {
				fmt.Fprintf(os.Stderr, "Invalid listen port in %q: expected 1-65535\n", listenAddr)
				os.Exit(1)
			}
		}
	}

	// Generate config and exit without starting the server.
	if pflag.CommandLine.Changed("gen-config") {
		target := *generateConfigPath
		if target == "" {
			target = ".sambamrc"
		}
		_, err := writeGeneratedConfig(target, *listenAddrs, *allowAddrs, advertiseEnabled, *readOnly, *verbose, *hideDotfiles, *userSpecs, *password, *expireStr, *pidFile, *logFile, *shareSpecs, pflag.Args())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s %s\n", Green("Generated config:"), Cyan(target))
		content, err := os.ReadFile(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading generated config %s: %v\n", target, err)
			os.Exit(1)
		}
		fmt.Println()
		fmt.Print(string(content))
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

	extraVerbose := *verbose >= 2
	fullVerbose := *verbose >= 3

	if *showHelp {
		printUsage()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("sambam %s (built with AI assistance)\n", version)
		os.Exit(0)
	}

	configLogsPrinted := false
	configMergeLogs := []string{}
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
		if *verbose >= 2 && len(configMergeLogs) > 0 {
			for _, msg := range configMergeLogs {
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
		for name, sc := range config.Shares {
			if strings.TrimSpace(sc.Path) == "" {
				fmt.Fprintf(os.Stderr, "Error: share.%s.path is required (set in one of the loaded config files)\n", name)
				os.Exit(1)
			}
			mask := config.shareMask[name]
			if !mask.AllowUsers {
				fmt.Fprintf(os.Stderr, "Error: share.%s.allow_users is required (set in one of the loaded config files)\n", name)
				os.Exit(1)
			}
			absPath, err := filepath.Abs(sc.Path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving path for '%s': %v\n", name, err)
				os.Exit(1)
			}
			shareMap[name] = Share{
				Name:       name,
				Path:       absPath,
				ReadOnly:   sc.Readonly || *readOnly,
				AllowUsers: append([]string(nil), sc.AllowUsers...),
			}
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
		s := Share{Name: name, Path: absPath, ReadOnly: *readOnly}
		if prev, ok := shareMap[name]; ok {
			s.Guest = prev.Guest
			s.AllowUsers = append([]string(nil), prev.AllowUsers...)
			s.ReadOnly = prev.ReadOnly || *readOnly
		}
		shareMap[name] = s
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
			s := Share{Name: name, Path: absPath, ReadOnly: *readOnly}
			if prev, ok := shareMap[name]; ok {
				s.Guest = prev.Guest
				s.AllowUsers = append([]string(nil), prev.AllowUsers...)
				s.ReadOnly = prev.ReadOnly || *readOnly
			}
			shareMap[name] = s
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
		shareMap[name] = Share{Name: name, Path: absPath, ReadOnly: *readOnly}
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

	// Validate and normalize per-share access policy.
	for _, share := range shares {
		guestEntries := 0
		normalizedUsers := make([]string, 0, len(share.AllowUsers))
		for _, u := range share.AllowUsers {
			trimmedUser := strings.TrimSpace(u)
			if strings.EqualFold(trimmedUser, "guest") {
				guestEntries++
				continue
			}
			normalizedUsers = append(normalizedUsers, trimmedUser)
		}
		if guestEntries > 1 {
			fmt.Fprintf(os.Stderr, "Error: share.%s allow_users cannot contain duplicate guest entries\n", share.Name)
			os.Exit(1)
		}
		if len(authUsers) == 0 && len(normalizedUsers) > 0 {
			fmt.Fprintf(os.Stderr, "Error: share.%s allow_users references named users but no [user.<name>] entries are configured\n", share.Name)
			os.Exit(1)
		}
		shareMap[share.Name] = Share{
			Name:       share.Name,
			Path:       share.Path,
			ReadOnly:   share.ReadOnly,
			Guest:      guestEntries == 1,
			AllowUsers: normalizedUsers,
		}
	}

	// Rebuild sorted share list after normalization.
	shares = shares[:0]
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

	// Resolve listen addresses once and reuse across banner/listener.
	listenEndpoints, listenPort, err := buildListenEndpoints(*listenAddrs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid listen address: %v\n", err)
		os.Exit(1)
	}
	listenDisplay := listenEndpoints[0].Display
	if len(listenEndpoints) > 1 {
		listenDisplay = fmt.Sprintf("%s %s", listenDisplay, Dim(fmt.Sprintf("(+%d more)", len(listenEndpoints)-1)))
	}
	bindAddrs := make([]string, 0, len(listenEndpoints))
	for _, ep := range listenEndpoints {
		bindAddrs = append(bindAddrs, ep.Bind)
	}

	// Get IPs for display.
	var displayIPs []string
	if len(listenEndpoints) == 1 && listenEndpoints[0].Wildcard {
		displayIPs = getLocalIPs()
	} else {
		seen := map[string]struct{}{}
		for _, ep := range listenEndpoints {
			if _, ok := seen[ep.IP]; ok {
				continue
			}
			seen[ep.IP] = struct{}{}
			displayIPs = append(displayIPs, ep.IP)
		}
	}

	// Format connection string with port if non-standard.
	portSuffix := ""
	if listenPort != "445" {
		portSuffix = ":" + listenPort
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
			printBanner(shares, listenDisplay, displayIPs, portSuffix, *allowAddrs, authDisplay(authUsers), mountAuthOpt(authUsers), *expireStr, true, extraVerbose)
			printConfigLogs()

			// Persist daemon status snapshot for `sambam status`.
			statusPath := daemonStatusFilePath(*pidFile)
			status := daemonStatus{
				PID:        child.Pid,
				PIDFile:    *pidFile,
				LogFile:    logFileName,
				Shares:     shares,
				Listen:     listenDisplay,
				Auth:       authDisplay(authUsers),
				AllowAddrs: append([]string(nil), *allowAddrs...),
				UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
			}
			if *expireStr != "" {
				if d, err := time.ParseDuration(*expireStr); err == nil {
					status.ExpiresAt = time.Now().Add(d).UTC().Format(time.RFC3339)
				}
			}
			if err := writeDaemonStatus(statusPath, status); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to write status file %s: %v\n", statusPath, err)
			}

			fmt.Println()
			fmt.Printf("  %-12s %s\n", "Status", Green("daemon started"))
			fmt.Printf("  %-12s %d\n", "PID", child.Pid)
			fmt.Printf("  %-12s %s\n", "PID file", *pidFile)
			fmt.Printf("  %-12s %s\n", "Log file", formatLogFileDisplay(logFileName))
			fmt.Printf("  %-12s %s%s%s\n", "Control", Cyan("sambam stop"), Dim(" | "), Cyan("sambam status"))
			fmt.Println()
			fmt.Printf("  %s\n", Red("Daemon mode: running in background"))
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
		fs := NewPassthroughFS(share.Path, share.ReadOnly)

		// Note: create/replace/delete logs are emitted in SMB handlers so they carry client context.
		if extraVerbose {
			fs.OnOpen = func(path string, mode string) {
				path = normalizeLogPath(path)
				logrus.Infof("open: %s (%s)", path, mode)
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
	var onDetect func(string, string)
	var onAuthFail func(string, string)
	if *verbose > 0 {
		onConnect = func(remoteAddr string) {
			logrus.Infof("connect: %s", remoteAddr)
		}
		var modLogMu sync.Mutex
		modLogLast := map[string]time.Time{}
		onDetect = func(action, path string) {
			if action == "modified" {
				modLogMu.Lock()
				now := time.Now()
				skip := now.Sub(modLogLast[path]) < 2*time.Second
				if !skip {
					modLogLast[path] = now
				}
				modLogMu.Unlock()
				if skip {
					return
				}
			}
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
	userReadonly := map[string]bool{}
	allowGuest := len(authUsers) == 0
	for _, au := range authUsers {
		userPassword[au.Name] = au.Password
		userReadonly[strings.ToLower(au.Name)] = au.Readonly
	}
	authUserNames := make([]string, 0, len(authUsers))
	for _, au := range authUsers {
		authUserNames = append(authUserNames, au.Name)
	}
	shareAllowUsers := map[string][]string{}
	shareGuest := map[string]bool{}
	guestShareExists := false
	for _, share := range shares {
		if share.Guest {
			shareGuest[share.Name] = true
			guestShareExists = true
		}
		if len(share.AllowUsers) > 0 {
			shareAllowUsers[share.Name] = append([]string(nil), share.AllowUsers...)
		}
	}
	if guestShareExists {
		allowGuest = true
	}

	// Create server
	srv := smb2.NewServer(
		&smb2.ServerConfig{
			AllowGuest:      allowGuest,
			Xatrrs:          true,
			HideDotfiles:    *hideDotfiles,
			ShareGuest:      shareGuest,
			ShareAllowUsers: shareAllowUsers,
			AuthUsers:       authUserNames,
			UserReadonly:    userReadonly,
			AllowConn: func(remoteAddr string) bool {
				return isRemoteAllowed(remoteAddr, allowNets)
			},
			OnReject: func(remoteAddr string) {
				logrus.Warnf("reject: %s (not in allow list)", remoteAddr)
			},
			OnConnect:  onConnect,
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

	// Print banner in foreground mode.
	if !*daemonMode {
		printBanner(shares, listenDisplay, displayIPs, portSuffix, *allowAddrs, authDisplay(authUsers), mountAuthOpt(authUsers), *expireStr, false, extraVerbose)
		printConfigLogs()
	}

	// Optional Bonjour/mDNS + WS-Discovery advertisement for discovery.
	var discovery *discoveryAdvertiser
	advertiseStarted := false
	if advertiseEnabled {
		discovery, err = startSMBAdvertiser(shares, listenEndpoints, listenPort, authUsers, *allowAddrs, effectiveConfig.DiscoveryNameMDNS, effectiveConfig.DiscoveryNameWSD)
		if err != nil {
			logrus.Warnf("advertise disabled: %v", err)
		} else {
			advertiseStarted = true
		}
	}
	if advertiseStarted {
		logrus.Infof("advertising via mDNS + WSD on SMB port %s", listenPort)
	}

	// Start server in goroutine
	go func() {
		if err := srv.ServeMany(bindAddrs); err != nil {
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
	var expireCountdownStop chan struct{}
	if *expireStr != "" {
		duration, err := time.ParseDuration(*expireStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid expire duration: %v\n", err)
			os.Exit(1)
		}
		expireAt := time.Now().Add(duration)
		expireTimer = time.NewTimer(duration)

		// In foreground mode, print periodic remaining-time updates as normal lines.
		// This avoids carriage-return redraw collisions with incoming logs.
		if !*daemonMode {
			expireCountdownStop = make(chan struct{})
			logrus.Infof("expires in %s", formatDuration(duration))
			go func(until time.Time) {
				ticker := time.NewTicker(1 * time.Second)
				defer ticker.Stop()
				lastShown := -1
				for {
					select {
					case <-ticker.C:
						remaining := int(time.Until(until).Round(time.Second) / time.Second)
						if remaining <= 0 {
							return
						}
						show := remaining <= 10 || remaining%10 == 0
						if show && remaining != lastShown {
							logrus.Infof("expires in %s", formatDuration(time.Duration(remaining)*time.Second))
							lastShown = remaining
						}
					case <-expireCountdownStop:
						return
					}
				}
			}(expireAt)
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
	if expireCountdownStop != nil {
		close(expireCountdownStop)
	}
	if discovery != nil {
		discovery.Shutdown()
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

func formatLogFileDisplay(path string) string {
	if strings.TrimSpace(path) == "" || path == "/dev/null" {
		return "none"
	}
	return path
}

func normalizeLogPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func printBanner(shares []Share, listenAddr string, displayIPs []string, portSuffix string, allowAddrs []string, authText string, authMount string, expireStr string, daemonMode bool, extendedConnect bool) {
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
		if maxLen < 11 {
			maxLen = 11
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

	modeStr := Red("read-write")
	roCount := 0
	for _, s := range shares {
		if s.ReadOnly {
			roCount++
		}
	}
	if roCount == len(shares) {
		modeStr = Green("read-only")
	} else if roCount > 0 {
		modeStr = Yellow("mixed")
	}
	fmt.Printf("  %-12s %s\n", "Mode", modeStr)

	fmt.Printf("  %-12s %s\n", "Auth", authText)
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
	mountOptForShare := func(share Share) string {
		if share.Guest {
			return "guest"
		}
		return authMount
	}

	fmt.Println()
	portOpt := ""
	if nonStdPort {
		portOpt = ",port=" + portNum
	}

	if !extendedConnect {
		fmt.Println("  Connect:")
		fmt.Printf("  %-12s %s\n", "Windows", Cyan(fmt.Sprintf("\\\\%s\\%s", firstIP, firstShare)))
		fmt.Printf("  %-12s %s\n", "macOS", Cyan(fmt.Sprintf("smb://%s/%s", firstIP, firstShare)))
		fmt.Printf("  %-12s %s\n", "Linux", Cyan(fmt.Sprintf("sudo mount -t cifs //%s/%s /mnt -o %s%s", firstIP, firstShare, mountOptForShare(shares[0]), portOpt)))
		if comboCount > 1 {
			fmt.Printf("  %-12s %s\n", "", Dim(fmt.Sprintf("(%d additional share/ip combinations; use -vv to show all)", comboCount-1)))
		}
		if nonStdPort {
			fmt.Printf("  %-12s %s\n", "", Dim(fmt.Sprintf("non-standard SMB port %s: Windows/macOS may require port forwarding", portNum)))
		}
	}

	if extendedConnect {
		const contPrefix = "               "
		fmt.Println("  All connections:")
		fmt.Printf("  %-12s ", "Windows")
		first := true
		for _, share := range shares {
			for _, ip := range displayIPs {
				prefix := contPrefix
				if first {
					prefix = ""
					first = false
				}
				fmt.Printf("%s%s\n", prefix, Cyan(fmt.Sprintf("\\\\%s\\%s", ip, share.Name)))
			}
		}

		fmt.Printf("  %-12s ", "macOS")
		first = true
		for _, share := range shares {
			for _, ip := range displayIPs {
				prefix := contPrefix
				if first {
					prefix = ""
					first = false
				}
				fmt.Printf("%s%s\n", prefix, Cyan(fmt.Sprintf("smb://%s/%s", ip, share.Name)))
			}
		}

		fmt.Printf("  %-12s ", "Linux")
		first = true
		for _, share := range shares {
			for _, ip := range displayIPs {
				prefix := contPrefix
				if first {
					prefix = ""
					first = false
				}
				authOpt := mountOptForShare(share)
				fmt.Printf("%s%s\n", prefix, Cyan(fmt.Sprintf("sudo mount -t cifs //%s/%s /mnt -o %s%s", ip, share.Name, authOpt, portOpt)))
				fmt.Printf("%s%s %s\n", contPrefix, Cyan(fmt.Sprintf("sudo mount -t cifs //%s/%s /mnt -o %s%s,vers=3.1.1,posix,cifsacl", ip, share.Name, authOpt, portOpt)), Dim("# POSIX"))
			}
		}

		if nonStdPort {
			fmt.Println()
			fmt.Println("  SSH tunnel:")
			for _, ip := range displayIPs {
				fmt.Printf("    %s\n", Cyan(fmt.Sprintf("ssh -L 445:%s:%s user@%s", ip, portNum, ip)))
			}
		}
	}
	fmt.Println()
	if !daemonMode && expireStr != "" {
		fmt.Printf("  %s\n", Dim("Press Ctrl+C to stop, or wait for expiry"))
	} else if !daemonMode {
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
	fmt.Printf("    %s\n", Cyan("sambam status"))
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
	printOpt("-l, --listen", "Address or @interface to listen on "+Dim("(repeatable, default: 0.0.0.0:445)"))
	printOpt("-u, --username", "Require authentication "+Dim("(user or user:password, repeatable)"))
	printOpt("-p, --password", "Password "+Dim("(random if not set)"))
	printOpt("-r, --readonly", "Make share read-only")
	printOpt("-e, --expire", "Auto-shutdown after duration "+Dim("(e.g., 30m, 1h)"))
	printOpt("-d, --daemon", "Run as background daemon")
	printOpt("-v, --verbose", "Show connections and file activity "+Dim("(-vv extended, -vvv full trace)"))
	printOpt("-H, --hide-dotfiles", "Hide files starting with '.'")
	printOpt("-a, --allow", "Allow client IP/CIDR "+Dim("(repeatable, default: allow all)"))
	printOpt("-x, --no-advertise", "Disable share advertisement")
	printOpt("-c, --config", "Config file "+Dim("(repeatable, disables default config discovery)"))
	printOpt("-G, --gen-config", "Generate config TOML and exit "+Dim("(default: ./.sambamrc)"))
	printOpt("-P, --pidfile", "PID file location "+Dim("(default: /tmp/sambam.pid)"))
	printOpt("-L, --logfile", "Log file path "+Dim("(default /tmp/sambam.log when omitted)"))
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
	printExample("sambam status", "Show current daemon status")
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
			out = append(out, "--logfile="+args[i+1])
			i++
			continue
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

func writeGeneratedConfig(target string, listenAddrs []string, allowAddrs []string, advertise bool, readOnly bool, verbose int, hideDotfiles bool, userSpecs []string, password, expire, pidFile, logFile string, shareSpecs []string, args []string) ([]string, error) {
	var b bytes.Buffer
	written := []string{}
	writeUserReadonly := false
	generatedUser := ""
	globalStarted := false
	b.WriteString("# sambam generated configuration\n")
	b.WriteString("# CLI flags override these settings.\n\n")

	startGlobal := func() {
		if globalStarted {
			return
		}
		b.WriteString("[global]\n")
		globalStarted = true
	}
	writeString := func(key, value string) {
		startGlobal()
		fmt.Fprintf(&b, "%s = %s\n", key, strconv.Quote(value))
		written = append(written, fmt.Sprintf("%s=%q", key, value))
	}
	writeBool := func(key string, value bool) {
		startGlobal()
		fmt.Fprintf(&b, "%s = %t\n", key, value)
		written = append(written, fmt.Sprintf("%s=%t", key, value))
	}
	writeInt := func(key string, value int) {
		startGlobal()
		fmt.Fprintf(&b, "%s = %d\n", key, value)
		written = append(written, fmt.Sprintf("%s=%d", key, value))
	}
	writeStringArray := func(key string, values []string) {
		startGlobal()
		quoted := make([]string, 0, len(values))
		for _, v := range values {
			quoted = append(quoted, strconv.Quote(v))
		}
		fmt.Fprintf(&b, "%s = [%s]\n", key, strings.Join(quoted, ", "))
		written = append(written, fmt.Sprintf("%s=%s", key, strings.Join(values, ",")))
	}

	if pflag.CommandLine.Changed("listen") {
		if len(listenAddrs) == 1 {
			writeString("listen", listenAddrs[0])
		} else {
			writeStringArray("listen", listenAddrs)
		}
	}
	if pflag.CommandLine.Changed("allow") {
		writeStringArray("allow", allowAddrs)
	}
	if pflag.CommandLine.Changed("no-advertise") {
		writeBool("advertise", advertise)
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
	if pflag.CommandLine.Changed("expire") {
		writeString("expire", expire)
	}
	if pflag.CommandLine.Changed("pidfile") {
		writeString("pidfile", pidFile)
	}
	if pflag.CommandLine.Changed("logfile") {
		writeString("logfile", logFile)
	}
	if pflag.CommandLine.Changed("username") {
		users, err := buildAuthUsers(userSpecs, password, true, pflag.CommandLine.Changed("password"), nil)
		if err != nil {
			return nil, err
		}
		if len(users) != 1 {
			return nil, fmt.Errorf("gen-config supports only a single user. Use one -u/--username value")
		}
		u := users[0]
		generatedUser = u.Name
		fmt.Fprintf(&b, "\n[user.%s]\n", u.Name)
		fmt.Fprintf(&b, "password = %s\n", strconv.Quote(u.Password))
		written = append(written, fmt.Sprintf("user.%s.password=%q", u.Name, u.Password))
		if readOnly {
			writeUserReadonly = true
			b.WriteString("readonly = true\n")
			written = append(written, fmt.Sprintf("user.%s.readonly=true", u.Name))
		}
	} else if pflag.CommandLine.Changed("password") {
		return nil, fmt.Errorf("password requires username. Use -u/--username together with -p/--password")
	}
	if pflag.CommandLine.Changed("readonly") && !writeUserReadonly {
		writeBool("readonly", readOnly)
	}

	shares := buildSharesForConfig(shareSpecs, args)
	if len(shares) > 0 {
		names := make([]string, 0, len(shares))
		for name := range shares {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(&b, "\n[share.%s]\n", name)
			fmt.Fprintf(&b, "path = %s\n", strconv.Quote(shares[name]))
			written = append(written, fmt.Sprintf("share.%s.path=%q", name, shares[name]))
			if generatedUser != "" {
				fmt.Fprintf(&b, "allow_users = [%s]\n", strconv.Quote(generatedUser))
				written = append(written, fmt.Sprintf("share.%s.allow_users=%q", name, generatedUser))
			} else {
				fmt.Fprintf(&b, "allow_users = [\"guest\"]\n")
				written = append(written, fmt.Sprintf("share.%s.allow_users=%q", name, "guest"))
			}
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

type listenEndpoint struct {
	Bind     string
	Display  string
	IP       string
	Port     string
	Wildcard bool
}

type authUser struct {
	Name     string
	Password string
	Readonly bool
}

func buildListenEndpoints(values []string) ([]listenEndpoint, string, error) {
	endpoints := make([]listenEndpoint, 0, len(values))
	seen := map[string]struct{}{}
	commonPort := ""
	wildcardByPort := map[string]bool{}
	nonWildcardByPort := map[string]bool{}

	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" {
			return nil, "", fmt.Errorf("empty listen value")
		}

		host, port := parseHostPort(v)
		if port == "" {
			port = "445"
		}
		if commonPort == "" {
			commonPort = port
		} else if commonPort != port {
			return nil, "", fmt.Errorf("all listen endpoints must use the same port (got %s and %s)", commonPort, port)
		}

		resolvedHost, iface, err := resolveListenHost(host)
		if err != nil {
			return nil, "", fmt.Errorf("%q: %w", raw, err)
		}
		if resolvedHost == "" || net.ParseIP(resolvedHost) == nil {
			return nil, "", fmt.Errorf("%q: resolved host is not a valid IP", raw)
		}

		bind := net.JoinHostPort(resolvedHost, port)
		if _, ok := seen[bind]; ok {
			continue
		}
		seen[bind] = struct{}{}

		wildcard := resolvedHost == "0.0.0.0" || resolvedHost == "::"
		if wildcard {
			wildcardByPort[port] = true
			if nonWildcardByPort[port] {
				return nil, "", fmt.Errorf("cannot mix wildcard %q with specific listen endpoints on port %s", raw, port)
			}
		} else {
			nonWildcardByPort[port] = true
			if wildcardByPort[port] {
				return nil, "", fmt.Errorf("cannot mix wildcard and specific listen endpoints on port %s", port)
			}
		}

		display := bind
		if iface != "" {
			display = fmt.Sprintf("%s %s", bind, Dim(fmt.Sprintf("(from @%s)", iface)))
		}
		endpoints = append(endpoints, listenEndpoint{
			Bind:     bind,
			Display:  display,
			IP:       resolvedHost,
			Port:     port,
			Wildcard: wildcard,
		})
	}

	if len(endpoints) == 0 {
		return nil, "", fmt.Errorf("no listen endpoints configured")
	}
	return endpoints, commonPort, nil
}

func defaultWSDDiscoveryName(hostname string) string {
	name := strings.TrimSpace(hostname)
	if name == "" {
		name = "sambam"
	}
	return name
}

func defaultMDNSDiscoveryName(hostname string) string {
	name := strings.TrimSpace(hostname)
	if name == "" {
		name = "sambam"
	}
	return name + "-sambam"
}

func startSMBAdvertiser(shares []Share, endpoints []listenEndpoint, listenPort string, users []authUser, allowAddrs []string, mdnsName string, wsdName string) (*discoveryAdvertiser, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares to advertise")
	}
	port, err := strconv.Atoi(listenPort)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid advertise port: %q", listenPort)
	}

	shareNames := make([]string, 0, len(shares))
	for _, s := range shares {
		shareNames = append(shareNames, s.Name)
	}
	sort.Strings(shareNames)

	hostname, _ := os.Hostname()
	instance := strings.TrimSpace(mdnsName)
	if instance == "" {
		instance = defaultMDNSDiscoveryName(hostname)
	}
	if len(instance) > 63 {
		instance = instance[:63]
	}

	authMode := "anonymous"
	if len(users) > 0 {
		authMode = "auth"
	}
	txt := []string{
		"vendor=sambam",
		"service=smb",
		"shares=" + strings.Join(shareNames, ","),
		"auth=" + authMode,
	}
	if len(allowAddrs) > 0 {
		txt = append(txt, "allow="+strings.Join(allowAddrs, ","))
	}

	adv := &discoveryAdvertiser{}
	var errs []string

	// zeroconf advertises on active interfaces automatically when ifaces=nil.
	s, err := zeroconf.Register(instance, "_smb._tcp", "local.", port, txt, nil)
	if err != nil {
		errs = append(errs, "mDNS: "+err.Error())
	} else {
		adv.mdns = s
	}

	wsd, err := startWSDiscovery(shares, endpoints, wsdName)
	if err != nil {
		errs = append(errs, "WSD: "+err.Error())
	} else {
		adv.wsd = wsd
	}

	if adv.mdns == nil && adv.wsd == nil {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	if len(errs) > 0 {
		logrus.Warnf("advertise partial: %s", strings.Join(errs, "; "))
	}
	return adv, nil
}

func advertiseIPsFromEndpoints(endpoints []listenEndpoint) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, ep := range endpoints {
		if ep.Wildcard {
			continue
		}
		if _, ok := seen[ep.IP]; ok {
			continue
		}
		seen[ep.IP] = struct{}{}
		out = append(out, ep.IP)
	}
	if len(out) > 0 {
		return out
	}
	for _, ip := range getLocalIPs() {
		if ip == "<your-ip>" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func stableUUIDFromSeed(seed string) string {
	sum := sha1.Sum([]byte(seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // RFC4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randomUUIDURN() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "urn:uuid:00000000-0000-0000-0000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func xmlFieldValue(xml, local string) string {
	open := "<" + local + ">"
	close := "</" + local + ">"
	if i := strings.Index(xml, open); i >= 0 {
		j := strings.Index(xml[i+len(open):], close)
		if j >= 0 {
			return strings.TrimSpace(xml[i+len(open) : i+len(open)+j])
		}
	}
	open = "<wsa:" + local + ">"
	close = "</wsa:" + local + ">"
	if i := strings.Index(xml, open); i >= 0 {
		j := strings.Index(xml[i+len(open):], close)
		if j >= 0 {
			return strings.TrimSpace(xml[i+len(open) : i+len(open)+j])
		}
	}
	open = "<a:" + local + ">"
	close = "</a:" + local + ">"
	if i := strings.Index(xml, open); i >= 0 {
		j := strings.Index(xml[i+len(open):], close)
		if j >= 0 {
			return strings.TrimSpace(xml[i+len(open) : i+len(open)+j])
		}
	}
	return ""
}

func startWSDiscovery(shares []Share, endpoints []listenEndpoint, wsdName string) (*wsDiscoveryService, error) {
	ips := advertiseIPsFromEndpoints(endpoints)
	if len(ips) == 0 {
		return nil, fmt.Errorf("no usable IP addresses for WSD")
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "sambam"
	}
	friendlyName := strings.TrimSpace(wsdName)
	if friendlyName == "" {
		friendlyName = defaultWSDDiscoveryName(hostname)
	}
	workgroup := strings.TrimSpace(os.Getenv("SAMBA_WORKGROUP"))
	if workgroup == "" {
		workgroup = strings.TrimSpace(os.Getenv("WORKGROUP"))
	}
	if workgroup == "" {
		workgroup = "WORKGROUP"
	}
	shareNames := make([]string, 0, len(shares))
	for _, s := range shares {
		shareNames = append(shareNames, s.Name)
	}
	sort.Strings(shareNames)
	seed := hostname + "|" + strings.Join(shareNames, ",") + "|" + friendlyName
	uuid := stableUUIDFromSeed(seed)

	mcast := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 3702}
	conn, err := net.ListenMulticastUDP("udp4", nil, mcast)
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadBuffer(1 << 20)

	wsd := &wsDiscoveryService{
		conn:            conn,
		multicastAddr:   mcast,
		endpointAddress: "urn:uuid:" + uuid,
		endpointUUID:    uuid,
		xaddr:           fmt.Sprintf("http://%s:5357/sambam/wsd", ips[0]),
		xaddrs:          make([]string, 0, len(ips)),
		friendlyName:    friendlyName,
		manufacturer:    "sambam",
		workgroup:       workgroup,
		scopes:          "smb://" + ips[0] + "/",
		metadataVersion: 1,
		sequenceID:      randomUUIDURN(),
		stop:            make(chan struct{}),
	}
	for _, ip := range ips {
		wsd.xaddrs = append(wsd.xaddrs, fmt.Sprintf("http://%s:5357/%s", ip, wsd.endpointUUID))
	}
	wsd.xaddr = wsd.xaddrs[0]
	if err := wsd.startMetadataHTTP("0.0.0.0"); err != nil {
		_ = conn.Close()
		return nil, err
	}
	logrus.Debugf("wsd init: ready (xaddrs=%d)", len(wsd.xaddrs))
	logrus.Tracef("wsd init detail: endpoint=%s xaddrs=%s scopes=%s", wsd.endpointAddress, strings.Join(wsd.xaddrs, ","), wsd.scopes)
	wsd.wg.Add(1)
	go wsd.serve()
	wsd.sendHello()
	return wsd, nil
}

func (w *wsDiscoveryService) Shutdown() {
	close(w.stop)
	w.sendBye()
	_ = w.conn.Close()
	if w.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		_ = w.httpServer.Shutdown(ctx)
		cancel()
	}
	w.wg.Wait()
}

func (w *wsDiscoveryService) serve() {
	defer w.wg.Done()
	buf := make([]byte, 64*1024)
	for {
		_ = w.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := w.conn.ReadFromUDP(buf)
		select {
		case <-w.stop:
			return
		default:
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue
		}
		msg := string(buf[:n])
		lower := strings.ToLower(msg)
		action := xmlFieldValue(msg, "Action")
		msgID := xmlFieldValue(msg, "MessageID")
		if action != "" || msgID != "" {
			logrus.Tracef("wsd recv: from=%s action=%s message_id=%s bytes=%d", src.String(), action, msgID, n)
		} else {
			logrus.Tracef("wsd recv: from=%s bytes=%d", src.String(), n)
		}
		if strings.Contains(lower, "ws-discovery/2009/01/probe") ||
			strings.Contains(lower, "ws/2005/04/discovery/probe") ||
			strings.Contains(lower, "<d:probe") || strings.Contains(lower, "<probe") {
			logrus.Debugf("wsd probe: from=%s", src.String())
			w.sendProbeMatch(src, xmlFieldValue(msg, "MessageID"))
			continue
		}
		if strings.Contains(lower, "ws-discovery/2009/01/resolve") ||
			strings.Contains(lower, "ws/2005/04/discovery/resolve") ||
			strings.Contains(lower, "<d:resolve") || strings.Contains(lower, "<resolve") {
			logrus.Debugf("wsd resolve: from=%s", src.String())
			requestedEndpoint := xmlFieldValue(msg, "Address")
			if requestedEndpoint != "" && !strings.EqualFold(requestedEndpoint, w.endpointAddress) {
				logrus.Debugf("wsd resolve: ignored foreign endpoint from=%s", src.String())
				logrus.Tracef("wsd resolve skip: from=%s requested=%s local=%s", src.String(), requestedEndpoint, w.endpointAddress)
				continue
			}
			w.sendResolveMatch(src, xmlFieldValue(msg, "MessageID"))
		}
	}
}

func (w *wsDiscoveryService) sendTo(addr *net.UDPAddr, payload string) {
	if w.conn == nil {
		logrus.Tracef("wsd send error: dst=%s err=nil socket", addr.String())
		return
	}
	n, err := w.conn.WriteToUDP([]byte(payload), addr)
	if err != nil {
		logrus.Tracef("wsd send error: dst=%s err=%v", addr.String(), err)
		return
	}
	src := ""
	if la := w.conn.LocalAddr(); la != nil {
		src = la.String()
	}
	logrus.Tracef("wsd send: src=%s dst=%s bytes=%d wrote=%d", src, addr.String(), len(payload), n)
}

func (w *wsDiscoveryService) sendHello() {
	xaddrList := w.xaddrListFor(nil)
	appSeq := w.appSequenceHeader()
	msg := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof"
 xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07">
<e:Header>
<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</wsa:Action>
<wsa:MessageID>%s</wsa:MessageID>
<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
%s
</e:Header>
<e:Body>
<d:Hello>
<wsa:EndpointReference><wsa:Address>%s</wsa:Address></wsa:EndpointReference>
<d:Types>wsdp:Device pub:Computer</d:Types>
<d:Scopes>%s</d:Scopes>
<d:XAddrs>%s</d:XAddrs>
<d:MetadataVersion>%d</d:MetadataVersion>
</d:Hello>
</e:Body>
</e:Envelope>`, randomUUIDURN(), appSeq, w.endpointAddress, w.scopes, xaddrList, w.metadataVersion)
	w.sendTo(w.multicastAddr, msg)
	logrus.Debugf("wsd hello: announced")
	logrus.Tracef("wsd hello detail: endpoint=%s xaddrs=%s", w.endpointAddress, xaddrList)
}

func (w *wsDiscoveryService) sendBye() {
	appSeq := w.appSequenceHeader()
	msg := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
<e:Header>
<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Bye</wsa:Action>
<wsa:MessageID>%s</wsa:MessageID>
<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
%s
</e:Header>
<e:Body>
<d:Bye><wsa:EndpointReference><wsa:Address>%s</wsa:Address></wsa:EndpointReference></d:Bye>
</e:Body>
</e:Envelope>`, randomUUIDURN(), appSeq, w.endpointAddress)
	w.sendTo(w.multicastAddr, msg)
	logrus.Debugf("wsd bye: announced")
	logrus.Tracef("wsd bye detail: endpoint=%s", w.endpointAddress)
}

func (w *wsDiscoveryService) sendProbeMatch(dst *net.UDPAddr, relatesTo string) {
	rel := ""
	if relatesTo != "" {
		rel = "<wsa:RelatesTo>" + relatesTo + "</wsa:RelatesTo>"
	}
	xaddrList := w.xaddrListFor(dst)
	appSeq := w.appSequenceHeader()
	msg := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof"
 xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07">
<e:Header>
<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>
<wsa:MessageID>%s</wsa:MessageID>
%s
<wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>
%s
</e:Header>
<e:Body>
<d:ProbeMatches>
<d:ProbeMatch>
<wsa:EndpointReference><wsa:Address>%s</wsa:Address></wsa:EndpointReference>
<d:Types>wsdp:Device pub:Computer</d:Types>
<d:Scopes>%s</d:Scopes>
<d:XAddrs>%s</d:XAddrs>
<d:MetadataVersion>%d</d:MetadataVersion>
</d:ProbeMatch>
</d:ProbeMatches>
</e:Body>
</e:Envelope>`, randomUUIDURN(), rel, appSeq, w.endpointAddress, w.scopes, xaddrList, w.metadataVersion)
	w.sendTo(dst, msg)
	logrus.Debugf("wsd probe match: to=%s", dst.String())
	logrus.Tracef("wsd probe match detail: to=%s relates_to=%s xaddrs=%s", dst.String(), relatesTo, xaddrList)
}

func (w *wsDiscoveryService) sendResolveMatch(dst *net.UDPAddr, relatesTo string) {
	rel := ""
	if relatesTo != "" {
		rel = "<wsa:RelatesTo>" + relatesTo + "</wsa:RelatesTo>"
	}
	xaddrList := w.xaddrListFor(dst)
	appSeq := w.appSequenceHeader()
	msg := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof"
 xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07">
<e:Header>
<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ResolveMatches</wsa:Action>
<wsa:MessageID>%s</wsa:MessageID>
%s
<wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>
%s
</e:Header>
<e:Body>
<d:ResolveMatches>
<d:ResolveMatch>
<wsa:EndpointReference><wsa:Address>%s</wsa:Address></wsa:EndpointReference>
<d:Types>wsdp:Device pub:Computer</d:Types>
<d:Scopes>%s</d:Scopes>
<d:XAddrs>%s</d:XAddrs>
<d:MetadataVersion>%d</d:MetadataVersion>
</d:ResolveMatch>
</d:ResolveMatches>
</e:Body>
</e:Envelope>`, randomUUIDURN(), rel, appSeq, w.endpointAddress, w.scopes, xaddrList, w.metadataVersion)
	w.sendTo(dst, msg)
	logrus.Debugf("wsd resolve match: to=%s", dst.String())
	logrus.Tracef("wsd resolve match detail: to=%s relates_to=%s endpoint=%s xaddrs=%s", dst.String(), relatesTo, w.endpointAddress, xaddrList)
}

func (w *wsDiscoveryService) xaddrListFor(dst *net.UDPAddr) string {
	if len(w.xaddrs) == 0 {
		return w.xaddr
	}
	if dst == nil || dst.IP == nil {
		return strings.Join(w.xaddrs, " ")
	}
	client4 := dst.IP.To4()
	if client4 == nil {
		return strings.Join(w.xaddrs, " ")
	}
	prefix := fmt.Sprintf("http://%d.%d.%d.", client4[0], client4[1], client4[2])
	for _, xa := range w.xaddrs {
		if strings.HasPrefix(xa, prefix) {
			return xa
		}
	}
	return strings.Join(w.xaddrs, " ")
}

func (w *wsDiscoveryService) metadataXML(relatesTo string) string {
	rel := ""
	if relatesTo != "" {
		rel = "<wsa:RelatesTo>" + relatesTo + "</wsa:RelatesTo>"
	}
	computerID := fmt.Sprintf("%s/Workgroup:%s", strings.ToUpper(w.friendlyName), strings.ToUpper(w.workgroup))
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:wsx="http://schemas.xmlsoap.org/ws/2004/09/mex"
 xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof"
 xmlns:pnpx="http://schemas.microsoft.com/windows/pnpx/2005/10"
 xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07">
<soap:Header>
<wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse</wsa:Action>
<wsa:MessageID>%s</wsa:MessageID>
%s
<wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>
</soap:Header>
<soap:Body>
<wsx:Metadata>
<wsx:MetadataSection Dialect="http://schemas.xmlsoap.org/ws/2006/02/devprof/ThisDevice">
<wsdp:ThisDevice>
<wsdp:FriendlyName>%s</wsdp:FriendlyName>
<wsdp:FirmwareVersion>1.0</wsdp:FirmwareVersion>
<wsdp:SerialNumber>%s</wsdp:SerialNumber>
</wsdp:ThisDevice>
</wsx:MetadataSection>
<wsx:MetadataSection Dialect="http://schemas.xmlsoap.org/ws/2006/02/devprof/ThisModel">
<wsdp:ThisModel>
<wsdp:Manufacturer>%s</wsdp:Manufacturer>
<wsdp:ModelName>sambam SMB Server</wsdp:ModelName>
<wsdp:ModelNumber>%s</wsdp:ModelNumber>
<pnpx:DeviceCategory>Computers</pnpx:DeviceCategory>
</wsdp:ThisModel>
</wsx:MetadataSection>
<wsx:MetadataSection Dialect="http://schemas.xmlsoap.org/ws/2006/02/devprof/Relationship">
<wsdp:Relationship Type="http://schemas.xmlsoap.org/ws/2006/02/devprof/host">
<wsdp:Host>
<wsa:EndpointReference><wsa:Address>%s</wsa:Address></wsa:EndpointReference>
<wsdp:Types>pub:Computer</wsdp:Types>
<wsdp:ServiceId>%s</wsdp:ServiceId>
<pub:Computer>%s</pub:Computer>
</wsdp:Host>
</wsdp:Relationship>
</wsx:MetadataSection>
</wsx:Metadata>
</soap:Body>
</soap:Envelope>`, randomUUIDURN(), rel, w.friendlyName, w.endpointAddress, w.manufacturer, version, w.endpointAddress, w.endpointAddress, computerID)
}

func (w *wsDiscoveryService) appSequenceHeader() string {
	msgNum := atomic.AddUint64(&w.messageNumber, 1)
	return fmt.Sprintf(`<d:AppSequence InstanceId="1" SequenceId="%s" MessageNumber="%d"/>`, w.sequenceID, msgNum)
}

func (w *wsDiscoveryService) startMetadataHTTP(bindIP string) error {
	mux := http.NewServeMux()
	handler := func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		bodyXML := string(body)
		action := xmlFieldValue(bodyXML, "Action")
		messageID := xmlFieldValue(bodyXML, "MessageID")
		host := r.RemoteAddr
		if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && h != "" {
			host = h
		}
		logrus.Debugf("network discovery: %s requested WSD metadata", host)
		logrus.Tracef("wsd metadata: method=%s remote=%s path=%s action=%s message_id=%s bytes=%d", r.Method, r.RemoteAddr, r.URL.Path, action, messageID, len(body))
		resp := w.metadataXML(messageID)
		rw.Header().Set("Content-Type", `application/soap+xml; charset=utf-8; action="http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse"`)
		_, _ = io.WriteString(rw, resp)
	}
	mux.HandleFunc("/sambam/wsd", handler)
	mux.HandleFunc("/", handler)
	srv := &http.Server{
		Addr:              net.JoinHostPort(bindIP, "5357"),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	w.httpServer = srv
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.Debugf("wsd metadata http stopped: %v", err)
		}
	}()
	logrus.Debugf("wsd metadata http: listening=%s", srv.Addr)
	return nil
}

func buildAuthUsers(cliUsers []string, cliPassword string, cliUsersChanged bool, cliPasswordChanged bool, cfg *Config) ([]authUser, error) {
	normalize := func(users []authUser) []authUser {
		sort.Slice(users, func(i, j int) bool {
			return strings.ToLower(users[i].Name) < strings.ToLower(users[j].Name)
		})
		return users
	}

	if cliUsersChanged || cliPasswordChanged {
		if len(cliUsers) == 0 {
			if cliPassword != "" {
				return nil, fmt.Errorf("password requires username. Use -u/--username together with -p/--password")
			}
			return nil, nil
		}
		if len(cliUsers) > 1 && cliPassword != "" {
			return nil, fmt.Errorf("-p/--password can only be used with a single -u value; use -u user:pass for multiple users")
		}

		users := make([]authUser, 0, len(cliUsers))
		for _, raw := range cliUsers {
			entry := strings.TrimSpace(raw)
			if entry == "" {
				return nil, fmt.Errorf("username cannot be empty")
			}
			name := entry
			pass := ""
			if strings.Contains(entry, ":") {
				parts := strings.SplitN(entry, ":", 2)
				name = strings.TrimSpace(parts[0])
				pass = parts[1]
				if name == "" || pass == "" {
					return nil, fmt.Errorf("invalid -u value %q: expected user:password", raw)
				}
			}
			users = append(users, authUser{Name: name, Password: pass})
		}

		if len(users) == 1 && users[0].Password == "" {
			users[0].Password = cliPassword
			if users[0].Password == "" {
				users[0].Password = generatePassword(10)
			}
		}
		for _, u := range users {
			if u.Password == "" {
				return nil, fmt.Errorf("missing password for user %q; use -u user:password", u.Name)
			}
		}
		return normalize(users), nil
	}

	if cfg != nil {
		byName := map[string]authUser{}
		users := make([]authUser, 0, len(cfg.Users))
		for _, u := range cfg.Users {
			name := strings.TrimSpace(u.Name)
			if name == "" {
				return nil, fmt.Errorf("config users entry has empty name")
			}
			if u.Password == "" {
				return nil, fmt.Errorf("config user %q is missing password", name)
			}
			key := strings.ToLower(name)
			byName[key] = authUser{Name: name, Password: u.Password, Readonly: u.Readonly}
		}
		for _, u := range byName {
			users = append(users, u)
		}
		if len(users) > 0 {
			return normalize(users), nil
		}
	}
	return nil, nil
}

func authUsersToConfig(users []authUser) []UserConfig {
	out := make([]UserConfig, 0, len(users))
	for _, u := range users {
		out = append(out, UserConfig{Name: u.Name, Password: u.Password, Readonly: u.Readonly})
	}
	return out
}

func authDisplay(users []authUser) string {
	if len(users) == 0 {
		return Dim("anonymous")
	}
	if len(users) == 1 {
		return Yellow(users[0].Name) + Dim(":") + Yellow(users[0].Password)
	}
	ro := 0
	for _, u := range users {
		if u.Readonly {
			ro++
		}
	}
	if ro > 0 {
		return Yellow(fmt.Sprintf("%d users (%d read-only)", len(users), ro))
	}
	return Yellow(fmt.Sprintf("%d users", len(users)))
}

func mountAuthOpt(users []authUser) string {
	if len(users) == 0 {
		return "guest"
	}
	if len(users) == 1 {
		return "username=" + users[0].Name + ",password=" + users[0].Password
	}
	return "username=<user>,password=<pass>"
}

func resolveListenHost(host string) (resolvedHost string, iface string, err error) {
	if !strings.HasPrefix(host, "@") {
		return host, "", nil
	}

	iface = strings.TrimPrefix(host, "@")
	if iface == "" {
		return "", "", fmt.Errorf("expected @<interface>")
	}

	netIf, err := net.InterfaceByName(iface)
	if err != nil {
		return "", "", fmt.Errorf("interface %q not found", iface)
	}
	addrs, err := netIf.Addrs()
	if err != nil {
		return "", "", fmt.Errorf("failed to read addresses for interface %q: %w", iface, err)
	}

	// Prefer non-loopback IPv4 for predictable endpoint display.
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), iface, nil
		}
	}

	// Fallback: first non-loopback IPv6.
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.To16() == nil || ip.To4() != nil {
			continue
		}
		return ip.String(), iface, nil
	}

	return "", "", fmt.Errorf("interface %q has no usable IP address", iface)
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
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
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
			os.Remove(daemonStatusFilePath(pidFilePath))
			return
		}
	}

	fmt.Fprintln(os.Stderr, "Warning: Daemon may not have stopped cleanly")
}

func daemonStatusFilePath(pidFile string) string {
	return pidFile + ".status"
}

func writeDaemonStatus(path string, status daemonStatus) error {
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readDaemonStatus(path string) (*daemonStatus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st daemonStatus
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func parseSubcommandPIDFile(defaultPath string, args []string) string {
	pidFilePath := defaultPath
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-P" || a == "--pidfile":
			if i+1 < len(args) {
				pidFilePath = args[i+1]
			}
		case strings.HasPrefix(a, "--pidfile="):
			pidFilePath = strings.TrimPrefix(a, "--pidfile=")
		}
	}
	return pidFilePath
}

func isProcessRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

func renderStatusBlock(st *daemonStatus) {
	fmt.Println()
	if len(st.Shares) == 1 {
		fmt.Printf("  %-12s %s\n", "Sharing", Green(st.Shares[0].Path))
		fmt.Printf("  %-12s %s\n", "Share", Yellow(st.Shares[0].Name))
	} else {
		maxLen := 0
		for _, share := range st.Shares {
			if len(share.Name) > maxLen {
				maxLen = len(share.Name)
			}
		}
		if maxLen < 11 {
			maxLen = 11
		}
		fmt.Printf("  %s\n", "Shares:")
		for _, share := range st.Shares {
			padding := strings.Repeat(" ", maxLen-len(share.Name))
			fmt.Printf("    %s%s %s %s\n", Yellow(share.Name), padding, Dim("→"), Green(share.Path))
		}
	}

	listenColored := Yellow(st.Listen)
	listenHost, _ := parseHostPort(st.Listen)
	if listenHost == "" || listenHost == "0.0.0.0" || listenHost == "::" {
		listenColored = Dim(st.Listen)
	}
	fmt.Printf("  %-12s %s\n", "Listen", listenColored)

	modeStr := Red("read-write")
	roCount := 0
	for _, s := range st.Shares {
		if s.ReadOnly {
			roCount++
		}
	}
	if roCount == len(st.Shares) {
		modeStr = Green("read-only")
	} else if roCount > 0 {
		modeStr = Yellow("mixed")
	}
	fmt.Printf("  %-12s %s\n", "Mode", modeStr)
	fmt.Printf("  %-12s %s\n", "Auth", st.Auth)

	allowTextColored := Dim("all")
	if len(st.AllowAddrs) > 0 {
		allowTextColored = Yellow(strings.Join(st.AllowAddrs, ", "))
	}
	fmt.Printf("  %-12s %s\n", "Allowlist", allowTextColored)
	fmt.Println()
	fmt.Printf("  %-12s %s\n", "Status", Green("daemon started"))
	fmt.Printf("  %-12s %d\n", "PID", st.PID)
	fmt.Printf("  %-12s %s\n", "PID file", st.PIDFile)
	fmt.Printf("  %-12s %s\n", "Log file", formatLogFileDisplay(st.LogFile))
	if st.ExpiresAt != "" {
		if expiry, err := time.Parse(time.RFC3339, st.ExpiresAt); err == nil {
			remaining := time.Until(expiry)
			if remaining > 0 {
				fmt.Printf("  %-12s %s\n", "Expires in", Yellow(formatDuration(remaining)))
			} else {
				fmt.Printf("  %-12s %s\n", "Expires in", Red("expired"))
			}
		}
	}
}

func statusDaemon() {
	pidFilePath := parseSubcommandPIDFile("/tmp/sambam.pid", os.Args[2:])
	statusPath := daemonStatusFilePath(pidFilePath)

	data, err := os.ReadFile(pidFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "No daemon running (PID file not found: %s)\n", pidFilePath)
		} else {
			fmt.Fprintf(os.Stderr, "Error reading PID file: %v\n", err)
		}
		os.Exit(1)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid PID in file: %v\n", err)
		os.Exit(1)
	}

	if !isProcessRunning(pid) {
		_ = os.Remove(pidFilePath)
		_ = os.Remove(statusPath)
		fmt.Fprintf(os.Stderr, "No daemon running (stale PID %d in %s)\n", pid, pidFilePath)
		os.Exit(1)
	}

	st, err := readDaemonStatus(statusPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Daemon is running (PID %d), but status file is missing: %s\n", pid, statusPath)
		} else {
			fmt.Fprintf(os.Stderr, "Daemon is running (PID %d), but status file is unreadable: %v\n", pid, err)
		}
		os.Exit(1)
	}

	// Trust live PID from pidfile even if status snapshot is stale.
	st.PID = pid
	if st.PIDFile == "" {
		st.PIDFile = pidFilePath
	}
	if st.LogFile == "" {
		st.LogFile = "/dev/null"
	}
	renderStatusBlock(st)
}
