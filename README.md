# sambam

**The fastest way to share files with Windows, macOS and Linux.** No setup. No passwords. No patience required.

> **Built with AI assistance** — Idea and design by a human, code by an AI. Fully open source and auditable.

You know the drill: Your colleague needs a file. They're on Windows. You're on Linux. You could email it (if it's under 25MB). You could upload it to some cloud service (and wait). You could set up Samba (LOL, see you next week). Or...

```bash
sudo sambam /path/to/folder
```

Done. They open `\\your-ip\share` in Explorer. Files are flowing. You're a hero.
**sambam** is like `python -m http.server` but for Windows network shares. One command, instant SMB file sharing.

![Demo](demo.gif)

## Why sambam?

| The Old Way | The sambam Way |
|-------------|----------------|
| Install Samba | `sudo sambam .` |
| Edit smb.conf | That's it. |
| Configure users | Seriously. |
| Restart services | You're done. |
| Debug permissions | Go grab coffee. |
| Google error messages | |
| Cry softly | |

## Features

- **Zero configuration** - No config files, no setup wizards, no existential dread
- **Anonymous access** - No passwords by default (or add authentication if needed)
- **Optional authentication** - Require username/password when you need it
- **Multiple shares** - Share multiple directories with different names
- **Auto-expire** - Automatically stop sharing after a set time
- **Config file** - Layered config from `/etc/sambamrc`, `~/.sambamrc`, and `./.sambamrc`
- **Cross-platform clients** - Works with Windows 10/11, macOS, and Linux (CIFS mount)
- **SMB 2.1 / 3.0 / 3.1.1** - Compatible with modern SMB protocol versions, including POSIX extensions
- **Single binary** - Runs on any Linux distribution (Debian, Ubuntu, OpenWrt, etc.)
- **Daemon mode** - Run in background, stop when done
- **Shell completions** - Bash and Fish completion scripts included

## Installation

Download artifacts from the [Releases](https://github.com/darkpenguin23/sambam/releases) page.

Native packages are available for:
- Debian/Ubuntu (`.deb`)
- Fedora/RHEL/openSUSE (`.rpm`)
- Arch Linux (`.pkg.tar.zst`)
- Alpine (`.apk`)

You can install the matching package for your distro, or use the standalone binary:

```bash
chmod +x sambam-linux-amd64
sudo mv sambam-linux-amd64 /usr/local/bin/sambam
```

Or build from source:

```bash
go build -o sambam .
```

## Quick Start

```bash
# Share current directory (anonymous access, read-write)
sudo sambam

# Share a specific folder
sudo sambam /path/to/folder

# Share read-only with a custom name
sudo sambam -r -n photos ~/Pictures
```

## Options

### `-n, --name <name>` or `-n <name:path>`

Set the share name. By default the share name is the directory name. Use `name:path` syntax to specify both name and path. Repeatable for multiple shares.

```bash
sudo sambam -n myfiles /data
sudo sambam -n docs:/home/user/documents -n pics:/home/user/photos
```

### `-l, --listen <address>`

Address and port to listen on. Default: `0.0.0.0:445`. Use a non-standard port if 445 is already in use.

```bash
sudo sambam -l 0.0.0.0:8445 /data
```

### `-r, --readonly`

Share in read-only mode. Clients can browse and copy files but cannot modify, delete, or upload.

### `-u, --username <name>`

Require authentication. Clients must provide this username to access the share. When set, anonymous access is disabled. If `-p, --password` is not specified, a random password is generated and displayed in the banner.

```bash
sudo sambam --username admin /data
sudo sambam --username admin --password secret123 /data
```

### `-p, --password <password>`

Set a specific password for authentication. Only used together with `-u, --username`. If omitted, a random 10-character password is generated.

### `-e, --expire <duration>`

Automatically stop sharing after the given duration. Accepts Go duration format: `30m`, `1h`, `2h30m`, etc.

```bash
sudo sambam --expire 30m /data
```

### `-v, --verbose`

Show real-time connection and file activity.

Use verbosity levels:
- `-v` basic activity
- `-vv` extended diagnostics (open mode, read events, close summaries, slow ops, auth failures)
- `-vvv` full protocol trace (includes `-v` and `-vv`)

```
  15:04:05 connect 192.168.1.100:54321
  15:04:10 [share] create file documents/report.docx
  15:04:12 [share] create dir  backup
  15:04:15 [share] delete temp/old-file.txt
```

### `-H, --hide-dotfiles`

Hide files starting with `.` from directory listings. By default dotfiles are visible.

### `-d, --daemon`

Run sambam as a background daemon. Use `sambam stop` to stop it.

```bash
sudo sambam -d /data
sudo sambam stop
```

### `-P, --pidfile <path>`

PID file location for daemon mode. Default: `/tmp/sambam.pid`.

### `-L, --logfile [path]`

Log file path. In daemon mode, logs go to this file (otherwise daemon output goes to `/dev/null`). In foreground mode, logs are written to both terminal and this file.
If used without a value, defaults to `/tmp/sambam.log`.

### `-c, --config <path>`

Load an additional config file. Repeatable.

Custom config files are applied after `/etc/sambamrc`, `~/.sambamrc`, and `./.sambamrc`, in the order they are passed. CLI flags still have highest priority.

```bash
sambam -c /etc/sambam-prod.toml -c ./sambam.override.toml
```

```bash
sudo sambam -d -L /var/log/sambam.log /data
sudo sambam -L /tmp/sambam.log /data
```

### `-G, --gen-config [path]`

Generate a TOML config from the currently passed CLI flags and exit without starting the server.

- If no path is given, writes `./.sambamrc`
- If a path is given, writes to that file

```bash
sambam -r -u admin -p secret -G
sambam -l 10.23.22.13:445 -e 1h -G /tmp/sambamrc.toml
```

### `-V, --version`

Show version and exit.

### `-h, --help`

Show help and exit.

## Configuration File

sambam reads configuration in this order:

1. Base config: `/etc/sambamrc` (if present)
2. User overrides: `~/.sambamrc` (if present)
3. Local overrides: `./.sambamrc` (if present)
4. Extra overrides: each `-c, --config <path>` in the order passed (required to exist)

Local config overrides only the keys explicitly set in `./.sambamrc`.
For `[shares]`, entries are merged by share name (later layers override same-name entries from earlier layers).

Finally, CLI flags override config values.

Example `/etc/sambamrc` + `~/.sambamrc` + `./.sambamrc` layering:

```toml
# /etc/sambamrc
listen = "10.23.22.12:445"
readonly = false
```

```toml
# ~/.sambamrc
listen = "10.23.22.13:445"
```

```toml
# ./.sambamrc
readonly = true
```

Result: `listen` comes from user config, `readonly` comes from local config.

Example configuration file (TOML):

```toml
# Listen address
listen = "0.0.0.0:445"

# Read-only mode
readonly = false

# Show connections and file activity
verbose = true
# verbose_level = 2   # equivalent to -vv

# verbose_level = 3   # equivalent to -vvv

# Hide files starting with '.'
# hide_dotfiles = true

# Authentication
# username = "admin"
# password = "secret123"

# Auto-expire
# expire = "1h"

# Daemon mode settings
# pidfile = "/tmp/sambam.pid"
# logfile = "/var/log/sambam.log"

# Multiple shares
[shares]
docs = "/home/user/documents"
pics = "/home/user/photos"
```

See `sambamrc.example` for a full example.

### Troubleshooting config selection

Run with verbosity to see exactly which config files were loaded:

```bash
sambam -v
```

You will see a line like:

```text
config: system=true (/etc/sambamrc), home=true (/root/.sambamrc), local=true (.sambamrc), custom=0
```

## Connecting from Windows

Once sambam is running, it shows you the exact path to use:

```
  sambam v1.2.6

  Sharing      /home/user/documents
  Share        share
  Listen       0.0.0.0:445
  Mode         read-write
  Auth         anonymous

  Connect from Windows:
    \\192.168.1.100\share

  Built with AI assistance

  Press Ctrl+C to stop
```

From Windows:
1. Open **File Explorer**
2. Type the path in the address bar: `\\192.168.1.100\share`
3. Press Enter
4. If authentication is required, enter the username and password

Or mount as a drive:
```cmd
net use Z: \\192.168.1.100\share /user:admin
```

## Connecting from Linux

Mount using CIFS with SMB 3.0:

```bash
# Anonymous access
sudo mount -t cifs //server-ip/share /mnt/share -o guest,vers=3.0

# With authentication
sudo mount -t cifs //server-ip/share /mnt/share -o username=admin,password=secret123,vers=3.0
```

### POSIX extensions (real Unix permissions)

sambam supports SMB2 POSIX extensions, which let Linux clients see real Unix permissions, owners, and use `chmod`/`chown`. This requires SMB 3.1.1:

```bash
# POSIX mount with chmod/chown support
sudo mount -t cifs //server-ip/share /mnt/share -o guest,vers=3.1.1,posix,cifsacl
```

With POSIX extensions, `ls -la` shows actual file owners and permissions from the server instead of defaults. The `cifsacl` option is required on kernel 6.1 for `chmod` to work; newer kernels (6.5+) may not need it.

## Windows Credential Troubleshooting

Windows caches SMB credentials. If you're having authentication issues:

```cmd
# List active connections
net use

# Disconnect a specific share
net use \\192.168.1.100\share /delete

# Or disconnect all shares
net use * /delete
```

After clearing cached connections, reconnect and Windows will prompt for new credentials.

## Non-standard ports

Port 445 requires root. You can use a non-standard port instead:

```bash
sambam -l :8888 /data
```

**Linux clients** support non-standard ports natively:

```bash
sudo mount -t cifs //server-ip/share /mnt -o guest,port=8888
```

**Windows and macOS** only connect to port 445. To use a non-standard port, create an SSH tunnel:

```bash
# Forward local port 445 to the sambam server
ssh -L 445:server-ip:8888 user@server-ip
```

Then connect to `\\localhost\share` (Windows) or `smb://localhost/share` (macOS).

On Windows, port 445 is usually already in use by the built-in SMB service. A workaround is to run the tunnel inside WSL and bind to the WSL network interface:

```bash
# Inside WSL — find WSL's IP with: ip addr show eth0
ssh -L 172.x.x.x:445:server-ip:8888 user@server-ip
```

Then connect from Windows using `\\172.x.x.x\share` (the WSL IP).

## Requirements

- **Root privileges** - Port 445 requires root (or use `-l :8888` for a non-standard port)
- **Linux server** - Works on any distribution (Debian, Ubuntu, OpenWrt, Alpine, etc.)
- **Clients** - Windows 10/11, macOS, or Linux (via CIFS mount)

## Known Issues

These notes apply to the **sambam server** (the application serving files), not to client applications (Windows Explorer, macOS Finder, Linux mount tools, etc.).

### Platform-Specific Notes

**Linux** - Fully stable. All features working including POSIX extensions, file permissions, and advanced operations.

**macOS (Apple Silicon)** - Excellent support. Thoroughly tested and works as reliably as Linux. All features including POSIX extensions fully functional. No known issues.

**Windows** - Experimental server build
- No POSIX extensions support (limitations on Unix-style permissions)
- File deletion issues: Files cannot be deleted while the server is running (Windows file locking behavior)
- Other features work correctly

## Security Notice

By default, sambam uses anonymous/guest authentication. This means:

- **No passwords** - Anyone on your network can access the share
- **Use on trusted networks only** - Don't run this on public WiFi
- **Not for production** - This is for quick file transfers, not Fort Knox

For sensitive shares, use `--username` to require authentication, and `-r` for read-only mode.

## License

AGPL-3.0

---
*Made for those moments when you just need to share a damn file.*
