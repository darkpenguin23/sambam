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
- **Tiered auth model** - Single-user CLI, multi-user CLI shorthand, or `[[users]]` config
- **Multiple shares** - Share multiple directories with different names
- **Per-share access control** - `allow_users` and share-level `readonly` in config
- **Auto-expire** - Automatically stop sharing after a set time
- **Config file** - Layered defaults, or explicit `-c` config-only mode
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

Address and port to listen on. Default: `0.0.0.0:445`.  
You can also bind by interface with `@<name>` (optionally with port), for example `@eth0` or `@eth0:445`.
Repeat the flag to bind multiple endpoints.

```bash
sudo sambam -l 0.0.0.0:8445 /data
sudo sambam -l @eth0:445 /data
sudo sambam -l @eth0 -l 10.23.22.13:445 /data
```

### `-a, --allow <ip-or-cidr>`

Allowlist client source addresses. Repeatable.

Accepted values:
- Single IP (`192.168.1.10`)
- CIDR network (`192.168.1.0/24`)

If one or more `--allow` rules are set, only matching clients can connect.

```bash
sambam -a 192.168.1.10 -a 192.168.2.0/24 /data
```

### `-r, --readonly`

Share in read-only mode. Clients can browse and copy files but cannot modify, delete, or upload.

### `-u, --username <user|user:password>`

Require authentication. Repeatable.

- Single-user quick mode: `-u admin -p secret` (or omit `-p` for random password)
- Multi-user CLI mode: `-u alice:secret1 -u bob:secret2`

```bash
sudo sambam -u admin /data
sudo sambam -u admin -p secret123 /data
sudo sambam -u alice:secret1 -u bob:secret2 /data
```

### `-p, --password <password>`

Set a password for single-user CLI mode (`-u <user>`).  
For multi-user CLI mode, use `-u <user:password>` for each user.

### Authentication Tiers

Tier 1 — quick share:

```bash
sambam /data
sambam -u alice -p secret /data
```

Tier 2 — multiple users (same access for all):

```bash
sambam -u alice:secret1 -u bob:secret2 /data
```

Tier 3 — per-share permissions (config):

```toml
[[users]]
name = "alice"
password = "secret1"

[[users]]
name = "bob"
password = "secret2"
readonly = true

[shares.media]
path = "/mnt/media"

[shares.private]
path = "/home/user/private"
allow_users = ["alice"]

[shares.public]
path = "/srv/public"
guest = true
```

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

Load config file(s) explicitly. Repeatable.

When `-c` is used, default discovery (`/etc/sambamrc`, `~/.sambamrc`, `./.sambamrc`) is skipped.
Files passed via `-c` are applied in order, and CLI flags still have highest priority.

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

sambam has two config loading modes:

1. Default mode (no `-c`): `/etc/sambamrc` -> `~/.sambamrc` -> `./.sambamrc`
2. Explicit mode (with `-c`): only the provided `-c, --config <path>` files, in order (required to exist)

CLI flags override all config values.

### Basic Config (Recommended)

Use the old-style format unless you need per-user/per-share controls.  
It maps directly to CLI flags and is easy to generate with `-G`.

```bash
sambam -n docs:/data/docs -u admin -p secret -r -G
```

```toml
listen = "0.0.0.0:445"
readonly = true
username = "admin"
password = "secret"

[shares]
docs = "/data/docs"
```

Why recommended:
- follows CLI behavior
- easiest to read and maintain
- can be generated quickly with `-G`

### Advanced Config

Use this when you need multiple users, per-user readonly, or per-share access rules.

```toml
[[users]]
name = "alice"
password = "secret1"

[[users]]
name = "bob"
password = "secret2"
readonly = true

[shares.media]
path = "/mnt/media"
guest = true

[shares.private]
path = "/home/user/private"
readonly = true
allow_users = ["alice"]
```

Notes:
- `guest = true` allows anonymous/guest access for that share.
- `allow_users` restricts a share to specific users.
- advanced share entries use `[shares.<name>]`.

### Mixing Basic + Advanced

Mixing works, but is not recommended unless you know why you need it.

Mix rules:
- legacy share entries from `[shares]` can be overlaid by `[shares.<name>]` in later config files
- legacy share without explicit advanced rule uses legacy auth mapping
- with legacy `username/password`, it is treated as `allow_users=["<legacy-user>"]`
- without legacy `username/password`, it is treated as guest-accessible

Use `-vv` to see effective settings and merge decisions in logs.

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
