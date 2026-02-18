# sambam fish completion

# Helper: true when no subcommand has been entered yet.
function __fish_sambam_no_subcommand
    not __fish_seen_subcommand_from stop status
end

# Subcommand (first positional argument)
complete -c sambam -n "__fish_use_subcommand" -a stop -d "Stop running daemon"
complete -c sambam -n "__fish_use_subcommand" -a status -d "Show daemon status"

# Main-mode flags
complete -c sambam -n "__fish_sambam_no_subcommand" -s n -l name -r -d "Share name or name:path (repeatable)"
complete -c sambam -n "__fish_sambam_no_subcommand" -s l -l listen -r -d "Address or @interface to listen on (repeatable)"
complete -c sambam -n "__fish_sambam_no_subcommand" -s a -l allow -r -d "Allow client IP/CIDR (repeatable)"
complete -c sambam -n "__fish_sambam_no_subcommand" -l advertise -d "Advertise shares via mDNS + WS-Discovery (default on)"
complete -c sambam -n "__fish_sambam_no_subcommand" -l no-advertise -d "Disable share advertisement"
complete -c sambam -n "__fish_sambam_no_subcommand" -s r -l readonly -d "Make share read-only"
complete -c sambam -n "__fish_sambam_no_subcommand" -s d -l daemon -d "Run as background daemon"
complete -c sambam -n "__fish_sambam_no_subcommand" -s P -l pidfile -r -d "PID file location"
complete -c sambam -n "__fish_sambam_no_subcommand" -s L -l logfile -r -d "Log file path"
complete -c sambam -n "__fish_sambam_no_subcommand" -s c -l config -r -d "Additional config file"
complete -c sambam -n "__fish_sambam_no_subcommand" -s v -l verbose -d "Show connections and file activity"
complete -c sambam -n "__fish_sambam_no_subcommand" -s H -l hide-dotfiles -d "Hide files starting with '.'"
complete -c sambam -n "__fish_sambam_no_subcommand" -s u -l username -r -d "Require authentication (user or user:password, repeatable)"
complete -c sambam -n "__fish_sambam_no_subcommand" -s p -l password -r -d "Password for authentication"
complete -c sambam -n "__fish_sambam_no_subcommand" -s e -l expire -r -d "Auto-shutdown after duration"
complete -c sambam -n "__fish_sambam_no_subcommand" -s G -l gen-config -r -d "Generate config TOML and exit"
complete -c sambam -n "__fish_sambam_no_subcommand" -s V -l version -d "Show version"
complete -c sambam -n "__fish_sambam_no_subcommand" -s h -l help -d "Show help"

# Positional directory argument in main mode
complete -c sambam -n "__fish_sambam_no_subcommand" -f -a "(__fish_complete_directories)" -d "Directory to share"

# stop subcommand flags
complete -c sambam -n "__fish_seen_subcommand_from stop" -s P -l pidfile -r -d "PID file location"
complete -c sambam -n "__fish_seen_subcommand_from stop" -s h -l help -d "Show help"

# status subcommand flags
complete -c sambam -n "__fish_seen_subcommand_from status" -s P -l pidfile -r -d "PID file location"
complete -c sambam -n "__fish_seen_subcommand_from status" -s h -l help -d "Show help"
