#!/usr/bin/env bash

_sambam_complete()
{
    local cur prev cword
    cword=$COMP_CWORD
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local global_flags="--name --listen --allow --readonly --daemon --pidfile --logfile --config --verbose --hide-dotfiles --username --password --expire --gen-config --version --help"
    local stop_flags="--pidfile --help"
    local cmds="stop"
    local _path_candidates

    _sambam_complete_path() {
        COMPREPLY=( $(compgen -f -- "$cur") )
        local i candidate
        for i in "${!COMPREPLY[@]}"; do
            candidate="${COMPREPLY[$i]}"
            if [[ -d "$candidate" && "$candidate" != */ ]]; then
                COMPREPLY[$i]="${candidate}/"
            fi
        done
        compopt -o filenames 2>/dev/null || true
        return 0
    }

    _sambam_complete_dir() {
        COMPREPLY=( $(compgen -d -- "$cur") )
        local i candidate
        for i in "${!COMPREPLY[@]}"; do
            candidate="${COMPREPLY[$i]}"
            if [[ -d "$candidate" && "$candidate" != */ ]]; then
                COMPREPLY[$i]="${candidate}/"
            fi
        done
        compopt -o dirnames -o nospace 2>/dev/null || true
        return 0
    }

    # Value-taking flags in main mode.
    case "$prev" in
        -P|--pidfile|-L|--logfile|-c|--config|-G|--gen-config)
            _sambam_complete_path
            return 0
            ;;
        -l|--listen|-a|--allow|-u|--username|-p|--password|-e|--expire)
            return 0
            ;;
        -n|--name)
            return 0
            ;;
    esac

    # Subcommand-aware completion for "sambam stop ...".
    if [[ ${#COMP_WORDS[@]} -ge 2 && ${COMP_WORDS[1]} == "stop" ]]; then
        case "$prev" in
            -P|--pidfile)
                _sambam_complete_path
                return 0
                ;;
        esac
        COMPREPLY=( $(compgen -W "$stop_flags" -- "$cur") )
        return 0
    fi

    # First argument: either subcommand or global flags/positional path.
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$cmds $global_flags" -- "$cur") )
        _path_candidates=( $(compgen -d -- "$cur") )
        COMPREPLY+=( "${_path_candidates[@]}" )
        local i candidate
        for i in "${!COMPREPLY[@]}"; do
            candidate="${COMPREPLY[$i]}"
            if [[ -d "$candidate" && "$candidate" != */ ]]; then
                COMPREPLY[$i]="${candidate}/"
            fi
        done
        compopt -o dirnames -o nospace 2>/dev/null || true
        return 0
    fi

    # Default main-mode completion: flags + directory paths.
    COMPREPLY=( $(compgen -W "$global_flags" -- "$cur") )
    _path_candidates=( $(compgen -d -- "$cur") )
    COMPREPLY+=( "${_path_candidates[@]}" )
    local i candidate
    for i in "${!COMPREPLY[@]}"; do
        candidate="${COMPREPLY[$i]}"
        if [[ -d "$candidate" && "$candidate" != */ ]]; then
            COMPREPLY[$i]="${candidate}/"
        fi
    done
    compopt -o dirnames -o nospace 2>/dev/null || true
}

complete -F _sambam_complete sambam
