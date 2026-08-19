# bash completion for bandrop
_bandrop() {
    local cur prev cmds
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmds="send receive pipe serve verify id discover version"
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$cmds --version --help" -- "$cur") )
        return
    fi
    case "${COMP_WORDS[1]}" in
        send)    COMPREPLY=( $(compgen -W "--to --port --compress" -- "$cur") ; compgen -f -- "$cur" >/dev/null && COMPREPLY+=( $(compgen -f -- "$cur") ) ;;
        receive) COMPREPLY=( $(compgen -W "--port --out --receipt --overwrite --no-announce" -- "$cur") ;;
        pipe)    COMPREPLY=( $(compgen -W "--listen --to --code --port --no-announce" -- "$cur") ;;
        serve)   COMPREPLY=( $(compgen -W "--port --once" -- "$cur") ; COMPREPLY+=( $(compgen -f -- "$cur") ) ;;
        verify)  COMPREPLY=( $(compgen -f -- "$cur") ) ;;
    esac
}
complete -F _bandrop bandrop
