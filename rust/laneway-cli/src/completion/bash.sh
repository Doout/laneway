# Bash completion for laneway.
_laneway_complete() {
    (( COMP_CWORD > 0 )) || return
    local suggestion
    local current="${COMP_WORDS[COMP_CWORD]:-}"
    local -a words
    words=("${COMP_WORDS[@]:1:COMP_CWORD-1}")
    COMPREPLY=()
    while IFS= read -r suggestion; do
        case "$suggestion" in
            :0)
                while IFS= read -r suggestion; do
                    COMPREPLY+=("$suggestion")
                done < <(compgen -f -- "$current")
                ;;
            :*) ;;
            *) COMPREPLY+=("$suggestion") ;;
        esac
    done < <("${COMP_WORDS[0]}" __completeNoDesc "${words[@]}" "$current" 2>/dev/null)
}
complete -F _laneway_complete laneway lane
