#compdef laneway lane
_laneway() {
    local output
    local -a suggestions
    output="$("${words[1]}" __completeNoDesc "${(@)words[2,CURRENT]}" 2>/dev/null)" || return
    suggestions=("${(@f)output}")
    if [[ "${suggestions[-1]}" == :0 ]]; then
        _files
        return
    fi
    suggestions[-1]=()
    compadd -- "${suggestions[@]}"
}
compdef _laneway laneway lane
