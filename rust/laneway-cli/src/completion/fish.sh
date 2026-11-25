function __laneway_complete
    set -l argv (commandline -opc)
    set -l token (commandline -ct)
    for suggestion in (command laneway __completeNoDesc $argv[2..-1] "$token" 2>/dev/null)
        if test "$suggestion" = :0
            __fish_complete_path "$token"
        else if not string match -q ':*' -- "$suggestion"
            printf '%s\n' "$suggestion"
        end
    end
end
complete -c laneway -f -a '(__laneway_complete)'
complete -c lane -f -a '(__laneway_complete)'
