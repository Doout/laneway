Register-ArgumentCompleter -Native -CommandName laneway, lane -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $previous = @($commandAst.CommandElements |
        Where-Object { $_.Extent.EndOffset -le ($cursorPosition - $wordToComplete.Length) } |
        Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text })
    & laneway __completeNoDesc @previous $wordToComplete 2>$null | ForEach-Object {
        if ($_ -eq ':0') {
            (Get-ChildItem -Path "$wordToComplete*" -Name -ErrorAction SilentlyContinue) |
                ForEach-Object { [System.Management.Automation.CompletionResult]::new($_) }
        } elseif ($_ -notlike ':*') {
            [System.Management.Automation.CompletionResult]::new($_)
        }
    }
}
