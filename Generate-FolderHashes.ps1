. "$PSScriptRoot\Folder-Hashing-Utilities.ps1" | Out-Null

#region Load .env if present, otherwise fall back to .env.test
$envFile = Join-Path $PSScriptRoot '.env'
if (-not (Test-Path $envFile)) {
    $envFile = Join-Path $PSScriptRoot '.env.test'
}

Get-Content $envFile -Raw |
    ForEach-Object { $_ -split "\r?\n" } |
    Where-Object { $_ -and $_ -notmatch '^\s*#' } |
    ForEach-Object { 
        $parts = $_ -split '=', 2
        if ($parts.Count -ge 2) { Set-Item -Path "Env:$($parts[0].Trim())" -Value $parts[1].Trim(" '`"") } 
    }
#endregion

$BasePaths = $env:BASE_FOLDER_PATHS -split ',' | ForEach-Object { $_.Trim() }           # Build base path(s) array (CSV) or default to current working directory
$ExclusionCriteria = $env:EXCLUSION_CRITERIA -split ',' | ForEach-Object { $_.Trim() }  # Build exclusions array (CSV) or default to .git and .vscode patterns
$EnvVerbose = $env:VERBOSE -ieq 'true'                                                  # Parse VERBOSE from .env (defaults to $false)
$EnvWhatIf = $env:WHATIF -ieq 'true'                                                    # Parse WHATIF from .env (defaults to $false)

foreach ($bp in $BasePaths) { 
    if ($bp) { 
        $params = @{
            BaseFolderPaths   = $bp
            ExclusionCriteria = $ExclusionCriteria
        }
        if ($EnvWhatIf) { $params['WhatIf'] = $true }
        if ($EnvVerbose) { $params['Verbose'] = $true }
        GenerateFolderHashes @params
    } 
}
