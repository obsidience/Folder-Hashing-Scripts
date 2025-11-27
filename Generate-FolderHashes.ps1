. "$PSScriptRoot\Folder-Hashing-Utilities.ps1" | Out-Null

# Load .env if present, otherwise fall back to .env.test and set WhatIf and Verbose
$IsTesting = $false
$envFile = Join-Path $PSScriptRoot '.env'
if (-not (Test-Path $envFile)) {
    $IsTesting = $true
    $envFile = Join-Path $PSScriptRoot '.env.test'
}

Get-Content $envFile -Raw |
    ForEach-Object { $_ -split "\r?\n" } |
    Where-Object { $_ -and $_ -notmatch '^\s*#' } |
    ForEach-Object { 
        $parts = $_ -split '=', 2
        if ($parts.Count -ge 2) { Set-Item -Path "Env:$($parts[0].Trim())" -Value $parts[1].Trim(" '`"") } 
    }

# Build base path(s) array (CSV) or default to current working directory
$BasePaths = $env:BASE_FOLDER_PATHS -split ',' | ForEach-Object { $_.Trim() }

# Build exclusions array (CSV) or default to .git and .vscode patterns
$ExclusionCriteria = $env:EXCLUSION_CRITERIA -split ',' | ForEach-Object { $_.Trim() }

# Run MaintainFolderHashes once per configured base path
foreach ($bp in $BasePaths) { 
    if ($bp) { 
        GenerateFolderHashes -BaseFolderPaths:$bp -ExclusionCriteria:$ExclusionCriteria -Sort -WhatIf:$IsTesting -Verbose:$IsTesting
    } 
}
