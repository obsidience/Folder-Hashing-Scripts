#$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot -ErrorAction Stop
$WhatIfPreference = $false
$VerbosePreference = 'SilentlyContinue'

function GenerateFolderHashes {
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		[String[]] $BaseFolderPaths,

		[DirectoryInfo[]] $FoldersToProcess,

		[Parameter(Mandatory = $false)]
		[String[]] $ExclusionCriteria,

		[Parameter(Mandatory = $false)]
		[Switch] $IncludeFoldersAlreadyHashed = $false,

		[Parameter(Mandatory = $false)]
		[Switch] $Recurse,

		[String] $FolderSortOrder = 'Alphabetical',

		[int] $Depth = 0
	)

	if ((-not $BaseFolderPaths -or $BaseFolderPaths.Count -eq 0) -and (-not $FoldersToProcess -or $FoldersToProcess.Count -eq 0)) { throw "Either -BaseFolderPaths or -FoldersToProcess must be provided." }

	if (-not $PSBoundParameters.ContainsKey('Recurse')) { $Recurse = $true }

	if ($PSBoundParameters.ContainsKey('Verbose')) { $VerbosePreference = 'Continue' } else { $VerbosePreference = 'SilentlyContinue' }
	if ($PSBoundParameters.ContainsKey('WhatIf')) { $WhatIfPreference = $true } else { $WhatIfPreference = $false }

	Write-Out -Mode:Verbose -Depth:$Depth -Message:'Verbose logging enabled.'
	$MethodCallDepth = if ($Depth -gt 0) { $Depth - 1 } else { $Depth }
	Write-Out -Mode:Host -Depth:$MethodCallDepth -Message:'GenerateFolderHashes() started...' -Prefix:$VerbosePadding
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"BaseFolderPaths: $BaseFolderPaths"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"FoldersToProcess: $($FoldersToProcess.Count) folders"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"ExclusionCriteria: $ExclusionCriteria"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"IncludeFoldersAlreadyHashed: $IncludeFoldersAlreadyHashed"
    
	if($null -eq $FoldersToProcess) {
		$FoldersToProcess = GetFoldersToProcess -BaseFolderPaths:$BaseFolderPaths -ExclusionCriteria:$ExclusionCriteria -IncludeFoldersAlreadyHashed:$IncludeFoldersAlreadyHashed -Recurse:$Recurse -SortOrder:$FolderSortOrder -Depth:($Depth + 1)
	}	

	for ($i = 0; $i -lt $FoldersToProcess.Count; $i++) {
		$Folder = $FoldersToProcess[$i]
		$Hashes = @{}
		$Files = Get-ChildItem $Folder -File| Where-Object { 
			($_.Name -ne '.hashes.md5') -and
			(if ($ExclusionCriteria -and $ExclusionCriteria.Count -gt 0) { $_.FullName -notmatch $($ExclusionCriteria -join "|")} else { $true })
		}

		Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"Processing folder `"$($Folder.FullName)`"... [$($i + 1) of $($FoldersToProcess.Count)]" -Prefix:$VerbosePadding
		for ($j = 0; $j -lt $Files.Count; $j++) {
			$File = $Files[$j]

			Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"Hashing file `"$($File.Name)`" ($(Format-FileSize -Bytes $File.Length))... [$($j + 1) of $($Files.Count)]" -Prefix:$VerbosePadding
			Write-Out -Mode:Progress -Depth:($Depth + 1) -Message:'Hashing...' -ProgressActivity:'Hashing'
			$HashValue = (Get-FileHash -LiteralPath:$File.FullName -Algorithm:MD5).Hash
			$Hashes.Add($File.Name, $HashValue)
		}

		if ($Hashes.Count -gt 0) {
			$OutFilePath = Join-Path -Path $Folder.FullName -ChildPath '.hashes.md5'
			Write-Out -Mode:Verbose -Depth:($Depth + 1) -Message:"Writing file `"$($OutFilePath)`"..."
			if ($PSCmdlet.ShouldProcess($OutFilePath, 'Write folder hash manifest')) {
				WriteHashFile -Hashes:$Hashes -FilePath:$OutFilePath -Depth:($Depth + 1)
			}
		}
		else {
			Write-Out -Mode:Host -Depth:($Depth + 1) -Message:'Skipping...' -Prefix:$VerbosePadding
		}
	}

	Write-Out -Mode:Verbose -Depth:$MethodCallDepth -Message:'GenerateFolderHashes() finished!'
}

function MaintainFolderHashes {
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String[]] $BaseFolderPaths,

		[Parameter(Mandatory = $false)]
		[String[]] $ExclusionCriteria,

		[Parameter(Mandatory = $false)]
		[Switch] $Recurse,

		[String] $FolderSortOrder = 'Alphabetical',

		[int] $Depth = 0
	)

	if (-not $PSBoundParameters.ContainsKey('Recurse')) { $Recurse = $true }

	if ($PSBoundParameters.ContainsKey('Verbose')) { $VerbosePreference = 'Continue' } else { $VerbosePreference = 'SilentlyContinue' }
	if ($PSBoundParameters.ContainsKey('WhatIf')) { $WhatIfPreference = $true } else { $WhatIfPreference = $false }

	Write-Out -Mode:Verbose -Depth:$Depth -Message:"VerbosePreference is: $VerbosePreference; WhatIfPreference is: $WhatIfPreference"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:'Verbose logging enabled.'

	Write-Out -Mode:Host -Depth:$Depth -Message:'VetFolderHashes() started...' -Prefix:$VerbosePadding
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"BaseFolderPaths: $BaseFolderPaths"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"ExclusionCriteria: $ExclusionCriteria"

	$FoldersToProcess = GetFoldersToProcess -BaseFolderPaths:$BaseFolderPaths -ExclusionCriteria:$ExclusionCriteria -Recurse:$Recurse -SortOrder:$FolderSortOrder -Depth:($Depth + 1)

	# step 1 - find invalid hashes for folders with changes
	Write-Host '------------------------------------------'
	InvalidateHashesWithFolderChanges -FoldersToProcess:$FoldersToProcess -ExclusionCriteria:$ExclusionCriteria -Depth:($Depth + 1)

	# step 2 - generate hashes for folders without them
	Write-Host '------------------------------------------'
	GenerateFolderHashes -FoldersToProcess:$FoldersToProcess -ExclusionCriteria:$ExclusionCriteria -IncludeFoldersAlreadyHashed:$false -Depth:($Depth + 1)
	# step 3 - vet and refresh all existing hashes
	Write-Host '------------------------------------------'
	VetAndRefreshExistingHashes -FoldersToProcess:$FoldersToProcess -ExclusionCriteria:$ExclusionCriteria -Depth:($Depth + 1)

	Write-Host '------------------------------------------'
	Write-Out -Mode:Verbose -Depth:$Depth -Message:'MaintainFolderHashes() finished!'
}

#region Private Methods
function InvalidateHashesWithFolderChanges {
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		[Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [DirectoryInfo[]] $FoldersToProcess,

		[String[]] $ExclusionCriteria,

		[int] $Depth = 0
	)

	Write-Out -Mode:Host -Depth:$Depth -Message:'InvalidateHashesWithFolderChanges() started...' -Prefix:$VerbosePadding
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"FoldersToProcess: $($FoldersToProcess.Count) folders"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"ExclusionCriteria: $ExclusionCriteria"
    

	Write-Out -Mode:Host -Depth:$Depth -Message:'Gathering list of hash files...' -Prefix:$VerbosePadding
	$HashFiles = @($FoldersToProcess | ForEach-Object { Get-ChildItem -Path $_.FullName -File -Force -Filter '.hashes.md5' -ErrorAction SilentlyContinue })

	for ($i = 0; $i -lt $HashFiles.Count; $i++) {
		$Hash = $HashFiles[$i]
		$Folder = $Hash.DirectoryName
		$Files = (Get-ChildItem -Path:("$Folder\\*") -File -Force -Exclude:".hashes.md5")| Where-Object { 
			if ($ExclusionCriteria -and $ExclusionCriteria.Count -gt 0) { $_.FullName -notmatch $($ExclusionCriteria -join "|")} else { $true }
		}
		$Hashes = ParseHashFile -HashFile:$Hash.FullName -Depth:($Depth + 1)
		$IsInvalid = $false

		Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"Processing folder `"$($Folder)`"... [$($i + 1) of $($HashFiles.Count)]" -Prefix:$VerbosePadding

		# invalidate hashes with file count mismatch
		if ($Hashes.Count -ne $Files.Count) { 
			Write-Out -Mode:Host -Depth:($Depth + 1) -Message:'File count mismatch, invalidating hash...' -Prefix:$VerbosePadding
			$IsInvalid = $true; 
		}
		else {
			foreach ($File in $Files) {
				# invalidate hashes with files newer than the hash
				if ($File.LastWriteTime -gt $Hash.LastWriteTime) { 
					Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"$($File) has been updated, invalidating hash..." -Prefix:$VerbosePadding
					$IsInvalid = $true; 
					break; 
				}

				# invalidate hashes with file name mismatch
				if (-not $Hashes.ContainsKey($File.Name)) { 
					Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"$($File) not found, invalidating hash..." -Prefix:$VerbosePadding
					$IsInvalid = $true; 
					break; 
				}
			}
		}

		if ($IsInvalid) {
			Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"Removing bad hash file `"$($Hash.FullName)`"..." -Prefix:$VerbosePadding
			if ($PSCmdlet.ShouldProcess($Hash.FullName, 'Remove invalid hash file')) {
				Remove-Item -Path:$Hash.FullName -Force
			}
		}
		else {
			Write-Out -Mode:Host -Depth:($Depth + 1) -Message:'No high-level folder changes detected, moving on...' -Prefix:$VerbosePadding
		}
	}

	Write-Out -Mode:Verbose -Depth:$Depth -Message:'InvalidateHashesWithFolderChanges() finished!'
}

function VetAndRefreshExistingHashes {
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.IO.DirectoryInfo[]] $FoldersToProcess,

		[String[]] $ExclusionCriteria,

		[int] $Depth = 0
	)

	Write-Out -Mode:Host -Depth:$Depth -Message:'VerifyFolderHashes() started...' -Prefix:$VerbosePadding
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"FoldersToProcess: $($FoldersToProcess.Count) folders"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"ExclusionCriteria: $ExclusionCriteria"
    
	Write-Out -Mode:Host -Depth:$Depth -Message:'Gathering list of all hash files that need vetting...' -Prefix:$VerbosePadding
	$HashFiles = @($FoldersToProcess | ForEach-Object { Get-ChildItem -Path $_.FullName -File -Force -Filter '.hashes.md5' -ErrorAction SilentlyContinue })

	for ($i = 0; $i -lt $HashFiles.Count; $i++) {
		$HashFile = $HashFiles[$i]
		$Folder = $HashFile.Directory

		$Files = (Get-ChildItem -Path:$("$($HashFile.DirectoryName)\\*") -File -Force -Exclude:"*.md5") | Where-Object { 
			if ($ExclusionCriteria -and $ExclusionCriteria.Count -gt 0) { $_.FullName -notmatch $($ExclusionCriteria -join "|")} else { $true }
		}
		$Hashes = ParseHashFile -HashFile:$HashFile.FullName -Depth:($Depth + 1)
		$RefreshNeeded = $false

		Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"Processing folder `"$($Folder.FullName)`"... [$($i + 1) of $($HashFiles.Count)]" -Prefix:$VerbosePadding
		Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"Folder was last hashed on $($HashFile.LastWriteTime)." -Prefix:$VerbosePadding

		for ($j = 0; $j -lt $Files.Count; $j++) {
			$File = $Files[$j]
			Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"Hashing file `"$($File.Name)`" ($(Format-FileSize -Bytes $File.Length))... [$($j + 1) of $($Files.Count)]" -Prefix:$VerbosePadding
			Write-Out -Mode:Progress -Depth:($Depth + 1) -Message:'Hashing...' -ProgressActivity:'Hashing'
			$HashValue = (Get-FileHash -LiteralPath:$File.FullName -Algorithm:MD5)
			if ($HashValue.Hash -ne $Hashes[$File.Name]) {
				Write-Out -Mode:Host -Depth:($Depth + 1) -Message:'Hash is bad, hash file for this folder will be refreshed...' -Prefix:$VerbosePadding
				$RefreshNeeded = $true
				$Hashes[$File.Name] = $HashValue.Hash
			}
		}

		if ($RefreshNeeded) {
			$OutFilePath =  Join-Path -Path $Folder.FullName -ChildPath '.hashes.md5'
			Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"Writing file `"$($OutFilePath)`"..." -Prefix:$VerbosePadding
			if ($PSCmdlet.ShouldProcess($OutFilePath, 'Refresh hash file')) {
				WriteHashFile -Hashes:$Hashes -FilePath:$OutFilePath -Depth:($Depth + 1)
			}
		}
		else { 
			Write-Out -Mode:Host -Depth:($Depth + 1) -Message:'Hashes are valid, updating hash file modified date and moving on...' -Prefix:$VerbosePadding
			if ($PSCmdlet.ShouldProcess($HashFile.FullName, 'Update hash file timestamp')) {
				$HashFile.LastWriteTime = (Get-Date)
			}
		}
	}

	Write-Out -Mode:Verbose -Depth:$Depth -Message:'VerifyFolderHashes() finished!'
}
#endregion

#region Helper Methods
function GetFoldersToProcess {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String[]] $BaseFolderPaths,

		[String[]] $ExclusionCriteria,

		[Switch] $IncludeFoldersAlreadyHashed = $false,

		[Switch] $Recurse,

		[int] $Depth = 0,

		[String] $SortOrder = 'Alphabetical' # 'Random' or 'Alphabetical'
	)

	Write-Out -Mode:Host -Depth:($Depth - 1) -Message:'GetFoldersToProcess() started...' -Prefix:$VerbosePadding
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"BaseFolderPaths: $BaseFolderPaths"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"ExclusionCriteria: $ExclusionCriteria"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"IncludeFoldersAlreadyHashed: $IncludeFoldersAlreadyHashed"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"Recurse: $Recurse"

	Write-Out -Mode:Host -Depth:$Depth -Message:'Gathering list of folders...' -Prefix:$VerbosePadding
	Write-Out -Mode:Progress -Depth:$Depth -Message:'Scanning...' -ProgressActivity:'Scanning'
	
	$FoldersToProcess = @(Get-Item -Path:$BaseFolderPaths -Directory -ErrorAction SilentlyContinue) # confirm that the base path is included
	$FoldersToProcess += Get-ChildItem -Path:$BaseFolderPaths -Directory -Recurse:$Recurse -ErrorAction:SilentlyContinue |
	Where-Object { 
		(if ($ExclusionCriteria -and $ExclusionCriteria.Count -gt 0) { $_.FullName -notmatch $($ExclusionCriteria -join "|")} else { $true }) -and # folders or files that aren't excluded or inside excluded 
		($IncludeFoldersAlreadyHashed -or !(Get-ChildItem -Path:$_.FullName -File -Force -Filter:'.hashes.md5')) -and # include folders already hashed when requested, otherwise only folders missing hashes
		((Get-ChildItem -Path:$_.FullName -File).Count -gt 0) # only folders with files in them
			
	} | 
	Sort-Object -Property @{
		Expression = {
			if ($SortOrder -eq 'Random') { Get-Random } else { $_.FullName }
		}
	}
	
	Write-Out -Mode:Verbose -Depth:($Depth - 1) -Message:'GetFoldersToProcess() finished!'
	return $FoldersToProcess
}

function GetHashFiles {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.IO.DirectoryInfo[]] $FoldersToProcess,

		[int] $Depth = 0
	)

	Write-Out -Mode:Host -Depth:($Depth - 1) -Message:'GetHashFiles() started...' -Prefix:$VerbosePadding
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"FoldersToProcess: $($FoldersToProcess.Count) folders"

	Write-Out -Mode:Host -Depth:$Depth -Message:'Gathering list of hash files...' -Prefix:$VerbosePadding
	Write-Out -Mode:Progress -Depth:$Depth -Message:'Scanning...' -ProgressActivity:'Scanning'
	$HashFiles = @($FoldersToProcess | ForEach-Object { Get-ChildItem -Path:$_.FullName -File -Force -Filter:'.hashes.md5' -ErrorAction:SilentlyContinue })
	Write-Out -Mode:Verbose -Depth:($Depth - 1) -Message:'GetHashFiles() finished!'
	return $HashFiles
}

function ParseHashFile {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $HashFile,

		[int] $Depth = 0
	)

	Write-Out -Mode:Verbose -Depth:($Depth - 1) -Message:'ParseHashFile() started...' -Prefix:$VerbosePadding
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"HashFile: $HashFile"

	$Hashes = @{}
	$(Get-Content $HashFile) | ForEach-Object {
		$value, $key = ($_).Split(" *")
		$Hashes[$key] = $value.ToUpper() # confirm that the md5 is upper
	}

	Write-Out -Mode:Verbose -Depth:($Depth - 1) -Message:'ParseHashFile() finished!'
	return $Hashes
}

function WriteHashFile {
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		[Parameter(Mandatory = $true)]
		[Hashtable] $Hashes,

		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $FilePath,

		[int] $Depth = 0
	)

	Write-Out -Mode:Verbose -Depth:($Depth - 1) -Message:'WriteHashFile() started...' -Prefix:$VerbosePadding
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"Hashes: $Hashes"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"FilePath: $FilePath"

	if ($PSCmdlet.ShouldProcess($FilePath, 'Write hash file')) {
		$Hashes.GetEnumerator() | 
		Sort-Object { $_.Key } | 
		ForEach-Object {
			$_.Value.ToUpper() + " *" + $_.Key
		} | 
		Out-File -FilePath:$FilePath
	}
	
	Write-Out -Mode:Verbose -Depth:($Depth - 1) -Message:'WriteHashFile() finished!'
}

function Format-FileSize {
	param(
		[Parameter(Mandatory = $true)][long] $Bytes,
		[int] $Decimals = 1
	)

	if ($Bytes -lt 0) { return "-$(Format-FileSize -Bytes (-$Bytes) -Decimals $Decimals)" }

	$units = 'B', 'KB', 'MB', 'GB', 'TB', 'PB'
	$i = 0
	while ($Bytes -ge 1024 -and $i -lt $units.Length - 1) {
		$Bytes /= 1024
		$i++
	}

	$fmt = "{0:N$Decimals} {1}"
	return $fmt -f $Bytes, $units[$i]
}

function Write-Out {
	param(
		[Parameter(Mandatory = $true)][object]$Message,
		[ValidateSet('Host', 'Verbose', 'Progress')][string]$Mode = 'Host',
		[int]$Depth = 0,
		[string]$Prefix,
		[string]$ProgressActivity = ''
	)

	$padding = $VerbosePreference -eq 'Continue' ? '         ' : '' # if verbose is on, add padding to host output so that it aligns with verbose output
	$msg = if ($Message -is [string]) { $Message } else { ($Message | Out-String).Trim() }
	$indent = ' ' * (3 * [math]::Max(0, $Depth))
	$out = "[$(Get-Date -format 'yyyy-MM-dd HH:mm:ss')] ${indent}${msg}"

	switch ($Mode) {
		'Host' { 
			Write-Host ($padding + $Prefix + $out) 
		}
		'Verbose' { 
			Write-Verbose ($Prefix + $out) 
		}
		'Progress' { 
			$act = if ($ProgressActivity) { $ProgressActivity } else { $msg }
			Write-Progress -Activity $act -Status $out 
		}
	}
}
#endregion