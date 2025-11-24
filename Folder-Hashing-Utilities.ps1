<#+
.SYNOPSIS
	Generate, verify, and maintain folder-level MD5 hashes in a simple, cross-folder format.

.DESCRIPTION
	This script creates and maintains standardized MD5 hash files (default: ".hashes.md5") inside folders you choose to
	process. Use it to detect file changes, accidental corruption (bitrot), and to verify backup consistency across copies
	of a folder. The output follows a compatible md5sum layout so it integrates well with tools like HashCheck or other
	file-integrity utilities.

	Key features:
	- Create folder-level MD5 manifests for all files in a folder
	- Optionally walk folder trees recursively
	- Filter folders or files via exclusion regexes
	- Verify and refresh hashes when file contents change
	- Option to only process folders without an existing hash file

	Security note: MD5 is not suitable for cryptographic security. This script uses MD5 only to detect accidental data
	corruption and file-synchronization problems; do not use MD5 hashes here for authentication or secure integrity checks.

.PARAMETERS
	-BaseFolderPaths
		String[]. One or more folder paths to scan. Can be provided as a string array.

	-ExclusionCriteria
		String[]. Array of regular-expression patterns used to exclude folders or files. Patterns are OR'd together.

	-IncludeFoldersAlreadyHashed
		Switch. When present, include folders that already contain a default hash file (".hashes.md5").
		Default behaviour (when not specified) is to NOT include already-hashed folders — i.e. only folders missing a hash file are processed.

	-Recurse
		Boolean. When present, processes folders recursively under each base folder.

	-Verbose
		Switch. Common PowerShell switch; pass to see additional logging during processing.

.NOTES
	- The default manifest filename is: ".hashes.md5"
	- Hash format follows md5sum style: <hash> *<filename>
	- This script writes results as text files that can be compared using folder diff tools (e.g. BeyondCompare).
	- TODO:
        - [ ] Consider making each public function an advanced function with [CmdletBinding()] to gain common parameters (-Verbose, -Debug, -ErrorAction) and standard behavior.
        - [ ] Consider using [Switch] for -Recurse on all functions to match native cmdlet patterns (update callers and downstream -Recurse:$Recurse usage).
        - [ ] Consider adding a -HashAlgorithm parameter (default: MD5) to GenerateFolderHashes and VetAndRefreshExistingHashes to support stronger checksums (SHA256).
        - [ ] Consider renaming -ExclusionCriteria to -Exclude for parity with Get-ChildItem (keep regex/array semantics).

.EXAMPLES
	# Generate site-wide folder hashes for a base path and pick up hidden files as well
	GenerateFolderHashes -BaseFolderPaths:'C:\Data' -ExclusionCriteria:@('temp','backup') -Recurse:$true -Verbose

	# Only create missing hash files, do not overwrite existing ones (old default behaviour)
	GenerateFolderHashes -BaseFolderPaths:'C:\Data' -IncludeFoldersAlreadyHashed:$false

	# Vet all existing hashes and refresh any that differ from file contents
	MaintainFolderHashes -BaseFolderPaths:'C:\Data' -ExclusionCriteria:@('temp','backup') -Verbose
#>

#$ErrorActionPreference = 'Stop'

$WhatIfPreference = $false
$VerbosePreference = 'SilentlyContinue'

function GenerateFolderHashes {
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String[]] $BaseFolderPaths,

		[Parameter(Mandatory = $false)]
		[String[]] $ExclusionCriteria,

		[Parameter(Mandatory = $false)]
		[Switch] $IncludeFoldersAlreadyHashed = $false,

		[Parameter(Mandatory = $false)]
		[Switch] $Recurse,

		[int] $Depth = 0
	)

	if (-not $PSBoundParameters.ContainsKey('Recurse')) { $Recurse = $true }

	# Ensure nested calls inherit caller's -Verbose/-WhatIf settings by setting
	# the function's preference variables. This allows inner calls to rely on
	# $VerbosePreference / $WhatIfPreference instead of explicit flag forwarding.
	if ($PSBoundParameters.ContainsKey('Verbose')) { $VerbosePreference = 'Continue' } else { $VerbosePreference = 'SilentlyContinue' }
	if ($PSBoundParameters.ContainsKey('WhatIf')) { $WhatIfPreference = $true } else { $WhatIfPreference = $false }

	Write-Out -Mode:Verbose -Depth:$Depth -Message:'Verbose logging enabled.'
	$MethodCallDepth = if ($Depth -gt 0) { $Depth - 1 } else { $Depth }
	Write-Out -Mode:Host -Depth:$MethodCallDepth -Message:'GenerateFolderHashes() started...' -Prefix:$VerbosePadding
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"BaseFolderPaths: $BaseFolderPaths"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"ExclusionCriteria: $ExclusionCriteria"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"IncludeFoldersAlreadyHashed: $IncludeFoldersAlreadyHashed"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"Recurse: $Recurse"

	# Keep passing explicit switch values for non-preference switches
	# (e.g. IncludeFoldersAlreadyHashed, Recurse) so their semantics are preserved
	$FoldersToProcess = GetFoldersToProcess -BaseFolderPaths:$BaseFolderPaths -ExclusionCriteria:$ExclusionCriteria -IncludeFoldersAlreadyHashed:$IncludeFoldersAlreadyHashed -Recurse:$Recurse -Depth:($Depth + 1)
	
	for ($i = 0; $i -lt $FoldersToProcess.Count; $i++) {
		$Folder = $FoldersToProcess[$i]
		$Hashes = @{}
		$Files = Get-ChildItem $Folder -File

		Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"Processing folder `"$($Folder.FullName)`"... ($($i + 1) of $($FoldersToProcess.Count))" -Prefix:$VerbosePadding
		for ($j = 0; $j -lt $Files.Count; $j++) {
			$File = $Files[$j]

			Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"Hashing file `"$($File.Name)`" ($(Format-FileSize -Bytes $File.Length))... ($($j + 1) of $($Files.Count))" -Prefix:$VerbosePadding
			Write-Out -Mode:Progress -Depth:($Depth + 1) -Message:'Hashing...' -ProgressActivity:'Hashing'
			$HashValue = (Get-FileHash -LiteralPath $File -Algorithm MD5).Hash
			$Hashes.Add($File.Name, $HashValue)
		}

		if ($Hashes.Count -gt 0) {
			$OutFilePath = "$($Folder.FullName)/.hashes.md5"
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

		[int] $Depth = 0
	)

	if (-not $PSBoundParameters.ContainsKey('Recurse')) { $Recurse = $true }

	# Apply the caller's verbose/whatif preferences to this function scope so
	# downstream calls don't need explicit -Verbose/-WhatIf forwarding.
	if ($PSBoundParameters.ContainsKey('Verbose')) { $VerbosePreference = 'Continue' } else { $VerbosePreference = 'SilentlyContinue' }
	if ($PSBoundParameters.ContainsKey('WhatIf')) { $WhatIfPreference = $true } else { $WhatIfPreference = $false }

	Write-Out -Mode:Verbose -Depth:$Depth -Message:"VerbosePreference is: $VerbosePreference; WhatIfPreference is: $WhatIfPreference"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:'Verbose logging enabled.'

	Write-Out -Mode:Host -Depth:$Depth -Message:'VetFolderHashes() started...' -Prefix:$VerbosePadding
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"BaseFolderPaths: $BaseFolderPaths"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"ExclusionCriteria: $ExclusionCriteria"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"Recurse: $Recurse"

	# step 1 - find invalid hashes for folders with changes
	Write-Host '------------------------------------------'
	InvalidateHashesWithFolderChanges -BaseFolderPaths:$BaseFolderPaths -ExclusionCriteria:$ExclusionCriteria -Recurse:$Recurse -Depth:($Depth + 1)

	# step 2 - generate hashes for folders without them
	Write-Host '------------------------------------------'
	GenerateFolderHashes -BaseFolderPaths:$BaseFolderPaths -ExclusionCriteria:$ExclusionCriteria -IncludeFoldersAlreadyHashed:$false -Recurse:$Recurse -Depth:($Depth + 1)

	# step 3 - vet and refresh all existing hashes
	Write-Host '------------------------------------------'
	VetAndRefreshExistingHashes -BaseFolderPaths:$BaseFolderPaths -ExclusionCriteria:$ExclusionCriteria -Recurse:$Recurse -Depth:($Depth + 1)

	Write-Host '------------------------------------------'
	Write-Out -Mode:Verbose -Depth:$Depth -Message:'MaintainFolderHashes() finished!'
}

#region Private Methods
function InvalidateHashesWithFolderChanges {
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String[]] $BaseFolderPaths,

		[String[]] $ExclusionCriteria,

		[Switch] $Recurse,

		[int] $Depth = 0
	)

	Write-Out -Mode:Host -Depth:$Depth -Message:'InvalidateHashesWithFolderChanges() started...' -Prefix:$VerbosePadding
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"BaseFolderPaths: $BaseFolderPaths"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"ExclusionCriteria: $ExclusionCriteria"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"Recurse: $Recurse"

	Write-Out -Mode:Host -Depth:$Depth -Message:'Gathering list of hash files...' -Prefix:$VerbosePadding
	$HashFilesToProcess = GetHashFiles -BaseFolderPaths:$BaseFolderPaths -ExclusionCriteria:$ExclusionCriteria -Recurse:$Recurse -Depth:($Depth + 1)

	for ($i = 0; $i -lt $HashFilesToProcess.Count; $i++) {
		$Hash = $HashFilesToProcess[$i]
		$Folder = $Hash.DirectoryName
		$Files = (Get-ChildItem -Path:("$Folder\\*") -File -Force -Exclude:".hashes.md5")
		$Hashes = ParseHashFile -HashFile:$Hash.FullName -Depth:($Depth + 1)
		$IsInvalid = $false

		Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"Processing folder `"$($Folder)`"... ($($i + 1) of $($HashFilesToProcess.Count))" -Prefix:$VerbosePadding

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
		[String[]] $BaseFolderPaths,

		[String[]] $ExclusionCriteria,

		[Switch] $Recurse,

		[int] $Depth = 0
	)

	Write-Out -Mode:Host -Depth:$Depth -Message:'VerifyFolderHashes() started...' -Prefix:$VerbosePadding
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"BaseFolderPaths: $BaseFolderPaths"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"ExclusionCriteria: $ExclusionCriteria"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"Recurse: $Recurse"

	Write-Out -Mode:Host -Depth:$Depth -Message:'Gathering list of all hash files that need vetting...' -Prefix:$VerbosePadding
	$HashFilesToProcess = GetHashFiles -BaseFolderPaths:$BaseFolderPaths -ExclusionCriteria:$ExclusionCriteria -Recurse:$Recurse -Depth:($Depth + 1)

	for ($i = 0; $i -lt $HashFilesToProcess.Count; $i++) {
		$HashFile = $HashFilesToProcess[$i]
		$Folder = $HashFile.Directory
		$Files = (Get-ChildItem -Path:$("$($HashFile.DirectoryName)\\*") -File -Force -Exclude:"*.md5")
		$Hashes = ParseHashFile -HashFile:$HashFile.FullName -Depth:($Depth + 1)
		$RefreshNeeded = $false

		Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"Processing folder `"$($Folder.FullName)`" ($(Format-FileSize -Bytes $File.Length))... ($($i + 1) of $($HashFilesToProcess.Count))" -Prefix:$VerbosePadding
		Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"Folder was last hashed on $($HashFile.LastWriteTime)." -Prefix:$VerbosePadding

		for ($j = 0; $j -lt $Files.Count; $j++) {
			$File = $Files[$j]
			Write-Out -Mode:Host -Depth:($Depth + 1) -Message:"Hashing file `"$($File.Name)`"... ($($j + 1) of $($Files.Count))" -Prefix:$VerbosePadding
			Write-Out -Mode:Progress -Depth:($Depth + 1) -Message:'Hashing...' -ProgressActivity:'Hashing'
			$HashValue = (Get-FileHash -LiteralPath:$File -Algorithm:MD5)
			if ($HashValue.Hash -ne $Hashes[$File.Name]) {
				Write-Out -Mode:Host -Depth:($Depth + 1) -Message:'Hash is bad, hash file for this folder will be refreshed...' -Prefix:$VerbosePadding
				$RefreshNeeded = $true
				$Hashes[$File.Name] = $HashValue.Hash
			}
		}

		if ($RefreshNeeded) {
			$OutFilePath = "$($Folder.FullName)/.hashes.md5"
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

		[String] $SortOrder = 'Random' # 'Random' or 'Alphabetical'
	)

	Write-Out -Mode:Host -Depth:($Depth - 1) -Message:'GetFoldersToProcess() started...' -Prefix:$VerbosePadding
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"BaseFolderPaths: $BaseFolderPaths"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"ExclusionCriteria: $ExclusionCriteria"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"IncludeFoldersAlreadyHashed: $IncludeFoldersAlreadyHashed"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"Recurse: $Recurse"

	Write-Out -Mode:Host -Depth:$Depth -Message:'Gathering list of folders...' -Prefix:$VerbosePadding
	Write-Out -Mode:Progress -Depth:$Depth -Message:'Scanning...' -ProgressActivity:'Scanning'
	$FoldersToProcess = Get-ChildItem -Path:$BaseFolderPaths -Directory -Recurse:$Recurse -ErrorAction:SilentlyContinue |
	Where-Object { 
		($_.FullName -notmatch $($ExclusionCriteria -join "|")) -and # folders that aren't excluded or inside excluded 
		($IncludeFoldersAlreadyHashed -or !(Get-ChildItem -Path $_.FullName -File -Force -Filter '.hashes.md5')) -and # include folders already hashed when requested, otherwise only folders missing hashes
		((Get-ChildItem -Path $_.FullName -File).Count -gt 0) # only folders with files in them
			
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
		[String[]] $BaseFolderPaths,

		[String[]] $ExclusionCriteria,

		[Switch] $Recurse,

		[int] $Depth = 0
	)

	Write-Out -Mode:Host -Depth:($Depth - 1) -Message:'GetHashFiles() started...' -Prefix:$VerbosePadding
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"BaseFolderPaths: $BaseFolderPaths"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"ExclusionCriteria: $ExclusionCriteria"
	Write-Out -Mode:Verbose -Depth:$Depth -Message:"Recurse: $Recurse"

	Write-Out -Mode:Host -Depth:$Depth -Message:'Gathering list of hash files...' -Prefix:$VerbosePadding
	Write-Out -Mode:Progress -Depth:$Depth -Message:'Scanning...' -ProgressActivity:'Scanning'
	$HashFiles = Get-ChildItem -Path:$BaseFolderPaths -File -Force -Recurse:$Recurse -Filter:".hashes.md5" -ErrorAction:SilentlyContinue |
	Where-Object { 
		($_.FullName -notmatch $($ExclusionCriteria -join "|"))
	} | 
	Sort-Object LastWriteTime

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
		$Hashes[$key] = $value
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