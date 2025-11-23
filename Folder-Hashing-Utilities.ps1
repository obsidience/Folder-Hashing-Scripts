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
	GenerateFolderHashes -BaseFolderPaths 'C:\Data' -ExclusionCriteria @('temp','backup') -Recurse $true -Verbose

	# Only create missing hash files, do not overwrite existing ones (old default behaviour)
	GenerateFolderHashes -BaseFolderPaths 'C:\Data' -IncludeFoldersAlreadyHashed:$false

	# Vet all existing hashes and refresh any that differ from file contents
	MaintainFolderHashes -BaseFolderPaths 'C:\Data' -ExclusionCriteria @('temp','backup') -Verbose
#>

#$ErrorActionPreference = 'Stop'

function GenerateFolderHashes {
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String[]] $BaseFolderPaths,

		[Parameter(Mandatory = $false)]
		[String[]] $ExclusionCriteria,

		[Parameter(Mandatory = $false)]
		[Switch] $IncludeFoldersAlreadyHashed = $false,

		[Parameter(Mandatory = $false)]
		[Switch] $Recurse
	)

	# Preserve original default of -Recurse:$true in MaintainFolderHashes for compatibility
	if (-not $PSBoundParameters.ContainsKey('Recurse')) { $Recurse = $true }

	Write-Verbose "Verbose logging enabled."

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] GenerateFolderHashes() started..."
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    BaseFolderPaths: $BaseFolderPaths"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    ExclusionCriteria: $ExclusionCriteria"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    IncludeFoldersAlreadyHashed: $IncludeFoldersAlreadyHashed"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    Recurse: $Recurse"

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    Gathering list of folders..."
	# Pass the switch value explicitly so Switch semantics are preserved when calling downstream functions
	$FoldersToProcess = GetFoldersToProcess -BaseFolderPaths @BaseFolderPaths -ExclusionCriteria $ExclusionCriteria -IncludeFoldersAlreadyHashed:$IncludeFoldersAlreadyHashed -Recurse:$Recurse -Verbose:$PSBoundParameters.ContainsKey('Verbose')
	
	for ($i = 0; $i -lt $FoldersToProcess.Count; $i++) {
		$Folder = $FoldersToProcess[$i]
		$Hashes = @{}
		$Files = Get-ChildItem $Folder -File

		Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] Processing folder `"$($Folder.FullName)`"... ($($i + 1) of $($FoldersToProcess.Count))"

		for ($j = 0; $j -lt $Files.Count; $j++) {
			$File = $Files[$j]

			Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    Hashing file `"$($File.Name)`"... ($($j + 1) of $($Files.Count))"
			$HashValue = (Get-FileHash -LiteralPath $File -Algorithm MD5).Hash
			$Hashes.Add($File.Name, $HashValue)
		}

		if ($Hashes.Count -gt 0) {
			$OutFilePath = "$($Folder.FullName)/.hashes.md5"
			Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    Writing file `"$($OutFilePath)`"..."
			if ($PSCmdlet.ShouldProcess($OutFilePath, 'Write folder hash manifest')) {
				WriteHashFile -Hashes $Hashes -FilePath $OutFilePath -Verbose:$PSBoundParameters.ContainsKey('Verbose')
			}
		}
		else {
			Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    Skipping..."
		}
	}

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] GenerateFolderHashes() finished!"
}

function MaintainFolderHashes {
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String[]] $BaseFolderPaths,

		[Parameter(Mandatory = $false)]
		[String[]] $ExclusionCriteria,

		[Parameter(Mandatory = $false)]
		[Switch] $Recurse
	)

	Write-Verbose "Verbose logging enabled."

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] VetFolderHashes() started..."
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    BaseFolderPaths: $BaseFolderPaths"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    ExclusionCriteria: $ExclusionCriteria"

	# step 1 - find invalid hashes for folders with changes
	InvalidateHashesWithFolderChanges -BaseFolderPaths @BaseFolderPaths -ExclusionCriteria $ExclusionCriteria -Recurse:$Recurse -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	# step 2 - generate hashes for folders without them
	GenerateFolderHashes -BaseFolderPaths @BaseFolderPaths -ExclusionCriteria $ExclusionCriteria -IncludeFoldersAlreadyHashed:$false -Recurse:$Recurse -Verbose:$PSBoundParameters.ContainsKey('Verbose')
	
	# step 3 - vet and refresh all existing hashes
	VetAndRefreshExistingHashes  -BaseFolderPaths @BaseFolderPaths -ExclusionCriteria $ExclusionCriteria -Recurse:$Recurse -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] MaintainFolderHashes() finished!"
}

#region Private Methods
function InvalidateHashesWithFolderChanges {
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String[]] $BaseFolderPaths,

		[String[]] $ExclusionCriteria,

		[Switch] $Recurse
	)

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] InvalidateHashesWithFolderChanges() started..."
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    BaseFolderPaths: $BaseFolderPaths"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    ExclusionCriteria: $ExclusionCriteria"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    Recurse: $Recurse"

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    Gathering list of hash files..."
	$HashFilesToProcess = GetHashFiles -BaseFolderPaths @BaseFolderPaths -ExclusionCriteria $ExclusionCriteria -Recurse:$Recurse -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	for ($i = 0; $i -lt $HashFilesToProcess.Count; $i++) {
		$Hash = $HashFilesToProcess[$i]
		$Folder = $Hash.DirectoryName
		$Files = (Get-ChildItem -Path $("$Folder\\*") -File -Force -Exclude "*.md5")
		$Hashes = ParseHashFile $Hash.FullName
		$IsInvalid = $false

		Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    Processing folder `"$($Folder)`"... ($($i + 1) of $($HashFilesToProcess.Count))"

		# invalidate hashes with file count mismatch
		if ($Hashes.Count -ne $Files.Count) { 
			Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]       File count mismatch, invalidating hash..."
			$IsInvalid = $true; 
		}
		else {
			foreach ($File in $Files) {
				# invalidate hashes with files newer than the hash
				if ($File.LastWriteTime -gt $Hash.LastWriteTime) { 
					Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]       $($File) has been updated, invalidating hash..."
					$IsInvalid = $true; 
					break; 
				}

				# invalidate hashes with file name mismatch
				if (-not $Hashes.ContainsKey($File.Name)) { 
					Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]       $($File) not found, invalidating hash..."
					$IsInvalid = $true; 
					break; 
				}
			}
		}

		if ($IsInvalid) {
			Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]       Removing bad hash file `"$($Hash.FullName)`"..."
			if ($PSCmdlet.ShouldProcess($Hash.FullName, 'Remove invalid hash file')) {
				Remove-Item -Path $Hash.FullName -Force
			}
		}
	}

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] InvalidateHashesWithFolderChanges() finished!"
}

function VetAndRefreshExistingHashes {
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String[]] $BaseFolderPaths,

		[String[]] $ExclusionCriteria,

		[Switch] $Recurse
	)

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] VerifyFolderHashes() started..."
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    BaseFolderPaths: $BaseFolderPaths"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    ExclusionCriteria: $ExclusionCriteria"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    Recurse: $Recurse"

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    Gathering list of all hash files that need vetting..."
	$HashFilesToProcess = GetHashFiles -BaseFolderPaths @BaseFolderPaths -ExclusionCriteria $ExclusionCriteria -Recurse:$Recurse -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	for ($i = 0; $i -lt $HashFilesToProcess.Count; $i++) {
		$HashFile = $HashFilesToProcess[$i]
		$Folder = $HashFile.Directory
		$Files = (Get-ChildItem -Path $("$($HashFile.DirectoryName)\\*") -File -Force -Exclude "*.md5")
		$Hashes = ParseHashFile $HashFile.FullName
		$RefreshNeeded = $false

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    Processing folder `"$($Folder.FullName)`"... ($($i + 1) of $($HashFilesToProcess.Count))"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]       Folder was last hashed on $($HashFile.LastWriteTime)."

		for ($j = 0; $j -lt $Files.Count; $j++) {
			$File = $Files[$j]
			Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]       Hashing file `"$($File.Name)`"... ($($j + 1) of $($Files.Count))"

			$HashValue = (Get-FileHash -LiteralPath $File -Algorithm MD5)
			if ($HashValue.Hash -ne $Hashes[$File.Name]) {
				Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]       Hash is bad, hash file for this folder will be refreshed..."
				$RefreshNeeded = $true
				$Hashes[$File.Name] = $HashValue.Hash
			}
		}

		if ($RefreshNeeded) {
			$OutFilePath = "$($Folder.FullName)/.hashes.md5"
			Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]       Writing file `"$($OutFilePath)`"..."
			if ($PSCmdlet.ShouldProcess($OutFilePath, 'Refresh hash file')) {
				WriteHashFile -Hashes $Hashes -FilePath $OutFilePath -Verbose:$PSBoundParameters.ContainsKey('Verbose')
			}
		}
		else { 
			Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]       Hashes are good, updating hash file modified date and moving on..." 
			$HashFile.LastWriteTime = (Get-Date)
		}
	}

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] VerifyFolderHashes() finished!"
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

		[String] $SortOrder = 'Random' # 'Random' or 'Alphabetical'
	)

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] GetFoldersToProcess() started..."
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    BaseFolderPaths: $BaseFolderPaths"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    ExclusionCriteria: $ExclusionCriteria"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    IncludeFoldersAlreadyHashed: $IncludeFoldersAlreadyHashed"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    Recurse: $Recurse"

	$FoldersToProcess = Get-ChildItem -Path $BaseFolderPaths -Directory -Recurse:$Recurse -Verbose:$PSBoundParameters.ContainsKey('Verbose') -ErrorAction SilentlyContinue |
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
	
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] GetFoldersToProcess() finished!"
	return $FoldersToProcess
}

function GetHashFiles {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String[]] $BaseFolderPaths,

		[String[]] $ExclusionCriteria,

		[Switch] $Recurse
	)

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] GetHashFiles()"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    BaseFolderPaths: $BaseFolderPaths"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    ExclusionCriteria: $ExclusionCriteria"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    Recurse: $Recurse"

	$HashFiles = Get-ChildItem -Path $BaseFolderPaths -File -Force -Recurse:$Recurse -Filter ".hashes.md5" -Verbose:$PSBoundParameters.ContainsKey('Verbose') -ErrorAction SilentlyContinue |
	Where-Object { 
		($_.FullName -notmatch $($ExclusionCriteria -join "|"))
	} | 
	Sort-Object LastWriteTime

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] GetHashFiles() finished!"
	return $HashFiles
}

function ParseHashFile {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $HashFile
	)

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] ParseHashFile() started..."
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    HashFile: $HashFile"

	$Hashes = @{}
	$(Get-Content $HashFile) | ForEach-Object {
		$value, $key = ($_).Split(" *")
		$Hashes[$key] = $value
	}

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] ParseHashFile() finished!"
	return $Hashes
}

function WriteHashFile {
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[Parameter(Mandatory = $true)]
		[Hashtable] $Hashes,

		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $FilePath
	)

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] WriteHashFile()"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    Hashes: $Hashes"
	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")]    FilePath: $FilePath"

	if ($PSCmdlet.ShouldProcess($FilePath, 'Write hash file')) {
		$Hashes.GetEnumerator() | 
			Sort-Object { $_.Key } | 
			ForEach-Object {
				$_.Value.ToUpper() + " *" + $_.Key
			} | 
			Out-File -FilePath $FilePath
	}

	Write-Verbose "[$(Get-Date -format "yyyy-MM-dd HH:mm:ss")] WriteHashFile() finished!"
}
#endregion