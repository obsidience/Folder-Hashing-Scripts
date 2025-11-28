# Folder-Hashing-Utilities

Generate, verify, and maintain folder-level MD5 hash manifests in a simple, cross-platform format.

## Overview

This PowerShell utility creates and maintains standardized MD5 hash files (`.hashes.md5`) inside folders you choose to process. Use it to:

- **Detect file changes** — identify when files have been modified
- **Catch accidental corruption (bitrot)** — verify data integrity over time
- **Verify backup consistency** — ensure copies of folders match their originals

The output follows a compatible `md5sum` layout, integrating well with tools like [HashCheck](https://github.com/gurnec/HashCheck) or other file-integrity utilities.

> **Security Note:** MD5 is not suitable for cryptographic security. This script uses MD5 only to detect accidental data corruption and file-synchronization problems. Do not rely on MD5 hashes for authentication or secure integrity checks.

## Features

- Create folder-level MD5 manifests for all files in a folder
- Optionally walk folder trees recursively
- Filter folders or files via exclusion regex patterns
- Verify and refresh hashes when file contents change
- Option to only process folders without an existing hash file
- Supports `-WhatIf` for dry-run mode and `-Verbose` for detailed logging

## Project Structure

```
Folder-Hashing-Scripts/
├── Folder-Hashing-Utilities.ps1   # Core library with all functions
├── Generate-FolderHashes.ps1      # Entry point for generating hashes
├── Maintain-FolderHashes.ps1      # Entry point for maintaining hashes
├── .env                           # Your configuration (not tracked in git)
├── .env.test                      # Test configuration
├── disabled.env                   # Example production config (disabled)
├── README.md
└── tests/
    └── fixtures/                  # Test folders with sample files
```

## Installation

1. Clone or download this repository
2. Ensure PowerShell 5.1+ or PowerShell Core 7+ is installed
3. Create a `.env` file based on your needs (see [Configuration](#configuration))

## Usage

### Using Entry Scripts (Recommended)

The simplest way to use this project is through the entry point scripts:

```powershell
# Generate hash manifests for all configured folders
./Generate-FolderHashes.ps1

# Maintain existing hashes (invalidate, regenerate, and verify)
./Maintain-FolderHashes.ps1
```

These scripts automatically:
- Load configuration from `.env` (or `.env.test` if `.env` doesn't exist)
- Pass `VERBOSE` and `WHATIF` settings from the environment file to the functions

### Direct Function Calls

For more control, dot-source the utilities and call functions directly:

```powershell
# Load the utilities
. ./Folder-Hashing-Utilities.ps1

# Generate hashes for a single folder (non-recursive)
GenerateFolderHashes -BaseFolderPaths:'C:\Data\Photos' -Recurse:$false

# Generate hashes recursively with exclusions
GenerateFolderHashes -BaseFolderPaths:'C:\Data' -ExclusionCriteria:@('temp','\.git','backup') -Verbose

# Only create hash files for folders that don't have them yet
GenerateFolderHashes -BaseFolderPaths:'C:\Data' -IncludeFoldersAlreadyHashed:$false

# Full maintenance workflow (invalidate changed, generate missing, verify all)
MaintainFolderHashes -BaseFolderPaths:'C:\Data' -ExclusionCriteria:@('temp','backup') -Verbose

# Dry run to see what would happen without making changes
MaintainFolderHashes -BaseFolderPaths:'C:\Data' -WhatIf
```

## Configuration

### Environment File (`.env`)

Create a `.env` file in the project root to configure your folders and exclusions:

```dotenv
# Comma-separated list of folder paths to process
BASE_FOLDER_PATHS=/mnt/storage/Photos, /mnt/storage/Documents

# Comma-separated list of regex patterns to exclude
EXCLUSION_CRITERIA=\.git, \.vscode, temp, \.plex

# Enable verbose output (true/false)
VERBOSE=false

# Enable dry-run mode (true/false)
WHATIF=false
```

| Variable | Format | Description |
|----------|--------|-------------|
| `BASE_FOLDER_PATHS` | CSV of paths | Folders to process (comma-separated) |
| `EXCLUSION_CRITERIA` | CSV of regex patterns | Patterns to exclude folders/files (comma-separated, OR'd together) |
| `VERBOSE` | `true` / `false` | Enable detailed logging output (defaults to `false`) |
| `WHATIF` | `true` / `false` | Dry-run mode — no files are written (defaults to `false`) |

## Testing

### Test Configuration

When no `.env` file is present, the entry scripts automatically fall back to `.env.test`. To run in test mode, configure `VERBOSE=true` and `WHATIF=true` in your `.env.test` file.

### Test Configuration (`.env.test`)

```dotenv
# CSV-of-base-folders or single path
BASE_FOLDER_PATHS=./tests/fixtures
# CSV-of-regular-expressions to exclude
EXCLUSION_CRITERIA=exclude, exclude.txt$
# Enable verbose output (true/false, defaults to false if not set)
VERBOSE=false
# Enable dry-run mode (true/false, defaults to false if not set)
WHATIF=false
```

### Test Fixtures

The `tests/fixtures/` folder contains sample folders for testing:

```
tests/fixtures/
├── exclude/           # Empty folder (excluded by "exclude" regex)
├── folder1/
│   ├── .hashes.md5    # Pre-generated hash manifest
│   ├── file1.txt
│   └── file2.txt
├── folder2/
│   ├── .hashes.md5
│   ├── exclude.txt    # Excluded by "exclude.txt$" regex
│   ├── file1.txt
│   └── file3.txt
└── folder3/
    ├── .hashes.md5
    ├── file1.txt
    ├── file2.txt
    └── file3.txt
```

Run tests by executing the entry scripts without a `.env` file (ensure `WHATIF=true` in `.env.test`):

```powershell
./Generate-FolderHashes.ps1   # Runs against test fixtures
./Maintain-FolderHashes.ps1   # Runs against test fixtures
```

## Function Reference

### `GenerateFolderHashes`

Creates `.hashes.md5` manifest files for folders.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `BaseFolderPaths` | `String[]` | Yes* | — | One or more folder paths to scan |
| `FoldersToProcess` | `DirectoryInfo[]` | Yes* | — | Pre-filtered folders (alternative to BaseFolderPaths) |
| `ExclusionCriteria` | `String[]` | No | — | Regex patterns to exclude folders/files (OR'd together) |
| `IncludeFoldersAlreadyHashed` | `Switch` | No | `$false` | When set, re-process folders that already have `.hashes.md5` |
| `Recurse` | `Switch` | No | `$true` | Process folders recursively |
| `FolderSortOrder` | `String` | No | `'Alphabetical'` | Sort order: `'Alphabetical'` or `'Random'` |

*Either `BaseFolderPaths` or `FoldersToProcess` must be provided.

### `MaintainFolderHashes`

Full maintenance workflow that invalidates changed hashes, generates missing ones, and verifies/refreshes all existing hashes.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `BaseFolderPaths` | `String[]` | Yes | — | One or more folder paths to scan |
| `ExclusionCriteria` | `String[]` | No | — | Regex patterns to exclude folders/files |
| `Recurse` | `Switch` | No | `$true` | Process folders recursively |
| `FolderSortOrder` | `String` | No | `'Alphabetical'` | Sort order for folder processing |

### Maintenance Workflow

`MaintainFolderHashes` performs three steps:

1. **Invalidate** — Removes `.hashes.md5` files when folder contents have changed (file count mismatch, newer files, or filename changes)
2. **Generate** — Creates hash files for folders that don't have them
3. **Verify/Refresh** — Re-hashes all files and updates manifests if content differs; otherwise just updates the hash file's timestamp

## Hash File Format

The generated `.hashes.md5` files follow the standard `md5sum` format:

```
8B0A37BB6D482EE31E4D27EED827C724 *file1.txt
6F3E28DB9819EDE251DCCBED43BD88A3 *file2.txt
A1B2C3D4E5F6789012345678ABCDEF01 *document.pdf
```

This format is compatible with:
- GNU `md5sum` command
- HashCheck Shell Extension
- Most file integrity verification tools

## Roadmap

- [ ] Add `-HashAlgorithm` parameter to support stronger checksums (SHA256)
- [ ] Rename `-ExclusionCriteria` to `-Exclude` for parity with `Get-ChildItem`
- [ ] Consider using `[Switch]` for `-Recurse` on all functions to match native cmdlet patterns