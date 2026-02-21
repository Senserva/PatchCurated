# Patch Repository

> Copyright (C) Senserva, LLC. All rights reserved.

The local patch repository is a portable SQLite database that stores patch metadata, detection rules, and supersedence chains from 38 data sources across Windows, macOS, and Linux. Once initialized, the `CloudPatchScanner` can evaluate machines offline without relying on the Windows Update Agent or internet access. The database file is a single `.db` file that can be copied between machines, making it ideal for air-gapped environments.

## Getting Started

```bash
# First time: full pull from all 38 sources
netchk25 repo init

# Later: incremental refresh (only changes)
netchk25 repo sync

# Check what you have
netchk25 repo status

# Or just add --refresh to any scan and it handles everything
netchk25 --refresh -h 192.168.1.0/24 -u admin
```

The `--refresh` flag will auto-run `repo init` if no database exists yet, or `repo sync` if one already does. It runs before the scan starts, so the scan always uses fresh data.

## Database Location

By default the database is stored at:

```
%LOCALAPPDATA%\Netchk25\patches.db
```

You can override this by passing a path to `--refresh`:

```bash
netchk25 --refresh D:\shared\patches.db -h server1 -u admin
```

## Database Schema

The repository uses five tables. Here is the full schema.

### patches

The main table. One row per patch per product per version. This means a single KB article can have multiple rows if it applies to different products (e.g., KB5001234 for Windows 11 23H2 and Windows 11 24H2).

```sql
CREATE TABLE patches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    patch_id        TEXT    NOT NULL,           -- KB number or vendor ID (e.g., "KB5001234", "Chrome-131.0.6778.86")
    title           TEXT    NOT NULL DEFAULT '',
    vendor          TEXT    NOT NULL DEFAULT 'Microsoft',
    product         TEXT    NOT NULL DEFAULT '', -- "Windows 11", "Google Chrome", "7-Zip", etc.
    product_version TEXT    NOT NULL DEFAULT '', -- "23H2", "131.0", "24.09", etc.
    severity        TEXT    NOT NULL DEFAULT '', -- Critical, Important, Moderate, Low
    classification  TEXT    NOT NULL DEFAULT '', -- Security Update, Update, Feature Pack, etc.
    description     TEXT    NOT NULL DEFAULT '',
    release_date    TEXT,                        -- ISO 8601 (nullable for unknown dates)
    cve_list        TEXT,                        -- Comma-separated: "CVE-2024-1234,CVE-2024-5678"
    download_url    TEXT,
    download_size   INTEGER,
    superseded_by   TEXT,                        -- PatchId of the replacement
    supersedes      TEXT,                        -- Comma-separated PatchIds this replaces
    is_superseded   INTEGER NOT NULL DEFAULT 0,  -- 1 if replaced by a newer patch
    source          TEXT    NOT NULL DEFAULT '',  -- Which source added this row
    created_utc     TEXT    NOT NULL,
    updated_utc     TEXT    NOT NULL
);

-- Unique constraint: one row per patch+product+version combo
CREATE UNIQUE INDEX idx_patches_patchid_product ON patches(patch_id, product, product_version);
CREATE INDEX idx_patches_vendor     ON patches(vendor);
CREATE INDEX idx_patches_severity   ON patches(severity);
CREATE INDEX idx_patches_superseded ON patches(is_superseded);
CREATE INDEX idx_patches_release    ON patches(release_date);
```

The upsert logic preserves existing data when a new source only has partial info. For example, MSRC might provide severity and CVEs while the Catalog Scraper adds download URLs and supersedence. The `ON CONFLICT` clause merges them intelligently — non-empty values from the new row overwrite blanks, but never erase existing data.

### detection_rules

Rules that determine if a patch is installed on a machine. Each patch can have multiple rules. All rules for a patch must pass (AND logic) for the patch to be considered installed.

```sql
CREATE TABLE detection_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    patch_entry_id  INTEGER NOT NULL,           -- FK to patches.id
    patch_id        TEXT    NOT NULL,
    rule_type       TEXT    NOT NULL,           -- FileVersion, RegistryKey, RegistryValue,
                                                -- MsiProductCode, UninstallDisplayVersion,
                                                -- BundleVersion, PlistValue, PackageVersion
    path            TEXT    NOT NULL,           -- What to check (file path, reg key, display name, etc.)
    expected_value  TEXT    NOT NULL DEFAULT '',-- Version or value to compare against
    comparison      TEXT    NOT NULL DEFAULT '>=', -- >=, ==, >, <, exists, contains
    architecture    TEXT,                        -- x64, x86, or NULL for both
    FOREIGN KEY (patch_entry_id) REFERENCES patches(id) ON DELETE CASCADE
);

CREATE INDEX idx_rules_patchentry ON detection_rules(patch_entry_id);
CREATE INDEX idx_rules_patchid    ON detection_rules(patch_id);
```

### sync_history

A log of every sync attempt. Useful for debugging and audit trails.

```sql
CREATE TABLE sync_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name     TEXT    NOT NULL,
    sync_utc        TEXT    NOT NULL,
    patches_added   INTEGER NOT NULL DEFAULT 0,
    patches_updated INTEGER NOT NULL DEFAULT 0,
    rules_added     INTEGER NOT NULL DEFAULT 0,
    cursor          TEXT,                        -- Source-specific bookmark
    etag            TEXT,                        -- HTTP ETag for change detection
    success         INTEGER NOT NULL DEFAULT 1,  -- 1 = success, 0 = failure
    error_message   TEXT
);
```

### sync_state

One row per source. Tracks the current sync position so incremental syncs can pick up where they left off.

```sql
CREATE TABLE sync_state (
    source_name     TEXT PRIMARY KEY,
    last_sync_utc   TEXT,
    cursor          TEXT,           -- MSRC uses page cursors, Catalog uses last KB, etc.
    etag            TEXT            -- HTTP ETag for sources that support it
);
```

### repo_metadata

Simple key-value store for internal bookkeeping.

```sql
CREATE TABLE repo_metadata (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL
);
```

Currently stores `schema_version` (always "1") and `wsus_cab_date` (when the WSUS cab was last downloaded).

## Detection Rule Types

Detection rules are the core of offline scanning. Each rule type checks something different on the target machine.

### FileVersion

Checks the version of a specific file on disk. The most common rule type. Path supports environment variables.

```
Rule Type:      FileVersion
Path:           %ProgramFiles%\Google\Chrome\Application\chrome.exe
Expected Value: 131.0.6778.86
Comparison:     >=
```

This means: "Chrome is patched if `chrome.exe` version is 131.0.6778.86 or higher."

### RegistryKey

Checks if a registry key exists (or doesn't exist). Supports wildcards for CBS packages.

```
Rule Type:      RegistryKey
Path:           HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\Package_for_KB5001234*
Comparison:     exists
```

### RegistryValue

Reads a specific registry value and compares it to an expected version string.

```
Rule Type:      RegistryValue
Path:           HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\VersionToReport
Expected Value: 16.0.18025.20160
Comparison:     >=
```

### UninstallDisplayVersion

Searches the Uninstall registry keys (both 64-bit and WOW6432Node) for a matching DisplayName, then compares the DisplayVersion. The path field is the display name pattern and supports `*` wildcards.

```
Rule Type:      UninstallDisplayVersion
Path:           Google Chrome*
Expected Value: 131.0.6778.86
Comparison:     >=
```

### MsiProductCode

Looks up an MSI product code GUID in the Windows Installer registry and compares its version.

```
Rule Type:      MsiProductCode
Path:           {AC76BA86-7AD7-1033-7B44-AC0F074E4100}
Expected Value: 24.004.20272
Comparison:     >=
```

### BundleVersion (macOS)

Reads `CFBundleShortVersionString` from a macOS app bundle's `Info.plist` and compares it. Used by Safari, Xcode, and Homebrew Cask sources.

```
Rule Type:      BundleVersion
Path:           /Applications/Safari.app
Expected Value: 18.3
Comparison:     >=
```

### PlistValue (macOS)

Reads a specific key from any `.plist` file and compares its value. Used by the macOS system update source to check the OS version.

```
Rule Type:      PlistValue
Path:           /System/Library/CoreServices/SystemVersion.plist::ProductVersion
Expected Value: 15.3
Comparison:     >=
```

### PackageVersion (Linux)

Checks the installed package version via the system package manager (`dpkg` for Debian/Ubuntu, `rpm` for RHEL/CentOS/Fedora). Used by the Ubuntu USN, Debian Security, and Red Hat CVE sources.

```
Rule Type:      PackageVersion
Path:           dpkg::openssl
Expected Value: 3.0.13-1~deb12u1
Comparison:     >=
```

```
Rule Type:      PackageVersion
Path:           rpm::kernel
Expected Value: 5.14.0-362.el9
Comparison:     >=
```

## Detection Logic

When the `CloudPatchScanner` evaluates a machine, it runs through every patch in the repo that has detection rules:

1. Load all non-superseded patches with their rules from the database
2. For each patch, evaluate every rule
3. If ALL rules pass → patch is **installed**
4. If ANY rule fails → patch is **missing**
5. If no rules are applicable (the product isn't installed) → skip it

The "not applicable" case is important. If Chrome isn't installed on a machine, the Chrome FileVersion rule returns `NotApplicable` rather than `Fail`. The scanner only reports a patch as missing if the product is actually present but outdated.

Version comparison handles common formats: `1.2.3.4`, `1.2.3`, `1.2`, and versions with suffixes like `21.0.3+9` (the `+9` is stripped before comparison). If both sides parse as `System.Version`, a proper numeric comparison is used. Otherwise it falls back to string comparison.

## Sources (24 Total)

Each source implements the `IPatchSource` interface:

```csharp
public interface IPatchSource
{
    string Name { get; }
    string Description { get; }
    Task<SyncResult> SyncAsync(PatchRepository repo, bool incremental, IProgress<string>? progress = null);
}
```

Every source follows the same pattern: fetch data from an API or web page, parse it into `PatchEntry` and `DetectionRule` objects, then upsert them into the database inside a transaction. Sources track their own sync state (ETags, cursors) so incremental syncs only pull changes.

### Microsoft Ecosystem (7 sources)

**MSRC API** (`MsrcApiSource`) — Calls the Microsoft Security Response Center API at `api.msrc.microsoft.com`. Pulls CVE/severity metadata for each month's Patch Tuesday release. Provides severity ratings, CVE lists, and affected product names. Uses page-based cursors for incremental sync.

**Catalog Scraper** (`CatalogScraperSource`) — Scrapes the Microsoft Update Catalog at `catalog.update.microsoft.com`. Retrieves supersedence chains, download URLs, file sizes, and file-level detection rules. This is where most of the Microsoft-specific detection rules come from.

**WSUS Cab** (`WsusCabSource`) — Downloads `wsusscn2.cab` from Microsoft for offline Windows Update Agent scanning. This is the same file WSUS uses. The cab file date is stored in repo_metadata.

**Edge** (`EdgeSource`) — Queries the Edge update API at `edgeupdates.microsoft.com/api/products`. Tracks the Stable channel for Microsoft Edge Chromium. Creates FileVersion rules for `msedge.exe` and UninstallDisplayVersion rules.

**Office 365** (`Office365Source`) — Parses the Microsoft 365 Apps update history page. Tracks build numbers across update channels (Current Channel, Monthly Enterprise, Semi-Annual Enterprise). Creates RegistryValue detection rules that check the `VersionToReport` registry key.

**.NET** (`DotNetSource`) — Fetches .NET release metadata from `dotnetcli.blob.core.windows.net`. Covers all active channels (6.0, 7.0, 8.0, 9.0, 10.0) for both Runtime and SDK. Creates FileVersion rules for `dotnet.exe` and RegistryValue rules.

**Teams** (`TeamsSource`) — Parses the Microsoft Teams Desktop update history page. Creates FileVersion rules for `ms-teams.exe`.

### WinGet Repository (1 source, ~4,700+ apps)

**WinGet** (`WinGetSource`) — Downloads the full `microsoft/winget-pkgs` GitHub repository as a zip file. Parses YAML manifest files under `manifests/[letter]/[Publisher]/[Package]/[Version]/`. For each package, it extracts the identifier, version, publisher, installer URL, and MSI product code. Keeps only the highest version per package ID.

Creates UninstallDisplayVersion rules (by matching on `PackageName`) and MsiProductCode rules (when a `ProductCode` GUID is present in the manifest). Batch inserts 500 packages per transaction for performance. Uses ETag-based incremental sync — if the repo hasn't changed since last download, the full zip is skipped entirely.

This single source covers approximately 4,700 applications including tools like PowerToys, VS Code, Postman, Docker Desktop, and thousands more.

### Browsers (2 sources)

**Chrome** (`ChromeSource`) — Fetches Chrome release data from the Chrome for Testing API and cross-references with the Chrome security blog for CVE counts. Creates FileVersion rules for `chrome.exe` and assigns severity based on CVE count (10+ = Critical, 5+ = Important, etc.).

**Firefox** (`FirefoxSource`) — Calls the Mozilla product-details API at `product-details.mozilla.org`. Tracks the latest release version. Creates FileVersion rules for `firefox.exe`.

### Communication (2 sources)

**Zoom** (`ZoomSource`) — Parses the Zoom Client release notes page. Creates FileVersion rules for `Zoom.exe` and UninstallDisplayVersion rules.

**Slack** (`SlackSource`) — Parses the Slack Desktop changelog page. Creates FileVersion rules for `slack.exe` and UninstallDisplayVersion rules.

### Enterprise / Security Tools (4 sources)

**Java** (`JavaSource`) — Fetches Oracle/Adoptium Java release info. Creates FileVersion rules for `java.exe` and RegistryValue rules that check the Java version in the registry.

**Adobe** (`AdobeSource`) — Parses Adobe Acrobat Reader release notes. Creates FileVersion rules for `AcroRd32.exe` and UninstallDisplayVersion rules.

**PuTTY** (`PuttySource`) — Parses the PuTTY download page. Flagged as security-critical since PuTTY vulnerabilities can expose SSH keys. Creates FileVersion and UninstallDisplayVersion rules.

**WinSCP** (`WinScpSource`) — Parses the WinSCP download page. Also security-critical (SFTP/SCP client). Creates FileVersion and UninstallDisplayVersion rules.

### IT Utilities (5 sources)

**7-Zip** (`SevenZipSource`) — Parses the 7-Zip download page. Creates FileVersion and UninstallDisplayVersion rules.

**WinRAR** (`WinRarSource`) — Parses the WinRAR download page. Notable because WinRAR has had critical CVEs (e.g., CVE-2023-38831). Creates FileVersion and UninstallDisplayVersion rules.

**Notepad++** (`NotepadPlusSource`) — Uses the GitHub Releases API via `GitHubReleaseHelper`. Creates FileVersion and UninstallDisplayVersion rules.

**FileZilla** (`FileZillaSource`) — Parses the FileZilla download page. Creates FileVersion and UninstallDisplayVersion rules.

**VLC** (`VlcSource`) — Parses the VLC media player download page. Creates FileVersion and UninstallDisplayVersion rules.

### Developer Tools (3 sources)

**Node.js** (`NodeJsSource`) — Fetches the official Node.js distribution index at `nodejs.org/dist/index.json`. Tracks both LTS and Current release lines. Includes a security flag from the upstream API. Creates FileVersion rules for `node.exe` and UninstallDisplayVersion rules.

**Python** (`PythonSource`) — Fetches from the official Python API. Keeps only the latest version per minor branch (3.11.x, 3.12.x, 3.13.x, etc.). Creates FileVersion and UninstallDisplayVersion rules.

**Git** (`GitSource`) — Uses the GitHub Releases API via `GitHubReleaseHelper`. Security-aware: flags releases whose notes mention CVE or security. Creates FileVersion rules for `git.exe` and UninstallDisplayVersion rules.

## Sync Engine

The `RepoSyncEngine` orchestrates all 24 sources. It runs them one at a time in a fixed order and displays a live Spectre.Console table showing progress for each source.

Two modes:

- **Init** (`repo init`) — Creates the schema, then runs every source with `incremental: false`. Each source does a full pull.
- **Sync** (`repo sync`) — Runs every source with `incremental: true`. Sources that support ETags or cursors skip unchanged data.

Each source runs independently inside its own try/catch. A failure in one source (e.g., a network timeout fetching Chrome data) does not block the other 23 sources. The sync history table records the outcome of every attempt.

After all sources finish, a summary is printed showing total patches added, rules created, sources that succeeded, and any failures.

## Querying the Database

The `PatchRepository` class provides several query methods, but you can also query the SQLite database directly. Here are some useful queries.

### Count patches by vendor

```sql
SELECT vendor, count(*) as patch_count
FROM patches
WHERE is_superseded = 0
GROUP BY vendor
ORDER BY patch_count DESC;
```

### Find all critical patches from the last 30 days

```sql
SELECT patch_id, title, vendor, product, release_date
FROM patches
WHERE severity = 'Critical'
  AND is_superseded = 0
  AND release_date >= date('now', '-30 days')
ORDER BY release_date DESC;
```

### List detection rules for a specific patch

```sql
SELECT dr.rule_type, dr.path, dr.expected_value, dr.comparison
FROM detection_rules dr
JOIN patches p ON p.id = dr.patch_entry_id
WHERE p.patch_id = 'KB5001234';
```

### Find all patches for a product

```sql
SELECT patch_id, title, severity, product_version, release_date
FROM patches
WHERE product LIKE '%Chrome%'
  AND is_superseded = 0
ORDER BY release_date DESC
LIMIT 20;
```

### Walk a supersedence chain

```sql
-- Start with a known KB, follow superseded_by
WITH RECURSIVE chain(patch_id, title, superseded_by, depth) AS (
    SELECT patch_id, title, superseded_by, 0
    FROM patches WHERE patch_id = 'KB5001234'
    UNION ALL
    SELECT p.patch_id, p.title, p.superseded_by, c.depth + 1
    FROM patches p
    JOIN chain c ON p.patch_id = c.superseded_by
    WHERE c.depth < 10
)
SELECT * FROM chain;
```

### Check sync history

```sql
SELECT source_name, sync_utc, patches_added, patches_updated, rules_added,
       CASE success WHEN 1 THEN 'OK' ELSE error_message END as status
FROM sync_history
ORDER BY sync_utc DESC
LIMIT 20;
```

### Count rules by type

```sql
SELECT rule_type, count(*) as rule_count
FROM detection_rules
GROUP BY rule_type
ORDER BY rule_count DESC;
```

### Find patches with CVEs

```sql
SELECT patch_id, title, vendor, cve_list
FROM patches
WHERE cve_list IS NOT NULL
  AND cve_list != ''
  AND is_superseded = 0
ORDER BY release_date DESC
LIMIT 20;
```

## Example: What a Synced Repo Looks Like

After running `netchk25 repo init`, here's the kind of data you'll find:

### A Microsoft KB entry

```
patch_id:        KB5044284
title:           2024-10 Cumulative Update for Windows 11 Version 23H2
vendor:          Microsoft
product:         Windows 11
product_version: 23H2
severity:        Critical
classification:  Security Update
cve_list:        CVE-2024-43572,CVE-2024-43573,CVE-2024-43583,...
supersedes:      KB5043076
is_superseded:   0
source:          MSRC
```

With detection rules:

```
FileVersion  %SystemRoot%\System32\ntoskrnl.exe  >= 10.0.22631.4317
RegistryKey  HKLM\SOFTWARE\...\Packages\Package_for_KB5044284*  exists
```

### A Chrome entry

```
patch_id:        Chrome-131.0.6778.86
title:           Google Chrome 131.0.6778.86
vendor:          Google
product:         Google Chrome
severity:        Critical
source:          ChromeFeed
```

With detection rules:

```
FileVersion              %ProgramFiles%\Google\Chrome\Application\chrome.exe  >= 131.0.6778.86
UninstallDisplayVersion  Google Chrome*                                        >= 131.0.6778.86
```

### A WinGet entry

```
patch_id:        WinGet-Microsoft.PowerToys
title:           Microsoft PowerToys 0.87.0
vendor:          Microsoft
product:         PowerToys
source:          WinGet
```

With detection rules:

```
UninstallDisplayVersion  PowerToys*          >= 0.87.0
MsiProductCode           {A0C1D507-...}      >= 0.87.0
```

## WAL Mode and Performance

The database runs in WAL (Write-Ahead Logging) mode and has foreign keys enabled. This gives good read performance during scans even if a sync is running at the same time in another process.

Bulk inserts (e.g., WinGet's 4,700+ packages) are wrapped in explicit transactions. The WinGet source uses batches of 500 packages per transaction to balance memory usage and write performance.

## Air-Gap Workflow

For environments without internet access:

1. On a machine with internet: `netchk25 repo init`
2. Copy `%LOCALAPPDATA%\Netchk25\patches.db` to a USB drive
3. On the air-gapped machine: copy the file to the same path
4. Run scans normally — the `CloudPatchScanner` detects the database and uses it automatically

No internet required after the initial sync. The single `.db` file contains everything.


## SDK Access

The SDK supports both patch sources. By default it uses the GitHub backend (zero config, internet required). Point it at a local SQLite database for offline scanning:

```csharp
using var client = new Netchk25Client(new SdkOptions
{
    PatchDatabase = @"C:\netchk25\patches.db"
});

var result = await client.ScanLocalAsync(); // Fully offline.
```

See [SDK.md](SDK.md) for the full guide.



---

*© Senserva, LLC. All rights reserved. Netchk25 software, data, and documentation are provided "as is" without warranty. Free to use, including within paid services. Not licensed for incorporation into for-pay products without written permission. Must be used unmodified with attribution. See [LICENSE](LICENSE) for full terms.*
