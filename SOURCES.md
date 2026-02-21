# Patch Repository Sources

> Copyright (C) Senserva, LLC. All rights reserved.

The Netchk25 patch repository aggregates security update and version data from **38 patch sources** and **3 CVE enrichment databases** across Windows, macOS, and Linux. A single `repo init` command pulls everything into a portable SQLite database.

The repository and its source implementations are designed to be **open source**. Anyone can add new sources by implementing the `IPatchSource` interface.

---

## Coverage Summary

| Platform | Patch Sources | Estimated Applications / Packages |
|----------|:------------:|:---------------------------------:|
| Windows | 29 | ~20,000+ |
| macOS | 4 | ~5,000+ |
| Linux | 3 | Ubuntu, Debian, RHEL/CentOS package CVEs |
| Cross-platform | 15 shared | (counted in Windows totals) |
| CVE enrichment | 3 | — |
| **Total** | **38 + 3** | **~25,000+ unique apps + Linux package CVEs** |

| Database Metric | Typical Value |
|-----------------|:-------------:|
| Patch entries | ~20,000+ rows |
| Detection rules | ~40,000+ rows |
| CVEs tracked | ~30,000+ |
| CVEs enriched (CVSS/CWE/KEV) | ~15,000+ |
| CISA KEV (actively exploited) | ~1,200+ |
| Database size | 50–100 MB |
| Full sync time | 3–8 minutes |

---

## Windows — 29 Sources

### Microsoft OS & Infrastructure (8 sources)

These cover the Windows operating system itself and core Microsoft software. Together they provide patch metadata, CVE mappings, severity ratings, supersedence chains, download URLs, and detection rules for every supported Windows version.

| Source | Name | Data Feed | What It Covers |
|--------|------|-----------|----------------|
| MsrcApiSource | `MSRC` | Microsoft Security Response Center API | All Microsoft CVEs, severity ratings, affected products, KB article mappings. The authoritative source for Microsoft vulnerability data |
| WindowsCuSource | `WindowsCU` | Windows cumulative update history pages | Windows 10/11 and Server cumulative updates with file version and registry detection rules. Depends on MSRC for severity data |
| CatalogScraperSource | `Catalog` | Microsoft Update Catalog | Supersedence chains, download URLs, file sizes, and file-level detection rules. Where most Microsoft detection rules originate |
| WsusCabSource | `WsusCab` | `wsusscn2.cab` download | WSUS offline scan cabinet for air-gapped Windows Update Agent scanning |
| EdgeSource | `Edge` | Edge update API (`edgeupdates.microsoft.com`) | Microsoft Edge (Chromium) stable channel releases |
| Office365Source | `Office365` | Microsoft 365 Apps update history | Office Click-to-Run builds across Current, Monthly Enterprise, and Semi-Annual channels |
| DotNetSource | `DotNet` | .NET release metadata (blob storage) | .NET Runtime and SDK versions across all active channels (6.0–10.0) |
| TeamsSource | `Teams` | Teams Desktop update history | Microsoft Teams Desktop releases |

### Windows Bulk App Repository (1 source, ~4,700+ apps)

| Source | Name | Data Feed | What It Covers |
|--------|------|-----------|----------------|
| WinGetSource | `WinGet` | `microsoft/winget-pkgs` GitHub repo | **~4,700+ Windows applications** — parses YAML manifests for version, publisher, installer URL, MSI product code. ETag-based incremental sync. Covers PowerToys, Docker Desktop, Postman, and thousands more |

### Browsers (2 sources)

| Source | Name | Data Feed | What It Covers |
|--------|------|-----------|----------------|
| ChromeSource | `Chrome` | Chrome Version History API + Chrome security blog | Google Chrome stable releases with CVE extraction from release blog posts |
| FirefoxSource | `Firefox` | Mozilla product-details API | Mozilla Firefox stable releases with Mozilla Foundation Security Advisory (MFSA) data |

### Communication (2 sources)

| Source | Name | Data Feed | What It Covers |
|--------|------|-----------|----------------|
| ZoomSource | `Zoom` | Zoom client release notes + security bulletins | Zoom desktop client versions with CVE data from security bulletins |
| SlackSource | `Slack` | Slack Desktop changelog | Slack Desktop for Windows releases |

### Enterprise & Security Tools (4 sources)

| Source | Name | Data Feed | What It Covers |
|--------|------|-----------|----------------|
| JavaSource | `Java` | Adoptium/Oracle release API | Java OpenJDK LTS versions (8, 11, 17, 21) — critical for enterprise environments |
| AdobeSource | `Adobe` | Adobe security bulletins | Adobe Acrobat/Reader security updates — frequent target for exploits |
| PuttySource | `PuTTY` | PuTTY download page | PuTTY SSH client — security-critical (SSH key exposure risks) |
| WinScpSource | `WinSCP` | WinSCP download page | WinSCP SFTP/SCP client — security-critical (file transfer) |

### IT Utilities (8 sources)

| Source | Name | Data Feed | What It Covers |
|--------|------|-----------|----------------|
| SevenZipSource | `7-Zip` | 7-Zip download page | 7-Zip file archiver |
| WinRarSource | `WinRAR` | WinRAR download page | WinRAR — notable for critical CVEs (e.g., CVE-2023-38831, actively exploited) |
| NotepadPlusSource | `Notepad++` | GitHub Releases API | Notepad++ text editor |
| FileZillaSource | `FileZilla` | FileZilla download page | FileZilla FTP client |
| VlcSource | `VLC` | VLC download page | VLC media player |
| WiresharkSource | `Wireshark` | Wireshark download page | Wireshark network analyzer |
| KeePassSource | `KeePass` | KeePass download page | KeePass password manager — security-critical |
| ObsStudioSource | `OBS` | OBS Studio releases | OBS Studio screen recording/streaming |

### Developer Tools (7 sources)

| Source | Name | Data Feed | What It Covers |
|--------|------|-----------|----------------|
| VsCodeSource | `VSCode` | VS Code update API | Visual Studio Code releases |
| NodeJsSource | `NodeJS` | `nodejs.org/dist/index.json` | Node.js LTS and Current releases — includes upstream security flag |
| PythonSource | `Python` | Python release API | Python runtime — latest per minor branch (3.11.x, 3.12.x, 3.13.x) |
| GitSource | `Git` | GitHub Releases API | Git for Windows — flags releases mentioning CVE/security |
| PowerShellSource | `PowerShell` | GitHub Releases API | PowerShell 7.x releases |
| CurlSource | `cURL` | curl download page | curl for Windows — frequent CVE target |
| OpenSshSource | `OpenSSH` | GitHub Releases API | Win32-OpenSSH releases — security-critical |

### Browsers / Email (1 source)

| Source | Name | Data Feed | What It Covers |
|--------|------|-----------|----------------|
| ThunderbirdSource | `Thunderbird` | Mozilla product-details API + security advisories | Mozilla Thunderbird email client releases |

### Windows Detection Rule Types (5)

| Rule Type | What It Checks | Example |
|-----------|---------------|---------|
| `FileVersion` | PE file version header of an EXE/DLL | `%ProgramFiles%\Google\Chrome\Application\chrome.exe >= 133.0.6943.127` |
| `RegistryKey` | Whether a registry key exists | `HKLM\...\Packages\Package_for_KB5034441* exists` |
| `RegistryValue` | A specific registry value against an expected version | `HKLM\...\VersionToReport >= 16.0.18025.20160` |
| `MsiProductCode` | An installed MSI product by GUID | `{AC76BA86-...} >= 24.001.30159` |
| `UninstallDisplayVersion` | Version from Add/Remove Programs (supports wildcards) | `Google Chrome* >= 133.0.6943.127` |

---

## macOS — 4 Sources

### Apple System & Apps (3 sources)

| Source | Name | Data Feed | What It Covers |
|--------|------|-----------|----------------|
| MacOSSecuritySource | `macOSUpdates` | Apple GDMF feed (`gdmf.apple.com/v2/pmv`) + Apple security releases page | macOS system security updates — all current macOS versions (Sequoia, Sonoma, Ventura, Monterey, Big Sur) with build numbers, dates, and CVE data |
| SafariSource | `Safari` | Apple security releases page | Safari browser security updates — version tracking with CVE extraction |
| XcodeSource | `Xcode` | Apple Developer RSS + security releases page | Xcode IDE security updates — release dates from Developer RSS, CVEs from security page |

### macOS Bulk App Repository (1 source, ~5,000+ apps)

| Source | Name | Data Feed | What It Covers |
|--------|------|-----------|----------------|
| HomebrewCaskSource | `HomebrewCask` | Homebrew Cask API (`formulae.brew.sh/api/cask.json`) | **~5,000+ macOS GUI applications** — token, version, download URL, and `.app` artifact paths for BundleVersion detection. ETag-based incremental sync. The macOS counterpart to WinGet |

### macOS Data Sources

| API | Auth Required | Rate Limit | Data Provided |
|-----|:------------:|:----------:|---------------|
| Apple GDMF (`gdmf.apple.com/v2/pmv`) | No | None | All public macOS versions, build numbers, posting dates |
| Apple Security Releases (`support.apple.com/en-us/100100`) | No | None | Per-release CVE lists, advisory details |
| Apple Developer RSS (`developer.apple.com/news/releases/rss/releases.rss`) | No | None | Xcode and developer tool release dates |
| Homebrew Cask API (`formulae.brew.sh/api/cask.json`) | No | None | ~5,000+ app tokens, versions, artifact install paths, download URLs |

### macOS Detection Rule Types (2)

| Rule Type | What It Checks | Example |
|-----------|---------------|---------|
| `BundleVersion` | `CFBundleShortVersionString` from an app bundle's `Info.plist` | `/Applications/Safari.app >= 18.3` |
| `PlistValue` | A specific key's value from any `.plist` file | `/System/Library/CoreServices/SystemVersion.plist::ProductVersion >= 15.3` |

---

## Linux — 3 Sources

The big three Linux distribution families: Debian/Ubuntu, Red Hat/CentOS/Fedora, and Debian itself. Each source pulls security advisory data from the distro's official vulnerability tracker and creates `PackageVersion` detection rules that check installed package versions via `dpkg` or `rpm`.

### Ubuntu (1 source)

| Source | Name | Data Feed | What It Covers |
|--------|------|-----------|----------------|
| UbuntuUsnSource | `UbuntuUSN` | Canonical Security API (`ubuntu.com/security/notices.json`) | Ubuntu Security Notices (USNs) — paginated API returning up to 2,000 recent advisories with CVE lists, affected packages, fixed versions, and Ubuntu priority ratings |

### Debian (1 source)

| Source | Name | Data Feed | What It Covers |
|--------|------|-----------|----------------|
| DebianSecuritySource | `DebianSec` | Debian Security Tracker (`security-tracker.debian.org/tracker/data/json`) | Full Debian vulnerability database (~29 MB JSON) — per-package CVE status with fixed versions for Bookworm (12), Trixie (13), and Bullseye (11). ETag-based incremental sync |

### Red Hat / RHEL / CentOS / Fedora (1 source)

| Source | Name | Data Feed | What It Covers |
|--------|------|-----------|----------------|
| RedHatCveSource | `RedHatCVE` | Red Hat Security Data API (`access.redhat.com/hydra/rest/securitydata/cve.json`) | Red Hat CVEs with RHSA advisory IDs, severity ratings, CVSS scores, and affected RPM packages with version-release strings. Paginated with date filtering. Data is CC BY 4.0 licensed |

### Linux Data Sources

| API | Auth Required | Rate Limit | Data Provided |
|-----|:------------:|:----------:|---------------|
| Canonical USN API (`ubuntu.com/security/notices.json`) | No | None | USN IDs, CVE lists, affected packages, fixed versions, priority |
| Debian Security Tracker (`security-tracker.debian.org/tracker/data/json`) | No | None | Per-package CVE status, fixed versions, urgency, per-release tracking |
| Red Hat Security Data API (`access.redhat.com/hydra/rest/securitydata/cve.json`) | No | 1,000/page | CVE IDs, severity, CVSS scores, RHSA advisories, affected RPM packages |

### Linux Detection Rule Type (1)

| Rule Type | What It Checks | Example |
|-----------|---------------|---------|
| `PackageVersion` | Installed package version via the system package manager | `dpkg::openssl >= 3.0.13-1~deb12u1` or `rpm::kernel >= 5.14.0-362.el9` |

The `PackageVersion` path format is `manager::package_name` where the manager prefix determines how the scanner queries the package:

| Prefix | Package Manager | Distros |
|--------|----------------|---------|
| `dpkg` | dpkg / APT | Debian, Ubuntu, Linux Mint, Pop!_OS |
| `rpm` | RPM / YUM / DNF | RHEL, CentOS, Fedora, Rocky, Alma, Oracle Linux, SUSE |
| `apk` | apk | Alpine Linux (ready for community contribution) |

---

## Cross-Platform Applications

These applications run on Windows, macOS, and Linux. They are tracked by dedicated Windows sources today, but their version data is relevant across all platforms. Homebrew Cask also independently tracks the macOS builds of many of these.

| Application | Category | Source | Windows | macOS | Linux |
|-------------|----------|--------|:-------:|:-----:|:-----:|
| Google Chrome | Browser | ChromeSource | Y | via Homebrew | via distro sources |
| Mozilla Firefox | Browser | FirefoxSource | Y | via Homebrew | via distro sources |
| Mozilla Thunderbird | Email | ThunderbirdSource | Y | via Homebrew | via distro sources |
| Visual Studio Code | Dev Tool | VsCodeSource | Y | via Homebrew | via distro sources |
| Node.js | Runtime | NodeJsSource | Y | via Homebrew | via distro sources |
| Python | Runtime | PythonSource | Y | via Homebrew | via distro sources |
| Git | Dev Tool | GitSource | Y | via Homebrew | via distro sources |
| Java/Adoptium | Runtime | JavaSource | Y | via Homebrew | via distro sources |
| VLC | Utility | VlcSource | Y | via Homebrew | via distro sources |
| Wireshark | Security | WiresharkSource | Y | via Homebrew | via distro sources |
| FileZilla | Utility | FileZillaSource | Y | via Homebrew | via distro sources |
| OBS Studio | Utility | ObsStudioSource | Y | via Homebrew | via distro sources |
| Zoom | Communication | ZoomSource | Y | via Homebrew | via distro sources |
| Slack | Communication | SlackSource | Y | via Homebrew | via distro sources |
| OpenSSL | Library | — | — | — | via distro sources |
| curl | Library | CurlSource | Y | via Homebrew | via distro sources |
| Linux kernel | OS | — | — | — | via distro sources |

---

## Package Vulnerability Databases — 1 Source

| Source | Name | Data Feed | What It Covers |
|--------|------|-----------|----------------|
| NuGetAuditSource | `NuGet` | GitHub Advisory Database (NuGet ecosystem) | NuGet package vulnerability advisories — maps package IDs to CVEs and severity ratings |

---

## CVE Enrichment — 3 Sources

These sources do not produce patch entries. They enrich existing CVEs in the repository with vulnerability intelligence: CVSS scores, severity ratings, CWE weakness classifications, EPSS exploitation probability, and CISA Known Exploited Vulnerability (KEV) status.

| Source | Name | Database | Auth | Rate Limit |
|--------|------|----------|:----:|:----------:|
| NvdSource | `NVD` | NIST National Vulnerability Database | `NVD_API_KEY` (optional) | 50/30s keyed, 5/30s unkeyed |
| OsvSource | `OSV` | Google Open Source Vulnerabilities | None | None |
| GitHubAdvisorySource | `GHSA` | GitHub Advisory Database | `GITHUB_TOKEN` (optional) | 5,000/hr keyed, 60/hr unkeyed |

### Enrichment Fields Per CVE

| Field | Type | Source(s) | Description |
|-------|------|-----------|-------------|
| CVSS v3.x Score | 0.0–10.0 | NVD, GHSA | Base vulnerability score |
| CVSS v4.0 Score | 0.0–10.0 | GHSA | Newer scoring methodology |
| CVSS Vector | String | NVD, OSV, GHSA | Attack vector breakdown (network/local, complexity, privileges) |
| Severity | Label | NVD, OSV, GHSA | CRITICAL / HIGH / MEDIUM / LOW |
| CWE IDs | List | NVD, OSV, GHSA | Weakness classification (CWE-79, CWE-416, etc.) |
| EPSS Score | 0.0–1.0 | NVD | Probability of exploitation in the next 30 days |
| EPSS Percentile | 0.0–1.0 | NVD | Relative ranking against all CVEs |
| CISA KEV | Boolean | NVD | Known to be actively exploited in the wild |
| Description | Text | NVD, OSV, GHSA | Human-readable vulnerability summary |

### Severity Mapping

| NVD / GitHub | Netchk25 Label | CVSS v3 Range |
|:------------:|:--------------:|:------------:|
| CRITICAL | Critical | 9.0–10.0 |
| HIGH | Important | 7.0–8.9 |
| MEDIUM | Moderate | 4.0–6.9 |
| LOW | Low | 0.1–3.9 |

---

## Source Counts by Category

| Category | Count | Key Highlights |
|----------|:-----:|----------------|
| Microsoft OS & Infrastructure | 8 | MSRC API, Windows CUs, WSUS Cab, Office 365, Edge, .NET, Teams |
| Bulk App Repositories | 2 | WinGet (~4,700+ Windows apps), Homebrew Cask (~5,000+ macOS apps) |
| Browsers | 4 | Chrome, Firefox, Edge, Safari |
| Communication | 2 | Zoom (with security bulletins), Slack |
| Enterprise / Security | 4 | Java, Adobe Reader, PuTTY, WinSCP |
| IT Utilities | 8 | 7-Zip, WinRAR, Notepad++, FileZilla, VLC, Wireshark, KeePass, OBS |
| Developer Tools | 7 | VS Code, Node.js, Python, Git, PowerShell, curl, OpenSSH |
| Email | 1 | Thunderbird |
| macOS System | 3 | macOS security updates, Safari, Xcode |
| Linux Distributions | 3 | Ubuntu USN, Debian Security Tracker, Red Hat CVE API |
| Package Vulnerabilities | 1 | NuGet |
| CVE Enrichment | 3 | NVD (NIST), OSV (Google), GitHub Advisory |
| **Total** | **38 + 3** | |

---

## Sync Architecture

All 38 sources run in parallel during `repo init` or `repo sync`, with up to 8 concurrent downloads. The only dependency is that WindowsCU waits for MSRC to finish (it needs MSRC's severity data). A failure in one source does not block any other source.

| Property | Value |
|----------|-------|
| Concurrency | 8 parallel workers |
| Source dependencies | 1 (WindowsCU depends on MSRC) |
| Failure isolation | Per-source try/catch — one failure doesn't block others |
| Progress display | Live Spectre.Console table with per-source status |
| Incremental sync | ETag, date cursors, or full re-pull per source |

---

## Contributing New Sources

The repository is open source. Adding a new source requires:

1. **One new C# file** in `Repository/Sources/` implementing `IPatchSource`
2. **One line** added to the `_sources` list in `RepoSyncEngine.cs`

The interface is minimal:

```csharp
public interface IPatchSource
{
    string Name { get; }        // Short unique name for sync tracking
    string Description { get; } // Human-readable description
    Task<SyncResult> SyncAsync(PatchRepository repo, bool incremental, IProgress<string>? progress = null);
}
```

### Wanted Sources

Community contributions are welcome for:

- **More Linux distributions** — SUSE/openSUSE, Alpine, Arch, Rocky, Alma, Oracle Linux, Amazon Linux
- **Linux package managers** — Flatpak, Snap store advisories
- **Additional macOS apps** — dedicated sources for high-value targets (iCloud, Apple Music, etc.)
- **Container images** — Docker Hub official images, distroless base images
- **Cloud CLI tools** — AWS CLI, Azure CLI, gcloud, Terraform, kubectl
- **Additional Windows apps** — any application with a public version API or release feed
- **IoT / embedded** — firmware version tracking for network devices, printers, etc.

See [REPOSITORY.md](REPOSITORY.md) for database schema details, detection logic, and example queries.

---

*Copyright (C) Senserva, LLC. All rights reserved.*
