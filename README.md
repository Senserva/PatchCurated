# PatchCurated

**Community-driven patch intelligence for Windows, macOS, and Linux.**

[![MISA Member](https://img.shields.io/badge/Microsoft%20MISA-Member-0078D4?logo=microsoft&logoColor=white)](https://www.microsoft.com/en-us/security/business/intelligent-security-association)

[![MISA Member](https://img.shields.io/badge/MISA_Member-Microsoft_Intelligent_Security_Association-0078d4?style=flat&logo=microsoft&logoColor=white)](https://www.microsoft.com/en-us/security/business/intelligent-security-association)

PatchCurated is an open patch data repository and the builder that populates it. It aggregates security update metadata, detection rules, supersedence chains, and CVE enrichment from **38 sources** into a single portable SQLite database — covering ~25,000+ applications across all three major platforms.

The database is the open data layer that [PatchCured](https://github.com/Senserva/PatchCured) — free patch scanner for Windows, macOS, and Linux, built on [PatchCurated](https://github.com/Senserva/PatchCurated) open data, with commercial remediation tiers — is built on. Any tool can use the data, as long as commercial tools give attribution to this site.

PatchCurated and PatchCured work as standalone solutions or alongside your existing patching tools — complementing products like Ivanti, SCCM, Intune, and others with open, vendor-neutral data and scanning that isn't tied to any one vendor's ecosystem.

Built by [Mark Shavlik](https://github.com/shavmark), creator of [HFNetChk](https://en.wikipedia.org/wiki/HFNetChk) (1999) and co-creator of the [Microsoft Baseline Security Analyzer](https://en.wikipedia.org/wiki/Microsoft_Baseline_Security_Analyzer) — the tools that secured millions of computers and created the patch management industry. A [Senserva](https://senserva.com) project — a member of the [Microsoft Intelligent Security Association (MISA)](https://www.microsoft.com/en-us/security/business/intelligent-security-association), an invite-only ecosystem of independent software vendors building security solutions on Microsoft technology.

---

## What's in This Repository

| Component | Description |
|-----------|-------------|
| `data/` | Pre-built SQLite patch database (`patches.db`) updated regularly |
| `src/` | The sync engine and all 38+ source implementations (C#) |
| `SOURCES.md` | Full documentation of every data source |
| `REPOSITORY.md` | Database schema, detection rule types, and query examples |

Both the data and the code that builds it live here. You can use the pre-built database directly, run the builder yourself, or contribute new sources.

---

## Coverage

| Platform | Sources | Applications / Packages |
|----------|:-------:|:-----------------------:|
| Windows | 29 | ~20,000+ |
| macOS | 4 | ~5,000+ |
| Linux | 3 | Ubuntu, Debian, RHEL/CentOS |
| CVE enrichment | 3 | NVD, OSV, GitHub Advisory |
| **Total** | **38 + 3** | **~25,000+ unique apps** |

| Metric | Typical Value |
|--------|:-------------:|
| Patch entries | ~20,000+ rows |
| Detection rules | ~40,000+ rows |
| CVEs tracked | ~30,000+ |
| CISA KEV (actively exploited) | ~1,200+ |
| Database size | 50–100 MB |
| Full sync time | 3–8 minutes |

---

## Quick Start

```bash
# First time — full pull from all 38 sources
curated repo init

# Later — incremental refresh (only what changed)
curated repo sync

# Check what you have
curated repo status
```

Or just use the pre-built database from `data/patches.db` — no build step required.

### Air-Gap Workflow

The database is a single `.db` file you can copy anywhere:

1. On a connected machine: `curated repo init`
2. Copy `patches.db` to a USB drive
3. Use it on the air-gapped machine — no internet needed at scan time

---

## Repository Builder — Command Reference

All repository management is under the `repo` subcommand.

### Global Option

```
--db <path>    Path to the SQLite database file
               Default: patches.db in the current directory
```

---

### `repo init`

Full pull from all 38 sources. Creates the schema and populates everything from scratch. Run this once.

```bash
curated repo init
curated repo init --db D:\patching\patches.db
```

---

### `repo sync`

Incremental refresh — only fetches changes since the last sync. Sources that support ETags or date cursors skip unchanged data. Run this on a schedule to keep the database current.

```bash
curated repo sync
curated repo sync --db D:\patching\patches.db
```

---

### `repo status`

Shows database statistics: total patch entries, vendors covered, detection rule count, CVE count, last sync time, and database file size.

```bash
curated repo status
```

---

### `repo cve <cve-id>`

Look up a specific CVE. Shows which patches address it, affected products, and CVSS score if enriched.

```bash
curated repo cve CVE-2025-21418
curated repo cve CVE-2024-43572 --db patches.db
```

---

### `repo enrich`

Enrich CVEs in the database with CVSS scores, severity ratings, CWE classifications, EPSS exploitation probability, and CISA KEV status. Pulls from NVD (NIST), OSV (Google), and GitHub Advisory Database.

Optional environment variables to increase API rate limits:
- `NVD_API_KEY` — raises NVD from 5 to 50 requests per 30 seconds
- `GITHUB_TOKEN` — raises GitHub Advisory from 60 to 5,000 requests per hour

```bash
curated repo enrich
```

---

### `repo export`

Export the local SQLite database as signed JSON files organized by bundle (`os`, `office`, `general`). Creates `manifest.json` and `manifest.sig` when a signing key is provided. Use this to publish the data to GitHub Pages or any static host so PatchCured scanners can consume it.

```
--output <dir>    Output directory for exported files  (required)
--key <path>      Path to RSA private key PEM file for signing
                  Also reads NETCHK25_SIGNING_KEY environment variable
```

```bash
curated repo export --output ./dist --key signing-key.pem
```

---

### `repo download`

Download a hosted patch repository (Azure Table Storage) into a local SQLite database. After download, scanning works fully offline with zero cloud dependency.

```
--table-url <url>    Azure Table URL for the patch repository  (required)
--sas <token>        SAS token with read permission           (required)
--api-key <key>      Senserva API key (for the public repo)
--db <path>          Output database path
```

```bash
curated repo download --table-url https://... --sas "?sv=..." --db patches.db
```

---

### `repo keygen`

Generate an RSA-2048 key pair for signing patch data exports. Produces `signing-key.pem` (private, keep secret) and `signing-key-public.pem` (distribute with the scanner).

```
--output <dir>    Directory for key files (default: current directory)
```

```bash
curated repo keygen --output ./keys
```

---

### `repo clone <o>`

Creates a compact, scan-ready copy of the database containing only active (non-superseded) patches. Superseded patches, their detection rules, sync history, and sync state are stripped out — producing a smaller file ideal for distributing to endpoints or air-gapped environments.

The cloned database is fully functional for scanning but cannot be incrementally synced (no sync state is included). To update it, re-clone from a freshly synced source.

```
<o>            Path for the cloned database file  (required)
--db <path>    Source database (default: patches.db in current directory)
```

```bash
# Clone the default repository
curated repo clone scan-ready.db

# Clone a specific source database
curated repo clone --db D:\full\patches.db D:\deploy\patches.db
```

Typical output:

```
Cloning repository (active patches only)...
  Source: patches.db
  Total patches: 4,200  (superseded: 1,350)

Clone complete: scan-ready.db
  Active patches: 2,850
  Size: 8.2 MB (was 14.7 MB — 44% smaller)
```

What is copied: active patches, detection rules for those patches, CVE links and enrichment data for active patches only, and schema metadata (`cloned_from`, `cloned_utc`). What is **not** copied: `sync_history`, `sync_state`, and superseded patch data. The clone uses SQLite `ATTACH DATABASE` to copy directly between files without loading into memory.

**Deployment workflows:**

```bash
# Sync, clone, distribute to a network share
curated repo sync
curated repo clone \\deploy\share\patches.db

# Air-gapped transfer — copy the single .db file to USB
curated repo sync
curated repo clone E:\transfer\patches.db

# CI/CD pipeline
curated repo clone $BUILD_ARTIFACTS/patches.db
```

| | Full Repository | Cloned Repository |
|---|---|---|
| Active patches | All | All |
| Superseded patches | Retained | Removed |
| Detection rules | All | Active patches only |
| CVE enrichment | All | Active patches only |
| Sync history | Full log | Not included |
| Sync state | Incremental cursors | Not included |

See [SCANNING.md](SCANNING.md) for how supersedence resolution works in the scanner.

---

## Database Schema

Five tables: `patches`, `detection_rules`, `sync_history`, `sync_state`, `repo_metadata`.

The `patches` table stores one row per patch per product per version. A single KB article can have multiple rows if it applies to different product versions. The upsert logic merges data from multiple sources — non-empty values overwrite blanks, but never erase existing data.

See [REPOSITORY.md](REPOSITORY.md) for the full schema, detection rule types, and example SQL queries.

### Detection Rule Types

| Platform | Rule Type | What It Checks |
|----------|-----------|----------------|
| Windows | `FileVersion` | PE file version of an EXE or DLL |
| Windows | `RegistryKey` | Whether a registry key exists |
| Windows | `RegistryValue` | A registry value compared to an expected version |
| Windows | `MsiProductCode` | An installed MSI product by GUID |
| Windows | `UninstallDisplayVersion` | Version from Add/Remove Programs (wildcard support) |
| macOS | `BundleVersion` | `CFBundleShortVersionString` from an app bundle |
| macOS | `PlistValue` | A key from any `.plist` file |
| Linux | `PackageVersion` | Installed package version via `dpkg` or `rpm` |

---

## What the Data Covers

### Windows — 29 Sources

- **Microsoft OS & Infrastructure** — MSRC API, Windows cumulative updates, Microsoft Update Catalog, WSUS cab, Edge, Office 365, .NET, Teams
- **Bulk App Repository** — WinGet (~4,700+ apps from `microsoft/winget-pkgs`)
- **Browsers** — Chrome (with CVE extraction), Firefox (with MFSA data)
- **Communication** — Zoom (with security bulletins), Slack
- **Enterprise & Security** — Java/Adoptium, Adobe Acrobat/Reader, PuTTY, WinSCP
- **IT Utilities** — 7-Zip, WinRAR, Notepad++, FileZilla, VLC, Wireshark, KeePass, OBS Studio
- **Developer Tools** — VS Code, Node.js, Python, Git, PowerShell, curl, OpenSSH

### macOS — 4 Sources

- **Apple System** — macOS security updates (Sequoia, Sonoma, Ventura, Monterey, Big Sur)
- **Apple Apps** — Safari, Xcode
- **Bulk App Repository** — Homebrew Cask (~5,000+ macOS GUI applications)

### Linux — 3 Sources

- **Ubuntu** — Ubuntu Security Notices (USN) via the Canonical Security API
- **Debian** — Full Debian Security Tracker (Bookworm, Trixie, Bullseye)
- **Red Hat / RHEL / CentOS / Fedora** — Red Hat Security Data API with CVE and RPM data

### CVE Enrichment — 3 Sources

| Field | Source |
|-------|--------|
| CVSS v3.x / v4.0 score | NVD, GitHub Advisory |
| CVSS vector string | NVD, OSV, GitHub Advisory |
| CWE weakness classification | NVD, OSV, GitHub Advisory |
| EPSS exploitation probability | NVD |
| CISA KEV (actively exploited) | NVD |
| Human-readable description | NVD, OSV, GitHub Advisory |

---

## Sync Architecture

All 38 sources run concurrently with up to 8 parallel workers. A failure in one source does not block any other — each runs inside its own try/catch and the sync history table records every outcome. After all sources finish, a summary shows patches added, rules created, sources that succeeded, and any failures.

The only dependency: `WindowsCU` waits for `MSRC` to finish (it needs MSRC's severity data before processing cumulative updates).

Incremental sync uses ETags, date cursors, or both per source — so after the first `init`, `sync` only fetches what changed. WinGet's 4,700+ packages sync in batches of 500 per transaction and finish in seconds.

---

## Contributing

Adding a new source requires two steps:

1. Create one C# file in `src/Sources/` implementing `IPatchSource`:

```csharp
public interface IPatchSource
{
    string Name        { get; }
    string Description { get; }
    Task<SyncResult> SyncAsync(
        PatchRepository repo,
        bool incremental,
        IProgress<string>? progress = null);
}
```

2. Add one line to the `_sources` list in `RepoSyncEngine.cs`.

### Wanted Sources

Community contributions are especially welcome for:

- **More Linux distributions** — SUSE, Alpine, Arch, Rocky, Alma, Amazon Linux
- **Linux package managers** — Flatpak, Snap advisories
- **Cloud CLI tools** — AWS CLI, Azure CLI, gcloud, Terraform, kubectl
- **Container images** — Docker Hub official images, distroless base images
- **Additional Windows / macOS apps** — anything with a public version API or release feed
- **IoT / embedded** — firmware version tracking for network devices and printers

See [SOURCES.md](SOURCES.md) for the full source list and the interface details.

### Get Involved

Whether you want to contribute a new patch source, improve existing ones, or become a regular collaborator with write access — you're welcome here. Open an issue to introduce yourself or discuss an idea, or just submit a pull request. If you'd like to be added as a collaborator, reach out via an issue and we'll go from there.

---

## License

| Component | License |
|-----------|---------|
| Source code (`src/`) | [MIT](LICENSE-MIT) |
| Patch data (`data/`) | [CC BY 4.0](LICENSE-DATA) — free to use, including commercially, with attribution |

The data aggregated here is derived from public sources. Each upstream source has its own terms; see [SOURCES.md](SOURCES.md) for details. Red Hat CVE data is CC BY 4.0 licensed upstream.

---

## About PatchCured

[PatchCured](https://github.com/Senserva/PatchCured) is the free patch scanner for Windows, macOS, and Linux — built on [PatchCurated](https://github.com/Senserva/PatchCurated) data, with commercial remediation tiers. Like HFNetChk and MBSA before it, PatchCured has a powerful free version — full patch scanning at no cost, with commercial features (fleet management, automated remediation, reporting, Azure integration) available in paid tiers. A [Senserva](https://senserva.com) product.

Senserva is actively building additional patch scanners and remediation tools on top of [PatchCurated](https://github.com/Senserva/PatchCurated) data. [PatchCurated](https://github.com/Senserva/PatchCurated) is the shared foundation — one community-maintained data layer, multiple tools built on it.

---

## Origin

In 2001, Mark Shavlik released **HFNetChk** — the first agentless patch scanner for Windows NT. Microsoft needed a tool to detect missing hotfixes across large NT server environments without installing any agent software. Shavlik built it: a command-line scanner that connected over the network, read file versions and registry keys, and reported which patches were missing. It was free.

HFNetChk was downloaded and used by millions of administrators. Microsoft noticed. Shavlik partnered with Microsoft to build the **Microsoft Baseline Security Analyzer (MBSA)** — a free GUI tool delivered as part of the Windows 2000 Server Toolkit that combined HFNetChk's patch scanning engine with OS configuration checks for IIS, SQL Server, and Windows security settings. MBSA went on to scan over 3 million computers per week at its peak. It was the standard for patch compliance in enterprises worldwide for over a decade.

Shavlik went on to found **Shavlik Technologies**, which turned HFNetChk into a full commercial patch management platform — scanning, deploying, and reporting across physical and virtual environments. Shavlik Technologies was acquired by VMware in 2011, then by LANDESK in 2013. LANDESK merged with HEAT Software in 2017 to form **Ivanti**. Today the same HFNetChk-lineage technology is a core part of Ivanti's security portfolio. Mark Shavlik is not affiliated with Ivanti.

After VMware, Mark founded [Senserva](https://senserva.com), focused on Microsoft 365 and Azure security auditing — and was accepted into the [Microsoft Intelligent Security Association (MISA)](https://www.microsoft.com/en-us/security/business/intelligent-security-association), an invite-only program for independent software vendors building best-in-class security solutions on Microsoft technology. Now, 25 years after HFNetChk, he's back in patch management with the 25th anniversary editions — because there is no public repository and simple scanner for it, and there should be.

**[PatchCurated](https://github.com/Senserva/PatchCurated)** is the open data layer he always wanted to exist: a community-maintained, vendor-neutral patch intelligence database covering Windows, macOS, and Linux — not locked to any vendor, not dependent on any cloud service. **PatchCured** is the scanner built on it, with the same philosophy as the originals: powerful, free to use and for pay versions that include remediation, and built for the people who actually have to keep systems patched.
