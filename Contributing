# Contributing to PatchCurated

Thanks for your interest in contributing. PatchCurated lives or dies by its data coverage — every new source you add means more applications monitored, more CVEs caught, and more systems kept patched.

---

## Ways to Contribute

- **Add a new patch source** — the highest-value contribution (see below)
- **Improve an existing source** — better CVE extraction, more detection rules, bug fixes
- **Expand Linux coverage** — new distros, package managers (Flatpak, Snap, Alpine, etc.)
- **Report bad data** — wrong versions, missing patches, incorrect detection rules
- **Fix bugs** — open an issue or submit a PR
- **Improve documentation** — clarify anything that was confusing

---

## Adding a New Patch Source

This is the core contribution. The interface is minimal — one C# file, one line in the engine.

### Step 1 — Implement `IPatchSource`

Create a new file in `src/Sources/` named after your source (e.g., `SlackSource.cs`):

```csharp
public class MyAppSource : IPatchSource
{
    public string Name        => "MyApp";
    public string Description => "MyApp releases from myapp.com/releases";

    public async Task<SyncResult> SyncAsync(
        PatchRepository repo,
        bool incremental,
        IProgress<string>? progress = null)
    {
        // 1. Fetch version data from upstream
        // 2. Build PatchEntry objects
        // 3. Call repo.UpsertAsync(entry) for each one
        // 4. Return SyncResult with counts
    }
}
```

### Step 2 — Register the source

Add one line to the `_sources` list in `src/RepoSyncEngine.cs`:

```csharp
new MyAppSource(),
```

That's it. The sync engine handles scheduling, error isolation, progress display, and history logging automatically.

### What makes a good source

- **A reliable public feed** — a JSON API, RSS feed, GitHub Releases API, or a stable download page. Avoid scraping pages that change layout frequently.
- **Version data** — at minimum a version string and a release date.
- **At least one FileVersion detection rule** — the file path and minimum version that confirms the patch is installed. FileVersion rules are the only ones evaluated by the scanner; other rule types (registry, MSI) are stored but not used for detection.
- **Incremental support if possible** — check for an ETag or a `Last-Modified` header and skip unchanged data on subsequent syncs. Look at `ChromeSource.cs` or `WinGetSource.cs` for examples.

### Existing sources to reference

| Source | Good example of |
|--------|----------------|
| `ChromeSource.cs` | JSON API + CVE extraction from release notes |
| `WinGetSource.cs` | Bulk YAML manifest parsing, ETag sync, batched inserts |
| `FirefoxSource.cs` | Security advisory (MFSA) cross-referencing |
| `NodeJsSource.cs` | Multiple release channels (LTS + Current) |
| `UbuntuUsnSource.cs` | Linux PackageVersion rules, paginated API |
| `GitHubReleaseHelper.cs` | Reusable helper for any GitHub Releases-backed app |

---

## Wanted Sources

These are confirmed gaps — contributions for any of these are immediately useful:

**Linux distributions**
- SUSE / openSUSE
- Alpine Linux
- Arch Linux / Manjaro
- Rocky Linux / Alma Linux / Oracle Linux
- Amazon Linux

**Linux package managers**
- Flatpak (Flathub advisories)
- Snap Store security notices

**Cloud & DevOps tools**
- AWS CLI
- Azure CLI
- gcloud SDK
- Terraform / OpenTofu
- kubectl / Helm

**Container images**
- Docker Hub official images
- Distroless base images

**Additional Windows / macOS apps**
- Any application with a public version API, GitHub Releases feed, or stable release page

**IoT / Embedded**
- Network device firmware (routers, switches, printers)

---

## Development Setup

### Prerequisites

- .NET 8 SDK or later
- SQLite (for testing the database)

### Build

```bash
dotnet build
```

### Run a full repo init locally

```bash
dotnet run -- repo init --db test.db
```

### Run tests

```bash
dotnet test
```

### Test your source in isolation

The fastest way to test a new source is to call it directly in a small test program or unit test, passing a fresh in-memory `PatchRepository`. Look at the existing tests in `src/Tests/` for examples.

---

## Pull Request Guidelines

- **One source per PR** — keeps reviews focused and makes it easy to merge or defer independently
- **Include at least one detection rule** — a patch entry with no FileVersion rule will be stored but marked undetectable
- **Test with `repo init`** — make sure your source runs cleanly end-to-end before submitting
- **Handle failures gracefully** — wrap network calls in try/catch and return a `SyncResult` with `Success = false` and an error message rather than throwing
- **No hardcoded credentials** — all API keys must come from environment variables

---

## Reporting Bad Data

If you find a patch entry with a wrong version, a missing CVE, or a detection rule that doesn't work, open an issue with:

- The `patch_id` value from the database
- What the data says vs. what it should say
- A link to the upstream source confirming the correct value

---

## Becoming a Collaborator

If you've submitted a few good PRs and want to get more involved — direct commit access, helping review PRs, maintaining a group of sources — open an issue and introduce yourself. We're happy to add trusted contributors as collaborators.

---

## Code of Conduct

Be straightforward, be helpful, assume good intent. This is a technical project focused on doing useful work. Keep discussions on-topic and constructive.

---

## Contributing to PatchCured

PatchCurated is the data layer. [PatchCured](https://github.com/patchcured) is the free scanner built on top of it — and it needs help too.

If you're interested in contributing to the scanner itself, the highest-value areas are:

- **Detection rule coverage** — verifying and improving FileVersion rules for specific applications
- **Platform support** — macOS and Linux scanning improvements
- **Reporting** — new output formats, report templates, integrations
- **Remediation workflows** — automated patch deployment for specific vendors and app types

The PatchCured scanner uses the same `IPatchSource` interface and the same SQLite database. Contributing to PatchCurated data automatically makes PatchCured more accurate. Contributing to PatchCured scanning improves what anyone can build on PatchCurated data.

Both projects are by [Senserva](https://senserva.com). Open issues on the respective repos or introduce yourself and we'll point you in the right direction.

---

## Questions

Open an issue with the `question` label. For anything sensitive, contact [mark@senserva.com](mailto:mark@senserva.com).
