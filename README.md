# Dependency Scanner — Core

Scans project manifests for known vulnerabilities (via [OSV.dev](https://osv.dev)),
license risks and maintenance signals, and produces a combined risk score.

Open-source core (MIT) of a commercial SCA service.

## Supported ecosystems

| Ecosystem | Manifests | Status |
|---|---|---|
| Python | `requirements.txt`, `poetry.lock`, `pyproject.toml` | **Production** — verified on real projects |
| Node.js | `package.json`, `package-lock.json` | **Production** — verified on real projects |
| Go | `go.mod` | **Production** — verified on real projects |
| Java | `pom.xml` | Experimental — **disabled** (see below) |
| Rust | `Cargo.toml` | Experimental — **disabled** (see below) |
| Ruby | `Gemfile.lock` | Experimental |

**Why Java/Rust are disabled:** stress-testing against real manifests
(`apache/commons-lang`, `BurntSushi/ripgrep`) showed the Maven parser merged
multiple `<dependency>` blocks into single entries — package names contained raw
XML and versions bled between packages. Sending that to a vulnerability database
produces false results, which is worse than no results. Rust inline tables
(`dep = { version = "1.0", path = "..." }`) are parsed incompletely. Both parsers
return empty until fixed properly.

## Design principles

**Deterministic results.** A single OSV `querybatch` request per scan; network
errors propagate instead of being silently swallowed. Running the same scan
three times returns the same number — a requirement for audit use.

**Penalties only for verifiable facts.** Missing data is not a risk. Unknown
licenses, version heuristics, and the mere existence of transitive dependencies
are reported as *observations*, never as score inflation. Score comes from real
CVEs, copyleft licenses, unpinned version ranges, and confirmed-outdated packages.

## Usage

```bash
git clone https://github.com/Edurd987/devops-scanner-core.git
cd devops-scanner-core

# scan a directory (declared dependencies only, no network)
python dependency_scanner.py /path/to/project

# include vulnerability data from OSV.dev
python dependency_scanner.py /path/to/project --osv

# other formats and filters
python dependency_scanner.py /path/to/project --osv -f json
python dependency_scanner.py /path/to/project --ecosystem npm --severity high
```

Requires Python 3.10+. No third-party dependencies.

## Scope and limitations

- Analyses **declared** dependencies. Manifests with ranges (`>=2.11.0`) are
  matched as ranges, so some findings may not apply to the exact installed
  version. Lock files give precise results.
- License detection currently relies on a small built-in mapping; most packages
  resolve as `Unknown`. Registry-based license enrichment is planned.
- No reachability analysis — every known CVE is reported, not filtered by
  whether the vulnerable code path is actually used.

## Commercial version

CycloneDX SBOM export, web dashboard, scan history, authenticated API and
audit-ready reports are part of the hosted service, not this repository.

## License

MIT — see [LICENSE](LICENSE).
