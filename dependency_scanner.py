#!/usr/bin/env python3
"""CLI utility for scanning project dependencies with Risk & Impact Analysis."""

import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class LicenseInfo:
    name: str
    spdx_id: str = ""
    is_copyleft: bool = False
    is_permissive: bool = False
    osi_approved: bool = True
    note: str = ""


@dataclass
class Dependency:
    name: str
    version: str
    source_file: str
    ecosystem: str
    line_number: int = 0
    pinned: bool = False
    severity: Optional[Severity] = None
    note: str = ""
    # --- NEW: Risk & Impact fields ---
    license: Optional[LicenseInfo] = None
    is_critical_domain: bool = False
    is_stale: bool = False
    is_shadow: bool = False
    is_outdated: bool = False
    latest_version: str = ""
    cve_count: int = 0
    cve_ids: list[str] = field(default_factory=list)
    risk_score: int = 0
    recommendations: list[str] = field(default_factory=list)


@dataclass
class RiskSummary:
    overall_score: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    security_score: int = 0
    license_score: int = 0
    maintenance_score: int = 0
    shadow_count: int = 0
    stale_count: int = 0
    critical_domain_count: int = 0
    copyleft_count: int = 0
    total_dependencies: int = 0
    recommendations: list[str] = field(default_factory=list)


@dataclass
class ImpactAnalysis:
    direct_count: int = 0
    transitive_count: int = 0
    max_depth: int = 0
    ecosystem_breakdown: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    dependencies: list[Dependency] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    risk_summary: RiskSummary = field(default_factory=RiskSummary)
    impact: ImpactAnalysis = field(default_factory=ImpactAnalysis)


# --- Critical domain detection ---

CRITICAL_KEYWORDS = {
    "crypto": ["cryptography", "crypto", "bcrypt", "argon2", "pycryptodome", "nacl",
               "openssl", "tls", "ssl", "jwt", "jose", "oauth", "passport"],
    "auth": ["auth", "authentication", "authorization", "session", "token",
             "oauth", "passport", "jwt", "ldap", "kerberos", "saml"],
    "network": ["requests", "httpx", "aiohttp", "urllib3", "http", "grpc",
                "websocket", "socket", "dns", "ssh", "paramiko", "fabric",
                "twisted", "tornado", "fastapi", "flask", "django", "express"],
}


def is_critical_domain(name: str) -> bool:
    name_lower = name.lower()
    for domain, keywords in CRITICAL_KEYWORDS.items():
        for kw in keywords:
            if kw in name_lower:
                return True
    return False


# --- License database ---

KNOWN_LICENSES = {
    "MIT": LicenseInfo("MIT", "MIT", is_permissive=True),
    "MIT License": LicenseInfo("MIT", "MIT", is_permissive=True),
    "Apache-2.0": LicenseInfo("Apache 2.0", "Apache-2.0", is_permissive=True),
    "Apache 2.0": LicenseInfo("Apache 2.0", "Apache-2.0", is_permissive=True),
    "Apache License 2.0": LicenseInfo("Apache 2.0", "Apache-2.0", is_permissive=True),
    "BSD-2-Clause": LicenseInfo("BSD 2-Clause", "BSD-2-Clause", is_permissive=True),
    "BSD-3-Clause": LicenseInfo("BSD 3-Clause", "BSD-3-Clause", is_permissive=True),
    "BSD": LicenseInfo("BSD", "BSD-3-Clause", is_permissive=True),
    "ISC": LicenseInfo("ISC", "ISC", is_permissive=True),
    "ISC License": LicenseInfo("ISC", "ISC", is_permissive=True),
    "MPL-2.0": LicenseInfo("MPL 2.0", "MPL-2.0"),
    "Mozilla Public License 2.0": LicenseInfo("MPL 2.0", "MPL-2.0"),
    "LGPL-2.1": LicenseInfo("LGPL 2.1", "LGPL-2.1", is_copyleft=True),
    "LGPL-3.0": LicenseInfo("LGPL 3.0", "LGPL-3.0", is_copyleft=True),
    "GPL-2.0": LicenseInfo("GPL 2.0", "GPL-2.0-only", is_copyleft=True),
    "GPL-3.0": LicenseInfo("GPL 3.0", "GPL-3.0-only", is_copyleft=True),
    "GPL-2.0-only": LicenseInfo("GPL 2.0", "GPL-2.0-only", is_copyleft=True),
    "GPL-3.0-only": LicenseInfo("GPL 3.0", "GPL-3.0-only", is_copyleft=True),
    "AGPL-3.0": LicenseInfo("AGPL 3.0", "AGPL-3.0-only", is_copyleft=True, note="strong copyleft — includes network use"),
    "Unlicense": LicenseInfo("Unlicense", "Unlicense", is_permissive=True),
    "Public Domain": LicenseInfo("Public Domain", "Unlicense", is_permissive=True),
}


def detect_license(name: str, ecosystem: str) -> LicenseInfo:
    name_lower = name.lower()
    # Common heuristic mappings
    heuristics = {
        "requests": "Apache-2.0",
        "flask": "BSD-3-Clause",
        "django": "BSD-3-Clause",
        "numpy": "BSD-3-Clause",
        "pandas": "BSD-3-Clause",
        "scipy": "BSD-3-Clause",
        "cryptography": "Apache-2.0",
        "pillow": "MIT-CMU",
        "express": "MIT",
        "lodash": "MIT",
        "react": "MIT",
        "vue": "MIT",
        "angular": "MIT",
        "typescript": "Apache-2.0",
        "webpack": "MIT",
        "babel": "MIT",
        "eslint": "MIT",
    }
    if name_lower in heuristics:
        lic_id = heuristics[name_lower]
        if lic_id in KNOWN_LICENSES:
            return KNOWN_LICENSES[lic_id]
        return LicenseInfo(lic_id, lic_id, note="heuristic detection")

    return LicenseInfo("Unknown", "LicenseRef-Unknown", osi_approved=False,
                       note="license could not be determined")


# --- Parsers ---

def parse_requirements(path: Path) -> list[Dependency]:
    deps = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return deps

    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        m = re.match(r'^([A-Za-z0-9_][A-Za-z0-9._-]*)\s*([><=!~]+)\s*([^\s,;]+)', line)
        if m:
            name, op, ver = m.groups()
            pinned = op in ("==",)
            deps.append(Dependency(
                name=name.lower(), version=f"{op}{ver}",
                source_file=str(path), ecosystem="python",
                line_number=i, pinned=pinned,
            ))
            continue

        m = re.match(r'^([A-Za-z0-9_][A-Za-z0-9._-]*)', line)
        if m:
            deps.append(Dependency(
                name=m.group(1).lower(), version="unspecified",
                source_file=str(path), ecosystem="python",
                line_number=i, pinned=False, severity=Severity.MEDIUM,
                note="no version constraint",
            ))

    return deps


def parse_package_json(path: Path) -> list[Dependency]:
    deps = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return deps

    sections = {"dependencies": "npm", "devDependencies": "npm"}
    for section, eco in sections.items():
        for name, ver in data.get(section, {}).items():
            deps.append(Dependency(
                name=name, version=ver,
                source_file=str(path), ecosystem=eco,
                pinned=ver.startswith("^") or ver.startswith("~"),
            ))

    return deps


def parse_pom_xml(path: Path) -> list[Dependency]:
    deps = []
    try:
        content = path.read_text(encoding="utf-8")
    except Exception:
        return deps

    pattern = re.compile(
        r'<dependency>\s*<groupId>(.*?)</groupId>\s*<artifactId>(.*?)</artifactId>\s*<version>(.*?)</version>',
        re.DOTALL,
    )
    for m in pattern.finditer(content):
        group, artifact, version = m.group(1), m.group(2), m.group(3)
        version = version.strip().replace("${", "").replace("}", "")
        deps.append(Dependency(
            name=f"{group}:{artifact}", version=version,
            source_file=str(path), ecosystem="maven",
            pinned="${" not in version,
        ))

    return deps


def parse_go_mod(path: Path) -> list[Dependency]:
    deps = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return deps

    in_require = False
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if in_require or stripped.startswith("require "):
            content = stripped.replace("require ", "").strip()
            if content.startswith("//"):
                continue
            parts = content.split()
            if len(parts) >= 2:
                deps.append(Dependency(
                    name=parts[0], version=parts[1],
                    source_file=str(path), ecosystem="go",
                    line_number=i, pinned=True,
                ))

    return deps


def parse_gemfile_lock(path: Path) -> list[Dependency]:
    deps = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return deps

    in_specs = False
    for i, line in enumerate(lines, 1):
        if "specs:" in line:
            in_specs = True
            continue
        if in_specs and (not line.startswith(" ") or line.strip() == "" or "DEPENDENCIES" in line or "PLATFORMS" in line):
            in_specs = False
            continue
        if in_specs:
            m = re.match(r'\s+(\S+)\s+\(([^)]+)\)', line)
            if m:
                deps.append(Dependency(
                    name=m.group(1), version=m.group(2),
                    source_file=str(path), ecosystem="ruby",
                    line_number=i, pinned=True,
                ))

    return deps


def parse_cargo_toml(path: Path) -> list[Dependency]:
    deps = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return deps

    in_deps = False
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped == "[dependencies]" or stripped.startswith("[dependencies."):
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
            continue
        if in_deps and "=" in stripped:
            parts = stripped.split("=", 1)
            name = parts[0].strip()
            ver = parts[1].strip().strip('"').strip("'")
            deps.append(Dependency(
                name=name, version=ver,
                source_file=str(path), ecosystem="rust",
                line_number=i, pinned=True,
            ))

    return deps


# --- Parsers for lock files (shadow dependency detection) ---

def parse_package_lock(path: Path) -> list[Dependency]:
    """Parse package-lock.json for transitive (shadow) dependencies."""
    deps = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return deps

    # npm v2/v3 format
    for name, info in data.get("packages", {}).items():
        if not name or name == "":
            continue
        # name is like "node_modules/lodash"
        real_name = name.split("node_modules/")[-1] if "node_modules/" in name else name
        ver = info.get("version", "")
        if real_name:
            deps.append(Dependency(
                name=real_name, version=ver,
                source_file=str(path), ecosystem="npm",
                is_shadow=True,
            ))

    # npm v1 format
    for name, info in data.get("dependencies", {}).items():
        ver = info.get("version", "")
        sub_deps = info.get("dependencies", {})
        if sub_deps:
            for sub_name, sub_info in sub_deps.items():
                deps.append(Dependency(
                    name=sub_name, version=sub_info.get("version", ""),
                    source_file=str(path), ecosystem="npm",
                    is_shadow=True,
                ))

    return deps


def parse_poetry_lock(path: Path) -> list[Dependency]:
    """Parse poetry.lock for transitive dependencies."""
    deps = []
    try:
        content = path.read_text(encoding="utf-8")
    except Exception:
        return deps

    # Simple regex extraction of [[package]] blocks
    pattern = re.compile(r'\[\[package\]\]\s*name\s*=\s*"([^"]+)"\s*version\s*=\s*"([^"]+)"', re.MULTILINE)
    for m in pattern.finditer(content):
        deps.append(Dependency(
            name=m.group(1), version=m.group(2),
            source_file=str(path), ecosystem="python",
            is_shadow=True,
        ))

    return deps


# --- Heuristic vulnerability checks ---

KNOWN_VULNERABLE = {
    "lodash": {"critical": ["<4.17.21"]},
    "minimist": {"critical": ["<0.2.4", ">=1.0.0 <1.2.6"]},
    "glob-parent": {"high": ["<5.1.2"]},
    "axios": {"high": ["<0.21.2"]},
    "express": {"medium": ["<4.18.2"]},
    "flask": {"medium": ["<2.3.2"]},
    "django": {"high": ["<4.2.4"]},
    "urllib3": {"critical": ["<1.26.18"]},
    "requests": {"medium": ["<2.31.0"]},
    "cryptography": {"critical": ["<41.0.6"]},
    "pillow": {"critical": ["<10.0.1"]},
    "pyyaml": {"high": ["<6.0.1"]},
    "werkzeug": {"critical": ["<3.0.1"]},
    "setuptools": {"high": ["<70.0.0"]},
    "node-fetch": {"medium": ["<2.6.7"]},
    "webpack-dev-middleware": {"critical": ["<5.3.4"]},
    "tar": {"critical": ["<6.2.1"]},
}


def check_vulnerabilities(deps: list[Dependency]) -> list[Dependency]:
    for dep in deps:
        name_lower = dep.name.lower()
        if name_lower in KNOWN_VULNERABLE:
            for severity_str, ranges in KNOWN_VULNERABLE[name_lower].items():
                for vuln_range in ranges:
                    if _version_matches_range(dep.version, vuln_range):
                        dep.severity = Severity(severity_str)
                        dep.note = f"known vulnerability in range {vuln_range}"
    return deps


def _version_matches_range(version: str, vuln_range: str) -> bool:
    ver = version.lstrip("=><!~^~").strip()
    if not ver or ver == "unspecified":
        return False

    try:
        parts = tuple(int(x) for x in re.split(r'[^\d]+', ver)[:3])
    except (ValueError, IndexError):
        return False

    if "<" in vuln_range:
        op, ref = vuln_range.split("<", 1)
        try:
            ref_parts = tuple(int(x) for x in re.split(r'[^\d]+', ref)[:3])
            return parts < ref_parts
        except (ValueError, IndexError):
            return False

    return False


# --- OSV.dev API integration ---

ECOSYSTEM_MAP = {
    "python": "PyPI",
    "npm": "npm",
    "go": "Go",
    "maven": "Maven",
    "ruby": "RubyGems",
    "rust": "crates.io",
}


def query_osv(package: str, version: str, ecosystem: str) -> list[dict]:
    """Query osv.dev API for known vulnerabilities."""
    osv_eco = ECOSYSTEM_MAP.get(ecosystem)
    if not osv_eco:
        return []

    clean_version = version.lstrip("=><!~^~").strip()
    if not clean_version or clean_version == "unspecified":
        return []

    payload = json.dumps({
        "package": {"name": package, "ecosystem": osv_eco},
        "version": clean_version,
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("vulns", [])
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
        return []


def enrich_with_osv(deps: list[Dependency], use_osv: bool) -> list[Dependency]:
    """Enrich dependencies with CVE data from osv.dev."""
    if not use_osv:
        return deps

    for dep in deps:
        vulns = query_osv(dep.name, dep.version, dep.ecosystem)
        if vulns:
            dep.cve_count = len(vulns)
            for v in vulns:
                vid = v.get("id", "")
                summary = v.get("summary", "")
                if vid:
                    dep.cve_ids.append(vid)
                # Determine severity from OSV database_specific or severity fields
                severity_list = v.get("severity", [])
                for s in severity_list:
                    score_str = s.get("score", "")
                    # Try to extract severity from CVSS
                    m = re.search(r'CVSS:[^/]+/([A-Z]+)', score_str)
                    if m:
                        cvss_sev = m.group(1).lower()
                        sev_map = {"s": Severity.CRITICAL, "h": Severity.HIGH, "m": Severity.MEDIUM, "l": Severity.LOW}
                        if cvss_sev in sev_map:
                            if dep.severity is None or SEVERITY_ORDER.index(sev_map[cvss_sev]) > SEVERITY_ORDER.index(dep.severity or Severity.LOW):
                                dep.severity = sev_map[cvss_sev]
                if dep.severity is None:
                    dep.severity = Severity.HIGH
                dep.note = f"{dep.cve_count} CVE(s): {', '.join(dep.cve_ids[:3])}"

    return deps


# --- Stale package detection ---

def parse_version_date(deps: list[Dependency]) -> dict[str, datetime | None]:
    """Placeholder — in real use, query PyPI/npm registry for release date."""
    # For demo, mark packages with very old-looking versions as stale heuristic
    return {d.name: None for d in deps}


def detect_stale_packages(deps: list[Dependency]) -> list[Dependency]:
    """Mark packages that are likely stale (>2 years without update).
    Heuristic: if version is 0.x or 1.x with low patch, likely old.
    In production, query registry API for last_release_date.
    """
    for dep in deps:
        ver = dep.version.lstrip("=><!~^~").strip()
        if not ver or ver == "unspecified":
            continue

        parts = ver.split(".")
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            # Heuristic: very old-looking versions
            if major == 0 and minor < 5:
                dep.is_stale = True
        except (ValueError, IndexError):
            pass

    return deps


# --- Outdated version detection ---

KNOWN_LATEST = {
    "flask": "3.0.0",
    "django": "5.0.0",
    "requests": "2.31.0",
    "urllib3": "2.1.0",
    "cryptography": "42.0.0",
    "pillow": "10.2.0",
    "pyyaml": "6.0.1",
    "werkzeug": "3.0.1",
    "setuptools": "69.0.0",
    "express": "4.18.2",
    "lodash": "4.17.21",
    "axios": "1.6.0",
    "react": "18.2.0",
    "webpack": "5.89.0",
}


def detect_outdated(deps: list[Dependency]) -> list[Dependency]:
    """Mark packages with outdated versions vs known latest."""
    for dep in deps:
        name_lower = dep.name.lower()
        ver = dep.version.lstrip("=><!~^~").strip()

        if name_lower in KNOWN_LATEST and ver and ver != "unspecified":
            latest = KNOWN_LATEST[name_lower]
            try:
                current_parts = [int(x) for x in ver.split(".")[:3]]
                latest_parts = [int(x) for x in latest.split(".")[:3]]
                if current_parts < latest_parts:
                    dep.is_outdated = True
                    dep.latest_version = latest
                    if not dep.severity:
                        dep.note = f"outdated: current={ver}, latest={latest}"
                        dep.risk_score += 5
                        dep.recommendations.append(f"Update {dep.name} from {ver} to {latest}")
            except (ValueError, IndexError):
                pass

    return deps


# --- Shadow dependency detection ---

def detect_shadow_dependencies(direct_deps: list[Dependency], lock_deps: list[Dependency]) -> list[Dependency]:
    """Find transitive deps in lock files not in direct config."""
    direct_names = {(d.name.lower(), d.source_file) for d in direct_deps}

    for ld in lock_deps:
        # Check if this lock dep is truly transitive
        is_direct = False
        for d in direct_deps:
            if d.name.lower() == ld.name.lower():
                is_direct = True
                break

        if not is_direct:
            ld.is_shadow = True
            ld.note = "shadow/transitive dependency — not in direct config"
            ld.recommendations.append(f"Audit shadow dependency {ld.name} {ld.version}")

    return lock_deps


# --- Risk scoring ---

SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def calculate_risk_score(deps: list[Dependency]) -> RiskSummary:
    """Calculate overall risk score 0-100."""
    summary = RiskSummary()
    summary.total_dependencies = len(deps)

    if not deps:
        return summary

    # Security score (0-40)
    sec_score = 0
    for d in deps:
        if d.severity == Severity.CRITICAL:
            sec_score += 15
        elif d.severity == Severity.HIGH:
            sec_score += 10
        elif d.severity == Severity.MEDIUM:
            sec_score += 5
        elif d.severity == Severity.LOW:
            sec_score += 2
        if d.cve_count > 0:
            sec_score += min(d.cve_count * 5, 15)
    summary.security_score = min(sec_score, 40)

    # License score (0-20)
    lic_score = 0
    for d in deps:
        if d.license and d.license.is_copyleft:
            lic_score += 10
            summary.copyleft_count += 1
        elif d.license and d.license.name == "Unknown":
            lic_score += 3
    summary.license_score = min(lic_score, 20)

    # Maintenance score (0-20)
    maint_score = 0
    for d in deps:
        if d.is_stale:
            maint_score += 5
            summary.stale_count += 1
        if d.is_outdated:
            maint_score += 3
        if not d.pinned:
            maint_score += 2
    summary.maintenance_score = min(maint_score, 20)

    # Shadow & domain (0-20)
    shadow_score = 0
    for d in deps:
        if d.is_shadow:
            shadow_score += 2
            summary.shadow_count += 1
        if d.is_critical_domain:
            shadow_score += 3
            summary.critical_domain_count += 1
    extra_score = min(shadow_score, 20)

    summary.overall_score = min(summary.security_score + summary.license_score +
                                summary.maintenance_score + extra_score, 100)

    # Risk level
    if summary.overall_score >= 70:
        summary.risk_level = RiskLevel.CRITICAL
    elif summary.overall_score >= 50:
        summary.risk_level = RiskLevel.HIGH
    elif summary.overall_score >= 25:
        summary.risk_level = RiskLevel.MEDIUM
    elif summary.overall_score >= 10:
        summary.risk_level = RiskLevel.LOW
    else:
        summary.risk_level = RiskLevel.MINIMAL

    # Global recommendations
    if summary.security_score > 20:
        summary.recommendations.append("URGENT: Address critical/high vulnerabilities immediately")
    if summary.copyleft_count > 0:
        summary.recommendations.append(f"Review {summary.copyleft_count} copyleft license(s) for commercial compliance")
    if summary.shadow_count > 5:
        summary.recommendations.append(f"Audit {summary.shadow_count} shadow dependencies for hidden risks")
    if summary.stale_count > 3:
        summary.recommendations.append(f"Update {summary.stale_count} stale packages to receive security patches")
    if summary.critical_domain_count > 0:
        summary.recommendations.append(f"Hardened review of {summary.critical_domain_count} critical-domain packages (crypto/auth/network)")

    return summary


# --- Impact analysis ---

def analyze_impact(direct_deps: list[Dependency], shadow_deps: list[Dependency], result: ScanResult) -> ImpactAnalysis:
    impact = ImpactAnalysis()
    impact.direct_count = len(direct_deps)
    impact.transitive_count = len(shadow_deps)

    # Estimate depth from file nesting levels
    max_depth = 0
    for d in direct_deps + shadow_deps:
        depth = d.source_file.count(os.sep)
        max_depth = max(max_depth, depth)
    impact.max_depth = max_depth

    # Ecosystem breakdown
    for d in direct_deps + shadow_deps:
        eco = d.ecosystem
        if eco not in impact.ecosystem_breakdown:
            impact.ecosystem_breakdown[eco] = {"direct": 0, "transitive": 0}
        if d.is_shadow:
            impact.ecosystem_breakdown[eco]["transitive"] += 1
        else:
            impact.ecosystem_breakdown[eco]["direct"] += 1

    return impact


# --- Scanners ---

SCANNERS = {
    "requirements.txt": parse_requirements,
    "package.json": parse_package_json,
    "pom.xml": parse_pom_xml,
    "go.mod": parse_go_mod,
    "Gemfile.lock": parse_gemfile_lock,
    "Cargo.toml": parse_cargo_toml,
}

LOCK_SCANNERS = {
    "package-lock.json": parse_package_lock,
    "yarn.lock": parse_package_lock,
    "poetry.lock": parse_poetry_lock,
}


def scan_directory(root: Path, use_osv: bool = False) -> ScanResult:
    result = ScanResult()
    direct_deps = []
    lock_deps = []

    if root.is_file():
        fname = root.name
        if fname in SCANNERS:
            deps = SCANNERS[fname](root)
            if deps:
                direct_deps.extend(deps)
                result.scanned_files.append(str(root))
        elif fname in LOCK_SCANNERS:
            deps = LOCK_SCANNERS[fname](root)
            if deps:
                lock_deps.extend(deps)
                result.scanned_files.append(str(root))
        else:
            deps = parse_requirements(root)
            if deps:
                direct_deps.extend(deps)
                result.scanned_files.append(str(root))
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ("node_modules", "vendor", "venv", "__pycache__")]

            for fname in filenames:
                fpath = Path(dirpath) / fname

                # Direct dependency parsers
                if fname in SCANNERS:
                    deps = SCANNERS[fname](fpath)
                    if deps:
                        direct_deps.extend(deps)
                        result.scanned_files.append(str(fpath))

                # Lock file parsers (shadow deps)
                if fname in LOCK_SCANNERS:
                    deps = LOCK_SCANNERS[fname](fpath)
                    if deps:
                        lock_deps.extend(deps)
                        result.scanned_files.append(str(fpath))

                # Glob patterns
                if re.match(r'requirements.*\.txt$', fname) and str(fpath) not in result.scanned_files:
                    deps = parse_requirements(fpath)
                    if deps:
                        direct_deps.extend(deps)
                        result.scanned_files.append(str(fpath))

    # Enrich direct deps
    direct_deps = check_vulnerabilities(direct_deps)
    direct_deps = enrich_with_osv(direct_deps, use_osv)
    direct_deps = detect_stale_packages(direct_deps)
    direct_deps = detect_outdated(direct_deps)

    # License detection
    for d in direct_deps:
        d.license = detect_license(d.name, d.ecosystem)
        d.is_critical_domain = is_critical_domain(d.name)

    # Shadow deps
    shadow_deps = detect_shadow_dependencies(direct_deps, lock_deps)
    for d in shadow_deps:
        d.license = detect_license(d.name, d.ecosystem)
        d.is_critical_domain = is_critical_domain(d.name)

    # Combine
    all_deps = direct_deps + shadow_deps
    result.dependencies = all_deps

    # Risk summary
    result.risk_summary = calculate_risk_score(all_deps)

    # Impact analysis
    result.impact = analyze_impact(direct_deps, shadow_deps, result)

    return result


# --- ANSI Color codes ---

class C:
    """ANSI escape codes for colored terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    BLACK   = "\033[30m"
    BG_RED  = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_GREEN  = "\033[42m"
    BG_BLUE   = "\033[44m"

    @staticmethod
    def disable():
        for attr in dir(C):
            if attr.isupper() and not attr.startswith("_"):
                setattr(C, attr, "")


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty"):
        return False
    return sys.stdout.isatty()


def _sev_color(severity: Optional[Severity]) -> str:
    if severity == Severity.CRITICAL:
        return C.BG_RED + C.WHITE + C.BOLD
    if severity == Severity.HIGH:
        return C.RED + C.BOLD
    if severity == Severity.MEDIUM:
        return C.YELLOW
    if severity == Severity.LOW:
        return C.CYAN
    return C.DIM


def _risk_color(level: RiskLevel) -> str:
    if level == RiskLevel.CRITICAL:
        return C.BG_RED + C.WHITE + C.BOLD
    if level == RiskLevel.HIGH:
        return C.RED + C.BOLD
    if level == RiskLevel.MEDIUM:
        return C.YELLOW + C.BOLD
    if level == RiskLevel.LOW:
        return C.GREEN
    return C.DIM


def _tag(text: str, bg: str, fg: str = C.WHITE) -> str:
    return f"{bg}{fg}{C.BOLD} {text} {C.RESET}"


def _bar(score: int, max_score: int, width: int = 20) -> str:
    filled = int(score / max_score * width) if max_score else 0
    empty = width - filled
    if score / max_score > 0.7:
        color = C.RED
    elif score / max_score > 0.4:
        color = C.YELLOW
    else:
        color = C.GREEN
    return f"{color}{'#' * filled}{C.DIM}{'.' * empty}{C.RESET}"


# --- Reporting ---

def format_text(result: ScanResult) -> str:
    lines = []
    lines.append("")
    lines.append(f"{C.BOLD}{C.CYAN}{'=' * 65}{C.RESET}")
    lines.append(f"{C.BOLD}{C.CYAN}  DEPENDENCY SCAN REPORT -- Risk & Impact Analysis{C.RESET}")
    lines.append(f"{C.BOLD}{C.CYAN}{'=' * 65}{C.RESET}")
    lines.append(f"  Scanned files:  {C.BOLD}{len(result.scanned_files)}{C.RESET}")
    lines.append(f"  Dependencies:   {C.BOLD}{result.impact.direct_count}{C.RESET} direct + {C.BOLD}{result.impact.transitive_count}{C.RESET} transitive")
    lines.append("")

    # Risk summary
    rs = result.risk_summary
    rc = _risk_color(rs.risk_level)
    lines.append(f"  {C.BOLD}RISK SCORE:{C.RESET} {rc}{C.BOLD}{rs.overall_score}/100 [{rs.risk_level.value.upper()}]{C.RESET}")
    lines.append(f"    Security:     {_bar(rs.security_score, 40)} {rs.security_score}/40")
    lines.append(f"    License:      {_bar(rs.license_score, 20)} {rs.license_score}/20")
    lines.append(f"    Maintenance:  {_bar(rs.maintenance_score, 20)} {rs.maintenance_score}/20")
    lines.append(f"    Shadow/Domain: {C.MAGENTA}{rs.shadow_count} shadow{C.RESET}, {C.YELLOW}{rs.critical_domain_count} critical-domain{C.RESET}")
    lines.append("")

    # Recommendations
    if rs.recommendations:
        lines.append(f"  {C.BOLD}{C.YELLOW}RECOMMENDATIONS:{C.RESET}")
        for r in rs.recommendations:
            lines.append(f"    {C.YELLOW}> {C.RESET} {r}")
        lines.append("")

    # CVEs
    cve_deps = [d for d in result.dependencies if d.cve_count > 0]
    if cve_deps:
        total_cves = sum(d.cve_count for d in cve_deps)
        lines.append(f"  {C.BOLD}{C.RED}CVE / VULNERABILITIES:{C.RESET} {_tag(f'{total_cves} CVEs', C.BG_RED)} across {len(cve_deps)} packages")
        lines.append(f"{C.RED}{'-' * 65}{C.RESET}")
        for d in cve_deps:
            sc = _sev_color(d.severity)
            lines.append(f"    {sc}[{d.severity.value.upper()}]{C.RESET} {C.BOLD}{d.name}{C.RESET} {d.version}")
            lines.append(f"      {C.DIM}CVEs: {', '.join(d.cve_ids[:5])}{C.RESET}")
        lines.append("")

    # Stale
    stale = [d for d in result.dependencies if d.is_stale]
    if stale:
        lines.append(f"  {C.BOLD}{C.YELLOW}STALE PACKAGES:{C.RESET} {_tag(f'{len(stale)}', C.BG_YELLOW, C.BLACK)}")
        lines.append(f"{C.YELLOW}{'-' * 65}{C.RESET}")
        for d in stale:
            lines.append(f"    {C.YELLOW}[!]{C.RESET} {d.name} {d.version} {C.DIM}({d.source_file}){C.RESET}")
        lines.append("")

    # Outdated
    outdated = [d for d in result.dependencies if d.is_outdated]
    if outdated:
        lines.append(f"  {C.BOLD}{C.YELLOW}OUTDATED PACKAGES:{C.RESET} {_tag(f'{len(outdated)}', C.BG_YELLOW, C.BLACK)}")
        lines.append(f"{C.YELLOW}{'-' * 65}{C.RESET}")
        for d in outdated:
            lines.append(f"    {C.YELLOW}[~]{C.RESET} {d.name} {C.BOLD}{d.version}{C.RESET} -> {C.GREEN}{d.latest_version}{C.RESET}")
        lines.append("")

    # Shadow
    shadow = [d for d in result.dependencies if d.is_shadow]
    if shadow:
        lines.append(f"  {C.BOLD}{C.MAGENTA}SHADOW DEPENDENCIES:{C.RESET} {_tag(f'{len(shadow)}', C.BG_BLUE)}")
        lines.append(f"{C.MAGENTA}{'-' * 65}{C.RESET}")
        for d in shadow[:20]:
            lines.append(f"    {C.MAGENTA}[*]{C.RESET} {d.name} {d.version} {C.DIM}({d.ecosystem}){C.RESET}")
        if len(shadow) > 20:
            lines.append(f"    {C.DIM}... and {len(shadow) - 20} more{C.RESET}")
        lines.append("")

    # License issues
    lic_issues = [d for d in result.dependencies if d.license and (d.license.is_copyleft or d.license.name == "Unknown")]
    if lic_issues:
        lines.append(f"  {C.BOLD}{C.RED}LICENSE COMPLIANCE:{C.RESET} {_tag(f'{len(lic_issues)} issues', C.BG_RED)}")
        lines.append(f"{C.RED}{'-' * 65}{C.RESET}")
        for d in lic_issues:
            if d.license.is_copyleft:
                tag = _tag("COPYLEFT", C.BG_RED)
            else:
                tag = _tag("UNKNOWN", C.BG_YELLOW, C.BLACK)
            lines.append(f"    {tag} {d.name} -- {d.license.name} {C.DIM}({d.license.note or d.license.spdx_id}){C.RESET}")
        lines.append("")

    # Critical domain
    crit_domain = [d for d in result.dependencies if d.is_critical_domain]
    if crit_domain:
        lines.append(f"  {C.BOLD}{C.RED}CRITICAL DOMAIN DEPS:{C.RESET} {C.DIM}(crypto/auth/network){C.RESET}")
        lines.append(f"{C.RED}{'-' * 65}{C.RESET}")
        for d in crit_domain[:10]:
            lines.append(f"    {C.RED}[#]{C.RESET} {d.name} {d.version} {C.DIM}({d.ecosystem}){C.RESET}")
        lines.append("")

    # Impact
    imp = result.impact
    lines.append(f"  {C.BOLD}{C.CYAN}IMPACT ANALYSIS:{C.RESET}")
    lines.append(f"{C.CYAN}{'-' * 65}{C.RESET}")
    lines.append(f"    Direct dependencies:   {C.BOLD}{imp.direct_count}{C.RESET}")
    lines.append(f"    Transitive (shadow):   {C.BOLD}{imp.transitive_count}{C.RESET}")
    lines.append(f"    Estimated tree depth:  {C.BOLD}{imp.max_depth}{C.RESET}")
    if imp.ecosystem_breakdown:
        lines.append(f"    {C.DIM}Ecosystem breakdown:{C.RESET}")
        for eco, counts in imp.ecosystem_breakdown.items():
            lines.append(f"      {eco}: {C.GREEN}{counts['direct']} direct{C.RESET}, {C.MAGENTA}{counts['transitive']} transitive{C.RESET}")
    lines.append("")

    lines.append(f"{C.BOLD}{C.CYAN}{'=' * 65}{C.RESET}")
    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    rs = result.risk_summary
    imp = result.impact
    output = {
        "report_version": "2.0",
        "generated_at": datetime.now().isoformat(),
        "scanned_files": result.scanned_files,
        "risk_score": {
            "overall": rs.overall_score,
            "level": rs.risk_level.value,
            "breakdown": {
                "security": {"score": rs.security_score, "max": 40, "pct": round(rs.security_score / 40 * 100)},
                "license": {"score": rs.license_score, "max": 20, "pct": round(rs.license_score / 20 * 100)},
                "maintenance": {"score": rs.maintenance_score, "max": 20, "pct": round(rs.maintenance_score / 20 * 100)},
                "shadow_domain": {"score": min(rs.shadow_count * 2 + rs.critical_domain_count * 3, 20), "max": 20},
            },
            "counts": {
                "total_dependencies": rs.total_dependencies,
                "shadow_count": rs.shadow_count,
                "stale_count": rs.stale_count,
                "critical_domain_count": rs.critical_domain_count,
                "copyleft_count": rs.copyleft_count,
            },
        },
        "impact": {
            "direct_count": imp.direct_count,
            "transitive_count": imp.transitive_count,
            "max_depth": imp.max_depth,
            "ecosystem_breakdown": imp.ecosystem_breakdown,
        },
        "recommendations": rs.recommendations,
        "issues": {
            "vulnerabilities": [
                {
                    "name": d.name,
                    "version": d.version,
                    "severity": d.severity.value if d.severity else None,
                    "cve_count": d.cve_count,
                    "cve_ids": d.cve_ids,
                    "note": d.note,
                    "source": d.source_file,
                    "ecosystem": d.ecosystem,
                    "risk_score": d.risk_score,
                }
                for d in result.dependencies if d.cve_count > 0
            ],
            "stale": [
                {"name": d.name, "version": d.version, "source": d.source_file, "ecosystem": d.ecosystem}
                for d in result.dependencies if d.is_stale
            ],
            "outdated": [
                {"name": d.name, "version": d.version, "latest": d.latest_version,
                 "source": d.source_file, "ecosystem": d.ecosystem}
                for d in result.dependencies if d.is_outdated
            ],
            "shadow": [
                {"name": d.name, "version": d.version, "ecosystem": d.ecosystem,
                 "source": d.source_file, "note": d.note}
                for d in result.dependencies if d.is_shadow
            ],
            "license_issues": [
                {"name": d.name, "license": d.license.name, "spdx": d.license.spdx_id,
                 "copyleft": d.license.is_copyleft, "osi_approved": d.license.osi_approved,
                 "note": d.license.note, "source": d.source_file}
                for d in result.dependencies if d.license and (d.license.is_copyleft or d.license.name == "Unknown")
            ],
            "critical_domain": [
                {"name": d.name, "version": d.version, "ecosystem": d.ecosystem,
                 "source": d.source_file}
                for d in result.dependencies if d.is_critical_domain
            ],
        },
        "all_dependencies": [asdict(d) for d in result.dependencies],
        "errors": result.errors,
    }
    return json.dumps(output, indent=2, default=str)


def format_csv(result: ScanResult) -> str:
    lines = ["ecosystem,name,version,source_file,pinned,severity,cve_count,is_stale,is_outdated,is_shadow,is_critical_domain,license"]
    for d in result.dependencies:
        sev = d.severity.value if d.severity else ""
        lic = d.license.name if d.license else ""
        lines.append(f"{d.ecosystem},{d.name},{d.version},{d.source_file},{d.pinned},{sev},{d.cve_count},{d.is_stale},{d.is_outdated},{d.is_shadow},{d.is_critical_domain},{lic}")
    return "\n".join(lines)


def format_html(result: ScanResult) -> str:
    rs = result.risk_summary
    imp = result.impact

    risk_bg = {"critical": "#dc3545", "high": "#e8590c", "medium": "#f59f00", "low": "#2f9e44", "minimal": "#868e96"}
    sev_bg = {"critical": "#dc3545", "high": "#e8590c", "medium": "#f59f00", "low": "#2f9e44", "info": "#868e96"}

    cve_deps = [d for d in result.dependencies if d.cve_count > 0]
    stale_deps = [d for d in result.dependencies if d.is_stale]
    outdated_deps = [d for d in result.dependencies if d.is_outdated]
    shadow_deps = [d for d in result.dependencies if d.is_shadow]
    lic_issues = [d for d in result.dependencies if d.license and (d.license.is_copyleft or d.license.name == "Unknown")]
    crit_deps = [d for d in result.dependencies if d.is_critical_domain]

    def _dep_table_rows(deps_list):
        rows = ""
        for d in deps_list:
            sev_color = sev_bg.get(d.severity.value, "#868e96") if d.severity else "#dee2e6"
            sev_label = d.severity.value.upper() if d.severity else ""
            lic_name = d.license.name if d.license else ""
            cve_badge = f'<span class="badge badge-red">{d.cve_count} CVE</span>' if d.cve_count > 0 else ""
            shadow_badge = '<span class="badge badge-purple">shadow</span>' if d.is_shadow else ""
            stale_badge = '<span class="badge badge-yellow">stale</span>' if d.is_stale else ""
            outdated_badge = f'<span class="badge badge-yellow">outdated → {d.latest_version}</span>' if d.is_outdated else ""
            domain_badge = '<span class="badge badge-red">critical domain</span>' if d.is_critical_domain else ""
            rows += f"""<tr>
  <td><strong>{d.name}</strong></td>
  <td><code>{d.version}</code></td>
  <td>{d.ecosystem}</td>
  <td>{d.source_file}</td>
  <td><span class="sev-badge" style="background:{sev_color}">{sev_label}</span></td>
  <td>{lic_name}</td>
  <td>{cve_badge}{shadow_badge}{stale_badge}{outdated_badge}{domain_badge}</td>
</tr>\n"""
        return rows

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dependency Scan Report</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --text-dim: #8b949e; --accent: #58a6ff;
    --red: #f85149; --yellow: #d29922; --green: #3fb950; --purple: #bc8cff;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
         background: var(--bg); color: var(--text); padding: 2rem; line-height: 1.6; }}
  h1 {{ color: var(--accent); margin-bottom: 0.5rem; }}
  h2 {{ color: var(--text); margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
  .meta {{ color: var(--text-dim); margin-bottom: 2rem; font-size: 0.9rem; }}
  .risk-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
                padding: 1.5rem; margin-bottom: 1.5rem; }}
  .risk-score {{ font-size: 3rem; font-weight: 700; }}
  .risk-level {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 4px;
                 font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }}
  .bar-container {{ background: var(--border); border-radius: 4px; height: 8px; margin: 0.5rem 0; }}
  .bar-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat-value {{ font-size: 1.5rem; font-weight: 700; }}
  .stat-label {{ color: var(--text-dim); font-size: 0.85rem; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th, td {{ padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ background: var(--surface); color: var(--text-dim); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }}
  tr:hover {{ background: rgba(88,166,255,0.05); }}
  code {{ background: var(--surface); padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }}
  .sev-badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px;
                font-size: 0.75rem; font-weight: 600; color: #fff; }}
  .badge {{ display: inline-block; padding: 0.1rem 0.4rem; border-radius: 3px;
            font-size: 0.7rem; font-weight: 600; color: #fff; margin-left: 0.3rem; }}
  .badge-red {{ background: var(--red); }}
  .badge-yellow {{ background: var(--yellow); color: #000; }}
  .badge-purple {{ background: var(--purple); color: #000; }}
  .badge-green {{ background: var(--green); color: #000; }}
  .recommendations {{ background: var(--surface); border-left: 3px solid var(--yellow);
                      padding: 1rem 1.5rem; border-radius: 0 8px 8px 0; margin: 1rem 0; }}
  .recommendations li {{ margin: 0.4rem 0; }}
  .section-empty {{ color: var(--text-dim); font-style: italic; padding: 1rem; }}
</style>
</head>
<body>

<h1>Dependency Scan Report</h1>
<p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &middot; {len(result.scanned_files)} files scanned</p>

<div class="risk-card">
  <div style="display:flex; align-items:center; gap:1.5rem;">
    <div class="risk-score" style="color:{risk_bg.get(rs.risk_level.value, '#868e96')}">{rs.overall_score}<span style="font-size:1rem;color:var(--text-dim)">/100</span></div>
    <div>
      <span class="risk-level" style="background:{risk_bg.get(rs.risk_level.value, '#868e96')};color:#fff">{rs.risk_level.value.upper()}</span>
    </div>
  </div>
  <div style="margin-top:1rem;">
    <div>Security <span style="float:right">{rs.security_score}/40</span></div>
    <div class="bar-container"><div class="bar-fill" style="width:{rs.security_score/40*100}%;background:{risk_bg.get('high','#e8590c')}"></div></div>
    <div>License <span style="float:right">{rs.license_score}/20</span></div>
    <div class="bar-container"><div class="bar-fill" style="width:{rs.license_score/20*100 if rs.license_score else 0}%;background:{risk_bg.get('medium','#f59f00')}"></div></div>
    <div>Maintenance <span style="float:right">{rs.maintenance_score}/20</span></div>
    <div class="bar-container"><div class="bar-fill" style="width:{rs.maintenance_score/20*100 if rs.maintenance_score else 0}%;background:{risk_bg.get('low','#2f9e44')}"></div></div>
  </div>
</div>

<div class="grid">
  <div class="stat"><div class="stat-value" style="color:var(--text)">{imp.direct_count + imp.transitive_count}</div><div class="stat-label">Total Dependencies</div></div>
  <div class="stat"><div class="stat-value" style="color:var(--green)">{imp.direct_count}</div><div class="stat-label">Direct</div></div>
  <div class="stat"><div class="stat-value" style="color:var(--purple)">{imp.transitive_count}</div><div class="stat-label">Transitive (Shadow)</div></div>
  <div class="stat"><div class="stat-value" style="color:var(--red)">{len(cve_deps)}</div><div class="stat-label">Vulnerable</div></div>
  <div class="stat"><div class="stat-value" style="color:var(--yellow)">{len(stale_deps)}</div><div class="stat-label">Stale</div></div>
  <div class="stat"><div class="stat-value" style="color:var(--yellow)">{len(outdated_deps)}</div><div class="stat-label">Outdated</div></div>
  <div class="stat"><div class="stat-value" style="color:var(--red)">{len(lic_issues)}</div><div class="stat-label">License Issues</div></div>
  <div class="stat"><div class="stat-value" style="color:var(--red)">{len(crit_deps)}</div><div class="stat-label">Critical Domain</div></div>
</div>

<h2>Recommendations</h2>
<div class="recommendations">
  <ul>
    {"".join(f"<li>{r}</li>" for r in rs.recommendations) if rs.recommendations else '<li style="color:var(--green)">No critical recommendations — project looks healthy!</li>'}
  </ul>
</div>

<h2>Vulnerabilities ({len(cve_deps)} packages)</h2>
{"<table><tr><th>Package</th><th>Version</th><th>Severity</th><th>CVEs</th><th>Source</th></tr>" + "".join(f'<tr><td><strong>{d.name}</strong></td><td><code>{d.version}</code></td><td><span class="sev-badge" style="background:{sev_bg.get(d.severity.value,"#868e96")}">{d.severity.value.upper()}</span></td><td>{", ".join(d.cve_ids[:5])}</td><td>{d.source_file}</td></tr>' for d in cve_deps) + "</table>" if cve_deps else '<p class="section-empty">No known vulnerabilities found.</p>'}

<h2>Stale Packages ({len(stale_deps)})</h2>
{"<table><tr><th>Package</th><th>Version</th><th>Source</th></tr>" + "".join(f'<tr><td><strong>{d.name}</strong></td><td><code>{d.version}</code></td><td>{d.source_file}</td></tr>' for d in stale_deps) + "</table>" if stale_deps else '<p class="section-empty">No stale packages.</p>'}

<h2>Outdated Packages ({len(outdated_deps)})</h2>
{"<table><tr><th>Package</th><th>Current</th><th>Latest</th><th>Source</th></tr>" + "".join(f'<tr><td><strong>{d.name}</strong></td><td><code>{d.version}</code></td><td><code style="color:var(--green)">{d.latest_version}</code></td><td>{d.source_file}</td></tr>' for d in outdated_deps) + "</table>" if outdated_deps else '<p class="section-empty">No outdated packages.</p>'}

<h2>Shadow Dependencies ({len(shadow_deps)})</h2>
{"<table><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Source</th></tr>" + "".join(f'<tr><td><strong>{d.name}</strong></td><td><code>{d.version}</code></td><td>{d.ecosystem}</td><td>{d.source_file}</td></tr>' for d in shadow_deps[:50]) + (f'<tr><td colspan="4" style="color:var(--text-dim)">... and {len(shadow_deps) - 50} more</td></tr>' if len(shadow_deps) > 50 else '') + "</table>" if shadow_deps else '<p class="section-empty">No shadow dependencies detected.</p>'}

<h2>License Issues ({len(lic_issues)})</h2>
{"<table><tr><th>Package</th><th>License</th><th>Type</th><th>Source</th></tr>" + "".join(f'<tr><td><strong>{d.name}</strong></td><td>{d.license.name}</td><td><span class="badge {"badge-red" if d.license.is_copyleft else "badge-yellow"}">{"COPYLEFT" if d.license.is_copyleft else "UNKNOWN"}</span></td><td>{d.source_file}</td></tr>' for d in lic_issues) + "</table>" if lic_issues else '<p class="section-empty">No license issues.</p>'}

<h2>Critical Domain Dependencies ({len(crit_deps)})</h2>
{"<table><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Source</th></tr>" + "".join(f'<tr><td><strong>{d.name}</strong></td><td><code>{d.version}</code></td><td>{d.ecosystem}</td><td>{d.source_file}</td></tr>' for d in crit_deps) + "</table>" if crit_deps else '<p class="section-empty">No critical-domain packages.</p>'}

<h2>Impact Analysis</h2>
<div class="grid">
  <div class="stat"><div class="stat-value">{imp.direct_count}</div><div class="stat-label">Direct Dependencies</div></div>
  <div class="stat"><div class="stat-value">{imp.transitive_count}</div><div class="stat-label">Transitive Dependencies</div></div>
  <div class="stat"><div class="stat-value">{imp.max_depth}</div><div class="stat-label">Max Tree Depth</div></div>
</div>
{"<h3>Ecosystem Breakdown</h3><table><tr><th>Ecosystem</th><th>Direct</th><th>Transitive</th><th>Total</th></tr>" + "".join(f'<tr><td>{eco}</td><td>{counts["direct"]}</td><td>{counts["transitive"]}</td><td>{counts["direct"] + counts["transitive"]}</td></tr>' for eco, counts in imp.ecosystem_breakdown.items()) + "</table>" if imp.ecosystem_breakdown else ""}

</body>
</html>"""
    return html


def print_summary(result: ScanResult) -> None:
    rs = result.risk_summary
    rc = _risk_color(rs.risk_level)
    print(f"\n  {C.BOLD}Risk Score:{C.RESET} {rc}{rs.overall_score}/100 [{rs.risk_level.value.upper()}]{C.RESET}")
    if rs.recommendations:
        print(f"  {C.BOLD}Top recommendations:{C.RESET}")
        for r in rs.recommendations[:3]:
            print(f"    {C.YELLOW}> {C.RESET} {r}")


# --- CLI ---

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dependency_scanner",
        description="Scan project dependencies with Risk & Impact Analysis.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Directory to scan (default: current dir)")
    parser.add_argument("-f", "--format", choices=["text", "json", "csv", "html"], default="text", help="Output format")
    parser.add_argument("-o", "--output", help="Write report to file")
    parser.add_argument("--osv", action="store_true", help="Query osv.dev API for real-time CVE data")
    parser.add_argument("--no-vuln-check", action="store_true", help="Skip local vulnerability checks")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], help="Filter by minimum severity")
    parser.add_argument("--ecosystem", help="Filter by ecosystem (python, npm, go, maven, ruby, rust)")
    parser.add_argument("--unpinned-only", action="store_true", help="Show only unpinned dependencies")
    parser.add_argument("--unspecified-only", action="store_true", help="Show only deps without version constraints")
    parser.add_argument("--shadow-only", action="store_true", help="Show only shadow/transitive dependencies")
    parser.add_argument("--stale-only", action="store_true", help="Show only stale packages")
    parser.add_argument("--outdated-only", action="store_true", help="Show only outdated packages")
    parser.add_argument("--license-issues-only", action="store_true", help="Show only license compliance issues")
    parser.add_argument("--critical-domain-only", action="store_true", help="Show only critical-domain packages")
    parser.add_argument("--min-risk-score", type=int, default=0, help="Filter deps with risk_score >= N")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="Exit code 1 if issue at this severity+ found")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Error: '{root}' is not a directory", file=sys.stderr)
        return 2

    # Color support
    if args.no_color or not _supports_color():
        C.disable()

    result = scan_directory(root, use_osv=args.osv)

    # Filters
    deps = result.dependencies

    if args.severity:
        min_sev = Severity(args.severity)
        min_idx = SEVERITY_ORDER.index(min_sev)
        deps = [d for d in deps if d.severity and SEVERITY_ORDER.index(d.severity) >= min_idx]

    if args.ecosystem:
        eco = args.ecosystem.lower()
        deps = [d for d in deps if d.ecosystem == eco]

    if args.unpinned_only:
        deps = [d for d in deps if not d.pinned and d.version != "unspecified"]

    if args.unspecified_only:
        deps = [d for d in deps if d.version == "unspecified"]

    if args.shadow_only:
        deps = [d for d in deps if d.is_shadow]

    if args.stale_only:
        deps = [d for d in deps if d.is_stale]

    if args.outdated_only:
        deps = [d for d in deps if d.is_outdated]

    if args.license_issues_only:
        deps = [d for d in deps if d.license and (d.license.is_copyleft or d.license.name == "Unknown")]

    if args.critical_domain_only:
        deps = [d for d in deps if d.is_critical_domain]

    if args.min_risk_score > 0:
        deps = [d for d in deps if d.risk_score >= args.min_risk_score]

    result.dependencies = deps

    # Output
    formatters = {"text": format_text, "json": format_json, "csv": format_csv, "html": format_html}
    report = formatters[args.format](result)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(report)

    # Exit code
    if args.fail_on:
        fail_sev = Severity(args.fail_on)
        fail_idx = SEVERITY_ORDER.index(fail_sev)
        for d in result.dependencies:
            if d.severity and SEVERITY_ORDER.index(d.severity) >= fail_idx:
                return 1

    if not args.output:
        print_summary(result)

    return 0


if __name__ == "__main__":
    sys.exit(main())
