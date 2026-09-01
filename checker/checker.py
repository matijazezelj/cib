"""
CIB Checker — Compliance in a Box

For each running container image:
  1. Container policy checks (privileged, root user, resource limits, security opts)
  2. SBOM generation via Trivy (CycloneDX) + license compliance
  3. Base image EOL check via endoflife.date
Pushes all results to VictoriaMetrics.
"""

import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, date, timezone
from pathlib import Path
from urllib.parse import quote

import docker
import requests
import schedule

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("cib")

_shutdown = threading.Event()


def _handle_sigterm(signum, frame):
    _shutdown.set()


signal.signal(signal.SIGTERM, _handle_sigterm)
signal.signal(signal.SIGINT, _handle_sigterm)

# ── Config ────────────────────────────────────────────────────────────────────

VICTORIAMETRICS_URL = os.environ.get("VICTORIAMETRICS_URL", "http://cib-victoriametrics:8428")
try:
    SCAN_INTERVAL_HOURS = float(os.environ.get("SCAN_INTERVAL_HOURS", "6"))
except ValueError as e:
    logger.error("Invalid SCAN_INTERVAL_HOURS: %s", e)
    sys.exit(1)
SCAN_ON_STARTUP = os.environ.get("SCAN_ON_STARTUP", "true").lower() == "true"
try:
    TRIVY_TIMEOUT = int(os.environ.get("TRIVY_TIMEOUT", "300"))
except ValueError as e:
    logger.error("Invalid TRIVY_TIMEOUT: %s", e)
    sys.exit(1)
ADDITIONAL_IMAGES = [
    i.strip() for i in os.environ.get("ADDITIONAL_IMAGES", "").split(",") if i.strip()
]
SBOM_DIR = Path(os.environ.get("SBOM_DIR", "/data/sboms"))

# Single remote host (backwards-compat). Prefer DOCKER_HOSTS for multi-host.
DOCKER_HOST = os.environ.get("DOCKER_HOST", "")

# Licenses that violate policy by default (copyleft — problematic for proprietary stacks)
_default_deny = "GPL-2.0-only,GPL-2.0-or-later,GPL-3.0-only,GPL-3.0-or-later,AGPL-3.0-only,AGPL-3.0-or-later"
# `or` rather than a get() default: docker-compose passes
# LICENSE_DENY_LIST=${LICENSE_DENY_LIST:-}, so the variable is always *set* and
# a get() default never applies — which silently left the deny list empty and
# license checking a no-op for every compose-based run.
LICENSE_DENY_LIST = {
    s.strip() for s in (os.environ.get("LICENSE_DENY_LIST") or _default_deny).split(",") if s.strip()
}

# EOL check: map Trivy OS family names to endoflife.date product names
EOL_PRODUCT_MAP = {
    "ubuntu": "ubuntu",
    "debian": "debian",
    "alpine": "alpine",
    "centos": "centos",
    "rhel": "rhel",
    "fedora": "fedora",
    "amazon": "amazon-linux",
    "rockylinux": "rocky-linux",
    "almalinux": "almalinux",
    "sles": "sles",
    "opensuse": "opensuse",
    "oracle": "oracle-linux",
    "photon": "photon",
    "wolfi": "wolfi",
    "chainguard": "chainguard",
}

SESSION = requests.Session()
SESSION.headers["User-Agent"] = "CIB/0.1 (Compliance in a Box)"
SBOM_DIR.mkdir(parents=True, exist_ok=True)


# ── Multi-host parsing ────────────────────────────────────────────────────────

def _parse_docker_hosts() -> list[tuple[str, str]]:
    """Return list of (name, docker_url) to scan.

    Priority:
      1. DOCKER_HOSTS=name1=tcp://host1:port1,name2=tcp://host2:port2
      2. DOCKER_HOST=tcp://host:port  (single host, name="docker")
      3. local socket                 (name="local", url="")
    """
    raw = os.environ.get("DOCKER_HOSTS", "").strip()
    if raw:
        hosts = []
        valid_schemes = ("tcp://", "unix://", "ssh://", "npipe://")
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if "=" in entry:
                name, url = entry.split("=", 1)
                name, url = name.strip(), url.strip()
            else:
                name, url = "docker", entry.strip()
            if not name or not url:
                logger.warning("Skipping DOCKER_HOSTS entry with empty name or url: %r", entry)
                continue
            if not url.startswith(valid_schemes):
                logger.warning("Skipping DOCKER_HOSTS entry with invalid scheme: %r", entry)
                continue
            hosts.append((name, url))
        return hosts
    if DOCKER_HOST:
        return [("docker", DOCKER_HOST)]
    return [("local", "")]


# ── Docker client helper ──────────────────────────────────────────────────────

def _docker_client(docker_url: str) -> docker.DockerClient:
    return docker.DockerClient(base_url=docker_url) if docker_url else docker.from_env()


# ── Metric helpers ────────────────────────────────────────────────────────────

def _safe_label(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _ts_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _push(lines: list[str]) -> None:
    if not lines:
        return
    payload = "\n".join(lines) + "\n"
    for attempt in range(2):
        try:
            resp = SESSION.post(
                f"{VICTORIAMETRICS_URL}/api/v1/import/prometheus",
                data=payload,
                headers={"Content-Type": "text/plain"},
                timeout=10,
            )
            resp.raise_for_status()
            break
        except requests.exceptions.ConnectionError as e:
            if attempt == 0:
                time.sleep(2)
            else:
                logger.error("Metric push failed after retry: %s", e)
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else 0
            if 500 <= status < 600 and attempt == 0:
                time.sleep(2)
            else:
                logger.error("Metric push failed (HTTP %s): %s", status, e)
                break
        except Exception as e:
            logger.error("Metric push failed: %s", e)
            break


# ── Docker discovery ──────────────────────────────────────────────────────────

def discover_images(docker_url: str = "", client=None) -> list[str]:
    try:
        if client is None:
            client = _docker_client(docker_url)
        images = set()
        for c in client.containers.list():
            try:
                if c.image and c.image.tags:
                    images.add(c.image.tags[0])
                elif c.image:
                    images.add(c.image.id)
            except Exception:
                continue
        return sorted(images)
    except Exception as e:
        logger.warning("Docker discovery failed: %s", e)
        return []


def get_containers(docker_url: str = "", client=None) -> list[docker.models.containers.Container]:
    try:
        if client is None:
            client = _docker_client(docker_url)
        return client.containers.list()
    except Exception as e:
        logger.warning("Could not list containers: %s", e)
        return []


# ── Container policy checks ───────────────────────────────────────────────────

POLICY_CHECKS = [
    "not_privileged",
    "non_root_user",
    "no_new_privileges",
    "memory_limit",
    "cpu_limit",
    "read_only_rootfs",
    "no_host_network",
    "no_host_pid",
]


def check_container_policy(container) -> dict[str, bool]:
    """Return dict of check_name → pass (True=good, False=violation)."""
    hc = container.attrs.get("HostConfig", {})
    cfg = container.attrs.get("Config", {})

    results = {}

    results["not_privileged"] = not hc.get("Privileged", False)

    user = cfg.get("User", "")
    user_id = user.split(":")[0] if user else ""
    results["non_root_user"] = user_id not in ("0", "root", "")

    sec_opts = hc.get("SecurityOpt") or []
    results["no_new_privileges"] = any("no-new-privileges" in o for o in sec_opts)

    results["memory_limit"] = (hc.get("Memory") or 0) > 0

    results["cpu_limit"] = (hc.get("NanoCpus") or 0) > 0 or (hc.get("CpuQuota") or 0) > 0

    results["read_only_rootfs"] = bool(hc.get("ReadonlyRootfs", False))

    results["no_host_network"] = hc.get("NetworkMode", "") != "host"

    results["no_host_pid"] = not hc.get("PidMode", "").startswith("host")

    return results


def push_policy_metrics(container_name: str, checks: dict[str, bool], host: str = "local") -> None:
    ts = _ts_ms()
    lines = []
    passing = 0
    safe_host = _safe_label(host)
    for check, passed in checks.items():
        val = 0 if passed else 1  # 1 = violation
        lines.append(
            f'cib_policy_violation{{container="{_safe_label(container_name)}",'
            f'check="{_safe_label(check)}",host="{safe_host}"}} {val} {ts}'
        )
        if passed:
            passing += 1

    score = (passing / len(checks)) * 100 if checks else 0
    lines.append(
        f'cib_container_policy_score{{container="{_safe_label(container_name)}",'
        f'host="{safe_host}"}} {score:.1f} {ts}'
    )
    _push(lines)


# ── Trivy SBOM scan ───────────────────────────────────────────────────────────

def scan_sbom(image: str, docker_url: str = "") -> dict | None:
    """Run trivy in CycloneDX mode and return parsed JSON, or None on failure."""
    safe_name = image.replace("/", "_").replace(":", "_")
    out_path = SBOM_DIR / f"{safe_name}.cdx.json"

    cmd = [
        "trivy", "image",
        "--format", "cyclonedx",
        "--quiet",
        "--timeout", f"{TRIVY_TIMEOUT}s",
        "--output", str(out_path),
    ]
    if docker_url:
        cmd.extend(["--docker-host", docker_url])
    cmd.append(image)
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=TRIVY_TIMEOUT + 30)
        if result.returncode != 0:
            logger.warning(
                "trivy sbom exited %d for %s: %s",
                result.returncode, image,
                result.stderr.decode(errors='replace')[:200],
            )
        # still try to parse if output file exists
        if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
            return None
        with open(out_path) as f:
            return json.load(f)
    except Exception as e:
        logger.warning("SBOM scan error for %s: %s", image, e)
        return None


def scan_trivy_json(image: str, docker_url: str = "") -> dict | None:
    """Run trivy in JSON mode (for OS metadata + vuln data).

    Trivy returns exit code 1 when vulnerabilities are found — that's still a
    successful scan, so we accept returncodes 0 and 1 and parse stdout either way.
    """
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--quiet",
        "--timeout", f"{TRIVY_TIMEOUT}s",
    ]
    if docker_url:
        cmd.extend(["--docker-host", docker_url])
    cmd.append(image)
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=TRIVY_TIMEOUT + 30)
        if result.returncode not in (0, 1):
            logger.warning(
                "trivy json exited %d for %s: %s",
                result.returncode, image,
                result.stderr.decode(errors='replace')[:200],
            )
        if not result.stdout:
            return None
        return json.loads(result.stdout)
    except Exception as e:
        logger.warning("Trivy JSON scan failed for %s: %s", image, e)
        return None


# ── License compliance ────────────────────────────────────────────────────────

def _denied_licenses(expr: str) -> list[str]:
    """Return the denied licence ids that make an SPDX expression a violation.

    `A WITH B` keeps A: the exception grants extra permission and is not itself
    a licence. `A AND B` requires both, so either being denied is a violation.
    `A OR B` lets the consumer choose, so it is only a violation when no
    alternative is clean. Parenthesised sub-expressions are flattened rather
    than parsed — SBOM data in practice is flat.
    """
    alternatives = []
    for alternative in re.split(r"\s+OR\s+", expr):
        ids = []
        for term in re.split(r"\s+AND\s+", alternative):
            base = re.split(r"\s+WITH\s+", term)[0].strip(" ()")
            if base:
                ids.append(base)
        if ids:
            alternatives.append(ids)
    if not alternatives:
        return []

    denied = [[i for i in ids if i in LICENSE_DENY_LIST] for ids in alternatives]
    if any(not group for group in denied):
        return []  # at least one alternative is free of denied licences

    seen, out = set(), []
    for group in denied:
        for lic_id in group:
            if lic_id not in seen:
                seen.add(lic_id)
                out.append(lic_id)
    return out


def check_licenses(image: str, sbom: dict) -> list[dict]:
    """Return list of license violations: {package, version, license}."""
    violations = []
    for component in sbom.get("components", []):
        name = component.get("name", "")
        version = component.get("version", "")
        for lic_entry in component.get("licenses", []):
            lic = lic_entry.get("license") or {}
            # Trivy puts compound expressions in license.id/name at least as
            # often as in the expression field, so every form is parsed.
            raw = lic_entry.get("expression") or lic.get("id") or lic.get("name") or ""
            for lic_id in _denied_licenses(raw):
                violations.append({"package": name, "version": version, "license": lic_id})
    return violations


def push_license_metrics(image: str, violations: list[dict], total_components: int, host: str = "local") -> None:
    ts = _ts_ms()
    safe_image = _safe_label(image)
    safe_host = _safe_label(host)
    lines = [
        f'cib_sbom_components_total{{image="{safe_image}",host="{safe_host}"}} {total_components} {ts}',
        f'cib_license_violations_total{{image="{safe_image}",host="{safe_host}"}} {len(violations)} {ts}',
    ]
    for v in violations:
        lines.append(
            f'cib_license_violation{{image="{safe_image}",'
            f'package="{_safe_label(v["package"])}",'
            f'version="{_safe_label(v["version"])}",'
            f'license="{_safe_label(v["license"])}",host="{safe_host}"}} 1 {ts}'
        )
    _push(lines)


# ── EOL check ─────────────────────────────────────────────────────────────────

def _parse_version_cycle(os_name: str) -> str:
    """Extract the major.minor cycle from an OS version string."""
    # Ubuntu: "22.04" → "22.04"; Debian: "12" → "12"; Alpine: "3.19.0" → "3.19"
    parts = os_name.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return parts[0]


def check_eol(image: str, trivy_data: dict) -> dict | None:
    """Return EOL info dict if the base OS is EOL or unknown, else None."""
    metadata = trivy_data.get("Metadata", {})
    os_info = metadata.get("OS", {})
    family = (os_info.get("Family") or "").lower()
    os_name = os_info.get("Name") or ""

    if not family or not os_name:
        return None

    product = EOL_PRODUCT_MAP.get(family)
    if not product:
        logger.debug("no EOL data for %s", family)
        return None

    cycle = _parse_version_cycle(os_name)

    try:
        r = SESSION.get(
            f"https://endoflife.date/api/{quote(product)}/{quote(cycle)}.json",
            timeout=10,
        )
        if r.status_code == 404:
            logger.debug("EOL 404 for %s/%s — skipping", product, cycle)
            return None
        if not r.ok:
            return None

        data = r.json()
        eol_raw = data.get("eol")
        if eol_raw is None:
            return None

        if isinstance(eol_raw, bool):
            is_eol = eol_raw
            eol_date = "unknown"
        else:
            try:
                eol_dt = date.fromisoformat(str(eol_raw))
                is_eol = eol_dt <= date.today()
                eol_date = str(eol_raw)
            except ValueError:
                is_eol = False
                eol_date = str(eol_raw)

        return {"family": family, "version": os_name, "cycle": cycle, "eol_date": eol_date, "is_eol": is_eol}

    except Exception as e:
        logger.debug("EOL check failed for %s %s: %s", product, cycle, e)
        return None


def push_eol_metrics(image: str, eol_info: dict | None, host: str = "local") -> None:
    ts = _ts_ms()
    safe_image = _safe_label(image)
    safe_host = _safe_label(host)
    if eol_info is None:
        _push([f'cib_eol_unknown{{image="{safe_image}",host="{safe_host}"}} 1 {ts}'])
        return

    val = 1 if eol_info["is_eol"] else 0
    _push([
        f'cib_image_eol{{image="{safe_image}",'
        f'os="{_safe_label(eol_info["family"])}",'
        f'version="{_safe_label(eol_info["version"])}",'
        f'eol_date="{_safe_label(eol_info["eol_date"])}",host="{safe_host}"}} {val} {ts}'
    ])


# ── Summary metrics ───────────────────────────────────────────────────────────

def push_summary(images_checked: int, containers_checked: int, total_violations: int, eol_count: int) -> None:
    ts = _ts_ms()
    _push([
        f"cib_images_checked_total {images_checked} {ts}",
        f"cib_containers_checked_total {containers_checked} {ts}",
        f"cib_total_policy_violations {total_violations} {ts}",
        f"cib_eol_images_total {eol_count} {ts}",
        f"cib_last_scan_timestamp {ts} {ts}",
    ])


# ── Main scan cycle ───────────────────────────────────────────────────────────

def run_scan() -> None:
    logger.info("─── CIB scan starting ───")
    ts_start = time.time()
    hosts = _parse_docker_hosts()

    total_violations = 0
    total_containers = 0
    total_images = 0
    eol_count = 0

    def scan_image_full(image: str, docker_url: str, host_name: str) -> None:
        nonlocal total_images, eol_count
        logger.info("Scanning image: %s", image)

        trivy_data = scan_trivy_json(image, docker_url)

        eol_info = check_eol(image, trivy_data) if trivy_data else None
        push_eol_metrics(image, eol_info, host=host_name)
        if eol_info and eol_info["is_eol"]:
            logger.info("  %s — EOL base OS: %s %s (eol: %s)",
                        image, eol_info["family"], eol_info["version"], eol_info["eol_date"])
            eol_count += 1

        sbom = scan_sbom(image, docker_url)
        if sbom:
            total_components = len(sbom.get("components", []))
            violations = check_licenses(image, sbom)
            push_license_metrics(image, violations, total_components, host=host_name)
            if violations:
                logger.info("  %s — %d license violations (%s)",
                            image, len(violations),
                            ", ".join(sorted({v["license"] for v in violations})))
            else:
                logger.info("  %s — %d components, no license violations", image, total_components)
            total_images += 1
        else:
            push_license_metrics(image, [], 0, host=host_name)

    for host_name, docker_url in hosts:
        logger.info("── Host: %s (%s) ──", host_name, docker_url or "local socket")

        try:
            client = _docker_client(docker_url)
        except Exception as e:
            logger.warning("Could not create Docker client for %s: %s", host_name, e)
            client = None

        # 1. Container policy checks
        containers = get_containers(docker_url, client=client)
        total_containers += len(containers)
        for container in containers:
            name = container.name
            logger.info("Policy check: %s", name)
            checks = check_container_policy(container)
            failing = [k for k, v in checks.items() if not v]
            total_violations += len(failing)
            if failing:
                logger.info("  %s — policy violations: %s", name, ", ".join(failing))
            push_policy_metrics(name, checks, host=host_name)

        # 2. Image SBOM + license + EOL checks
        images = discover_images(docker_url, client=client)
        for image in images:
            if _shutdown.is_set():
                logger.info("Shutdown requested — aborting scan loop")
                break
            scan_image_full(image, docker_url, host_name)
        if _shutdown.is_set():
            break

    # Scan ADDITIONAL_IMAGES once, outside the per-host loop, under "additional" host label
    if ADDITIONAL_IMAGES and not _shutdown.is_set():
        logger.info("── Host: additional (extra images) ──")
        for image in ADDITIONAL_IMAGES:
            if _shutdown.is_set():
                logger.info("Shutdown requested — aborting scan loop")
                break
            scan_image_full(image, "", "additional")

    push_summary(total_images, total_containers, total_violations, eol_count)
    logger.info("─── CIB scan complete in %.0fs across %d host(s) ───",
                time.time() - ts_start, len(hosts))


def main() -> None:
    if "--once" in sys.argv:
        run_scan()
        return

    logger.info("CIB checker starting (interval=%.1fh)", SCAN_INTERVAL_HOURS)

    if SCAN_ON_STARTUP:
        run_scan()

    schedule.every(SCAN_INTERVAL_HOURS).hours.do(run_scan)

    while not _shutdown.is_set():
        schedule.run_pending()
        if _shutdown.wait(60):
            break
    logger.info("Shutdown signal received, exiting.")


if __name__ == "__main__":
    main()
