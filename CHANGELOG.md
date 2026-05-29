# Changelog

## [0.1.0] — 2026-05-29

### Added
- Container policy checks: privileged mode, root user, no-new-privileges, memory/CPU limits, read-only rootfs, host network/PID
- SBOM generation via Trivy (CycloneDX format) — saved to `/data/sboms/`
- License compliance: configurable deny list (default: GPL, AGPL copyleft)
- EOL base image detection via endoflife.date API (Ubuntu, Debian, Alpine, RHEL, CentOS, Rocky, Alma, Fedora, openSUSE)
- VictoriaMetrics storage + Grafana dashboard with policy, EOL, and license violation panels
- Compliance trend time series
