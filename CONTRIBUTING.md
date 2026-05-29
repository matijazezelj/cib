# Contributing

PRs and issues welcome. Ground rules:

1. **One concern per PR.** Policy checks separate from license checks separate from dashboard changes.
2. **Test with real containers.** Run `make up` against a local Docker environment and verify metrics appear.
3. **New policy checks** should be CIS benchmark-backed or NIST-referenced — include a link to the source standard in the PR description.
4. **Dashboard changes:** export updated JSON from Grafana and replace `grafana/dashboards/cib-overview.json`.

## Dev setup

```bash
cp .env.example .env
make up
docker logs -f cib-checker
```

SBOMs are saved to the `cib-data` volume at `/data/sboms/`.
