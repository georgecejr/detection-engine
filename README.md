# detection-engine

Python engine that loads Sigma rules from `detections/sigma`, evaluates them against sample Okta and AWS events, and keeps a matching SQL query next to each rule.

## Quick start

```bash
python3 -m pip install -r requirements-dev.txt
detection-engine validate
detection-engine list
detection-engine run
pytest
```

`detection-engine run --json` prints the alerts as JSON.

## Layout

```
detections/
├── sigma/                 # Portable Sigma detections
│   ├── okta/
│   │   ├── users/
│   │   └── admin/
│   └── aws/
│       ├── cloudtrail/
│       └── iam/
├── sql/                   # Query-engine SQL (same relative path as Sigma)
│   ├── okta/
│   │   ├── users/
│   │   └── admin/
│   └── aws/
│       ├── cloudtrail/
│       └── iam/
└── samples/
    ├── test_data_1.json   # Okta System Log events
    └── test_data_2.json   # AWS CloudTrail events
src/detection_engine/      # Loader, matcher, CLI
tests/
```

GitHub Actions live at the repository root:

- `.github/workflows/validate.yml` — install the package, validate the tree, run pytest, and evaluate samples
- `.github/workflows/deploy.yml` — re-run validation, package detections, and upload a deploy artifact on `main`

Sigma and SQL files share a path and stem. Example:

- `detections/sigma/okta/users/okta_mfa_factor_reset.yml`
- `detections/sql/okta/users/okta_mfa_factor_reset.sql`

Sample files list `expected_alerts` so CI fails if a starter rule stops firing.

## Adding a detection

1. Add a Sigma rule under `detections/sigma/<vendor>/<category>/`.
2. Add the matching SQL file under `detections/sql/<vendor>/<category>/` with the same filename stem.
3. Add a sample event and an `expected_alerts` entry in `detections/samples/`.
4. Run `detection-engine validate && pytest` before opening a pull request.
