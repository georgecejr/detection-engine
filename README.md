# detection-engine

Detections-as-code for Okta and AWS. Sigma rules live next to equivalent SQL queries, with sample events and CI that validates the tree on every pull request.

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
```

GitHub Actions live at the repository root (required by GitHub):

- `.github/workflows/validate.yml` — lint Sigma YAML, require a matching SQL file, and parse sample JSON
- `.github/workflows/deploy.yml` — re-run validation, package detections, and upload a deploy artifact on `main`

Sigma and SQL files share a path and stem. Example:

- `detections/sigma/okta/users/okta_mfa_factor_reset.yml`
- `detections/sql/okta/users/okta_mfa_factor_reset.sql`

## Local validation

```bash
python3 -m pip install -r requirements-dev.txt
python3 scripts/validate_detections.py
```

## Adding a detection

1. Add a Sigma rule under `detections/sigma/<vendor>/<category>/`.
2. Add the matching SQL file under `detections/sql/<vendor>/<category>/` with the same filename stem.
3. If the rule needs new event fixtures, extend `detections/samples/`.
4. Run `python3 scripts/validate_detections.py` before opening a pull request.
