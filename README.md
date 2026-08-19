# detection-engine

Detection-as-code repository for Sigma rules and SQL detections, with sample events and GitHub Actions for validation and deploy.

```
.
├── sigma/
│   ├── okta/
│   │   ├── users/
│   │   └── admin/
│   └── aws/
│       ├── cloudtrail/
│       └── iam/
├── sql/
│   ├── okta/
│   │   ├── users/
│   │   └── admin/
│   └── aws/
│       ├── cloudtrail/
│       └── iam/
├── samples/
│   ├── test_data_1.json
│   └── test_data_2.json
└── .github/
    └── workflows/
        ├── validate.yml
        └── deploy.yml
```

## Layout

| Path | Purpose |
| --- | --- |
| `sigma/` | Sigma detection rules, grouped by product and domain |
| `sql/` | SQL detections with the same product/domain split |
| `samples/` | JSON test events used to exercise rules |
| `.github/workflows/` | CI to validate content and package detections for deploy |

## Samples

- `samples/test_data_1.json` — Okta System Log events (session, password reset, MFA deny, privilege grant)
- `samples/test_data_2.json` — AWS CloudTrail / IAM events (user create, admin policy attach, stop logging, assume role)

## Workflows

- **Validate** runs on pull requests and pushes to `main`. It checks JSON samples, parses Sigma YAML, and rejects empty SQL files.
- **Deploy** runs on pushes to `main` (or manually). It packages `sigma/`, `sql/`, and `samples/` as an artifact. Replace the placeholder deploy step with your SIEM or platform publish job.
