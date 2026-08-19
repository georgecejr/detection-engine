# Detection Engine

Detection-as-code repository for developing, testing, and deploying cloud security detections.

This project uses SQL detections against AWS CloudTrail data, GitHub for version control and collaboration, GitHub Actions for automated validation and deployment, and RunReveal for detection execution and monitoring.

## Architecture

```text
AWS CloudTrail
      |
      v
   AWS S3
      |
      v
   RunReveal
      |
      v
 SQL Detection
      |
      v
 Detection Finding
      |
      v
 GitHub Repository
      |
      v
 Pull Request
      |
      v
 GitHub Actions
      |
      +----------------------+
      |                      |
      v                      v
 Validation              Deployment
      |                      |
      +----------+-----------+
                 |
                 v
             RunReveal
```

## Detection Engineering Workflow

Detections are developed and maintained as code.

```text
Create detection
      ↓
Write SQL
      ↓
Create test data
      ↓
Validate detection
      ↓
Pull Request
      ↓
GitHub Actions
      ↓
Review and merge
      ↓
Automatic deployment
      ↓
RunReveal
```

Changes merged into `main` are automatically deployed to RunReveal through GitHub Actions.

## Current Detections

### AWS Root Account Modification

**Purpose:** Detects non-read-only activity performed using the AWS root account.

**Severity:** High

**Risk Score:** 80

**Data Source:** AWS CloudTrail

Example events include:

* `CreateBucket`
* `PutBucketEncryption`

Detection query:

```sql
SELECT
    eventName,
    eventSource,
    userIdentity.type,
    userIdentity.accountId,
    awsRegion,
    srcIP,
    readOnly
FROM aws_cloudtrail_logs
WHERE userIdentity.type = 'Root'
  AND readOnly = false
```

### AWS S3 Bucket Encryption Modification

**Purpose:** Detects changes to S3 bucket encryption configuration.

**Severity:** Medium

**Risk Score:** 60

**Data Source:** AWS CloudTrail

Detection query:

```sql
SELECT
    eventName,
    eventSource,
    userIdentity.type,
    userIdentity.accountId,
    awsRegion,
    srcIP,
    readOnly
FROM aws_cloudtrail_logs
WHERE eventName = 'PutBucketEncryption'
  AND eventSource = 's3.amazonaws.com'
  AND readOnly = false
```

The detection has been tested against CloudTrail events and successfully generated RunReveal findings.

## Testing

Each detection is tested using positive and negative JSON samples.

A positive sample should trigger the detection.

A negative sample should not trigger the detection.

Current test samples include:

```text
samples/
├── aws_root_account_modification_positive.json
├── aws_root_account_modification_negative.json
├── aws_s3_bucket_encryption_modification_positive.json
└── aws_s3_bucket_encryption_modification_negative.json
```

Detection test definitions are maintained in:

```text
.github/detection-tests.json
```

## CI/CD

GitHub Actions validates detection changes before they reach `main`.

### Pull Requests

The validation workflow checks:

* JSON sample syntax
* Sigma YAML syntax
* SQL detection files
* Detection test configuration

Pull requests must pass the required validation checks before merging into `main`.

### Deployment

Changes merged into `main` trigger the deployment workflow.

```text
Push/Merge to main
        ↓
GitHub Actions
        ↓
RunReveal CLI
        ↓
RUNREVEAL_TOKEN
        ↓
Detection Sync
        ↓
RunReveal
```

The RunReveal API token is stored as a GitHub Actions repository secret and is not committed to the repository.

## Repository Structure

```text
detection-engine/
├── .github/
│   ├── detection-tests.json
│   └── workflows/
│       ├── validate.yml
│       └── deploy.yml
│
├── samples/
│   ├── aws_root_account_modification_positive.json
│   ├── aws_root_account_modification_negative.json
│   ├── aws_s3_bucket_encryption_modification_positive.json
│   ├── aws_s3_bucket_encryption_modification_negative.json
│   ├── test_data_1.json
│   └── test_data_2.json
│
├── sigma/
│   ├── okta/
│   │   ├── users/
│   │   └── admin/
│   └── aws/
│       ├── cloudtrail/
│       └── iam/
│
├── sql/
│   ├── okta/
│   │   ├── users/
│   │   └── admin/
│   └── aws/
│       ├── cloudtrail/
│       └── iam/
│
├── .gitignore
└── README.md
```

## MITRE ATT&CK

Detections are mapped to MITRE ATT&CK tactics and techniques when the detection behavior supports a defensible mapping.

The project avoids adding ATT&CK mappings solely to increase coverage.

## Security Engineering Practices

This project demonstrates:

* Detection-as-code
* SQL-based threat detection
* AWS CloudTrail analysis
* Detection testing
* Positive and negative test cases
* Git version control
* Pull request-based development
* Protected `main` branch
* Automated CI validation
* Automated detection deployment
* RunReveal integration
* MITRE ATT&CK mapping

## Roadmap

Planned improvements include:

* Additional AWS detections
* Sigma rules
* Expanded detection test coverage
* Additional MITRE ATT&CK mappings
* Detection tuning and false-positive analysis
* Alert notification integration
* Detection documentation and investigation guidance
