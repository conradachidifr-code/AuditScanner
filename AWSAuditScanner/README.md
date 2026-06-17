# AWS Audit Scanner

Python scanner that runs AWS security control checks by domain across multiple accounts. Each check calls the AWS CLI and writes structured JSON results.

## Project structure

```
AWSAuditScanner/
├── scan.py                  # Scanner entry point
├── protect_audit_output.py  # Output anonymizer
├── requirements.txt
├── accounts.json            # Target accounts and SSO profiles
├── audit_scanner/           # Python package
│   ├── scanner.py
│   └── domains/             # LOG, IAM, DET, DAT, GOV, ORG, NET, CIC, BCK, INC, WRK
└── output/                  # Created at runtime (gitignored)
```

Scan output layout:

```
output/
├── log/AuditSession_{timestamp}.log
├── AuditReport_{Domain}_{timestamp}.html
└── {AccountName}_{AccountId}/
    ├── {Domain}_{timestamp}.json
    ├── evidence/{Domain}_{timestamp}_evidence.json
    └── errors/AuditDiagnostics_{Domain}_{timestamp}.log
```

---

## Prerequisites

1. **Python 3.11+** (tested with 3.14)
2. **AWS CLI v2** on your `PATH`
3. **AWS SSO** configured with access to target accounts (`accounts.json`, `aws sso login`)

## Setup

```bash
cd AWSAuditScanner
python3 -m venv .venv
source .venv/bin/activate          # macOS / Linux
# .venv\Scripts\activate.bat       # Windows cmd
python -m pip install --upgrade pip
pip install -r requirements.txt
aws sso login --profile PROD-SEC
```

## Run a scan

```bash
python scan.py --domain IAM --auditor "Jane Doe"
```

**All domains:** `LOG`, `IAM`, `DET`, `DAT`, `GOV`, `ORG`, `NET`, `CIC`, `BCK`, `INC`, `WRK`

### Scan a single account

Use `--account` with an account **name** or **12-digit ID** from `accounts.json`. No need to edit the config file.

```bash
python scan.py --domain NET --account PROD-SEC
python scan.py --domain IAM --account 421366298108
python scan.py --domain BCK --account PROD-SEC,PROD-NET
python scan.py --domain LOG --account PROD-SHARED --account PROD-MON
```

### Dry run (connectivity only)

```bash
python scan.py --domain IAM --dry-run
python scan.py --domain IAM --dry-run --account PROD-SEC
```

### CLI options

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | *(required)* | Domain code |
| `--account` | all | Account name or ID (repeatable or comma-separated) |
| `--auditor` | OS username | Auditor name in metadata |
| `--config-file` | `accounts.json` | Account configuration |
| `--output-path` | `./output` | Output directory |
| `--dry-run` | off | Test SSO connectivity only |
| `--skip-controls` | none | Comma-separated control IDs |
| `--verbose` | off | Print each control status |
| `--sequential` | off | Disable parallel account scanning |
| `--workers` | CPU count | Max parallel account workers |

Parallel account scanning runs one process per account (safe for per-account `AWS_PROFILE`).

An **HTML summary report** is written to `output/AuditReport_{Domain}_{timestamp}.html`.

## Configure accounts

Edit `accounts.json`. Each account entry needs at least `id`, `name`, and optionally:

- `profile` — AWS CLI profile name (must match `~/.aws/config`)
- `role_arn` — full role ARN override (when `auth_mode` is `assume_role`)
- `regions` — override `default_regions`
- `skip` / `skip_reason` — exclude from scans

| `auth_mode` | Behaviour |
|-------------|-----------|
| `sso_profile` | One SSO profile per account (recommended) |
| `assume_role` | `sts assume-role` with `role_arn` / `default_role_path` |
| `auto` | SSO profile first, then `assume_role` |

## Anonymize output

Copy scan results to `output/anonymized/` with account IDs and resource identifiers masked. Account **names** stay visible.

```bash
python protect_audit_output.py --force
python protect_audit_output.py --account PROD-SEC --domain NET --force
```

| Option | Default | Description |
|--------|---------|-------------|
| `--input-path` | `./output` | Source scan output folder |
| `--output-path` | auto | Destination folder |
| `--account` | all | Account name or ID to include |
| `--domain` | all | Domain code to include |
| `--config-file` | `accounts.json` | Resolves account names/IDs |
| `--mapping-file` | `output/anonymization-map.local.json` | Internal ID map (do not share) |
| `--force` | off | Overwrite destination if it exists |

Keep `anonymization-map.local.json` internal — it reverses masked account IDs.

## Troubleshooting

- **`AccessDenied` on `AssumeRole`** — use `"auth_mode": "sso_profile"` and a `profile` per account in `accounts.json`.
- **`No valid SSO profile`** — add `profile` to the account entry or verify `sso_account_id` in `~/.aws/config`.
- **`ExpiredToken`** — run `aws sso login --profile PROD-SEC` again.
- **`PARTIAL` with "API call returned null"** — check `output/{AccountName}_{AccountId}/errors/AuditDiagnostics_{Domain}_{timestamp}.log`.
- **`NOT_TESTED` with "Global control - checked in eu-west-1 only"** — review results from `eu-west-1`.

---

## Français

Scanner Python de contrôles de sécurité AWS par domaine et par compte.

### Lancer un scan

```bash
python scan.py --domain IAM --auditor "Jean Dupont"
```

### Scanner un seul compte

```bash
python scan.py --domain NET --account PROD-SEC
python scan.py --domain IAM --account 421366298108
python scan.py --domain BCK --account PROD-SEC,PROD-NET
```

Aucune modification de `accounts.json` n'est nécessaire.

### Test de connectivité

```bash
python scan.py --domain IAM --dry-run --account PROD-SEC
```

### Anonymiser la sortie

```bash
python protect_audit_output.py --force
python protect_audit_output.py --account PROD-SEC --domain NET --force
```

Les noms de compte restent visibles ; les identifiants AWS et ressources sont masqués. Ne partagez pas `anonymization-map.local.json`.
