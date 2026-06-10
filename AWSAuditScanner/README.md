# AWS Audit Scanner

PowerShell 5.1 tool that runs AWS security control checks by domain across multiple accounts. Each check calls the AWS CLI and writes structured JSON results.

## Project structure

Repository layout (committed to git):

```
AWSAuditScanner/
├── Invoke-AWSScanner.ps1    # Main scanner script
├── accounts.json            # Target accounts and SSO profiles
├── README.md
├── .gitignore               # Ignores output/
└── domains/
    ├── LOG.ps1
    ├── IAM.ps1
    ├── DET.ps1
    ├── DAT.ps1
    ├── GOV.ps1
    ├── ORG.ps1
    ├── NET.ps1
    ├── CIC.ps1
    ├── BCK.ps1
    ├── INC.ps1
    └── WRK.ps1
```

Scan output layout (created at runtime, not committed):

```
output/
├── log/
│   └── AuditSession_{timestamp}.log
├── {AccountName}_{AccountId}/
│   ├── {Domain}_{timestamp}.json          # Scan results
│   ├── evidence/
│   │   └── {Domain}_{timestamp}_evidence.json
│   └── errors/
│       └── AuditDiagnostics_{Domain}_{timestamp}.log
└── {AccountName}_{AccountId}/
    └── ...
```

---

## English

### Prerequisites

1. **Windows PowerShell 5.1** (not PowerShell 7+)
2. **AWS CLI v2** installed and on your `PATH`
3. **AWS SSO** configured with access to the **PROD-SEC** account
4. IAM Identity Center (SSO) permission set **`CCOE_SecurityAudit`** assigned in each target account

### Step 1 — Configure target accounts

Edit `accounts.json` in this folder. Each account entry needs at least:

- `id` — 12-digit AWS account ID
- `name` — short label used in output filenames
- `skip` — set to `true` to exclude an account from scans

Optional per account:

- `profile` — AWS CLI profile name for this account (must match `~/.aws/config`)
- `role_arn` — full role ARN override (only used when `auth_mode` is `assume_role`)
- `regions` — override `default_regions` (e.g. `["eu-west-1"]` only)

**Authentication mode** (`auth_mode` in `accounts.json`, default `sso_profile`):

| Mode | Behaviour |
|------|-----------|
| `sso_profile` | Uses one SSO profile per account (recommended for IAM Identity Center) |
| `assume_role` | Calls `sts assume-role` with `role_arn` / `default_role_path` |
| `auto` | Tries SSO profile first, then falls back to `assume_role` |

With SSO, each account typically has its own profile in `~/.aws/config`:

```ini
[profile PROD-SEC]
sso_account_id = 421366298108
sso_role_name = CCOE_SecurityAudit
sso_start_url = https://...
sso_region = eu-west-1
```

The scanner switches profile per account — it does **not** use cross-account `AssumeRole` unless you set `"auth_mode": "assume_role"`.

### Step 2 — Authenticate with AWS SSO

From a shell where your SSO profiles are configured, log in once (any profile from the same SSO portal):

```powershell
aws sso login --profile PROD-SEC
```

Ensure each account in `accounts.json` has a matching `profile` name. Test each profile:

```powershell
aws sts get-caller-identity --profile PROD-SEC
aws sts get-caller-identity --profile PROD-SHARED
```

Replace profile names with those in your `~/.aws/config` if they differ.

### Step 3 — Open the scanner directory

```powershell
cd path\to\AWSAuditScanner
```

### Step 4 — Verify connectivity (dry run)

Before running a full scan, confirm SSO access works for every account:

```powershell
.\Invoke-AWSScanner.ps1 -Domain IAM -DryRun
```

`-Domain` is required even for dry runs. The domain value is ignored during connectivity checks.

Expected output: a table with `Status = OK` and an identity ARN containing `AWSReservedSSO_CCOE_SecurityAudit` for reachable accounts.

### Step 5 — Run a domain scan

Pick one domain and run the scan:

```powershell
.\Invoke-AWSScanner.ps1 -Domain LOG -Auditor "Jane Doe"
```

**Available domains**

| Domain | Focus |
|--------|--------|
| `LOG` | Logging (CloudTrail, VPC Flow Logs, CloudWatch) |
| `IAM` | Identity and access management |
| `DET` | Detection (scaffold) |
| `DAT` | Data protection and encryption |
| `GOV` | Governance and tagging |
| `ORG` | Organization, SCPs, Identity Center |
| `NET` | Network security |
| `CIC` | CI/CD pipelines and IaC |
| `BCK` | Backup and recovery |
| `INC` | Incident response |
| `WRK` | Workloads (Lambda, ECS, EKS, RDS, API Gateway) |

The scanner loops through each non-skipped account, assumes `CCOE_SecurityAudit`, runs every control in that domain for each configured region, and writes one JSON file per account.

### Step 6 — Review results

Each scanned account gets its own folder under `output/`:

```
output/{AccountName}_{AccountId}/
├── {Domain}_{timestamp}.json
├── evidence/{Domain}_{timestamp}_evidence.json
└── errors/AuditDiagnostics_{Domain}_{timestamp}.log
```

**Results file** (`{Domain}_{timestamp}.json`) — contains `metadata` and a `results` array:

| Field | Meaning |
|-------|---------|
| `Status` | `PASS`, `FAIL`, `PARTIAL`, or `NOT_TESTED` |
| `Severity` | `P0`, `P1`, or `P2` |
| `Evidence` | Structured data collected by the check |
| `Notes` | Human-readable context |

**Evidence file** — controls where evidence or CLI commands were captured, with a `commands_executed` array per control.

**Account diagnostics** — PowerShell exceptions and failed `aws` commands for that account only.

**Session log** — `output/log/AuditSession_{timestamp}.log` covers the full run across all accounts.

A summary table (Passed / Failed / Partial / Not Tested) is printed at the end of each run.

### Optional parameters

```powershell
# Custom config or output location
.\Invoke-AWSScanner.ps1 -Domain NET -ConfigFile C:\audit\accounts.json -OutputPath C:\audit\results

# Skip specific controls (marked NOT_TESTED)
.\Invoke-AWSScanner.ps1 -Domain IAM -SkipControls IAM-10,IAM-24

# Per-control status while running
.\Invoke-AWSScanner.ps1 -Domain DAT -Verbose
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Domain` | *(required)* | Domain code to scan |
| `-Auditor` | `$env:USERNAME` | Name recorded in output metadata |
| `-ConfigFile` | `accounts.json` | Path to account configuration |
| `-OutputPath` | `./output` | Directory for JSON results |
| `-DryRun` | off | Test role assumption only; no checks run |
| `-SkipControls` | none | Comma-separated control IDs to skip |
| `-Verbose` | off | Print each control status as it runs |

### Troubleshooting

- **`AccessDenied` on `AssumeRole`** — normal with SSO. Set `"auth_mode": "sso_profile"` in `accounts.json` and add a `profile` per account matching `~/.aws/config`. Do not use manual `sts assume-role` for cross-account SSO access.
- **`No valid SSO profile`** — add `profile` to the account entry or ensure `sso_account_id` in `~/.aws/config` matches the account `id`.
- **`ExpiredToken` / SSO session expired** — run `aws sso login --profile PROD-SEC` again.
- **`PARTIAL` with "API call returned null"** — the SSO role may lack read permission for that service API. Check `output/{AccountName}_{AccountId}/errors/AuditDiagnostics_{Domain}_{timestamp}.log` for the failed `aws` command and CLI error text.
- **PowerShell exceptions in results** — open the diagnostics log for the full exception, stack trace, and CLI commands from that control.
- **`NOT_TESTED` with "Global control - checked in eu-west-1 only"** — some org-wide controls run only in `eu-west-1`; review results from that region.

---

## Français

### Prérequis

1. **Windows PowerShell 5.1** (pas PowerShell 7+)
2. **AWS CLI v2** installé et accessible dans le `PATH`
3. **AWS SSO** configuré avec accès au compte **PROD-SEC**
4. Permission set IAM Identity Center (SSO) **`CCOE_SecurityAudit`** assigné dans chaque compte cible

### Étape 1 — Configurer les comptes cibles

Modifiez `accounts.json` dans ce dossier. Chaque entrée de compte doit contenir au minimum :

- `id` — identifiant AWS à 12 chiffres
- `name` — libellé court utilisé dans les noms de fichiers de sortie
- `skip` — mettre à `true` pour exclure un compte des scans

Options par compte :

- `profile` — nom du profil AWS CLI (doit correspondre à `~/.aws/config`)
- `role_arn` — ARN complet (utilisé uniquement si `auth_mode` vaut `assume_role`)
- `regions` — remplace `default_regions` (ex. `["eu-west-1"]` uniquement)

**Mode d'authentification** (`auth_mode` dans `accounts.json`, défaut `sso_profile`) :

| Mode | Comportement |
|------|--------------|
| `sso_profile` | Un profil SSO par compte (recommandé avec IAM Identity Center) |
| `assume_role` | Appelle `sts assume-role` avec `role_arn` / `default_role_path` |
| `auto` | Essaie d'abord le profil SSO, puis `assume_role` |

Avec SSO, chaque compte a généralement son propre profil dans `~/.aws/config`. Le scanner change de profil par compte — il n'utilise **pas** `AssumeRole` inter-comptes sauf si `"auth_mode": "assume_role"`.

### Étape 2 — S'authentifier avec AWS SSO

Depuis un shell où vos profils SSO sont configurés, connectez-vous une fois (n'importe quel profil du même portail SSO) :

```powershell
aws sso login --profile PROD-SEC
```

Vérifiez que chaque compte dans `accounts.json` a un champ `profile` correspondant. Testez chaque profil :

```powershell
aws sts get-caller-identity --profile PROD-SEC
aws sts get-caller-identity --profile PROD-SHARED
```

### Étape 3 — Se placer dans le répertoire du scanner

```powershell
cd chemin\vers\AWSAuditScanner
```

### Étape 4 — Vérifier la connectivité (dry run)

Avant un scan complet, vérifiez que l'assumption de rôle fonctionne pour chaque compte :

```powershell
.\Invoke-AWSScanner.ps1 -Domain IAM -DryRun
```

`-Domain` est obligatoire même en dry run. La valeur du domaine est ignorée lors des tests de connectivité.

Résultat attendu : un tableau avec `Status = OK` pour les comptes accessibles. Les comptes marqués `SKIPPED` dans `accounts.json` apparaissent avec leur motif d'exclusion.

### Étape 5 — Lancer un scan par domaine

Choisissez un domaine et exécutez le scan :

```powershell
.\Invoke-AWSScanner.ps1 -Domain LOG -Auditor "Jean Dupont"
```

**Domaines disponibles**

| Domaine | Périmètre |
|---------|-----------|
| `LOG` | Journalisation (CloudTrail, VPC Flow Logs, CloudWatch) |
| `IAM` | Gestion des identités et des accès |
| `DET` | Détection (ébauche) |
| `DAT` | Protection et chiffrement des données |
| `GOV` | Gouvernance et étiquetage |
| `ORG` | Organisation, SCP, Identity Center |
| `NET` | Sécurité réseau |
| `CIC` | Pipelines CI/CD et IaC |
| `BCK` | Sauvegarde et reprise |
| `INC` | Réponse aux incidents |
| `WRK` | Charges de travail (Lambda, ECS, EKS, RDS, API Gateway) |

Le scanner parcourt chaque compte non exclu, assume `CCOE_SecurityAudit`, exécute tous les contrôles du domaine pour chaque région configurée, et écrit un fichier JSON par compte.

### Étape 6 — Consulter les résultats

Chaque compte scanné dispose de son propre dossier sous `output/` :

```
output/{AccountName}_{AccountId}/
├── {Domain}_{timestamp}.json
├── evidence/{Domain}_{timestamp}_evidence.json
└── errors/AuditDiagnostics_{Domain}_{timestamp}.log
```

**Fichier de résultats** — contient `metadata` et le tableau `results` :

| Champ | Signification |
|-------|---------------|
| `Status` | `PASS`, `FAIL`, `PARTIAL` ou `NOT_TESTED` |
| `Severity` | `P0`, `P1` ou `P2` |
| `Evidence` | Données structurées collectées par le contrôle |
| `Notes` | Contexte lisible pour l'auditeur |

**Fichier de preuves** — contrôles avec preuves ou commandes CLI capturées.

**Diagnostics par compte** — exceptions PowerShell et échecs `aws` pour ce compte uniquement.

**Journal de session** — `output/log/AuditSession_{timestamp}.log` pour l'exécution complète.

Un tableau récapitulatif (Passed / Failed / Partial / Not Tested) s'affiche à la fin de chaque exécution.

### Paramètres optionnels

```powershell
# Fichier de config ou dossier de sortie personnalisé
.\Invoke-AWSScanner.ps1 -Domain NET -ConfigFile C:\audit\accounts.json -OutputPath C:\audit\results

# Ignorer certains contrôles (marqués NOT_TESTED)
.\Invoke-AWSScanner.ps1 -Domain IAM -SkipControls IAM-10,IAM-24

# Afficher le statut de chaque contrôle pendant l'exécution
.\Invoke-AWSScanner.ps1 -Domain DAT -Verbose
```

| Paramètre | Valeur par défaut | Description |
|-----------|-------------------|-------------|
| `-Domain` | *(obligatoire)* | Code du domaine à scanner |
| `-Auditor` | `$env:USERNAME` | Nom enregistré dans les métadonnées |
| `-ConfigFile` | `accounts.json` | Chemin vers la configuration des comptes |
| `-OutputPath` | `./output` | Répertoire des résultats JSON |
| `-DryRun` | désactivé | Teste uniquement l'assumption de rôle |
| `-SkipControls` | aucun | IDs de contrôles à ignorer, séparés par des virgules |
| `-Verbose` | désactivé | Affiche le statut de chaque contrôle en cours d'exécution |

### Dépannage

- **`AccessDenied` sur `AssumeRole`** — normal avec SSO. Définissez `"auth_mode": "sso_profile"` dans `accounts.json` et un champ `profile` par compte correspondant à `~/.aws/config`.
- **`No valid SSO profile`** — ajoutez `profile` à l'entrée du compte ou vérifiez que `sso_account_id` dans `~/.aws/config` correspond à l'`id` du compte.
- **`ExpiredToken` / session SSO expirée** — relancez `aws sso login --profile PROD-SEC`.
- **`PARTIAL` avec "API call returned null"** — le rôle SSO peut ne pas avoir les droits de lecture sur l'API concernée. Consultez `output/{AccountName}_{AccountId}/errors/AuditDiagnostics_{Domaine}_{timestamp}.log`.
- **Exceptions PowerShell dans les résultats** — ouvrez le journal de diagnostic pour l'exception complète, la pile d'appels et les commandes CLI du contrôle.
- **`NOT_TESTED` avec "Global control - checked in eu-west-1 only"** — certains contrôles organisationnels ne s'exécutent qu'en `eu-west-1`.
