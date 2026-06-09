# AWS Audit Scanner

PowerShell 5.1 tool that runs AWS security control checks by domain across multiple accounts. Each check calls the AWS CLI and writes structured JSON results.

---

## English

### Prerequisites

1. **Windows PowerShell 5.1** (not PowerShell 7+)
2. **AWS CLI v2** installed and on your `PATH`
3. **AWS SSO** configured with access to the **PROD-SEC** account
4. Permission to assume **`CCOE_DataRead`** in each target account listed in `accounts.json`

### Step 1 — Configure target accounts

Edit `accounts.json` in this folder. Each account entry needs at least:

- `id` — 12-digit AWS account ID
- `name` — short label used in output filenames
- `skip` — set to `true` to exclude an account from scans

Optional per account:

- `role_arn` — override the default role ARN
- `regions` — override `default_regions` (e.g. `["eu-west-1"]` only)

The default role is built as `arn:aws:iam::<account-id>:role/CCOE_DataRead`.

### Step 2 — Authenticate with AWS SSO

From a shell where your SSO profile is configured, log in using the **PROD-SEC** profile:

```powershell
aws sso login --profile PROD-SEC
```

Set that profile for the scan session:

```powershell
$env:AWS_PROFILE = 'PROD-SEC'
```

Replace `PROD-SEC` with your actual profile name if it differs.

### Step 3 — Open the scanner directory

```powershell
cd path\to\AWSAuditScanner
```

### Step 4 — Verify connectivity (dry run)

Before running a full scan, confirm role assumption works for every account:

```powershell
.\Invoke-AWSScanner.ps1 -Domain IAM -DryRun
```

`-Domain` is required even for dry runs. The domain value is ignored during connectivity checks.

Expected output: a table with `Status = OK` for reachable accounts. Accounts marked `SKIPPED` in `accounts.json` are listed with their skip reason.

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

The scanner loops through each non-skipped account, assumes `CCOE_DataRead`, runs every control in that domain for each configured region, and writes one JSON file per account.

### Step 6 — Review results

**Scan output** — one file per account per run:

```
output/{AccountName}_{AccountId}_{Domain}_{timestamp}.json
```

Each file contains `metadata` (account, domain, auditor, regions) and a `results` array. Each result includes:

| Field | Meaning |
|-------|---------|
| `Status` | `PASS`, `FAIL`, `PARTIAL`, or `NOT_TESTED` |
| `Severity` | `P0`, `P1`, or `P2` |
| `Evidence` | Structured data collected by the check |
| `Notes` | Human-readable context |

**Session log** — written to `output/errors/AuditSession_{timestamp}.log`.

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

- **`Failed to assume role`** — confirm SSO login is still valid (`aws sso login`) and `CCOE_DataRead` trust allows your PROD-SEC identity.
- **`PARTIAL` with "API call returned null"** — the assumed role may lack read permission for that service API.
- **`NOT_TESTED` with "Global control - checked in eu-west-1 only"** — some org-wide controls run only in `eu-west-1`; review results from that region.
- **No `accounts.json`** — the scanner falls back to SSO profiles in `~/.aws/config` and assumes `CCOE_DataRead` in each discovered account.

---

## Français

### Prérequis

1. **Windows PowerShell 5.1** (pas PowerShell 7+)
2. **AWS CLI v2** installé et accessible dans le `PATH`
3. **AWS SSO** configuré avec accès au compte **PROD-SEC**
4. Droit d'assumer le rôle **`CCOE_DataRead`** dans chaque compte cible listé dans `accounts.json`

### Étape 1 — Configurer les comptes cibles

Modifiez `accounts.json` dans ce dossier. Chaque entrée de compte doit contenir au minimum :

- `id` — identifiant AWS à 12 chiffres
- `name` — libellé court utilisé dans les noms de fichiers de sortie
- `skip` — mettre à `true` pour exclure un compte des scans

Options par compte :

- `role_arn` — remplace l'ARN de rôle par défaut
- `regions` — remplace `default_regions` (ex. `["eu-west-1"]` uniquement)

Le rôle par défaut est construit ainsi : `arn:aws:iam::<account-id>:role/CCOE_DataRead`.

### Étape 2 — S'authentifier avec AWS SSO

Depuis un shell où votre profil SSO est configuré, connectez-vous avec le profil **PROD-SEC** :

```powershell
aws sso login --profile PROD-SEC
```

Définissez ce profil pour la session de scan :

```powershell
$env:AWS_PROFILE = 'PROD-SEC'
```

Remplacez `PROD-SEC` par le nom réel de votre profil si nécessaire.

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

Le scanner parcourt chaque compte non exclu, assume `CCOE_DataRead`, exécute tous les contrôles du domaine pour chaque région configurée, et écrit un fichier JSON par compte.

### Étape 6 — Consulter les résultats

**Sortie du scan** — un fichier par compte et par exécution :

```
output/{AccountName}_{AccountId}_{Domain}_{timestamp}.json
```

Chaque fichier contient `metadata` (compte, domaine, auditeur, régions) et un tableau `results`. Chaque résultat inclut :

| Champ | Signification |
|-------|---------------|
| `Status` | `PASS`, `FAIL`, `PARTIAL` ou `NOT_TESTED` |
| `Severity` | `P0`, `P1` ou `P2` |
| `Evidence` | Données structurées collectées par le contrôle |
| `Notes` | Contexte lisible pour l'auditeur |

**Journal de session** — enregistré dans `output/errors/AuditSession_{timestamp}.log`.

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

- **`Failed to assume role`** — vérifiez que la session SSO est encore valide (`aws sso login`) et que la relation de confiance de `CCOE_DataRead` autorise votre identité PROD-SEC.
- **`PARTIAL` avec "API call returned null"** — le rôle assumé peut ne pas avoir les droits de lecture sur l'API concernée.
- **`NOT_TESTED` avec "Global control - checked in eu-west-1 only"** — certains contrôles organisationnels ne s'exécutent qu'en `eu-west-1` ; consultez les résultats de cette région.
- **Absence de `accounts.json`** — le scanner utilise les profils SSO de `~/.aws/config` et assume `CCOE_DataRead` dans chaque compte découvert.
