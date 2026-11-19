# MongoDB Managed-Services DBA Toolkit (`mongo_dba_toolkit.sh`)

Production-grade Bash script for MongoDB managed-services DBAs supporting **MongoDB Community** and **Enterprise** across:
- **On-Prem / Self-Managed** (`--deployment onprem`)
- **MongoDB Ops Manager** (`--deployment opsmanager`)
- **MongoDB Atlas** (`--deployment atlas`)

## Dependencies & Exit Codes

Checked at startup: `mongosh`, `jq`, `ssh`, and `timeout` (`curl` and/or `atlas` CLI are optional for Atlas/Ops Manager API workflows).

| Exit Code | Meaning |
|---|---|
| `0` | Success (`PASS` or `WARN` pre-checks only) |
| `2` | Invalid CLI arguments, missing required `--change-id`, or bad option |
| `3` | Missing required dependency |
| `4` | Connection, authentication, or empty secret failure |
| `5` | One or more `FAIL` items in pre-checks or health gate |
| `6` | Typed confirmation rejected / aborted |
| `10` | Runtime error during external/API command execution |

## Password & Secret Handling

- **Never stored or passed via CLI flags:** Passwords and API private keys are prompted via `read -rs` on every run and never written to disk, config files, logs, or shell history.
- **Scoped child-process injection:** `run_mongosh_js()` launches `mongosh` with `env -i` and passes `MONGO_DBA_PW` only to that child command, authenticating inside JavaScript via `process.env.MONGO_DBA_PW`.
- **Exit trap & redaction:** `trap cleanup EXIT INT TERM` clears secret variables, shreds temporary files, and `redact_secrets()` sanitizes logs and terminal output.

## Capability Gating & Safety

- **Dry-run by default:** `switchover` and `rolling-maint` run in dry-run mode unless `--execute` is passed.
- **Typed confirmation:** Live disruptive actions require typing the detected cluster/target name and supplying `--change-id`.
- **Capability gating:** OS SSH checks and direct `replSetStepDown` are gated so Atlas and Community/standalone targets report clear capability boundaries rather than failing unexpectedly.
- **Artifacts:** Logs (`session.log`), reports (`health_report.md` / `health_report.html`), and audit output (`audit_findings.json`) are saved under `./reports/<customer>_<UTC_timestamp>/`.

## Usage Examples

### 1. Interactive Menu
```bash
./mongo_dba_toolkit.sh

## ON PREM

./mongo_dba_toolkit.sh \
  --deployment onprem \
  --uri "mongodb://db1.internal:27017,db2.internal:27017,db3.internal:27017/?replicaSet=rs0" \
  --user dba_admin \
  --auth-db admin \
  --tls \
  --tls-ca /etc/ssl/mongo/ca.pem \
  --ssh-user mongodba \
  --ssh-key ~/.ssh/id_ed25519 \
  --customer acme_prod \
  --action prechecks

## DRY RUN AND LIVE 

# Dry-run (default)
./mongo_dba_toolkit.sh \
  --deployment onprem \
  --host db1.internal:27017 \
  --user dba_admin \
  --tls \
  --action switchover \
  --change-id CHG-2026-4410 \
  --customer acme_prod

# Live execution
./mongo_dba_toolkit.sh \
  --deployment onprem \
  --host db1.internal:27017 \
  --user dba_admin \
  --tls \
  --action switchover \
  --execute \
  --change-id CHG-2026-4410 \
  --customer acme_prod

## ATLAS OPS

# Atlas pre-checks
./mongo_dba_toolkit.sh \
  --deployment atlas \
  --uri "mongodb+srv://cluster0.abcde.mongodb.net/" \
  --user dba_ops \
  --tls \
  --api-public-key "$ATLAS_PUB_KEY" \
  --api-project-id "$ATLAS_PROJECT_ID" \
  --customer globex_atlas \
  --action prechecks

# Ops Manager report and read-only audit
./mongo_dba_toolkit.sh \
  --deployment opsmanager \
  --host om-db1.corp.local:27017 \
  --user dba_admin \
  --tls \
  --api-public-key "$OM_PUB_KEY" \
  --api-project-id "$OM_GROUP_ID" \
  --api-base-url "[https://opsmanager.corp.local:8443](https://opsmanager.corp.local:8443)" \
  --report-format both \
  --customer corp_om \
  --action report

./mongo_dba_toolkit.sh \
  --deployment opsmanager \
  --host om-db1.corp.local:27017 \
  --user dba_auditor \
  --tls \
  --customer corp_om \
  --action audit

## ROLLING

./mongo_dba_toolkit.sh \
  --deployment onprem \
  --host db1.internal:27017 \
  --user dba_admin \
  --tls \
  --action rolling-maint \
  --execute \
  --change-id CHG-2026-4419 \
  --customer acme_prod
