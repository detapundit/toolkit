#!/usr/bin/env bash
# ==============================================================================
# mongo_dba_toolkit.sh  (patched revision)
# Production-grade MongoDB Managed-Services DBA Toolkit
# Supports: Community & Enterprise | onprem, opsmanager, atlas
#
# Requirements : bash >= 4.3, GNU coreutils/findutils (timeout, date -d, shred,
#                find -printf), mongosh, jq. Optional: ssh, openssl, curl, atlas.
#                Linux only (macOS needs GNU coreutils + gnubin on PATH).
#
# Design rules
#   * A check that cannot be evaluated is NEVER reported as PASS (fail closed).
#   * Disruptive actions verify the outcome (new primary elected) and never
#     swallow errors.
#   * Secrets are prompted for, held only in shell variables, and handed to
#     children via per-command environment or stdin - never argv or disk.
# ==============================================================================
# shellcheck disable=SC2034  # API_BASE_URL is reserved for Ops Manager (backup-age lookup not implemented)
set -euo pipefail
IFS=$'\n\t'
# bash 5.2 treats '&' in ${var//pat/repl} replacements specially unless disabled
shopt -u patsub_replacement 2>/dev/null || true

# --- Exit Codes ---------------------------------------------------------------
readonly EXIT_OK=0
readonly EXIT_USAGE=2
readonly EXIT_DEPENDENCY=3
readonly EXIT_AUTH_CONN=4
readonly EXIT_PRECHECK_FAIL=5
readonly EXIT_ABORTED=6
readonly EXIT_RUNTIME_ERR=10

# --- Thresholds ---------------------------------------------------------------
readonly LAG_WARN_SEC=10
readonly LAG_FAIL_SEC=30
readonly STEPDOWN_WAIT_SEC=90
readonly ATLAS_FAILOVER_WAIT_SEC=300
# Atlas Admin API (v2) uses dated media types. Verify against your tenant; an
# unsupported version is reported (HTTP 406/4xx) and never treated as success.
readonly ATLAS_API_VER_FAILOVER="2023-02-01"
readonly ATLAS_API_VER_SNAPSHOTS="2023-01-01"

# --- Defaults & Global State --------------------------------------------------
DEPLOYMENT=""
HOST_OR_URI=""
DB_USER=""
AUTH_DB="admin"
USE_TLS="false"
TLS_CA_FILE=""
ACTION=""
DRY_RUN="true"
CHANGE_ID=""
CUSTOMER_NAME="default_customer"
SSH_USER=""
SSH_KEY=""
SSH_TIMEOUT=10
SSH_ACCEPT_NEW="false"
MONGOSH_TIMEOUT=30
API_PUBLIC_KEY=""
API_PROJECT_ID=""
API_BASE_URL=""
ATLAS_CLUSTER=""
SHARD_ID=""
MAINT_HOOK=""
MAINT_WAIT=900
REPORT_FORMAT="both" # markdown | html | both
BACKUP_DIR=""

# Sensitive values (populated only at runtime via read -rs, cleared on exit).
# Deliberately NOT exported: children only receive them via explicit env/stdin.
MONGO_PASSWORD=""
API_PRIVATE_KEY=""

# Runtime environment & paths
RUN_TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT_DIR=""
LOG_FILE=""
SESSION_TMP_DIR=""

# Detected cluster metadata
DETECTED_EDITION="unknown"      # Community | Enterprise | unknown
DETECTED_VERSION="unknown"
DETECTED_FCV="unknown"
DETECTED_TOPOLOGY="unknown"     # standalone | replicaset | sharded | unknown
DETECTED_CLUSTER_NAME="unknown"
DETECTED_SHARDS_JSON="[]"
DETECTED_MEMBERS_JSON="[]"
DETECTED_CONFIG_SERVERS=""
DETECTED_DBPATH=""

# Change-action target (resolved by resolve_target_rs)
TARGET_RS_URI=""
TARGET_RS_LABEL=""
NEW_PRIMARY=""

# Pre-check counters
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
PRECHECK_RESULTS_FILE=""
NODE_STATS_FILE=""
LAST_RS_NODES="[]"
NODE_VERSION=""
NODE_DBPATH=""
OS_SKIPPED=0
declare -A OS_CHECKED=()

# --- Secret Redaction & Cleanup Trap -----------------------------------------
redact_secrets() {
  local line="$1"
  # NOTE: the pattern side MUST be quoted, otherwise glob characters in a
  # password ( * ? [ ] ) change the match and the secret can leak into logs.
  if [[ -n "${MONGO_PASSWORD:-}" ]]; then
    line="${line//"${MONGO_PASSWORD}"/[REDACTED_PASSWORD]}"
  fi
  if [[ -n "${API_PRIVATE_KEY:-}" ]]; then
    line="${line//"${API_PRIVATE_KEY}"/[REDACTED_API_KEY]}"
  fi
  # Credentials embedded in mongodb / mongodb+srv URIs and query parameters
  line="$(printf '%s' "$line" | sed -E 's#(mongodb(\+srv)?://[^:/@]+:)[^@]+(@)#\1[REDACTED_PASSWORD]\3#g')"
  line="$(printf '%s' "$line" | sed -E 's/([?&](password|Password|PASSWORD|privateKey|apiKey|token)=)[^&[:space:]]+/\1[REDACTED]/g')"
  printf '%s\n' "$line"
}

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  MONGO_PASSWORD=""
  API_PRIVATE_KEY=""
  unset MONGO_PASSWORD API_PRIVATE_KEY 2>/dev/null || true

  if [[ -n "${SESSION_TMP_DIR}" && -d "${SESSION_TMP_DIR}" ]]; then
    find "${SESSION_TMP_DIR}" -type f -exec shred -u {} + 2>/dev/null || true
    rm -rf "${SESSION_TMP_DIR}" 2>/dev/null || true
  fi

  if [[ -n "${LOG_FILE}" && -f "${LOG_FILE}" ]]; then
    printf '[%s] [INFO] Session ended (exit_code=%d). Secrets scrubbed.\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$exit_code" >> "${LOG_FILE}" || true
  fi
  exit "$exit_code"
}

# --- Logging Helpers ----------------------------------------------------------
init_logging() {
  local safe_customer
  safe_customer="$(printf '%s' "$CUSTOMER_NAME" | tr -cs 'A-Za-z0-9._-' '_')"
  REPORT_DIR="./reports/${safe_customer}_${RUN_TIMESTAMP}"
  SESSION_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mongo_dba.XXXXXX")"
  chmod 700 "${SESSION_TMP_DIR}"
  mkdir -p "${REPORT_DIR}"
  chmod 750 "${REPORT_DIR}"
  LOG_FILE="${REPORT_DIR}/session.log"
  PRECHECK_RESULTS_FILE="${SESSION_TMP_DIR}/prechecks.tsv"
  NODE_STATS_FILE="${SESSION_TMP_DIR}/node_stats.jsonl"
  : > "${LOG_FILE}"
  : > "${PRECHECK_RESULTS_FILE}"
  : > "${NODE_STATS_FILE}"
  chmod 600 "${LOG_FILE}" "${PRECHECK_RESULTS_FILE}" "${NODE_STATS_FILE}"
}

log_msg() {
  local level="$1"
  shift
  local msg
  msg="$(redact_secrets "$*")"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '[%s] [%s] %s\n' "$ts" "$level" "$msg" | tee -a "${LOG_FILE:-/dev/null}" >&2
}

log_info()  { log_msg "INFO"  "$*"; }
log_warn()  { log_msg "WARN"  "$*"; }
log_error() { log_msg "ERROR" "$*"; }

# --- Small utilities ----------------------------------------------------------
# Float comparisons without bc: num_gt A B  =>  A > B
num_gt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 > b + 0) }'; }
num_lt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 < b + 0) }'; }
is_number() { [[ "${1:-}" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; }

html_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

md_escape() {
  local s="$1"
  s="${s//|/\\|}"
  printf '%s' "$s"
}

# --- Usage / Help -------------------------------------------------------------
usage() {
  cat <<'EOF'
Usage: mongo_dba_toolkit.sh [OPTIONS]

MongoDB Managed-Services DBA Toolkit for Community & Enterprise across
on-prem/self-managed, Ops Manager, and MongoDB Atlas.

Connection:
  --deployment <type>      onprem | opsmanager | atlas
  --host <host[:port]>     Target host/port (or comma-separated seed list)
  --uri <mongodb-uri>      MongoDB connection URI (without embedded password)
  --user <username>        Database username (SCRAM; password is prompted)
  --auth-db <db>           Authentication database (default: admin)
  --tls                    Enable TLS for mongosh connections
  --tls-ca <path>          CA bundle path when --tls is set
  --timeout <sec>          Timeout per mongosh command (default: 30)

Actions:
  --action <action>        prechecks | switchover | rolling-maint | report | audit
  --dry-run                Dry-run (default for change actions)
  --execute                Perform live changes after typed confirmation
  --change-id <id>         Change ticket / RFC ID (required for change actions)
  --customer <name>        Customer/environment label (REQUIRED with --execute;
                           part of the typed confirmation phrase)
  --shard <shardId>        Sharded clusters: shard that switchover/rolling-maint
                           operates on (required for those actions)

Rolling maintenance:
  --maint-hook <path>      Absolute path of an executable invoked per node as
                           <hook> <host:port> <role> <change-id>. Non-zero exit
                           halts the run. Without a hook the script pauses for
                           manual maintenance (needs a TTY).
  --maint-wait <sec>       Max wait for a node to rejoin and catch up (900)

OS / backup / Atlas:
  --ssh-user <user>        SSH username for OS-level checks (onprem/opsmanager)
  --ssh-key <path>         SSH private key path
  --ssh-accept-new         Accept unseen SSH host keys (default: strict checking;
                           pre-seed known_hosts for production)
  --backup-dir <path>      On-prem: directory (readable from this host) whose
                           newest file timestamp is used as backup age
  --api-public-key <key>   Ops Manager / Atlas API public key
  --api-project-id <id>    Ops Manager groupId or Atlas projectId
  --api-base-url <url>     Ops Manager base URL
  --atlas-cluster <name>   Atlas cluster NAME (not the replica-set name); needed
                           for Atlas backup check and failover

Reporting:
  --report-format <fmt>    markdown | html | both (default: both)
  -h, --help               Show this help message and exit

Security Notes:
  - Passwords and API private keys are NEVER accepted via CLI flags or files.
  - You are prompted with `read -rs`; secrets are passed to children only via
    per-command environment variables or stdin (never argv).
EOF
}

# --- Input Validation ---------------------------------------------------------
is_change_action() {
  local act="${1:-}"
  [[ "$act" == "switchover" || "$act" == "rolling-maint" ]]
}

validate_inputs() {
  local re_name='^[A-Za-z0-9._-]{1,64}$'
  local re_authdb='^[A-Za-z0-9._$-]{1,64}$'
  local re_hostlist='^[]A-Za-z0-9._:,[-]+$'

  if [[ -n "$DEPLOYMENT" ]]; then
    case "$DEPLOYMENT" in
      onprem|opsmanager|atlas) ;;
      *) log_error "Invalid --deployment '$DEPLOYMENT'. Must be onprem, opsmanager, or atlas."; return "$EXIT_USAGE" ;;
    esac
  fi

  if [[ -n "$ACTION" ]]; then
    case "$ACTION" in
      prechecks|switchover|rolling-maint|report|audit) ;;
      *) log_error "Invalid --action '$ACTION'."; return "$EXIT_USAGE" ;;
    esac
  fi

  case "$USE_TLS" in
    true|false) ;;
    *) log_error "Invalid --tls value '$USE_TLS'."; return "$EXIT_USAGE" ;;
  esac

  case "$REPORT_FORMAT" in
    markdown|html|both) ;;
    *) log_error "Invalid --report-format '$REPORT_FORMAT'."; return "$EXIT_USAGE" ;;
  esac

  if [[ ! "$MONGOSH_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    log_error "Invalid --timeout '$MONGOSH_TIMEOUT' (must be a positive integer)."; return "$EXIT_USAGE"
  fi
  if [[ ! "$MAINT_WAIT" =~ ^[1-9][0-9]*$ ]]; then
    log_error "Invalid --maint-wait '$MAINT_WAIT' (must be a positive integer)."; return "$EXIT_USAGE"
  fi

  if [[ ! "$AUTH_DB" =~ $re_authdb ]]; then
    log_error "Invalid --auth-db '$AUTH_DB'."; return "$EXIT_USAGE"
  fi

  if [[ -n "$SHARD_ID" && ! "$SHARD_ID" =~ $re_name ]]; then
    log_error "Invalid --shard '$SHARD_ID'."; return "$EXIT_USAGE"
  fi
  if [[ -n "$ATLAS_CLUSTER" && ! "$ATLAS_CLUSTER" =~ $re_name ]]; then
    log_error "Invalid --atlas-cluster '$ATLAS_CLUSTER'."; return "$EXIT_USAGE"
  fi

  if [[ -n "$TLS_CA_FILE" && ! -r "$TLS_CA_FILE" ]]; then
    log_error "TLS CA file not readable: $TLS_CA_FILE"; return "$EXIT_USAGE"
  fi
  if [[ -n "$SSH_KEY" && ! -r "$SSH_KEY" ]]; then
    log_error "SSH key file not readable: $SSH_KEY"; return "$EXIT_USAGE"
  fi
  if [[ -n "$MAINT_HOOK" ]]; then
    if [[ "$MAINT_HOOK" != /* || ! -x "$MAINT_HOOK" || -d "$MAINT_HOOK" ]]; then
      log_error "--maint-hook must be an absolute path to an executable file: $MAINT_HOOK"
      return "$EXIT_USAGE"
    fi
  fi

  if [[ -n "$HOST_OR_URI" ]]; then
    if [[ "$HOST_OR_URI" =~ :[^:@/]+@ ]]; then
      log_error "Do not embed passwords in --uri/--host. Use --user and the interactive password prompt."
      return "$EXIT_USAGE"
    fi
    if [[ "$HOST_OR_URI" == mongodb://* || "$HOST_OR_URI" == mongodb+srv://* ]]; then
      if [[ "$HOST_OR_URI" =~ [[:space:]] ]]; then
        log_error "--uri must not contain whitespace."; return "$EXIT_USAGE"
      fi
    elif [[ ! "$HOST_OR_URI" =~ $re_hostlist ]]; then
      log_error "Invalid --host '$HOST_OR_URI' (expected host[:port][,host[:port]...])."
      return "$EXIT_USAGE"
    fi
  fi

  if is_change_action "$ACTION"; then
    if [[ -z "$CHANGE_ID" ]]; then
      log_error "Action '$ACTION' requires a non-empty --change-id."
      return "$EXIT_USAGE"
    fi
    if [[ ! "$CHANGE_ID" =~ ^[A-Za-z0-9._-]{3,64}$ ]]; then
      log_error "Invalid --change-id '$CHANGE_ID'. Use 3-64 alphanumeric, dot, underscore, or hyphen chars."
      return "$EXIT_USAGE"
    fi
    if [[ "$DRY_RUN" == "false" && "$CUSTOMER_NAME" == "default_customer" ]]; then
      log_error "--execute requires an explicit --customer (it is part of the typed confirmation phrase)."
      return "$EXIT_USAGE"
    fi
    if [[ "$ACTION" == "rolling-maint" && "$DEPLOYMENT" == "atlas" ]]; then
      log_error "rolling-maint does not apply to Atlas (Atlas performs rolling maintenance itself)."
      return "$EXIT_USAGE"
    fi
  fi
  return "$EXIT_OK"
}

# Checks that need the detected topology
validate_after_detect() {
  if ! is_change_action "$ACTION"; then
    return "$EXIT_OK"
  fi

  if [[ "$DETECTED_TOPOLOGY" == "sharded" ]]; then
    local known
    known="$(printf '%s' "$DETECTED_SHARDS_JSON" | jq -r '[.[]?._id] | join(", ")')"
    if [[ -z "$SHARD_ID" ]]; then
      log_error "Sharded cluster: '$ACTION' operates on one shard at a time. Pass --shard <shardId> (known shards: ${known:-none})."
      return "$EXIT_USAGE"
    fi
    if ! printf '%s' "$DETECTED_SHARDS_JSON" | jq -e --arg s "$SHARD_ID" 'any(.[]?; ._id == $s)' >/dev/null 2>&1; then
      log_error "Shard '$SHARD_ID' not found (known shards: ${known:-none})."
      return "$EXIT_USAGE"
    fi
  elif [[ -n "$SHARD_ID" ]]; then
    log_warn "--shard ignored: topology is ${DETECTED_TOPOLOGY}."
    SHARD_ID=""
  fi

  if [[ "$ACTION" == "rolling-maint" && "$DRY_RUN" == "false" && -z "$MAINT_HOOK" && ! -t 0 ]]; then
    log_error "Live rolling-maint needs --maint-hook, or an interactive terminal for manual pauses."
    return "$EXIT_USAGE"
  fi
  if [[ "$DEPLOYMENT" == "opsmanager" && "$ACTION" == "rolling-maint" ]]; then
    log_warn "Ops Manager deployment: do node maintenance through Ops Manager automation (e.g. drive it from --maint-hook); manual changes may be reverted by the automation agent."
  fi
  return "$EXIT_OK"
}

# --- Dependency Checks --------------------------------------------------------
check_dependencies() {
  local missing=0
  local cmd
  for cmd in mongosh jq timeout; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      log_error "Required dependency not found in PATH: $cmd"
      missing=1
    fi
  done
  if [[ "$DEPLOYMENT" != "atlas" && -n "$SSH_USER" ]] && ! command -v ssh >/dev/null 2>&1; then
    log_error "--ssh-user given but 'ssh' not found in PATH."
    missing=1
  fi
  if ! date -u -d '@0' +%s >/dev/null 2>&1; then
    log_error "GNU 'date -d' is required (this script targets GNU/Linux)."
    missing=1
  fi

  if [[ "$DEPLOYMENT" == "atlas" ]]; then
    if ! command -v curl >/dev/null 2>&1 && ! command -v atlas >/dev/null 2>&1; then
      log_warn "Neither 'curl' nor 'atlas' CLI found; Atlas backup/failover actions are unavailable."
    fi
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    log_warn "'openssl' not found; TLS certificate expiry checks will report WARN."
  fi

  if (( missing > 0 )); then
    return "$EXIT_DEPENDENCY"
  fi
  log_info "Core dependencies verified."
  return "$EXIT_OK"
}

# --- Secret Prompting (Never saved to disk/history/args) ---------------------
prompt_secrets() {
  if [[ -n "$DB_USER" && -z "$MONGO_PASSWORD" ]]; then
    printf 'Enter MongoDB password for user "%s": ' "$DB_USER" >&2
    IFS= read -rs MONGO_PASSWORD || true
    printf '\n' >&2
    if [[ -z "$MONGO_PASSWORD" ]]; then
      log_error "Empty password provided for user '$DB_USER'."
      return "$EXIT_AUTH_CONN"
    fi
  fi

  if [[ "$DEPLOYMENT" == "atlas" || "$DEPLOYMENT" == "opsmanager" ]]; then
    if [[ -n "$API_PUBLIC_KEY" && -z "$API_PRIVATE_KEY" ]]; then
      printf 'Enter %s API private key for "%s": ' "$DEPLOYMENT" "$API_PUBLIC_KEY" >&2
      IFS= read -rs API_PRIVATE_KEY || true
      printf '\n' >&2
      if [[ -z "$API_PRIVATE_KEY" ]]; then
        log_error "Empty API private key provided."
        return "$EXIT_AUTH_CONN"
      fi
    fi
  fi
  return "$EXIT_OK"
}

# --- Interactive Menu ---------------------------------------------------------
interactive_menu() {
  echo "=== MongoDB Managed-Services DBA Toolkit ===" >&2
  if [[ -z "$DEPLOYMENT" ]]; then
    echo "Select deployment type:" >&2
    echo "  1) onprem (self-managed / bare-metal / VM)" >&2
    echo "  2) opsmanager (MongoDB Ops Manager)" >&2
    echo "  3) atlas (MongoDB Atlas)" >&2
    printf "Choice [1-3]: " >&2
    local d_choice
    IFS= read -r d_choice
    case "$d_choice" in
      1) DEPLOYMENT="onprem" ;;
      2) DEPLOYMENT="opsmanager" ;;
      3) DEPLOYMENT="atlas" ;;
      *) log_error "Invalid selection."; return "$EXIT_USAGE" ;;
    esac
  fi

  if [[ -z "$HOST_OR_URI" ]]; then
    printf "Enter target host[:port] or MongoDB URI (no password): " >&2
    IFS= read -r HOST_OR_URI
  fi

  if [[ -z "$DB_USER" ]]; then
    printf "Enter MongoDB username (leave blank if authentication is disabled): " >&2
    IFS= read -r DB_USER
  fi

  if [[ -n "$DB_USER" && "$AUTH_DB" == "admin" ]]; then
    printf "Authentication database [admin]: " >&2
    local adb
    IFS= read -r adb
    if [[ -n "$adb" ]]; then AUTH_DB="$adb"; fi
  fi

  if [[ -z "$ACTION" ]]; then
    echo "Select action:" >&2
    echo "  1) prechecks      - Full health & readiness pre-checks (PASS/WARN/FAIL)" >&2
    echo "  2) switchover     - Controlled primary step-down / failover" >&2
    echo "  3) rolling-maint  - Rolling maintenance orchestration (secondaries first)" >&2
    echo "  4) report         - Pre-check based health report (Markdown/HTML)" >&2
    echo "  5) audit          - Read-only user/role & slow-query/index analysis" >&2
    printf "Choice [1-5]: " >&2
    local a_choice
    IFS= read -r a_choice
    case "$a_choice" in
      1) ACTION="prechecks" ;;
      2) ACTION="switchover" ;;
      3) ACTION="rolling-maint" ;;
      4) ACTION="report" ;;
      5) ACTION="audit" ;;
      *) log_error "Invalid action selection."; return "$EXIT_USAGE" ;;
    esac
  fi

  if is_change_action "$ACTION" && [[ -z "$CHANGE_ID" ]]; then
    printf "Enter Change ID (RFC/Ticket, e.g. CHG-2026-1042): " >&2
    IFS= read -r CHANGE_ID
  fi

  if [[ "$CUSTOMER_NAME" == "default_customer" ]]; then
    printf "Enter customer/environment tag [default_customer]: " >&2
    local cust
    IFS= read -r cust
    if [[ -n "$cust" ]]; then CUSTOMER_NAME="$cust"; fi
  fi

  if [[ "$DEPLOYMENT" != "atlas" && -z "$SSH_USER" ]]; then
    printf "Optional SSH user for OS checks (blank to skip SSH): " >&2
    IFS= read -r SSH_USER
  fi

  return "$EXIT_OK"
}

# --- Confirmation Gate for Disruptive Actions -------------------------------
# $1 description, $2 phrase the operator must type exactly
# The phrase embeds customer + target + change id so that a generic name such
# as "rs0" can never be confirmed against the wrong environment.
confirm_disruptive_action() {
  local action_desc="$1"
  local expected_token="$2"

  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Would execute '${action_desc}' (Change ID: ${CHANGE_ID}). Confirmation phrase would be '${expected_token}'. No live changes made."
    return 0
  fi

  printf '\n[WARNING] LIVE DISRUPTIVE ACTION: %s\n' "$action_desc" >&2
  printf 'Change ID : %s\n' "$CHANGE_ID" >&2
  printf 'Customer  : %s\n' "$CUSTOMER_NAME" >&2
  printf 'Topology  : %s (edition=%s, version=%s)\n' "$DETECTED_TOPOLOGY" "$DETECTED_EDITION" "$DETECTED_VERSION" >&2
  printf 'Type exactly "%s" to confirm execution: ' "$expected_token" >&2
  local typed=""
  if ! IFS= read -r typed; then
    log_error "No confirmation received. Aborting disruptive action."
    return "$EXIT_ABORTED"
  fi
  if [[ "$typed" != "$expected_token" ]]; then
    log_error "Confirmation phrase did not match. Aborting disruptive action."
    return "$EXIT_ABORTED"
  fi
  log_info "Typed confirmation accepted (Change ID: ${CHANGE_ID})."
  return 0
}

# --- URI builders --------------------------------------------------------------
# TLS is passed as mongosh flags (not appended to the URI) so that CA paths with
# special characters are safe.
build_mongosh_uri() {
  local target="$HOST_OR_URI"
  if [[ "$target" == mongodb://* || "$target" == mongodb+srv://* ]]; then
    printf '%s' "$target"
    return 0
  fi
  if [[ "$DEPLOYMENT" == "atlas" && "$target" == *.mongodb.net ]]; then
    printf 'mongodb+srv://%s/?authSource=%s' "$target" "$AUTH_DB"
    return 0
  fi
  printf 'mongodb://%s/?authSource=%s' "$target" "$AUTH_DB"
}

# Direct connection to one specific member (host:port)
build_member_uri() {
  printf 'mongodb://%s/?authSource=%s&directConnection=true' "$1" "$AUTH_DB"
}

# Replica-set URI for a shard, from listShards "rsName/host1:port,host2:port"
build_shard_uri() {
  local host="$1" rs_name="" hosts="$1"
  if [[ "$host" == */* ]]; then
    rs_name="${host%%/*}"
    hosts="${host#*/}"
  fi
  if [[ -n "$rs_name" ]]; then
    printf 'mongodb://%s/?authSource=%s&replicaSet=%s' "$hosts" "$AUTH_DB" "$rs_name"
  else
    printf 'mongodb://%s/?authSource=%s' "$hosts" "$AUTH_DB"
  fi
}

# --- JavaScript snippets (each starts with a SNIPPET marker used by tests) ----
js_detect() {
  cat <<'JS'
// SNIPPET:detect
const result = { ok: 1 };
const msg = (e) => String((e && e.message) || e);
const hello = db.hello();
const buildInfo = db.adminCommand({ buildInfo: 1 });

let edition = "Community";
if (Array.isArray(buildInfo.modules) && buildInfo.modules.includes("enterprise")) {
  edition = "Enterprise";
} else if (typeof buildInfo.gitVersion === "string" && buildInfo.gitVersion.toLowerCase().includes("enterprise")) {
  edition = "Enterprise";
}

let fcv = "unknown";
try {
  const f = db.adminCommand({ getParameter: 1, featureCompatibilityVersion: 1 });
  const v = f.featureCompatibilityVersion;
  const cand = (v && (v.version || v)) || "unknown";
  fcv = (typeof cand === "string") ? cand : "unknown";
} catch (e) {}

let topology = "standalone";
let clusterName = hello.setName || "standalone";
if (hello.msg === "isdbgrid") {
  topology = "sharded";
  clusterName = "sharded-cluster";
} else if (hello.setName) {
  topology = "replicaset";
  clusterName = hello.setName;
}

let shards = [];
let members = [];
let configServers = "";
let dbPath = null;
if (topology === "sharded") {
  try {
    const sList = db.adminCommand({ listShards: 1 });
    shards = (sList.shards || []).map(s => ({ _id: s._id, host: s.host, state: s.state }));
  } catch (e) {}
  try {
    const sm = db.adminCommand({ getShardMap: 1 });
    if (sm && sm.map && typeof sm.map.config === "string") configServers = sm.map.config;
  } catch (e) {}
} else {
  if (topology === "replicaset") {
    try {
      const st = rs.status();
      members = (st.members || []).map(m => ({ name: m.name, stateStr: m.stateStr, health: m.health }));
    } catch (e) {}
  }
  try {
    const o = db.adminCommand({ getCmdLineOpts: 1 });
    dbPath = (((o.parsed || {}).storage || {}).dbPath) || null;
  } catch (e) {}
}

result.edition = edition;
result.version = buildInfo.version || "unknown";
result.fcv = fcv;
result.topology = topology;
result.clusterName = clusterName;
result.shards = shards;
result.members = members;
result.configServers = configServers;
result.dbPath = dbPath;
print(JSON.stringify(result));
JS
}

# Replica-set membership/state for ONE replica set (the node/URI you connect to must be a
# member, or a replicaSet= seed URI). Every sub-query is isolated so a missing
# privilege is reported, never silently turned into "healthy".
js_rs_health() {
  cat <<'JS'
// SNIPPET:rs_health
const out = { ok: 1 };
const msg = (e) => String((e && e.message) || e);
const num = (v) => { if (v === null || v === undefined) return null; const x = Number(v); return Number.isFinite(x) ? x : null; };
let st = null;
try { st = rs.status(); } catch (e) { out.statusError = msg(e); }
if (st) {
  out.set = st.set;
  out.members = (st.members || []).map(m => ({
    name: m.name,
    stateStr: m.stateStr,
    health: num(m.health),
    optimeMs: m.optimeDate ? new Date(m.optimeDate).getTime() : null
  }));
}
try {
  const conf = rs.conf();
  out.conf = (conf.members || []).map(m => ({
    host: m.host,
    votes: num(m.votes),
    priority: num(m.priority),
    hidden: !!m.hidden,
    arbiterOnly: !!m.arbiterOnly
  }));
} catch (e) { out.confError = msg(e); }
print(JSON.stringify(out));
JS
}

# Node-local / mongos telemetry. Each section is independent and reports
# ok | n/a | error:<reason>. Run against ONE node (direct connection).
js_telemetry() {
  cat <<'JS'
// SNIPPET:telemetry
const out = { ok: 1, sections: {} };
const msg = (e) => String((e && e.message) || e);
const num = (v) => { if (v === null || v === undefined) return null; const x = Number(v); return Number.isFinite(x) ? x : null; };
const sec = (name, fn) => {
  try {
    const r = fn();
    if (r === null) { out.sections[name] = "n/a"; } else { out[name] = r; out.sections[name] = "ok"; }
  } catch (e) { out.sections[name] = "error: " + msg(e); }
};
let ss = null, ssErr = "unknown";
try { ss = db.adminCommand({ serverStatus: 1 }); } catch (e) { ssErr = msg(e); }
const needSS = () => { if (!ss) throw new Error("serverStatus failed: " + ssErr); return ss; };
const h = db.hello();
const isMongos = (h.msg === "isdbgrid");

sec("server", () => {
  const s = needSS();
  const bi = db.adminCommand({ buildInfo: 1 });
  let dbPath = null;
  try {
    const o = db.adminCommand({ getCmdLineOpts: 1 });
    dbPath = (((o.parsed || {}).storage || {}).dbPath) || null;
  } catch (e) {}
  let role = "OTHER";
  if (isMongos) role = "MONGOS";
  else if (h.isWritablePrimary && h.setName) role = "PRIMARY";
  else if (h.isWritablePrimary) role = "STANDALONE";
  else if (h.secondary) role = "SECONDARY";
  else if (h.arbiterOnly) role = "ARBITER";
  return { version: bi.version || null, uptimeSec: num(s.uptime), role: role, hidden: !!h.hidden, dbPath: dbPath, me: h.me || null };
});

sec("connections", () => {
  const c = needSS().connections || {};
  const cur = num(c.current), av = num(c.available);
  if (cur === null || av === null) throw new Error("connections.current/available missing");
  return { current: cur, available: av };
});

sec("memory", () => {
  const s = needSS();
  const res = s.mem ? num(s.mem.resident) : null;
  const wt = s.wiredTiger && s.wiredTiger.cache;
  let dirtyPct = null, usedPct = null;
  if (wt) {
    const max = num(wt["maximum bytes configured"]);
    const dirty = num(wt["tracked dirty bytes in the cache"]);
    const used = num(wt["bytes currently in the cache"]);
    if (max !== null && max > 0 && dirty !== null) dirtyPct = Number(((dirty / max) * 100).toFixed(2));
    if (max !== null && max > 0 && used !== null) usedPct = Number(((used / max) * 100).toFixed(2));
  }
  if (res === null && dirtyPct === null) {
    if (isMongos) return null;
    throw new Error("no mem / wiredTiger cache statistics returned");
  }
  return { residentMB: res, dirtyPct: dirtyPct, cacheUsedPct: usedPct };
});

sec("lock", () => {
  const q = (needSS().globalLock || {}).currentQueue;
  if (!q) throw new Error("globalLock.currentQueue missing");
  return { queueTotal: num(q.total), readers: num(q.readers), writers: num(q.writers) };
});

sec("opcounters", () => {
  const o = needSS().opcounters;
  if (!o) throw new Error("opcounters missing");
  return { insert: num(o.insert), query: num(o.query), update: num(o.update), delete: num(o.delete), getmore: num(o.getmore), command: num(o.command) };
});

sec("dataSize", () => {
  const r = db.adminCommand({ listDatabases: 1 });
  return { totalSizeBytes: num(r.totalSize), dbCount: (r.databases || []).length };
});

sec("oplog", () => {
  if (isMongos || !h.setName) return null;
  const ri = db.getReplicationInfo();
  const w = num(ri.timeDiffHours);
  if (w === null) throw new Error("timeDiffHours missing");
  return { windowHours: w, usedMB: num(ri.usedMB), sizeMB: num(ri.logSizeMB) };
});

sec("longOps", () => {
  const ops = db.getSiblingDB("admin").aggregate([
    { $currentOp: { allUsers: true, idleConnections: false } },
    { $match: { active: true, secs_running: { $gte: 30 } } },
    { $project: { opid: 1, ns: 1, secs_running: 1, op: 1 } }
  ]).toArray();
  return { count: ops.length, maxSecs: ops.reduce((a, o) => Math.max(a, num(o.secs_running) || 0), 0) };
});

sec("sharded", () => {
  if (!isMongos) return null;
  const r = {};
  r.shardCount = (db.adminCommand({ listShards: 1 }).shards || []).length;
  try { const b = db.adminCommand({ balancerStatus: 1 }); r.balancerMode = b.mode; r.inBalancerRound = !!b.inBalancerRound; }
  catch (e) { r.balancerError = msg(e); }
  try { r.jumboChunks = db.getSiblingDB("config").chunks.countDocuments({ jumbo: true }); }
  catch (e) { r.jumboError = msg(e); }
  return r;
});
print(JSON.stringify(out));
JS
}

# Runs on the node that must step down. Refuses unless that node is PRIMARY.
js_stepdown() {
  cat <<'JS'
// SNIPPET:stepdown
const msg = (e) => String((e && e.message) || e);
const result = { ok: 1, issued: false };
const h = db.hello();
if (!h.isWritablePrimary) {
  result.reason = "target node is not PRIMARY (me=" + h.me + ")";
} else {
  try {
    const r = db.adminCommand({ replSetStepDown: 60, secondaryCatchUpPeriodSecs: 15 });
    result.issued = (r && Number(r.ok) === 1);
    if (!result.issued) result.reason = "replSetStepDown returned ok!=1";
  } catch (e) {
    if (e && e.codeName) {
      // Server rejected the command (e.g. no electable secondary caught up)
      result.reason = msg(e);
      result.codeName = e.codeName;
    } else {
      // Older servers close connections on step-down: expected, verified later
      result.issued = true;
      result.note = "connection closed during step-down: " + msg(e);
    }
  }
}
print(JSON.stringify(result));
JS
}

js_audit() {
  cat <<'JS'
// SNIPPET:audit
const msg = (e) => String((e && e.message) || e);
let users = [];
let roles = [];
try {
  const uRes = db.getSiblingDB("admin").runCommand({ usersInfo: { forAllDBs: true }, showPrivileges: false });
  if (uRes.ok !== 1) throw new Error(uRes.errmsg || "usersInfo failed");
  users = (uRes.users || []).map(u => ({
    user: u.user,
    db: u.db,
    roles: (u.roles || []).map(r => `${r.role}@${r.db}`)
  }));
} catch (e) {
  users = [{ error: msg(e) }];
}

try {
  const rRes = db.getSiblingDB("admin").runCommand({ rolesInfo: 1, showPrivileges: false });
  if (rRes.ok !== 1) throw new Error(rRes.errmsg || "rolesInfo failed");
  roles = (rRes.roles || []).map(r => ({ role: r.role, db: r.db, isBuiltin: r.isBuiltin }));
} catch (e) {
  roles = [{ error: msg(e) }];
}

let slowQueries = [];
let indexSummary = [];
let profilerStatus = [];
let dbErrors = [];
try {
  const dbs = db.adminCommand({ listDatabases: 1 }).databases || [];
  for (const d of dbs) {
    if (["admin", "config", "local"].includes(d.name)) continue;
    const targetDb = db.getSiblingDB(d.name);
    try {
      const ps = targetDb.getProfilingStatus();
      profilerStatus.push({ db: d.name, level: ps.was, slowms: ps.slowms });
    } catch (e) { profilerStatus.push({ db: d.name, error: msg(e) }); }
    try {
      const prof = targetDb.getCollection("system.profile")
        .find({ millis: { $gte: 100 } }).sort({ ts: -1 }).limit(15).toArray();
      for (const p of prof) {
        slowQueries.push({ ns: p.ns, op: p.op, millis: p.millis, planSummary: p.planSummary || "n/a" });
      }
    } catch (e) { dbErrors.push({ db: d.name, part: "system.profile", error: msg(e) }); }
    try {
      const colls = targetDb.getCollectionInfos({ type: "collection" }) || [];
      for (const c of colls.slice(0, 20)) {
        const idx = targetDb.getCollection(c.name).getIndexes();
        indexSummary.push({ ns: `${d.name}.${c.name}`, indexCount: idx.length, indexes: idx.map(i => i.name) });
      }
    } catch (e) { dbErrors.push({ db: d.name, part: "indexes", error: msg(e) }); }
  }
} catch (e) { dbErrors.push({ part: "listDatabases", error: msg(e) }); }

print(JSON.stringify({
  ok: 1,
  userCount: users.length,
  users: users,
  customRolesCount: roles.filter(r => r.isBuiltin === false).length,
  roles: roles,
  profilerStatus: profilerStatus,
  profilerOffDatabases: profilerStatus.filter(p => p.level === 0).length,
  slowQueriesCount: slowQueries.length,
  slowQueries: slowQueries,
  indexSummary: indexSummary,
  errors: dbErrors
}));
JS
}

# --- mongosh Execution Wrapper (Scoped Child Env + Timeout) -----------------
# $1 = JS code, $2 = optional URI (defaults to the user's target)
# Authentication happens inside the JS using values from the child's
# environment. mongosh is deliberately NOT given --username: with a username
# and no password it would prompt for a password on its own and hang.
run_mongosh_js() {
  local js_code="$1"
  local uri="${2:-}"
  if [[ -z "$uri" ]]; then
    uri="$(build_mongosh_uri)"
  fi

  local -a args=(--quiet --norc)
  if [[ "$USE_TLS" == "true" ]]; then
    args+=(--tls)
    if [[ -n "$TLS_CA_FILE" ]]; then
      args+=(--tlsCAFile "$TLS_CA_FILE")
    fi
  fi
  args+=("$uri")

  local wrapped_js
  wrapped_js='
    const _pw = process.env.MONGO_DBA_PW || "";
    if (process.env.MONGO_DBA_USER && _pw.length > 0) {
      const authRes = db.getSiblingDB(process.env.MONGO_DBA_AUTHDB || "admin").auth({
        user: process.env.MONGO_DBA_USER,
        pwd: _pw
      });
      if (!authRes || authRes.ok !== 1) {
        throw new Error("Authentication failed");
      }
    }
  '
  wrapped_js+="$js_code"

  local errfile="${SESSION_TMP_DIR}/mongosh.err"
  local output
  local rc=0
  output="$(
    env -i \
      PATH="$PATH" \
      HOME="${SESSION_TMP_DIR}" \
      MONGO_DBA_PW="${MONGO_PASSWORD}" \
      MONGO_DBA_USER="${DB_USER}" \
      MONGO_DBA_AUTHDB="${AUTH_DB}" \
      timeout --kill-after=5s "${MONGOSH_TIMEOUT}s" \
      mongosh "${args[@]}" --eval "$wrapped_js" 2>"${errfile}"
  )" || rc=$?

  # Keep the (redacted) last stderr so callers can put it in error messages
  # even though they usually run us inside $(...) subshells.
  local err_clean=""
  if [[ -s "$errfile" ]]; then
    err_clean="$(redact_secrets "$(cat "$errfile")")"
    : > "$errfile"
  fi
  printf '%s' "$err_clean" > "${SESSION_TMP_DIR}/mongosh.last_err"
  if (( rc != 0 )) && [[ -n "$err_clean" ]]; then
    log_warn "mongosh stderr (rc=${rc}): ${err_clean}"
  fi

  printf '%s' "$output"
  return "$rc"
}

last_mongosh_error() {
  local f="${SESSION_TMP_DIR}/mongosh.last_err"
  if [[ -s "$f" ]]; then
    head -c 300 "$f" | tr '\n' ' '
  else
    printf 'no error output'
  fi
}

# Last JSON object line carrying "ok":1 ; non-zero if none present
extract_json() {
  printf '%s\n' "$1" | grep -E '^\{.*"ok":1' | tail -n 1
}

# --- Topology, Edition, Version & FCV Auto-Detection ------------------------
detect_cluster_metadata() {
  log_info "Auto-detecting MongoDB edition, version, FCV, and topology..."
  local raw_json=""
  if ! raw_json="$(run_mongosh_js "$(js_detect)")"; then
    log_error "mongosh failed while connecting/detecting metadata: $(last_mongosh_error)"
    return "$EXIT_AUTH_CONN"
  fi

  local parsed=""
  parsed="$(extract_json "$raw_json" || true)"
  if [[ -z "$parsed" ]]; then
    log_error "Unable to parse cluster metadata from mongosh output."
    return "$EXIT_AUTH_CONN"
  fi

  DETECTED_EDITION="$(printf '%s' "$parsed" | jq -r '.edition // "unknown"')"
  DETECTED_VERSION="$(printf '%s' "$parsed" | jq -r '.version // "unknown"')"
  DETECTED_FCV="$(printf '%s' "$parsed" | jq -r '.fcv // "unknown"')"
  DETECTED_TOPOLOGY="$(printf '%s' "$parsed" | jq -r '.topology // "unknown"')"
  DETECTED_CLUSTER_NAME="$(printf '%s' "$parsed" | jq -r '.clusterName // "unknown"')"
  DETECTED_SHARDS_JSON="$(printf '%s' "$parsed" | jq -c '.shards // []')"
  DETECTED_MEMBERS_JSON="$(printf '%s' "$parsed" | jq -c '.members // []')"
  DETECTED_CONFIG_SERVERS="$(printf '%s' "$parsed" | jq -r '.configServers // ""')"
  DETECTED_DBPATH="$(printf '%s' "$parsed" | jq -r '.dbPath // ""')"

  log_info "Detected: edition=${DETECTED_EDITION}, version=${DETECTED_VERSION}, FCV=${DETECTED_FCV}, topology=${DETECTED_TOPOLOGY}, cluster=${DETECTED_CLUSTER_NAME}"
  return "$EXIT_OK"
}

# --- Capability Gating Helper -------------------------------------------------
supports_capability() {
  local cap="$1"
  case "$cap" in
    enterprise_audit_ldap_kmip) [[ "$DETECTED_EDITION" == "Enterprise" ]] ;;
    *) return 1 ;;
  esac
}

# --- Pre-Check recording --------------------------------------------------------
record_check() {
  local name="$1"
  local status="$2" # PASS | WARN | FAIL
  local detail="$3"
  # tabs/newlines would corrupt the TSV
  detail="${detail//$'\t'/ }"
  detail="${detail//$'\n'/ }"
  printf '%s\t%s\t%s\n' "$name" "$status" "$detail" >> "${PRECHECK_RESULTS_FILE}"
  case "$status" in
    PASS) PASS_COUNT=$((PASS_COUNT + 1)); log_info "[PASS] ${name}: ${detail}" ;;
    WARN) WARN_COUNT=$((WARN_COUNT + 1)); log_warn "[WARN] ${name}: ${detail}" ;;
    FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)); log_error "[FAIL] ${name}: ${detail}" ;;
  esac
}

# --- Replica-set health (primary, members, majority, lag, electability, oplog) --
# jq program turning the js_rs_health document into a verdict summary.
jq_rs_summary_program() {
  cat <<'JQ'
(.members // []) as $m
| (.conf // null) as $c
| ($m | map(select(.stateStr == "PRIMARY"))) as $p
| ($p[0].optimeMs // null) as $po
| ($m | map(. as $x | . + {
    lag: (if $x.stateStr == "PRIMARY" then 0
          elif $x.stateStr == "SECONDARY" and $po != null and $x.optimeMs != null
          then ([0, (($po - $x.optimeMs) / 1000)] | max) else null end),
    cf: (if $c == null then null else ($c | map(select(.host == $x.name)) | .[0]) end),
    healthy: (($x.health == 1) and ($x.stateStr | IN("PRIMARY", "SECONDARY", "ARBITER")))
  })) as $mm
| ($mm | map(select(.cf == null or ((.cf.votes // 1) > 0)))) as $voters
| {
    primaryCount: ($p | length),
    primary: ($p[0].name // ""),
    memberCount: ($m | length),
    unhealthy: [$mm[] | select(.healthy | not) | "\(.name)=\(.stateStr)"],
    maxLagSec: ([$mm[] | .lag | select(. != null)] | max // 0),
    lagKnown: ($po != null),
    confAvailable: ($c != null),
    voters: ($voters | length),
    healthyVoters: ($voters | map(select(.healthy)) | length),
    electable: [$mm[] | select(.stateStr == "SECONDARY" and .healthy and .lag != null and .lag <= $warn
                 and (.cf == null or (((.cf.priority // 1) > 0)
                      and ((.cf.hidden // false) | not)
                      and ((.cf.arbiterOnly // false) | not)))) | .name],
    secondaries: [$mm[] | select(.stateStr == "SECONDARY") | .name],
    nodes: [$mm[] | {name: .name, stateStr: .stateStr, healthy: .healthy, lagSec: .lag}],
    confError: (.confError // null)
  }
JQ
}

# Raw replica-set health JSON from a (seed) URI; non-zero when unavailable
get_rs_health_json() {
  local uri="${1:-}"
  local raw
  raw="$(run_mongosh_js "$(js_rs_health)" "$uri")" || return 1
  extract_json "$raw"
}

check_rs_health() {
  local uri="$1"
  local label="${2:-}"
  local sfx=""
  if [[ -n "$label" ]]; then sfx=" [${label}]"; fi

  LAST_RS_NODES="[]"
  local hj=""
  if ! hj="$(get_rs_health_json "$uri")" || [[ -z "$hj" ]]; then
    record_check "replica_set_state${sfx}" "FAIL" "Could not read replica set state - connection or privilege problem (${label:-target}): $(last_mongosh_error)"
    return 0
  fi

  local st_err
  st_err="$(printf '%s' "$hj" | jq -r '.statusError // empty')"
  if [[ -n "$st_err" ]]; then
    record_check "replica_set_state${sfx}" "FAIL" "rs.status() failed: ${st_err}"
    return 0
  fi

  local sum
  if ! sum="$(printf '%s' "$hj" | jq -c --argjson warn "$LAG_WARN_SEC" "$(jq_rs_summary_program)")"; then
    record_check "replica_set_state${sfx}" "FAIL" "Could not evaluate replica set status document"
    return 0
  fi

  LAST_RS_NODES="$(printf '%s' "$sum" | jq -c '.nodes')"
  local pc primary
  pc="$(printf '%s' "$sum" | jq -r '.primaryCount')"
  primary="$(printf '%s' "$sum" | jq -r '.primary')"
  if [[ "$pc" == "1" ]]; then
    record_check "rs_primary${sfx}" "PASS" "Exactly one PRIMARY: ${primary}"
  elif [[ "$pc" == "0" ]]; then
    record_check "rs_primary${sfx}" "FAIL" "No PRIMARY (election in progress or no majority)"
  else
    record_check "rs_primary${sfx}" "FAIL" "${pc} members report PRIMARY (transient split view)"
  fi

  local unhealthy_n unhealthy_list
  unhealthy_n="$(printf '%s' "$sum" | jq -r '.unhealthy | length')"
  unhealthy_list="$(printf '%s' "$sum" | jq -r '.unhealthy | join(", ")')"
  if (( unhealthy_n > 0 )); then
    record_check "rs_member_health${sfx}" "FAIL" "${unhealthy_n} unhealthy/non-normal member(s): ${unhealthy_list}"
  else
    record_check "rs_member_health${sfx}" "PASS" "All $(printf '%s' "$sum" | jq -r '.memberCount') members healthy"
  fi

  local voters hvoters majority
  voters="$(printf '%s' "$sum" | jq -r '.voters')"
  hvoters="$(printf '%s' "$sum" | jq -r '.healthyVoters')"
  majority=$(( voters / 2 + 1 ))
  if (( hvoters < majority )); then
    record_check "rs_majority${sfx}" "FAIL" "Only ${hvoters}/${voters} voting members healthy (majority needs ${majority})"
  else
    record_check "rs_majority${sfx}" "PASS" "${hvoters}/${voters} voting members healthy (majority=${majority})"
  fi

  local lag_known lag
  lag_known="$(printf '%s' "$sum" | jq -r '.lagKnown')"
  lag="$(printf '%s' "$sum" | jq -r '.maxLagSec')"
  if [[ "$lag_known" != "true" ]]; then
    record_check "rs_lag${sfx}" "FAIL" "Replication lag cannot be computed without a PRIMARY"
  elif num_gt "$lag" "$LAG_FAIL_SEC"; then
    record_check "rs_lag${sfx}" "FAIL" "Max replication lag ${lag}s (> ${LAG_FAIL_SEC}s)"
  elif num_gt "$lag" "$LAG_WARN_SEC"; then
    record_check "rs_lag${sfx}" "WARN" "Max replication lag ${lag}s (> ${LAG_WARN_SEC}s)"
  else
    record_check "rs_lag${sfx}" "PASS" "Max replication lag ${lag}s"
  fi

  local el_n el_list conf_ok
  el_n="$(printf '%s' "$sum" | jq -r '.electable | length')"
  el_list="$(printf '%s' "$sum" | jq -r '.electable | join(", ")')"
  conf_ok="$(printf '%s' "$sum" | jq -r '.confAvailable')"
  if (( el_n > 0 )); then
    record_check "rs_electable_secondary${sfx}" "PASS" "${el_n} electable caught-up secondary(ies): ${el_list}"
  elif is_change_action "$ACTION"; then
    record_check "rs_electable_secondary${sfx}" "FAIL" "No electable secondary within ${LAG_WARN_SEC}s lag - step-down would be unsafe"
  else
    record_check "rs_electable_secondary${sfx}" "WARN" "No electable secondary within ${LAG_WARN_SEC}s lag - a step-down would not succeed"
  fi
  if [[ "$conf_ok" != "true" ]]; then
    record_check "rs_config_visibility${sfx}" "WARN" "rs.conf() unavailable ($(printf '%s' "$sum" | jq -r '.confError // "unknown"')); voting/priority/hidden status was estimated"
  fi

  return 0
}

# Gate used between rolling-maintenance steps: true if no new FAIL was recorded
rs_gate() {
  local before="$FAIL_COUNT"
  check_rs_health "$1" "$2"
  if (( FAIL_COUNT > before )); then
    return "$EXIT_PRECHECK_FAIL"
  fi
  return 0
}

# --- Node telemetry checks (connections, memory/cache, queue, oplog, long ops) ---
sec_status() {
  printf '%s' "$1" | jq -r --arg n "$2" '.sections[$n] // "missing"'
}

# Section not "ok": n/a is a legitimate PASS, everything else is a WARN - an
# unevaluated check is never a PASS.
record_unavailable() {
  local name="$1" status="$2"
  if [[ "$status" == "n/a" ]]; then
    record_check "$name" "PASS" "Not applicable on this node type (${DETECTED_TOPOLOGY})"
  else
    record_check "$name" "WARN" "Could not be evaluated - ${status#error: }"
  fi
}

# Per-node stats row definition (shared by console table and reports)
node_rows_jq() {
  cat <<'JQ'
def f(x): if x == null then "n/a" else (x | tostring) end;
def up: if . == null then "n/a" else "\((. / 86400) | floor)d\(((. % 86400) / 3600) | floor)h" end;
.[] | [
  .node,
  (f(.state) + (if .error then " (no direct conn)" else "" end)),
  f(.version),
  (.uptimeSec | up),
  (if .connCur == null then "n/a" else "\(.connCur)/\(.connCur + .connAvail) (\(.connPct)%)" end),
  f(.residentMB),
  (if .cacheUsedPct == null then "n/a" else "\(.cacheUsedPct)/\(.dirtyPct // "n/a")" end),
  f(.lagSec),
  f(.oplogHours),
  f(.dataSizeGB),
  f(.queue),
  f(.longOps)
] | @tsv
JQ
}

print_node_table() {
  if [[ ! -s "$NODE_STATS_FILE" ]]; then
    return 0
  fi
  {
    printf '\n=== Per-node statistics ===\n'
    printf '%-24s %-18s %-9s %-8s %-16s %-7s %-11s %-6s %-8s %-8s %-6s %-6s\n' \
      Node State Version Uptime Connections RSS_MB 'Cache u/d%' Lag_s Oplog_h Data_GB Queue LongOps
    local n st ver up conn rss cache lag oph dgb q lo
    while IFS=$'\t' read -r n st ver up conn rss cache lag oph dgb q lo; do
      printf '%-24s %-18s %-9s %-8s %-16s %-7s %-11s %-6s %-8s %-8s %-6s %-6s\n' \
        "$n" "$st" "$ver" "$up" "$conn" "$rss" "$cache" "$lag" "$oph" "$dgb" "$q" "$lo"
    done < <(jq -rs "$(node_rows_jq)" "$NODE_STATS_FILE")
    printf '\n'
  } | tee -a "${LOG_FILE:-/dev/null}" >&2
}

# Evaluate one node (or the mongos / standalone target) and record its stats.
#   $1 uri   $2 check-name suffix   $3 host:port of a replica-set member (optional)
#   $4 member state from rs.status (optional)   $5 lag seconds or "null"
check_node() {
  local uri="$1" sfx="$2" node="${3:-}" state="${4:-}" lag="${5:-null}"
  local label="$node"
  if [[ -z "$label" ]]; then
    label="$(seed_hostports | head -n 1 || true)"
    if [[ -z "$label" ]]; then label="target"; fi
  fi
  NODE_VERSION=""
  NODE_DBPATH=""

  local raw="" tel=""
  if ! raw="$(run_mongosh_js "$(js_telemetry)" "$uri")" || ! tel="$(extract_json "$raw")" || [[ -z "$tel" ]]; then
    if [[ -n "$node" ]]; then
      local nstat="WARN"
      if is_change_action "$ACTION"; then nstat="FAIL"; fi
      record_check "node_stats${sfx}" "$nstat" "NOT VERIFIED: could not connect directly to ${node} from this host: $(last_mongosh_error)"
      jq -cn --arg node "$label" --arg state "$state" --argjson lag "$lag" '{node:$node, state:$state, lagSec:$lag, error:true}' >> "$NODE_STATS_FILE"
      check_os_node "$node" ""
    else
      record_check "telemetry${sfx}" "FAIL" "Could not collect server telemetry (connections, memory, operations): $(last_mongosh_error)"
    fi
    return 0
  fi

  NODE_VERSION="$(printf '%s' "$tel" | jq -r '.server.version // empty')"
  NODE_DBPATH="$(printf '%s' "$tel" | jq -r '.server.dbPath // empty')"

  local s
  s="$(sec_status "$tel" connections)"
  if [[ "$s" != "ok" ]]; then
    record_unavailable "connections${sfx}" "$s"
  else
    local cur avail total pct=0
    cur="$(printf '%s' "$tel" | jq -r '.connections.current')"
    avail="$(printf '%s' "$tel" | jq -r '.connections.available')"
    total=$(( cur + avail ))
    if (( total > 0 )); then pct=$(( cur * 100 / total )); fi
    if (( pct >= 85 )); then
      record_check "connections${sfx}" "FAIL" "Connections at ${pct}% (${cur} used, ${avail} available)"
    elif (( pct >= 70 )); then
      record_check "connections${sfx}" "WARN" "Connections at ${pct}% (${cur} used, ${avail} available)"
    else
      record_check "connections${sfx}" "PASS" "Connections at ${pct}% (${cur} used, ${avail} available)"
    fi
  fi

  s="$(sec_status "$tel" memory)"
  if [[ "$s" != "ok" ]]; then
    record_unavailable "memory_and_cache${sfx}" "$s"
  else
    local rss dirty used
    rss="$(printf '%s' "$tel" | jq -r '.memory.residentMB // "unknown"')"
    dirty="$(printf '%s' "$tel" | jq -r '.memory.dirtyPct // "n/a"')"
    used="$(printf '%s' "$tel" | jq -r '.memory.cacheUsedPct // "n/a"')"
    if ! is_number "$dirty"; then
      record_check "memory_and_cache${sfx}" "WARN" "Resident=${rss}MB; WiredTiger dirty-cache % not available"
    elif ! num_lt "$dirty" 20; then
      record_check "memory_and_cache${sfx}" "FAIL" "Resident=${rss}MB, WT cache used=${used}%, dirty=${dirty}% of configured cache (>= 20%)"
    elif ! num_lt "$dirty" 10; then
      record_check "memory_and_cache${sfx}" "WARN" "Resident=${rss}MB, WT cache used=${used}%, dirty=${dirty}% of configured cache (>= 10%)"
    else
      record_check "memory_and_cache${sfx}" "PASS" "Resident=${rss}MB, WT cache used=${used}%, dirty=${dirty}% of configured cache"
    fi
  fi

  s="$(sec_status "$tel" lock)"
  if [[ "$s" != "ok" ]]; then
    record_unavailable "lock_queue${sfx}" "$s"
  else
    local qt qr qw
    qt="$(printf '%s' "$tel" | jq -r '.lock.queueTotal // 0')"
    qr="$(printf '%s' "$tel" | jq -r '.lock.readers // 0')"
    qw="$(printf '%s' "$tel" | jq -r '.lock.writers // 0')"
    if (( qt >= 10 )); then
      record_check "lock_queue${sfx}" "WARN" "${qt} operations queued (readers=${qr}, writers=${qw})"
    else
      record_check "lock_queue${sfx}" "PASS" "${qt} operations queued (readers=${qr}, writers=${qw})"
    fi
  fi

  s="$(sec_status "$tel" longOps)"
  if [[ "$s" != "ok" ]]; then
    record_unavailable "long_running_ops${sfx}" "$s"
  else
    local lcount lmax
    lcount="$(printf '%s' "$tel" | jq -r '.longOps.count')"
    lmax="$(printf '%s' "$tel" | jq -r '.longOps.maxSecs')"
    if (( lcount >= 5 )); then
      record_check "long_running_ops${sfx}" "WARN" "${lcount} active operations >= 30s across all users (longest ${lmax}s)"
    else
      record_check "long_running_ops${sfx}" "PASS" "${lcount} active operations >= 30s across all users (longest ${lmax}s)"
    fi
  fi

  # Oplog window is a property of EACH member's own oplog
  if [[ -n "$node" ]]; then
    s="$(sec_status "$tel" oplog)"
    if [[ "$s" != "ok" ]]; then
      record_unavailable "oplog_window${sfx}" "$s"
    else
      local ow used_pct
      ow="$(printf '%s' "$tel" | jq -r '.oplog.windowHours')"
      used_pct="$(printf '%s' "$tel" | jq -r 'if (.oplog.sizeMB // 0) > 0 and .oplog.usedMB != null then ((.oplog.usedMB * 100 / .oplog.sizeMB) | floor) else "unknown" end')"
      if num_lt "$ow" 12; then
        if [[ "$used_pct" =~ ^[0-9]+$ ]] && (( used_pct < 80 )); then
          record_check "oplog_window${sfx}" "WARN" "Oplog spans ${ow}h but is only ${used_pct}% full, so this is a lower bound (oplog has not wrapped yet); re-check under steady-state load"
        else
          record_check "oplog_window${sfx}" "FAIL" "Oplog window is ${ow}h (< 12h; oplog ${used_pct}% full)"
        fi
      elif num_lt "$ow" 24; then
        record_check "oplog_window${sfx}" "WARN" "Oplog window is ${ow}h (< 24h)"
      else
        record_check "oplog_window${sfx}" "PASS" "Oplog window is ${ow}h"
      fi
    fi
  fi

  s="$(sec_status "$tel" sharded)"
  if [[ "$DETECTED_TOPOLOGY" == "sharded" && -z "$node" ]]; then
    if [[ "$s" != "ok" ]]; then
      record_unavailable "sharded_balancer_and_config" "$s"
    else
      local shard_cnt jumbo jerr bmode inround berr
      shard_cnt="$(printf '%s' "$tel" | jq -r '.sharded.shardCount')"
      jumbo="$(printf '%s' "$tel" | jq -r '.sharded.jumboChunks // "unknown"')"
      jerr="$(printf '%s' "$tel" | jq -r '.sharded.jumboError // empty')"
      bmode="$(printf '%s' "$tel" | jq -r '.sharded.balancerMode // "unknown"')"
      inround="$(printf '%s' "$tel" | jq -r '.sharded.inBalancerRound // false')"
      berr="$(printf '%s' "$tel" | jq -r '.sharded.balancerError // empty')"
      if (( shard_cnt < 1 )); then
        record_check "sharded_balancer_and_config" "FAIL" "No shards registered on mongos"
      elif [[ -n "$berr" || -n "$jerr" ]]; then
        record_check "sharded_balancer_and_config" "WARN" "${shard_cnt} shards; balancer/jumbo status unavailable (${berr:-$jerr})"
      elif [[ "$jumbo" != "0" ]]; then
        record_check "sharded_balancer_and_config" "WARN" "${shard_cnt} shards, ${jumbo} jumbo chunk(s), balancer mode=${bmode}"
      elif [[ "$inround" == "true" ]] && is_change_action "$ACTION"; then
        record_check "sharded_balancer_and_config" "WARN" "Balancer is mid-round (mode=${bmode}); stop the balancer and let migrations drain before a change"
      else
        record_check "sharded_balancer_and_config" "PASS" "${shard_cnt} shards, 0 jumbo chunks, balancer mode=${bmode}, inRound=${inround}"
      fi
    fi
  elif [[ "$DETECTED_TOPOLOGY" != "sharded" && -z "$node" ]]; then
    record_check "sharded_balancer_and_config" "PASS" "Not a sharded cluster (topology=${DETECTED_TOPOLOGY})"
  fi

  # Stats row for the per-node table / report
  jq -c --arg node "$label" --arg state "$state" --argjson lag "$lag" '{
      node: $node,
      state: (if $state != "" then $state else (.server.role // null) end),
      lagSec: $lag,
      version: (.server.version // null),
      uptimeSec: (.server.uptimeSec // null),
      connCur: (.connections.current // null),
      connAvail: (.connections.available // null),
      connPct: (if .connections and ((.connections.current + .connections.available) > 0)
                then ((.connections.current * 100 / (.connections.current + .connections.available)) | floor) else null end),
      residentMB: (.memory.residentMB // null),
      cacheUsedPct: (.memory.cacheUsedPct // null),
      dirtyPct: (.memory.dirtyPct // null),
      oplogHours: (.oplog.windowHours // null),
      dataSizeGB: (if .dataSize.totalSizeBytes != null then ((((.dataSize.totalSizeBytes / 1073741824) * 100) | round) / 100) else null end),
      queue: (.lock.queueTotal // null),
      longOps: (.longOps.count // null),
      ops: (.opcounters // null)
    }' <<<"$tel" >> "$NODE_STATS_FILE"

  if [[ -n "$node" ]]; then
    check_os_node "$node" "$NODE_DBPATH"
  fi
  return 0
}

# Connect DIRECTLY to every data-bearing member of the replica set last
# evaluated by check_rs_health (LAST_RS_NODES) and collect per-node stats.
check_rs_members() {
  local label="${1:-}"
  local base_sfx=""
  if [[ -n "$label" ]]; then base_sfx="${label}/"; fi

  local n_total
  n_total="$(printf '%s' "$LAST_RS_NODES" | jq -r 'length')"
  if (( n_total == 0 )); then
    record_check "node_stats${label:+ [$label]}" "WARN" "NOT VERIFIED: member list unavailable, per-node statistics skipped"
    return 0
  fi

  local -a versions=()
  local name state healthy lag lag_json sfx
  while IFS=$'\t' read -r name state healthy lag; do
    if [[ -z "$name" ]]; then continue; fi
    sfx=" [${base_sfx}${name}]"
    if [[ "$state" == "ARBITER" ]]; then
      record_check "node_stats${sfx}" "PASS" "Arbiter: holds no data or users; node-level statistics not applicable"
      continue
    fi
    lag_json="null"
    if is_number "$lag"; then lag_json="$lag"; fi
    if [[ "$healthy" != "true" ]]; then
      jq -cn --arg node "$name" --arg state "$state" --argjson lag "$lag_json" '{node:$node, state:$state, lagSec:$lag, error:true}' >> "$NODE_STATS_FILE"
      record_check "node_stats${sfx}" "WARN" "Skipped: member reported ${state} by the replica set (see rs_member_health)"
      continue
    fi
    check_node "$(build_member_uri "$name")" "$sfx" "$name" "$state" "$lag_json"
    if [[ -n "$NODE_VERSION" ]]; then versions+=("$NODE_VERSION"); fi
  done < <(printf '%s' "$LAST_RS_NODES" | jq -r '.[] | [.name, .stateStr, (.healthy | tostring), (.lagSec // "null" | tostring)] | @tsv')

  local vsfx=""
  if [[ -n "$label" ]]; then vsfx=" [${label}]"; fi
  if (( ${#versions[@]} >= 2 )); then
    local uniq
    uniq="$(printf '%s\n' "${versions[@]}" | sort -u | paste -sd, -)"
    if [[ "$uniq" == *,* ]]; then
      record_check "rs_version_consistency${vsfx}" "WARN" "Members run different mongod versions: ${uniq} (expected only mid-upgrade)"
    else
      record_check "rs_version_consistency${vsfx}" "PASS" "All ${#versions[@]} members run ${uniq}"
    fi
  fi
  return 0
}

# --- Target host lists (for TLS / OS checks) -----------------------------------
seed_hostports() {
  if [[ "$HOST_OR_URI" == mongodb+srv://* ]]; then
    return 0
  fi
  printf '%s' "$HOST_OR_URI" \
    | sed -E 's#^mongodb://([^/@]+@)?##; s#[/?].*$##' \
    | tr ',' '\n' | sed '/^$/d'
}

collect_target_hostports() {
  {
    local used_members=0
    if [[ "$DETECTED_TOPOLOGY" == "replicaset" ]]; then
      local names
      names="$(printf '%s' "$DETECTED_MEMBERS_JSON" | jq -r '.[]?.name')"
      if [[ -n "$names" ]]; then
        printf '%s\n' "$names"
        used_members=1
      fi
    elif [[ "$DETECTED_TOPOLOGY" == "sharded" ]]; then
      seed_hostports
      printf '%s' "$DETECTED_SHARDS_JSON" | jq -r '.[]?.host' | sed -E 's#^[^/]*/##' | tr ',' '\n'
      if [[ -n "$DETECTED_CONFIG_SERVERS" ]]; then
        printf '%s\n' "$DETECTED_CONFIG_SERVERS" | sed -E 's#^[^/]*/##' | tr ',' '\n'
      fi
      used_members=1
    fi
    if (( used_members == 0 )); then
      seed_hostports
    fi
  } | sed '/^$/d' | sort -u
}

# --- Backup recency ---------------------------------------------------------------
curl_cfg_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s"
}

# Atlas Admin API call. Credentials go to curl through a config on STDIN, so
# the private key never appears in the process list.
# $1 method, $2 path (after /api/atlas/v2), $3 media-type version
# Prints the body, then a final line with the HTTP status code.
atlas_api_curl() {
  local method="$1" path="$2" version="$3"
  printf 'user = "%s:%s"\n' "$(curl_cfg_escape "$API_PUBLIC_KEY")" "$(curl_cfg_escape "$API_PRIVATE_KEY")" \
    | curl -sS --max-time 25 --digest --config - -X "$method" \
        -H "Accept: application/vnd.atlas.${version}+json" \
        -H "Content-Type: application/json" \
        -w '\n%{http_code}' \
        "https://cloud.mongodb.com/api/atlas/v2${path}" 2>/dev/null
}

age_status() {
  # $1 name, $2 age hours, $3 what
  local name="$1" age="$2" what="$3"
  if (( age >= 48 )); then
    record_check "$name" "FAIL" "${what} is ${age}h old (>= 48h)"
  elif (( age >= 24 )); then
    record_check "$name" "WARN" "${what} is ${age}h old (>= 24h)"
  else
    record_check "$name" "PASS" "${what} is ${age}h old"
  fi
}

check_backup_age() {
  case "$DEPLOYMENT" in
    atlas)
      if [[ -z "$API_PUBLIC_KEY" || -z "$API_PRIVATE_KEY" || -z "$API_PROJECT_ID" || -z "$ATLAS_CLUSTER" ]] || ! command -v curl >/dev/null 2>&1; then
        record_check "last_backup_age" "WARN" "NOT VERIFIED: needs curl plus --api-public-key (+prompted private key), --api-project-id and --atlas-cluster"
        return 0
      fi
      local resp code body latest latest_epoch age
      resp="$(atlas_api_curl GET "/groups/${API_PROJECT_ID}/clusters/${ATLAS_CLUSTER}/backup/snapshots?itemsPerPage=500" "$ATLAS_API_VER_SNAPSHOTS" || true)"
      code="${resp##*$'\n'}"
      body="${resp%$'\n'*}"
      if [[ "$code" != "200" ]]; then
        record_check "last_backup_age" "WARN" "NOT VERIFIED: Atlas API returned HTTP ${code:-none} for snapshot listing"
        return 0
      fi
      latest="$(printf '%s' "$body" | jq -r '[.results[]? | select(.status == "completed")] | sort_by(.createdAt) | last | .createdAt // empty' 2>/dev/null || true)"
      if [[ -z "$latest" ]]; then
        record_check "last_backup_age" "WARN" "No completed Atlas snapshots returned for cluster '${ATLAS_CLUSTER}'"
        return 0
      fi
      if ! latest_epoch="$(date -u -d "$latest" +%s 2>/dev/null)"; then
        record_check "last_backup_age" "WARN" "Could not parse snapshot timestamp '${latest}'"
        return 0
      fi
      age=$(( ( $(date -u +%s) - latest_epoch ) / 3600 ))
      age_status "last_backup_age" "$age" "Latest completed Atlas snapshot (${latest})"
      ;;
    opsmanager)
      record_check "last_backup_age" "WARN" "NOT VERIFIED: automatic Ops Manager backup-age lookup is not implemented; confirm the latest snapshot in Ops Manager"
      ;;
    onprem)
      if [[ -z "$BACKUP_DIR" ]]; then
        record_check "last_backup_age" "WARN" "NOT VERIFIED: pass --backup-dir (path readable from this host) or confirm backup job timestamps"
        return 0
      fi
      if [[ ! -d "$BACKUP_DIR" ]]; then
        record_check "last_backup_age" "FAIL" "Backup directory does not exist: ${BACKUP_DIR}"
        return 0
      fi
      local latest_mtime
      latest_mtime="$(find "$BACKUP_DIR" -maxdepth 3 -type f -printf '%T@\n' 2>/dev/null | sort -nr | head -n 1 || true)"
      if [[ -z "$latest_mtime" ]]; then
        record_check "last_backup_age" "WARN" "No backup files found in ${BACKUP_DIR}"
        return 0
      fi
      age=$(( ( $(date -u +%s) - ${latest_mtime%.*} ) / 3600 ))
      age_status "last_backup_age" "$age" "Newest file in ${BACKUP_DIR}"
      ;;
  esac
  return 0
}

# --- TLS: real server-certificate expiry per member ---------------------------
check_tls_certs() {
  if [[ "$DEPLOYMENT" == "atlas" ]]; then
    record_check "tls_cert_expiry" "PASS" "N/A: server certificates are managed by Atlas"
    return 0
  fi
  if [[ "$USE_TLS" != "true" ]]; then
    record_check "tls_cert_expiry" "WARN" "TLS flag not set for this session; verify transport-encryption policy and certificate expiry manually"
    return 0
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    record_check "tls_cert_expiry" "WARN" "NOT VERIFIED: openssl not available"
    return 0
  fi

  local hp host port end_str end_epoch now days checked=0
  now="$(date -u +%s)"
  while IFS= read -r hp; do
    if [[ -z "$hp" ]]; then continue; fi
    if [[ "$hp" == *:* ]]; then host="${hp%:*}"; port="${hp##*:}"; else host="$hp"; port=27017; fi
    checked=$((checked + 1))
    end_str="$(timeout 15 openssl s_client -connect "${host}:${port}" -servername "$host" </dev/null 2>/dev/null \
               | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
    if [[ -z "$end_str" ]] || ! end_epoch="$(date -u -d "$end_str" +%s 2>/dev/null)"; then
      record_check "tls_cert_expiry@${hp}" "WARN" "NOT VERIFIED: could not read the server certificate"
      continue
    fi
    days=$(( (end_epoch - now) / 86400 ))
    if (( days < 7 )); then
      record_check "tls_cert_expiry@${hp}" "FAIL" "Server certificate expires ${end_str} (${days} days)"
    elif (( days < 30 )); then
      record_check "tls_cert_expiry@${hp}" "WARN" "Server certificate expires ${end_str} (${days} days)"
    else
      record_check "tls_cert_expiry@${hp}" "PASS" "Server certificate expires ${end_str} (${days} days)"
    fi
  done < <(collect_target_hostports)

  if (( checked == 0 )); then
    record_check "tls_cert_expiry" "WARN" "NOT VERIFIED: no member host:port known"
  fi
  return 0
}

# --- OS checks over SSH (every member host) --------------------------------------
# Runs on the remote host: $1 = mongod dbPath. Emits KEY:value lines.
remote_os_script() {
  cat <<'EOS'
dbpath="$1"
port="$2"
if [ -n "$dbpath" ] && [ -d "$dbpath" ]; then target="$dbpath"; else target=/; fi
df -P "$target" 2>/dev/null | awk 'NR==2 {print "DISK:" $5 "(" $4 "KB free on " $6 ")"}'
pid=""
if [ -n "$port" ] && command -v ss >/dev/null 2>&1; then
  pid=$(ss -H -ltnp "sport = :$port" 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1)
fi
if [ -z "$pid" ] && [ -n "$port" ] && command -v pgrep >/dev/null 2>&1; then
  pid=$(pgrep -f "mongo[ds].*--port[ =]${port}( |\$)" 2>/dev/null | head -n 1)
fi
src=process
if [ -z "$pid" ]; then
  n=$(pidof mongod mongos 2>/dev/null | wc -w)
  if [ "$n" = 1 ]; then pid=$(pidof mongod mongos)
  elif [ "$n" -gt 1 ]; then src=ambiguous
  else src=session
  fi
fi
if [ -n "$pid" ] && [ -r "/proc/$pid/limits" ]; then
  awk '/^Max open files/ {print "NOFILE:" $4} /^Max processes/ {print "NPROC:" $3}' "/proc/$pid/limits"
  echo "ULIMIT_SRC:process"
else
  echo "NOFILE:$(ulimit -n 2>/dev/null)"
  echo "NPROC:$(ulimit -u 2>/dev/null)"
  if [ "$src" = process ]; then src=session; fi
  echo "ULIMIT_SRC:$src"
fi
if [ -r /sys/kernel/mm/transparent_hugepage/enabled ]; then
  mode=$(cat /sys/kernel/mm/transparent_hugepage/enabled)
  case "$mode" in
    *\[*\]*) thp=$(printf '%s' "$mode" | sed -E 's/.*\[([^]]+)\].*/\1/') ;;
    *) thp="$mode" ;;
  esac
  echo "THP:$thp"
else
  echo "THP:unreadable"
fi
ntp=unknown
if command -v timedatectl >/dev/null 2>&1; then
  v=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  if [ -n "$v" ]; then ntp="$v"; fi
fi
if [ "$ntp" = unknown ] && command -v chronyc >/dev/null 2>&1; then
  t=$(chronyc tracking 2>/dev/null)
  if [ -n "$t" ]; then
    if printf '%s' "$t" | grep -q 'Leap status *: Normal'; then ntp=yes; else ntp=no; fi
  fi
fi
echo "NTP:$ntp"
EOS
}

is_local_host() {
  [[ "$1" == "127.0.0.1" || "$1" == "localhost" || "$1" == "::1" ]]
}

os_kv() {
  # $1 output, $2 key
  printf '%s\n' "$1" | sed -n "s/^$2://p" | head -n 1
}

check_os_host() {
  local host="$1" port="$2" dbp="$3" script="$4"
  local out=""
  local hp="$host"
  if [[ -n "$port" ]]; then hp="${host}:${port}"; else port=""; fi
  if [[ -n "$port" && ! "$port" =~ ^[0-9]+$ ]]; then port=""; fi
  if is_local_host "$host"; then
    out="$(bash -s -- "$dbp" "$port" <<<"$script" 2>/dev/null || true)"
  else
    local strict="yes"
    if [[ "$SSH_ACCEPT_NEW" == "true" ]]; then strict="accept-new"; fi
    local -a ssh_opts=(-o BatchMode=yes -o "ConnectTimeout=${SSH_TIMEOUT}" -o "StrictHostKeyChecking=${strict}")
    if [[ -n "$SSH_KEY" ]]; then ssh_opts+=(-i "$SSH_KEY"); fi
    out="$(timeout "$((SSH_TIMEOUT + 20))s" ssh "${ssh_opts[@]}" "${SSH_USER}@${host}" "bash -s -- '${dbp}' '${port}'" <<<"$script" 2>/dev/null || true)"
  fi

  if [[ -z "$out" ]]; then
    record_check "os_checks_ssh@${hp}" "WARN" "NOT VERIFIED: OS check failed or timed out (SSH auth/host-key problem?)"
    return 0
  fi

  local disk_info nofile nproc src thp ntp
  disk_info="$(os_kv "$out" DISK)"
  nofile="$(os_kv "$out" NOFILE)"
  nproc="$(os_kv "$out" NPROC)"
  src="$(os_kv "$out" ULIMIT_SRC)"
  thp="$(os_kv "$out" THP)"
  ntp="$(os_kv "$out" NTP)"

  local disk_pct="${disk_info%%%*}"
  if [[ "$disk_pct" =~ ^[0-9]+$ ]]; then
    if (( disk_pct >= 85 )); then
      record_check "os_disk_space@${hp}" "FAIL" "Disk usage ${disk_info}"
    elif (( disk_pct >= 75 )); then
      record_check "os_disk_space@${hp}" "WARN" "Disk usage ${disk_info}"
    else
      record_check "os_disk_space@${hp}" "PASS" "Disk usage ${disk_info}"
    fi
  else
    record_check "os_disk_space@${hp}" "WARN" "NOT VERIFIED: could not read disk usage for the data path"
  fi

  local lim_name val
  for lim_name in NOFILE NPROC; do
    if [[ "$lim_name" == "NOFILE" ]]; then val="$nofile"; else val="$nproc"; fi
    local label="os_ulimit_${lim_name,,}@${hp}"
    if [[ "$src" == "ambiguous" ]]; then
      record_check "$label" "WARN" "NOT VERIFIED: several mongod processes on this host and the one on port ${port:-?} could not be identified (run as the mongod user or root)"
    elif [[ "$src" != "process" ]]; then
      record_check "$label" "WARN" "NOT VERIFIED: no mongod/mongos process found on host; SSH-session value (${val:-unknown}) is not representative"
    elif [[ "$val" == "unlimited" ]]; then
      record_check "$label" "PASS" "${lim_name} limit of mongod is unlimited"
    elif [[ "$val" =~ ^[0-9]+$ ]]; then
      if (( val < 64000 )); then
        record_check "$label" "WARN" "${lim_name} limit of running mongod is ${val} (recommended >= 64000)"
      else
        record_check "$label" "PASS" "${lim_name} limit of running mongod is ${val}"
      fi
    else
      record_check "$label" "WARN" "NOT VERIFIED: could not read ${lim_name} limit of mongod"
    fi
  done

  local v_major="${DETECTED_VERSION%%.*}"
  if [[ "$thp" == "unreadable" || -z "$thp" ]]; then
    record_check "os_thp@${hp}" "WARN" "NOT VERIFIED: THP setting unreadable"
  elif [[ "$v_major" =~ ^[0-9]+$ ]] && (( v_major >= 8 )); then
    record_check "os_thp@${hp}" "WARN" "THP is '${thp}'. THP guidance differs for MongoDB 8.0+ - verify against the Production Notes for ${DETECTED_VERSION}"
  elif [[ "$thp" == "never" ]]; then
    record_check "os_thp@${hp}" "PASS" "Transparent Huge Pages is 'never'"
  else
    record_check "os_thp@${hp}" "WARN" "THP is '${thp}' (MongoDB < 8.0 recommends 'never')"
  fi

  case "$ntp" in
    yes|Normal) record_check "os_ntp@${hp}" "PASS" "Clock synchronised (${ntp})" ;;
    no)         record_check "os_ntp@${hp}" "WARN" "Clock reported NOT synchronised" ;;
    *)          record_check "os_ntp@${hp}" "WARN" "NOT VERIFIED: neither timedatectl nor chronyc gave a sync status" ;;
  esac
  return 0
}

# OS checks for one host:port (once), using that node's own dbPath/port
check_os_node() {
  local hp="$1" dbp="$2" host port=""
  if [[ "$DEPLOYMENT" == "atlas" ]]; then return 0; fi
  if [[ -n "${OS_CHECKED[$hp]:-}" ]]; then return 0; fi
  OS_CHECKED["$hp"]=1
  if [[ "$hp" == *:* ]]; then host="${hp%:*}"; port="${hp##*:}"; else host="$hp"; fi
  if [[ ! "$dbp" =~ ^/[A-Za-z0-9._/-]*$ ]]; then dbp=""; fi
  if is_local_host "$host" || [[ -n "$SSH_USER" ]]; then
    check_os_host "$host" "$port" "$dbp" "$(remote_os_script)"
  else
    OS_SKIPPED=$((OS_SKIPPED + 1))
  fi
  return 0
}

# Hosts not already covered by the per-node pass (standalone, mongos, config servers)
check_os_hosts() {
  if [[ "$DEPLOYMENT" == "atlas" ]]; then
    record_check "os_checks_ssh" "PASS" "N/A: Atlas manages OS, THP and ulimits"
    return 0
  fi

  local hp seen=0
  while IFS= read -r hp; do
    if [[ -z "$hp" ]]; then continue; fi
    seen=$((seen + 1))
    check_os_node "$hp" "$DETECTED_DBPATH"
  done < <(collect_target_hostports)

  if (( seen == 0 && ${#OS_CHECKED[@]} == 0 )); then
    record_check "os_checks_ssh" "WARN" "NOT VERIFIED: no member hosts known"
  elif (( OS_SKIPPED > 0 )); then
    record_check "os_checks_ssh" "WARN" "NOT VERIFIED: SSH not configured (--ssh-user omitted); OS checks skipped for ${OS_SKIPPED} node(s)"
  fi
  return 0
}

# --- Pre-Checks (PASS / WARN / FAIL) -----------------------------------------
run_prechecks() {
  PASS_COUNT=0
  WARN_COUNT=0
  FAIL_COUNT=0
  : > "${PRECHECK_RESULTS_FILE}"
  : > "${NODE_STATS_FILE}"
  OS_CHECKED=()
  OS_SKIPPED=0

  log_info "=== Running Pre-Checks (deployment=${DEPLOYMENT}, topology=${DETECTED_TOPOLOGY}, edition=${DETECTED_EDITION}) ==="

  record_check "connectivity_and_auth" "PASS" "Connected and authenticated to ${HOST_OR_URI} (authDb=${AUTH_DB})"

  if [[ "$DETECTED_VERSION" != "unknown" && "$DETECTED_FCV" != "unknown" ]]; then
    local v_major_minor
    v_major_minor="$(printf '%s' "$DETECTED_VERSION" | awk -F. '{print $1"."$2}')"
    if [[ "$v_major_minor" == "$DETECTED_FCV" ]]; then
      record_check "version_and_fcv" "PASS" "Version=${DETECTED_VERSION}, FCV=${DETECTED_FCV} (aligned)"
    else
      record_check "version_and_fcv" "WARN" "Version=${DETECTED_VERSION} (major.minor=${v_major_minor}) differs from FCV=${DETECTED_FCV} (expected only mid-upgrade)"
    fi
  else
    record_check "version_and_fcv" "WARN" "Could not determine version (${DETECTED_VERSION}) or FCV (${DETECTED_FCV})"
  fi

  case "$DETECTED_TOPOLOGY" in
    standalone)
      check_node "$(build_mongosh_uri)" ""
      record_check "replica_set_state" "PASS" "Standalone node: no replication to verify"
      ;;
    replicaset)
      check_rs_health "$(build_mongosh_uri)" ""
      check_rs_members ""
      ;;
    sharded)
      check_node "$(build_mongosh_uri)" ""
      local n_shards=0 sid shost
      while IFS=$'\t' read -r sid shost; do
        if [[ -z "$sid" ]]; then continue; fi
        if [[ -n "$SHARD_ID" && "$sid" != "$SHARD_ID" ]]; then continue; fi
        n_shards=$((n_shards + 1))
        check_rs_health "$(build_shard_uri "$shost")" "shard:${sid}"
        check_rs_members "shard:${sid}"
      done < <(printf '%s' "$DETECTED_SHARDS_JSON" | jq -r '.[]? | "\(._id)\t\(.host)"')
      if (( n_shards == 0 )); then
        record_check "replica_set_state" "FAIL" "No shard replica sets could be selected for checking"
      fi
      ;;
    *)
      record_check "replica_set_state" "FAIL" "Unknown topology '${DETECTED_TOPOLOGY}'"
      ;;
  esac

  check_backup_age
  check_tls_certs
  check_os_hosts
  print_node_table

  log_info "=== Pre-Check Summary: PASS=${PASS_COUNT}, WARN=${WARN_COUNT}, FAIL=${FAIL_COUNT} ==="
  if (( FAIL_COUNT > 0 )); then
    return "$EXIT_PRECHECK_FAIL"
  fi
  return "$EXIT_OK"
}

# --- Change-action target resolution ------------------------------------------
# Sets TARGET_RS_URI / TARGET_RS_LABEL for the replica set the action works on.
resolve_target_rs() {
  case "$DETECTED_TOPOLOGY" in
    replicaset)
      TARGET_RS_URI="$(build_mongosh_uri)"
      TARGET_RS_LABEL="${DETECTED_CLUSTER_NAME}"
      ;;
    sharded)
      local shost
      shost="$(printf '%s' "$DETECTED_SHARDS_JSON" | jq -r --arg s "$SHARD_ID" '[.[]? | select(._id == $s) | .host] | .[0] // empty')"
      if [[ -z "$shost" ]]; then
        log_error "Cannot resolve hosts for shard '${SHARD_ID}'."
        return "$EXIT_USAGE"
      fi
      TARGET_RS_URI="$(build_shard_uri "$shost")"
      TARGET_RS_LABEL="shard-${SHARD_ID}"
      ;;
    *)
      log_error "Topology '${DETECTED_TOPOLOGY}' has no replica set to operate on."
      return "$EXIT_USAGE"
      ;;
  esac
  return 0
}

# Name of the single PRIMARY in an rs-health document, empty otherwise
single_primary_of() {
  printf '%s' "$1" | jq -r '[.members[]? | select(.stateStr == "PRIMARY") | .name] | if length == 1 then .[0] else "" end'
}

# Poll until exactly one PRIMARY exists and it is not $2. Sets NEW_PRIMARY.
wait_for_new_primary() {
  local rs_uri="$1" old_primary="$2" max_wait="$3"
  local waited=0 hj="" np=""
  NEW_PRIMARY=""
  while (( waited < max_wait )); do
    sleep 3
    waited=$((waited + 3))
    hj=""
    if ! hj="$(get_rs_health_json "$rs_uri" 2>/dev/null)" || [[ -z "$hj" ]]; then
      continue
    fi
    np="$(single_primary_of "$hj")"
    if [[ -n "$np" && "$np" != "$old_primary" ]]; then
      NEW_PRIMARY="$np"
      return 0
    fi
  done
  return 1
}

# Step the current primary down by connecting to it DIRECTLY, then prove a
# different primary was elected. Never reports success on an unverified outcome.
perform_stepdown() {
  local rs_uri="$1" old_primary="$2"
  local direct_uri out="" parsed=""
  direct_uri="$(build_member_uri "$old_primary")"
  log_info "Issuing replSetStepDown on ${old_primary} (direct connection)..."

  if ! out="$(run_mongosh_js "$(js_stepdown)" "$direct_uri")"; then
    log_warn "mongosh reported an error while stepping down; the outcome will be verified from replica set state."
  fi
  parsed="$(extract_json "$out" || true)"
  if [[ -n "$parsed" ]]; then
    local issued
    issued="$(printf '%s' "$parsed" | jq -r '.issued')"
    if [[ "$issued" != "true" ]]; then
      log_error "Step-down was NOT performed: $(printf '%s' "$parsed" | jq -r '(.reason // "unknown reason") + (if .codeName then " [" + .codeName + "]" else "" end)')"
      return "$EXIT_RUNTIME_ERR"
    fi
  else
    log_warn "No result returned by the step-down command; verifying from replica set state."
  fi

  log_info "Waiting up to ${STEPDOWN_WAIT_SEC}s for a new PRIMARY (other than ${old_primary})..."
  if ! wait_for_new_primary "$rs_uri" "$old_primary" "$STEPDOWN_WAIT_SEC"; then
    log_error "No new PRIMARY observed within ${STEPDOWN_WAIT_SEC}s - step-down did not take effect or the set is mid-election. Investigate before retrying."
    return "$EXIT_RUNTIME_ERR"
  fi
  log_info "New PRIMARY elected: ${NEW_PRIMARY} (previous primary: ${old_primary})."
  return 0
}

# --- Atlas failover (test failover via CLI, else Admin API v2) -------------------
atlas_failover() {
  local out="" rc=0
  if command -v atlas >/dev/null 2>&1; then
    log_info "Triggering Atlas failover test for cluster '${ATLAS_CLUSTER}' via atlas CLI..."
    out="$(
      env -i \
        PATH="$PATH" \
        HOME="${SESSION_TMP_DIR}" \
        DO_NOT_TRACK=1 \
        MONGODB_ATLAS_SILENCE_STORAGE_WARNING=true \
        MONGODB_ATLAS_PUBLIC_API_KEY="${API_PUBLIC_KEY}" \
        MONGODB_ATLAS_PRIVATE_API_KEY="${API_PRIVATE_KEY}" \
        timeout --kill-after=5s 120s \
        atlas clusters failover "${ATLAS_CLUSTER}" --projectId "${API_PROJECT_ID}" --force 2>&1
    )" || rc=$?
    if (( rc != 0 )); then
      log_error "atlas CLI failover failed (rc=${rc}): ${out}"
      return "$EXIT_RUNTIME_ERR"
    fi
    log_info "atlas CLI: ${out}"
    return 0
  fi

  if command -v curl >/dev/null 2>&1; then
    log_info "Triggering Atlas failover test for cluster '${ATLAS_CLUSTER}' via Admin API..."
    local resp code
    resp="$(atlas_api_curl POST "/groups/${API_PROJECT_ID}/clusters/${ATLAS_CLUSTER}/restartPrimaries" "$ATLAS_API_VER_FAILOVER" || true)"
    code="${resp##*$'\n'}"
    if [[ "$code" != "200" && "$code" != "202" ]]; then
      log_error "Atlas API failover returned HTTP ${code:-none}: ${resp%$'\n'*}"
      return "$EXIT_RUNTIME_ERR"
    fi
    return 0
  fi

  log_error "Neither 'atlas' CLI nor 'curl' is available for Atlas failover."
  return "$EXIT_DEPENDENCY"
}

switchover_atlas() {
  if [[ -z "$ATLAS_CLUSTER" || -z "$API_PROJECT_ID" || -z "$API_PUBLIC_KEY" || -z "$API_PRIVATE_KEY" ]]; then
    log_error "Atlas switchover needs --atlas-cluster (the Atlas cluster NAME, not the replica-set name), --api-project-id and --api-public-key (private key is prompted)."
    return "$EXIT_USAGE"
  fi

  local main_uri hj old_primary
  main_uri="$(build_mongosh_uri)"
  if ! hj="$(get_rs_health_json "$main_uri")" || [[ -z "$hj" ]]; then
    log_error "Cannot read replica set state from Atlas: $(last_mongosh_error)"
    return "$EXIT_PRECHECK_FAIL"
  fi
  old_primary="$(single_primary_of "$hj")"
  if [[ -z "$old_primary" ]]; then
    log_error "No single PRIMARY found; refusing to trigger a failover."
    return "$EXIT_PRECHECK_FAIL"
  fi

  local token="${CUSTOMER_NAME}:${ATLAS_CLUSTER}:${CHANGE_ID}"
  confirm_disruptive_action "Atlas failover test on cluster '${ATLAS_CLUSTER}' (current primary ${old_primary})" "$token" || return $?
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Would trigger Atlas failover for '${ATLAS_CLUSTER}' (project ${API_PROJECT_ID}) and wait up to ${ATLAS_FAILOVER_WAIT_SEC}s for a new primary."
    return 0
  fi

  atlas_failover || return $?
  log_info "Waiting up to ${ATLAS_FAILOVER_WAIT_SEC}s for Atlas to elect a new primary..."
  if ! wait_for_new_primary "$main_uri" "$old_primary" "$ATLAS_FAILOVER_WAIT_SEC"; then
    log_error "No new PRIMARY observed within ${ATLAS_FAILOVER_WAIT_SEC}s after the Atlas failover request."
    return "$EXIT_RUNTIME_ERR"
  fi
  log_info "New PRIMARY elected: ${NEW_PRIMARY} (previous primary: ${old_primary})."
  return 0
}

# --- Action: switchover ---------------------------------------------------------
action_switchover() {
  log_info "=== Primary Switchover (dry_run=${DRY_RUN}, change_id=${CHANGE_ID}) ==="

  local pre_rc=0
  run_prechecks || pre_rc=$?
  if (( pre_rc == EXIT_PRECHECK_FAIL )); then
    log_error "Pre-checks FAILED. Refusing to proceed with switchover."
    return "$EXIT_PRECHECK_FAIL"
  fi

  if [[ "$DETECTED_TOPOLOGY" == "standalone" ]]; then
    log_warn "Standalone node detected: there is no primary to switch over. Nothing to do."
    return "$EXIT_OK"
  fi
  if [[ "$DETECTED_TOPOLOGY" != "replicaset" && "$DETECTED_TOPOLOGY" != "sharded" ]]; then
    log_error "Unknown topology '${DETECTED_TOPOLOGY}'. Aborting."
    return "$EXIT_RUNTIME_ERR"
  fi

  if [[ "$DEPLOYMENT" == "atlas" ]]; then
    if [[ "$DETECTED_TOPOLOGY" == "sharded" ]]; then
      log_error "Atlas failover tests act on the whole cluster; a per-shard switchover is not supported by this script."
      return "$EXIT_USAGE"
    fi
    switchover_atlas
    return $?
  fi

  resolve_target_rs || return $?

  local hj="" old_primary=""
  if ! hj="$(get_rs_health_json "$TARGET_RS_URI")" || [[ -z "$hj" ]]; then
    log_error "Cannot read replica set state for ${TARGET_RS_LABEL}: $(last_mongosh_error)"
    return "$EXIT_PRECHECK_FAIL"
  fi
  old_primary="$(single_primary_of "$hj")"
  if [[ -z "$old_primary" ]]; then
    log_error "No single PRIMARY found for ${TARGET_RS_LABEL}; refusing to step down."
    return "$EXIT_PRECHECK_FAIL"
  fi

  local token="${CUSTOMER_NAME}:${TARGET_RS_LABEL}:${CHANGE_ID}"
  confirm_disruptive_action "Primary switchover on ${TARGET_RS_LABEL} (current primary ${old_primary})" "$token" || return $?

  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Plan for ${TARGET_RS_LABEL}:"
    log_info "[DRY-RUN]   1. Connect DIRECTLY to ${old_primary} and verify it is PRIMARY."
    log_info "[DRY-RUN]   2. replSetStepDown(stepDownSecs=60, secondaryCatchUpPeriodSecs=15) - the server refuses if no secondary is caught up."
    log_info "[DRY-RUN]   3. Poll the set for up to ${STEPDOWN_WAIT_SEC}s until a different single PRIMARY appears; otherwise report failure."
    log_info "[DRY-RUN]   4. Re-run pre-checks. No live change was made."
    return "$EXIT_OK"
  fi

  perform_stepdown "$TARGET_RS_URI" "$old_primary" || return $?

  log_info "Running post-switchover verification..."
  detect_cluster_metadata || true
  local post_rc=0
  run_prechecks || post_rc=$?
  if (( post_rc != 0 )); then
    log_error "Switchover COMPLETED (new primary ${NEW_PRIMARY}) but post-checks report FAIL - review immediately."
    return "$post_rc"
  fi
  log_info "Switchover completed and verified."
  return "$EXIT_OK"
}

# --- Rolling maintenance --------------------------------------------------------
# Poll until member $2 is SECONDARY, healthy and within lag tolerance.
wait_for_member_ready() {
  local rs_uri="$1" node="$2" max_wait="$3"
  local waited=0 hj="" verdict="unknown"
  while (( waited < max_wait )); do
    hj=""
    if hj="$(get_rs_health_json "$rs_uri" 2>/dev/null)" && [[ -n "$hj" ]]; then
      verdict="$(printf '%s' "$hj" | jq -r --arg n "$node" --argjson warn "$LAG_WARN_SEC" '
        (.members // []) as $m
        | ([$m[] | select(.stateStr == "PRIMARY")][0].optimeMs // null) as $po
        | ([$m[] | select(.name == $n)][0]) as $x
        | if $x == null then "member not visible"
          elif ($x.stateStr != "SECONDARY") or ($x.health != 1) then "state=" + ($x.stateStr | tostring)
          elif $po == null or $x.optimeMs == null then "lag unknown"
          elif (($po - $x.optimeMs) / 1000) > $warn then "still catching up"
          else "ready" end')"
      if [[ "$verdict" == "ready" ]]; then
        return 0
      fi
    else
      verdict="replica set unreachable"
    fi
    log_info "Waiting for ${node} to rejoin and catch up (${verdict})..."
    sleep 10
    waited=$((waited + 10))
  done
  log_error "${node} did not become a caught-up SECONDARY within ${max_wait}s (last state: ${verdict})."
  return 1
}

maintain_node() {
  local node="$1" role="$2"

  rs_gate "$TARGET_RS_URI" "$TARGET_RS_LABEL" || {
    log_error "Gate FAILED before maintaining ${node}. Halting."
    return "$EXIT_PRECHECK_FAIL"
  }

  log_info "[MAINT] Node ${node} (${role}) - hand-off."
  if [[ -n "$MAINT_HOOK" ]]; then
    local hook_rc=0
    timeout --kill-after=10s "${MAINT_WAIT}s" "$MAINT_HOOK" "$node" "$role" "$CHANGE_ID" || hook_rc=$?
    if (( hook_rc != 0 )); then
      log_error "Maintenance hook failed for ${node} (rc=${hook_rc}). Halting; the node may be down - check it."
      return "$EXIT_RUNTIME_ERR"
    fi
  else
    local ans=""
    printf '\n>>> Perform maintenance on %s now (role: %s).\n>>> Press Enter once mongod is running again, or type "abort" to stop: ' "$node" "$role" >&2
    if ! IFS= read -r ans || [[ "$ans" == "abort" ]]; then
      log_error "Operator aborted rolling maintenance at ${node}."
      return "$EXIT_ABORTED"
    fi
  fi

  if ! wait_for_member_ready "$TARGET_RS_URI" "$node" "$MAINT_WAIT"; then
    return "$EXIT_RUNTIME_ERR"
  fi
  log_info "[MAINT] ${node} is back as a caught-up SECONDARY."
  return 0
}

action_rolling_maint() {
  log_info "=== Rolling Maintenance (dry_run=${DRY_RUN}, change_id=${CHANGE_ID}) ==="

  local pre_rc=0
  run_prechecks || pre_rc=$?
  if (( pre_rc == EXIT_PRECHECK_FAIL )); then
    log_error "Pre-checks FAILED. Refusing to start rolling maintenance."
    return "$EXIT_PRECHECK_FAIL"
  fi

  if [[ "$DETECTED_TOPOLOGY" == "standalone" ]]; then
    log_warn "Standalone node: no rolling procedure exists. Schedule a downtime window instead."
    return "$EXIT_OK"
  fi
  resolve_target_rs || return $?

  local hj="" primary=""
  if ! hj="$(get_rs_health_json "$TARGET_RS_URI")" || [[ -z "$hj" ]]; then
    log_error "Cannot read replica set state for ${TARGET_RS_LABEL}: $(last_mongosh_error)"
    return "$EXIT_PRECHECK_FAIL"
  fi
  primary="$(single_primary_of "$hj")"
  if [[ -z "$primary" ]]; then
    log_error "No single PRIMARY found for ${TARGET_RS_LABEL}; refusing to start."
    return "$EXIT_PRECHECK_FAIL"
  fi
  local -a secondaries=()
  mapfile -t secondaries < <(printf '%s' "$hj" | jq -r '.members[]? | select(.stateStr == "SECONDARY") | .name')

  log_info "Plan for ${TARGET_RS_LABEL}: secondaries [${secondaries[*]:-none}] first, then step down ${primary} and maintain it last."
  local arbiters
  arbiters="$(printf '%s' "$hj" | jq -r '[.members[]? | select(.stateStr == "ARBITER") | .name] | join(", ")')"
  if [[ -n "$arbiters" ]]; then
    log_warn "Arbiter(s) ${arbiters} are not handled by this procedure (no data to resync); maintain them separately."
  fi

  local token="${CUSTOMER_NAME}:${TARGET_RS_LABEL}:${CHANGE_ID}"
  confirm_disruptive_action "Rolling maintenance on ${TARGET_RS_LABEL}" "$token" || return $?

  if [[ "$DRY_RUN" == "true" ]]; then
    local node
    for node in "${secondaries[@]}"; do
      log_info "[DRY-RUN] Gate -> maintenance hand-off (${MAINT_HOOK:-manual pause}) -> wait until ${node} is a caught-up SECONDARY."
    done
    log_info "[DRY-RUN] Gate -> verified step-down of ${primary} -> maintain it as former primary -> final pre-checks. No live change was made."
    return "$EXIT_OK"
  fi

  local node
  for node in "${secondaries[@]}"; do
    maintain_node "$node" "SECONDARY" || return $?
  done

  rs_gate "$TARGET_RS_URI" "$TARGET_RS_LABEL" || {
    log_error "Gate FAILED before stepping down ${primary}. Halting."
    return "$EXIT_PRECHECK_FAIL"
  }
  perform_stepdown "$TARGET_RS_URI" "$primary" || return $?
  maintain_node "$primary" "FORMER_PRIMARY" || return $?

  log_info "Running final verification..."
  detect_cluster_metadata || true
  local post_rc=0
  run_prechecks || post_rc=$?
  if (( post_rc != 0 )); then
    log_error "Rolling maintenance finished but final pre-checks report FAIL - review immediately."
    return "$post_rc"
  fi
  log_info "Rolling maintenance completed and verified."
  return "$EXIT_OK"
}

# --- Action: audit -----------------------------------------------------------
action_audit() {
  log_info "=== Read-only Audit (users/roles, slow queries, indexes) ==="
  local raw_out="" audit_json=""
  if ! raw_out="$(run_mongosh_js "$(js_audit)")"; then
    log_error "Audit query failed: $(last_mongosh_error)"
    return "$EXIT_RUNTIME_ERR"
  fi
  audit_json="$(extract_json "$raw_out" || true)"
  if [[ -z "$audit_json" ]]; then
    log_error "Audit returned no parseable data."
    return "$EXIT_RUNTIME_ERR"
  fi

  local out_file="${REPORT_DIR}/audit_${RUN_TIMESTAMP}.json"
  printf '%s\n' "$audit_json" | jq . > "$out_file"
  chmod 640 "$out_file"

  log_info "Audit summary: users=$(printf '%s' "$audit_json" | jq -r '.userCount') (all databases), custom roles in admin=$(printf '%s' "$audit_json" | jq -r '.customRolesCount'), slow queries seen=$(printf '%s' "$audit_json" | jq -r '.slowQueriesCount'), databases with profiler OFF=$(printf '%s' "$audit_json" | jq -r '.profilerOffDatabases')"
  if [[ "$(printf '%s' "$audit_json" | jq -r '.profilerOffDatabases')" != "0" ]]; then
    log_warn "Profiler is off on some databases: an empty slow-query list there means 'not measured', not 'no slow queries'."
  fi
  if [[ "$(printf '%s' "$audit_json" | jq -r '.errors | length')" != "0" ]]; then
    log_warn "Some audit sections failed (see ${out_file}): $(printf '%s' "$audit_json" | jq -c '.errors')"
  fi
  if supports_capability enterprise_audit_ldap_kmip; then
    log_info "Enterprise detected: LDAP/KMIP/auditLog review is applicable (not auto-collected)."
  fi
  log_info "Audit written to: ${out_file}"
  return "$EXIT_OK"
}

# --- Action: report (Markdown / HTML, content escaped) ---------------------------
action_report() {
  log_info "=== Health Report (customer=${CUSTOMER_NAME}) ==="
  local pre_rc=0
  run_prechecks || pre_rc=$?

  local md_file="${REPORT_DIR}/report_${RUN_TIMESTAMP}.md"
  local html_file="${REPORT_DIR}/report_${RUN_TIMESTAMP}.html"
  local overall="PASS"
  if (( FAIL_COUNT > 0 )); then overall="FAIL"; elif (( WARN_COUNT > 0 )); then overall="WARN"; fi

  if [[ "$REPORT_FORMAT" == "markdown" || "$REPORT_FORMAT" == "both" ]]; then
    {
      printf '# MongoDB Health Report - %s\n\n' "$(md_escape "$CUSTOMER_NAME")"
      printf '*Generated (UTC):* %s  \n' "$RUN_TIMESTAMP"
      printf '*Deployment:* %s  \n' "$(md_escape "$DEPLOYMENT")"
      # shellcheck disable=SC2016
      printf '*Target:* `%s`  \n' "$(md_escape "$HOST_OR_URI")"
      printf '*Topology:* %s | *Edition:* %s | *Version:* %s | *FCV:* %s  \n' \
        "$DETECTED_TOPOLOGY" "$DETECTED_EDITION" "$DETECTED_VERSION" "$DETECTED_FCV"
      printf '*Overall:* **%s** (PASS=%d, WARN=%d, FAIL=%d)\n\n' "$overall" "$PASS_COUNT" "$WARN_COUNT" "$FAIL_COUNT"
      if [[ -s "$NODE_STATS_FILE" ]]; then
        printf '## Per-node statistics\n\n'
        printf '| Node | State | Version | Uptime | Connections | RSS MB | Cache used/dirty %% | Lag s | Oplog h | Data GB | Queue | Long ops |\n'
        printf '|---|---|---|---|---|---|---|---|---|---|---|---|\n'
        local n st ver up conn rss cache lag oph dgb q lo
        while IFS=$'\t' read -r n st ver up conn rss cache lag oph dgb q lo; do
          printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
            "$(md_escape "$n")" "$(md_escape "$st")" "$(md_escape "$ver")" "$up" "$conn" "$rss" "$cache" "$lag" "$oph" "$dgb" "$q" "$lo"
        done < <(jq -rs "$(node_rows_jq)" "$NODE_STATS_FILE")
        printf '\n## Checks\n\n'
      fi
      printf '| Check | Status | Detail |\n|---|---|---|\n'
      local cname cstatus cdetail
      while IFS=$'\t' read -r cname cstatus cdetail; do
        printf '| %s | %s | %s |\n' "$(md_escape "$cname")" "$cstatus" "$(md_escape "$cdetail")"
      done < "${PRECHECK_RESULTS_FILE}"
    } > "$md_file"
    chmod 640 "$md_file"
    log_info "Markdown report: ${md_file}"
  fi

  if [[ "$REPORT_FORMAT" == "html" || "$REPORT_FORMAT" == "both" ]]; then
    {
      printf '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
      printf '<title>MongoDB Health Report - %s</title>' "$(html_escape "$CUSTOMER_NAME")"
      printf '<style>body{font-family:sans-serif;margin:2rem}table{border-collapse:collapse;width:100%%}'
      printf 'th,td{border:1px solid #ccc;padding:6px 10px;text-align:left}th{background:#f3f3f3}'
      printf '.PASS{color:#1a7f37;font-weight:bold}.WARN{color:#9a6700;font-weight:bold}.FAIL{color:#cf222e;font-weight:bold}</style></head><body>'
      printf '<h1>MongoDB Health Report - %s</h1>' "$(html_escape "$CUSTOMER_NAME")"
      printf '<p>Generated (UTC): %s<br>Deployment: %s<br>Target: <code>%s</code><br>' \
        "$RUN_TIMESTAMP" "$(html_escape "$DEPLOYMENT")" "$(html_escape "$HOST_OR_URI")"
      printf 'Topology: %s | Edition: %s | Version: %s | FCV: %s<br>' \
        "$(html_escape "$DETECTED_TOPOLOGY")" "$(html_escape "$DETECTED_EDITION")" "$(html_escape "$DETECTED_VERSION")" "$(html_escape "$DETECTED_FCV")"
      printf 'Overall: <span class="%s">%s</span> (PASS=%d, WARN=%d, FAIL=%d)</p>' "$overall" "$overall" "$PASS_COUNT" "$WARN_COUNT" "$FAIL_COUNT"
      if [[ -s "$NODE_STATS_FILE" ]]; then
        printf '<h2>Per-node statistics</h2><table><tr><th>Node</th><th>State</th><th>Version</th><th>Uptime</th><th>Connections</th><th>RSS MB</th><th>Cache used/dirty %%</th><th>Lag s</th><th>Oplog h</th><th>Data GB</th><th>Queue</th><th>Long ops</th></tr>'
        local n st ver up conn rss cache lag oph dgb q lo
        while IFS=$'\t' read -r n st ver up conn rss cache lag oph dgb q lo; do
          printf '<tr>'
          local cell
          for cell in "$n" "$st" "$ver" "$up" "$conn" "$rss" "$cache" "$lag" "$oph" "$dgb" "$q" "$lo"; do
            printf '<td>%s</td>' "$(html_escape "$cell")"
          done
          printf '</tr>'
        done < <(jq -rs "$(node_rows_jq)" "$NODE_STATS_FILE")
        printf '</table><h2>Checks</h2>'
      fi
      printf '<table><tr><th>Check</th><th>Status</th><th>Detail</th></tr>'
      local cname cstatus cdetail
      while IFS=$'\t' read -r cname cstatus cdetail; do
        printf '<tr><td>%s</td><td class="%s">%s</td><td>%s</td></tr>' \
          "$(html_escape "$cname")" "$cstatus" "$cstatus" "$(html_escape "$cdetail")"
      done < "${PRECHECK_RESULTS_FILE}"
      printf '</table></body></html>\n'
    } > "$html_file"
    chmod 640 "$html_file"
    log_info "HTML report: ${html_file}"
  fi
  return "$pre_rc"
}

# --- Argument Parsing -----------------------------------------------------------
parse_args() {
  while (( $# > 0 )); do
    case "$1" in
      --deployment|--host|--uri|--user|--auth-db|--tls-ca|--timeout|--action|--change-id|--customer|--shard|--maint-hook|--maint-wait|--ssh-user|--ssh-key|--backup-dir|--api-public-key|--api-project-id|--api-base-url|--atlas-cluster|--report-format)
        if (( $# < 2 )); then
          log_error "Option $1 requires a value."
          return "$EXIT_USAGE"
        fi
        ;;
    esac
    case "$1" in
      --deployment)      DEPLOYMENT="$2"; shift 2 ;;
      --host|--uri)      HOST_OR_URI="$2"; shift 2 ;;
      --user)            DB_USER="$2"; shift 2 ;;
      --auth-db)         AUTH_DB="$2"; shift 2 ;;
      --tls)             USE_TLS="true"; shift ;;
      --tls-ca)          TLS_CA_FILE="$2"; shift 2 ;;
      --timeout)         MONGOSH_TIMEOUT="$2"; shift 2 ;;
      --action)          ACTION="$2"; shift 2 ;;
      --dry-run)         DRY_RUN="true"; shift ;;
      --execute)         DRY_RUN="false"; shift ;;
      --change-id)       CHANGE_ID="$2"; shift 2 ;;
      --customer)        CUSTOMER_NAME="$2"; shift 2 ;;
      --shard)           SHARD_ID="$2"; shift 2 ;;
      --maint-hook)      MAINT_HOOK="$2"; shift 2 ;;
      --maint-wait)      MAINT_WAIT="$2"; shift 2 ;;
      --ssh-user)        SSH_USER="$2"; shift 2 ;;
      --ssh-key)         SSH_KEY="$2"; shift 2 ;;
      --ssh-accept-new)  SSH_ACCEPT_NEW="true"; shift ;;
      --backup-dir)      BACKUP_DIR="$2"; shift 2 ;;
      --api-public-key)  API_PUBLIC_KEY="$2"; shift 2 ;;
      --api-project-id)  API_PROJECT_ID="$2"; shift 2 ;;
      --api-base-url)    API_BASE_URL="$2"; shift 2 ;;
      --atlas-cluster)   ATLAS_CLUSTER="$2"; shift 2 ;;
      --report-format)   REPORT_FORMAT="$2"; shift 2 ;;
      -h|--help)         usage; exit 0 ;;
      *) log_error "Unknown option: $1"; usage >&2; return "$EXIT_USAGE" ;;
    esac
  done
  return "$EXIT_OK"
}

# --- Main Orchestration ---------------------------------------------------------
main() {
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  parse_args "$@" || return $?

  if [[ -z "$DEPLOYMENT" || -z "$HOST_OR_URI" || -z "$ACTION" ]]; then
    if [[ -t 0 ]]; then
      interactive_menu || return $?
    else
      log_error "Missing --deployment/--host/--action and no interactive terminal available."
      usage >&2
      return "$EXIT_USAGE"
    fi
  elif [[ -z "$DB_USER" && -t 0 ]]; then
    printf "Enter MongoDB username (leave blank if authentication is disabled): " >&2
    IFS= read -r DB_USER
  fi

  validate_inputs || return $?
  init_logging
  log_info "Session start: deployment=${DEPLOYMENT}, action=${ACTION}, dry_run=${DRY_RUN}, customer=${CUSTOMER_NAME}"
  check_dependencies || return $?
  prompt_secrets || return $?
  detect_cluster_metadata || return $?
  validate_after_detect || return $?

  # Every action is invoked the same way (|| rc=$?) so errexit behaves
  # identically everywhere; all fallible calls inside check their own status.
  local rc=0
  case "$ACTION" in
    prechecks)     run_prechecks || rc=$? ;;
    switchover)    action_switchover || rc=$? ;;
    rolling-maint) action_rolling_maint || rc=$? ;;
    report)        action_report || rc=$? ;;
    audit)         action_audit || rc=$? ;;
  esac
  return "$rc"
}

# Allow sourcing for tests without running main
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
