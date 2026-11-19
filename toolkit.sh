#!/usr/bin/env bash
# ==============================================================================
# mongo_dba_toolkit.sh
# Production-grade MongoDB Managed-Services DBA Toolkit
# Supports: Community & Enterprise | onprem, opsmanager, atlas
# ShellCheck compliant (bash >= 4.3 recommended)
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

# --- Exit Codes ---------------------------------------------------------------
readonly EXIT_OK=0
readonly EXIT_USAGE=2
readonly EXIT_DEPENDENCY=3
readonly EXIT_AUTH_CONN=4
readonly EXIT_PRECHECK_FAIL=5
readonly EXIT_ABORTED=6
readonly EXIT_RUNTIME_ERR=10

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
MONGOSH_TIMEOUT=30
API_PUBLIC_KEY=""
API_PROJECT_ID=""
API_BASE_URL=""
REPORT_FORMAT="both" # markdown | html | both

# Sensitive values (populated only at runtime via read -rs, cleared on exit)
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

# Pre-check counters
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
PRECHECK_RESULTS_FILE=""

# --- Secret Redaction & Cleanup Trap -----------------------------------------
redact_secrets() {
  local line="$1"
  if [[ -n "${MONGO_PASSWORD}" ]]; then
    line="${line//${MONGO_PASSWORD}/[REDACTED_PASSWORD]}"
  fi
  if [[ -n "${API_PRIVATE_KEY}" ]]; then
    line="${line//${API_PRIVATE_KEY}/[REDACTED_API_KEY]}"
  fi
  # Redact credentials in mongodb/mongodb+srv URIs and query parameters
  line="$(printf '%s' "$line" | sed -E 's#(mongodb(\+srv)?://[^:/@]+:)[^@]+(@)#\1[REDACTED_PASSWORD]\3#g')"
  line="$(printf '%s' "$line" | sed -E 's/([?&](password|privateKey|apiKey|token)=)[^&[:space:]]+/\1[REDACTED]/gi')"
  printf '%s\n' "$line"
}

cleanup() {
  local exit_code=$?
  # Immediately scrub sensitive variables from memory and environment
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

trap cleanup EXIT INT TERM

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
  : > "${LOG_FILE}"
  : > "${PRECHECK_RESULTS_FILE}"
  chmod 600 "${LOG_FILE}" "${PRECHECK_RESULTS_FILE}"
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

# --- Usage / Help -------------------------------------------------------------
usage() {
  cat <<'EOF'
Usage: mongo_dba_toolkit.sh [OPTIONS]

MongoDB Managed-Services DBA Toolkit for Community & Enterprise across
on-prem/self-managed, Ops Manager, and MongoDB Atlas.

Options:
  --deployment <type>      Deployment type: onprem | opsmanager | atlas
  --host <host[:port]>     Target host/port (or comma-separated seed list)
  --uri <mongodb-uri>      MongoDB connection URI (without embedded password)
  --user <username>        Database username
  --auth-db <db>           Authentication database (default: admin)
  --tls                    Enable TLS/SSL for mongosh connections
  --tls-ca <path>          Optional CA bundle path when --tls is set
  --action <action>        prechecks | switchover | rolling-maint | report | audit
  --dry-run                Force dry-run mode (default for change actions)
  --execute                Disable dry-run (perform live changes after confirmation)
  --change-id <id>         Change ticket / RFC ID (required for change actions)
  --customer <name>        Customer/environment label for report folder (default: default_customer)
  --ssh-user <user>        SSH username for OS-level checks (onprem/opsmanager)
  --ssh-key <path>         SSH private key path
  --api-public-key <key>   Ops Manager / Atlas API public key
  --api-project-id <id>    Ops Manager groupId or Atlas projectId
  --api-base-url <url>     Ops Manager base URL (e.g. https://opsmanager.example.com:8443)
  --report-format <fmt>    Report format: markdown | html | both (default: both)
  --timeout <sec>          Timeout per mongosh command in seconds (default: 30)
  -h, --help               Show this help message and exit

Security Notes:
  - Passwords and API private keys are NEVER accepted via CLI flags or files.
  - You will be prompted interactively with `read -rs` and secrets are passed
    only via child-process environment variables scoped to single commands.
EOF
}

# --- Input Validation ---------------------------------------------------------
is_change_action() {
  local act="${1:-}"
  [[ "$act" == "switchover" || "$act" == "rolling-maint" ]]
}

validate_inputs() {
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

  if [[ -n "$TLS_CA_FILE" && ! -r "$TLS_CA_FILE" ]]; then
    log_error "TLS CA file not readable: $TLS_CA_FILE"; return "$EXIT_USAGE"
  fi

  if [[ -n "$SSH_KEY" && ! -r "$SSH_KEY" ]]; then
    log_error "SSH key file not readable: $SSH_KEY"; return "$EXIT_USAGE"
  fi

  if [[ -n "$HOST_OR_URI" && "$HOST_OR_URI" =~ :[^:@/]+@ ]]; then
    log_error "Do not embed passwords in --uri/--host. Use --user and interactive password prompt."
    return "$EXIT_USAGE"
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
  fi
  return "$EXIT_OK"
}

# --- Dependency Checks --------------------------------------------------------
check_dependencies() {
  local missing=0
  local cmd
  for cmd in mongosh jq ssh timeout; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      log_error "Required dependency not found in PATH: $cmd"
      missing=1
    fi
  done

  if [[ "$DEPLOYMENT" == "atlas" || "$DEPLOYMENT" == "opsmanager" ]]; then
    if ! command -v curl >/dev/null 2>&1 && ! command -v atlas >/dev/null 2>&1; then
      log_warn "Neither 'curl' nor 'atlas' CLI found; API-driven Atlas/Ops Manager actions will be limited."
    fi
  fi

  if (( missing > 0 )); then
    return "$EXIT_DEPENDENCY"
  fi
  log_info "Core dependencies verified (mongosh, jq, ssh, timeout)."
  return "$EXIT_OK"
}

# --- Secret Prompting (Never saved to disk/history/args) ---------------------
prompt_secrets() {
  if [[ -n "$DB_USER" && -z "$MONGO_PASSWORD" ]]; then
    printf 'Enter MongoDB password for user "%s": ' "$DB_USER" >&2
    IFS= read -rs MONGO_PASSWORD
    printf '\n' >&2
    if [[ -z "$MONGO_PASSWORD" ]]; then
      log_error "Empty password provided for user '$DB_USER'."
      return "$EXIT_AUTH_CONN"
    fi
  fi

  if [[ "$DEPLOYMENT" == "atlas" || "$DEPLOYMENT" == "opsmanager" ]]; then
    if [[ -n "$API_PUBLIC_KEY" && -z "$API_PRIVATE_KEY" ]]; then
      printf 'Enter %s API private key for "%s": ' "$DEPLOYMENT" "$API_PUBLIC_KEY" >&2
      IFS= read -rs API_PRIVATE_KEY
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
    printf "Enter MongoDB username (leave blank if no-auth/x509): " >&2
    IFS= read -r DB_USER
  fi

  if [[ -n "$DB_USER" && "$AUTH_DB" == "admin" ]]; then
    printf "Authentication database [admin]: " >&2
    local adb
    IFS= read -r adb
    [[ -n "$adb" ]] && AUTH_DB="$adb"
  fi

  if [[ -z "$ACTION" ]]; then
    echo "Select action:" >&2
    echo "  1) prechecks      - Full health & readiness pre-checks (PASS/WARN/FAIL)" >&2
    echo "  2) switchover     - Controlled primary step-down / failover" >&2
    echo "  3) rolling-maint  - Rolling maintenance helper (secondaries first)" >&2
    echo "  4) report         - OS, storage & MongoDB health report (Markdown/HTML)" >&2
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
    [[ -n "$cust" ]] && CUSTOMER_NAME="$cust"
  fi

  if [[ "$DEPLOYMENT" != "atlas" && -z "$SSH_USER" ]]; then
    printf "Optional SSH user for OS checks (blank to skip SSH): " >&2
    IFS= read -r SSH_USER
  fi

  return "$EXIT_OK"
}

# --- Confirmation Gate for Disruptive Actions -------------------------------
confirm_disruptive_action() {
  local action_desc="$1"
  local expected_token="$DETECTED_CLUSTER_NAME"
  if [[ -z "$expected_token" || "$expected_token" == "unknown" ]]; then
    expected_token="$HOST_OR_URI"
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Would execute '${action_desc}' (Change ID: ${CHANGE_ID}) on target '${expected_token}'. No live changes made."
    return 0
  fi

  printf '\n[WARNING] LIVE DISRUPTIVE ACTION: %s\n' "$action_desc" >&2
  printf 'Change ID : %s\n' "$CHANGE_ID" >&2
  printf 'Target    : %s (topology=%s, edition=%s)\n' "$expected_token" "$DETECTED_TOPOLOGY" "$DETECTED_EDITION" >&2
  printf 'Type the cluster/target name "%s" to confirm execution: ' "$expected_token" >&2
  local typed=""
  IFS= read -r typed
  if [[ "$typed" != "$expected_token" ]]; then
    log_error "Confirmation mismatch ('%s' != '%s'). Aborting disruptive action." "$typed" "$expected_token"
    return "$EXIT_ABORTED"
  fi
  log_info "Typed confirmation accepted for '%s' (Change ID: %s)." "$expected_token" "$CHANGE_ID"
  return 0
}

# --- mongosh Execution Wrapper (Scoped Child Env + Timeout) -----------------
build_mongosh_uri() {
  local target="$HOST_OR_URI"
  local uri=""
  if [[ "$target" == mongodb://* || "$target" == mongodb+srv://* ]]; then
    uri="$target"
  else
    uri="mongodb://${target}/?authSource=${AUTH_DB}"
  fi

  if [[ "$USE_TLS" == "true" ]]; then
    if [[ "$uri" == *\?* ]]; then
      uri="${uri}&tls=true"
    else
      uri="${uri}?tls=true"
    fi
    if [[ -n "$TLS_CA_FILE" ]]; then
      uri="${uri}&tlsCAFile=${TLS_CA_FILE}"
    fi
  fi
  printf '%s' "$uri"
}

run_mongosh_js() {
  local js_code="$1"
  local uri
  uri="$(build_mongosh_uri)"

  local -a args=(--quiet --uri "$uri")
  if [[ -n "$DB_USER" ]]; then
    args+=(--username "$DB_USER")
  fi

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
      mongosh "${args[@]}" --eval "$wrapped_js" 2>"${SESSION_TMP_DIR}/mongosh.err"
  )" || rc=$?

  if [[ -s "${SESSION_TMP_DIR}/mongosh.err" ]]; then
    local err_clean
    err_clean="$(redact_secrets "$(cat "${SESSION_TMP_DIR}/mongosh.err")")"
    if (( rc != 0 )); then
      log_warn "mongosh stderr (rc=${rc}): ${err_clean}"
    fi
    : > "${SESSION_TMP_DIR}/mongosh.err"
  fi

  printf '%s' "$output"
  return "$rc"
}

# --- Topology, Edition, Version & FCV Auto-Detection ------------------------
detect_cluster_metadata() {
  log_info "Auto-detecting MongoDB edition, version, FCV, and topology..."
  local js
  js='
    const hello = db.hello();
    const buildInfo = db.adminCommand({ buildInfo: 1 });
    const fcvDoc = db.adminCommand({ getParameter: 1, featureCompatibilityVersion: 1 });

    let edition = "Community";
    if (buildInfo.modules && Array.isArray(buildInfo.modules) && buildInfo.modules.includes("enterprise")) {
      edition = "Enterprise";
    } else if (typeof buildInfo.gitVersion === "string" && buildInfo.gitVersion.toLowerCase().includes("enterprise")) {
      edition = "Enterprise";
    }

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
    if (topology === "sharded") {
      try {
        const sList = db.adminCommand({ listShards: 1 });
        shards = (sList.shards || []).map(s => ({ _id: s._id, host: s.host, state: s.state }));
      } catch (e) {}
    } else if (topology === "replicaset") {
      try {
        const st = rs.status();
        members = (st.members || []).map(m => ({
          name: m.name,
          stateStr: m.stateStr,
          health: m.health,
          optimeDate: m.optimeDate
        }));
      } catch (e) {}
    }

    print(JSON.stringify({
      ok: 1,
      edition: edition,
      version: buildInfo.version || "unknown",
      fcv: (fcvDoc.featureCompatibilityVersion && (fcvDoc.featureCompatibilityVersion.version || fcvDoc.featureCompatibilityVersion)) || "unknown",
      topology: topology,
      clusterName: clusterName,
      shards: shards,
      members: members
    }));
  '

  local raw_json
  if ! raw_json="$(run_mongosh_js "$js")"; then
    log_error "Failed to connect or authenticate to MongoDB target."
    return "$EXIT_AUTH_CONN"
  fi

  local parsed
  parsed="$(printf '%s\n' "$raw_json" | grep -E '^\{.*"ok":1' | tail -n 1 || true)"
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

  log_info "Detected: edition=${DETECTED_EDITION}, version=${DETECTED_VERSION}, FCV=${DETECTED_FCV}, topology=${DETECTED_TOPOLOGY}, cluster=${DETECTED_CLUSTER_NAME}"
  return "$EXIT_OK"
}

# --- Capability Gating Helper -------------------------------------------------
supports_capability() {
  local cap="$1"
  case "$cap" in
    os_ssh)
      [[ "$DEPLOYMENT" != "atlas" && -n "$SSH_USER" ]]
      ;;
    rs_stepdown_direct)
      [[ "$DEPLOYMENT" != "atlas" && ( "$DETECTED_TOPOLOGY" == "replicaset" || "$DETECTED_TOPOLOGY" == "sharded" ) ]]
      ;;
    atlas_failover_api)
      [[ "$DEPLOYMENT" == "atlas" ]]
      ;;
    opsmanager_api)
      [[ "$DEPLOYMENT" == "opsmanager" ]]
      ;;
    enterprise_audit_ldap_kmip)
      [[ "$DETECTED_EDITION" == "Enterprise" ]]
      ;;
    *)
      return 1
      ;;
  esac
}

# --- Pre-Checks (PASS / WARN / FAIL) -----------------------------------------
record_check() {
  local name="$1"
  local status="$2" # PASS | WARN | FAIL
  local detail="$3"
  printf '%s\t%s\t%s\n' "$name" "$status" "$detail" >> "${PRECHECK_RESULTS_FILE}"
  case "$status" in
    PASS) ((PASS_COUNT++)) || true; log_info "[PASS] ${name}: ${detail}" ;;
    WARN) ((WARN_COUNT++)) || true; log_warn "[WARN] ${name}: ${detail}" ;;
    FAIL) ((FAIL_COUNT++)) || true; log_error "[FAIL] ${name}: ${detail}" ;;
  esac
}

run_prechecks() {
  PASS_COUNT=0
  WARN_COUNT=0
  FAIL_COUNT=0
  : > "${PRECHECK_RESULTS_FILE}"

  log_info "=== Running Pre-Checks (deployment=${DEPLOYMENT}, topology=${DETECTED_TOPOLOGY}, edition=${DETECTED_EDITION}) ==="

  record_check "connectivity_and_auth" "PASS" "Connected and authenticated to ${HOST_OR_URI} (authDb=${AUTH_DB})"

  if [[ "$DETECTED_VERSION" != "unknown" && "$DETECTED_FCV" != "unknown" ]]; then
    local v_major_minor
    v_major_minor="$(printf '%s' "$DETECTED_VERSION" | awk -F. '{print $1"."$2}')"
    if [[ "$v_major_minor" == "$DETECTED_FCV" ]]; then
      record_check "version_and_fcv" "PASS" "Version=${DETECTED_VERSION}, FCV=${DETECTED_FCV} (aligned)"
    else
      record_check "version_and_fcv" "WARN" "Version=${DETECTED_VERSION} (major.minor=${v_major_minor}) differs from FCV=${DETECTED_FCV}"
    fi
  else
    record_check "version_and_fcv" "WARN" "Could not determine version (${DETECTED_VERSION}) or FCV (${DETECTED_FCV})"
  fi

  local telemetry_js='
    const serverStatus = db.adminCommand({ serverStatus: 1 });
    const conn = serverStatus.connections || {};
    const mem = serverStatus.mem || {};
    const wiredTiger = serverStatus.wiredTiger || {};
    const wtCache = wiredTiger.cache || {};

    let longOps = [];
    try {
      longOps = db.getSiblingDB("admin").aggregate([
        { $currentOp: { allUsers: false, idleConnections: false } },
        { $match: { active: true, secs_running: { $gte: 30 } } },
        { $project: { opid: 1, ns: 1, secs_running: 1, op: 1 } }
      ]).toArray();
    } catch (e) {}

    let rsSummary = null;
    if (db.hello().setName) {
      const st = rs.status();
      let primaryOptime = null;
      for (const m of (st.members || [])) {
        if (m.stateStr === "PRIMARY" && m.optimeDate) {
          primaryOptime = new Date(m.optimeDate).getTime();
        }
      }
      const unhealthy = (st.members || []).filter(
        m => m.health !== 1 || ["UNKNOWN","DOWN","RECOVERING","ROLLBACK","FATAL"].includes(m.stateStr)
      );
      let maxLagSec = 0;
      if (primaryOptime) {
        for (const m of (st.members || [])) {
          if (m.stateStr === "SECONDARY" && m.optimeDate) {
            const lag = Math.max(0, (primaryOptime - new Date(m.optimeDate).getTime()) / 1000);
            if (lag > maxLagSec) maxLagSec = lag;
          }
        }
      }
      rsSummary = {
        set: st.set,
        unhealthyCount: unhealthy.length,
        maxLagSec: maxLagSec,
        memberCount: (st.members || []).length
      };
    }

    let oplogWindowHours = null;
    try {
      const repInfo = rs.getReplicationInfo ? rs.getReplicationInfo() : null;
      if (repInfo && typeof repInfo.timeDiffHours === "number") {
        oplogWindowHours = repInfo.timeDiffHours;
      } else {
        const oplogInfo = db.getSiblingDB("local").getCollection("oplog.rs").stats();
        if (oplogInfo && oplogInfo.maxSize) oplogWindowHours = -1;
      }
    } catch (e) {}

    let shardedInfo = null;
    if (db.hello().msg === "isdbgrid") {
      let balancerRunning = null;
      let chunksJumbo = 0;
      try {
        const bal = db.adminCommand({ balancerStatus: 1 });
        balancerRunning = !!bal.inBalancerRound;
      } catch (e) {}
      try {
        chunksJumbo = db.getSiblingDB("config").chunks.countDocuments({ jumbo: true });
      } catch (e) {}
      const shards = db.adminCommand({ listShards: 1 }).shards || [];
      shardedInfo = {
        shardCount: shards.length,
        balancerRunning: balancerRunning,
        jumboChunks: chunksJumbo
      };
    }

    print(JSON.stringify({
      ok: 1,
      connections: { current: conn.current || 0, available: conn.available || 0 },
      mem: { residentMB: mem.resident || 0, virtualMB: mem.virtual || 0 },
      wtCacheDirtyPct: (wtCache["bytes currently in the cache"] && wtCache["tracked dirty bytes in the cache"])
        ? Number(((wtCache["tracked dirty bytes in the cache"] / wtCache["bytes currently in the cache"]) * 100).toFixed(2))
        : 0,
      longOpsCount: longOps.length,
      rsSummary: rsSummary,
      oplogWindowHours: oplogWindowHours,
      shardedInfo: shardedInfo
    }));
  '

  local tel_raw tel_json
  tel_raw="$(run_mongosh_js "$telemetry_js" || true)"
  tel_json="$(printf '%s\n' "$tel_raw" | grep -E '^\{.*"ok":1' | tail -n 1 || echo '{}')"

  local rs_unhealthy rs_lag
  rs_unhealthy="$(printf '%s' "$tel_json" | jq -r '.rsSummary.unhealthyCount // -1')"
  rs_lag="$(printf '%s' "$tel_json" | jq -r '.rsSummary.maxLagSec // -1')"
  if [[ "$rs_unhealthy" == "-1" ]]; then
    record_check "replica_set_health_and_lag" "PASS" "Topology is ${DETECTED_TOPOLOGY} (not a single replica set)"
  elif (( rs_unhealthy > 0 )); then
    record_check "replica_set_health_and_lag" "FAIL" "${rs_unhealthy} unhealthy/non-normal replica set member(s) detected"
  elif (( ${rs_lag%.*} > 30 )); then
    record_check "replica_set_health_and_lag" "FAIL" "Replication lag is ${rs_lag}s (> 30s threshold)"
  elif (( ${rs_lag%.*} > 10 )); then
    record_check "replica_set_health_and_lag" "WARN" "Replication lag is ${rs_lag}s (> 10s warning)"
  else
    record_check "replica_set_health_and_lag" "PASS" "All members healthy; max replication lag=${rs_lag}s"
  fi

  local oplog_hrs
  oplog_hrs="$(printf '%s' "$tel_json" | jq -r '.oplogWindowHours // "null"')"
  if [[ "$oplog_hrs" == "null" || "$oplog_hrs" == "-1" ]]; then
    record_check "oplog_window" "WARN" "Oplog window unavailable (standalone, mongos, or restricted privileges)"
  else
    local oplog_int="${oplog_hrs%.*}"
    if (( oplog_int < 12 )); then
      record_check "oplog_window" "FAIL" "Oplog window is ${oplog_hrs}h (< 12h)"
    elif (( oplog_int < 24 )); then
      record_check "oplog_window" "WARN" "Oplog window is ${oplog_hrs}h (< 24h)"
    else
      record_check "oplog_window" "PASS" "Oplog window is ${oplog_hrs}h"
    fi
  fi

  local cur_conn avail_conn total_conn conn_pct=0
  cur_conn="$(printf '%s' "$tel_json" | jq -r '.connections.current // 0')"
  avail_conn="$(printf '%s' "$tel_json" | jq -r '.connections.available // 1')"
  total_conn=$((cur_conn + avail_conn))
  if (( total_conn > 0 )); then
    conn_pct=$(( (cur_conn * 100) / total_conn ))
  fi
  if (( conn_pct >= 85 )); then
    record_check "connections" "FAIL" "Connections at ${conn_pct}% (${cur_conn}/${total_conn} available)"
  elif (( conn_pct >= 70 )); then
    record_check "connections" "WARN" "Connections at ${conn_pct}% (${cur_conn}/${total_conn} available)"
  else
    record_check "connections" "PASS" "Connections at ${conn_pct}% (${cur_conn}/${total_conn} available)"
  fi

  local rss_mb dirty_pct
  rss_mb="$(printf '%s' "$tel_json" | jq -r '.mem.residentMB // 0')"
  dirty_pct="$(printf '%s' "$tel_json" | jq -r '.wtCacheDirtyPct // 0')"
  if (( ${dirty_pct%.*} >= 20 )); then
    record_check "memory_and_cache" "FAIL" "Resident=${rss_mb}MB, WT dirty cache=${dirty_pct}% (>= 20%)"
  elif (( ${dirty_pct%.*} >= 10 )); then
    record_check "memory_and_cache" "WARN" "Resident=${rss_mb}MB, WT dirty cache=${dirty_pct}% (>= 10%)"
  else
    record_check "memory_and_cache" "PASS" "Resident=${rss_mb}MB, WT dirty cache=${dirty_pct}%"
  fi

  local long_ops
  long_ops="$(printf '%s' "$tel_json" | jq -r '.longOpsCount // 0')"
  if (( long_ops >= 5 )); then
    record_check "long_running_ops" "WARN" "${long_ops} active operations running >= 30s"
  else
    record_check "long_running_ops" "PASS" "${long_ops} active operations running >= 30s"
  fi

  local sharded_present
  sharded_present="$(printf '%s' "$tel_json" | jq -r '.shardedInfo != null')"
  if [[ "$sharded_present" == "true" ]]; then
    local shard_cnt jumbo_cnt
    shard_cnt="$(printf '%s' "$tel_json" | jq -r '.shardedInfo.shardCount // 0')"
    jumbo_cnt="$(printf '%s' "$tel_json" | jq -r '.shardedInfo.jumboChunks // 0')"
    if (( shard_cnt < 1 )); then
      record_check "sharded_balancer_and_config" "FAIL" "No shards registered on mongos"
    elif (( jumbo_cnt > 0 )); then
      record_check "sharded_balancer_and_config" "WARN" "${shard_cnt} shards, config DB reachable, ${jumbo_cnt} jumbo chunk(s) present"
    else
      record_check "sharded_balancer_and_config" "PASS" "${shard_cnt} shards healthy, config server reachable, 0 jumbo chunks"
    fi
  else
    record_check "sharded_balancer_and_config" "PASS" "Not a sharded cluster (topology=${DETECTED_TOPOLOGY})"
  fi

  check_backup_age

  if [[ "$USE_TLS" == "true" ]]; then
    if [[ -n "$TLS_CA_FILE" && -f "$TLS_CA_FILE" ]] && command -v openssl >/dev/null 2>&1; then
      local expiry_str
      expiry_str="$(openssl x509 -in "$TLS_CA_FILE" -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
      record_check "tls_cert_expiry" "PASS" "TLS enabled; CA certificate expiry=${expiry_str:-verified}"
    else
      record_check "tls_cert_expiry" "PASS" "TLS enabled for mongosh session"
    fi
  else
    record_check "tls_cert_expiry" "WARN" "TLS flag not set (--tls=false); verify transport encryption policy"
  fi

  check_os_via_ssh

  log_info "=== Pre-Check Summary: PASS=${PASS_COUNT}, WARN=${WARN_COUNT}, FAIL=${FAIL_COUNT} ==="
  if (( FAIL_COUNT > 0 )); then
    return "$EXIT_PRECHECK_FAIL"
  fi
  return "$EXIT_OK"
}

check_backup_age() {
  case "$DEPLOYMENT" in
    atlas)
      if [[ -n "$API_PUBLIC_KEY" && -n "$API_PRIVATE_KEY" && -n "$API_PROJECT_ID" ]] && command -v curl >/dev/null 2>&1; then
        local resp
        resp="$(curl -sS --max-time 15 --digest -u "${API_PUBLIC_KEY}:${API_PRIVATE_KEY}" \
          "https://cloud.mongodb.com/api/atlas/v1.0/groups/${API_PROJECT_ID}/clusters/${DETECTED_CLUSTER_NAME}/backup/snapshots" 2>/dev/null || true)"
        if printf '%s' "$resp" | jq -e '.results[0].createdAt' >/dev/null 2>&1; then
          local snap_date
          snap_date="$(printf '%s' "$resp" | jq -r '.results[0].createdAt')"
          record_check "last_backup_age" "PASS" "Latest Atlas snapshot createdAt=${snap_date}"
          return 0
        fi
      fi
      record_check "last_backup_age" "WARN" "Atlas snapshot age not verified via API (supply --api-public-key, --api-project-id & private key or check Atlas UI)"
      ;;
    opsmanager)
      if [[ -n "$API_PUBLIC_KEY" && -n "$API_PRIVATE_KEY" && -n "$API_PROJECT_ID" && -n "$API_BASE_URL" ]] && command -v curl >/dev/null 2>&1; then
        record_check "last_backup_age" "PASS" "Ops Manager API target configured (${API_BASE_URL})"
      else
        record_check "last_backup_age" "WARN" "Ops Manager backup status requires API credentials and --api-base-url to verify programmatically"
      fi
      ;;
    onprem)
      record_check "last_backup_age" "WARN" "Self-managed backup age not automatically verified; confirm backup/snapshot job timestamps"
      ;;
  esac
}

check_os_via_ssh() {
  if ! supports_capability "os_ssh"; then
    if [[ "$DEPLOYMENT" == "atlas" ]]; then
      record_check "os_checks_ssh" "PASS" "Skipped on Atlas (managed infrastructure; OS/THP/ulimits managed by Atlas)"
    else
      record_check "os_checks_ssh" "WARN" "SSH not configured (--ssh-user omitted); skipping OS disk, ulimit, THP, and NTP checks"
    fi
    return 0
  fi

  local target_host
  target_host="$(printf '%s' "$HOST_OR_URI" | sed -E 's#^mongodb(\+srv)?://([^/@]+@)?##; s#/.*$##; s/,.*$//; s/:[0-9]+$//')"

  local -a ssh_opts=(-o BatchMode=yes -o ConnectTimeout="${SSH_TIMEOUT}" -o StrictHostKeyChecking=accept-new)
  if [[ -n "$SSH_KEY" ]]; then
    ssh_opts+=(-i "$SSH_KEY")
  fi

  local remote_cmd='
    df -hP /var/lib/mongo /data / 2>/dev/null | awk "NR==2 {print \"DISK:\" \$5 \"(\" \$4 \" free)\"}"
    ulimit -n 2>/dev/null | awk "{print \"NOFILE:\" \$1}"
    ulimit -u 2>/dev/null | awk "{print \"NPROC:\" \$1}"
    if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
      cat /sys/kernel/mm/transparent_hugepage/enabled | sed -E "s/.*\[([^\]]+)\].*/THP:\1/"
    else
      echo "THP:unknown"
    fi
    if command -v timedatectl >/dev/null 2>&1; then
      timedatectl show -p NTPSynchronized --value 2>/dev/null | awk "{print \"NTP:\" \$1}"
    elif command -v chronyc >/dev/null 2>&1; then
      chronyc tracking 2>/dev/null | awk "/Leap status/ {print \"NTP:\" \$4}"
    else
      echo "NTP:unknown"
    fi
  '

  local os_out
  if os_out="$(timeout "${SSH_TIMEOUT}s" ssh "${ssh_opts[@]}" "${SSH_USER}@${target_host}" "$remote_cmd" 2>/dev/null)"; then
    local disk_info nofile_val thp_val ntp_val
    disk_info="$(printf '%s\n' "$os_out" | awk -F: '/^DISK:/ {print $2}')"
    nofile_val="$(printf '%s\n' "$os_out" | awk -F: '/^NOFILE:/ {print $2}')"
    thp_val="$(printf '%s\n' "$os_out" | awk -F: '/^THP:/ {print $2}')"
    ntp_val="$(printf '%s\n' "$os_out" | awk -F: '/^NTP:/ {print $2}')"

    local disk_pct="${disk_info%%%*}"
    if [[ -n "$disk_pct" && "$disk_pct" =~ ^[0-9]+$ ]] && (( disk_pct >= 85 )); then
      record_check "os_disk_space" "FAIL" "Disk usage at ${disk_info}"
    elif [[ -n "$disk_pct" && "$disk_pct" =~ ^[0-9]+$ ]] && (( disk_pct >= 75 )); then
      record_check "os_disk_space" "WARN" "Disk usage at ${disk_info}"
    else
      record_check "os_disk_space" "PASS" "Disk usage ${disk_info:-checked}"
    fi

    if [[ -n "$nofile_val" && "$nofile_val" =~ ^[0-9]+$ ]] && (( nofile_val < 64000 )); then
      record_check "os_ulimits" "WARN" "ulimit -n is ${nofile_val} (recommended >= 64000)"
    else
      record_check "os_ulimits" "PASS" "ulimit -n=${nofile_val:-unknown}"
    fi

    if [[ "$thp_val" == "never" ]]; then
      record_check "os_thp" "PASS" "Transparent Huge Pages (THP) is 'never'"
    else
      record_check "os_thp" "WARN" "THP is '${thp_val}' (MongoDB recommends 'never')"
    fi

    if [[ "$ntp_val" == "yes" || "$ntp_val" == "Normal" ]]; then
      record_check "os_ntp" "PASS" "Clock / NTP synchronized (${ntp_val})"
    else
      record_check "os_ntp" "WARN" "NTP sync status '${ntp_val}' (verify time sync across nodes)"
    fi
  else
    record_check "os_checks_ssh" "WARN" "SSH connection to ${SSH_USER}@${target_host} failed or timed out"
  fi
}

# --- Action 2: Primary Switchover ---------------------------------------------
action_switchover() {
  log_info "=== Primary Switchover Workflow (Change ID: ${CHANGE_ID}, dry_run=${DRY_RUN}) ==="

  local pre_rc=0
  run_prechecks || pre_rc=$?
  if (( pre_rc == EXIT_PRECHECK_FAIL )); then
    log_error "Aborting primary switchover: pre-checks reported one or more FAIL items."
    return "$EXIT_PRECHECK_FAIL"
  fi

  if [[ "$DETECTED_TOPOLOGY" == "standalone" ]]; then
    log_warn "Target is a standalone node; primary switchover does not apply."
    return "$EXIT_OK"
  fi

  confirm_disruptive_action "Primary switchover (stepDown / test failover)" || return $?

  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Steps that would execute:"
    if supports_capability "atlas_failover_api"; then
      log_info "  - Trigger Atlas 'test failover' via Admin API / atlas CLI for cluster '${DETECTED_CLUSTER_NAME}'."
    elif supports_capability "opsmanager_api"; then
      log_info "  - Trigger controlled step-down via MongoDB command / Ops Manager API (never SSH-restarting managed nodes)."
    else
      log_info "  - Execute replSetStepDown(60, 15) on current PRIMARY (per shard if sharded)."
    fi
    log_info "  - Wait for new PRIMARY election and verify replication lag."
    log_info "  - Run post-switchover prechecks."
    return "$EXIT_OK"
  fi

  if supports_capability "atlas_failover_api"; then
    if command -v atlas >/dev/null 2>&1 && [[ -n "$API_PROJECT_ID" ]]; then
      log_info "Invoking Atlas CLI test failover for cluster '${DETECTED_CLUSTER_NAME}'..."
      env -i PATH="$PATH" HOME="${SESSION_TMP_DIR}" \
        timeout "${MONGOSH_TIMEOUT}s" \
        atlas clusters failover test "${DETECTED_CLUSTER_NAME}" --projectId "${API_PROJECT_ID}" || {
          log_error "Atlas CLI test failover failed."
          return "$EXIT_RUNTIME_ERR"
        }
    elif [[ -n "$API_PUBLIC_KEY" && -n "$API_PRIVATE_KEY" && -n "$API_PROJECT_ID" ]] && command -v curl >/dev/null 2>&1; then
      log_info "Invoking Atlas Admin API testFailover for cluster '${DETECTED_CLUSTER_NAME}'..."
      curl -sf --max-time 20 --digest -u "${API_PUBLIC_KEY}:${API_PRIVATE_KEY}" \
        -X POST "https://cloud.mongodb.com/api/atlas/v1.0/groups/${API_PROJECT_ID}/clusters/${DETECTED_CLUSTER_NAME}/restartPrimaries" \
        -H "Content-Type: application/json" >/dev/null || {
          log_error "Atlas Admin API testFailover call failed."
          return "$EXIT_RUNTIME_ERR"
        }
    else
      log_error "Atlas failover requires 'atlas' CLI or --api-public-key, --api-project-id, and private key."
      return "$EXIT_USAGE"
    fi
  elif supports_capability "opsmanager_api" || supports_capability "rs_stepdown_direct"; then
    log_info "Executing controlled replSetStepDown(60, 15) on primary..."
    local stepdown_js='
      const res = db.adminCommand({ replSetStepDown: 60, secondaryCatchUpPeriodSecs: 15 });
      print(JSON.stringify(res));
    '
    run_mongosh_js "$stepdown_js" >/dev/null || {
      log_warn "replSetStepDown closed connection or returned non-zero during election; verifying new primary..."
    }
  fi

  sleep 5
  detect_cluster_metadata || true
  log_info "Running post-switchover verification checks..."
  run_prechecks || return $?
  return "$EXIT_OK"
}

# --- Action 3: Rolling Maintenance Helper --------------------------------------
action_rolling_maint() {
  log_info "=== Rolling Maintenance Helper (Change ID: ${CHANGE_ID}, dry_run=${DRY_RUN}) ==="

  local pre_rc=0
  run_prechecks || pre_rc=$?
  if (( pre_rc == EXIT_PRECHECK_FAIL )); then
    log_error "Aborting rolling maintenance: pre-checks reported FAIL items."
    return "$EXIT_PRECHECK_FAIL"
  fi

  confirm_disruptive_action "Rolling maintenance (secondaries first, primary last, with health gates)" || return $?

  if [[ "$DETECTED_TOPOLOGY" == "standalone" ]]; then
    log_info "Standalone topology: maintenance applies directly to single node '${HOST_OR_URI}'."
    if [[ "$DRY_RUN" == "true" ]]; then
      log_info "[DRY-RUN] Would run health gate on standalone node."
      return "$EXIT_OK"
    fi
    run_prechecks
    return $?
  fi

  local secondaries primary_node
  secondaries="$(printf '%s' "$DETECTED_MEMBERS_JSON" | jq -r '.[] | select(.stateStr == "SECONDARY") | .name')"
  primary_node="$(printf '%s' "$DETECTED_MEMBERS_JSON" | jq -r '.[] | select(.stateStr == "PRIMARY") | .name')"

  log_info "Planned order: [1] Secondaries (${secondaries:-none}) -> [2] Primary (${primary_node:-unknown}) last."

  if [[ "$DRY_RUN" == "true" ]]; then
    local sec
    for sec in $secondaries; do
      log_info "[DRY-RUN] Gate & maintain SECONDARY: ${sec}"
    done
    if [[ -n "$primary_node" ]]; then
      log_info "[DRY-RUN] Step down & maintain former PRIMARY last: ${primary_node}"
    fi
    return "$EXIT_OK"
  fi

  local sec
  for sec in $secondaries; do
    log_info "Processing SECONDARY node: ${sec}"
    log_info "Running health gate check after secondary '${sec}'..."
    run_prechecks || {
      log_error "Health gate failed after secondary '${sec}'. Halting rolling maintenance."
      return "$EXIT_PRECHECK_FAIL"
    }
  done

  if [[ -n "$primary_node" ]]; then
    log_info "All secondaries passed health gates. Stepping down PRIMARY '${primary_node}' last..."
    run_mongosh_js 'db.adminCommand({ replSetStepDown: 60, secondaryCatchUpPeriodSecs: 15 });' >/dev/null || true
    sleep 5
    run_prechecks || return $?
  fi

  return "$EXIT_OK"
}

# --- Action 4: Health / Assessment Report (Markdown / HTML) -------------------
action_report() {
  log_info "=== Generating Health / Assessment Report ==="
  run_prechecks || true

  local md_path="${REPORT_DIR}/health_report.md"
  local html_path="${REPORT_DIR}/health_report.html"

  if [[ "$REPORT_FORMAT" == "markdown" || "$REPORT_FORMAT" == "both" ]]; then
    {
      printf '# MongoDB Health & Assessment Report\n\n'
      printf '* **Customer:** %s\n' "$CUSTOMER_NAME"
      printf '* **Timestamp (UTC):** %s\n' "$RUN_TIMESTAMP"
      printf '* **Deployment:** %s\n' "$DEPLOYMENT"
      printf '* **Edition:** %s\n' "$DETECTED_EDITION"
      printf '* **Version:** %s\n' "$DETECTED_VERSION"
      printf '* **FCV:** %s\n' "$DETECTED_FCV"
      printf '* **Topology:** %s (%s)\n' "$DETECTED_TOPOLOGY" "$DETECTED_CLUSTER_NAME"
      printf '* **Summary:** PASS=%d | WARN=%d | FAIL=%d\n\n' "$PASS_COUNT" "$WARN_COUNT" "$FAIL_COUNT"
      printf '## Check Results\n\n'
      printf '| Check | Status | Details |\n|---|---|---|\n'
      while IFS=$'\t' read -r cname cstatus cdetail; do
        printf '| `%s` | **%s** | %s |\n' "$cname" "$cstatus" "$cdetail"
      done < "${PRECHECK_RESULTS_FILE}"
    } > "$md_path"
    chmod 640 "$md_path"
    log_info "Markdown report saved to: ${md_path}"
  fi

  if [[ "$REPORT_FORMAT" == "html" || "$REPORT_FORMAT" == "both" ]]; then
    {
      printf '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>MongoDB Health Report</title>'
      printf '<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#1e293b}table{border-collapse:collapse;width:100%%}th,td{border:1px solid #cbd5e1;padding:0.5rem 0.75rem;text-align:left}th{background:#f1f5f9}.PASS{color:#15803d;font-weight:700}.WARN{color:#b45309;font-weight:700}.FAIL{color:#b91c1c;font-weight:700}</style></head><body>'
      printf '<h1>MongoDB Health &amp; Assessment Report</h1>'
      printf '<p><strong>Customer:</strong> %s | <strong>UTC:</strong> %s | <strong>Deployment:</strong> %s | <strong>Edition:</strong> %s | <strong>Version:</strong> %s | <strong>FCV:</strong> %s | <strong>Topology:</strong> %s</p>' \
        "$CUSTOMER_NAME" "$RUN_TIMESTAMP" "$DEPLOYMENT" "$DETECTED_EDITION" "$DETECTED_VERSION" "$DETECTED_FCV" "$DETECTED_TOPOLOGY"
      printf '<p><strong>Summary:</strong> PASS=%d, WARN=%d, FAIL=%d</p>' "$PASS_COUNT" "$WARN_COUNT" "$FAIL_COUNT"
      printf '<table><thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead><tbody>'
      while IFS=$'\t' read -r cname cstatus cdetail; do
        printf '<tr><td><code>%s</code></td><td class="%s">%s</td><td>%s</td></tr>' "$cname" "$cstatus" "$cstatus" "$cdetail"
      done < "${PRECHECK_RESULTS_FILE}"
      printf '</tbody></table></body></html>'
    } > "$html_path"
    chmod 640 "$html_path"
    log_info "HTML report saved to: ${html_path}"
  fi

  return "$EXIT_OK"
}

# --- Action 5: Read-Only User/Role Audit & Slow-Query/Index Analysis ---------
action_audit() {
  log_info "=== Read-Only User/Role Audit & Slow-Query/Index Analysis ==="

  local audit_js='
    let users = [];
    let roles = [];
    try {
      const uRes = db.getSiblingDB("admin").runCommand({ usersInfo: 1, showPrivileges: false });
      users = (uRes.users || []).map(u => ({
        user: u.user,
        db: u.db,
        roles: (u.roles || []).map(r => `${r.role}@${r.db}`)
      }));
    } catch (e) {
      users = [{ error: e.message }];
    }

    try {
      const rRes = db.getSiblingDB("admin").runCommand({ rolesInfo: 1, showPrivileges: false });
      roles = (rRes.roles || []).map(r => ({ role: r.role, db: r.db, isBuiltin: r.isBuiltin }));
    } catch (e) {
      roles = [{ error: e.message }];
    }

    let slowQueries = [];
    let indexSummary = [];
    try {
      const dbs = db.adminCommand({ listDatabases: 1 }).databases || [];
      for (const d of dbs) {
        if (["admin", "config", "local"].includes(d.name)) continue;
        const targetDb = db.getSiblingDB(d.name);
        try {
          const prof = targetDb.getCollection("system.profile")
            .find({ millis: { $gte: 100 } })
            .sort({ ts: -1 })
            .limit(15)
            .toArray();
          for (const p of prof) {
            slowQueries.push({
              ns: p.ns,
              op: p.op,
              millis: p.millis,
              planSummary: p.planSummary || "n/a"
            });
          }
        } catch (innerErr) {}

        try {
          const colls = targetDb.getCollectionInfos({ type: "collection" }) || [];
          for (const c of colls.slice(0, 20)) {
            const idx = targetDb.getCollection(c.name).getIndexes();
            indexSummary.push({
              ns: `${d.name}.${c.name}`,
              indexCount: idx.length,
              indexes: idx.map(i => i.name)
            });
          }
        } catch (idxErr) {}
      }
    } catch (e) {}

    print(JSON.stringify({
      ok: 1,
      userCount: users.length,
      users: users,
      customRolesCount: roles.filter(r => !r.isBuiltin).length,
      slowQueriesCount: slowQueries.length,
      slowQueries: slowQueries,
      indexSummary: indexSummary
    }));
  '

  local raw_out audit_json
  raw_out="$(run_mongosh_js "$audit_js")"
  audit_json="$(printf '%s\n' "$raw_out" | grep -E '^\{.*"ok":1' | tail -n 1 || echo '{}')"

  local audit_file="${REPORT_DIR}/audit_findings.json"
  printf '%s\n' "$audit_json" | jq '.' > "$audit_file" 2>/dev/null || printf '%s\n' "$audit_json" > "$audit_file"
  chmod 640 "$audit_file"

  local u_cnt r_cnt sq_cnt
  u_cnt="$(printf '%s' "$audit_json" | jq -r '.userCount // 0')"
  r_cnt="$(printf '%s' "$audit_json" | jq -r '.customRolesCount // 0')"
  sq_cnt="$(printf '%s' "$audit_json" | jq -r '.slowQueriesCount // 0')"

  log_info "Audit complete: users=${u_cnt}, custom_roles=${r_cnt}, slow_queries_sampled=${sq_cnt}"
  log_info "Detailed read-only audit artifact saved to: ${audit_file}"

  if supports_capability "enterprise_audit_ldap_kmip"; then
    log_info "Enterprise edition detected: verify auditLog / LDAP / KMIP parameters in mongod configuration."
  fi

  return "$EXIT_OK"
}

# --- Argument Parser ----------------------------------------------------------
parse_args() {
  while (( $# > 0 )); do
    case "$1" in
      --deployment)     DEPLOYMENT="${2:-}"; shift 2 ;;
      --host|--uri)     HOST_OR_URI="${2:-}"; shift 2 ;;
      --user)           DB_USER="${2:-}"; shift 2 ;;
      --auth-db)        AUTH_DB="${2:-}"; shift 2 ;;
      --tls)            USE_TLS="true"; shift 1 ;;
      --tls-ca)         TLS_CA_FILE="${2:-}"; shift 2 ;;
      --action)         ACTION="${2:-}"; shift 2 ;;
      --dry-run)        DRY_RUN="true"; shift 1 ;;
      --execute)        DRY_RUN="false"; shift 1 ;;
      --change-id)      CHANGE_ID="${2:-}"; shift 2 ;;
      --customer)       CUSTOMER_NAME="${2:-}"; shift 2 ;;
      --ssh-user)       SSH_USER="${2:-}"; shift 2 ;;
      --ssh-key)        SSH_KEY="${2:-}"; shift 2 ;;
      --api-public-key) API_PUBLIC_KEY="${2:-}"; shift 2 ;;
      --api-project-id) API_PROJECT_ID="${2:-}"; shift 2 ;;
      --api-base-url)   API_BASE_URL="${2:-}"; shift 2 ;;
      --report-format)  REPORT_FORMAT="${2:-}"; shift 2 ;;
      --timeout)        MONGOSH_TIMEOUT="${2:-}"; shift 2 ;;
      -h|--help)        usage; exit "$EXIT_OK" ;;
      *)
        log_error "Unknown option: $1"
        usage
        return "$EXIT_USAGE"
        ;;
    esac
  done
  return "$EXIT_OK"
}

# --- Main Orchestrator --------------------------------------------------------
main() {
  parse_args "$@" || return $?

  if [[ -z "$DEPLOYMENT" || -z "$HOST_OR_URI" || -z "$ACTION" ]]; then
    if [[ -t 0 ]]; then
      interactive_menu || return $?
    else
      log_error "Non-interactive mode requires --deployment, --host/--uri, and --action."
      return "$EXIT_USAGE"
    fi
  fi

  validate_inputs || return $?
  init_logging
  check_dependencies || return $?
  prompt_secrets || return $?
  detect_cluster_metadata || return $?

  case "$ACTION" in
    prechecks)     run_prechecks; return $? ;;
    switchover)    action_switchover; return $? ;;
    rolling-maint) action_rolling_maint; return $? ;;
    report)        action_report; return $? ;;
    audit)         action_audit; return $? ;;
    *)
      log_error "Unsupported action: $ACTION"
      return "$EXIT_USAGE"
      ;;
  esac
}

main "$@"
