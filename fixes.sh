if [ -r /sys/kernel/mm/transparent_hugepage/enabled ]; then
  mode=$(cat /sys/kernel/mm/transparent_hugepage/enabled)
  if printf '%s' "$mode" | grep -qE '\[[^]]+\]'; then
    thp_clean=$(printf '%s' "$mode" | sed -E 's/.*\[([^]]+)\].*/\1/')
  else
    thp_clean="$mode"
  fi
  printf 'THP:%s\n' "$thp_clean"
else
  echo "THP:unreadable"
fi


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
      if [[ -n "$BACKUP_DIR" ]]; then
        if [[ ! -d "$BACKUP_DIR" ]]; then
          record_check "last_backup_age" "FAIL" "Backup directory does not exist: ${BACKUP_DIR}"
          return 0
        fi
        local latest_mtime now_epoch age_hours
        latest_mtime="$(find "$BACKUP_DIR" -maxdepth 3 -type f -printf '%T@\n' 2>/dev/null | sort -nr | head -n 1 || true)"
        if [[ -z "$latest_mtime" ]]; then
          record_check "last_backup_age" "WARN" "No backup files found in ${BACKUP_DIR}"
          return 0
        fi
        now_epoch="$(date -u +%s)"
        age_hours=$(( (now_epoch - ${latest_mtime%.*}) / 3600 ))
        if (( age_hours >= 48 )); then
          record_check "last_backup_age" "FAIL" "Latest backup in ${BACKUP_DIR} is ${age_hours}h old (>= 48h)"
        elif (( age_hours >= 24 )); then
          record_check "last_backup_age" "WARN" "Latest backup in ${BACKUP_DIR} is ${age_hours}h old (>= 24h)"
        else
          record_check "last_backup_age" "PASS" "Latest backup in ${BACKUP_DIR} is ${age_hours}h old"
        fi
      else
        record_check "last_backup_age" "WARN" "Self-managed backup age not automatically verified; pass --backup-dir or confirm backup job timestamps"
      fi
      ;;
  esac
}
