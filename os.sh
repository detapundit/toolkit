check_os_via_ssh() {
  if [[ "$DEPLOYMENT" == "atlas" ]]; then
    record_check "os_checks_ssh" "PASS" "Skipped on Atlas (managed infrastructure; OS/THP/ulimits managed by Atlas)"
    return 0
  fi

  local target_host
  target_host="$(printf '%s' "$HOST_OR_URI" | sed -E 's#^mongodb(\+srv)?://([^/@]+@)?##; s#/.*$##; s/,.*$//; s/:[0-9]+$//')"

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

  local os_out=""
  if [[ "$target_host" == "127.0.0.1" || "$target_host" == "localhost" ]]; then
    os_out="$(bash -c "$remote_cmd" 2>/dev/null || true)"
  elif [[ -n "$SSH_USER" ]]; then
    local -a ssh_opts=(-o BatchMode=yes -o ConnectTimeout="${SSH_TIMEOUT}" -o StrictHostKeyChecking=accept-new)
    if [[ -n "$SSH_KEY" ]]; then
      ssh_opts+=(-i "$SSH_KEY")
    fi
    os_out="$(timeout "${SSH_TIMEOUT}s" ssh "${ssh_opts[@]}" "${SSH_USER}@${target_host}" "$remote_cmd" 2>/dev/null || true)"
  else
    record_check "os_checks_ssh" "WARN" "SSH not configured (--ssh-user omitted); skipping OS disk, ulimit, THP, and NTP checks"
    return 0
  fi

  if [[ -n "$os_out" ]]; then
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
    record_check "os_checks_ssh" "WARN" "OS check command failed or timed out for ${target_host}"
  fi
}
