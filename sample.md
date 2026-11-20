# MongoDB Health Report - demo

*Generated (UTC):* 20261119T071214Z
*Deployment:* onprem
*Target:* `mongodb://127.0.0.1:27017,127.0.0.1:27018,127.0.0.1:27019/?replicaSet=rs0`
*Topology:* replicaset | *Edition:* Community | *Version:* 8.0.38 | *FCV:* 8.0
*Overall:* **FAIL** (PASS=17, WARN=11, FAIL=1)

| Check | Status | Detail |
|---|---|---|
| connectivity_and_auth | PASS | Connected and authenticated to mongodb://127.0.0.1:27017,127.0.0.1:27018,127.0.0.1:27019/?replicaSet=rs0 (authDb=admin) |
| version_and_fcv | PASS | Version=8.0.38, FCV=8.0 (aligned) |
| connections | PASS | Connections at 5% (23 used, 386 available) |
| memory_and_cache | PASS | Resident=184MB, WT dirty cache=0.16% of configured cache |
| long_running_ops | PASS | 0 active operations >= 30s across all users (longest 0s) |
| sharded_balancer_and_config | PASS | Not a sharded cluster (topology=replicaset) |
| rs_primary | PASS | Exactly one PRIMARY: 127.0.0.1:27017 |
| rs_member_health | PASS | All 3 members healthy |
| rs_majority | PASS | 3/3 voting members healthy (majority=2) |
| rs_lag | PASS | Max replication lag 0s |
| rs_electable_secondary | PASS | 2 electable caught-up secondary(ies): 127.0.0.1:27018, 127.0.0.1:27019 |
| oplog_window | FAIL | Oplog window is 3.47h (< 12h) |
| last_backup_age | WARN | NOT VERIFIED: pass --backup-dir (path readable from this host) or confirm backup job timestamps |
| tls_cert_expiry | WARN | TLS flag not set for this session; verify transport-encryption policy and certificate expiry manually |
| os_disk_space@127.0.0.1 | PASS | Disk usage 1%(992236304KB free on /) |
| os_ulimit_nofile@127.0.0.1 | WARN | NOFILE limit of running mongod is 1024 (recommended >= 64000) |
| os_ulimit_nproc@127.0.0.1 | WARN | NPROC limit of running mongod is 31225 (recommended >= 64000) |
| os_thp@127.0.0.1 | WARN | THP is 'madvise'. THP guidance differs for MongoDB 8.0+ - verify against the Production Notes for 8.0.38 |
| os_ntp@127.0.0.1 | PASS | Clock synchronised (yes) |
| os_disk_space@127.0.0.1 | PASS | Disk usage 1%(992236288KB free on /) |
| os_ulimit_nofile@127.0.0.1 | WARN | NOFILE limit of running mongod is 1024 (recommended >= 64000) |
| os_ulimit_nproc@127.0.0.1 | WARN | NPROC limit of running mongod is 31225 (recommended >= 64000) |
| os_thp@127.0.0.1 | WARN | THP is 'madvise'. THP guidance differs for MongoDB 8.0+ - verify against the Production Notes for 8.0.38 |
| os_ntp@127.0.0.1 | PASS | Clock synchronised (yes) |
| os_disk_space@127.0.0.1 | PASS | Disk usage 1%(992236288KB free on /) |
| os_ulimit_nofile@127.0.0.1 | WARN | NOFILE limit of running mongod is 1024 (recommended >= 64000) |
| os_ulimit_nproc@127.0.0.1 | WARN | NPROC limit of running mongod is 31225 (recommended >= 64000) |
| os_thp@127.0.0.1 | WARN | THP is 'madvise'. THP guidance differs for MongoDB 8.0+ - verify against the Production Notes for 8.0.38 |
| os_ntp@127.0.0.1 | PASS | Clock synchronised (yes) |
