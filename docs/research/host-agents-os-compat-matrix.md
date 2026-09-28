# Host agents: OS compatibility matrix for otelcol-contrib, restic, resticprofile

Research for [#9](https://github.com/ppzxc/infra-automation/issues/9), part of map [#8](https://github.com/ppzxc/infra-automation/issues/8) (Host Agents: otelcol + resticprofile).
Researched on 2026-09-28. Latest upstream releases at that date: otelcol-contrib v0.161.0, restic 0.19.1, resticprofile v0.33.1.

## TL;DR

- The kernel is the only real constraint. None of the three projects documents its own OS floor. They inherit it from the Go toolchain used to build the release. **Go 1.24+ requires Linux kernel 3.2**, and Go 1.23 was the last release that supports 2.6.32.
- glibc does not matter. Every official linux/amd64 release asset checked is `CGO_ENABLED=0` and statically linked, so glibc 2.12 (CentOS 6) and glibc 2.17 (CentOS 7) are never loaded.
- CentOS 7 (kernel 3.10) runs the **latest** release of all three binaries.
- CentOS 6 (kernel 2.6.32) must pin to the last Go 1.23 builds:

  | Binary | Last CentOS 6-safe version | Built with | First Go 1.24 build |
  |---|---|---|---|
  | otelcol-contrib | v0.119.0 | go1.23.5 | v0.120.0 (go1.24.0) |
  | restic | 0.17.3 | go1.23.3 | 0.18.0 (go1.24.1) |
  | resticprofile | v0.29.1 | go1.23.6 | v0.30.0 (go1.24.2) |

- **resticprofile's systemd scheduler does not work on CentOS 7 (systemd 219).** Its create path runs `systemd-analyze calendar`, which needs systemd 236 or later. Rocky 8 (systemd 239) can create schedules, but listing and unscheduling are broken on resticprofile v0.30.0 and later, because `systemctl --output json` is not supported there (upstream issue #516, still open). **Use the crond or crontab scheduler on CentOS 6, CentOS 7, and Rocky 8.** Use systemd timers on Rocky 9/10, Ubuntu 22.04+ and Debian 12+.
- The current `roles/monitoring` pin (`otelcol_version: "0.108.0"`) is already CentOS 6-safe as a binary. The role still cannot reach CentOS 6/7 hosts, because those hosts have to go through the ADR-0005 raw provisioning path (no AnsiballZ).

## Matrix

Legend:
- **T** = tested here, meaning the binary was executed or the systemd feature was probed in a container.
- **I** = inferred from primary sources: Go release notes plus `go version -m` on the release asset.
- Container probes share the WSL2 host kernel 6.18, so they prove userspace and systemd behaviour only. **No kernel-compatibility claim here is container-tested.**

| OS | Kernel / glibc / systemd | otelcol-contrib | restic | resticprofile | Init system for otelcol | resticprofile `schedule` |
|---|---|---|---|---|---|---|
| CentOS 6 | 2.6.32 / 2.12 / none (Upstart 0.6.5 + SysV `/etc/init.d`) | **<= v0.119.0** (I) | **<= 0.17.3** (I) | **<= v0.29.1** (I) | SysV init script + `chkconfig` (the role already ships `otelcol-contrib.init.j2`) | systemd: no. Set `scheduler: crontab:*:/etc/cron.d/resticprofile` (or `crond`) explicitly. See the scheduler section. |
| CentOS 7 | 3.10 / 2.17 (T) / systemd 219 (T) | latest (I) | latest (I) | latest (I) | systemd unit | **systemd: no** (needs `systemd-analyze calendar`, v236+). Use crontab/crond. |
| Rocky 8 | 4.18 / 2.28 / systemd 239 (T) | latest (T) | latest (T, runs) | latest (T, runs) | systemd unit | systemd create works (T: `systemd-analyze calendar` ok). `--output json` is **not** supported (T), so status/unschedule are broken on v0.30.0+ (issue #516). Prefer crontab/crond, or pin <= v0.29.1 if systemd timers are required. |
| Rocky 9 | 5.14 / 2.34 / systemd 252 (T) | latest (T) | latest (T, runs) | latest (T, runs) | systemd unit | systemd timer: yes (T: JSON list + calendar ok) |
| Rocky 10 | 6.12 / 2.39 (T) / systemd 257 (not probed) | latest (I) | latest (I) | latest (I) | systemd unit | systemd timer: yes (I) |
| Ubuntu 22.04 | 5.15 / 2.35 / systemd 249 (T) | latest (T) | latest (T, runs) | latest (T, runs) | systemd unit | systemd timer: yes (T: JSON list + calendar ok) |
| Ubuntu 24.04 / Debian 12 / 13 | >= 6.1 / >= 2.36 / systemd >= 252 | latest (I) | latest (I) | latest (I) | systemd unit | systemd timer: yes (I) |

Notes on the matrix:
- "latest" means v0.161.0 / 0.19.1 / v0.33.1 as of 2026-09-28. All of them are built with Go 1.26.x, which requires kernel 3.2+.
- CentOS 7 JSON output was not probed. The CentOS 7 image has no systemd PID 1 in Docker. The verdict does not depend on it, because the create path already fails at `systemd-analyze calendar`. CentOS 7's `systemd-analyze --help` lists no `calendar` verb (T).
- Userspace check on old glibc (T): all nine binaries executed inside the stock `centos:6` image (glibc 2.12), including the Go 1.24/1.26 builds (restic printed `restic 0.19.1 compiled with go1.26.4`, and the otelcol binaries reached their CLI parser). On Rocky 8/9 and Ubuntu 22.04, otelcol-contrib printed its version and restic ran up to flag parsing. This confirms static linking and shows glibc is irrelevant. It says **nothing** about the 2.6.32 kernel, because the containers run on host kernel 6.18. The kernel floor rests on the Go release notes and the syscall changes listed in the Evidence section.
- Rocky 10's x86-64-v3 CPU baseline is not a constraint, because every release asset is built with `GOAMD64=v1`.
- arm64: all three projects publish `linux_arm64` assets for every version above, including the pinned ones (otelcol-contrib v0.119.0 `.tar.gz`/`.rpm`/`.deb`, `restic_0.17.3_linux_arm64.bz2`, `resticprofile_0.29.1_linux_arm64.tar.gz`). CentOS 6 has no official aarch64 build, so arm64 only matters for EL7+ and Ubuntu/Debian.

## Evidence

### 1. Go kernel floor

- Go 1.23 release notes, Ports/Linux: "Go 1.23 is the last release that requires Linux kernel version 2.6.32 or later. Go 1.24 will require Linux kernel version 3.2 or later." [go.dev/doc/go1.23](https://go.dev/doc/go1.23#linux)
- Go 1.24 release notes, Ports/Linux: "As announced in the Go 1.23 release notes, Go 1.24 requires Linux kernel version 3.2 or later." [go.dev/doc/go1.24](https://go.dev/doc/go1.24#linux)
- The decision issue is [golang/go#67001](https://github.com/golang/go/issues/67001), "all: require Linux 3.2 kernel for Go 1.24". An earlier draft of the Go 1.23 notes said 3.17 (with a 3.10 + getrandom exception). That was corrected to 3.2 in CL 611943, so **CentOS 7's 3.10 kernel is above the floor.**
- Pre-getrandom kernels such as 3.10: commit [65679cfeb4](https://github.com/golang/go/commit/65679cfeb4) ("crypto/rand: reintroduce urandom fallback for legacy Linux kernels") keeps a `/dev/urandom` fallback. The Go 1.24 `crypto/rand` notes say that on kernels before 3.17 the default Reader "still opens /dev/urandom and may fail". This is fine on CentOS 7.
- Code changes that break 2.6.32 under Go 1.24: `syscall: always use prlimit for getrlimit/setrlimit` (prlimit arrived in 2.6.36, commit d0baac37e6) and the removal of the accept4 fallback (commit 5192d41f23). This is why the CentOS 6 pin is a hard floor and not just "unsupported but works".
- The Go minimum-requirements wiki lists only "For Go 1.24 and later: Kernel version 3.2 or later", and it does not mention glibc for CGO-disabled builds. [go.dev/wiki/MinimumRequirements](https://go.dev/wiki/MinimumRequirements)

### 2. Which Go built each release (from `go version -m` on the downloaded linux_amd64 asset)

| Asset | Go | Link | Build settings |
|---|---|---|---|
| otelcol-contrib v0.119.0 | go1.23.5 | static | CGO_ENABLED=0, GOAMD64=v1 |
| otelcol-contrib v0.120.0 | go1.24.0 | static | the tarball binary reports `otelcol-contrib version 0.120.1` (T) |
| otelcol-contrib v0.161.0 | go1.26.8 | static | CGO_ENABLED=0, GOAMD64=v1 |
| restic 0.17.3 | go1.23.3 | static | CGO_ENABLED=0 |
| restic 0.18.0 | go1.24.1 | static | |
| restic 0.19.1 | go1.26.4 | static | `-tags=selfupdate,disable_grpc_modules`, CGO_ENABLED=0, GOAMD64=v1 |
| resticprofile v0.29.1 | go1.23.6 | static | |
| resticprofile v0.30.0 | go1.24.2 | static | |
| resticprofile v0.33.1 | go1.26.2 | static | CGO_ENABLED=0, GOAMD64=v1 |

Release lists come from `gh release list` on the three upstream repos. No patch release exists after these Go 1.23 builds:
- otelcol releases tags go v0.118.0, v0.119.0, v0.120.0, v0.121.0 (no v0.119.x).
- restic goes 0.17.3, then 0.18.0.
- resticprofile goes v0.29.1, then v0.30.0.

### 3. Self-build ceiling with Go 1.23 (the "older Go" fallback)

The latest prebuilt release that runs on CentOS 6 is not the same as the latest source that still compiles with Go 1.23. The `go` directive in each `go.mod` is what decides whether Go 1.23 will build it:

| Project | Last tag whose `go.mod` accepts Go 1.23 | First tag requiring Go 1.24+ |
|---|---|---|
| restic | **0.18.1** (`go 1.23.0`) | 0.19.0 (`go 1.25.8`) |
| resticprofile | **v0.29.1** (`go 1.23.5`) | v0.30.0 (`go 1.24.1`) |
| otelcol-contrib | **v0.132.0** (core `otelcol/go.mod` and contrib `hostmetricsreceiver/go.mod` both `go 1.23.0`) | v0.133.0 (`go 1.24`) |

Caveats:
- For otelcol, the distribution is assembled by the builder (`ocb`) from the `opentelemetry-collector-releases` manifest. Every component module in a custom manifest has to satisfy Go 1.23, so only the core and hostmetrics modules were checked here. Any other receiver or exporter in the manifest (filelog, otlp, resourcedetection, prometheus) must be checked the same way before trusting v0.132.0.
- Self-building gains about 13 minor versions of otelcol and one minor version of restic. It does not gain anything for resticprofile. It also adds a build pipeline to maintain.

### 4. resticprofile scheduler behaviour (source: `creativeprojects/resticprofile`, `schedule/` package)

Where the schedules live:
- The global option `scheduler` selects the scheduler. The docs are at [schedules/cron](https://creativeprojects.github.io/resticprofile/schedules/cron/index.html).
- Supported forms: `crond`, `crond:/path/to/crontab`, `crontab:*:/etc/cron.d/resticprofile` (writes a file with a user field filled in automatically), `crontab:<user>:<file>`, `crontab:-:<file>` (no user field) and `systemd`.
- The `crontab` file forms exist in v0.29.1 (`schedule/scheduler_config.go@v0.29.1`, `case constants.SchedulerCrontab`), so they work with the CentOS 6 pin.

The default on Linux is systemd, and it does **not** auto-detect:
- The systemd provider claims both `SchedulerSystemd` and `SchedulerOSDefault` on the first, non-fallback pass (`handler_systemd.go`, `init()`).
- The crond provider only takes `SchedulerOSDefault` when `fallback == true` (`handler_crond.go`, `init()`).
- `FindHandler` returns the first non-nil handler, so on a host without systemctl the OS default still resolves to systemd, and `Init()` then fails at `lookupBinary("systemd", "systemctl")`. This is the same in v0.29.1 and on master.
- Conclusion: **`scheduler:` must be set explicitly on CentOS 6, and on any host where crontab is wanted.**

What the systemd generator needs from the host (master):
- `Job.Create` (`schedule/job.go`) calls `DisplaySchedules` before creating anything. For systemd, that runs `systemd-analyze calendar <expr>` and returns its error. The `calendar` verb was added in **systemd 236** (systemd NEWS, "CHANGES WITH 236": "systemd-analyze gained a new verb "calendar""). CentOS 7 ships systemd 219, and its `systemd-analyze --help` has no `calendar` verb (T), so **schedule creation fails on CentOS 7**. v0.29.1 has the same call (`job.go` line 45).
- It enables with `systemctl enable --now` (`handler_systemd.go` L190-196). `--now` came in systemd 220 (NEWS "CHANGES WITH 220"), which is another break on 219.
- It generates `Type=notify` service units and timers with `OnCalendar=`, `Persistent=true` and `WantedBy=timers.target`, installed in `/etc/systemd/system/` (system/user permission) or `~/.config/systemd/user/` (user_logged_on). See [schedules/systemd](https://creativeprojects.github.io/resticprofile/schedules/systemd/index.html).
- Listing units (status, unschedule, and removing units of the other type before a create) uses `systemctl list-units --output json` since v0.30.0 (commit 8d8a0dac, per upstream [issue #516](https://github.com/creativeprojects/resticprofile/issues/516), still open as of 2026-09-11).
  - On systemd 239 (Rocky 8 / AlmaLinux 8), `--output json` silently prints the plain table (T), and resticprofile logs "error decoding JSON".
  - On systemd 249 (Ubuntu 22.04) and 252 (Rocky 9), JSON output works (T).

### 5. Init systems

- **CentOS 6**: Upstart 0.6.5 is PID 1, but services are classic SysV scripts under `/etc/init.d` managed with `chkconfig`/`service`. `roles/monitoring/templates/otelcol-contrib.init.j2` is already a SysV script (nohup + pidfile), so otelcol needs nothing new here. restic/resticprofile are cron-driven and need no init script. cron comes from `cronie` with `/etc/cron.d`. The bare `centos:6` and `centos:7` Docker images do not include cronie, so real hosts need to be checked for it.
- **CentOS 7 and later, Ubuntu, Debian**: systemd units.

## Recommended fallbacks

**CentOS 7**
- Install the latest official static binaries.
- otelcol-contrib gets a systemd unit.
- resticprofile runs with `scheduler: crontab:*:/etc/cron.d/resticprofile` (or `crond`), because the systemd generator cannot run on systemd 219.
- An Ansible-managed hand-written systemd timer is an alternative if timers are preferred. resticprofile would then be invoked as a plain command, not through `resticprofile schedule`.

**CentOS 6**
- Pin otelcol-contrib v0.119.0, restic 0.17.3 and resticprofile v0.29.1. otelcol runs under the existing SysV init script, and resticprofile uses the explicit crontab scheduler.
- Security trade-off: Go 1.23 left upstream support when Go 1.25 shipped (August 2025). These pins carry unpatched Go standard-library CVEs (crypto/tls, net/http, and others) and unpatched application dependencies. The pins should be treated as a time-boxed exception with a migration deadline.
- If newer otelcol features are needed, self-build contrib with Go 1.23 up to about v0.132.0 (see section 3). This is not worth it for restic (gains one minor version) or resticprofile (gains nothing).
- Not researched: forwarding CentOS 6 logs through rsyslog to OpenObserve instead of running otelcol. Pinned otelcol v0.119.0 already covers CentOS 6, so this was not investigated. There are no primary-source claims here about EL6 rsyslog (v5.x) or OpenObserve syslog ingestion. Research it separately if the pin is rejected.

**Rocky 8**
- Latest binaries, systemd unit for otelcol.
- For resticprofile, prefer crontab/crond. Alternatively, pin v0.29.1 to keep systemd timers without the JSON-listing bug. Or accept that `resticprofile unschedule` and `status` misbehave (create works) until #516 is fixed.

**Rocky 9/10, Ubuntu 22.04+, Debian 12+**
- Latest binaries, systemd units, and the resticprofile systemd scheduler.

## Implications for this repo

- **Version per OS**: `otelcol_version` (and the future restic/resticprofile version vars) needs a per-OS override, via `group_vars` or a `vars/` map keyed on `ansible_distribution_major_version`. It cannot be one global pin once CentOS 6 is in scope.
- **Upgrades**: the `creates: /usr/local/bin/otelcol-contrib` guard in `roles/monitoring/tasks/main.yml` blocks version changes (already noted in map #8). A per-OS pin makes that worse.
- **CentOS 6/7 install path**: installs on these hosts have to go through the ADR-0005 raw provisioning path (`ansible.builtin.raw`, no AnsiballZ), because the current module-based tasks cannot run there.
- **Scheduler**: the resticprofile scheduler choice (crontab on EL6/7/8, systemd on newer systems) is a per-OS variable too.
