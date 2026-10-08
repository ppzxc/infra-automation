# Infra Automation Domain Context

## 1. Overview
**`infra-automation`** is an idempotent Ansible automation suite executed by **Semaphore UI** (within the `overseer` Central Control Plane) to provision, maintain, harden, and orchestrate on-premise IDC target hosts across multiple Linux generations (CentOS 6 legacy to Rocky Linux 10, Ubuntu/Debian).

## 2. System Boundaries & Relationship
- **Central Control Plane (`../overseer`)**: Hosts OpenBao (SSH CA & Secrets), HashiCorp Boundary (Zero-Trust Session Proxy), PostgreSQL, and Semaphore UI (GitOps orchestrator).
- **Target Host Automation (`infra-automation`)**: Manages the managed hosts (`servers`, `loadbalancers`). It connects hosts to the Control Plane by configuring SSH CA trust, Boundary Target metadata, and OpenTelemetry OTLP hostmetric/log pipelines.

## 3. Core Roles & Modules
- **`access_security`**: Deep module unifying Zero-Trust access control (OpenBao SSH CA public key injection, AuthorizedPrincipals mapping, Boundary Worker metadata generation, and CentOS 6 fallback authentication).
- **`security`**: Host-level OS hardening (SSH parameters, Auditd rules, Fail2ban, SELinux permissive mode, sudo logging, firewalld-docker CLI).
- **`docker_engine`**: Automated cleanup of conflicting packages (Podman) and deployment of hardened Docker CE and compose plugins.
- **`monitoring`**: OpenTelemetry Collector Contrib (`otelcol-contrib`) deployment sending hostmetrics and system logs to the central OpenObserve backend, replacing legacy `node_exporter`.
- **`common`**: Baseline OS packages, timezone, Chrony/NTP time synchronization, sysctl kernel parameters, and admin accounts.

## Language

**Inventory Hostname**:
The management number (e.g. `ns0332`) under which a host is listed in the inventory; it is the name Ansible, Semaphore and Boundary use to identify the host and the key for its host-specific variables. It is not the host's FQDN, which is only a value the host carries.
_Avoid_: hostname, FQDN (when you mean the inventory key), server name

**Raw Provisioning Path**:
A design for provisioning CentOS 6/7 targets (which lack a Python 3.7+ interpreter, so ansible-core's AnsiballZ module wrapper SyntaxErrors on every standard module call) by driving `ansible.builtin.raw` directly and bypassing AnsiballZ entirely. It supplies its own write-temp/validate/move helper to replace module `validate:` clauses, and its own changed/unchanged sentinel contract to preserve this suite's idempotence guarantee despite `raw` always reporting `changed: true`. Covers `roles/common` + `roles/security`; excludes `roles/docker_engine`. Implemented (ADR-0005, #28): the write-temp/validate/move helper and sentinel contract (`filter_plugins/raw_provisioning.py`), automatic path detection from `/etc/redhat-release` (`raw_classify_os_path`, `playbooks/common/detect_raw_path.yml`; an explicit inventory `raw_provisioning_path` overrides it) and fact bypass via raw parsing (`raw_parse_os_release`), and raw equivalents for every module-based task of `common` and `security` — shared tasks (sysctl, accounts, sudoers, SSH keys, limits, fail2ban, auditd), the CentOS 6-only iptables pair (`SEC-008`/`SEC-021`) and ntpd (`COMMON-010`), and the CentOS 7 firewalld block (`SEC-042`~`SEC-050`). raw tasks are skipped under `--check` (ADR-0005 Option A), so a dry run never changes the target. Host Agents (ADR-0006) extend this path with a minimal helper subset (`roles/monitoring/tasks/raw_upload.yml`, #46): scp binary upload verified against the pinned sha256, plus check-mode read-only probes and diff output; the per-agent legacy tasks are not yet implemented.
_Avoid_: raw fallback, raw mode, raw provisioning (imprecise — always the full canonical name)

**Host Agents**:
The pair of agents — `otelcol-contrib` (logs + hostmetrics shipped to OpenObserve) and `resticprofile`/`restic` (backups shipped to RustFS over the S3 API) — that are always installed together, never one without the other, on every host in the `servers` group. Collection and backup targets follow the ISMS (not ISMS-P) standard. Their standard configuration is held in Git; per-host overrides and secrets come from OpenBao. Designed in ADR-0006; not yet implemented.
_Avoid_: monitoring agent, backup agent (when meaning the pair), sidecar

**Host Agents Exclusion**:
Membership of a `servers` host in the inventory group `host_agents_excluded`, meaning Host Agents are not (yet) applied to it. Deploy, Config and Repo Maintenance all leave such a host out, so the exclusion lives in one place instead of per-template Limits or `target_hosts`. Removing the host from the group is how it is brought under Host Agents. Defined in ADR-0006 §2.1.
_Avoid_: skip list, Limit (for this purpose)

**Resource Attribute**:
A key/value stamped once per host (or per log source) on every log and metric that Host Agents ship — OTel semantic-convention names such as `host.name`, `host.id`, `host.ip`, `host.arch`, `os.name`, `os.version`, `deployment.environment.name` and `service.name`. OpenObserve turns them into stream fields (logs) and series labels (metrics). The values come from the Remote OS Probe and the inventory, not from a collector-side detector. `deployment.environment.name` is declared per host (never defaulted); `host.id` and `host.ip` are left out when the host has none, and the run summary names those hosts. Defined in ADR-0006 §2.3.
_Avoid_: label, tag, metadata (imprecise — they differ per signal in OTel)

**Host Audit**:
A read-only, periodic inspection of managed hosts that never changes a target and produces one consolidated report per run — an overall summary followed by a per-host appendix — covering Asset Inventory, Configuration Drift, Configuration Vulnerabilities and Package Vulnerabilities. It inspects every managed host, including those in Host Agents Exclusion and the CentOS 6/7 hosts, and names the checks a host could not undergo rather than omitting them. Fixing what it finds belongs to provisioning and maintenance, not to it.
_Avoid_: audit (when meaning only the CIS audit), scan, compliance check

**Asset Inventory**:
The per-host record of what a host is and in what state — identity, OS and its end-of-life status, hardware, installed packages, listening ports, accounts and who holds privilege. The asset list that ISMS control 1.2.1 (asset identification) asks for; produced by Host Audit, not kept in a separate CMDB product.
_Avoid_: CMDB, operational info, server list

**Configuration Vulnerability**:
A host setting that falls short of the KISA technical vulnerability checklist for Unix servers, 2026 edition — e.g. remote root login allowed, weak password policy. Each finding is named with its edition (`KISA-2026:U-13`), because the editions reuse item numbers for different checks; CIS Benchmark is cited only as a cross-reference, not checked separately.
_Avoid_: vulnerability (unqualified), misconfiguration

**Package Vulnerability**:
An installed package version that is affected by a known CVE or vendor security advisory.
_Avoid_: vulnerability (unqualified), CVE (when meaning the finding on a host)

**Configuration Drift**:
A difference between the state a host is declared to have in Git (provisioning and Host Agents configuration) and the state it actually has — a change made outside the change process. Reported per host as the declared tasks that would change. A difference from the previous Host Audit is not Configuration Drift but a change since the last audit. Not detectable on Raw Provisioning Path hosts, which Host Audit reports as such.
_Avoid_: drift (unqualified), config change, diff

**Log Type**:
The routing key (`log_type`: `security_logs`, `system_logs`, `app_logs`, `backup_logs`) that decides which OpenObserve stream, and so which retention, a log record goes to. Not a service name: `service.name` says which file group or daemon produced the record and is what operators filter on; one Log Type holds several service names.
_Avoid_: log category, stream tag

**Envelope Parsing**:
Lifting the fields that a log source's fixed format defines (event time, emitting program, pid, severity where the format carries one) out of a log line into structured fields, at the collector, without touching the original line. The original line stays the record's body and is the evidence; parsed fields sit beside it. Interpreting what a message *means* (who logged in, from which address, OCSF normalisation) is not Envelope Parsing and is done centrally in OpenObserve.
_Avoid_: log parsing (when meaning only this edge layer), normalisation, structuring

**Fast Scenario**:
The molecule scenario run at pre-push. Exercises the roles that need no external network (`common`, `security`, `access_security`) on the Representative Platform, including the idempotence check; widens to every platform in one run when `roles/security` or `roles/common` changed. `common` is always applied first as the Base Layer; the other roles can be selected individually.
_Avoid_: default scenario, quick test, smoke test

**Slow Scenario**:
The molecule scenario covering roles that depend on external networks (`docker_engine`, `monitoring`). Runs real installs, never at pre-push; run manually or from CI.
_Avoid_: network scenario, integration scenario

**Full Matrix**:
Every scenario on every supported platform (Rocky 8, Rocky 9, Ubuntu 22.04). The only run that verifies OS-family branches the Representative Platform does not cover. Run on demand and before a release, not at pre-push.
_Avoid_: full test, all-OS run

**Representative Platform**:
The platform (Rocky 9) that the Fast Scenario runs on at pre-push unless a change warrants the wider run, standing in for the Full Matrix.
_Avoid_: primary OS, default platform

**Base Layer**:
The `common` role, applied before any other role in a scenario because other roles (e.g. `access_security`) depend on the accounts it creates. Mirrors the production apply order.
_Avoid_: prerequisite role, seed

**Test Image**:
A derived container image with per-run preparation (SSH server, host keys, Python interpreter) already baked in, so a scenario spends no time on it. Rebuilt only when its definition changes.
_Avoid_: base image, custom image
