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
The management number (e.g. `ns0331`) under which a host is listed in the inventory; it is the name Ansible, Semaphore and Boundary use to identify the host and the key for its host-specific variables. It is not the host's FQDN, which is only a value the host carries.
_Avoid_: hostname, FQDN (when you mean the inventory key), server name

**Raw Provisioning Path**:
A design for provisioning CentOS 6/7 targets (which lack a Python 3.7+ interpreter, so ansible-core's AnsiballZ module wrapper SyntaxErrors on every standard module call) by driving `ansible.builtin.raw` directly and bypassing AnsiballZ entirely. It supplies its own write-temp/validate/move helper to replace module `validate:` clauses, and its own changed/unchanged sentinel contract to preserve this suite's idempotence guarantee despite `raw` always reporting `changed: true`. Covers `roles/common` + `roles/security`; excludes `roles/docker_engine`. Implemented (ADR-0005, #28): the write-temp/validate/move helper and sentinel contract (`filter_plugins/raw_provisioning.py`), automatic path detection from `/etc/redhat-release` (`raw_classify_os_path`, `playbooks/common/detect_raw_path.yml`; an explicit inventory `raw_provisioning_path` overrides it) and fact bypass via raw parsing (`raw_parse_os_release`), and raw equivalents for every module-based task of `common` and `security` — shared tasks (sysctl, accounts, sudoers, SSH keys, limits, fail2ban, auditd), the CentOS 6-only iptables pair (`SEC-008`/`SEC-021`) and ntpd (`COMMON-010`), and the CentOS 7 firewalld block (`SEC-042`~`SEC-050`). raw tasks are skipped under `--check` (ADR-0005 Option A), so a dry run never changes the target. Host Agents (ADR-0006) extend this path with a minimal helper subset (`roles/monitoring/tasks/raw_upload.yml`, #46): scp binary upload verified against the pinned sha256, plus check-mode read-only probes and diff output; the per-agent legacy tasks are not yet implemented.
_Avoid_: raw fallback, raw mode, raw provisioning (imprecise — always the full canonical name)

**Host Agents**:
The pair of agents — `otelcol-contrib` (logs + hostmetrics shipped to OpenObserve) and `resticprofile`/`restic` (backups shipped to RustFS over the S3 API) — that are installed together on every host in the `servers` group, except a Host Agents Backup Only host, which gets the backup agent alone. Collection and backup targets follow the ISMS (not ISMS-P) standard. Their standard configuration is held in Git; per-host overrides and secrets come from OpenBao. Designed in ADR-0006; not yet implemented.
_Avoid_: monitoring agent, backup agent (when meaning the pair), sidecar

**Host Agents Exclusion**:
Membership of a `servers` host in the inventory group `host_agents_excluded`, meaning Host Agents are not (yet) applied to it. Deploy, Config and Repo Maintenance all leave such a host out, so the exclusion lives in one place instead of per-template Limits or `target_hosts`. Removing the host from the group is how it is brought under Host Agents. Defined in ADR-0006 §2.1.
_Avoid_: skip list, Limit (for this purpose)

**Host Agents Backup Only**:
Membership of a `servers` host in the inventory group `host_agents_backup_only`, meaning it gets only the backup agent (`resticprofile`/`restic`) and no `otelcol-contrib`, because its logs are collected by a separate system. Deploy, Config, Backup and Repo Maintenance still include it; every otelcol step is skipped and the per-host ingestion token is not required. Its daily backup results are not shipped to OpenObserve. Defined in ADR-0006 §2.1 (2026-10-12 amendment).
_Avoid_: partial exclusion, otel exclusion

**FUNA Cluster**:
The three `servers` hosts ns0325, ns0327 and ns0338 that together serve the FUNA API behind a shared VIP, each running the app plus the cluster infrastructure (Caddy, keepalived, Valkey) that is installed and configured by hand. ns0270 is not part of it, although older documents group it with these hosts as the "API cluster".
_Avoid_: API cluster, API servers, funa nodes (when ns0270 might be included)

**Resource Attribute**:
A key/value stamped once per host (or per log source) on every log and metric that Host Agents ship — OTel semantic-convention names such as `host.name`, `host.id`, `host.ip`, `host.arch`, `os.name`, `os.version`, `deployment.environment.name` and `service.name`. OpenObserve turns them into stream fields (logs) and series labels (metrics). The values come from the Remote OS Probe and the inventory, not from a collector-side detector. `deployment.environment.name` is declared per host (never defaulted); `host.id` and `host.ip` are left out when the host has none, and the run summary names those hosts. Defined in ADR-0006 §2.3.
_Avoid_: label, tag, metadata (imprecise — they differ per signal in OTel)

**Business Telemetry**:
The traces and metrics that an application and its edge proxy produce while serving a business request: one that an external client sends to a business API path. A trace that starts at such a request keeps every span beneath it, database queries and message-broker calls included. Traffic that serves operation instead of the business is noise and is not collected: health and management endpoints, monitoring probes, API documentation, scheduled and internal polling work, and requests to hosts the service does not serve. Runtime metrics of the application process (memory, threads, garbage collection) count as Business Telemetry, because a slow business request is diagnosed with them.
_Avoid_: app metrics, APM data, observability data (when the noise is meant to be excluded)

**Host Audit**:
A read-only, periodic inspection of managed hosts and produces one consolidated report per run — an overall summary followed by a per-host appendix and then a per-item appendix explaining how to fix each Configuration Vulnerability found in that run — covering Asset Inventory, Configuration Drift, Configuration Vulnerabilities and Package Vulnerabilities. It inspects every managed host, including those in Host Agents Exclusion and the CentOS 6/7 hosts, and names the checks a host could not undergo rather than omitting them. Read-only means it leaves every managed state of a host unchanged — configuration files, packages and their caches, repository definitions, services, accounts, kernel settings; the traces of logging in and using privilege (authentication, sudo and audit logs, login records) and temporary files created and removed within the same run are allowed. Fixing what it finds belongs to provisioning and maintenance, not to it.
_Avoid_: audit (when meaning only the CIS audit), scan, compliance check

**Asset Inventory**:
The per-host record of what a host is and in what state — identity, OS and its end-of-life status, hardware, installed packages, listening ports, accounts and who holds privilege. Part of it is collected from the host; the rest — purpose, owning department, owner and administrator (by role, never by name) and asset importance — cannot be, so it is copied per host into OpenBao from the ISMS asset ledger, which stays the source. A host with a value missing is shown as unassigned there; a host whose values could not be read is shown as lookup-failed, never as unassigned. The asset list that ISMS control 1.2.1 (asset identification) asks for; produced by Host Audit, not kept in a separate CMDB product. Covers only the hosts Host Audit inspects, not network devices.
_Avoid_: CMDB, operational info, server list

**Asset Importance**:
How much a host matters to the business, as the ISMS asset ledger rates it — H, M or L, written as the ledger writes it. A rating of the host, not of a finding: how dangerous a Configuration Vulnerability is belongs to the item's severity from the KISA guide (상/중/하), never to Asset Importance.
_Avoid_: security grade, 보안등급, 중요도 (unqualified)

**Asset**:
A piece of equipment or system listed in the ISMS asset ledger under a management number (written lowercase, `nsXXXX`) — a server, switch, firewall, NAS or database instance. The thing itself; what Host Audit collects about it is its Asset Inventory.
_Avoid_: host (when the thing may not be a server), device, node

**Endpoint**:
One way to reach an Asset: an address, a port, a protocol (SSH, Telnet, HTTPS, a database protocol) and the Credential used by default. It may reach the Asset through another Asset's Endpoint, and that hop may itself go through another. An Asset can have several, and each job picks the one it needs. Whether the far end speaks a shell or a network device CLI is a property of the Asset, not of the Endpoint.
_Avoid_: connection info, target, bastion address (a hop is always another Asset's Endpoint)

**Credential**:
One set of secrets for reaching an Asset or a Service, whose `type` names the shape of the secret — a password, an SSH key, an API token — not the channel it is used over; the same account password serves both login and privilege escalation. Who owns it follows how it is issued: a secret issued to one Asset alone (its own ingest token, its own DNS provider token) belongs to that Asset even when it opens a Service; a secret several jobs share belongs to the Service it opens. It never belongs to the job that uses it.
_Avoid_: account (when the secret is meant), login, user entry

**Automation Identity**:
The identity the automation itself presents when it connects — an SSH key pair whose public half is installed on many Assets. An Endpoint says whether logging in through it uses this identity (then the Credential supplies only the account name and the escalation password). It opens nothing on its own, so it is not a Credential of any Asset and not an Operator's personal key.
_Avoid_: admin key, deploy key (unqualified), the operator's key

**Service**:
A shared system that several jobs talk to — OpenObserve, RustFS, GitHub, the alert platform, the FUNA Cluster, Semaphore — whose address is kept once and whose shared Credentials are split by privilege level (`admin`, `ingest`, …), named for what the privilege allows, never for the job that uses it. A system the jobs reach without any secret (the mail relay) is not kept as a Service.
_Avoid_: agent (for these shared systems), global secret

**Operator**:
A person who operates the infrastructure, holding personal SSH public keys and revoked keys. Not an account on an Asset.
_Avoid_: admin user, user (when the person is meant)

**Configuration Vulnerability**:
A host setting that falls short of the KISA technical vulnerability checklist for Unix servers, 2026 edition — e.g. remote root login allowed, weak password policy. Each finding is named with its edition (`KISA-2026:U-13`), because the editions reuse item numbers for different checks; CIS Benchmark is cited only as a cross-reference, not checked separately.
_Avoid_: vulnerability (unqualified), misconfiguration

**Remediation Impact**:
How much fixing a Configuration Vulnerability disturbs the service running on the host — a restart, dropped sessions, a client that stops connecting. Set once per checklist item, the same for every host; how dangerous the finding itself is belongs to the item's severity from the KISA guide (상/중/하), not to Remediation Impact.
_Avoid_: impact, 영향도 (unqualified)

**Remediation Effort**:
How hard a Configuration Vulnerability is to fix — one setting changed versus a package replaced, a structure rebuilt or another team consulted. Set once per checklist item, the same for every host. The "환경성" column of the implementation plan.
_Avoid_: difficulty, 환경성 (outside the plan's column name)

**Remediation Plan**:
The per-host workbook a Host Audit run hands to the people who fix things: one row for each checklist item that is not 양호 on that host, carrying its verdict and evidence, how it is checked, how to fix it on that host's OS family, and its severity, Remediation Impact and Remediation Effort with the priority and urgency derived from them. One per host per run, plus one combined "total" workbook that carries every host's rows in one sheet, all kept with the run's report; the owner column carries the Asset Inventory administrator's role exactly as the Asset Inventory shows it (including unassigned and lookup-failed), and the columns for the plan and what came of it are left for people to fill. The "이행계획서" of the implementation plan.
_Avoid_: xlsx report, 조치계획서, action plan

**Package Vulnerability**:
An installed package version that is affected by a known CVE or vendor security advisory.
_Avoid_: vulnerability (unqualified), CVE (when meaning the finding on a host)

**Configuration Drift**:
A difference between the state a host is declared to have in Git (provisioning and Host Agents configuration) and the state it actually has — a change made outside the change process. Reported per host as the declared tasks that would change. A difference from the previous Host Audit is not Configuration Drift but a change since the last audit. Not detectable on Raw Provisioning Path hosts, which Host Audit reports as such.
_Avoid_: drift (unqualified), config change, diff

**Audit Baseline**:
The previous scheduled Host Audit run, against which the current run marks each finding as new, resolved, recurring or persisting and each Asset Inventory change (new account, port, privileged user). An on-demand run is kept but never becomes the baseline. A finding is recurring when a scheduled run in the past twelve months had marked it resolved.
_Avoid_: previous run (when an on-demand run could be meant), last audit, snapshot

**Log Review**:
The monthly review by a person of one calendar month of the logs held centrally in OpenObserve — those of the hosts Host Audit inspects and of the network and security devices and services whose logs are collected there — item by item against the log review items of the company's log and security-policy review ledger, ending in a Log Review Report that the CISO approves by signature. Every such host is reviewed each month, which is more often than the company guideline asks of hosts other than personal information processing systems; those systems are marked separately because the company guideline sets their review at monthly to meet the legal duty to review access records on a cycle the company itself sets. Logs that are not collected centrally are outside it, and the report names them and the review items they leave unchecked. Figures and threshold breaches are drafted automatically, but the verdict, the reviewer's remarks and the actions taken are the reviewer's; a draft no person has completed is not a Log Review.
_Avoid_: 로그 점검, log audit, 감사 (Host Audit and Audit Watch Key already use "audit")

**Log Review Report**:
The record of one calendar month's Log Review, Security Policy Review and state of log management (collection gaps, retention, time synchronisation): the period and hosts reviewed, each review item with how it was checked, what was found and the verdict — an item that could not be checked is named as such with the reason, never dropped or marked not applicable — the actions taken, and the signatures with dates of the reviewer, the information security manager and the CISO. A signed copy is kept beside it, and the next month's report says whether it was. Sent as a separate attachment in the same mail as a Host Audit report, but not part of that report.
_Avoid_: 로그 점검 보고서, log audit report

**Security Policy Review**:
The periodic review of whether the policies set on a security system (the firewalls) are still appropriate — rules unused for a long time, left behind by a departure or a role change, kept from a test, allowing too much, past their period, duplicated, or naming addresses no longer in use — against the security-policy items of the same company ledger. It reads the policies themselves, not logs, so it is not part of Log Review, although its result travels in the same Log Review Report under the same signatures.
_Avoid_: firewall audit, 정책 점검 (unqualified), rule cleanup (that is the fix, not the review)

**Log Type**:
The routing key (`log_type`: `security_logs`, `system_logs`, `app_logs`, `backup_logs`) that decides which OpenObserve stream, and so which retention, a log record goes to. Not a service name: `service.name` says which file group or daemon produced the record and is what operators filter on; one Log Type holds several service names.
_Avoid_: log category, stream tag

**Audit Watch Key**:
The label the kernel audit system attaches to every record of a change it was told to watch (`identity`, `sudo_config`, `sshd_config`, `auth_config`, `secret_access`, …). Records are collected per key into `security_logs`, but whether a key raises an alert is decided per key: some keys are evidence only. Unrelated to Host Audit and Audit Baseline, which are the periodic read-only inspection.
_Avoid_: audit key (ambiguous with Host Audit), watch rule (the rule is how a key is produced, not the key), 감시 키

**Envelope Parsing**:
Lifting the fields that a log source's fixed format defines (event time, emitting program, pid, severity where the format carries one) out of a log line into structured fields, at the collector, without touching the original line. The original line stays the record's body and is the evidence; parsed fields sit beside it. Interpreting what a message *means* (who logged in, from which address, OCSF normalisation) is not Envelope Parsing and is done centrally in OpenObserve.
_Avoid_: log parsing (when meaning only this edge layer), normalisation, structuring

**Silent Host**:
A host that the inventory says should be shipping to OpenObserve (a `servers` host with Host Agents applied, neither a Host Agents Exclusion nor Host Agents Backup Only) but from which no logs or metrics have arrived for a set time. It says nothing about whether the server itself is up: a running server whose collector has died is a Silent Host, and a server that is down is one too until another tool tells them apart.
_Avoid_: host down, dead host, offline host (they imply the server itself is down)

**Unreachable Host**:
A `servers` host whose SSH port the central prober on the Semaphore host cannot connect to. It says the server or the network path to it is down, not that its collector stopped; a host that is reachable but sends nothing is a Silent Host instead. Applies to every `servers` host, including Host Agents Backup Only hosts that ship nothing to OpenObserve.
_Avoid_: host down, dead host (when the prober has not actually failed to connect)

**Watched Port**:
A network switch port whose description marks it as `Core:` or `Transit:` (switch-to-switch links and links out of the site). Only a Watched Port going down is an incident; any other port being down is normal (unused, reserved, or a server link that Unreachable Host already covers). A port is watched by labelling it on the switch, not by listing it in alert configuration.
_Avoid_: uplink, important port, monitored port (every port is polled; only Watched Ports alert)

**Event Alert**:
An alert where each matching log line is itself the incident (a root login, a burst of SSH failures, a kernel I/O error). Once the moment passes there is nothing left to fix, so it is notified once per occurrence window and not repeated.
_Avoid_: instant alert, log alert

**State Alert**:
An alert on a condition that persists until someone fixes it (a disk nearly full, a Silent Host, a missing backup). It keeps firing while the condition holds, so it is re-notified at an interval set by its severity rather than every evaluation. Its going quiet is the only sign of recovery.
_Avoid_: threshold alert, metric alert (a log-based alert can be a State Alert too)

**Audit Watch Key**:
The name an audit rule attaches to every record it produces, saying what was being watched (identity files, sudo configuration, secret files) rather than which file or system call fired. Alerts and investigations select records by this name, so one meaning can cover many paths and the paths can change without the alert changing. It only exists on hosts whose audit rules are provisioned.
_Avoid_: audit key, audit tag, audit rule (the rule is what produces records; the key is what they are called)

**Evidence-Only Watch Key**:
An Audit Watch Key that deliberately has no alert. Its records arise during ordinary work (privileged commands, file deletions, mounts), so alerting on them would only add noise, yet they are kept for after-the-fact investigation and as evidence that the control exists. Making one alert later is a new decision, not a fix.
_Avoid_: unused key, silent key

**Fast Scenario**:
The molecule scenario run by the CI `molecule` job (formerly at pre-push). Exercises the roles that need no external network (`common`, `security`, `access_security`) on the Representative Platform, including the idempotence check; widens to every platform in one run when `roles/security` or `roles/common` changed. `common` is always applied first as the Base Layer; the other roles can be selected individually.
_Avoid_: default scenario, quick test, smoke test

**Slow Scenario**:
The molecule scenario covering roles that depend on external networks (`docker_engine`, `monitoring`). Runs real installs, never at pre-push; run manually or from CI.
_Avoid_: network scenario, integration scenario

**Full Matrix**:
Every scenario on every supported platform (Rocky 8, Rocky 9, Ubuntu 22.04). The only run that verifies OS-family branches the Representative Platform does not cover. Run on demand and before a release, not at pre-push.
_Avoid_: full test, all-OS run

**Representative Platform**:
The platform (Rocky 9) that the Fast Scenario runs on in CI unless a change warrants the wider run, standing in for the Full Matrix.
_Avoid_: primary OS, default platform

**Base Layer**:
The `common` role, applied before any other role in a scenario because other roles (e.g. `access_security`) depend on the accounts it creates. Mirrors the production apply order.
_Avoid_: prerequisite role, seed

**Test Image**:
A derived container image with per-run preparation (SSH server, host keys, Python interpreter) already baked in, so a scenario spends no time on it. Rebuilt only when its definition changes.
_Avoid_: base image, custom image
