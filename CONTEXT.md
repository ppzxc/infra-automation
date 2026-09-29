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

**Raw Provisioning Path**:
A design for provisioning CentOS 6/7 targets (which lack a Python 3.7+ interpreter, so ansible-core's AnsiballZ module wrapper SyntaxErrors on every standard module call) by driving `ansible.builtin.raw` directly and bypassing AnsiballZ entirely. It supplies its own write-temp/validate/move helper to replace module `validate:` clauses, and its own changed/unchanged sentinel contract to preserve this suite's idempotence guarantee despite `raw` always reporting `changed: true`. Covers `roles/common` + `roles/security`; excludes `roles/docker_engine`. Partially implemented: the write-temp/validate/move helper and sentinel contract (`filter_plugins/raw_provisioning.py`) exist with `SEC-001` as the first consumer; the remaining tasks are tracked separately from the standard AnsiballZ-based provisioning this suite otherwise uses.
_Avoid_: raw fallback, raw mode, raw provisioning (imprecise — always the full canonical name)

**Host Agents**:
The pair of agents — `otelcol-contrib` (logs + hostmetrics shipped to OpenObserve) and `resticprofile`/`restic` (backups shipped to RustFS over the S3 API) — that are always installed together, never one without the other, on every host in the `servers` group. Collection and backup targets follow the ISMS (not ISMS-P) standard. Their standard configuration is held in Git; per-host overrides and secrets come from OpenBao. Designed in ADR-0006; not yet implemented.
_Avoid_: monitoring agent, backup agent (when meaning the pair), sidecar

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
