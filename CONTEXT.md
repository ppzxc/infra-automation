# Node Provisioner Domain Context

## 1. Overview
**`node-provisioner`** is an idempotent Ansible automation suite executed by **Semaphore UI** (within the `overseer` Central Control Plane) to migrate, provision, harden, and onboard on-premise IDC target hosts across multiple Linux generations (CentOS 6 legacy to Rocky Linux 10, Ubuntu/Debian).

## 2. System Boundaries & Relationship
- **Central Control Plane (`../overseer`)**: Hosts OpenBao (SSH CA & Secrets), HashiCorp Boundary (Zero-Trust Session Proxy), PostgreSQL, and Semaphore UI (GitOps orchestrator).
- **Target Node Provisioner (`node-provisioner`)**: Manages the managed hosts (`servers`, `loadbalancers`). It connects nodes to the Control Plane by configuring SSH CA trust, Boundary Target metadata, and OpenTelemetry OTLP hostmetric/log pipelines.

## 3. Core Roles & Modules
- **`access_security`**: Deep module unifying Zero-Trust access control (OpenBao SSH CA public key injection, AuthorizedPrincipals mapping, Boundary Worker metadata generation, and CentOS 6 fallback authentication).
- **`security`**: Host-level OS hardening (SSH parameters, Auditd rules, Fail2ban, SELinux permissive mode, sudo logging, firewalld-docker CLI).
- **`docker_engine`**: Automated cleanup of conflicting packages (Podman) and deployment of hardened Docker CE and compose plugins.
- **`monitoring`**: OpenTelemetry Collector Contrib (`otelcol-contrib`) deployment sending hostmetrics and system logs to the central OpenObserve backend, replacing legacy `node_exporter`.
- **`common`**: Baseline OS packages, timezone, Chrony/NTP time synchronization, sysctl kernel parameters, and admin accounts.
