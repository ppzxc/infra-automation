# Research: OpenObserve OTLP ingestion contract and RustFS S3 compatibility for restic

- Ticket: [#10](https://github.com/ppzxc/infra-automation/issues/10) (map [#8](https://github.com/ppzxc/infra-automation/issues/8))
- Date: 2026-09-28
- Versions checked: OpenObserve **v1.0.4** (latest release), RustFS **1.0.0** (latest stable; 1.0.1-preview.* are prereleases), restic **v0.19.1** (latest release), otelcol-contrib as pinned in `roles/monitoring/defaults/main.yml` (0.108.0).
- Source trust: official docs and source code at the release tags listed. Anything taken from `main` is marked as such.

## TL;DR: minimal per-host connection contract

### otelcol-contrib → OpenObserve

| Item | Value | Source |
|---|---|---|
| Protocol (recommended) | OTLP/HTTP via the `otlphttp` exporter. It works through proxies, and the org goes in the URL path | [O2 OTLP logs doc][o2-otlp] |
| HTTP endpoint | `http(s)://<o2-host>:5080/api/<org>`, **with no trailing slash**. The exporter appends `/v1/logs`, `/v1/metrics`, `/v1/traces`. A trailing `/` returns 404 | [O2 OTLP logs doc][o2-otlp]; routes `/{org_id}/v1/{logs,metrics,traces}` in [router v1.0.4][o2-router] |
| HTTP port | `5080` (`ZO_HTTP_PORT`) | [O2 env vars][o2-env] |
| gRPC endpoint (alternative) | `<o2-host>:5081` (`ZO_GRPC_PORT`, default 5081). Needs HTTP/2 end to end | [config.rs v1.0.4][o2-config] |
| Auth header | `Authorization: Basic base64(<user>:<secret>)`. For both protocols the secret is either (a) a user/service-account email + password, or (b) an **org ingestion token**: username = org identifier, password = the token (prefix `o2oi_`). Ingestion tokens work **only** on ingestion endpoints, including the OTLP gRPC services | [ingestion tokens doc][o2-ingest-token]; [grpc auth v1.0.4][o2-grpc-auth] (`check_otlp_auth` → `allow_org_ingestion_token = true`) |
| `organization` header | **Required for gRPC**, and the value is the org id. The gRPC handlers reject requests without it. HTTP doesn't use it (the org is in the path). Key name comes from `ZO_GRPC_ORG_HEADER_KEY`, default `organization` | [config.rs v1.0.4][o2-config]; [grpc metrics ingester][o2-grpc-metrics] |
| `stream-name` header | Optional. Selects the **logs** (and traces) stream. Default is `default` when omitted. Key name comes from `ZO_GRPC_STREAM_HEADER_KEY`, default `stream-name`. The HTTP handler reads the same key | [config.rs v1.0.4][o2-config]; [core/logs/otlp.rs v1.0.4][o2-logs-otlp] (`unwrap_or("default")`); [http logs ingest v1.0.4][o2-http-logs] |
| Metrics → streams | `stream-name` **does not apply to metrics**. Every OTLP metric name becomes its own metrics stream (`format_stream_name(metric.name)`, stored as `{org}/metrics/{metric_name}`). hostmetrics therefore creates about 30+ streams named like `system_cpu_time` | [core/metrics/otlp.rs][o2-metrics-otlp] (read on `main`) |
| Content type | `application/x-protobuf` (the default for `otlphttp`) or `application/json` | [http logs ingest v1.0.4][o2-http-logs] |
| Compression | gzip is fine. gRPC OTLP services `accept_compressed(Gzip)` and `Zstd`. HTTP uses tower-http `RequestDecompressionLayer` (gzip/deflate/br) plus a snappy shim. The otelcol default (gzip) works as-is | [grpc server.rs v1.0.4][o2-grpc-server]; [router v1.0.4][o2-router] |
| gRPC max message | 32 MiB (`ZO_GRPC_MAX_MESSAGE_SIZE`, default 32 in config.rs; the docs page says 16). The otelcol `batch` of 1024 is far below either | [config.rs v1.0.4][o2-config] |
| TLS | Plaintext is O2's default. `ZO_HTTP_TLS_ENABLED` and `ZO_GRPC_TLS_ENABLED` both default to `false`. If TLS is on (in O2 or at a reverse proxy), the agent needs `tls.ca_file` for a private CA. The docs don't cover client-side CA handling beyond `tls.insecure` | [config.rs v1.0.4][o2-config]; [O2 OTLP logs doc][o2-otlp] |

Per-host inputs this implies, all from OpenBao or group_vars:
`o2_endpoint` (scheme+host+port), `o2_org`, `o2_logs_stream`, `o2_auth_user` + `o2_auth_secret` (ingestion token preferred), and an optional `o2_ca_file`.

Minimal exporter (HTTP):

```yaml
exporters:
  otlphttp/openobserve:
    endpoint: "https://<o2-host>:5080/api/<org>"   # no trailing slash
    headers:
      Authorization: "Basic <base64(org:o2oi_...)>"
      stream-name: "<logs-stream>"                  # logs/traces only
    tls:
      ca_file: /etc/otelcol/ca.pem                  # only if a private CA
```

gRPC equivalent: `otlp/openobserve` with `endpoint: <o2-host>:5081` and headers `Authorization`, `organization: <org>`, `stream-name: <stream>`.

**Gap against the current template** (`roles/monitoring/templates/otelcol-contrib.yaml.j2`):
- It uses the gRPC `otlp/backend` exporter with `otel_target_headers: {}` by default. That sends **no `organization` header**, so OpenObserve's gRPC handler rejects every request. Either make `organization` mandatory in the contract or switch to `otlphttp` (org in the path).
- `otel_target_insecure: true` is the default. That's acceptable only while O2 runs plaintext on a trusted network.
- A single exporter carries the same `stream-name` for both logs and metrics. That's harmless, because metrics ignore it, but it can't split logs into several streams (for example `syslog` vs `audit`). Splitting would need several exporters or per-pipeline exporters.

### restic (resticprofile) → RustFS

| Item | Value | Source |
|---|---|---|
| Repository URL | `s3:https://<rustfs-host>:9000/<bucket>[/<prefix>]`. The `s3:http(s)://` form takes the host as the endpoint and the first path segment as the bucket | [restic S3 doc][restic-s3]; [s3/config.go][restic-s3-config] |
| RustFS S3 port | `9000` (`DEFAULT_PORT`, `DEFAULT_ADDRESS=":9000"`) | [RustFS app.rs 1.0.0][rustfs-app] |
| Credentials | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | [restic S3 doc][restic-s3] |
| Repo password | `RESTIC_PASSWORD_FILE` (preferred, a `0600` file) or `RESTIC_PASSWORD` | [restic manual][restic-manual] (`--password-file`, default `$RESTIC_PASSWORD_FILE`) |
| Region | `AWS_DEFAULT_REGION` or `-o s3.region=`. **Must match the server's `RUSTFS_REGION`, default `us-east-1`.** restic defaults to `us-east-1` when unset, so it works out of the box unless the server region was changed. A mismatched region breaks SigV4 signing | [s3/config.go][restic-s3-config] (`ApplyEnvironment`); [RustFS app.rs 1.0.0][rustfs-app] (`RUSTFS_REGION="us-east-1"`, env `RUSTFS_REGION`) |
| Addressing | Path-style. restic's default `s3.bucket-lookup=auto` uses minio-go's detection, which picks virtual-host only for AWS/GCS/Aliyun endpoints, so a RustFS host already gets path-style. **Set `-o s3.bucket-lookup=path` explicitly** anyway so DNS or wildcard-cert changes can't flip it. Virtual-host support in RustFS was not verified | [s3/config.go][restic-s3-config]; [minio-go `IsVirtualHostSupported`][minio-go-utils] |
| TLS / private CA | `--cacert <file>` or `RESTIC_CACERT`. Don't use `--insecure-tls` in production. RustFS serves TLS when `RUSTFS_TLS_PATH` points at a dir containing `rustfs_cert.pem` / `rustfs_key.pem` (off by default) | [restic manual v0.19.1][restic-manual]; [RustFS app.rs 1.0.0][rustfs-app]; [RustFS certs README][rustfs-certs] |
| Concurrency | `-o s3.connections=` (default 5) | [s3/config.go][restic-s3-config] |
| Bucket | `restic init` calls `BucketExists` and, if the bucket is missing, `MakeBucket`. In this design the server side pre-creates the bucket, so the key only needs object R/W/List/Delete on its bucket (plus `BucketExists`/HEAD) | [s3/s3.go][restic-s3-go] |

Per-host inputs: `restic_repository` (URL incl. bucket/prefix), `aws_access_key_id`, `aws_secret_access_key`, `restic_password`, optional `restic_cacert`, `s3_region` (default `us-east-1`).

Minimal environment:

```sh
RESTIC_REPOSITORY=s3:https://<rustfs-host>:9000/<bucket>/<hostname>
AWS_ACCESS_KEY_ID=...            # from OpenBao
AWS_SECRET_ACCESS_KEY=...        # from OpenBao
AWS_DEFAULT_REGION=us-east-1     # == RUSTFS_REGION
RESTIC_PASSWORD_FILE=/etc/restic/password   # 0600
RESTIC_CACERT=/etc/restic/ca.pem            # only if private CA
# plus: -o s3.bucket-lookup=path
```

## Pitfalls and operational constraints

1. **Truncated listings on RustFS ([rustfs#2916][rustfs-2916]).** Recursive `ListObjects` could end early *without an error* on cold cache or slow disks. restic then sees an incomplete pack list, which can lead to a corrupted repository, and `prune` makes that destructive. The cold-cache case was fixed in May 2026 (before 1.0.0). The reporter still saw truncation on a **versioned bucket with delete markers** and said they would open a separate ticket. No follow-up was found. Constraints:
   - require RustFS ≥ 1.0.0;
   - the restic bucket **must not have versioning enabled**;
   - run `restic check` periodically, and before any `prune`.
2. **Range-read errors ([rustfs#2670][rustfs-2670]).** Restic spot-check restores got `file size is less than offset + length` on ranged GETs. Closed 2026-04-24, before 1.0.0. That's more reason to require ≥ 1.0.0 and to include periodic `restic check --read-data-subset` in the ISMS restore test.
3. **Object Lock / WORM is incompatible with plain restic.** restic has to delete lock files and pruned packs. There's no append-only mode against S3 (open upstream: [restic#3195][restic-3195], [restic#5041][restic-5041]). Don't enable Object Lock on the restic bucket. Ransomware protection needs a different mechanism, for example server-side replication or snapshots, which is out of scope.
4. **Don't copy restic repos into RustFS with filesystem-level tools.** Syncing a filesystem copy into RustFS left restic unable to read the repo. Copying S3→S3 works. Only ever write through the S3 API ([rustfs#1507][rustfs-1507]).
5. **OpenObserve metric stream explosion.** One stream per metric name. Choose scrapers deliberately, because `stream-name` can't consolidate them.
6. **OTLP HTTP endpoint trailing slash.** Returns 404 ([O2 doc][o2-otlp]).
7. **gRPC without `organization`.** Rejected. This is the current template default (see the gap above).
8. **Ingestion token vs user password.** Prefer an org ingestion token (`o2oi_…`, username = org id). It can't be used against query or admin APIs, which limits the damage if a host is compromised ([ingestion tokens doc][o2-ingest-token]). In OSS, service accounts have full access by default ([RBAC doc][o2-rbac]), so a service-account token is a worse per-host secret.

## Input for the compatibility-matrix ticket (not a finding here)

restic v0.19.1 is built with Go 1.25 (`go.mod`: `go 1.25.8`). Since Go 1.24, Linux binaries need **kernel ≥ 3.2** ([Go 1.24 release notes][go124]). CentOS 6 runs 2.6.32, so current upstream restic binaries likely won't run there. Check the current otelcol-contrib toolchain too.

## Sources

[o2-otlp]: https://openobserve.ai/docs/ingestion/logs/otlp
[o2-env]: https://openobserve.ai/docs/environment-variables/
[o2-ingest-token]: https://openobserve.ai/docs/user-guide/account-administration/identity-and-access-management/ingestion-tokens/
[o2-rbac]: https://openobserve.ai/docs/user-guide/account-administration/identity-and-access-management/role-based-access-control
[o2-config]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/config/src/config.rs
[o2-grpc-auth]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/api/grpc/src/handler/grpc/auth/mod.rs
[o2-grpc-server]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/api/grpc/src/server.rs
[o2-grpc-metrics]: https://github.com/openobserve/openobserve/blob/main/src/api/grpc/src/handler/grpc/request/metrics/ingester.rs
[o2-router]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/api/http/src/handler/http/router/mod.rs
[o2-http-logs]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/api/ingest/src/request/logs/ingest.rs
[o2-logs-otlp]: https://github.com/openobserve/openobserve/blob/v1.0.4/src/core/src/logs/otlp.rs
[o2-metrics-otlp]: https://github.com/openobserve/openobserve/blob/main/src/core/src/metrics/otlp.rs
[rustfs-app]: https://github.com/rustfs/rustfs/blob/1.0.0/crates/config/src/constants/app.rs
[rustfs-certs]: https://github.com/rustfs/rustfs/blob/main/deploy/certs/README.md
[rustfs-2916]: https://github.com/rustfs/rustfs/issues/2916
[rustfs-2670]: https://github.com/rustfs/rustfs/issues/2670
[rustfs-1507]: https://github.com/rustfs/rustfs/issues/1507
[restic-s3]: https://github.com/restic/restic/blob/v0.19.1/doc/030_preparing_a_new_repo.rst
[restic-s3-config]: https://github.com/restic/restic/blob/v0.19.1/internal/backend/s3/config.go
[restic-s3-go]: https://github.com/restic/restic/blob/v0.19.1/internal/backend/s3/s3.go
[restic-manual]: https://github.com/restic/restic/blob/v0.19.1/doc/manual_rest.rst
[restic-3195]: https://github.com/restic/restic/issues/3195
[restic-5041]: https://github.com/restic/restic/issues/5041
[minio-go-utils]: https://github.com/minio/minio-go/blob/master/pkg/s3utils/utils.go
[go124]: https://go.dev/doc/go1.24

- OpenObserve OTLP ingestion (logs): <https://openobserve.ai/docs/ingestion/logs/otlp>
- OpenObserve ingestion tokens: <https://openobserve.ai/docs/user-guide/account-administration/identity-and-access-management/ingestion-tokens/>
- OpenObserve source @ v1.0.4: config.rs, grpc auth/server, http router, logs ingest (links above)
- RustFS constants @ 1.0.0: <https://github.com/rustfs/rustfs/blob/1.0.0/crates/config/src/constants/app.rs>
- RustFS issues #2916, #2670, #1507
- restic @ v0.19.1: S3 docs, `internal/backend/s3/{config,s3}.go`, manual
- minio-go bucket-lookup auto-detection: `pkg/s3utils/utils.go`
- Go 1.24 release notes (kernel ≥ 3.2)
