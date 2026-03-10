# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.11] - 2026-03-10

### Removed
- **BREAKING:** NTLM authentication support has been completely removed.
  The `github.com/Azure/go-ntlmssp` dependency is no longer used.
- `ntlm_certsrv.go` removed; replaced by `basic_certsrv.go`.

### Changed
- **BREAKING:** Default `authMode` changed from `"ntlm"` to `"basic"`.
  Existing deployments using the default (NTLM) must explicitly set `authMode: "basic"`
  or will automatically use Basic Auth after upgrade.
- Renamed `NtlmCertsrv` → `BasicCertsrv`, `NewNtlmCertsrv` → `NewBasicCertsrv`.
- Only two authentication modes remain: `"basic"` (default) and `"kerberos"`.
- Updated Helm chart `values.yaml`: default `authMode` is now `"basic"`.
- Updated README with two-mode authentication documentation.

## [1.0.10] - 2026-03-10

### Added
- Kerberos (SPNEGO) authentication support via `authMode: "kerberos"` in issuer spec.
  Uses `github.com/jcmturner/gokrb5/v8` library for Kerberos ticket acquisition.
- New `realm` field support in credentials secret (required for Kerberos mode).
- Helm chart: `kerberos.enabled` and `kerberos.krb5ConfigMapName` values for
  mounting `/etc/krb5.conf` via ConfigMap.

### Changed
- `getUserPassword` now supports returning `realm` from credentials secret.
- Authentication mode selection uses `switch` for cleaner Basic/Kerberos routing.
- Updated README with authentication documentation and Kerberos examples.

## [1.0.9] - 2026-03-09

### Added
- Resolve `cert-manager.io/cert-template` annotation from Ingress owner chain
  (Ingress → Certificate → CertificateRequest) so ingress-shim users don't need
  to create Certificate resources manually.
- RBAC permissions for `certificates` (cert-manager.io) and `ingresses` (networking.k8s.io).

## [1.0.8] - 2026-03-08

### Fixed
- Upgrade Go from 1.25.0 to 1.26.1 to resolve 20 stdlib CVEs
  (1 Critical, 6 High, 10 Medium, 3 Low).

### Added
- SLSA provenance and SBOM attestation on release Docker images.

### Changed
- golangci-lint CI: use `goinstall` mode and 5m timeout for Go 1.26.1 compatibility.
- Fix all lint warnings: errcheck, gosimple (S1008, S1023, S1024, S1035),
  unused fields, tautological conditions.

## [1.0.7] - 2026-03-07

### Fixed
- CA certificate now returned as X.509 PEM instead of PKCS#7, fixing
  nginx-ingress serving a fake certificate.
- RBAC: added `create` and `patch` verbs for `events` resource to allow
  cross-namespace event recording.

## [1.0.6] - 2026-03-06

### Fixed
- Duplicate certificate requests: added guard to skip CertificateRequest
  that already has certificate data (`status.certificate` not empty).
- SetStatus error handling with retry on conflict.

## [1.0.5] - 2026-03-05

### Fixed
- Early return for Rejected/Errored ADCS requests to prevent unnecessary
  reprocessing.

## [1.0.4] - 2026-03-04

### Added
- Annotation-based ADCS template selection via `cert-manager.io/cert-template`
  on Certificate or CertificateRequest resources.

## [1.0.3] - 2026-03-03

### Fixed
- HTTP redirect no longer strips Authorization header (broken Basic Auth on
  ADCS servers with redirect rules).
- Double-slash URL bug fixed (`TrimRight` on base URL).

## [1.0.2] - 2026-03-02

### Added
- Basic Authentication support via `authMode: basic` on AdcsIssuer/ClusterAdcsIssuer.
- NTLM remains the default authentication mode.

## [1.0.1] - 2026-03-01

### Added
- Initial fork from [djkormo/adcs-issuer](https://github.com/djkormo/adcs-issuer).
- Helm chart with comprehensive `values.yaml`.
- CI/CD workflows (lint, test, build, release).
- Community files: README, CONTRIBUTING.md, SECURITY.md, LICENSE.

[1.0.9]: https://github.com/lcwsre/adcs-issuer/compare/v1.0.8...v1.0.9
[1.0.8]: https://github.com/lcwsre/adcs-issuer/compare/v1.0.7...v1.0.8
[1.0.7]: https://github.com/lcwsre/adcs-issuer/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/lcwsre/adcs-issuer/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/lcwsre/adcs-issuer/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/lcwsre/adcs-issuer/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/lcwsre/adcs-issuer/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/lcwsre/adcs-issuer/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/lcwsre/adcs-issuer/releases/tag/v1.0.1
