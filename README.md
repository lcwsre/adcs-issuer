# ADCS Issuer

ADCS Issuer is a [cert-manager's](https://github.com/cert-manager/cert-manager) CertificateRequest controller that uses MS Active Directory Certificate Service to sign certificates 
(see [cert-manager external issuers documentation](https://cert-manager.io/docs/contributing/external-issuers/) for details on external issuers). 

ADCS provides HTTP GUI that can be normally used to request new certificates or see status of existing requests. This implementation is simply a HTTP client that interacts with the
ADCS server sending appropriately prepared HTTP requests and interpretting the server's HTTP responses (the approach inspired by [this Python ADCS client](https://github.com/magnuswatn/certsrv)).
It supports **HTTP Basic** and **Kerberos (SPNEGO)** authentication.

## Description

### Requirements
ADCS Issuer has been tested with cert-manager v1.14+ and supports CertificateRequest CRD API version v1.

## Configuration and usage

### Authentication Modes

ADCS Issuer supports two authentication modes configured via the `authMode` field in the issuer spec:

| Mode | Description | When to use |
|------|-------------|-------------|
| `basic` (default) | HTTP Basic Authentication | Standard mode. Requires Basic Auth enabled on IIS/ADCS certsrv |
| `kerberos` | Kerberos (SPNEGO) authentication | When pods can obtain Kerberos tickets. Requires `/etc/krb5.conf` in the container and a `realm` field in the credentials secret |

### Certificate Template Selection

ADCS certificate templates can be specified per-Certificate using the `cert-manager.io/cert-template` annotation:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-cert
  annotations:
    cert-manager.io/cert-template: "WebServer"
spec:
  # ...
```

If no annotation is specified, the default template `BasicSSLWebServer` is used.

### Issuers
The ADCS service data can be configured in `AdcsIssuer` or `ClusterAdcsIssuer` CRD objects e.g.:
```yaml
apiVersion: adcs.certmanager.lcwsre.io/v1
kind: AdcsIssuer
metadata:
  name: test-adcs
  namespace: <namespace>
spec:
  caBundle: <base64-encoded-ca-certificate>
  credentialsRef:
    name: test-adcs-issuer-credentials
  statusCheckInterval: 6h
  retryInterval: 1h
  url: <adcs-service-url>
  authMode: basic  # "basic" (default) or "kerberos"
```

For cluster-wide usage (recommended for multi-namespace environments):
```yaml
apiVersion: adcs.certmanager.lcwsre.io/v1
kind: ClusterAdcsIssuer
metadata:
  name: test-adcs
spec:
  caBundle: <base64-encoded-ca-certificate>
  credentialsRef:
    name: test-adcs-issuer-credentials
  statusCheckInterval: 6h
  retryInterval: 1h
  url: <adcs-service-url>
  authMode: basic
```

The `caBundle` parameter is BASE64-encoded CA certificate which is used by the ADCS server itself, which may not be the same certificate that will be used to sign your request. Leave empty to use the system CA pool (works for public CAs like GoDaddy, DigiCert, etc.).

The `statusCheckInterval` indicates how often the status of the request should be tested. Typically, it can take a few hours or even days before the certificate is issued.

The `retryInterval` says how long to wait before retrying requests that errored.

The `authMode` specifies the authentication mode: `"basic"` (default) or `"kerberos"`.

The `credentialsRef.name` is name of a secret that stores user credentials used for authentication. The secret must be `Opaque` and contain `password` and `username` fields. For Kerberos mode, a `realm` field is also required:

**Basic secret:**
```yaml
apiVersion: v1
data:
  password: cGFzc3dvcmQ=
  username: dXNlcm5hbWU=
kind: Secret
metadata:
  name: test-adcs-issuer-credentials
  namespace: <namespace>
type: Opaque
```

**Kerberos secret (includes realm):**
```yaml
apiVersion: v1
data:
  password: cGFzc3dvcmQ=
  username: dXNlcm5hbWU=
  realm: RVhBTVBMRS5DT00=   # base64 of "EXAMPLE.COM"
kind: Secret
metadata:
  name: test-adcs-issuer-credentials
  namespace: <namespace>
type: Opaque
```

> **Note:** Kerberos mode requires a valid `/etc/krb5.conf` file mounted in the controller container. You can mount it via a ConfigMap volume in the Helm chart or deployment manifest.

#### IIS/ADCS Server Prerequisites for Kerberos (SPNEGO)

Before using Kerberos authentication, the following **must** be configured on the ADCS/IIS server:

| # | Requirement | Details |
|---|-------------|--------|
| 1 | **Extended Protection MUST be disabled** | The Go `gokrb5` SPNEGO library does **not** support Channel Binding Tokens (CBT). If Extended Protection is set to `Accept` or `Require`, IIS will reject every Kerberos token with `401 Unauthorized` causing an infinite retry loop until timeout. |
| 2 | **Negotiate before NTLM** | Windows Authentication provider order must list `Negotiate` before `NTLM`. |
| 3 | **HTTP SPN registered** | An `HTTP/adcs.example.com` SPN must be registered for the ADCS server computer account. |
| 4 | **Windows Authentication enabled** | Windows Authentication must be enabled on the `certsrv` IIS virtual directory. |
| 5 | **Kernel mode + AppPool credentials** | If `useKernelMode` is `true`, `useAppPoolCredentials` should also be `true` (or the app pool must run as the machine account). |

**PowerShell commands to verify and fix on the ADCS server:**

```powershell
# Check Extended Protection (must be "None")
Get-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication/extendedProtection" `
  -PSPath "IIS:\Sites\Default Web Site\certsrv" -Name "tokenChecking"

# Disable Extended Protection if enabled
Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication/extendedProtection" `
  -PSPath "IIS:\Sites\Default Web Site\certsrv" -Name "tokenChecking" -Value "None"

# Check auth provider order (Negotiate should be first)
Get-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" `
  -PSPath "IIS:\Sites\Default Web Site\certsrv" -Name "providers" | Select-Object -ExpandProperty Collection

# Check kernel mode settings
Get-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" `
  -PSPath "IIS:\Sites\Default Web Site\certsrv" -Name "useKernelMode"
Get-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" `
  -PSPath "IIS:\Sites\Default Web Site\certsrv" -Name "useAppPoolCredentials"

# Register HTTP SPN (run on Domain Controller or with domain admin)
setspn -S HTTP/adcs.example.com ADCSSERVER$

# Restart IIS after changes
iisreset
```

If cluster level issuer configuration is needed then `ClusterAdcsIssuer` can be defined (see above).

The secret used by the `ClusterAdcsIssuer` must be defined in the namespace where controller's pod is running.

### Requesting certificates

To request a certificate with `AdcsIssuer` the standard `certificate.cert-manager.io` object needs to be created. The `issuerRef` must be set to point to `AdcsIssuer` or `ClusterAdcsIssuer` object
from group `adcs.certmanager.lcwsre.io` e.g.:
```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  annotations:
    cert-manager.io/cert-template: "WebServer"
  name: adcs-cert
  namespace: <namespace>
spec:
  commonName: example.com
  dnsNames:
  - service1.example.com
  - service2.example.com
  issuerRef:
    group: adcs.certmanager.lcwsre.io
    kind: ClusterAdcsIssuer
    name: test-adcs
  secretName: adcs-cert
```
Cert-manager is responsible for creating the `Secret` with a key and `CertificateRequest` with proper CSR data.


ADCS Issuer creates `AdcsRequest` CRD object that keep actual state of the processing. Its name is always the same as the corresponding `CertificateRequest` object (there is strict one-to-one mapping).
The `AdcsRequest` object stores the ID of request assigned by the ADCS server as wall as the current status which can be one of:
* **Pending** - the request has been sent to ADCS and is waiting for acceptance (status will be checked periodically),
* **Ready** - the request has been successfully processed and the certificate is ready and stored in secret defined in the original `Certificate` object,
* **Rejected** - the request was rejected by ADCS and will be re-tried unless the `Certificate` is updated,
* **Errored**  - unrecoverable problem occured.

```
apiVersion: adcs.certmanager.lcwsre.io/v1
kind: AdcsRequest
metadata:
  name: adcs-cert-3831834799
  namespace: c1
  ownerReferences:
  - apiVersion: cert-manager.io/v1
    blockOwnerDeletion: true
    controller: true
    kind: CertificateRequest
    name: adcs-cert-3831834799
    uid: f5cf630d-f4cf-11e9-95eb-fa163e038ef8
  uid: f5d22b47-f4cf-11e9-95eb-fa163e038ef8
spec:
  csr: <base64-encoded-csr>
  issuerRef:
    group: adcs.certmanager.lcwsre.io
    kind: AdcsIssuer
    name: test-adcs
status:
  id: "18"
  state: ready
```

#### Auto-request certificate from ingress
Add the following to an `Ingress` for cert-manager to auto-generate a
`Certificate` using `Ingress` information with ingress-shim:
```yaml
metadata:
  name: test-ingress
  annotations:
    cert-manager.io/issuer: "adcs-issuer"           # issuer name
    cert-manager.io/issuer-kind: "ClusterAdcsIssuer" # or AdcsIssuer
    cert-manager.io/issuer-group: "adcs.certmanager.lcwsre.io"
    cert-manager.io/cert-template: "WebServer"  # optional: ADCS template
```
in addition to:
```yaml
spec:
  tls:
    - hosts:
        - test-host.com
      secretName: ingress-secret
```

## Installation

### Helm (Recommended)

```bash
# Install with default values
helm install adcs-issuer charts/adcs-issuer -n adcs-issuer-system --create-namespace

# Install with custom values
helm install adcs-issuer charts/adcs-issuer -n adcs-issuer-system --create-namespace -f my-values.yaml

# Upgrade
helm upgrade adcs-issuer charts/adcs-issuer -n adcs-issuer-system -f my-values.yaml
```

The Helm chart creates all necessary resources including:
- Deployment with the controller
- ClusterRole/ClusterRoleBinding with necessary RBAC permissions
- ServiceAccount
- Webhook configuration and self-signed certificate
- ADCS credentials Secret (optional)
- ClusterAdcsIssuer or AdcsIssuer CR (optional)
- Sample Certificate for testing (optional)

See [values.yaml](charts/adcs-issuer/values.yaml) for all available configuration options.

### Manual (Kustomize)

This controller is implemented using [kubebuilder](https://github.com/kubernetes-sigs/kubebuilder). Automatically generated Makefile contains targets needed for build and installation. 
Generated CRD manifests are stored in `config/crd`. RBAC roles and bindings can be found in `config/rbac`.


### Disable Approval Check

The ADCS Issuer will wait for CertificateRequests to have an [approved condition
set](https://cert-manager.io/docs/concepts/certificaterequest/#approval) before
signing. If using an older version of cert-manager (pre v1.3), you can disable
this check by supplying the command line flag `-enable-approved-check=false` to
the Issuer Deployment.

## Testing considerations

### ADCS Simulator
The test/adcs-sim directory contains a simple ADCS simulator that can be used for basic tests (run `make sim-install` to build it and install in /usr/local directory tree). The simulator can be started on the host and work as ADCS server that will sign certificates using provided self-signed certificate and key (`root.pem` and `root.key` files). If needed the certificate can be replaced with any other available.

The simulator accepts directives to control its behavior. The directives are set as additional domain names in the certificate request:
* **delay.<time>.sim**  where <time> is e.g. 10m, 15h etc - the certificate will be issued after the specified time
* **reject.sim** - the certificate will be rejected
* **unauthorized.sim** - the certificate request will be rejected because of authorization problems (to simulate invalid user permissions)

More then one directive can be used at a time. e.g. to simulate rejecting the certificate after 10 minutes add the following domain names:

```
- delay.10m.sim
- reject.sim
```

## Contributing

Contributions are welcome! Please open issues and pull requests.

Maintained by **LC Waikiki SRE Team** (lcwsre@lcwaikiki.com).

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a complete version history.


## License

This project is licensed under the BSD-3-Clause license - see the [LICENSE](https://github.com/lcwsre/adcs-issuer/blob/master/LICENSE).
