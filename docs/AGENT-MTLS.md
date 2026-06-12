# Agent ↔ Control-Plane Mutual TLS (A-4)

The runtime agent sits **inline on customer LLM traffic**, on infrastructure the
platform does not control. A long-lived bearer credential on such a box is the
weakest link in the product's own threat model. So the agent authenticates to
the control plane with a **short-lived client certificate** (rotated by
cert-manager, hot-reloaded by the agent) over **TLS 1.3**, with the
control-plane server identity **pinned to the platform CA** — not the system
trust store. (NIST 800-53 IA-3, SC-8, SC-12/13.)

## Agent side (implemented)

`runtime-agent/internal/controlplane/client.go` — `NewHTTPClient(caPath,
certPath, keyPath)` returns the only HTTP client the agent uses to reach the
control plane:

- `MinVersion: tls.VersionTLS13`.
- `RootCAs` = the platform CA bundle only (a MITM cert signed by any other CA is
  rejected — proven by `TestClientRefusesServerWithoutPlatformCA`).
- `GetClientCertificate` from a reloader that re-reads the cert files every 5
  minutes, so cert-manager rotation needs **no process restart**
  (`TestCertReloaderPicksUpRotation`).

`cmd/agent/main.go` builds this client from `CONTROL_PLANE_CA_PATH` /
`CONTROL_PLANE_CERT_PATH` / `CONTROL_PLANE_KEY_PATH` and injects it into **every**
control-plane caller: the policy fetcher, telemetry uploader, kill-switch poller,
and heartbeat. A partial configuration is fatal (no silent downgrade). A lint
test (`guard_test.go`) bans `http.DefaultClient` and the convenience wrappers so
a future call can't bypass the pinned client.

## Deployment (cert-manager + Helm)

Issue the agent a client certificate from the platform CA with cert-manager, into
a Secret with keys `ca.crt`, `tls.crt`, `tls.key`:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: agent-control-plane-tls
spec:
  secretName: agent-control-plane-tls
  duration: 24h          # short-lived
  renewBefore: 8h        # cert-manager rotates the Secret; the agent hot-reloads
  issuerRef:
    name: platform-ca-issuer
    kind: ClusterIssuer
  commonName: agent.<tenant>
  usages: [client auth]
```

Enable mTLS in the agent chart (`deploy/helm/ai-security-agent/values.yaml`):

```yaml
mtls:
  enabled: true
  secretName: agent-control-plane-tls
  mountPath: /etc/aisp/agent-certs
```

The chart mounts the Secret read-only and sets the `CONTROL_PLANE_*` paths.

## Control-plane side (ingress mTLS — infra)

The control-plane ingress must **require and verify** client certificates from
the platform CA on the agent-facing routes. With ingress-nginx:

```yaml
metadata:
  annotations:
    nginx.ingress.kubernetes.io/auth-tls-verify-client: "on"
    nginx.ingress.kubernetes.io/auth-tls-secret: "platform/platform-ca"
    nginx.ingress.kubernetes.io/auth-tls-verify-depth: "1"
```

`auth-tls-secret` references a Secret holding the platform CA `ca.crt`. Requests
without a valid platform-CA-signed client cert are rejected at the edge, before
reaching the FastAPI app. (For other ingress controllers / service meshes, use
the equivalent mTLS-required policy.)

## Rotation drill

1. cert-manager rewrites the Secret (new `tls.crt`/`tls.key`) on renewal.
2. The mounted files update; within ≤5 minutes the agent's reloader re-reads them.
3. The next control-plane call uses the new certificate — zero dropped requests,
   no restart. Verified by `TestCertReloaderPicksUpRotation`.
