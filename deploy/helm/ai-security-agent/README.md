# AI Security Platform runtime-agent chart

This chart deploys the customer-side inline enforcement agent as a Deployment,
DaemonSet, or sidecar configuration.

Production installation requires HTTPS and mTLS to the control plane plus the
exact approved image digest:

```bash
helm install aisp-agent deploy/helm/ai-security-agent \
  --namespace ai-security --create-namespace \
  --set image.digest=sha256:REPLACE_WITH_APPROVED_RELEASE_DIGEST \
  --set config.platformUrl=https://api.platform.example \
  --set mtls.enabled=true \
  --set mtls.secretName=agent-control-plane-tls \
  --set agentApiKey.existingSecret=agent-api-key
```

Before admission, verify the digest’s tag-qualified signature, SPDX attestation,
and GitHub provenance using `docs/RELEASE-ASSURANCE.md`. Production rendering
rejects mutable image tags, plaintext control-plane transport, and disabled
mTLS.

Validate a prospective values file before applying it:

```bash
helm lint deploy/helm/ai-security-agent -f production-values.yaml
helm template aisp-agent deploy/helm/ai-security-agent \
  -f production-values.yaml \
  | kubectl apply --dry-run=server -f -
```
