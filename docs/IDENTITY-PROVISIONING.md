# Enterprise identity provisioning

## Supported production surfaces

- `GET|POST /v1/idp`, `PATCH|DELETE /v1/idp/{id}`, and
  `POST /v1/idp/{id}/scim-token` require an `admin` or `owner` JWT and operate
  only on the caller's organization.
- `/v1/scim/v2/{org_slug}` implements the supported SCIM 2.0 User, Group, and
  discovery subset. Each request requires the bearer token for the single
  active SCIM provider belonging to that URL organization.
- IdP administration is limited to 120 requests per principal per minute.
  SCIM is limited to 600 requests per source IP per minute. The shared Redis
  limiter fails open during a limiter outage; alert on
  `rate_limit_unavailable` and enforce an additional edge limit at the ingress.
- Request bodies default to a 1 MiB ceiling. SCIM list pagination is capped at
  200 users per response.

## Provision and activate

1. Create a `scim` provider with `POST /v1/idp`. It starts in
   `pending_verification`.
2. Mint its bearer token with `POST /v1/idp/{id}/scim-token`. The plaintext is
   returned once; only its bcrypt hash is retained. Store the plaintext in the
   IdP's managed secret store.
3. Test the returned `/v1/scim/v2/{org_slug}` endpoint from the IdP.
4. Activate the provider with `PATCH /v1/idp/{id}` and
   `{"status":"active"}`. Activation is rejected until a token has been
   minted. The database permits only one active SCIM provider per organization,
   including under concurrent activation attempts.

## Rotate or revoke

- Rotation is replacement, not overlap: minting a new token immediately
  invalidates the old token. Coordinate a maintenance window, update the IdP,
  and verify `ServiceProviderConfig` before resuming sync.
- To revoke without replacement, set the provider to `disabled`. A disabled
  provider cannot authenticate even if its token remains known.
- Delete only after dependent identity workflows have been retired. SCIM user
  deletion deactivates the platform user rather than erasing its audit
  attribution.

## Authorization and failure contract

Provisioning group maps may grant `admin`, `analyst`, or `viewer`; they can
never grant `owner`. Runtime mapping also fails unknown or legacy `owner`
values to `viewer`, so direct database writes cannot bypass this boundary.
User and Group operations are bound to both the URL organization and the
authenticating IdP configuration: a SCIM provider cannot list, mutate, group,
or deactivate local users or identities owned by a different SSO provider in
the same tenant. Cross-organization IdP object access returns 404. A bearer
token presented against another organization's URL returns 401. SCIM
authentication, payload, path, and query errors use `application/scim+json`.
Every successful SCIM user lifecycle and group-membership mutation emits a
tenant-bound, tamper-evident audit event attributed to the authenticating IdP;
tokens and user payloads are never written to audit detail.

The mounted end-to-end campaign is
`backend/tests/integration/test_tenant_isolation.py::test_enterprise_identity_provisioning_is_org_scoped`.
It drives all 13 SCIM operations and proves role enforcement, object
non-disclosure, token-to-tenant and token-to-provider binding,
single-active-provider integrity, mutation audit emission, malformed-payload
handling, and sibling tenant isolation.
