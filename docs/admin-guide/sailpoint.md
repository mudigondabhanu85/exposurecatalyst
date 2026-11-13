# SailPoint provisioning & group mapping

SailPoint IdentityNow / Identity Security Cloud (ISC) and IdentityIQ (IIQ) can govern ExposureCatalyst
access in two ways, and can use both together:

| Mechanism | How groups arrive | When to use |
|---|---|---|
| **SAML group attribute** | SailPoint manages Okta group membership, and Okta sends `groups` in each assertion | Simplest. Roles update at next sign-in |
| **SCIM 2.0** | SailPoint calls `https://<host>/scim/v2` to create, deactivate and group users | Immediate joiner/mover/leaver. Accounts exist before first sign-in. Leavers are deactivated and their sessions revoked at once |

For SCIM-provisioned users, the **SCIM group memberships** are authoritative, and the SAML `groups`
attribute is ignored for them. Either way, groups become roles only through **Settings → Identity & SSO →
group → role mapping**.

## SCIM setup

1. In ExposureCatalyst: **Settings → Identity & SSO → SailPoint SCIM 2.0 provisioning → Generate token**.
   Copy the **base URL** and **bearer token**. The token is shown once and stored only as a SHA-256 hash.
2. In ISC: **Admin → Connections → Sources → Create new → SCIM 2.0**.
   - Base URL: `https://<host>/scim/v2`
   - Authentication: *OAuth 2.0 Bearer Token / API token* → paste the token
   - Account schema: `userName` (identity), `emails[primary].value`, `name.givenName`, `name.familyName`,
     `active`, `externalId` (the SailPoint identity ID)
   - Entitlement (group) schema: `displayName`, `members`
3. **Test connection**. SailPoint calls `/ServiceProviderConfig` and `/Users`.
4. Create **access profiles / roles** in SailPoint that grant the entitlement groups (`ExcatAnalysts`, …).
5. Map those groups to ExposureCatalyst roles (below).
6. In IIQ, use the *SCIM 2.0* connector with the same base URL and bearer token.

### Supported SCIM operations

| Resource | Operations |
|---|---|
| `/Users` | `GET` (filter `userName eq "…"` / `externalId eq "…"`, `startIndex`, `count` ≤ 200), `POST`, `PUT`, `PATCH` (`active`, `displayName`, `name.*`, `emails`, `externalId`), `DELETE` (deactivate, keeps audit history) |
| `/Groups` | `GET` (filter `displayName eq "…"`), `POST` (with members), `PUT`, `PATCH` (`add`/`remove`/`replace` `members`, `members[value eq "id"]`, `displayName`), `DELETE` |
| Discovery | `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` |

SCIM never binds to a local break-glass account (`409 uniqueness`).

## Group → role mapping examples

| SailPoint entitlement / Okta group | ExposureCatalyst role | Typical holders |
|---|---|---|
| `ExcatViewers` | Viewer | IT operations, app owners |
| `ExcatAnalysts` | Security Analyst | Vulnerability management team |
| `ExcatApprovers` | Approver | Security leads |
| `ExcatAuditors` | Auditor | Internal audit, GRC |
| `ExcatAdmins` | Admin | Platform engineering |

!!! warning "Segregation of duties"
    Don't give one SailPoint role both `ExcatAnalysts` and `ExcatApprovers` unless policy allows it. The
    server still prevents an author from approving their own advisory, but define an SoD policy in SailPoint
    too (for example, *Approver* conflicts with *Analyst*). Keep `Super Admin` for local break-glass accounts.

## Sync status

The mapping step shows the number of SSO users, users **without access** (no mapped group), SCIM groups,
**last SCIM activity**, and groups seen but not yet mapped (a suggestion list for new mappings).
Adding or removing a mapping recomputes every SSO user's roles immediately and revokes the sessions of users
whose roles changed. Every change is audited (`sso.mapping_added`, `scim.user_*`, `scim.group_*`).
