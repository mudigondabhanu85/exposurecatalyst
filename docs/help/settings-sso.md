---
id: settings-sso
title: Settings — Identity & SSO
page: /settings/sso
permission: sso:manage
summary: Set up Okta SAML sign-in, map SailPoint/Okta groups to roles, and issue SCIM tokens for SailPoint provisioning.
keywords: [sso, saml, okta, sailpoint, scim, groups, roles, mapping, metadata, app tile]
docs: admin-guide/okta-saml/
---

## What this page is for

Connects ExposureCatalyst to Okta for single sign-on and to SailPoint for access governance. SSO users' roles
come **only** from the group → role mappings on this page.

## How to use it

1. **Step 1**: create a SAML 2.0 app in Okta with the shown ACS URL and Entity ID. Download the **App tile
   logo** (`app-icon-512.png`) for the Okta app.
2. **Step 2**: import the Okta metadata from its URL, or paste the XML.
3. **Step 3**: check the attribute names (`email`, `firstName`, `lastName`, `groups`) and decide on JIT
   provisioning.
4. **Step 4**: map each group to a role, for example `ExcatAnalysts` → Security Analyst.
5. **Step 5**: **Enable** SAML, then **Test sign-in in a new tab** while keeping this session open.
6. For SailPoint SCIM, **Generate token** and configure the SCIM 2.0 source in SailPoint with the base URL
   and token. Copy the token immediately, because it's shown once.

## Fields and columns

| Field | Meaning |
|---|---|
| JIT provisioning | Create the account on first SAML sign-in. Turn it off when SailPoint provisions via SCIM |
| IdP-initiated sign-in | Allow sign-in from the Okta dashboard tile without starting here (less safe, off by default) |
| Users (mapping) | SSO users currently in that group |
| Users without access | SSO users whose groups map to no role. They can't sign in |
| Last SCIM activity | When SailPoint last called the SCIM API |

## Required permissions

`sso:manage` for SAML settings and tokens. Mappings also need `role:manage`, and you can only map roles whose
permissions you hold. Generating SCIM tokens also needs `user:manage`.

## Common errors

- **"Map at least one group to a role before enabling SAML"**: complete Step 4 first.
- **"Could not fetch metadata"**: the URL must be on an Okta domain (or the egress allowlist). Paste the XML
  instead.
- Sign-in errors are shown on the login page. See the troubleshooting table in the
  [Okta guide](../admin-guide/okta-saml.md#troubleshooting).

## Learn more

See [Okta SAML](../admin-guide/okta-saml.md), [SailPoint](../admin-guide/sailpoint.md) and the
[identity flow](../architecture/identity-flow.md).
