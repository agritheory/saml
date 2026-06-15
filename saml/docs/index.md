<!-- Copyright (c) 2025, AgriTheory and contributors
For license information, please see license.txt-->

# SAML Integration

<div class="byline">
  Tyler Matteson 2026-06-13
</div>


The SAML (Security Assertion Markup Language) integration for Frappe enables secure single sign-on (SSO) authentication between your Frappe application and your organization's Identity Provider (IdP). When a user attempts to access your Frappe application, the following authentication flow occurs:

1. The user tries to access a protected page or clicks on the SAML login button.
2. Frappe redirects the user to your configured Identity Provider (IdP) with a SAML authentication request.
3. The user authenticates with the IdP using their organizational credentials.
4. Upon successful authentication, the IdP generates a SAML response containing user information.
5. The user is redirected back to Frappe with this SAML response.
6. Frappe verifies the SAML response, extracts user information, and either logs in an existing user or creates a new user account.
7. The user is redirected to their intended destination within Frappe.

This process enables secure authentication without requiring users to maintain separate credentials for your Frappe application.

## Setting Up SAML Integration

This guide assumes you have already installed the SAML integration app. If you haven't, please refer to the [Installation Documentation](https://github.com/agritheory/samlREADME.md).

### Configuring SAML Login Key

To set up a SAML provider:

1. Go to Desk > SAML > SAML Login Key
2. Click "New" to create a new SAML provider configuration
3. Enter a descriptive "Provider Name" (e.g., "Corporate SSO" or "Okta SSO")
4. Check "Enable SAML Login" to activate this provider
5. Fill in the Service Provider and Identity Provider details as outlined in the following sections

### Auto SAML Login

When **Auto SAML Login** is enabled on a SAML Login Key, guest requests matching the configured scope are sent to the IdP for silent SSO before ERPNext UI is shown. If the user already has an active IdP session, authentication is attempted passively (no credential prompt). If silent authentication fails, an interactive SAML login is attempted automatically.

**Auto SAML Scope** controls which guest requests trigger auto SAML:

- **All Guest Routes** (default): every guest page load, recommended for private SSO-mandatory sites with no public content. Built-in exclusions always apply (see below).
- **Configured Paths**: only paths listed in **Auto SAML Paths**, one per line. Use a trailing `/*` for prefix match (for example `/app/*` matches `/app/user/user-001` in Frappe v15 path-based Desk routing). `/login` covers all login hash sections (`/login#login`, `#forgot`, etc.) because hashes are client-side only.
- **Desk Only**: legacy behavior — only `/app` and `/app/*`.

Requirements and notes:

- Only one enabled SAML Login Key may use Auto SAML Login at a time.
- Built-in exclusions (not configurable): `/api/*`, `/assets/*`, `/files/*`, `/private/*`, static file paths (for example `/website_script.js`), `/logout`, and the SAML login/ACS API methods. These paths never trigger auto SAML.
- HTTP redirects between ERPNext and the IdP are still required for SAML; this setting removes the ERPNext login page and IdP password prompt when the IdP session is already valid.
- After a successful login, ERPNext stores a session cookie (`sid`) on the ERPNext domain. Subsequent visits use that cookie until the session expires.
- When Auto SAML Login is enabled, logout sends users to `/logout` instead of `/login`, so they are not immediately signed back in through passive SSO. Use **Log in again** on that page when you want to start a new session.

### Service Provider (SP) Configuration

The Service Provider is your Frappe application. Configure these settings:

**Service Provider Entity ID**: A unique identifier for your Frappe application. Typically set as your site URL (e.g., `https://your-site.com`) or a specific identifier agreed upon with your IdP.

**Service Provider x509cert**: The public certificate used to verify signed SAML messages. You can generate a self-signed certificate using OpenSSL

**Service Provider Private Key**: The private key corresponding to your x509 certificate. Copy the contents of the sp.key file generated above into this field.

When configuring your Identity Provider, you'll need to provide:
- Your Entity ID
- Assertion Consumer Service (ACS) URL: `https://your-site.com/api/method/saml.saml.acs?provider=your_provider_name`
- The SP x509 certificate for signature verification

> **Note on ports:** In production (`developer_mode` disabled), port numbers are automatically stripped from the host when constructing the ACS URL and SAML request data, so your IdP configuration should use a standard HTTPS URL without a port. In developer mode (`developer_mode = 1`), the port is preserved in the host and also passed as `server_port` in the SAML request, allowing the library to construct correct URLs for non-standard ports such as `http://localhost:8000`.

### Identity Provider (IdP) Configuration

Obtain the following information from your Identity Provider (such as Okta, Azure AD, or OneLogin):

**IDP Entity ID**: The unique identifier for your Identity Provider. This is provided by your IdP.

**IDP SSO URL**: The URL endpoint where users will be redirected for authentication. This is the single sign-on URL provided by your IdP.

**IDP x509cert**: The public certificate provided by your IdP, used to verify signed SAML responses. Copy the full certificate provided by your IdP, excluding the `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` tags.

### IdP Metadata Sync

Instead of manually copying the IdP signing certificate, you can fetch it from IdP metadata on a schedule or on demand. Sync only updates **IDP x509cert**; Entity ID and SSO URL remain manual configuration.

**Sync IdP Metadata**: When checked, this provider is included in the background metadata sync schedule. Requires **Enable SAML Login**.

**IdP Metadata URL**: The URL fetched for IdP metadata.

- Keycloak default: `{entity_id}/protocol/saml/descriptor` (for example, `http://localhost:8080/realms/myrealm/protocol/saml/descriptor`)
- Entra ID example: `https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml`

When you enter an **IDP Entity ID** on a new SAML Login Key, the form auto-fills this field with the Keycloak descriptor pattern if it is empty.

**IdP Metadata Sync Cron**: Per-provider cron schedule for background sync. Default: `0 6 * * *` (daily at 6:00 AM). Uses standard five-field cron syntax (minute, hour, day of month, month, day of week). Only evaluated when **Sync IdP Metadata** is checked.

**Last IdP Metadata Sync**: Read-only timestamp of the last successful metadata sync.

**Manual sync**: On a saved SAML Login Key with **Enable SAML Login**, use the **Sync IdP Metadata** button to fetch metadata immediately. Manual sync works whether or not scheduled sync is enabled.

**Scheduler behavior**: Frappe runs an hourly background job that checks each provider with **Sync IdP Metadata** enabled. If the provider's cron schedule is due based on **Last IdP Metadata Sync**, the certificate is updated. Sync may run up to about one hour after the configured cron time. Metadata sync never runs during login or ACS processing.

### Security Settings

**Allow Relaxed SAML Validation**: By default, SAML responses are validated strictly according to the SAML 2.0 specification. This includes:

- Destination URL validation
- Response timing and conditions
- Audience restriction
- InResponseTo correlation

Some older or non-compliant Identity Providers may fail strict validation. If you encounter SAML errors after upgrading or with a specific IdP, you can enable **Allow Relaxed SAML Validation** to disable these checks.

> **WARNING**: Only enable relaxed validation if your IdP requires it. Strict validation protects against SAML response replay and injection attacks. When relaxed validation is enabled, ensure your IdP is properly secured and uses HTTPS.

#### Common IdP Setup Examples:


#### Keycloak Configuration

To configure Keycloak as your Identity Provider:

1. Log in to your Keycloak Admin Console
2. Select or create a new realm for your organization
3. Navigate to Clients and click "Create"
4. Set Client ID to your Service Provider Entity ID
5. Set Client Protocol to "saml"
6. Set Client SAML Endpoint to your ACS URL (`https://your-site.com/api/method/saml.saml.acs?provider=your_provider_name`)
7. Under Settings tab:
   - Set "Include AuthnStatement" to ON
   - Set "Sign Documents" to ON
   - Set "Sign Assertions" to ON
8. Under "Fine Grain SAML Endpoint Configuration":
   - Set "Assertion Consumer Service Redirect Binding URL" to your ACS URL
9. Under "Mappers" tab, create the following protocol mappers:
   - Create mapper for "X500 email" to map user email to the NameID
     - Name: "email"
     - Mapper Type: "User Property"
     - Property: "email"
     - SAML Attribute Name: "NameID"
     - SAML Attribute NameFormat: "Basic"
10. In the Installation tab, select "SAML Metadata IDPSSODescriptor" format to download the XML metadata
11. Extract the following information from the metadata (or set **IdP Metadata URL** to the descriptor URL and use **Sync IdP Metadata** to fetch the certificate automatically):
    - Entity ID: The value of the `entityID` attribute in the `EntityDescriptor` element
    - SSO URL: The value of the `Location` attribute in the `SingleSignOnService` element with `Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"`
    - X509 Certificate: The value between the `<X509Certificate>` and `</X509Certificate>` tags

After configuring Keycloak, enter the extracted Entity ID, SSO URL, and X509 Certificate into the corresponding fields in your Frappe SAML Login Key.