<!-- Copyright (c) 2025, AgriTheory and contributors
For license information, please see license.txt-->

# SAML Integration

<div class="byline">
  Tyler Matteson 2026-05-09
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

When **Auto SAML Login** is enabled on a SAML Login Key, guests who open `/app` or any `/app/*` route are sent directly to the configured Identity Provider instead of the ERPNext login page. If the user already has an active IdP session, authentication is attempted silently (no credential prompt). If silent authentication fails, an interactive SAML login is attempted automatically.

Requirements and notes:

- Only one enabled SAML Login Key may use Auto SAML Login at a time.
- HTTP redirects between ERPNext and the IdP are still required for SAML; this setting removes the ERPNext login page and IdP password prompt when the IdP session is already valid.
- After a successful login, ERPNext stores a session cookie (`sid`) on the ERPNext domain. Subsequent visits use that cookie until the session expires.

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
11. Extract the following information from the metadata:
    - Entity ID: The value of the `entityID` attribute in the `EntityDescriptor` element
    - SSO URL: The value of the `Location` attribute in the `SingleSignOnService` element with `Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"`
    - X509 Certificate: The value between the `<X509Certificate>` and `</X509Certificate>` tags

After configuring Keycloak, enter the extracted Entity ID, SSO URL, and X509 Certificate into the corresponding fields in your Frappe SAML Login Key.