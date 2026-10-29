<!-- Copyright (c) 2025, AgriTheory and contributors
For license information, please see license.txt-->

<div class="rolling-hills-header">
  <style>
    .rolling-hills-header {
      position: relative;
      width: 100%;
      height: 200px;
      overflow: hidden;
      background: linear-gradient(to bottom, #fff 0%, #f5f0eb 100%);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .rolling-hills-header .header-title {
      position: relative;
      z-index: 10;
      font-family: Arial, sans-serif;
      font-size: 2.5rem;
      font-weight: 700;
      color: #333;
      margin: 0;
      padding: 0;
      border: none;
      text-align: center;
    }
    .rolling-hills-header .hill {
      position: absolute;
      bottom: 0;
      left: 0;
      width: 100%;
      height: 100px;
      background-size: 1200px 100px;
      background-repeat: repeat-x;
      background-position: bottom;
    }
    .rolling-hills-header .hill1 {
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='1200' height='100' viewBox='0 0 1200 100'%3E%3Cpath fill='%239d6335' d='M0,100 C99.86,100 399.07,0 600,0 c200.93,0 501.99,100 600,100'/%3E%3C/svg%3E");
      animation: rollHills 45s linear infinite;
      z-index: 1;
      opacity: 0.5;
    }
    .rolling-hills-header .hill2 {
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='1200' height='100' viewBox='0 0 1200 100'%3E%3Cpath fill='%23a1684e' d='M0,100 C99.86,100 399.07,0 600,0 c200.93,0 501.99,100 600,100'/%3E%3C/svg%3E");
      animation: rollHills 45s linear infinite;
      animation-delay: -15s;
      z-index: 2;
      opacity: 0.7;
    }
    .rolling-hills-header .hill3 {
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='1200' height='100' viewBox='0 0 1200 100'%3E%3Cpath fill='%23a9755e' d='M0,100 C99.86,100 399.07,0 600,0 c200.93,0 501.99,100 600,100'/%3E%3C/svg%3E");
      animation: rollHills 67.5s linear infinite;
      animation-delay: -15s;
      z-index: 3;
      opacity: 0.6;
      bottom: -3.5px;
    }
    .rolling-hills-header .hill4 {
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='1200' height='100' viewBox='0 0 1200 100'%3E%3Cpath fill='%239d6335' d='M0,100 C99.86,100 399.07,0 600,0 c200.93,0 501.99,100 600,100'/%3E%3C/svg%3E");
      animation: rollHills 45s linear infinite;
      animation-delay: -30s;
      z-index: 4;
      bottom: -5px;
    }
    @keyframes rollHills {
      0% { background-position-x: 1200px; }
      100% { background-position-x: 0; }
    }
  </style>
  <h1 class="header-title">SAML</h1>
  <div class="hill hill1"></div>
  <div class="hill hill2"></div>
  <div class="hill hill3"></div>
  <div class="hill hill4"></div>
</div>
<br>

SAML2 Login and SCIM 2.0 provisioning for Frappe apps

- **SAML** — single sign-on authentication
- **SCIM** — automated user create, update, and deactivation from your IdP

See [SAML Integration docs](saml/docs/index.md) for setup details including SCIM provisioning.

## Install Instructions

Set up a new bench, substitute a path to the python version to use, which should 3.10 latest

```
# for linux development
bench init --frappe-branch version-15 {{ bench name }} --python ~/.pyenv/versions/3.10.4/bin/python3
```

Create a new site in that bench

```
cd {{ bench name }}
bench new-site {{ site name }} --force --db-name {{ site name }}
bench use {{ site name }}
bench set-config developer_mode 1
bench set-config mute_emails 1
```

Update and get the site ready

```
bench start
```

Install the SAML app

```
bench get-app saml
bench --site {{ site name }} install-app saml
```

NOTE: If you get `xmlsec.InternalError: (-1, 'lxml & xmlsec libxml2 library version mismatch')`, ensure lxml and xmlsec use the same libxml2:

- **Linux (recommended):** `sudo apt-get install python3-lxml` per [lxml installation docs](https://lxml.de/installation.html)
- **Fallback:** `bench pip install --force-reinstall lxml` (avoid `--no-binary lxml` as it can timeout on slower systems)

In a new terminal window

```
bench update
bench migrate
bench build
```

To run mypy and pytest

```shell
source env/bin/activate
mypy ./apps/saml/saml --ignore-missing-imports
pytest ./apps/saml/saml/tests -s --disable-warnings
```

## Tests (using Keycloak)

This app comes with a `docker-compose` file that sets up a Keycloak instance for testing, which relies on your current site's bench port and SCIM bearer token.

From `apps/saml/saml/tests`, run:

```shell
./keycloak.sh --build
```

Keycloak listens on [http://localhost:8080](http://localhost:8080). The imported realm is **`frappe`**.

### Test credentials

These are local-dev / test-only values from `saml/tests/setup.py`, `saml/tests/realm-template.json`, and `saml/tests/docker-compose.yml`.

#### Frappe site (direct login)

| User | Password | Notes |
| --- | --- | --- |
| `Administrator` | `admin` | Set by `before_test` / setup wizard during test bootstrap |

Use this for desk access, DocType setup, and tests that call `frappe.set_user("Administrator")`. It is not a SAML user.

#### Keycloak admin console

| User | Password | URL |
| --- | --- | --- |
| `admin` | `admin` | [http://localhost:8080/admin](http://localhost:8080/admin) (master realm) |

Use this to inspect the **`frappe`** realm, SAML client, and (optionally) the SCIM user-storage plugin.

#### Keycloak realm users (SAML login)

SAML tests authenticate against Keycloak, then land in Frappe as the matching email user. Log in at your site login page with the **Keycloak** provider (or follow the auto-SAML redirect when enabled in the test fixture).

| Keycloak username | Frappe email | Password | Typical test role |
| --- | --- | --- | --- |
| `warehouse` | `warehouse@ambrosiapieco.example` | `apc-warehouse` | Warehouse Manager |
| `kb.contributor` | `kb.contributor@ambrosiapieco.example` | `apc-kb-contributor` | Knowledge Base |
| `saml.existing` | `saml.existing@ambrosiapieco.example` | `apc-saml-existing` | Pre-existing SAML-managed Frappe user |
| `picker` | `picker@ambrosiapieco.example` | `apc-picker` | Stock User |
| `saml.admin` | `saml.admin@ambrosiapieco.example` | `apc-saml-admin` | System Administrator |
| `scim.demo` | `scim.demo@ambrosiapieco.example` | `apc-scim-demo` | Table-mapping demo (see below) |

SAML-managed users do not use Frappe passwords in normal operation; the IdP password above is what you enter at Keycloak.

#### Table mapping demo (`social_logins` on login)

`scim.demo` lives in the Keycloak realm fixture only — not in Frappe until the first SAML login. Keycloak sends a SAML `employeeNumber` attribute (`APC-DEMO-001`); the Keycloak SAML Login Key table mapping writes it to **User → Social Logins** (`provider=keycloak`) during ACS.

1. Confirm the user does not exist in Frappe (or delete it to replay the demo).
2. Rebuild Keycloak if you changed `realm-template.json`: `./keycloak.sh reset && ./keycloak.sh --build`
3. Sign in as `scim.demo` / `apc-scim-demo` via Keycloak SAML.
4. As `Administrator`, open **User → scim.demo@ambrosiapieco.example → Social Logins** and confirm the `keycloak` / `APC-DEMO-001` row.

#### SCIM API (not interactive login)

| Setting | Value |
| --- | --- |
| Bearer token | `test-scim-bearer-token` |
| Service user | `scim-provisioner@system.local` (audit owner only; no password login) |
| Endpoint | `http://localhost:<bench-port>/scim/v2` |

