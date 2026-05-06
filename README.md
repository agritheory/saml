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

SAML2 Login for Frappe apps

## Install Instructions

Set up a new bench, substitute a path to the python version to use, which should 3.13 latest

```
# for linux development
bench init --frappe-branch version-16 {{ bench name }} --python ~/.pyenv/versions/3.13/bin/python3
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

This app comes with a `docker-compose` file that sets up a Keycloak instance for testing, which would rely on your current site's information.

In the tests folder, simply run the following script to get the active bench port and start the Keycloak instance:

```shell
./keycloak.sh --build
```
