<!-- Copyright (c) 2025, AgriTheory and contributors
For license information, please see license.txt-->

## SAML

SAML2 Login for Frappe apps

#### License

MIT

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

NOTE: If you get a version mismatch error for the `libxml2` package between `lxml` and `xmlsec`, you should refer to the upstream [note](https://github.com/SAML-Toolkits/python3-saml#note) for resolving it. If you see the error, run the following command:

```
bench pip install --force-reinstall --no-binary lxml lxml
```

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
