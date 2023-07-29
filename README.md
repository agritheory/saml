## SAML

SAML2 Login for Frappe apps

#### License

MIT

## Install Instructions

Set up a new bench, substitute a path to the python version to use, which should 3.10 latest

```
# for linux development
bench init --frappe-branch version-14 {{ bench name }} --python ~/.pyenv/versions/3.10.4/bin/python3
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
In a new terminal window
```
bench update
bench migrate
bench build
```

Setup test data
```shell
bench execute 'saml.tests.setup.before_test'
# for complete reset to run before tests:
bench reinstall --yes --admin-password admin --mariadb-root-password admin && bench execute 'saml.tests.setup.before_test'
```

To run mypy and pytest
```shell
source env/bin/activate
mypy ./apps/saml/saml --ignore-missing-imports
pytest ./apps/saml/saml/tests -s --disable-warnings
```