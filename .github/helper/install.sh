#!/bin/bash

export PIP_ROOT_USER_ACTION=ignore

set -e
cd ~ || exit

DB="${DB:-mariadb}"

pip install --upgrade pip
pip install frappe-bench

if [ "$DB" == "mariadb" ]; then
	mysql --host 127.0.0.1 --port 3306 -u root -e "SET GLOBAL character_set_server = 'utf8mb4'"
	mysql --host 127.0.0.1 --port 3306 -u root -e "SET GLOBAL collation_server = 'utf8mb4_unicode_ci'"
	mysql --host 127.0.0.1 --port 3306 -u root -e "CREATE OR REPLACE DATABASE test_site"
	mysql --host 127.0.0.1 --port 3306 -u root -e "CREATE OR REPLACE USER 'test_site'@'localhost' IDENTIFIED BY 'test_site'"
	mysql --host 127.0.0.1 --port 3306 -u root -e "GRANT ALL PRIVILEGES ON \`test_site\`.* TO 'test_site'@'localhost'"
	mysql --host 127.0.0.1 --port 3306 -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'admin'"
	mysql --host 127.0.0.1 --port 3306 -u root -e "FLUSH PRIVILEGES"
fi

if [ "$DB" == "postgres" ]; then
	PGPASSWORD=admin psql -h 127.0.0.1 -p 5432 -U postgres -c "DROP DATABASE IF EXISTS test_site"
	PGPASSWORD=admin psql -h 127.0.0.1 -p 5432 -U postgres -c "CREATE DATABASE test_site"
	PGPASSWORD=admin psql -h 127.0.0.1 -p 5432 -U postgres -c "DROP USER IF EXISTS test_site"
	PGPASSWORD=admin psql -h 127.0.0.1 -p 5432 -U postgres -c "CREATE USER test_site WITH PASSWORD 'test_site'"
	PGPASSWORD=admin psql -h 127.0.0.1 -p 5432 -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE test_site TO test_site"
	PGPASSWORD=admin psql -h 127.0.0.1 -p 5432 -U postgres -d test_site -c "GRANT ALL ON SCHEMA public TO test_site"
fi

bench init --skip-assets --frappe-branch version-16 --python "$(which python)" frappe-bench

mkdir ~/frappe-bench/sites/test_site
cp -r "${GITHUB_WORKSPACE}/.github/helper/db/${DB}.json" ~/frappe-bench/sites/test_site/site_config.json

cd ~/frappe-bench || exit

sed -i 's/watch:/# watch:/g' Procfile
sed -i 's/schedule:/# schedule:/g' Procfile
sed -i 's/socketio:/# socketio:/g' Procfile
sed -i 's/redis_socketio:/# redis_socketio:/g' Procfile

bench get-app saml "${GITHUB_WORKSPACE}" --skip-assets
bench setup requirements --python
bench setup requirements --dev
# Ensure lxml links to same libxml2 as xmlsec (https://lxml.de/installation.html).
bench pip install --force-reinstall lxml
bench use test_site
bench --site test_site reinstall --yes --admin-password admin

bench start &> bench_run_logs.txt &
CI=Yes &
bench execute 'saml.tests.setup.before_test'
