#!/bin/bash

# Check for merge conflicts before proceeding
python -m compileall -f $GITHUB_WORKSPACE
if grep -lr --exclude-dir=node_modules "^<<<<<<< " $GITHUB_WORKSPACE
    then echo "Found merge conflicts"
    exit 1
fi

# SAML xmlsec/lxml stack plus bench CI dependencies.
sudo apt update -y && sudo apt install -y \
	libxml2-dev \
	libxslt-dev \
	python3-dev \
	pkg-config \
	libxmlsec1-dev \
	libxmlsec1-openssl \
	python3-lxml \
	redis-server \
	mariadb-client \
	postgresql-client
