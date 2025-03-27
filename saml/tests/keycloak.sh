#!/bin/bash
which jq > /dev/null || apt install jq
touch realm-export.json

CONFIG_PATH="../../../../sites/common_site_config.json"
if [ -f "$CONFIG_PATH" ]; then
  WEBSERVER_PORT=$(jq -r '.webserver_port // "8000"' "$CONFIG_PATH")
else
  WEBSERVER_PORT="8000"
fi

echo "Detected webserver port: $WEBSERVER_PORT"
export BENCH_PORT="$WEBSERVER_PORT"
docker compose up "$@"
