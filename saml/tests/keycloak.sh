#!/bin/bash
touch realm-export.json

if [ $# -eq 0 ]; then
	exec docker compose up -d
fi

command="$1"
shift

case "$command" in
	--build | build)
		exec docker compose up --build -d "$@"
		;;
	down)
		exec docker compose down "$@"
		;;
	reset)
		exec docker compose down -v "$@"
		;;
	stop | logs | ps | pull | restart | exec | run)
		exec docker compose "$command" "$@"
		;;
	-d)
		exec docker compose up -d "$@"
		;;
	*)
		exec docker compose up "$command" "$@"
		;;
esac
