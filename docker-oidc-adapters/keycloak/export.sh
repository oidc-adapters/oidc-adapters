#!/usr/bin/env sh
docker compose run --rm -it --entrypoint=/opt/keycloak/bin/kc.sh keycloak export --dir /opt/keycloak/data/export --users realm_file