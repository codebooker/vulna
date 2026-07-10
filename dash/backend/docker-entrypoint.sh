#!/bin/sh
# API container entrypoint: bring the schema up to date, then serve.
#
# Applying migrations on startup is what lets a fresh single-host stack come up
# with no manual step (Phase 17). It is idempotent, so it is safe on every boot.
# Advanced operators who run migrations as a separate job can opt out with
# VULNA_RUN_MIGRATIONS=false.
set -eu

if [ "${VULNA_RUN_MIGRATIONS:-true}" = "true" ]; then
	echo "api: applying database migrations (alembic upgrade head)"
	alembic upgrade head
fi

exec "$@"
