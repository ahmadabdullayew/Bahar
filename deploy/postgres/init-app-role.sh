#!/bin/sh
set -eu

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=app_password="$BAHAR_APP_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE bahar_app LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bahar_app')\gexec
GRANT CONNECT ON DATABASE bahar TO bahar_app;
SQL
