# The lane's Postgres: postgres:17 with pgtap baked in (V001__baseline.sql requires the
# extension; installing it into a running container broke the postmaster once).
FROM postgres:17
RUN apt-get update -qq && apt-get install -y -qq postgresql-17-pgtap && rm -rf /var/lib/apt/lists/*
