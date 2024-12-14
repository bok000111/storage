#!/bin/sh

exec docker run --rm --name postgres-dev \
  -e POSTGRES_USER=myuser \
  -e POSTGRES_PASSWORD=mypassword \
  -e POSTGRES_DB=mydb \
  -p 5432:5432 \
  postgres:14.15-alpine3.20