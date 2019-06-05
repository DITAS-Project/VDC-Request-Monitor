#! /bin/sh
docker pull ditas/keycloak:latest
docker build -t elasticsearch_metrics -f Dockerfile.elastic .
