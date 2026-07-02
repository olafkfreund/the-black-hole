#!/usr/bin/env bash
# Generates a demo client-CA + one sample client certificate for Janus mTLS.
# Output: certs/ca.crt, certs/ca.key, certs/client.crt, certs/client.key
# The CA cert (ca.crt) is what the ingress verifies against; keep ca.key + client.key SECRET.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs && cd certs

openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/C=GB/O=Janus Demo/OU=Security/CN=Janus Demo Client CA" -out ca.crt

openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj "/C=GB/O=Janus Demo/OU=Clients/CN=demo-mcp-client" -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 825 -sha256
rm -f client.csr ca.srl
echo "Generated: ca.crt ca.key client.crt client.key"
echo "Create the ingress CA secret:  kubectl -n janus create secret generic janus-client-ca --from-file=ca.crt=certs/ca.crt"
echo "Test:  curl --cert certs/client.crt --key certs/client.key https://janus.<host>/mcp"
