#!/usr/bin/env bash
set -euo pipefail

# --- CA (root of trust, never used directly for TLS) ---
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout ca.key -out ca.crt \
  -days 3650 -nodes \
  -subj "/CN=sozo-ca"

# --- Write ext files ---
cat > server_ext.cnf << 'EOF'
[v3_req]
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:localhost
EOF

cat > client_ext.cnf << 'EOF'
[v3_req]
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth,serverAuth
subjectAltName=DNS:client
EOF

# --- Server key + CSR ---
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout server.key -out server.csr \
  -nodes \
  -subj "/CN=localhost"

# --- Sign server cert with CA (v3) ---
openssl x509 -req \
  -in server.csr \
  -CA ca.crt -CAkey ca.key \
  -CAcreateserial \
  -out server.crt \
  -days 3650 \
  -extensions v3_req \
  -extfile server_ext.cnf

# --- Client key + CSR ---
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout client.key -out client.csr \
  -nodes \
  -subj "/CN=client"

# --- Sign client cert with CA (v3) ---
openssl x509 -req \
  -in client.csr \
  -CA ca.crt -CAkey ca.key \
  -CAcreateserial \
  -out client.crt \
  -days 3650 \
  -extensions v3_req \
  -extfile client_ext.cnf

# --- Cleanup ---
rm -f client.csr server.csr server_ext.cnf client_ext.cnf ca.srl

echo "Generated:"
echo "  ca.key / ca.crt           — CA (root of trust)"
echo "  server.key / server.crt   — server cert signed by CA"
echo "  client.key / client.crt   — client cert signed by CA (for mTLS)"