#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
work=".work"
rm -rf "$work" && mkdir "$work"
trap 'rm -rf "$work"' EXIT
touch "$work/index.txt"
echo 1000 > "$work/serial"
cat > "$work/ca.cnf" <<CONF
[ca]
default_ca = test_ca
[test_ca]
database = $work/index.txt
serial = $work/serial
new_certs_dir = $work
default_md = sha256
policy = any
unique_subject = no
[any]
commonName = supplied
[root]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[intermediate]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = \${ENV::SAN}
[leaf_no_san]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
CONF
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
csr() { openssl req -new -key "$1" -subj "/CN=$2" -out "$work/request.csr"; }
sign() { openssl ca -batch -notext -config "$work/ca.cnf" "$@" -in "$work/request.csr" 2>/dev/null; }
export SAN="DNS:ok.fixture-scan.dev"
key ca.key && csr ca.key "Scanner Test Root"
sign -selfsign -keyfile ca.key -extensions root -startdate 20260101000000Z -enddate 21260101000000Z -out ca.pem
key intermediate.key && csr intermediate.key "Scanner Test Intermediate"
sign -cert ca.pem -keyfile ca.key -extensions intermediate -startdate 20260101000000Z -enddate 21260101000000Z -out intermediate.pem
key leaf.key && csr leaf.key "ok.fixture-scan.dev"
leaf() { sign -cert intermediate.pem -keyfile intermediate.key "$@"; }
SAN="DNS:ok.fixture-scan.dev,DNS:www.fixture-scan.dev" leaf -extensions leaf -startdate 20260101000000Z -enddate 21260101000000Z -out ok.pem
SAN="DNS:ok.fixture-scan.dev" leaf -extensions leaf -startdate 20200101000000Z -enddate 20210101000000Z -out expired.pem
SAN="DNS:other.fixture-scan.dev" leaf -extensions leaf -startdate 20260101000000Z -enddate 21260101000000Z -out wrong-name.pem
leaf -extensions leaf_no_san -startdate 20260101000000Z -enddate 21260101000000Z -out no-san.pem
SAN="DNS:ok.fixture-scan.dev" sign -selfsign -keyfile leaf.key -extensions leaf -startdate 20260101000000Z -enddate 21260101000000Z -out self-signed.pem
