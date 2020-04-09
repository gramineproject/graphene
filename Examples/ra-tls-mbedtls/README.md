# RA-TLS Minimal Example

This directory contains the Makefile, the template server manifest, and the minimal server and
client written against the mbedTLS 2.21.0 library.  This was tested on a machine with SGX v1 and
Ubuntu 18.04.

The server and client are based on `ssl_server.c` and `ssl_client.c` example programs shipped with
mbedTLS. We modified them to allow using RA-TLS flows if the programs detect this library is
preloaded via the `LD_PRELOAD` trick.  In particular, the server uses a self-signed RA-TLS certificate
with the SGX quote embedded in it via `ra_tls_create_key_and_crt()`. The client uses an RA-TLS
verification callback to verify the server RA-TLS certificate via `ra_tls_verify_callback()`.

This example uses the RA-TLS libraries `ra_tls_attest.so` for server and `ra_tls_verify.so` for
client. These libraries are found under `Pal/src/host/Linux-SGX/tools/ra-tls`. Additionally, mbedTLS
libraries are required to correctly run RA-TLS, the client, and the server.

The current example works only with SGX EPID remote attestation.


## RA-TLS server

The server is supposed to run in the SGX enclave with Graphene and RA-TLS preloaded. If RA-TLS
library is not preloaded, the server falls back to using normal X.509 PKI flows.

The RA-TLS library expects the following information in the manifest:

- `sgx.ra_client_spid` -- client SPID for EPID remote attestation.
- `sgx.ra_client_linkable` -- client linkable/unlinkable attestation policy.

The RA-TLS library uses the following environment variables if available:

- `RA_TLS_CERT_TIMESTAMP_NOT_BEFORE` -- the generated RA-TLS certificate uses this
  timestamp-not-before value, in the format "20010101000000" (this is also the default value if
environment variable is not available).
- `RA_TLS_CERT_TIMESTAMP_NOT_AFTER` -- the generated RA-TLS certificate uses this
  timestamp-not-after value, in the format "20301231235959" (this is also the default value if
environment variable is not available).


## RA-TLS client

The client is supposed to run on a trusted machine (not in the SGX enclave).  If RA-TLS library is
not preloaded, the client falls back to using normal X.509 PKI flows.

The RA-TLS library uses the following environment variables if available:

- `RA_TLS_EPID_API_KEY` (mandatory) -- client API key for EPID remote attestation.

- `RA_TLS_MRSIGNER` (optional) -- verify that the server enclave has this `MRSIGNER`. This is a hex
  string.
- `RA_TLS_MRENCLAVE` (optional) -- verify that the server enclave has this `MRENCLAVE`. This is a hex
  string.
- `RA_TLS_ISV_PROD_ID` (optional) -- verify that the server enclave has this `ISV_PROD_ID`. This is a
  decimal string.
- `RA_TLS_ISV_SVN` (optional) -- verify that the server enclave has this `ISV_SVN`. This is a decimal
  string.

- `RA_TLS_ALLOW_OUTDATED_TCB` (optional) -- whether to allow outdated TCB as returned in the IAS
  attestation report. Any value that is not `0 / false / FALSE` means "allow outdated TCB".
Outdated TCB is not allowed by default.

- `RA_TLS_REPORT_URL` (optional) -- URL for IAS "verify attestation evidence" API endpoint. If not
  specified, the default hard-coded URL for IAS is used.
- `RA_TLS_SIGRL_URL` (optional) -- URL for IAS "Retrieve SigRL" API endpoint. If not specified, the
  default hard-coded URL for IAS is used.
- `RA_TLS_IAS_PUB_KEY_PEM` (optional) -- public key of IAS. If not specified, the default hard-coded
  public key is used.


# Quick Start

- Normal non-RA-TLS flows; without SGX and without Graphene:

```sh
make
./server &
./client
# client will succesfully connect to the server via normal x.509 PKI flows
kill %%
```

- RA-TLS flows with SGX and with Graphene:

```sh
RA_CLIENT_SPID=12345678901234567890123456789012 RA_CLIENT_LINKABLE=0 make
SGX=1 ./pal_loader ./server &
RA_TLS_EPID_API_KEY=12345678901234567890123456789012 RA_TLS_ALLOW_OUTDATED_TCB=1 \
RA_TLS_MRENCLAVE=1234567890123456789012345678901234567890123456789012345678901234 \
RA_TLS_MRSGINER=1234567890123456789012345678901234567890123456789012345678901234 \
RA_TLS_ISV_PROD_ID=0 RA_TLS_ISV_SVN=0 \
LD_PRELOAD=$PWD/libra_tls_verify.so ./client
# client will succesfully connect to the server via normal x.509 PKI flows
kill %%
```
