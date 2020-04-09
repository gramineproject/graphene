# RA-TLS Minimal Example

This directory contains the Makefile, the template server manifest, and the minimal server and
client written against the mbedTLS 2.21.0 library.  This was tested on a machine with SGX v1 and
Ubuntu 18.04.

The server and client are based on `ssl_server.c` and `ssl_client.c` example programs shipped with
mbedTLS. We modified them to allow using RA-TLS flows if the programs detect this library is
preloaded via the `LD_PRELOAD` trick.  In particular, the server uses a self-signed RA-TLS cert
with the SGX quote embedded in it via `ra_tls_create_key_and_crt()`. The client uses an RA-TLS
verification callback to verify the server RA-TLS certificate via `ra_tls_verify_callback()`.

This example uses the RA-TLS libraries `ra_tls_attest.so` for server and `ra_tls_verify_epid.so`/
`ra_tls_verify_dcap.so` for client. These libraries are found under
`Pal/src/host/Linux-SGX/tools/ra-tls`. Additionally, mbedTLS libraries are required to correctly
run RA-TLS, the client, and the server. For ECDSA/DCAP attestation, the DCAP software
infrastructure must be installed and working correctly on the host.

The current example works with both EPID (IAS) and ECDSA (DCAP) remote attestation schemes. For
more documentation, refer to `Pal/src/host/Linux-SGX/tools/README.rst`.


## RA-TLS server

The server is supposed to run in the SGX enclave with Graphene and RA-TLS preloaded. If RA-TLS
library `ra_tls_attest.so` is not preloaded, the server falls back to using normal X.509 PKI flows.

If server is run with any command-line options (the only important thing is to have at least one
option), then the server will maliciously modify the SGX quote before sending to the client. This
is useful for testing purposes.

## RA-TLS client

The client is supposed to run on a trusted machine (*not* in an SGX enclave). If RA-TLS library
`ra_tls_verify_epid.so` or `ra_tls_verify_dcap.so` is not preloaded, the client falls back to using
normal X.509 PKI flows.

If client is run without command-line options, it uses default RA-TLS verification callback that
compares `MRENCLAVE`, `MRSIGNER`, `ISV_PROD_ID` and `ISV_SVN` against the corresonding `RA_TLS_*`
environment variables. To run the client with its own verification callback, execute it with four
command-line options (see the source code for details).


# Quick Start

- Normal non-RA-TLS flows; without SGX and without Graphene:

```sh
make app
./server &
./client
# client will successfully connect to the server via normal x.509 PKI flows
kill %%
```

- RA-TLS flows with SGX and with Graphene, EPID-based (IAS) attestation:

```sh
# replace dummy values with your SPID, linkable setting, API key, MRENCLAVE, etc!
make clean
RA_CLIENT_SPID=12345678901234567890123456789012 RA_CLIENT_LINKABLE=0 make app epid

SGX=1 ./pal_loader ./server &

RA_TLS_EPID_API_KEY=12345678901234567890123456789012 \
RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 \
RA_TLS_MRENCLAVE=1234567890123456789012345678901234567890123456789012345678901234 \
RA_TLS_MRSIGNER=1234567890123456789012345678901234567890123456789012345678901234 \
RA_TLS_ISV_PROD_ID=0 RA_TLS_ISV_SVN=0 \
LD_PRELOAD="$PWD/libra_tls_verify_epid.so" ./client

# client will successfully connect to the server via RA-TLS/EPID flows
kill %%
```

- RA-TLS flows with SGX and with Graphene, ECDSA-based (DCAP) attestation:

```sh
# replace dummy values with your MRENCLAVE, MRSIGNER, etc!
make clean
make app dcap

SGX=1 ./pal_loader ./server &

RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 \
RA_TLS_MRENCLAVE=1234567890123456789012345678901234567890123456789012345678901234 \
RA_TLS_MRSIGNER=1234567890123456789012345678901234567890123456789012345678901234 \
RA_TLS_ISV_PROD_ID=0 RA_TLS_ISV_SVN=0 \
LD_PRELOAD="libsgx_urts.so $PWD/libra_tls_verify_dcap.so" \
./client

# client will successfully connect to the server via RA-TLS/DCAP flows
kill %%
```

- RA-TLS flows with SGX and with Graphene, client with its own verification callback:

```sh
# replace dummy values with your MRENCLAVE, MRSIGNER, etc!
make clean
make app dcap

SGX=1 ./pal_loader ./server &

# arguments are: MRENCLAVE in hex, MRSIGNER in hex, ISV_PROD_ID as dec, ISV_SVN as dec
LD_PRELOAD="libsgx_urts.so $PWD/libra_tls_verify_dcap.so" ./client \
    1234567890123456789012345678901234567890123456789012345678901234 \
    1234567890123456789012345678901234567890123456789012345678901234 \
    0 0

# client will successfully connect to the server via RA-TLS/DCAP flows
kill %%
```

- RA-TLS flows with SGX and with Graphene, server sends malicious SGX quote:

```sh
make clean
make app dcap

SGX=1 ./pal_loader ./server dummy-option &
LD_PRELOAD="libsgx_urts.so $PWD/libra_tls_verify_dcap.so" ./client

# client will fail to verify the malicious SGX quote and will *not* connect to the server
kill %%
```
