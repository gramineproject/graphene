# Secret Provisioning Minimal Examples

This directory contains the Makefile, the template client manifests, and the
minimal server and clients written against the Secret Provisioning library.

This example uses the Secret Provisioning libraries `secret_prov_attest.so` for
clients and `secret_prov_verify_epid.so`/`secret_prov_verify_dcap.so` for
server. These libraries can be found under
`Pal/src/host/Linux-SGX/tools/ra-tls`. Additionally, mbedTLS libraries are
required. For ECDSA/DCAP attestation, the DCAP software infrastructure must be
installed and work correctly on the host.

The current example works with both EPID (IAS) and ECDSA (DCAP) remote
attestation schemes. For more documentation, refer to
https://graphene.readthedocs.io/en/latest/attestation.html.

## Secret Provisioning server

The server is supposed to run on a trusted machine (not in the SGX enclave). The
server listens for client connections. For each connected client, the server
verifies the client's RA-TLS certificate and the embedded SGX quote and, if
verification succeeds, sends the first secret back to the client (the master key
for protected files, read from `files/wrap-key`). If the client requests a
second secret, the server sends the dummy string `42` as the second secret.

There are two versions of the server: the EPID one and the DCAP one. Each of
them links against the corresponding EPID/DCAP secret-provisioning library at
build time.


## Secret Provisioning clients

There are three clients in this example:

1. Minimal client. It relies on constructor-time secret provisioning and gets
   the first (and only) secret from the environment variable
   `SECRET_PROVISION_SECRET_STRING`.
2. Feature-rich client. It uses a programmatic C API to get two secrets from the
   server.
3. Protected-files client. Similarly to the minimal client, it relies on
   constructor-time secret provisioning and instructs Graphene to consider the
   provisioned secret as the wrap (master) key for the Protected Files feature.
   After the master key is applied, the client reads an encrypted file
   `files/input.txt`.

As part of secret provisioning flow, all clients create a self-signed RA-TLS
certificate with the embedded SGX quote, send it to the server for verification,
and expect secrets in return.

The minimal and the protected-files clients rely on the `LD_PRELOAD` trick that
preloads `libsecret_prov_attest.so` and runs it before the clients' main logic.
The feature-rich client links against `libsecret_prov_attest.so` explicitly at
build time.

# Quick Start

Please make sure that the corresponding RA-TLS libraries (EPID or DCAP versions)
are built.

First, start with adding the library directory to `LD_LIBRARY_PATH`:

```sh
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./libs
```

Remember to undo this change after finishing the tutorial (or just do everything
in a subshell).

- Secret Provisioning flows, EPID-based (IAS) attestation:

```sh
RA_CLIENT_SPID=12345678901234567890123456789012 RA_CLIENT_LINKABLE=0 make app epid files/input.txt

RA_TLS_EPID_API_KEY=12345678901234567890123456789012 \
RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 ./secret_prov_server_epid &

# test minimal client
graphene-sgx ./secret_prov_min_client

# test feature-rich client
graphene-sgx ./secret_prov_client

# test protected-files client
graphene-sgx ./secret_prov_pf_client

kill %%
```

- Secret Provisioning flows, ECDSA-based (DCAP) attestation:

```sh
# make sure RA-TLS DCAP libraries are built in Graphene via:
#   cd graphene/Pal/src/host/Linux-SGX/tools/ra-tls && make dcap

make app dcap files/input.txt

RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 ./secret_prov_server_dcap &

# test minimal client
graphene-sgx ./secret_prov_min_client

# test feature-rich client
graphene-sgx ./secret_prov_client

# test protected-files client
graphene-sgx ./secret_prov_pf_client

kill %%
```
