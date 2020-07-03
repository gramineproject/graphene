# Secret Provisioning Minimal Examples

This directory contains the Makefile, the template client manifests, and the minimal server and
clients written against the Secret Provisioning library.  This was tested on a machine with SGX v1
and Ubuntu 18.04.

This example uses the Secret Provisioning libraries `secret_prov_attest.so` for clients and
`secret_prov_verify_epid.so`/`secret_prov_verify_dcap.so` for server. These libraries can be found
under `Pal/src/host/Linux-SGX/tools/ra-tls`. Additionally, mbedTLS libraries are required. For
ECDSA/DCAP attestation, the DCAP software infrastructure must be installed and working correctly on
the host.

The current examples work with both EPID (IAS) and ECDSA (DCAP) remote attestation schemes. For
more documentation, refer to `Pal/src/host/Linux-SGX/tools/README.rst`.


## Secret Provisioning server

The server is supposed to run on a trusted machine (not in the SGX enclave). The server listens for
client connections. For each connected client, the server verifies the client's RA-TLS certificate
and the embedded SGX quote and, if verification succeeds, sends the first secret back to the client
(hard-coded dummy string `This is a secret string!`). If the client requests a second secret, the
server sends the dummy integer `42` as the second secret.

If the Secret Provisioning library `libsecret_prov_verify_epid.so`/`libsecret_prov_verify_dcap.so`
is not preloaded, then the server exits with error message.


## Secret Provisioning clients

There are two clients in this example: a minimal one and a more flexible one. The former relies
on constructor-time secret provisioning and gets the first (and only) secret from the environment
variable `SECRET_PROVISION_SECRET_STRING`. The second uses a programmatic C API to get two secrets
from the server. As part of secret provisioning flow, both clients create a self-signed RA-TLS
certificate with the embedded SGX quote, send it to the server for verification, and expect secrets
in return.

If the Secret Provisioning library `libsecret_prov_attest.so` is not preloaded, then the client
exits with error message.


# Quick Start

Please make sure that the corresponding RA-TLS libraries (EPID or DCAP versions) are built.

- Secret Provisioning flows, EPID-based (IAS) attestation:

```sh
RA_CLIENT_SPID=12345678901234567890123456789012 RA_CLIENT_LINKABLE=0 make app epid

RA_TLS_EPID_API_KEY=12345678901234567890123456789012 \
RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 \
LD_PRELOAD="libsecret_prov_verify_epid.so" ./secret_prov_server &

# test minimal client
SGX=1 ./pal_loader ./secret_prov_min_client

# test normal client
SGX=1 ./pal_loader ./secret_prov_client

kill %%
```

- Secret Provisioning flows, ECDSA-based (DCAP) attestation:

```sh
make app dcap

RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 \
LD_PRELOAD="libsgx_urts.so libsecret_prov_verify_dcap.so" ./secret_prov_server &

# test minimal client
SGX=1 ./pal_loader ./secret_prov_min_client

# test normal client
SGX=1 ./pal_loader ./secret_prov_client

kill %%
```
