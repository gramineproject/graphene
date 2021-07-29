# Graphene Attestation Inside AKS cluster

This guide demonstrates how Graphene DCAP attestation quote can be generated and verified from
within an AKS cluster. Here, we provide an end to end example to help CSPs integrate graphene’s
RA-TLS attestation and secret provisioning feature with a confidential compute cluster managed by
Azure Kubernetes Service. The necessary reference wrappers that will enable graphene to use AKS
components such as the AESMD and quote provider libraries are contributed. A microservice deployment
is also provided for the RA-TLS verifier module that can be readily deployed to the AKS cluster.

## Create client and server images for graphene attestation samples

This demonstration is created for ``graphene/Examples/ra-tls-secret-prov`` sample.

- Steps to create ra-tls-secret-prov-server image for AKS:

```sh
Please refer graphene/Tools/gsc/images/aks-ra-tls-secret-prov-server.dockerfile
```

- Steps to create ra-tls-secret-prov-client gsc image for AKS:

```sh
STEP 1: Prepare client to connect with remote ra-tls-secret-prov server hosted inside AKS cluster
        1.1 Provide server dns name <AKS-DNS-NAME> as loader.env.SECRET_PROVISION_SERVERS value
            inside graphene/Tools/gsc/test/ubuntu18.04-ra-tls-secret-prov.manifest file.

STEP 2: Create gsc image for ra-tls-secret-prov client
        2.1 Gsc image creation steps for ra-tls-secret-prov-client image are described
            inside graphene/Tools/gsc/test/ubuntu18.04-ra-tls-secret-prov.manifest.

STEP 3: Push resulting image to Docker Hub or your preferred registry
        $ docker tag <gsc-ra-tls-secret-prov-client-img> \
          <dockerhubusername>/<aks-gsc-ra-tls-secret-prov-client-img>
        $ docker push <dockerhubusername>/<aks-gsc-ra-tls-secret-prov-client-img>

STEP 4: Deploy <aks-gsc-ra-tls-secret-prov-client-img> in confidential compute AKS cluster
        Reference deployment file: graphene/Tools/gsc/images/aks-client-deployment.yaml
```

## Deploy both client and server images inside AKS confidential compute cluster

AKS confidential compute cluster can be created using following
[link](https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-aks-get-started).

Graphene performs out-of-proc mode DCAP quote generation. Out-of-proc mode quote generation requires aesmd
service. To fulfill this requirement, AKS provides
[sgxquotehelper daemonset](https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-out-of-proc-attestation).
This feature exposes aesmd service for the container node. The service will internally connect with
az-dcap-client to fetch the platform collateral required for quote generation. In this demo, the
``aks-client-deployment.yaml`` uses aesmd service exposed by AKS with the help of sgxquotehelper
plugin.

In the ra-tls-secret-prov example, the client will generate out-of-proc mode sgx quote that will be
embedded inside RA-TLS certificate. On receiving the quote, the server will internally verify it
using libsgx-dcap-quote-verify library via az-dcap-client library. Here,
``aks-server-deployment.yaml`` will deploy a ra-tls-secret-prov server container inside AKS cluster.

**Deployment**<br>

```sh
$ kubectl apply -f aks-server-deployment.yaml
```

Once the server container is in running state, start the client container as shown below

```sh
$ kubectl apply -f aks-client-deployment.yaml
```

At this stage, a successful RA-TLS verification would be completed, and the secrets have been
provisioned from the server to the client container.

## Steps to verify successful quote generation and quote verification using logs

Verify the client job is completed

```sh
$ kubectl get jobs -l app=gsc-ra-tls-secret-prov-client
```

Receive logs to verify the secret has been provisioned to the client

```sh
$ kubectl logs -l app=gsc-ra-tls-secret-prov-client --tail=50
```

**Expected Output**<br>

--- Received secret1 = 'XXXXXXXXXXXXXXXXXXXXXXXXXXX', secret2 = 'XX'

Delete both client and server containers

```sh
$ kubectl apply -f aks-server-deployment.yaml
$ kubectl apply -f aks-client-deployment.yaml
```
