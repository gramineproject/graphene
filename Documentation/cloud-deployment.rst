Cloud Deployment
================

.. highlight:: sh

Graphene without Intel SGX can be deployed on arbitrary cloud VMs. Please see
our :doc:`quickstart` guide for the details.

To deploy Graphene with Intel SGX, the cloud VM has to support Intel SGX. Please
see the installation and usage guide for each cloud VM offering individually
below (currently only for Microsoft Azure).

Azure confidential computing VMs
--------------------------------

`Azure confidential computing services
<https://azure.microsoft.com/en-us/solutions/confidential-compute/>`__ are
generally available and provide access to VMs with Intel SGX enabled in `DCsv2
VM instances
<https://docs.microsoft.com/en-us/azure/virtual-machines/dcv2-series>`__. The
description below uses a VM running Ubuntu 18.04.

Prerequisites
^^^^^^^^^^^^^

Update and install the required packages for Graphene::

   sudo apt-get update
   sudo apt-get install -y autoconf bison build-essential gawk \
       libcurl4-openssl-dev libprotobuf-c-dev meson protobuf-c-compiler \
       python3 python3-click python3-jinja2 python3-pip python3-protobuf \
       wget
   python3 -m pip install toml>=0.10

Graphene requires the kernel to support FSGSBASE x86 instructions. Older Azure
Confidential Compute VMs may not contain the required kernel patches and need to
be updated.

To be able to run all tests also install::

    sudo apt-get install -y libunwind8 python3-pyelftools python3-pytest

Building
^^^^^^^^

#. Clone Graphene::

       git clone https://github.com/oscarlab/graphene.git
       cd graphene

#. Prepare the signing keys::

       openssl genrsa -3 -out Pal/src/host/Linux-SGX/signer/enclave-key.pem 3072

#. Build Graphene::

       make ISGX_DRIVER_PATH=/usr/src/linux-headers-`uname -r`/arch/x86/ SGX=1
       meson setup build/ --buildtype=release -Dsgx=enabled -Ddirect=disabled
       ninja -C build/
       sudo ninja -C build/ install

#. Build and run :program:`helloworld`::

       cd LibOS/shim/test/regression
       make SGX=1
       make SGX=1 sgx-tokens
       graphene-sgx helloworld

Azure Kubernetes Services (AKS)
-------------------------------

Azure Kubernetes Service (AKS) offers a popular deployment technique relying on
Azure's cloud resources. AKS hosts Kubernetes pods in Azure confidential compute
VMs and exposes the underlying confidential compute hardware. In particular,
`Graphene Shielded Containers (GSC)
<https://graphene.readthedocs.io/en/latest/manpages/gsc.html>`__ translate
existing Docker images to graphenized Docker images, which can be deployed in
AKS. Graphenized Docker images execute the application inside an Intel SGX
enclave using the Graphene Library OS, thus enabling confidential containers
functions on AKS.

This section describes the workflow to create an AKS cluster with confidential
compute VMs, graphenize a simple application, and deploy the graphenized Docker
image in an AKS cluster.

Prerequisites
^^^^^^^^^^^^^

Follow the instructions on the `AKS Confidential Computing Quick Start guide
<https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-aks-get-started>`__
to provision an AKS cluster with Intel SGX enabled worker nodes.

Follow the `instructions
<https://graphene.readthedocs.io/en/latest/manpages/gsc.html>`__ to set up
Graphene Shielded Containers and create your own enclave key.

Graphenizing Python Docker image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This section demonstrate how to translate the Python Docker Hub image to a
graphenized image, which is ready to deploy in a confidential compute AKS
cluster.

.. warning::

   This example relies on insecure arguments provided at runtime and should not
   be used production. To use trusted arguments, please see the `manpage of GSC
   <https://graphene.readthedocs.io/en/latest/manpages/gsc.html#using-graphene-s-trusted-command-line-arguments>`__.

#. Pull Python image::

       docker pull python

#. Configure GSC to build graphenized images for AKS with the
   `Graphene Docker Image for AKS from Docker Hub
   <https://hub.docker.com/r/graphenelibos/aks>`__ by creating the following
   configuration file :file:`config.aks.yaml`::

       Distro: ubuntu18.04
       Graphene:
              Image: graphenelibos/aks:latest

#. Create the application-specific Manifest file :file:`python.manifest`::

       sgx.enclave_size = "256M"
       sgx.thread_num = 4

#. Graphenize the Python image and allow insecure runtime arguments::

       ./gsc build --insecure-args -c config.aks.yaml python python.manifest

#. Sign the graphenized image with your enclave signing key::

       ./gsc sign-image python enclave-key.pem

#. Push resulting image to Docker Hub or your preferred registry::

       docker tag gsc-python <dockerhubusername>/python:gsc-aks
       docker push <dockerhubusername>/python:gsc-aks

Deploying a "HelloWorld" Python Application in a confidential compute AKS cluster
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This example first created an AKS cluster capable to create Intel SGX enclaves
and then, created a graphenized Docker image of Python. The goal of this section
is to combine both by deploying the Python application in the AKS cluster.

#. Create job deployment file :file:`gsc-aks-python.yaml` for AKS. It specifies
   the underlying Docker image and the insecure arguments (in this case Python
   code to print "HelloWorld!")::

       apiVersion: batch/v1
       kind: Job
       metadata:
          name: gsc-aks-python
          labels:
             app: gsc-aks-python
       spec:
          template:
             metadata:
                labels:
                   app: gsc-aks-python
             spec:
                containers:
                - name: gsc-aks-python
                  image:  index.docker.io/<dockerhubusername>/python:gsc-aks
                  imagePullPolicy: Always
                  args: ["-c", "print('HelloWorld!')"]
                  resources:
                     limits:
                        kubernetes.azure.com/sgx_epc_mem_in_MiB: 25
                restartPolicy: Never
          backoffLimit: 0

#. You may need to follow this
   `guide <https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/>`__
   to pull from a private registry.

#. Deploy `gsc-aks-python` job::

       kubectl apply -f gsc-aks-python.yaml

#. Test job status::

       kubectl get jobs -l app=gsc-aks-python

#. Receive logs of job::

       kubectl logs -l app=gsc-aks-python

#. Delete job after completion::

       kubectl delete -f gsc-aks-python.yaml
