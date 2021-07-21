# TensorFlow Lite

This example demonstrates how to run TensorFlow Lite v1.9. In particular, the
example runs `label_image` program on Graphene. It reads an input image
`image.bmp` from the current directory and uses TensorFlow Lite and the
Inception v3 model to label the image.

To install build dependencies on Ubuntu there is a convenience target invoked
with `make install-dependencies-ubuntu`. This also serves as a starting point to
figure out which packages to install on newer releases of Ubuntu.

# Quick Start

To build TensorFlow Lite and Graphene artifacts:
- without SGX do `make`
- with SGX do `make SGX=1 `

To run the image labeling example:
- without Graphene do `make run-native`
- with Graphene do `make run-graphene`
- with Graphene-SGX do `make SGX=1 run-graphene`
