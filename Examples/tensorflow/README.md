This example demonstrates how to run TensorFlow (v1.9) Lite's label_image example on Graphene. Reads an input image `image.bmp` from the current directory and uses TensorFlow lite and the Inception v3 model to label the image.

Known limitations:

- Tested on Ubuntu 16.04 with Graphene [commit 030a088](https://github.com/oscarlab/graphene/tree/030a0888926f315710da94ee6f855c466059cf6c). Ubuntu 18.04 should work, but have not tested.

To install build dependencies on Ubuntu 16.04 there is a convenience target invoked with `make install-dependencies-ubuntu`. This also serves as a starting point to figure out which packages to install on newer releases of Ubuntu.

To build TensorFlow and Graphene artifacts:
- without SGX do `make`
- with SGX do `make SGX=1 `

To run the image labeling example of TensorFlow:
- without Graphene do `make run-native`
- with Graphene do `make run-graphene`
- with Graphene-SGX do `make SGX=1 run-graphene`
