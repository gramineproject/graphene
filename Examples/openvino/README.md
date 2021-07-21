# OpenVINO

This directory contains a Makefile and a template manifest for the most
recent version of OpenVINO toolkit (as of this writing, version 2020.4).
We use the "Object Detection C++ Sample SSD" (object_detection_sample_ssd)
example from the OpenVINO distribution as a concrete application running
under Graphene-SGX. We test only the CPU backend (i.e., no GPU or FPGA).

We build OpenVINO from the source code instead of using an existing installation.
**Note:** the build process requires ~1.1GB of disk space and takes ~20 minutes.

We also download the Open Model Zoo repository and use the SSD300 pre-trained
model from it. **Note:** the model zoo requires ~350MB of disk space.

# Prerequisites

For Ubuntu 18.04, install the following prerequisite packages:

* Install CMake version >= 3.11 (on Ubuntu 18.04, this may require installing
  Cmake from a non-official APT repository like Kitware).

* Install libusb version >= 1.0.0 (`sudo apt install libusb-1.0-0-dev`).

* Install libtbb-dev

* Install packages for Python3:
  `pip3 install pyyaml numpy networkx test-generator defusedxml protobuf>=3.6.1`

# Quick Start

```sh
# build OpenVINO together with object_detection_sample_ssd and the final manifest;
# note that it also downloads the SSD300 model and transforms it from the Caffe
# format to an optimized Intermediate Representation (IR)
make SGX=1

# run original OpenVINO/object_detection_sample_ssd
# note that this assumes the Release build of OpenVINO (no DEBUG=1)
./openvino/bin/intel64/Release/object_detection_sample_ssd -i images/horses.jpg \
    -m model/VGG_VOC0712Plus_SSD_300x300_ft_iter_160000.xml -d CPU

# run OpenVINO/object_detection_sample_ssd in non-SGX Graphene
graphene-direct object_detection_sample_ssd -i images/horses.jpg \
    -m model/VGG_VOC0712Plus_SSD_300x300_ft_iter_160000.xml -d CPU

# run OpenVINO/object_detection_sample_ssd in Graphene-SGX
graphene-sgx object_detection_sample_ssd -i images/horses.jpg \
    -m model/VGG_VOC0712Plus_SSD_300x300_ft_iter_160000.xml -d CPU

# Each of these commands produces an image out_0.bmp with detected objects
xxd out_0.bmp   # or open in any image editor
```
