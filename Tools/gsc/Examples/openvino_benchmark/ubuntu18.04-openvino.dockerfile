From ubuntu:18.04

ARG DEBIAN_FRONTEND=noninteractive

# Install prerequisites
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    git \
    wget \
    python3 \
    python3-pip \
    numactl \
    gnupg \
    build-essential \
    cmake

# Install OpenVINO
ARG PUBLIC_KEY="https://apt.repos.intel.com/openvino/2021/GPG-PUB-KEY-INTEL-OPENVINO-2021"
ARG APT_REPOSITORY="deb https://apt.repos.intel.com/openvino/2021 all main"
ARG BUILD_ID

RUN curl -o GPG-PUB-KEY-INTEL-OPENVINO-2021 ${PUBLIC_KEY} && \
    apt-key add GPG-PUB-KEY-INTEL-OPENVINO-2021 && \
    echo ${APT_REPOSITORY} | tee - a /etc/apt/sources.list.d/intel-openvino-2021.list && \
    apt-get update && apt-get install -y --no-install-recommends "intel-openvino-dev-ubuntu18-${BUILD_ID}" && \
    rm -rf /var/lib/apt/lists/*

# Build apps
RUN cd /opt/intel/openvino_2021/inference_engine/samples/cpp && \
    ./build_samples.sh && \
    cd / && \
    ln -sf ~/inference_engine_cpp_samples_build/intel64/Release/benchmark_app benchmark_app

# Download models benchmark app
RUN cd /opt/intel/openvino_2021/deployment_tools/open_model_zoo/tools/downloader && \
    pip3 install -r ./requirements.in && \
    cd /opt/intel/openvino_2021/deployment_tools/model_optimizer && \
    python3 -m pip install --upgrade pip setuptools && \
    pip3 install -r requirements.txt && \
    cd /opt/intel/openvino_2021/deployment_tools/open_model_zoo/tools/downloader && \
    python3 ./downloader.py --name resnet-50-tf -o /model && \
    python3 ./converter.py --mo /opt/intel/openvino_2021/deployment_tools/model_optimizer/mo.py --name resnet-50-tf -d /model -o /model && \
    python3 ./downloader.py --name bert-large-uncased-whole-word-masking-squad-0001 -o /model && \
    python3 ./converter.py --mo /opt/intel/openvino_2021/deployment_tools/model_optimizer/mo.py --name bert-large-uncased-whole-word-masking-squad-0001 -d /model -o /model && \
    python3 ./downloader.py --name bert-large-uncased-whole-word-masking-squad-int8-0001 -o /model && \
    python3 ./converter.py --mo /opt/intel/openvino_2021/deployment_tools/model_optimizer/mo.py --name bert-large-uncased-whole-word-masking-squad-int8-0001 -d /model -o /model && \
    python3 ./downloader.py --name brain-tumor-segmentation-0001 -o /model && \
    python3 ./converter.py --mo /opt/intel/openvino_2021/deployment_tools/model_optimizer/mo.py --name brain-tumor-segmentation-0001 -d /model -o /model && \
    python3 ./downloader.py --name brain-tumor-segmentation-0002 -o /model && \
    python3 ./converter.py --mo /opt/intel/openvino_2021/deployment_tools/model_optimizer/mo.py --name brain-tumor-segmentation-0002 -d /model -o /model && \
    python3 ./downloader.py --name ssd_mobilenet_v1_coco  -o /model && \
    python3 ./converter.py --mo /opt/intel/openvino_2021/deployment_tools/model_optimizer/mo.py --name ssd_mobilenet_v1_coco -d /model -o /model

ENV LD_LIBRARY_PATH = "${LD_LIBRARY_PATH}:/opt/intel/openvino_2021/deployment_tools/inference_engine/external/tbb/lib:/opt/intel/openvino_2021/deployment_tools/inference_engine/lib/intel64:/opt/intel/openvino_2021/deployment_tools/ngraph/lib"

RUN echo "source /opt/intel/openvino_2021/bin/setupvars.sh" | tee -a /root/.bashrc

ENTRYPOINT ["./benchmark_app"]
