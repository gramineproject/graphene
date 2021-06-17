DISTRIBUTIONS ?= ubuntu18.04

TESTCASES ?= python3 python3-trusted-args base-python3 hello-world nodejs bash numpy pytorch
MAXTESTNUM ?= 11
TESTS = $(foreach D,$(DISTRIBUTIONS),$(foreach T,$(TESTCASES),$D-$T))

GRAPHENE_REPO ?= https://github.com/oscarlab/graphene.git
GRAPHENE_BRANCH ?= "2e737e69f076c60918f87d6829bb769925e75fec" # last working commit

# the below default values assume Linux 5.11+ with built-in SGX driver; see ../config.yaml.template
# for different options (legacy driver, out-of-tree DCAP driver, in-kernel driver)
SGXDRIVER_REPO ?=
SGXDRIVER_BRANCH ?=

DOCKER_BUILD_FLAGS ?= --rm --no-cache
GSC_BUILD_FLAGS ?= --rm --no-cache
KEY_FILE ?= ../enclave-key.pem
ENV_VARS ?=
IMAGE_SUFFIX ?=

# use "isgx" for legacy driver, "sgx/enclave" for DCAP driver, "sgx_enclave" for in-kernel driver
INTEL_SGX_DEVICE ?= sgx_enclave
# use "--device=/dev/gsgx" on Linux 5.8- (before FSGSBASE was merged), otherwise leave empty
ADDITIONAL_DEVICES ?=
# use if AESM daemon from the host is needed (e.g. for remote attestation), otherwise leave empty
ADDITIONAL_VOLUMES ?= --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket

DEVICES_VOLUMES = --device=/dev/${INTEL_SGX_DEVICE} ${ADDITIONAL_DEVICES} ${ADDITIONAL_VOLUMES}

.PHONY: all
all: $(KEY_FILE)
	for d in $(DISTRIBUTIONS); do \
		$(MAKE) $(addprefix gsc-$${d}-, $(TESTCASES)) || exit 1; \
	done

config-%.yaml:
	echo "Distro: \"$*\"" > config-$*.yaml
	echo "Graphene:" >> config-$*.yaml
	echo "    Repository: \"$(GRAPHENE_REPO)\"" >> config-$*.yaml
	echo "    Branch:     \"$(GRAPHENE_BRANCH)\"" >> config-$*.yaml
	echo "SGXDriver:" >> config-$*.yaml
	echo "    Repository: \"$(SGXDRIVER_REPO)\"" >> config-$*.yaml
	echo "    Branch:     \"$(SGXDRIVER_BRANCH)\"" >> config-$*.yaml;

$(KEY_FILE):
	openssl genrsa -3 -out $(KEY_FILE) 3072

.PRECIOUS: gsc-%-bash
gsc-%-bash: %-bash config-%.yaml
	echo "Building graphenized image $@..."
	cd .. && ./gsc build -c test/config-$*.yaml -L --insecure-args $(GSC_BUILD_FLAGS) $(addsuffix $(IMAGE_SUFFIX), $*-bash) test/bash.manifest
	cd .. && ./gsc sign-image -c test/config-$*.yaml $(addsuffix $(IMAGE_SUFFIX), $*-bash) $(notdir $(KEY_FILE))
	touch $@

.PRECIOUS: gsc-%-python3
gsc-%-python3: %-python3 %-python3.manifest config-%.yaml
	echo "Building graphenized image $@..."
	cd .. && ./gsc build -c test/config-$*.yaml -L --insecure-args $(GSC_BUILD_FLAGS) $(addsuffix $(IMAGE_SUFFIX), $*-python3) test/$*-python3.manifest
	cd .. && ./gsc sign-image -c test/config-$*.yaml $(addsuffix $(IMAGE_SUFFIX), $*-python3) $(notdir $(KEY_FILE))
	touch $@

.PRECIOUS: gsc-%-python3-trusted-args
gsc-%-python3-trusted-args: %-python3-trusted-args %-python3.manifest config-%.yaml
	echo "Building graphenized image $@..."
	cd .. && ./gsc build -c test/config-$*.yaml -L $(GSC_BUILD_FLAGS) $(addsuffix $(IMAGE_SUFFIX), $*-python3-trusted-args) test/$*-python3.manifest
	cd .. && ./gsc sign-image -c test/config-$*.yaml $(addsuffix $(IMAGE_SUFFIX), $*-python3-trusted-args) $(notdir $(KEY_FILE))
	touch $@

.PRECIOUS: gsc-%-pytorch
gsc-%-pytorch: %-pytorch %-pytorch.manifest config-%.yaml
	echo "Building graphenized image $@..."
	cd .. && ./gsc build -c test/config-$*.yaml -L --insecure-args $(GSC_BUILD_FLAGS) $(addsuffix $(IMAGE_SUFFIX), $*-pytorch) test/$*-pytorch.manifest
	cd .. && ./gsc sign-image -c test/config-$*.yaml $(addsuffix $(IMAGE_SUFFIX), $*-pytorch) $(notdir $(KEY_FILE))
	touch $@

.PRECIOUS: gsc-%-base-python3
gsc-%-base-python3: graphene-% %-base-python3 config-%.yaml
	printf "Distro: \"$*\"\nGraphene:\n   Image: \"graphene-$*$(IMAGE_SUFFIX)\"\n" > config-image-$*.yaml
	echo "Building graphenized image $@..."
	cd .. && ./gsc build -c test/config-image-$*.yaml -L --insecure-args $(GSC_BUILD_FLAGS) $(addsuffix $(IMAGE_SUFFIX), $*-base-python3) test/$*-python3.manifest
	cd .. && ./gsc sign-image -c test/config-image-$*.yaml $(addsuffix $(IMAGE_SUFFIX), $*-base-python3) $(notdir $(KEY_FILE))
	touch $@

.PRECIOUS: gsc-%
gsc-%: % config-%.yaml
	echo "Building graphenized image $@..."
	cd .. && ./gsc build -c test/config-$(firstword $(subst -, ,$*)).yaml -L --insecure-args $(GSC_BUILD_FLAGS) $(addsuffix $(IMAGE_SUFFIX), $*) test/$(*:gsc-%=%).manifest
	cd .. && ./gsc sign-image -c test/config-$(firstword $(subst -, ,$*)).yaml $(addsuffix $(IMAGE_SUFFIX), $*) $(notdir $(KEY_FILE))
	touch $@

.PRECIOUS: graphene-%
graphene-%: config-%.yaml
	echo "Building Graphene image $@..."
	cd .. && ./gsc build-graphene -c test/config-$*.yaml -L $(GSC_BUILD_FLAGS) $(addsuffix $(IMAGE_SUFFIX), $@)
	touch $@

.PRECIOUS: ubuntu18.04-base-%
ubuntu18.04-base-%: ubuntu18.04-%
	docker tag $(addsuffix $(IMAGE_SUFFIX), $^) $(addsuffix $(IMAGE_SUFFIX), $@)
	touch $@

.PRECIOUS: ubuntu18.04-%
ubuntu18.04-%: ubuntu18.04-%.dockerfile
	echo "Building base image $@.dockerfile..."
	docker build $(DOCKER_BUILD_FLAGS) -t $(addsuffix $(IMAGE_SUFFIX), $@) -f $@.dockerfile ../../../Examples
	touch $@

.PHONY: test
test: $(addprefix test-distro-, $(DISTRIBUTIONS))
	echo "[SUCCESS] Completed all GSC test cases"

.PHONY: test-distro-%
test-distro-%:
	echo "Testing $*."
	for t in $(shell seq 1 $(MAXTESTNUM)); do \
		printf "$${t}/$(MAXTESTNUM): "; \
		$(MAKE) test-$${t}-$* || exit 1; \
		printf "[SUCCESS]\\n"; \
	done
	echo "Successfully finished testing $*."

.PHONY: test-1-%
test-1-%: gsc-%-python3
	docker run $(addprefix -e , $(ENV_VARS)) $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) -c 'print("HelloWorld!")' 2>&1 | tee out
	grep -q "HelloWorld!" out
	$(RM) out

.PHONY: test-2-%
test-2-%: gsc-%-python3
	docker run $(addprefix -e , $(ENV_VARS)) $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) /graphene/Examples/scripts/helloworld.py  2>&1 | tee out
	grep -q "Hello World" out
	$(RM) out

.PHONY: test-3-%
test-3-%: gsc-%-python3-trusted-args
	docker run $(addprefix -e , $(ENV_VARS)) $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3-trusted-args) 2>&1 | tee out
	grep -q "HelloWorld!" out
	$(RM) out

.PHONY: test-4-%
test-4-%: gsc-%-python3
	docker run $(addprefix -e , $(ENV_VARS)) $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) -c 'import os;os.system("ls")' 2>&1 | tee out
	grep -q "entrypoint.manifest.sgx" out
	$(RM) out

.PHONY: test-5-%
test-5-%: gsc-%-python3
	docker run $(addprefix -e , $(ENV_VARS)) $(DEVICES_VOLUMES) -d -p 8005:8005 $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) /graphene/Examples/scripts/dummy-web-server.py 8005 | tee c.id
	sleep 30
	wget -q http://localhost:8005/ -O output
	grep -q "hi!" output
	cat c.id | head -n 1 | xargs docker container rm -f >/dev/null 2>/dev/null
	$(RM) c.id output

.PHONY: test-6-%
test-6-%: gsc-%-hello-world
	docker run $(addprefix -e , $(ENV_VARS)) $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-hello-world)  2>&1 | tee out
	grep -q "Hello World!" out
	$(RM) out

.PHONY: test-7-%
test-7-%: gsc-%-nodejs
	docker run $(addprefix -e , $(ENV_VARS)) $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-nodejs) -e 'console.log("HelloWorld");' 2>&1 | tee out
	grep -q "HelloWorld" out
	$(RM) out

.PHONY: test-8-%
test-8-%: gsc-%-nodejs
	docker run $(addprefix -e , $(ENV_VARS)) $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-nodejs) /graphene/Examples/helloworld.js 2>&1 | tee out
	grep -q "Hello World" out
	$(RM) out

.PHONY: test-9-%
test-9-%: gsc-%-numpy
	docker run $(addprefix -e , $(ENV_VARS)) $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-numpy) /graphene/Examples/scripts/test-numpy.py 2>&1 | tee out
	grep -q "numpy version:" out
	$(RM) out

.PHONY: test-10-%
test-10-%: gsc-%-bash
	docker run $(addprefix -e , $(ENV_VARS)) $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-bash) -c 'ls' 2>&1 | tee out
	grep -q "entrypoint.manifest.sgx" out
	$(RM) out

.PHONY: test-11-%
test-11-%: gsc-%-pytorch
	touch result.txt
	docker run $(addprefix -e , $(ENV_VARS)) $(DEVICES_VOLUMES) -v$${PWD}/result.txt:/graphene/Examples/result.txt $(addsuffix $(IMAGE_SUFFIX), gsc-$*-pytorch) pytorchexample.py
	grep -q "('Labrador retriever'" result.txt
	$(RM) results.txt

.PHONY: test-info-image-%
test-info-image-%: gsc-%-python3
	../gsc info-image $< > sig.txt
	grep -q "mr_enclave" sig.txt
	$(RM) sig.txt

.PHONY: clean-image-%
clean-image-%:
	docker image rm -f $*

.PHONY: clean-base
clean-base: $(addsuffix $(IMAGE_SUFFIX), $(addprefix clean-image-, $(TESTS)))

.PHONY: clean-gsc
clean-gsc: $(addsuffix $(IMAGE_SUFFIX), $(addprefix clean-image-gsc-, $(TESTS))) $(addsuffix $(IMAGE_SUFFIX)-unsigned, $(addprefix clean-image-gsc-, $(TESTS)))

.PHONY: clean-gsc-base
clean-gsc-base: $(addsuffix $(IMAGE_SUFFIX), $(addprefix clean-image-graphene-, $(DISTRIBUTIONS)))  $(addsuffix -python3-base$(IMAGE_SUFFIX), $(addprefix clean-image-gsc-, $(DISTRIBUTIONS))) $(addsuffix -python3-base$(IMAGE_SUFFIX)-unsigned, $(addprefix clean-image-gsc-, $(DISTRIBUTIONS)))

# Create a space to be used in subst
space :=
space +=

.PHONY: clean-containers
clean-containers:
	docker container ls -a | grep -e '$(subst $(space),\|,$(addsuffix $(IMAGE_SUFFIX), $(TESTS)))\|$(subst $(space),\|,$(addsuffix $(IMAGE_SUFFIX), $(addprefix gsc-, $(TESTS))))' | cut -d ' ' -f 1 | grep -v CONTAINER | xargs -r docker container rm -f

.PHONY: clean-files
clean-files:
	for d in $(DISTRIBUTIONS); do \
		$(RM) config-$${d}.yaml; \
		$(RM) config-image-$${d}.yaml; \
		$(RM) -r ../graphene-$${d}$(IMAGE_SUFFIX); \
		$(RM) graphene-$${d}; \
		$(RM) -r ../gsc-$${d}-python3-base$(IMAGE_SUFFIX); \
		$(RM) gsc-$${d}-python3-base $${d}-python3-base; \
		for t in $(TESTCASES); do \
			$(RM) -r ../gsc-$${d}-$${t}$(IMAGE_SUFFIX) || exit 1; \
			$(RM) gsc-$${d}-$${t} $${d}-$${t}; \
		done \
	done

.PHONY: clean
clean: clean-containers clean-base clean-gsc clean-gsc-base clean-files
