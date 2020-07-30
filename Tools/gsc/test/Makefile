TESTCASES ?= python3 hello-world nodejs bash numpy pytorch
DISTRIBUTIONS ?= ubuntu18.04
GRAPHENE_BRANCH ?= master
DOCKER_BUILD_FLAGS ?= --rm --no-cache
GSC_BUILD_FLAGS ?= --rm --no-cache
TESTS = $(foreach D,$(DISTRIBUTIONS),$(foreach T,$(TESTCASES),$D-$T))
MAXTESTNUM ?= 11
KEY_FILE ?= ../enclave-key.pem
ifeq ($(wildcard /dev/isgx), )
	SGX_DEVICE = sgx
else
	SGX_DEVICE = isgx
endif
DEVICES_VOLUMES = --device=/dev/gsgx --device=/dev/${SGX_DEVICE} -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket

IMAGE_SUFFIX ?=

.PHONY: all
all: $(KEY_FILE) $(TESTS)
	for d in $(DISTRIBUTIONS); do \
		sed -e 's/Distro: \".*\"/Distro: \"'$${d}'\"/' \
		    -e 's/Branch: \"master\"/Branch: \"'$(GRAPHENE_BRANCH)'\"/' \
			../config.yaml.template > ../config.yaml; \
		$(MAKE) $(addprefix gsc-$${d}-, $(TESTCASES)) || exit 1; \
	done

$(KEY_FILE):
	openssl genrsa -3 -out $(KEY_FILE) 3072

.PRECIOUS: %: %.dockerfile
%: %.dockerfile
	echo "Building base image $@.dockerfile..."
	docker build $(DOCKER_BUILD_FLAGS) -t $(addsuffix $(IMAGE_SUFFIX), $@) -f $@.dockerfile ../../../Examples
	touch $@

.PRECIOUS: gsc-%-bash
gsc-%-bash: %-bash
	echo "Building graphenized image $@..."
	cd .. && ./gsc build --insecure-args $(GSC_BUILD_FLAGS) $(addsuffix $(IMAGE_SUFFIX), $*-bash) $(addprefix test/, bash.manifest ls.manifest)
	cd .. && ./gsc sign-image $(addsuffix $(IMAGE_SUFFIX), $*-bash) $(notdir $(KEY_FILE))
	touch $@

.PRECIOUS: gsc-%-python3
gsc-%-python3: %-python3 %-python3.manifest
	echo "Building graphenized image $@..."
	cd .. && ./gsc build --insecure-args $(GSC_BUILD_FLAGS) $(addsuffix $(IMAGE_SUFFIX), $*-python3) $(addprefix test/, $*-python3.manifest sh.manifest ls.manifest)
	cd .. && ./gsc sign-image $(addsuffix $(IMAGE_SUFFIX), $*-python3) $(notdir $(KEY_FILE))
	touch $@

.PRECIOUS: gsc-%-pytorch
gsc-%-pytorch: %-pytorch %-pytorch.manifest
	echo "Building graphenized image $@..."
	cd .. && ./gsc build --insecure-args $(GSC_BUILD_FLAGS) $(addsuffix $(IMAGE_SUFFIX), $*-pytorch) $(addprefix test/, $*-pytorch.manifest sh.manifest uname.manifest)
	cd .. && ./gsc sign-image $(addsuffix $(IMAGE_SUFFIX), $*-pytorch) $(notdir $(KEY_FILE))
	touch $@

.PRECIOUS: gsc-%
gsc-%: %
	echo "Building graphenized image $@..."
	cd .. && ./gsc build --insecure-args $(BUILD_FLAGS) $(addsuffix $(IMAGE_SUFFIX), $*) test/$(*:gsc-%=%).manifest
	cd .. && ./gsc sign-image $(addsuffix $(IMAGE_SUFFIX), $*) $(notdir $(KEY_FILE))
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
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) -c 'print("HelloWorld!")' 2>&1 | tee out
	grep -q "HelloWorld!" out
	$(RM) out

.PHONY: test-2-%
test-2-%: gsc-%-python3
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) /graphene/Examples/scripts/helloworld.py  2>&1 | tee out
	grep -q "Hello World" out
	$(RM) out

.PHONY: test-3-%
test-3-%: gsc-%-python3
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) /graphene/Examples/scripts/fibonacci.py  2>&1 | tee out
	grep -q "fib2              55" out
	$(RM) out

.PHONY: test-4-%
test-4-%: gsc-%-python3
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) -c 'import os;os.system("ls")' 2>&1 | tee out
	grep -q "ls.manifest.sgx" out
	$(RM) out

.PHONY: test-5-%
test-5-%: gsc-%-python3
	docker run $(DEVICES_VOLUMES) -d -p 8005:8005 $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) /graphene/Examples/scripts/dummy-web-server.py 8005 | tee c.id
	sleep 30
	wget -q http://localhost:8005/ -O output
	grep -q "hi!" output
	cat c.id | head -n 1 | xargs docker container rm -f >/dev/null 2>/dev/null
	$(RM) c.id output

.PHONY: test-6-%
test-6-%: gsc-%-hello-world
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-hello-world)  2>&1 | tee out
	grep -q "Hello World!" out
	$(RM) out

.PHONY: test-7-%
test-7-%: gsc-%-nodejs
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-nodejs) -e 'console.log("HelloWorld");' 2>&1 | tee out
	grep -q "HelloWorld" out
	$(RM) out

.PHONY: test-8-%
test-8-%: gsc-%-nodejs
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-nodejs) /graphene/Examples/helloworld.js 2>&1 | tee out
	grep -q "Hello World" out
	$(RM) out

.PHONY: test-9-%
test-9-%: gsc-%-numpy
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-numpy) /graphene/Examples/scripts/test-numpy.py 2>&1 | tee out
	grep -q "numpy version:" out
	$(RM) out

.PHONY: test-10-%
test-10-%: gsc-%-bash
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-bash) -c 'ls' 2>&1 | tee out
	grep -q "ls.manifest.sgx" out
	$(RM) out

.PHONY: test-11-%
test-11-%: gsc-%-pytorch
	touch result.txt
	docker run $(DEVICES_VOLUMES) -v$${PWD}/result.txt:/graphene/Examples/result.txt $(addsuffix $(IMAGE_SUFFIX), gsc-$*-pytorch) pytorchexample.py
	grep -q "('Labrador retriever'" result.txt
	$(RM) results.txt

.PHONY: clean-image-%
clean-image-%:
	docker image rm -f $*

.PHONY: clean-base
clean-base: $(addsuffix $(IMAGE_SUFFIX), $(addprefix clean-image-, $(TESTS)))

.PHONY: clean-gsc
clean-gsc: $(addsuffix $(IMAGE_SUFFIX), $(addprefix clean-image-gsc-, $(TESTS))) $(addsuffix $(IMAGE_SUFFIX)-unsigned, $(addprefix clean-image-gsc-, $(TESTS)))

# Create a space to be used in subst
space :=
space +=

.PHONY: clean-containers
clean-containers:
	docker container ls -a | grep -e '$(subst $(space),\|,$(addsuffix $(IMAGE_SUFFIX), $(TESTS)))\|$(subst $(space),\|,$(addsuffix $(IMAGE_SUFFIX), $(addprefix gsc-, $(TESTS))))' | cut -d ' ' -f 1 | grep -v CONTAINER | xargs -r docker container rm -f

.PHONY: clean-files
clean-files:
	for d in $(DISTRIBUTIONS); do \
		for t in $(TESTCASES); do \
			$(RM) -r ../gsc-$${d}-$${t}$(IMAGE_SUFFIX) || exit 1; \
			$(RM) gsc-$${d}-$${t}$(IMAGE_SUFFIX) $${d}-$${t}$(IMAGE_SUFFIX); \
		done \
	done

.PHONY: clean
clean: clean-containers clean-base clean-gsc clean-files
