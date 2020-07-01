TESTCASES ?= python3 hello-world nodejs bash numpy pytorch
DISTRIBUTIONS ?= ubuntu18.04
FLAGS ?=
TESTS = $(foreach D,$(DISTRIBUTIONS),$(foreach T,$(TESTCASES),$D-$T))
MAXTESTNUM ?= 11
KEYFILE ?= ../enclave-key.pem
ifeq ($(wildcard /dev/isgx), )
	SGX_DEVICE = sgx
else
	SGX_DEVICE = isgx
endif
DEVICES_VOLUMES = --device=/dev/gsgx --device=/dev/${SGX_DEVICE} -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket

IMAGE_SUFFIX ?=

.PHONY: all
all: $(KEYFILE) $(TESTS)
	for d in $(DISTRIBUTIONS); do \
		sed -e 's/\"Distro\": \".*\"/\"Distro\": \"'$${d}'\"/' \
			../config.yaml.template > ../config.yaml; \
		$(MAKE) $(addprefix gsc-$${d}-, $(TESTCASES)) || exit 1; \
	done

$(KEYFILE):
	openssl genrsa -3 -out $(KEYFILE) 3072

.PRECIOUS: %
%: %.dockerfile
	echo "Building base image $@.dockerfile..."
	docker build -t $(addsuffix $(IMAGE_SUFFIX), $@) -f $@.dockerfile ../../../Examples
	touch $@

.PRECIOUS: gsc-%-bash
gsc-%-bash: %-bash
	echo "Building graphenized image $@..."
	cd .. && ./gsc build --insecure-args $(FLAGS) $(addsuffix $(IMAGE_SUFFIX), $*-bash) $(addprefix test/, bash.manifest ls.manifest)
	cd .. && ./gsc sign-image $(addsuffix $(IMAGE_SUFFIX), $*-bash) $(notdir $(KEYFILE))
	touch $@

.PRECIOUS: gsc-%-python3
gsc-%-python3: %-python3 %-python3.manifest
	echo "Building graphenized image $@..."
	cd .. && ./gsc build --insecure-args $(FLAGS) $(addsuffix $(IMAGE_SUFFIX), $*-python3) $(addprefix test/, $*-python3.manifest sh.manifest ls.manifest)
	cd .. && ./gsc sign-image $(addsuffix $(IMAGE_SUFFIX), $*-python3) $(notdir $(KEYFILE))
	touch $@

.PRECIOUS: gsc-%-pytorch
gsc-%-pytorch: %-pytorch %-pytorch.manifest
	echo "Building graphenized image $@..."
	cd .. && ./gsc build --insecure-args $(FLAGS) $(addsuffix $(IMAGE_SUFFIX), $*-pytorch) $(addprefix test/, $*-pytorch.manifest sh.manifest uname.manifest)
	cd .. && ./gsc sign-image $(addsuffix $(IMAGE_SUFFIX), $*-pytorch) $(notdir $(KEYFILE))
	touch $@

.PRECIOUS: gsc-%
gsc-%: %
	echo "Building graphenized image $@..."
	cd .. && ./gsc build --insecure-args $(FLAGS) $(addsuffix $(IMAGE_SUFFIX), $*) test/$(*:gsc-%=%).manifest
	cd .. && ./gsc sign-image $(addsuffix $(IMAGE_SUFFIX), $*) $(notdir $(KEYFILE))
	touch $@

.PHONY: test
test: $(addprefix test-distro-, $(DISTRIBUTIONS))
	echo "[SUCCESS] Completed all GSC test cases"

.PHONY: test-%
test-distro-%:
	echo "Testing $*."
	for t in $(shell seq 1 $(MAXTESTNUM)); do \
		printf "$${t}/$(MAXTESTNUM): "; \
		$(MAKE) test-$${t}-$* || exit 1; \
		printf "[SUCCESS]\\n"; \
	done
	echo "Successfully finished testing $*."

.PHONY:
test-1-%: gsc-%-python3
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) -c 'print("HelloWorld!")' >out 2>&1
	grep -q "HelloWorld!" out
	rm -f out

.PHONY: test-2-%
test-2-%: gsc-%-python3
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) /graphene/Examples/scripts/helloworld.py >out 2>&1
	grep -q "Hello World" out
	rm -f out

.PHONY: test-3-%
test-3-%: gsc-%-python3
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) /graphene/Examples/scripts/fibonacci.py >out 2>&1
	grep -q "fib2              55" out
	rm -f out

.PHONY: test-4-%
test-4-%: gsc-%-python3
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) -c 'import os;os.system("ls")' >out 2>&1
	grep -q "ls.manifest.sgx" out
	rm -f out

.PHONY: test-5-%
test-5-%: gsc-%-python3
	docker run $(DEVICES_VOLUMES) -d -p 8005:8005 $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) /graphene/Examples/scripts/dummy-web-server.py 8005 >c.id 2>/dev/null
	sleep 30
	wget -q http://localhost:8005/ -O output
	grep -q "hi!" output
	cat c.id | head -n 1 | xargs docker container rm -f >/dev/null 2>/dev/null
	rm -f c.id output

.PHONY: test-6-%
test-6-%: gsc-%-hello-world
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-hello-world) > out 2>/dev/null
	grep -q "Hello World!" out
	rm -f out

.PHONY: test-7-%
test-7-%: gsc-%-nodejs
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-nodejs) -e 'console.log("HelloWorld");' >out 2>/dev/null
	grep -q "HelloWorld" out
	rm -f out

.PHONY: test-8-%
test-8-%: gsc-%-nodejs
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-nodejs) /graphene/Examples/helloworld.js >out 2>/dev/null
	grep -q "Hello World" out
	rm -f out

.PHONY: test-9-%
test-9-%: gsc-%-numpy
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-numpy) /graphene/Examples/scripts/test-numpy.py >out 2>/dev/null
	grep -q "numpy version:" out
	rm -f out

.PHONY: test-10-%
test-10-%: gsc-%-bash
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-bash) -c 'ls' >out 2>/dev/null
	grep -q "ls.manifest.sgx" out
	rm -f out

.PHONY: test-11-%
test-11-%: gsc-%-pytorch
	docker run $(DEVICES_VOLUMES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-pytorch) pytorchexample.py >out 2>/dev/null
	grep -q "('Labrador retriever'" out
	rm -f out

.PHONY: clean-image-%
clean-image-%:
	docker image rm -f $(addsuffix $(IMAGE_SUFFIX), $*)

.PHONY: clean-base
clean-base: $(addprefix clean-image-, $(TESTS))

.PHONY: clean-gsc
clean-gsc: $(addprefix clean-image-gsc-, $(TESTS)) $(addsuffix -unsigned, $(addprefix clean-image-gsc-, $(TESTS)))

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
			rm -rf ../gsc-$${d}-$${t}$(IMAGE_SUFFIX) || exit 1; \
			rm -f gsc-$${d}-$${t}$(IMAGE_SUFFIX) $${d}-$${t}$(IMAGE_SUFFIX); \
		done \
	done

.PHONY: clean
clean: clean-base clean-gsc clean-files
