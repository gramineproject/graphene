TESTCASES?=python3 hello-world nodejs bash numpy pytorch
DISTRIBUTIONS?=ubuntu18.04 ubuntu16.04
TESTS=$(foreach D,$(DISTRIBUTIONS),$(foreach T,$(TESTCASES),$D-$T))
SGX_DEVICES=--device=/dev/gsgx --device=/dev/isgx -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket

.PHONY: test clean cleanBase cleanGSC cleanContainer

IMAGE_SUFFIX?=

all: $(TESTS)
	for d in $(DISTRIBUTIONS); do \
		sed 's/\"distro\": \".*\"/\"distro\": \"'$${d}'\"/' ../config.json.template > ../config.json; \
		$(MAKE) $(addprefix gsc-$${d}-, $(TESTCASES)) || exit 1; \
	done

%: %.dockerfile
	echo "Build base image $@.dockerfile"
	docker build -t $(addsuffix $(IMAGE_SUFFIX), $@) -f $@.dockerfile .

gsc-%-bash:
	echo "Build graphenized image $@"
	cd .. && ./gsc build $(addsuffix $(IMAGE_SUFFIX), $*-bash) bash.manifest ls.manifest

gsc-%-python3: %-python3.manifest
	echo "Build graphenized image $@"
	cd .. && ./gsc build $(addsuffix $(IMAGE_SUFFIX), $*-python3) $(addprefix test/, $^ sh.manifest ls.manifest)

gsc-%-pytorch: %-pytorch.manifest
	echo "Build graphenized image $@"
	cd .. && ./gsc build $(addsuffix $(IMAGE_SUFFIX), $*-pytorch) $(addprefix test/, $^ sh.manifest)

gsc-%:
	echo "Build graphenized image $@"
	cd .. && ./gsc build $(addsuffix $(IMAGE_SUFFIX), $*) test/$(*:gsc-%=%).manifest

test: $(addprefix test-, $(DISTRIBUTIONS))
	echo "[SUCCESS] Completed all GSC test cases"

MAXTESTNUM?=9

test-1-%:
	docker run $(SGX_DEVICES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) -c 'print("HelloWorld!")' >out 2>/dev/null;
	grep -q "HelloWorld!" out;

test-2-%:
	docker run $(SGX_DEVICES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) /graphene-tests/python-simple/scripts/helloworld.py >out 2>/dev/null
	grep -q "Hello World" out;

test-3-%:
	docker run $(SGX_DEVICES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) /graphene-tests/python-simple/scripts/fibonacci.py >out 2>/dev/null;
	grep -q "fib2              55" out;

test-4-%:
	docker run $(SGX_DEVICES) -d -p 8005:8005 $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) graphene-tests/python-simple/scripts/dummy-web-server.py 8005 >c.id 2>/dev/null;
	sleep 10
	docker run $(SGX_DEVICES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) graphene-tests/python-simple/scripts/test-http.py `ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | grep -v 172.17` 8005 >output1 2>/dev/null;
	cat output1 | tail -n 1 > output1.clean
	wget -q http://localhost:8005/ -O output2
	echo >> output2
	diff -q output1.clean output2
	cat c.id | head -n 1 | xargs docker container rm -f >/dev/null 2>/dev/null;
	rm -f out c.id output1 output1.clean output2;

test-5-%:
	docker run $(SGX_DEVICES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-hello-world) > out 2>/dev/null;
	grep -q "Hello World!" out;

test-6-%:
	docker run $(SGX_DEVICES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-nodejs) -e 'console.log("HelloWorld");' >out 2>/dev/null;
	grep -q "HelloWorld" out;

test-7-%:
	docker run $(SGX_DEVICES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-nodejs) graphene-tests/nodejs/helloworld.js >out 2>/dev/null;
	grep -q "Hello World" out;

test-8-%:
	docker run $(SGX_DEVICES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-numpy) graphene-tests/python-scipy-insecure/scripts/test-numpy.py >out 2>/dev/null;
	grep -q "numpy version:" out;

test-9-%:
	docker run $(SGX_DEVICES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-bash) -c 'ls' >out 2>/dev/null;
	grep -q "ls.manifest.sgx" out;

test-10-%:
	docker run $(SGX_DEVICES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-python3) -c 'import os;os.system("ls")';
	grep -q "ls.manifest.sgx" out;

test-11-%:
	docker run $(SGX_DEVICES) $(addsuffix $(IMAGE_SUFFIX), gsc-$*-pytorch) pytorchexample.py

test-%:
	echo "Testing $*."
	for t in $(shell seq 1  $(MAXTESTNUM)); do \
		printf "$${t}/$(MAXTESTNUM): "; \
		$(MAKE) test-$${t}-$* || exit 1; \
		printf "[SUCCESS]\\n"; \
	done
	echo "Successfully finished testing $*."


cleanImage-%:
	docker image rm -f $(addsuffix $(IMAGE_SUFFIX), $*);

cleanBase: $(addprefix cleanImage-, $(TESTS))
	docker image prune -f

cleanGSC: $(addprefix cleanImage-gsc-, $(TESTS))
	docker image prune -f

# Create a space to be used in subst
space :=
space +=

cleanContainers:
	docker container ls -a | grep -e '$(subst $(space),\|,$(addsuffix $(IMAGE_SUFFIX), $(TESTS)))\|$(subst $(space),\|,$(addsuffix $(IMAGE_SUFFIX), $(addprefix gsc-, $(TESTS))))' | cut -d ' ' -f 1 | grep -v CONTAINER | xargs -r docker container rm -f

distclean: cleanContainers cleanBase cleanGSC
	docker builder prune -a -f

clean: cleanContainers
	docker image prune -f
