TESTCASES=hello-world python3 nodejs
DISTRIBUTIONS=ubuntu18.04 #ubuntu16.04
TESTS=$(foreach D,$(DISTRIBUTIONS),$(foreach T,$(TESTCASES),$D-$T))
SGX_DEVICES=--device=/dev/gsgx --device=/dev/isgx -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket

.PHONY: test clean cleanBase cleanGSC cleanContainer

all: $(TESTS)
	for d in $(DISTRIBUTIONS); do \
		sed -i 's/\"distro\": \".*\"/\"distro\": \"'$${d}'\"/' ../config.json; \
		$(MAKE) $(addprefix gsc-$${d}-, $(TESTCASES)); \
	done

%: %.dockerfile
	echo "Build base image $@.dockerfile"
	docker build -t $@ -f $@.dockerfile .

gsc-%: %.manifest
	echo "Build graphenized image $@"
	cd .. && ./gsc build $* test/$<

test: $(addprefix test-, $(DISTRIBUTIONS))
	echo "[SUCCESS] Completed all GSC test cases"

TESTNUM=7

test-%:
	echo "Testing $*"
	printf "1/$(TESTNUM): "
	docker run $(SGX_DEVICES) gsc-$*-hello-world > out 2>/dev/null;
	grep -q "Hello World!" out;
	printf "[SUCCESS]\\n2/$(TESTNUM): "
	docker run $(SGX_DEVICES) gsc-$*-python3 -c 'print("HelloWorld!")' >out 2>/dev/null;
	grep -q "HelloWorld!" out;
	printf "[SUCCESS]\\n3/$(TESTNUM): "
	docker run $(SGX_DEVICES) gsc-$*-python3 /graphene-tests/python-simple/scripts/helloworld.py >out 2>/dev/null;
	grep -q "Hello World" out;
	printf "[SUCCESS]\\n4/$(TESTNUM): "
	docker run $(SGX_DEVICES) gsc-$*-python3 /graphene-tests/python-simple/scripts/fibonacci.py >out 2>/dev/null;
	grep -q "fib2              55" out;
	printf "[SUCCESS]\\n5/$(TESTNUM): "
	docker run $(SGX_DEVICES) -d -p 8005:8005 gsc-$*-python3 graphene-tests/python-simple/scripts/dummy-web-server.py 8005 >c.id 2>/dev/null;
	sleep 10
	docker run $(SGX_DEVICES) gsc-$*-python3 graphene-tests/python-simple/scripts/test-http.py `ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | grep -v 172.17` 8005 >output1 2>/dev/null;
	cat output1 | tail -n 1 > output1.clean
	wget -q http://localhost:8005/ -O output2
	echo >> output2
	diff -q output1.clean output2
	printf "[SUCCESS]\\n5/$(TESTNUM): "
	cat c.id | head -n 1 | xargs docker container rm -f >/dev/null 2>&1;
	rm -f out c.id output1 output1.clean output2;
	printf "[SUCCESS]\\n6/$(TESTNUM): "
	docker run $(SGX_DEVICES) gsc-$*-nodejs -e 'console.log("HelloWorld");' >out 2>/dev/null;
	grep -q "HelloWorld" out;
	printf "[SUCCESS]\\n7/$(TESTNUM): "
	docker run $(SGX_DEVICES) gsc-$*-nodejs graphene-tests/nodejs/helloworld.js >out 2>/dev/null;
	grep -q "Hello World" out;
	printf "[SUCCESS]\\n"

cleanImage-%:
	docker image rm -f $*;

cleanBase: $(addprefix cleanImage-, $(TESTS))
	docker image prune -f

cleanGSC: $(addprefix cleanImage-gsc-, $(TESTS))
	docker image prune -f

# Create a space to be used in subst
space :=
space +=

cleanContainers:
	docker container ls -a | grep -e '$(subst $(space),\|,$(TESTS))\|$(subst $(space),\|,$(addprefix gsc-, $(TESTS)))' | cut -d ' ' -f 1 | grep -v CONTAINER | xargs -r docker container rm -f

distclean: cleanContainers cleanBase cleanGSC
	docker builder prune -a -f

clean: cleanContainers
	docker image prune -f
