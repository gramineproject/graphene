TESTS=hello-world python3 gtpython

all: $(TESTS)
	
%: ubuntu.%.manifest ubuntu.%.dockerfile
	echo "Build base image ubuntu/$@"
	docker build -t ubuntu/$@ -f ubuntu.$@.dockerfile .

gsc-ubuntu/%: ubuntu.%.manifest ubuntu.%.dockerfile %
	echo "Build graphenized image $@"
	cd .. && ./gsc build test/$< ubuntu/$*

run-gsc-ubuntu/%:
	echo "Run image " $*;
	cd .. && ./gsc run ubuntu/$*;

test: $(addprefix gsc-ubuntu/, $(TESTS))
	cd .. && ./gsc run ubuntu/hello-world > out && cd -;
	grep -q "Hello World!" ../out;
	cd .. && ./gsc run ubuntu/python3 -c "print("HelloWorld!")" >out && cd -;
	grep -q "HelloWorld!" ../out;
	cd .. && ./gsc run ubuntu/gtpython /graphene-tests/python-simple/scripts/helloworld.py >out && cd -;
	grep -q "Hello World" ../out;
	cd .. && ./gsc run ubuntu/gtpython /graphene-tests/python-simple/scripts/fibonacci.py >out && cd -;
	grep -q "fib2              55" ../out;
	cd .. && ./gsc run -d -p 8005:8005 ubuntu/gtpython graphene-tests/python-simple/scripts/dummy-web-server.py 8005 >c.id && cd -;
	sleep 10
	cd .. && ./gsc run ubuntu/gtpython graphene-tests/python-simple/scripts/test-http.py `ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | grep -v 172.17` 8005 >output1 && cd -;
	cat ../output1 | tail -n 2 | head -n 1 > ../output1.clean
	wget -q http://localhost:8005/ -O ../output2
	echo >> ../output2
	diff -q ../output1.clean ../output2
	cat ../c.id | head -n 1 | xargs docker container rm -f ;
	rm -f ../out ../c.id ../output1 ../output1.clean ../output2;

cleanBase:
	for image in $(TESTS); do \
		docker image rm -f ubuntu/$${image}; \
	done
	docker image prune

cleanGSC:
	for image in $(TESTS); do \
		docker image rm -f gsc-ubuntu/$${image}; \
	done
	docker image prune

cleanContainers:
	docker container ls | cut -d ' ' -f 1 | grep -v CONTAINER | xargs -r docker container rm -f

clean: cleanGSC cleanBase cleanContainers
	docker image prune
