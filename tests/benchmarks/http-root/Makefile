.PHONY: all
all: 10K.1.html

10K.1.html:
	dd if=/dev/urandom of=$@ bs=1000 count=10

.PHONY: clean
clean:
	$(RM) *.html
