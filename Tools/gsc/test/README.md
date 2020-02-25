# Examples and Tests for GSC

This folder includes sample images and test cases for GSC. The set of examples include:

* Hello-World (print "Hello World!" using echo)
* Python3 (Run python3 command line) which is tested with a `-c 'print("Hello World!")'` and the
  three [Graphene test](https://github.com/oscarlab/graphene-tests) scripts  from python-simple

Each sample consists of two files `ubuntu.<image name>.dockerfile` and `ubuntu.<image name>.manifest`.

**\*.dockerfile** describes the basic image and its application. It builds the docker image by installing required software packages, configuring the application and changing the docker entrypoint to start the application.

**\*.manifest** describes the specific Graphene manifest changes required to run this application reliably. For instance, this includes the memory size and the number of threads. In some cases this file might be empty, but its existence is required for the makefile structure.

## Building sample images

Run:

```
make
```

To build base images named `<image name>`:

```
make <image name>
```

To build a graphenized image named `<image name>`:

```
make gsc-ubuntu/<image name>
```

## Run sample images with test arguments

Run all samples with test arguments:

```
make test
```

To run a container of an image named `<image name>`:

(may not work for all images, since the test cases are invoked via command line arguments)

```
make run-gsc-ubuntu/<image name>
```

## Remove images & containers from docker daemon

Remove GSC built sample images:

```
make cleanGSC
```

Remove base sample images:

```
make cleanBase
```

Remove containers:

```
make cleanContainers
```

Remove all images & containers built by this test folder:

```
make clean
```