# Running Node.js express server with Graphene SGX

This is a Node.js application, runs an express server, listening on a given port.

## Environment

This application was tested with Node.js version 8.

## Requirements

This project requires Node.js to be installed.
See https://nodejs.org/ for more details on how to install Node.js.

## Steps to run with SGX

1. Run `npm install`, which installs all dependencies and modules needed for this application.
See `package.json` for more details on Node.js dependencies needed for this project.
At this point, the application itself can be executed without SGX by running `node helloworld.js`.
2. Run `make SGX=1` in order to build the application using SGX.
3. Once the application is built, and manifest files are generated, execute application by running:
 `./pal_loader SGX nodejs.manifest.sgx helloworld.js 3000`
4. The expected output should be the following: `Example app listening on port 3000!`

## Steps to run without SGX

1. Run `npm install`, which installs all dependencies and modules needed for this application.
See `package.json` for more details on Node.js dependencies needed for this project.
2. Run `node helloworld.js 3000`.
3. The expected output should be the following: `Example app listening on port 3000!`
