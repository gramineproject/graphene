# Running Node.js express server with Graphene SGX

This is a Node.js application, runs an express server, listening on a given port.

## Environment

This application was tested with Node.js version 8.

## Prerequisites

This project requires Node.js to be installed.
See https://nodejs.org/ for more details on how to install Node.js.

Run `npm install`, which installs all dependencies and modules needed for this application. See
`package.json` for more details on Node.js dependencies needed for this project. At this point, the
application itself can be executed without Graphene by running `node helloworld.js`.

## Steps to run without SGX

1. Run `make`.
2. Run `./pal_loader nodejs helloworld.js 3000`.
3. The expected output should be the following: `Example app listening on port 3000!`

## Steps to run with SGX

1. Run `make SGX=1` in order to build the application using SGX.
2. Run `./pal_loader SGX nodejs helloworld.js 3000`
3. The expected output should be the following: `Example app listening on port 3000!`
