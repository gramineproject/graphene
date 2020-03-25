# Example Integrations

This folder contains application integration examples.

For instructions how to build and run each application under Graphene,
please see the README or README.md in each subdirectory.

## How to Contribute?

Please put your application sample in a subdirectory with a
comprehensible name. Ideally, the subdirectory name should be the same
as your application. In addition, your application sample should
have the following elements:

- `README.md`:
  Please document the tested environment and instructions for
  building and running the application. If your application sample
  has any known issues or requirements, please also specify them in
  the documentation.

- `Makefile`:
  Users should be able to build your application sample by running
  the `make` command. If your application needs extra building steps,
  please document them in the `README.md`. In addition, we ask you
  to provide sufficient comments in the `Makefile` to help users
  understand the build process. If your application also runs on
  Graphene-SGX, please include the commands for signing and retrieving
  the token in the `Makefile`.

- Manifest(s):
  Please provide all the manifests needed for running your application
  sample. Do not hard-code any user-specific path or personal info
  in the manifests. The ideal way is to create manifest templates that
  contain variables to be replaced by runtime options in `Makefile`.
  See other subdirectories for examples of the manifest templates.
  We also ask you to provide sufficient comments in all the manifests
  to help users understand the environment.

- Sample inputs and test suites:
  If you have any inputs and test suites for testing the application,
  please provide them in the same subdirectory, too.

Please do not include any tarball of source code or binaries in the
application samples. If an application requires downloading the source
code or binaries, please provide instructions in the `README.md`, or
download them automatically and verify the checksums as part of the
build process.
