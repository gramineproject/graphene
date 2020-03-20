SGX tools
=========


SGX availability checker
------------------------

Example output::

    > ./is_sgx_available/is_sgx_available
    SGX supported by CPU: true
    SGX1 (ECREATE, EENTER, ...): true
    SGX2 (EAUG, EACCEPT, EMODPR, ...): false
    Flexible Launch Control (IA32_SGXPUBKEYHASH{0..3} MSRs): false
    SGX extensions for virtualizers (EINCVIRTCHILD, EDECVIRTCHILD, ESETCONTEXT): false
    Extensions for concurrent memory management (ETRACKC, ELDBC, ELDUC, ERDINFO): false
    Max enclave size (32-bit): 0x80000000
    Max enclave size (64-bit): 0x1000000000
    EPC size: 0x5d80000
    SGX driver loaded: true
    SGX PSW/libsgx installed: true
    AESMD running: false

The program terminates successfully if all SGX1 components are detected and running, otherwise
the program exits with an error code (see the source code for possible values).
To suppress printing output use the --quiet argument.


SGX quote dump
--------------

Displays internal structure of an SGX quote::

    > ./quote_dump enclave.quote
    version           : 0200
    sign_type         : 0100
    epid_group_id     : ef0a0000
    qe_svn            : 0700
    pce_svn           : 0600
    xeid              : 00000000
    basename          : 655afa33faa5b9cc5e9e241fa229b99400000000000000000000000000000000
    report_body       :
     cpu_svn          : 080effff010200000000000000000000
     misc_select      : 00000000
     reserved1        : 000000000000000000000000
     isv_ext_prod_id  : 00000000000000000000000000000000
     attributes.flags : 0700000000000000
     attributes.xfrm  : 1f00000000000000
     mr_enclave       : 03b3b784d26f030f58451860b05d60b73fe71b6056b14ea5401f40402c10694d
     reserved2        : 0000000000000000000000000000000000000000000000000000000000000000
     mr_signer        : 577b180dbcdae37bd9f26444189e3ba78ad85bd03515bf26f5c4455c5284b214
     reserved3        : 0000000000000000000000000000000000000000000000000000000000000000
     config_id        : 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
     isv_prod_id      : 0000
     isv_svn          : 0000
     config_svn       : 0000
     reserved4        : 000000000000000000000000000000000000000000000000000000000000000000000000000000000000
     isv_family_id    : 00000000000000000000000000000000
     report_data      : 0100000000000000722ce121e376a44b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    signature_len     : 680 (0x2a8)
    signature         : a22de3fa...

Intel Attestation Service submitter
-----------------------------------

Submits requests to Intel Attestation Service (IAS) for retrieving EPID signature revocation lists
and for verifying attestation evidence (enclave quote)::

    Usage: ias_request <request> [options]
    Available requests:
      sigrl                     Retrieve signature revocation list for a given EPID group
      report                    Verify attestation evidence (quote)
    Available general options:
      --help, -h                Display this help
      --verbose, -v             Enable verbose output
      --api-key, -k STRING      IAS API key
    Available sigrl options:
      --gid, -g STRING          EPID group ID (hex string)
      --sigrl-path, -i PATH     Path to save SigRL to
      --sigrl-url, -S URL       URL for the IAS SigRL endpoint (default:
                                https://api.trustedservices.intel.com/sgx/dev/attestation/v3/sigrl)
    Available report options:
      --quote-path, -q PATH     Path to quote to submit
      --nonce, -n STRING        Nonce to use (optional)
      --report-path, -r PATH    Path to save IAS report to
      --sig-path, -s PATH       Path to save IAS report's signature to (optional)
      --cert-path, -c PATH      Path to save IAS certificate to (optional)
      --advisory-path, -a PATH  Path to save IAS advisories to (optional)
      --report-url, -R URL      URL for the IAS attestation report endpoint (default:
                                https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report)

Example SigRL retrieval::

    $ ias_request sigrl -k $IAS_API_KEY -g ef0a0000 -i sigrl
    No SigRL for given EPID group ID ef0a0000

Example quote verification::

    $ ias_request report -k $IAS_API_KEY -q gr.quote -r ias.report -s ias.sig -c ias.cert -a ias.adv -v
    Verbose output enabled
    IAS request:
    {"isvEnclaveQuote":"AgABAO8..."}
    [...snip curl output...]
    IAS response: 200
    IAS report saved to: ias.report
    IAS report signature saved to: ias.sig
    IAS certificate saved to: ias.cert
    IAS advisory saved to: ias.adv
    IAS submission successful
    $ cat ias.report
    {"id":"205146415611480061439763344693868541328","timestamp":"2020-03-20T10:48:32.353294","version":3,"epidPseudonym":"Itmg0 [...]","isvEnclaveQuoteStatus":"GROUP_OUT_OF_DATE" [...]}
