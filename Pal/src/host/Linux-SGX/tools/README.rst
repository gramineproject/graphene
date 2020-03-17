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

The program terminates successfully if all SGX components are detected and running, otherwise
the program exits with an error code (see source code for possible values).
To supress printing output use the --quiet argument.

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
    basename          : 47c1b58ce721a47f127965ddf7b4ac5600000000000000000000000000000000
    report_body       :
     cpu_svn          : 0808ffff010200000000000000000000
     misc_select      : 00000000
     reserved1        : 00000000000000000000000000000000000000000000000000000000
     attributes.flags : 0700000000000000
     attributes.xfrm  : 0700000000000000
     mr_enclave       : 64ac58fa317cf55eda97ca969c76618d6145bc1d72d60369bf27f0c7d510b9f4
     reserved2        : 0000000000000000000000000000000000000000000000000000000000000000
     mr_signer        : 577b180dbcdae37bd9f26444189e3ba78ad85bd03515bf26f5c4455c5284b214
     reserved3        : 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
     isv_prod_id      : 0000
     isv_svn          : 0000
     reserved4        : 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
     report_data      : 8b287999fbf00bd795b74886b3e173cf8a6dd97a86a0057fdf43840adb1864430000000000000000000000000000000000000000000000000000000000000000
    signature_len     : 680 (0x2a8)
    signature         : 240aafaa...
