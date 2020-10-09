conf = configuration_data()
conf.set('GRAPHENEDIR', meson.source_root())

signerdir = meson.source_root() / 'Pal/src/host/Linux-SGX/signer'
enclave_key = files(signerdir / 'enclave-key.pem')
pal_sgx_sign = find_program(signerdir / 'pal-sgx-sign')
pal_sgx_get_token = find_program(signerdir / 'pal-sgx-get-token')
libpal = meson.source_root() / 'Runtime/libpal-Linux-SGX.so'

benchmarks = [
    executable('write_1e4', 'write_pages.c', c_args: '-DPAGECOUNT=10000'),
    executable('write_1e5', 'write_pages.c', c_args: '-DPAGECOUNT=100000'),
    executable('write_1e6', 'write_pages.c', c_args: '-DPAGECOUNT=1000000'),
    executable('write_1e7', 'write_pages.c', c_args: '-DPAGECOUNT=10000000'),
    executable('helloworld', 'helloworld.c'),
]

foreach exec : benchmarks
    name = exec.full_path().split('/')[-1]

    manifest = configure_file(
        input: 'manifest.in',
        output: '@0@.manifest'.format(name),
        configuration: conf,
    )

    manifest_sgx_and_sig = custom_target('@0@.manifest.sgx'.format(name),
        input: [exec, manifest],
        output: ['@0@.manifest.sgx'.format(name), '@0@.sig'.format(name)],
        command: [pal_sgx_sign,
            '--exec', '@INPUT0@',
            '--manifest', '@INPUT1@',
            '--output', '@OUTPUT0@',
            '--key', enclave_key,
            '--libpal', libpal,
        ],
        build_by_default: true,
    )

    token = custom_target('@0@.token'.format(name),
        input: manifest_sgx_and_sig[1],
        output: ['@0@.token'.format(name)],
        command: [pal_sgx_get_token,
            '--sig', '@INPUT0@',
            '--output', '@OUTPUT0@',
        ],
        build_by_default: true,
    )
endforeach
