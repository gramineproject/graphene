#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_arch.h"
#include "sgx_attest.h"

void __hexdump(const void* data, size_t size) {
    const uint8_t* ptr = (const uint8_t*)data;

    for (size_t i = 0; i < size; i++)
        printf("%02x", ptr[i]);
    printf("\n");
}

#define hexdump(x) __hexdump((void*)&x, sizeof(x))

void display_report_body(const sgx_report_body_t* body) {
    printf(" cpu_svn          : ");
    hexdump(body->cpu_svn);
    printf(" misc_select      : ");
    hexdump(body->misc_select);
    printf(" reserved1        : ");
    hexdump(body->reserved1);
    printf(" attributes.flags : ");
    hexdump(body->attributes.flags);
    printf(" attributes.xfrm  : ");
    hexdump(body->attributes.xfrm);
    printf(" mr_enclave       : ");
    hexdump(body->mr_enclave);
    printf(" reserved2        : ");
    hexdump(body->reserved2);
    printf(" mr_signer        : ");
    hexdump(body->mr_signer);
    printf(" reserved3        : ");
    hexdump(body->reserved3);
    printf(" isv_prod_id      : ");
    hexdump(body->isv_prod_id);
    printf(" isv_svn          : ");
    hexdump(body->isv_svn);
    printf(" reserved4        : ");
    hexdump(body->reserved4);
    printf(" report_data      : ");
    hexdump(body->report_data);
}

void display_quote(const sgx_quote_t* quote) {
    printf("version           : ");
    hexdump(quote->version);
    printf("sign_type         : ");
    hexdump(quote->sign_type);
    printf("epid_group_id     : ");
    hexdump(quote->epid_group_id);
    printf("qe_svn            : ");
    hexdump(quote->qe_svn);
    printf("pce_svn           : ");
    hexdump(quote->pce_svn);
    printf("xeid              : ");
    hexdump(quote->xeid);
    printf("basename          : ");
    hexdump(quote->basename);
    printf("report_body       :\n");
    display_report_body(&quote->report_body);
    printf("signature_len     : %d (0x%x)\n", quote->signature_len, quote->signature_len);
    printf("signature         : ");
    __hexdump(&quote->signature, quote->signature_len);

    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        exit(1);
    }

    const char* path = argv[1];

    char* buf = NULL;
    size_t buf_size = 0;
 
    FILE* f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        exit(-EINVAL);
    }

    fseek(f, 0, SEEK_END);
    buf_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    buf = malloc(buf_size);
    if (!buf) {
        fprintf(stderr, "No memory\n");
        exit(-ENOMEM);
    }

    if (fread(buf, buf_size, 1, f) != 1) {
        fprintf(stderr, "Error reading '%s'!\n", path);
        exit(-EINVAL);
    }

    fclose(f);
    display_quote((const sgx_quote_t*)buf);
    return 0;
}
