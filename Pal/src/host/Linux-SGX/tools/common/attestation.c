#include "sgx_arch.h"
#include "sgx_attest.h"
#include "util.h"

// TODO: decode some known values (flags etc)
void display_report_body(const sgx_report_body_t* body) {
    INFO(" cpu_svn          : ");
    HEXDUMP(body->cpu_svn);
    INFO(" misc_select      : ");
    HEXDUMP(body->misc_select);
    INFO(" reserved1        : ");
    HEXDUMP(body->reserved1);
    INFO(" isv_ext_prod_id  : ");
    HEXDUMP(body->isv_ext_prod_id);
    INFO(" attributes.flags : ");
    HEXDUMP(body->attributes.flags);
    INFO(" attributes.xfrm  : ");
    HEXDUMP(body->attributes.xfrm);
    INFO(" mr_enclave       : ");
    HEXDUMP(body->mr_enclave);
    INFO(" reserved2        : ");
    HEXDUMP(body->reserved2);
    INFO(" mr_signer        : ");
    HEXDUMP(body->mr_signer);
    INFO(" reserved3        : ");
    HEXDUMP(body->reserved3);
    INFO(" config_id        : ");
    HEXDUMP(body->config_id);
    INFO(" isv_prod_id      : ");
    HEXDUMP(body->isv_prod_id);
    INFO(" isv_svn          : ");
    HEXDUMP(body->isv_svn);
    INFO(" config_svn       : ");
    HEXDUMP(body->config_svn);
    INFO(" reserved4        : ");
    HEXDUMP(body->reserved4);
    INFO(" isv_family_id    : ");
    HEXDUMP(body->isv_family_id);
    INFO(" report_data      : ");
    HEXDUMP(body->report_data);
}

void display_quote(const void* quote_data, size_t quote_size) {
    if (quote_size < offsetof(sgx_quote_t, signature_len)) {
        ERROR("Quote size too small\n");
        return;
    }

    sgx_quote_t* quote = (sgx_quote_t*)quote_data;
    INFO("version           : ");
    HEXDUMP(quote->version);
    INFO("sign_type         : ");
    HEXDUMP(quote->sign_type);
    INFO("epid_group_id     : ");
    HEXDUMP(quote->epid_group_id);
    INFO("qe_svn            : ");
    HEXDUMP(quote->qe_svn);
    INFO("pce_svn           : ");
    HEXDUMP(quote->pce_svn);
    INFO("xeid              : ");
    HEXDUMP(quote->xeid);
    INFO("basename          : ");
    HEXDUMP(quote->basename);
    INFO("report_body       :\n");
    display_report_body(&quote->report_body);

    // quotes from IAS reports are missing signature fields
    if (quote_size >= sizeof(sgx_quote_t)) {
        INFO("signature_len     : %d (0x%x)\n", quote->signature_len, quote->signature_len);
    }

    if (quote_size >= sizeof(sgx_quote_t) + quote->signature_len) {
        INFO("signature         : ");
        hexdump_mem(&quote->signature, quote->signature_len);
        INFO("\n");
    }
}
