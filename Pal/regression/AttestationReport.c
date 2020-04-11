#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "sgx_arch.h"

int main(int argc, char** argv) {
    bool ret;

    size_t user_report_data_size;
    size_t target_info_size;
    size_t report_size;
    ret = DkAttestationReport(/*user_report_data=*/NULL, &user_report_data_size,
                              /*target_info=*/NULL, &target_info_size,
                              /*report=*/NULL, &report_size);
    if (!ret) {
        pal_printf("ERROR: DkAttestationReport() to get sizes of SGX structs failed\n");
        return -1;
    }

    if (user_report_data_size != sizeof(sgx_report_data_t)) {
        pal_printf("ERROR: DkAttestationReport() returned incorrect user_report_data size\n");
        return -1;
    }

    if (target_info_size != sizeof(sgx_target_info_t)) {
        pal_printf("ERROR: DkAttestationReport() returned incorrect target_info size\n");
        return -1;
    }

    if (report_size != sizeof(sgx_report_t)) {
        pal_printf("ERROR: DkAttestationReport() returned incorrect report size\n");
        return -1;
    }

    pal_printf("user_report_data_size = %lu, target_info_size = %lu, report_size = %lu\n",
               user_report_data_size, target_info_size, report_size);

    char user_report_data[user_report_data_size];
    char target_info[target_info_size];
    char report[report_size];

    memset(&user_report_data, 'A', sizeof(user_report_data));
    memset(&target_info, 0, sizeof(target_info));
    memset(&report, 0, sizeof(report));

    ret = DkAttestationReport(&user_report_data, &user_report_data_size,
                              &target_info, &target_info_size,
                              &report, &report_size);
    if (!ret) {
        pal_printf("ERROR: DkAttestationReport() to get SGX report failed\n");
        return -1;
    }

    sgx_report_t* sgx_report = (sgx_report_t*)&report;
    if (memcmp(&sgx_report->body.report_data.d, &user_report_data,
           sizeof(sgx_report->body.report_data.d))) {
        pal_printf("ERROR: DkAttestationReport() returned SGX report with wrong report_data\n");
        return -1;
    }

    char zerobuf[report_size];
    memset(&zerobuf, 0, sizeof(zerobuf));

    if (memcmp(&sgx_report->body.reserved1, &zerobuf, sizeof(sgx_report->body.reserved1)) ||
        memcmp(&sgx_report->body.reserved2, &zerobuf, sizeof(sgx_report->body.reserved2)) ||
        memcmp(&sgx_report->body.reserved3, &zerobuf, sizeof(sgx_report->body.reserved3)) ||
        memcmp(&sgx_report->body.reserved4, &zerobuf, sizeof(sgx_report->body.reserved4)))
    {
        pal_printf("ERROR: DkAttestationReport() returned SGX report with non-zero reserved "
                   "fields\n");
        return -1;
    }

    pal_printf("Success\n");
    return 0;
}
