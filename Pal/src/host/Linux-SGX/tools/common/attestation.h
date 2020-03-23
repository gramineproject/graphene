#ifndef ATTESTATION_H
#define ATTESTATION_H

#include <stdint.h>

#include "sgx_arch.h"

/*!
 *  \brief Display internal SGX quote structure.
 *  
 *  \param[in] quote_data Buffer with quote data. This can be a full quote (sgx_quote_t)
 *                        or a quote from IAS attestation report (which is missing signature
 *                        fields).
 *  \param[in] quote_size Size of \a quote_data in bytes.
 */
void display_quote(const void* quote_data, size_t quote_size);

/*!
 *  \brief Display internal SGX report body structure (sgx_report_body_t).
 *  
 *  \param[in] body Buffer with report body data.
 */
void display_report_body(const sgx_report_body_t* body);

#endif /* ATTESTATION_H */
