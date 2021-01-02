#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ecall_key_gen_and_seal(char* pubkey, size_t pubkey_size, char* sealedprivkey, size_t sealedprivkey_size);
sgx_status_t ecall_calc_buffer_sizes(size_t* epubkey_size, size_t* esealedprivkey_size, size_t* esignature_size);
sgx_status_t ecall_unseal_and_sign(uint8_t* msg, uint32_t msg_size, char* sealed, size_t sealed_size, char* signature, size_t signature_size);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_print_integer(int num);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
