/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include <enclave_t.h>
#include "enclave.h"

#include <sgx_tcrypto.h>
#include <sgx_utils.h>
#include <sgx_tseal.h>

/**
 * This function generates a key pair and then seals the private key.
 *
 * @param pubkey                 Output parameter for public key.
 * @param pubkey_size            Input parameter for size of public key.
 * @param sealedprivkey          Output parameter for sealed private key.
 * @param sealedprivkey_size     Input parameter for size of sealed private key.
 *
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success, some
 *                               sgx_status_t value upon failure.
 */

sgx_status_t ecall_key_gen_and_seal(char *pubkey, size_t pubkey_size, char *sealedprivkey, size_t sealedprivkey_size)
{
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;

  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS)
  {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }

  // Step 2: Create Key Pair.
  sgx_ec256_private_t p_private;
  // if ((ret = sgx_ecc256_create_key_pair(&p_private, (sgx_ec256_public_t *)pubkey, p_ecc_handle)) != SGX_SUCCESS)
  // {
  //   print("\nTrustedApp: sgx_ecc256_create_key_pair() failed !\n");
  //   goto cleanup;
  // }

  for(int i=0;i<SGX_ECP256_KEY_SIZE;i++)
  {
    p_private.r[i] = 0x02;
  }

  if ((ret = sgx_ecc256_calculate_pub_from_priv(&p_private, (sgx_ec256_public_t *)pubkey)) != SGX_SUCCESS)
  {
    print("\nTrustedApp: sgx_ecc256_calculate_pub_from_priv() failed !\n");
    goto cleanup;
  }

  static const uint8_t  kQx[] = {
    0xc8, 0x15, 0x61, 0xec, 0xf2, 0xe5, 0x4e, 0xde, 0xfe, 0x66, 0x17,
    0xdb, 0x1c, 0x7a, 0x34, 0xa7, 0x07, 0x44, 0xdd, 0xb2, 0x61, 0xf2,
    0x69, 0xb8, 0x3d, 0xac, 0xfc, 0xd2, 0xad, 0xe5, 0xa6, 0x81
  };
  static const uint8_t  kQy[] = {
    0xe0, 0xe2, 0xaf, 0xa3, 0xf9, 0xb6, 0xab, 0xe4, 0xc6, 0x98, 0xef,
    0x64, 0x95, 0xf1, 0xbe, 0x49, 0xa3, 0x19, 0x6c, 0x50, 0x56, 0xac,
    0xb3, 0x76, 0x3f, 0xe4, 0x50, 0x7e, 0xec, 0x59, 0x6e, 0x88
  };
  static const uint8_t  kD[] = {
    0xc6, 0xc1, 0xaa, 0xda, 0x15, 0xb0, 0x76, 0x61, 0xf8, 0x14, 0x2c,
    0x6c, 0xaf, 0x0f, 0xdb, 0x24, 0x1a, 0xff, 0x2e, 0xfe, 0x46, 0xc0,
    0x93, 0x8b, 0x74, 0xf2, 0xbc, 0xc5, 0x30, 0x52, 0xb0, 0x77
  };

  for(int i=0;i<SGX_ECP256_KEY_SIZE;i++)
  {
    p_private.r[i] = kD[i];
  }

  for(int i=0;i<SGX_ECP256_KEY_SIZE;i++)
  {
    pubkey[i] = kQx[SGX_ECP256_KEY_SIZE-1-i];
  }
  for(int i=0;i<SGX_ECP256_KEY_SIZE;i++)
  {
    pubkey[i+32] = kQy[SGX_ECP256_KEY_SIZE-1-i];
  }

  print("\n\n\n");

  for(int i=0;i<SGX_ECP256_KEY_SIZE;i++)
  {
    printInt(p_private.r[i]);
  }

  // print("\n");

  // for(int i=SGX_ECP256_KEY_SIZE-1; i>=0;i--)
  // {
  //   printInt(p_private.r[i]);
  // }

  print("\n\n\n");
  for(int i=0;i<SGX_ECP256_KEY_SIZE*2;i++)
  {
    printInt((uint8_t)pubkey[i]);
  }
  
  // print("\n");

  // for(int i=SGX_ECP256_KEY_SIZE*2-1;i>=0;i--)
  // {
  //   printInt((uint8_t)pubkey[i]);
  // }

  print("\n\n\n");

  // Step 3: Calculate sealed data size.
  if (sealedprivkey_size >= sgx_calc_sealed_data_size(0U, sizeof(p_private)))
  {
    if ((ret = sgx_seal_data(0U, NULL, sizeof(p_private), (uint8_t *)&p_private, (uint32_t) sealedprivkey_size, (sgx_sealed_data_t *)sealedprivkey)) != SGX_SUCCESS)
    {
      print("\nTrustedApp: sgx_seal_data() failed !\n");
      goto cleanup;
    }
  }
  else
  {
    print("\nTrustedApp: Size allocated for sealedprivkey by untrusted app is less than the required size !\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  print("\nTrustedApp: Key pair generated and private key was sealed. Sent the public key and sealed private key back.\n");
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  if (p_ecc_handle != NULL)
  {
    sgx_ecc256_close_context(p_ecc_handle);
  }

  return ret;
}
