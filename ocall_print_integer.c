/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>

/* Ensure that ocall_print_string has exern C linkage */
#include <enclave_u.h>

void ocall_print_integer(int num)
{
  printf("%x", num);
}
