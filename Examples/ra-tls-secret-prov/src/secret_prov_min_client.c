/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    printf("--- Received secret = '%s' ---\n", getenv("SECRET_PROVISION_SECRET_STRING"));
    return 0;
}
