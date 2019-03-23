/*
 * Functional implementation for handling Cast device authentication.
 *
 * Copyright (C) 2016-2019 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "php_castptl.h"
#include <openssl/err.h>
#include "socket.h"
#include "buffer.h"

/**
 * Optional method to check the validity of the cast device instance, based
 * on a private signed key exchange with the Google certificate.
 *
 * @param conn The persistent connection to the cast device instance.
 * @return 0 if the device is authentic, -1 on authentication or related
 *         device messaging error.
 */
int castDeviceAuth(CastDeviceConnection *conn)
{
    return -1;
}
