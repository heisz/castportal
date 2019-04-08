dnl
dnl PHP configuration file for the CastPortal API extension
dnl
dnl Copyright (C) 2016-2019 J.M. Heisz.  All Rights Reserved.
dnl See the LICENSE file accompanying the distribution your rights to use
dnl this software.
dnl

PHP_ARG_ENABLE(castportal, whether to enable Cast Portal extension support, 
               [  --enable-castportal     Enable Cast Portal extension support])

PHP_ARG_WITH(openssl-dir, for the availability of OpenSSL support, 
             [  --with-openssl-dir[=DIR]    Specify OpenSSL support], yes, no)

if test $PHP_CASTPORTAL != "no"; then
    dnl
    dnl Lots of header checks are required (from toolkit)
    dnl
    AC_CHECK_HEADERS([fcntl.h])
    AC_CHECK_HEADERS([sys/time.h])
    AC_CHECK_HEADERS([arpa/inet.h])
    AC_CHECK_HEADERS([netinet/in.h])
    AC_CHECK_HEADERS([endian.h])
    AC_CHECK_HEADERS([sys/endian.h])
    AC_CHECK_HEADERS([byteswap.h])

    dnl
    dnl Requires OpenSSL for the TLS communication with cast devices
    dnl
    PHP_SETUP_OPENSSL(OPENSSL_SHARED_LIBADD, [
        AC_DEFINE(HAVE_OPENSSL_EXT,1,[ ])
    ], [
        AC_MSG_ERROR([Unable to resolve OpenSSL library (required).])
    ])

    PHP_ADD_INCLUDE(toolkit)
    PHP_ADD_INCLUDE(toolkit/src/lang)
    PHP_ADD_INCLUDE(toolkit/src/network)
    PHP_ADD_INCLUDE(toolkit/src/utility)
    PHP_NEW_EXTENSION(castportal,
                      php_castptl.c castptl_discover.c castptl_device.c \
                      castptl_auth.c castptl_app.c castptl_message.c \
                      castptl_compat.c \
                      toolkit/src/lang/json.c toolkit/src/network/socket.c \
                      toolkit/src/utility/hash.c toolkit/src/utility/array.c \
                      toolkit/src/utility/buffer.c, 
                      $ext_shared)
fi
