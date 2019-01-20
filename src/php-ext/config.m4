dnl
dnl PHP configuration file for the CastPortal API extension
dnl
dnl Copyright (C) 2016-2019 J.M. Heisz.  All Rights Reserved.
dnl See the LICENSE file accompanying the distribution your rights to use
dnl this software.
dnl

PHP_ARG_ENABLE(castportal, whether to enable Cast Portal extension support, 
               [  --enable-castportal     Enable Cast Portal extension support])

AC_CHECK_HEADERS([sys/time.h])

if test $PHP_CASTPORTAL != "no"; then
    PHP_ADD_INCLUDE(toolkit)
    PHP_ADD_INCLUDE(toolkit/src/network)
    PHP_ADD_INCLUDE(toolkit/src/utility)
    PHP_NEW_EXTENSION(castportal,
                      php_castptl.c castptl_discover.c \
                      castptl_compat.c toolkit/src/network/socket.c \
                      toolkit/src/utility/buffer.c, 
                      $ext_shared)
fi
