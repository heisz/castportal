/*
 * Header definitions for the Cast Portal PHP extension API.
 *
 * Copyright (C) 2016-2019 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#ifndef _PHP_CASTPTL_H
#define _PHP_CASTPTL_H 1

/* Standard inclusions for autoconf and PHP elements */
#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#ifdef ZTS
    #include <TSRM.h>
#endif

#include <php.h>
#include <php_ini.h>

/* Encapsulate PHP-isms, along with functional migrations from PHP5 -> PHP 7 */
#define PHP_BOOL_TRUE 1
#define PHP_BOOL_FALSE 0

#if PHP_MAJOR_VERSION < 7
    #define PHP_DECLARE_ZVAL(zv_nm) zval *zv_nm
    #define PHP_ALLOC_INIT_ZVAL(zv_nm) ALLOC_INIT_ZVAL(zv_nm)
    #define PHP_ADD_ASSOC_STR(arr, key, str) add_assoc_string(arr, key, str, \
                                                              PHP_BOOL_TRUE)
#else
    #define PHP_DECLARE_ZVAL(zv_nm) zval zv_nm##_var;\
                                    zval *zv_nm = &zv_nm##_var
    #define PHP_ALLOC_INIT_ZVAL(zv_nm) ZVAL_NULL(zv_nm)
    #define PHP_ADD_ASSOC_STR(arr, key, str) add_assoc_string(arr, key, str)
#endif

/* Fixed definitions for extension details */
#define CPTL_EXTENSION_EXTNAME "castportal"
#define CPTL_EXTENSION_VERSION "1.0"

/* Exposed definition of the extension module instance */
extern zend_module_entry castportal_module_entry;

/* Standard function definitions for PHP module/request extensions */
PHP_MINIT_FUNCTION(castportal);
PHP_MSHUTDOWN_FUNCTION(castportal);
PHP_RINIT_FUNCTION(castportal);
PHP_RSHUTDOWN_FUNCTION(castportal);
PHP_MINFO_FUNCTION(castportal);

/* Definitions for the functional extension capabilities */
PHP_FUNCTION(cptl_discover);

/* Remainder of this file deals with internal functional elements */

/* Linked list data object for returning discovery results */
typedef struct _castDeviceInfo {
    char id[256];
    char name[256];
    char model[256];
    char ipAddr[32];
    uint16_t port;
    struct _castDeviceInfo *next;
} CastDeviceInfo;

/**
 * Execute a cast discovery process, using multicast DNS queries.
 *
 * @param ipMode Flagset to determine which IP networks to discover against,
 *               mix of CPTL_INET4 (1) and CPTL_INET6 (2), as defined in the
 *               global PHP constants.
 * @param waitTm Time period (in seconds) to wait for responses to
 *               the UDP query.
 * @param tstMode TRUE (non-zero) if running in test mode, which discards
 *                real discovery responses and processes locked test data.
 * @return Linked list of discovered cast devices or NULL on error/empty.
 */
CastDeviceInfo *castDiscover(int ipMode, int waitTm, int tstMode);

#endif
