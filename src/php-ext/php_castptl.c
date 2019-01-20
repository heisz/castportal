/*
 * API entry points for the cast portal PHP extensions.
 *
 * Copyright (C) 2016-2019 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "php_castptl.h"
#include "mem.h"

/* Obtain the module context for the extension instance */
#if COMPILE_DL_CASTPORTAL
    ZEND_GET_MODULE(castportal)
#endif

/* Definition table for extension function instances */
static const zend_function_entry cptl_functions[] = {
    PHP_FE(cptl_discover, NULL)
    PHP_FE_END
};

/* Where the magic happens */
zend_module_entry castportal_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    CPTL_EXTENSION_EXTNAME, 
    cptl_functions,
    PHP_MINIT(castportal),
    PHP_MSHUTDOWN(castportal),
    PHP_RINIT(castportal),
    PHP_RSHUTDOWN(castportal),
    PHP_MINFO(castportal),
#if ZEND_MODULE_API_NO >= 20010901
    CPTL_EXTENSION_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

PHP_INI_BEGIN()
PHP_INI_END()

PHP_MINIT_FUNCTION(castportal) {
    REGISTER_INI_ENTRIES();

    /* Constants for the discovery flagset */
    REGISTER_LONG_CONSTANT("CPTL_INET4", 1, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("CPTL_INET6", 2, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("CPTL_INET_ALL", 3, CONST_CS | CONST_PERSISTENT);

    return SUCCESS;
}
PHP_MSHUTDOWN_FUNCTION(castportal) {
    UNREGISTER_INI_ENTRIES();

    return SUCCESS;
}
PHP_RINIT_FUNCTION(castportal) {
    return SUCCESS;
}
PHP_RSHUTDOWN_FUNCTION(castportal) {
    return SUCCESS;
}

PHP_MINFO_FUNCTION(castportal) {}

/**
 * Execute a cast discovery process, through a call to cptl_discover().
 *
 * @param ipMode Flagset to determine which IP networks to discover against,
 *               mix of CPTL_INET4 and CPTL_INET6.
 * @param timeout Time period (in seconds) to wait for responses for each
 *                category of network request.
 * @param isTest Indicates that the extension is operating in test mode,
 *               as used by the internal test program.  Optional, defaults
 *               to false for 'normal' usage.
 */
PHP_FUNCTION(cptl_discover) {
    CastDeviceInfo *info, *next;
    PHP_DECLARE_ZVAL(zv_ptr);
    long ipMode, timeout;
    zend_bool isTest = 0;

    /* Read the argument set for the function */
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ll|b",
                              &ipMode, &timeout, &isTest) != SUCCESS) return;

    /* Execute the discovery process */
    info = castDiscover(ipMode, timeout, isTest);

    /* And convert it to a hash array for data return */
    array_init(return_value);
    while (info != NULL) {
        PHP_ALLOC_INIT_ZVAL(zv_ptr);
        array_init(zv_ptr);
        PHP_ADD_ASSOC_STR(zv_ptr, "id", info->id);
        PHP_ADD_ASSOC_STR(zv_ptr, "name", info->name);
        PHP_ADD_ASSOC_STR(zv_ptr, "model", info->model);
        PHP_ADD_ASSOC_STR(zv_ptr, "ipAddr", info->ipAddr);
        add_assoc_long(zv_ptr, "port", (long) info->port);
        add_next_index_zval(return_value, zv_ptr);

        next = info->next;
        WXFree(info);
        info = next;
    }
}
