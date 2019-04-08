/*
 * API entry points for the cast portal PHP extensions.
 *
 * Copyright (C) 2016-2019 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "php_castptl.h"
#include "zend_exceptions.h"
#include "mem.h"

/* Elements for test mode: mode 0 - normal, 1 - simulate, 2 - invalid */
long _cptl_tstmode = 0;
void *_cptl_tstresp = NULL;
long _cptl_tstresplen = 0;

/* Obtain the module context for the extension instance */
#if COMPILE_DL_CASTPORTAL
    ZEND_GET_MODULE(castportal)
#endif

/* Definition table for extension function instances */
static const zend_function_entry cptl_functions[] = {
    PHP_FE(cptl_testctl, NULL)
    PHP_FE(cptl_discover, NULL)
    PHP_FE(cptl_device_connect, NULL)
    PHP_FE(cptl_device_auth, NULL)
    PHP_FE(cptl_device_ping, NULL)
    PHP_FE(cptl_device_close, NULL)
    PHP_FE(cptl_app_available, NULL)
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

/* Declarations for global ini variables for the extension */
PHP_INI_BEGIN()
    /* Note: this default is the Cast application id for 'portal' */
    STD_PHP_INI_ENTRY("castportal.application_id", "02834648", PHP_INI_SYSTEM,
                      OnUpdateString, applicationId, zend_castportal_globals,
                      castportal_globals)
    STD_PHP_INI_ENTRY("castportal.discovery_timeout", "5000", PHP_INI_SYSTEM,
                      OnUpdateLong, discoveryTimeout, zend_castportal_globals,
                      castportal_globals)
    STD_PHP_INI_ENTRY("castportal.message_timeout", "500", PHP_INI_SYSTEM,
                      OnUpdateLong, messageTimeout, zend_castportal_globals,
                      castportal_globals)
PHP_INI_END()

/* Tracking and destructor for the Cast connection resource object */
int castptl_devconn_resid;
static ZEND_RSRC_DTOR_FUNC(castptl_devconn_dtor) {
#if PHP_MAJOR_VERSION < 7
    CastDeviceConnection *conn = (CastDeviceConnection *) rsrc->ptr;
#else
    CastDeviceConnection *conn = (CastDeviceConnection *) res->ptr;
#endif

    /* Comparatively, it's pretty easy when you have a wrapping method */
    if (conn != NULL) castDeviceClose(conn);
}

PHP_MINIT_FUNCTION(castportal) {
    REGISTER_INI_ENTRIES();

    /* Constants for the discovery flagset */
    REGISTER_LONG_CONSTANT("CPTL_INET4", 1, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("CPTL_INET6", 2, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("CPTL_INET_ALL", 3, CONST_CS | CONST_PERSISTENT);

    /* Initialize OpenSSL resources */
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    /* Track the connection resources */
    castptl_devconn_resid =
        zend_register_list_destructors_ex(castptl_devconn_dtor, NULL,
                                          PHP_CASTPTL_DEVCONN_RESNAME,
                                          module_number);

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
 * Control method to enable various test processing models.
 *
 * @param mode Mode argument for test control.
 */
PHP_FUNCTION(cptl_testctl) {
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
                              &_cptl_tstmode) != SUCCESS) return;
    RETURN_TRUE;
}

/**
 * Execute a cast discovery process, through a call to cptl_discover().
 *
 * @param ipMode Flagset to determine which IP networks to discover against,
 *               mix of CPTL_INET4 and CPTL_INET6.  Defaults to ALL if
 *               unspecified.
 * @param timeout Time period (in milliseconds) to wait for responses for each
 *                category of network request.  If unspecified (or zero),
 *                defaults to the system-level configuration value.
 */
PHP_FUNCTION(cptl_discover) {
    CastDeviceInfo *info, *next;
    long ipMode = 3, timeout = 0;
#if PHP_MAJOR_VERSION < 7
    zval *zvRow;
#else
    zval zvRowData; zval *zvRow = &zvRowData;
#endif

    /* Read the argument set for the function */
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ll",
                              &ipMode, &timeout) != SUCCESS) return;

    /* Execute the discovery process */
    info = castDiscover(ipMode, timeout);

    /* And convert it to a hash array for data return */
    array_init(return_value);
    while (info != NULL) {
#if PHP_MAJOR_VERSION < 7
        ALLOC_INIT_ZVAL(zvRow);
        array_init(zvRow);
        add_assoc_string(zvRow, "id", info->id, 1);
        add_assoc_string(zvRow, "name", info->name, 1);
        add_assoc_string(zvRow, "model", info->model, 1);
        add_assoc_string(zvRow, "ipAddr", info->ipAddr, 1);
#else
        ZVAL_NULL(zvRow);
        array_init(zvRow);
        add_assoc_string(zvRow, "id", info->id);
        add_assoc_string(zvRow, "name", info->name);
        add_assoc_string(zvRow, "model", info->model);
        add_assoc_string(zvRow, "ipAddr", info->ipAddr);
#endif
        add_assoc_long(zvRow, "port", (long) info->port);
        add_next_index_zval(return_value, zvRow);

        next = info->next;
        WXFree(info);
        info = next;
    }
}

/**
 * Execute a cast connection to create a persistent message channel (NOT
 * PHP-persistent!).
 *
 * @param devAddr Network address (typically from discovery) of the cast
 *                device to connect to.
 * @param port Connection port as discovered - optional, defaults to 8009.
 * @return Device connection resource for remaining messaging methods.
 */
PHP_FUNCTION(cptl_device_connect) {
    CastDeviceConnection *conn;
    long port = 8009;
    int ipAddrLen;
    char* ipAddr;

    /* Read the argument set for the function */
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l",
                              &ipAddr, &ipAddrLen, &port) != SUCCESS) return;

    /* Hand off to the device authentication method */
    /* Note that this assumes no monkey business with the string content */
    conn = castDeviceConnect(ipAddr, port);
    if (conn == NULL) {
        zend_throw_exception(zend_exception_get_default(TSRMLS_C),
                             "Unable to obtain/authenticate cast connection",
                             0 TSRMLS_CC);
        RETURN_FALSE;
    }

    /* Authentication successful, allocate a resource to track the connection */
#if PHP_MAJOR_VERSION < 7
    ZEND_REGISTER_RESOURCE(return_value, conn, castptl_devconn_resid);
#else
    RETURN_RES(zend_register_resource(conn, castptl_devconn_resid));
#endif
}

/**
 * Authenticate that the device on the other side of the connection is a valid
 * Google chromecast device (through private signatures).
 *
 * @param conn The device connection instance returned from cptl_device_connect.
 */
PHP_FUNCTION(cptl_device_auth) {
    CastDeviceConnection *conn;
    zval *zvRes = NULL;

    /* Access the resource for the associated connection */
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r",
                              &zvRes) != SUCCESS) return;

#if PHP_MAJOR_VERSION < 7
    ZEND_FETCH_RESOURCE(conn, CastDeviceConnection *, &zvRes, -1,
                        PHP_CASTPTL_DEVCONN_RESNAME, castptl_devconn_resid);
#else
    conn = (CastDeviceConnection *) zend_fetch_resource(Z_RES_P(zvRes),
                           PHP_CASTPTL_DEVCONN_RESNAME, castptl_devconn_resid);
#endif
    if (conn == NULL) {
        RETURN_FALSE;
        return;
    }

    if (castDeviceAuth(conn) < 0) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Failed to authenticate remote cast device");
#if PHP_MAJOR_VERSION < 7
        zend_list_delete(Z_LVAL_P(zvRes));
#else
        zend_list_close(Z_RES_P(zvRes));
#endif
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}

/**
 * Exchange a ping/heartbeat message to maintain the persistent connection
 * instance.
 *
 * @param conn The device connection instance returned from cptl_device_connect.
 * @return True if the device connection is still valid (pong response), false
 *         on failure (logged).
 */
PHP_FUNCTION(cptl_device_ping) {
    CastDeviceConnection *conn;
    zval *zvRes = NULL;

    /* Access the resource for the associated connection */
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r",
                              &zvRes) != SUCCESS) return;

#if PHP_MAJOR_VERSION < 7
    ZEND_FETCH_RESOURCE(conn, CastDeviceConnection *, &zvRes, -1,
                        PHP_CASTPTL_DEVCONN_RESNAME, castptl_devconn_resid);
#else
    conn = (CastDeviceConnection *) zend_fetch_resource(Z_RES_P(zvRes),
                           PHP_CASTPTL_DEVCONN_RESNAME, castptl_devconn_resid);
#endif
    if (conn == NULL) {
        RETURN_FALSE;
        return;
    }

    /* And perform the ping operation */
    if (castDevicePing(conn) < 0) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Failed to ping remote cast device");
#if PHP_MAJOR_VERSION < 7
        zend_list_delete(Z_LVAL_P(zvRes));
#else
        zend_list_close(Z_RES_P(zvRes));
#endif
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}

/**
 * Close the persistent connection instance that was opened by the auth method.
 * Note that this will destroy/free the connection instance as well as the
 * associated resource.
 *
 * @param conn The device connection instance returned from cptl_device_connect.
 */
PHP_FUNCTION(cptl_device_close) {
    CastDeviceConnection *conn;
    zval *zvRes = NULL;

    /* Access the resource and just delete if valid, destructor will close */
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r",
                              &zvRes) != SUCCESS) return;

#if PHP_MAJOR_VERSION < 7
    ZEND_FETCH_RESOURCE(conn, CastDeviceConnection *, &zvRes, -1,
                        PHP_CASTPTL_DEVCONN_RESNAME, castptl_devconn_resid);
    if (conn != NULL) {
        zend_list_delete(Z_LVAL_P(zvRes));
        RETURN_TRUE;
    } else {
        RETURN_FALSE;
    }
#else
    conn = (CastDeviceConnection *) zend_fetch_resource(Z_RES_P(zvRes),
                           PHP_CASTPTL_DEVCONN_RESNAME, castptl_devconn_resid);
    if (conn != NULL) {
        zend_list_close(Z_RES_P(zvRes));
        RETURN_TRUE;
    } else {
        RETURN_FALSE;
    }
#endif
}

/**
 * Validate the availability of the configured portal application instance
 * on the provided device.
 *
 * @param conn The device connection instance returned from cptl_device_connect.
 * @return True if the application is defined/available or false on any failure
 *         in the request (logged).
 */
PHP_FUNCTION(cptl_app_available) {
    CastDeviceConnection *conn;
    zval *zvRes = NULL;

    /* Access the resource for the associated connection */
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r",
                              &zvRes) != SUCCESS) return;

#if PHP_MAJOR_VERSION < 7
    ZEND_FETCH_RESOURCE(conn, CastDeviceConnection *, &zvRes, -1,
                        PHP_CASTPTL_DEVCONN_RESNAME, castptl_devconn_resid);
#else
    conn = (CastDeviceConnection *) zend_fetch_resource(Z_RES_P(zvRes),
                           PHP_CASTPTL_DEVCONN_RESNAME, castptl_devconn_resid);
#endif
    if (conn == NULL) {
        RETURN_FALSE;
        return;
    }

    /* And check for the availability of the application */
    if (castAppCheckAvailability(conn) < 0) {
        RETURN_FALSE;
    } else {
        RETURN_TRUE;
    }
}
