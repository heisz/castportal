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
#include <openssl/ssl.h>
#include "socket.h"
#include "buffer.h"

/* Fixed definitions for extension details */
#define CPTL_EXTENSION_EXTNAME "castportal"
#define CPTL_EXTENSION_VERSION "1.0"

/* Exposed definition of the extension module instance */
extern zend_module_entry castportal_module_entry;

/* Global settings managed by php.ini (and related) with suitable defaults */
ZEND_BEGIN_MODULE_GLOBALS(castportal)
    char *applicationId;
    long discoveryTimeout;
    long messageTimeout;
ZEND_END_MODULE_GLOBALS(castportal)

ZEND_DECLARE_MODULE_GLOBALS(castportal)

/* And the accessor macros for the above */
#ifdef ZTS
    #define CPTL_G(v) TSRMG(castportal_globals_id, zend_castportal_globals *, v)
#else
    #define CPTL_G(v) (castportal_globals.v)
#endif

/* Internal tracking elements for test operation */
extern long _cptl_tstmode;
extern void *_cptl_tstresp;
extern long _cptl_tstresplen;

/* Standard function definitions for PHP module/request extensions */
PHP_MINIT_FUNCTION(castportal);
PHP_MSHUTDOWN_FUNCTION(castportal);
PHP_RINIT_FUNCTION(castportal);
PHP_RSHUTDOWN_FUNCTION(castportal);
PHP_MINFO_FUNCTION(castportal);

/* Definitions for the functional extension capabilities */
PHP_FUNCTION(cptl_testctl);
PHP_FUNCTION(cptl_discover);
PHP_FUNCTION(cptl_device_connect);
PHP_FUNCTION(cptl_device_auth);
PHP_FUNCTION(cptl_device_ping);
PHP_FUNCTION(cptl_device_close);
PHP_FUNCTION(cptl_app_available);

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
 * @param waitTm Time period (in milliseconds) to wait for responses to
 *               the UDP query.  If zero, use the system configuration value.
 * @return Linked list of discovered cast devices or NULL on error/empty.
 */
CastDeviceInfo *castDiscover(int ipMode, int waitTm);

/* Definitions for connection tracking object (PHP resource) */
#define PHP_CASTPTL_DEVCONN_RESNAME "CastConnection"

typedef struct {
    wxsocket_t scktHandle;
    SSL_CTX *sslCtx;
    SSL *ssl;
    int isConnected;
    WXBuffer readBuffer;
    char readBufferData[1024];
    int32_t requestId;
} CastDeviceConnection;

/**
 * Execute a cast connection to a device instance, to create a persistent
 * message channel (NOT PHP-persistent).
 *
 * @param devAddr Network address (typically from discovery) of the cast
 *                device to connect to.
 * @param port Connection port as discovered, 8009 would be typical.
 * @return TLS-enabled connection instance (allocated) or NULL if connection
 *         failed.
 */
CastDeviceConnection *castDeviceConnect(char *devAddr, int port);

/**
 * Optional method to check the validity of the cast device instance, based
 * on a private signed key exchange with the Google certificate.
 *
 * @param conn The persistent connection to the cast device instance.
 * @return 0 if the device is authentic, -1 on authentication or related
 *         device messaging error.
 */
int castDeviceAuth(CastDeviceConnection *conn);

/**
 * Exchange a ping/heartbeat keepalive message with the cast device.
 *
 * @param conn The connection instance returned from the device connect method.
 * @return Zero on success, -1 on error (logged).
 */
int castDevicePing(CastDeviceConnection *conn);

/**
 * Close the persistent connection instance that was opened by the auth method.
 *
 * @param conn The connection instance returned from the authentication method.
 *             Note that the instance will be freed by this method and should
 *             no longer be referenced (NULLify the resource).
 */
void castDeviceClose(CastDeviceConnection *conn);

/* Set of enumerations for namespace definition */
typedef enum {
    NS_ANY = -1,
    NS_CONNECTION = 0,
    NS_DEVICE_AUTH = 1,
    NS_HEARTBEAT = 2,
    NS_RECEIVER = 3,
    NS_UNKNOWN = 9999
} CastNamespace;

/**
 * Issue a message to the given cast device connection.
 *
 * @param conn The persistent connection to the cast device instance.
 * @param fromSenderSession If true (non-zero), message is originating from the
 *                          controller session, if false, originating from the
 *                          global application (sender-0).
 * @param toPortalReceiver If true (non-zero), message is being delivered to
 *                         to the portal application, if false, message is
 *                         intended for the global device receiver (receiver-0).
 * @param namespace Enumerated namespace for multiplexing messages across the
 *                  connection/channel.
 * @param data Payload of the message to be delivered, either binary or string
 *             content based on provided length.
 * @param dataLen Length of the prior data, -1 for a string, >= 0 for a binary
 *                buffer.
 * @return 0 if message successfully issued, -1 on error (already logged).
 */
int castSendMessage(CastDeviceConnection *conn, int fromSessionSender,
                    int toPortalReceiver, CastNamespace namespace,
                    void *data, ssize_t dataLen);

#define CPTL_RESP_ERROR ((void *) (intptr_t) -1)

/**
 * Definition for processing matched (according to specified criteria) response
 * messages from the cast device.
 *
 * Note: by design, the message processor will automatically clean up the
 *       parsed JSON content, *unless* the return value of the callback is the
 *       JSON value reference, in which case the caller must clean up.  If
 *       extracting data from the JSON content for return, it needs to be
 *       copied (or swapped out).
 *
 * @param conn The connection from which the response was received.
 * @param content The response content, either binary (contentLen >= 0) or
 *                a parsed JSON value (contentLen < 0).
 * @param contentLen For binary responses, the number of bytes in the dataset,
 *                   -1 if the content is parsed JSON data.
 * @return A non-NULL response if successfully processed, NULL to ignore this
 *         response and continue processing or CTPL_RESP_ERROR if a data error
 *         condition occured (and processing should stop).
 */
typedef void *ProcessResponseCB(CastDeviceConnection *conn, void *content,
                                size_t contentLen);

/**
 * Read responses from the cast device, looking for a matched response
 * according to the filtering criteria.  Timeout is managed by the global
 * module parameter setting.
 *
 * @param conn The connection to read responses from.
 * @param forSenderSession True (greater than zero) if expecting a message for
 *                         the controller session, false (zero) if for the
 *                         global application.  Negative indicates any.
 * @param fromPortalReceiver True (greater than zero) if expecting a message
 *                           from the portal application, false (zero) if from
 *                           the device receiver.  Negative indicates any.
 * @param namespace The namespace to match the response again, use NS_ANY (-1)
 *                  for any namespace.
 * @param responseCallback Reference to the method to handle callbacks for
 *                         matched response instances.
 * @param expJsonResponse True (greater than zero) if the callback is expecting
 *                        only JSON content, false (zero) for binary-only
 *                        content and negative for any response type.
 * @param requestId If greater than zero, match against the provided request
 *                  identifier.  This is ignored if the response is not JSON.
 * @return Non-null if a valid response was determined by the response callback
 *         function (value returned from callback is passed through) or NULL
 *         for any processing error (logged internally).  CPTL_RESP_ERROR is
 *         not returned by this method.
 */
void *castReceiveMessage(CastDeviceConnection *conn, int forSenderSession,
                         int fromPortalReceiver, CastNamespace namespace,
                         ProcessResponseCB responseCallback,
                         int expJsonResponse, int32_t requestId);

/**
 * Verify the availability of the configured application instance on the
 * associated device (connection).
 *
 * @param conn The connection instance returned from the device connect method.
 * @return Zero on success (communicated and configuration application is
 *         available), -1 on error or unavailable application (logged).
 */
int castAppCheckAvailability(CastDeviceConnection *conn);

#endif
