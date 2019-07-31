/*
 * Functions pertaining to cast device management (connections).
 *
 * Copyright (C) 2016-2019 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "php_castptl.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include "json.h"

/* If you have to uncomment this, you probably won't link properly */
/*
 * void SSL_trace(int write_p, int version, int content_type,
 *                const void *buf, size_t len, SSL *ssl, void *arg);
 */

/* To make things exciting, custom BIO to handle unblocked read on demand */
/* Note: even though it is a socket, uses ptr->object so *not* descriptor! */

#define BIO_TYPE_WXSOCKET (69 | BIO_TYPE_SOURCE_SINK)

static int castSslWrite(BIO *bio, const char *data, int len) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    CastDeviceConnection *conn = bio->ptr;
#else
    CastDeviceConnection *conn = (CastDeviceConnection *) BIO_get_data(bio);
#endif
    int ret = 0;

    /* Outbound is always blocking */
    if (data != NULL) {
        ret = (int) WXSocket_Send(conn->scktHandle, data, len, 0);
    }

    return ret;
}

static int castSslRead(BIO *bio, char *data, int len) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    CastDeviceConnection *conn = bio->ptr;
#else
    CastDeviceConnection *conn = (CastDeviceConnection *) BIO_get_data(bio);
#endif
    int ret = 0;

    if (data != NULL) {
        ret = (int) WXSocket_Recv(conn->scktHandle, data, len,
                                  (conn->isConnected) ? MSG_DONTWAIT : 0);
        BIO_clear_retry_flags(bio);
        if (ret == 0) {
            BIO_set_retry_read(bio);
            /* Need to force an error condition for SSL to read this state */
            ret = -1;
        }
    }

    return ret;
}

static int castSslPuts(BIO *bio, const char *str) {
    return castSslWrite(bio, str, strlen(str));
}

/* Note: unlike the OpenSSL sock implementation, socket managed externally */
static long castSslCtrl(BIO *bio, int cmd, long num, void *ptr) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    CastDeviceConnection *conn = bio->ptr;
#else
    CastDeviceConnection *conn = (CastDeviceConnection *) BIO_get_data(bio);
#endif
    long ret = 1;

    if (conn == NULL) return 0;
    switch (cmd) {
        case BIO_C_SET_FD:
            /* Ignore, should not be called... */
            break;

        case BIO_C_GET_FD:
            if (ptr != NULL) *((int *) ptr) = (int) conn->scktHandle;
            ret = conn->scktHandle;
            break;

        case BIO_CTRL_GET_CLOSE:
            ret = (long) conn->scktHandle;
            break;

        case BIO_CTRL_SET_CLOSE:
            /* Just like for setFd, ignore */
            break;

        case BIO_CTRL_DUP:
        case BIO_CTRL_FLUSH:
            ret = 1;
            break;

        default:
            ret = 0;
            break;
    }

    return ret;
}

/* BIO just a reference to the external conn object, placeholders here */
static int castSslNew(BIO *bio) {
    return 1;
}

static int castSslFree(BIO *bio) {
    return 1;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static const BIO_METHOD castSslMethods = {
    BIO_TYPE_WXSOCKET,
    "wxsocket",
    castSslWrite,
    castSslRead,
    castSslPuts,
    NULL,
    castSslCtrl,
    castSslNew,
    castSslFree,
    NULL
};

const BIO_METHOD *castSslBio() {
    return (&castSslMethods);
}

#else

const BIO_METHOD *castSslBio() {
    static BIO_METHOD *biom = NULL;

    if (biom == NULL) {
        biom = BIO_meth_new(BIO_TYPE_WXSOCKET, "wxsocket");
        BIO_meth_set_write(biom, castSslWrite);
        BIO_meth_set_read(biom, castSslRead);
        BIO_meth_set_puts(biom, castSslPuts);
        BIO_meth_set_ctrl(biom, castSslCtrl);
        BIO_meth_set_create(biom, castSslNew);
        BIO_meth_set_destroy(biom, castSslFree);
    }

    return biom;
}

#endif

/* Wrap all of the above into a tidy bow */
static int bindSslBio(CastDeviceConnection *conn) {
    BIO *bio;

    bio = BIO_new(castSslBio());
    if (bio == NULL) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Failed to allocate BIO instance");
        return -1;
    }
    BIO_set_data(bio, conn);
    BIO_set_init(bio, 1);
    SSL_set_bio(conn->ssl, bio, bio);

    return 0;
}

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
CastDeviceConnection *castDeviceConnect(char *devAddr, int port) {
    char txtBuff[256], errBuff[256];
    const SSL_METHOD *connMethod;
    CastDeviceConnection *retVal;
    unsigned long sslErrNo;
    WXSocket scktHandle;

    /* Allocate connection/resource object for complex return */
    retVal = (CastDeviceConnection *) WXMalloc(sizeof(CastDeviceConnection));
    if (retVal == NULL) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Failed to allocate connection resource");
        return NULL;
    }
    (void) memset(retVal, 0, sizeof(CastDeviceConnection));
    WXBuffer_InitLocal(&(retVal->readBuffer), retVal->readBufferData,
                       sizeof(retVal->readBufferData));

    /* Handle test simulation */
    if (_cptl_tstmode != 0) {
        retVal->scktHandle = INVALID_SOCKET_FD;
        retVal->isConnected = FALSE;
        return retVal;
    }

    /* Create the base connection instance */
    (void) sprintf(txtBuff, "%d", port);
    if (WXSocket_OpenTCPClient(devAddr, txtBuff, &scktHandle,
                               NULL) != WXNRC_OK) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Connection failure for %s: %s", devAddr,
                         WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
        return NULL;
    }
    retVal->scktHandle = scktHandle;
    retVal->isConnected = FALSE;
    retVal->requestId = 0;

    /* Setup SSL context (negotiated maximum) and associate to socket */
    if (((connMethod = TLS_client_method()) == NULL) ||
        ((retVal->sslCtx = SSL_CTX_new(connMethod)) == NULL)) {
        sslErrNo = ERR_get_error();
        ERR_error_string_n(sslErrNo, errBuff, sizeof(errBuff));
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Failed to initialize client SSL context [%s]",
                         errBuff);
        castDeviceClose(retVal);
        return NULL;
    }
    if (((retVal->ssl = SSL_new(retVal->sslCtx)) == NULL) ||
                                       (bindSslBio(retVal) < 0)) {
        sslErrNo = ERR_get_error();
        ERR_error_string_n(sslErrNo, errBuff, sizeof(errBuff));
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Failed to associate SSL processing [%s]", errBuff);
        castDeviceClose(retVal);
        return NULL;
    }

    /* Debugging support, will only work if OpenSSL is compiled with trace */
    /*
    SSL_set_msg_callback(retVal->ssl, SSL_trace);
    SSL_set_msg_callback_arg(retVal->ssl, BIO_new_fp(stderr, 0));
     */

    /* And negotiate the connection (synchronous) */
    SSL_set_connect_state(retVal->ssl);
    if (SSL_connect(retVal->ssl) <= 0) {
        sslErrNo = ERR_get_error();
        ERR_error_string_n(sslErrNo, errBuff, sizeof(errBuff));
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Failed to establish SSL connection [%s]", errBuff);
        castDeviceClose(retVal);
        return NULL;
    }

    /* We are connected! */
    retVal->isConnected = TRUE;

    /* Initial connection always starts with a baseline connect message */
    if (castSendMessage(retVal, FALSE, FALSE, NS_CONNECTION,
                        "{\"type\": \"CONNECT\"}", -1) < 0) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Failed to issue CONNECT request");
        castDeviceClose(retVal);
        return NULL;
    }

    /* No response is currently returned from the connect message */

    return retVal;
}

/* Test response for PING request */
static uint8_t _tstPongResp[] = {
    0x00, 0x00, 0x00, 0x54, 0x08, 0x00, 0x12, 0x0A,   // ...T....
    0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x72,   // receiver
    0x2D, 0x30, 0x1A, 0x08, 0x73, 0x65, 0x6E, 0x64,   // -0..send
    0x65, 0x72, 0x2D, 0x30, 0x22, 0x27, 0x75, 0x72,   // er-0"'ur
    0x6E, 0x3A, 0x78, 0x2D, 0x63, 0x61, 0x73, 0x74,   // n:x-cast
    0x3A, 0x63, 0x6F, 0x6D, 0x2E, 0x67, 0x6F, 0x6F,   // :com.goo
    0x67, 0x6C, 0x65, 0x2E, 0x63, 0x61, 0x73, 0x74,   // gle.cast
    0x2E, 0x74, 0x70, 0x2E, 0x68, 0x65, 0x61, 0x72,   // .tp.hear
    0x74, 0x62, 0x65, 0x61, 0x74, 0x28, 0x00, 0x32,   // tbeat(.2
    0x0F, 0x7B, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22,   // .{"type"
    0x3A, 0x22, 0x50, 0x4F, 0x4E, 0x47, 0x22, 0x7D    // :"PONG"}
};

/* Marker tag for response and validation return */
static char *_pongOk = "PONG";

/**
 * Callback to validate pong response, filtered against the global sender and
 * receiver, heartbeat namespace and JSON response.  Returns global marker
 * if type matches successfully.
 */
static void *validatePongResponse(CastDeviceConnection *conn, void *content,
                                  size_t contentLen) {
    WXJSONValue *val = (WXJSONValue *) content;
    WXJSONValue *respType = WXHash_GetEntry(&(val->value.oval), "type",
                                        WXHash_StrHashFn, WXHash_StrEqualsFn);
    if ((respType == NULL) || (respType->type != WXJSONVALUE_STRING)) {
        return CPTL_RESP_ERROR;
    }
    if (strcmp(respType->value.sval, _pongOk) == 0) return _pongOk;
    return NULL;
}

/**
 * Exchange a ping/heartbeat keepalive message with the cast device.
 *
 * @param conn The connection instance returned from the device connect method.
 * @return Zero on success, -1 on error (logged).
 */
int castDevicePing(CastDeviceConnection *conn) {
    void *retval = NULL;

    /* Just in case a malformed resource gets destroyed */
    if (conn == NULL) return -1;

    /* Pretty basic message structure, I actually had this sequence years ago */
    if (castSendMessage(conn, FALSE, FALSE, NS_HEARTBEAT,
                        "{\"type\": \"PING\"}", -1) < 0) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Failed to issue PING request");
        return -1;
    }

    /* And the response */
    _cptl_tstresp = _tstPongResp;
    _cptl_tstresplen = sizeof(_tstPongResp);
    retval = castReceiveMessage(conn, FALSE, FALSE, NS_HEARTBEAT,
                                validatePongResponse, TRUE, -1);
    if (retval != _pongOk) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Failed to obtain PONG response to PING request");
        return -1;
    }

    return 0;
}

/**
 * Close the persistent connection instance that was opened by the auth method.
 *
 * @param conn The connection instance returned from the device connect method.
 *             Note that the instance will be freed by this method and should
 *             no longer be referenced (NULLify the resource).
 */
void castDeviceClose(CastDeviceConnection *conn) {
    /* Just in case a malformed resource gets destroyed */
    if (conn == NULL) return;

    /* Quietly be polite about it, no response because we're going to close */
    (void) castSendMessage(conn, FALSE, FALSE, NS_CONNECTION,
                           "{\"type\": \"CLOSE\"}", -1);

    /* And then just unwind the connection elements */
    if (conn->scktHandle != INVALID_SOCKET_FD) WXSocket_Close(conn->scktHandle);
    WXBuffer_Destroy(&(conn->readBuffer));
    WXFree(conn);
}
