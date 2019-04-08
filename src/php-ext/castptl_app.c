/*
 * Functions pertaining to interfaces with the cast portal application.
 *
 * Copyright (C) 2016-2019 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "php_castptl.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include "json.h"

/* Test response for available/unavailable application instances */
static uint8_t _appAvailResp[] = {
    0x00, 0x00, 0x00, 0xA2, 0x08, 0x00, 0x12, 0x0A,   // ........
    0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x72,   // receiver
    0x2D, 0x30, 0x1A, 0x08, 0x73, 0x65, 0x6E, 0x64,   // -0..send
    0x65, 0x72, 0x2D, 0x30, 0x22, 0x23, 0x75, 0x72,   // er-0"#ur
    0x6E, 0x3A, 0x78, 0x2D, 0x63, 0x61, 0x73, 0x74,   // n:x-cast
    0x3A, 0x63, 0x6F, 0x6D, 0x2E, 0x67, 0x6F, 0x6F,   // :com.goo
    0x67, 0x6C, 0x65, 0x2E, 0x63, 0x61, 0x73, 0x74,   // gle.cast
    0x2E, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65,   // .receive
    0x72, 0x28, 0x00, 0x32, 0x61, 0x7B, 0x22, 0x61,   // r(.2a{"a
    0x76, 0x61, 0x69, 0x6C, 0x61, 0x62, 0x69, 0x6C,   // vailabil
    0x69, 0x74, 0x79, 0x22, 0x3A, 0x7B, 0x22, 0x30,   // ity":{"0
    0x32, 0x38, 0x33, 0x34, 0x36, 0x34, 0x38, 0x22,   // 2834648"
    0x3A, 0x22, 0x41, 0x50, 0x50, 0x5F, 0x41, 0x56,   // :"APP_AV
    0x41, 0x49, 0x4C, 0x41, 0x42, 0x4C, 0x45, 0x22,   // AILABLE"
    0x7D, 0x2C, 0x22, 0x72, 0x65, 0x71, 0x75, 0x65,   // },"reque
    0x73, 0x74, 0x49, 0x64, 0x22, 0x3A, 0x31, 0x2C,   // stId":1,
    0x22, 0x72, 0x65, 0x73, 0x70, 0x6F, 0x6E, 0x73,   // "respons
    0x65, 0x54, 0x79, 0x70, 0x65, 0x22, 0x3A, 0x22,   // eType":"
    0x47, 0x45, 0x54, 0x5F, 0x41, 0x50, 0x50, 0x5F,   // GET_APP_
    0x41, 0x56, 0x41, 0x49, 0x4C, 0x41, 0x42, 0x49,   // AVAILABI
    0x4C, 0x49, 0x54, 0x59, 0x22, 0x7D                // LITY"}
};

static uint8_t _appUnavailResp[] = {
   0x00, 0x00, 0x00, 0xA4, 0x08, 0x00, 0x12, 0x0A,   // ........
   0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x72,   // receiver
   0x2D, 0x30, 0x1A, 0x08, 0x73, 0x65, 0x6E, 0x64,   // -0..send
   0x65, 0x72, 0x2D, 0x30, 0x22, 0x23, 0x75, 0x72,   // er-0"#ur
   0x6E, 0x3A, 0x78, 0x2D, 0x63, 0x61, 0x73, 0x74,   // n:x-cast
   0x3A, 0x63, 0x6F, 0x6D, 0x2E, 0x67, 0x6F, 0x6F,   // :com.goo
   0x67, 0x6C, 0x65, 0x2E, 0x63, 0x61, 0x73, 0x74,   // gle.cast
   0x2E, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65,   // .receive
   0x72, 0x28, 0x00, 0x32, 0x63, 0x7B, 0x22, 0x61,   // r(.2c{"a
   0x76, 0x61, 0x69, 0x6C, 0x61, 0x62, 0x69, 0x6C,   // vailabil
   0x69, 0x74, 0x79, 0x22, 0x3A, 0x7B, 0x22, 0x30,   // ity":{"0
   0x32, 0x38, 0x33, 0x34, 0x36, 0x34, 0x38, 0x22,   // 2834648"
   0x3A, 0x22, 0x41, 0x50, 0x50, 0x5F, 0x55, 0x4E,   // :"APP_UN
   0x41, 0x56, 0x41, 0x49, 0x4C, 0x41, 0x42, 0x4C,   // AVAILABL
   0x45, 0x22, 0x7D, 0x2C, 0x22, 0x72, 0x65, 0x71,   // E"},"req
   0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x22, 0x3A,   // uestId":
   0x31, 0x2C, 0x22, 0x72, 0x65, 0x73, 0x70, 0x6F,   // 1,"respo
   0x6E, 0x73, 0x65, 0x54, 0x79, 0x70, 0x65, 0x22,   // nseType"
   0x3A, 0x22, 0x47, 0x45, 0x54, 0x5F, 0x41, 0x50,   // :"GET_AP
   0x50, 0x5F, 0x41, 0x56, 0x41, 0x49, 0x4C, 0x41,   // P_AVAILA
   0x42, 0x49, 0x4C, 0x49, 0x54, 0x59, 0x22, 0x7D    // BILITY"}
};

/* Various constants of the messaging/signalling of application status */
static char *_reqType = "GET_APP_AVAILABILITY";
static char *_appIsAvail = "APP_AVAILABLE";
static char *_appNotAvail = "APP_UNAVAILABLE";

/**
 * Callback to validate application availability response.  Note that this
 * is aligned to original request id, so it either matches or errors.
 */
static void *parseAvailabilityResponse(CastDeviceConnection *conn,
                                       void *content, size_t contentLen) {
    WXJSONValue *respType, *availData, *availStatus;
    WXJSONValue *val = (WXJSONValue *) content;

    /* Verify that the response aligns with the request */
    respType = WXHash_GetEntry(&(val->value.oval), "responseType",
                               WXHash_StrHashFn, WXHash_StrEqualsFn);
    if ((respType == NULL) || (respType->type != WXJSONVALUE_STRING) ||
            (strcmp(respType->value.sval, _reqType) != 0)) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Invalid response to matched availability request");
        return CPTL_RESP_ERROR;
    }

    /* Extract availability status for the target application */
    availData = WXHash_GetEntry(&(val->value.oval), "availability",
                                WXHash_StrHashFn, WXHash_StrEqualsFn);
    if ((availData == NULL) || (availData->type != WXJSONVALUE_OBJECT)) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Missing/invalid availability status object");
        return CPTL_RESP_ERROR;
    }

    availStatus = WXHash_GetEntry(&(availData->value.oval),
                                  CPTL_G(applicationId),
                                  WXHash_StrHashFn, WXHash_StrEqualsFn);
    if ((availStatus == NULL) || (availStatus->type != WXJSONVALUE_STRING)) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Missing/invalid application availability record");
        return CPTL_RESP_ERROR;
    }

    /* Available, unavailable or invalid... */
    if (strcmp(availStatus->value.sval, _appIsAvail) == 0) return _appIsAvail;
    if (strcmp(availStatus->value.sval, _appNotAvail) == 0) return _appNotAvail;
    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                     "Invalid application availability status: %s",
                     availStatus->value.sval);
    return CPTL_RESP_ERROR;
}

/**
 * Verify the availability of the configured application instance on the
 * associated device (connection).
 *
 * @param conn The connection instance returned from the device connect method.
 * @return Zero on success (communicated and configuration application is
 *         available), -1 on error or unavailable application (logged).
 */
int castAppCheckAvailability(CastDeviceConnection *conn) {
    char msgBuffer[1024];
    void *retval = NULL;
    int32_t requestId;

    /* Just in case a malformed resource gets destroyed */
    if (conn == NULL) return -1;

    /* Assemble the request content (dynamic) */
    requestId = ++(conn->requestId);
    if (_cptl_tstmode != 0) requestId = 1;
    (void) snprintf(msgBuffer, sizeof(msgBuffer),
                    "{"
                        "\"type\": \"%s\","
                        "\"appId\": [ \"%s\" ],"
                        "\"requestId\": %d"
                     "}",
                     _reqType, CPTL_G(applicationId), requestId);

    /* And send it */
    if (castSendMessage(conn, FALSE, FALSE, NS_RECEIVER, msgBuffer, -1) < 0) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Failed to issue application availability request");
        return -1;
    }

    /* Filter the response */
    _cptl_tstresp = (_cptl_tstmode == 1) ? _appAvailResp : _appUnavailResp;
    _cptl_tstresplen = (_cptl_tstmode == 1) ? sizeof(_appAvailResp) :
                                              sizeof(_appUnavailResp);
    retval = castReceiveMessage(conn, FALSE, FALSE, NS_RECEIVER,
                                parseAvailabilityResponse, TRUE, requestId);
    if ((retval != _appIsAvail) && (retval != _appNotAvail)) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Unable to obtain availability response");
        return -1;
    }
    if (retval == _appNotAvail) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Target application is not available on device");
        return -1;
    }

    return 0;
}
