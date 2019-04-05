/*
 * Functional implementation and supporting methods for cast messaging.
 *
 * Copyright (C) 2016-2019 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "php_castptl.h"
#include <openssl/err.h>
#include "buffer.h"
#include "json.h"

/*
 * For reference, the protofbuf definition for the cast message protocol.
 *
 * message CastMessage {
 *     enum ProtocolVersion {
 *         CASTV2_1_0 = 0;
 *     }
 *     required ProtocolVersion protocol_version = 1;
 *
 *     required string source_id = 2;
 *     required string destination_id = 3;
 *
 *     required string namespace = 4;
 *
 *     enum PayloadType {
 *         STRING = 0;
 *         BINARY = 1;
 *     }
 *     required PayloadType payload_type = 5;
 *
 *     optional string payload_utf8 = 6;
 *     optional bytes payload_binary = 7;
 * }
 *
 * enum SignatureAlgorithm {
 *     UNSPECIFIED = 0;
 *     RSASSA_PKCS1v15 = 1;
 *     RSASSA_PSS = 2;
 * }
 *
 * enum HashAlgorithm {
 *     SHA1 = 0;
 *     SHA256 = 1;
 * }
 *
 * message AuthChallenge {
 *     optional SignatureAlgorithm signature_algorithm = 1
 *         [default = RSASSA_PKCS1v15];
 *     optional bytes sender_nonce = 2;
 *     optional HashAlgorithm hash_algorithm = 3
 *         [default = SHA1];
 * }
 *
 * message AuthResponse {
 *     required bytes signature = 1;
 *     required bytes client_auth_certificate = 2;
 * }
 *
 * message AuthError {
 *     enum ErrorType {
 *         INTERNAL_ERROR = 0;
 *         NO_TLS = 1;
 *     }
 *     required ErrorType error_type = 1;
 * }
 *
 * message DeviceAuthMessage {
 *     optional AuthChallenge challenge = 1;
 *
 *     optional AuthResponse response = 2;
 *     optional AuthError error = 3;
 * }
 *
 */

/* The following namespace array must align to the CastNamespace enumeration */
static char* namespaces[] = {
    "urn:x-cast:com.google.cast.tp.connection",
    "urn:x-cast:com.google.cast.tp.deviceauth",
    "urn:x-cast:com.google.cast.tp.heartbeat",
    "urn:x-cast:com.google.cast.receiver"
};

#define NS_COUNT 4

/* Handy utility to generate the test datasets below... */
static void dump(char *dir, WXBuffer *buffer) {
    char chrs[9];
    int ch, idx;
 
    chrs[8] = '\0';
    php_printf("%s: [%d bytes]\n", dir, (int) buffer->length);
    for (idx = 0; idx < buffer->length; idx++) {
        if (idx != 0) {
            php_printf((((idx % 8) == 0) ? ",   %s\n" : ", "), chrs);
        }
        ch = *(buffer->buffer + idx);
        php_printf("0x%02X", ch);
        chrs[idx % 8] = (isprint(ch)) ? ((char) ch) : '.';
    }
    while ((idx % 8) != 0) {
        php_printf("      ");
        chrs[idx % 8] = ' ';
        idx++;
    }
    php_printf("    %s\n", chrs);
}

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
int castSendMessage(CastDeviceConnection *conn, int fromSenderSession,
                    int toPortalReceiver, CastNamespace namespace,
                    void *data, ssize_t dataLen) {
    char *nsStr = namespaces[namespace], *senderId, *receiverId;
    uint8_t msgBufferData[2048];
    unsigned long sslErrNo;
    WXBuffer msgBuffer;
    char errBuff[512];
    size_t len;

    /* Translate messsage endpoints */
    senderId = (fromSenderSession) ? "castptl-nnn" : "sender-0";
    receiverId = (toPortalReceiver) ? "castptl-000" : "receiver-0";

    /* Encoding is pretty straightforward with the buffer pack capability */
    WXBuffer_InitLocal(&msgBuffer, msgBufferData, sizeof(msgBufferData));
    if (WXBuffer_Pack(&msgBuffer, "yy yya* yya* yya*",
                      (1 << 3) | 0, 0 /* CASTV2_1_0 */,
                      (2 << 3) | 2, strlen(senderId), senderId,
                      (3 << 3) | 2, strlen(receiverId), receiverId,
                      (4 << 3) | 2, strlen(nsStr), nsStr) == NULL) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Message header packaging failure");
        return -1;
    }
    if (dataLen < 0) {
        if (WXBuffer_Pack(&msgBuffer, "yy yya*",
                          (5 << 3) | 0, 0 /* STRING */,
                          (6 << 3) | 2, strlen((char *) data),
                                        (char *) data) == NULL) {
            php_error_docref(NULL TSRMLS_CC, E_WARNING,
                             "Message payload (string) packaging failure");
            return -1;
       }
    } else {
        if (WXBuffer_Pack(&msgBuffer, "yy yyb%",
                          (5 << 3) | 0, 1 /* BINARY */,
                          (7 << 3) | 2, dataLen, (int) dataLen, data) == NULL) {
            php_error_docref(NULL TSRMLS_CC, E_WARNING,
                             "Message payload (binary) packaging failure");
            return -1;
       }
    }

    /* Message is prefixed with length in big-endian order */
    if (WXBuffer_EnsureCapacity(&msgBuffer, 4, TRUE) == NULL) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Message header prefix allocation failure");
        return -1;
    }
    len = msgBuffer.length;
    (void) memmove(msgBuffer.buffer + 4, msgBuffer.buffer, len);
    msgBuffer.length = 0;
    (void) WXBuffer_Pack(&msgBuffer, "N", len);
    msgBuffer.length += len;

    /* Bypass the actual write for test conditions */
    if ((_cptl_tstmode != 0) && (conn->ssl == NULL)) return 0;

    /* Issue the message */
    if (SSL_write(conn->ssl, msgBuffer.buffer, msgBuffer.length) < 0) {
        sslErrNo = ERR_get_error();
        ERR_error_string_n(sslErrNo, errBuff, sizeof(errBuff));
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Failed to write outbound message [%s]", errBuff);
        return -1;
    }

    return 0;
}

/* Might want to look at putting this into the buffer.c code someday */
static void consumeBuffer(WXBuffer *buffer, uint32_t len) {
    buffer->length -= len;
    (void) memmove(buffer->buffer, buffer->buffer + len, buffer->length);
    buffer->offset = 0;
}

/**
 * Looping processor for handling inbound message content from the main
 * message receive method.  Refer to that method (below) for more details on
 * the arguments.  Note that this method will return CPTL_RESP_ERROR for
 * any error occurrences (including callback errors).
 */
static void *parseInboundMessages(CastDeviceConnection *conn,
                                  int forSenderSession, int fromPortalReceiver,
                                  CastNamespace targNamespace,
                                  ProcessResponseCB responseCallback,
                                  int expJsonResponse) {
    uint32_t msgLen = 0, msgLimit, fragIdx, fragType, fragLen, fragVarInt;
    int idx, isSenderSession, isPortalReceiver, matched;
    int32_t msgProtoVersion, contentType, contentLen;
    WXBuffer *rdBuffer = &(conn->readBuffer);
    CastNamespace namespace;
    WXJSONValue *jsonVal;
    void *retval = NULL;
    uint8_t *content;

    /* Note that the cast device can send multiple messages in a single bound */
    while ((rdBuffer->length >= 4) && (retval == NULL)) {
        /* Encoded as defined 4-byte length parcel */
        rdBuffer->offset = 0;
        (void) WXBuffer_Unpack(rdBuffer, "N", &msgLen);
        if (rdBuffer->length < msgLen + 4) break;
        msgLimit = msgLen + 4;

        /* Prepare for general content extraction */
        msgProtoVersion = -1;
        namespace = NS_UNKNOWN;
        contentType = -1;
        isSenderSession = isPortalReceiver = -1;

        /* Read the fragments to extract the message elements */
        while (rdBuffer->offset < msgLimit) {
            fragType = (uint32_t) -1;
            (void) WXBuffer_Unpack(rdBuffer, "y", &fragType);
            if ((fragType == (uint32_t) -1) ||
                        (rdBuffer->offset >= msgLimit)) goto msg_error;
            fragIdx = fragType >> 3;
            fragType = fragType & 0x07;
            switch (fragType) {
                case 0: /* Varint, just read it */
                    fragLen = 0;
                    fragVarInt = (uint32_t) -1;
                    (void) WXBuffer_Unpack(rdBuffer, "y", &fragVarInt);
                    if ((fragVarInt == (uint32_t) -1) ||
                                (rdBuffer->offset >= msgLimit)) goto msg_error;
                    break;

                case 1: /* Fixed 64 */
                    fragLen = 8;
                    break;

                case 2: /* Length delimited */
                    fragLen = (uint32_t) -1;
                    (void) WXBuffer_Unpack(rdBuffer, "y", &fragLen);
                    if ((fragLen == (uint32_t) -1) ||
                                (rdBuffer->offset >= msgLimit)) goto msg_error;
                    break;

                case 3:
                case 4:
                    /* Ugh, groups are deprecated and ignored... */
                    goto msg_error;

                case 5: /* Fixed 32 */
                    fragLen = 4;
                    break;
            }

            /* Good thing this is a compact protocol... */
            switch (fragIdx) {
                case 1: /* Protocol Version */
                    if (fragType != 0) goto msg_error;
                    msgProtoVersion = fragVarInt;
                    break;

                case 2: /* Sender ID */
                    if ((fragLen == 10) &&
                            (strncmp(rdBuffer->buffer + rdBuffer->offset,
                                     "receiver-0", 10) == 0)) {
                        isPortalReceiver = 0;
                    } else if (fragLen = 999) /* TODO */ {
                        isPortalReceiver = 1;
                    } else {
                        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                   "Unrecognized sender id '%.*s'", fragLen,
                                   rdBuffer->buffer + rdBuffer->offset);
                    }
                    break;
                case 3: /* Receiver ID */
                    if ((fragLen == 8) &&
                            (strncmp(rdBuffer->buffer + rdBuffer->offset,
                                     "sender-0", 8) == 0)) {
                        isSenderSession = 0;
                    } else if (fragLen = 999) /* TODO */ {
                        isSenderSession = 1;
                    } else {
                        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                   "Unrecognized receiver id '%.*s'", fragLen,
                                   rdBuffer->buffer + rdBuffer->offset);
                    }
                    break;
                case 4: /* Namespace */
                    for (idx = 0; idx < NS_COUNT; idx++) {
                        if ((fragLen == strlen(namespaces[idx])) &&
                                (memcmp(rdBuffer->buffer + rdBuffer->offset,
                                         namespaces[idx], fragLen) == 0)) {
                            namespace = (CastNamespace) idx;
                            break;
                        }
                    }
                    break;

                case 5: /* Content type */
                    if (fragType != 0) goto msg_error;
                    if ((fragVarInt != 0) && (fragVarInt != 1)) goto msg_error;
                    contentType = fragVarInt;
                    break;

                case 6: /* Text Content */
                case 7: /* Binary Content */
                    /* Don't really need to differentiate here... */
                    /* Caller will need to allocate if standalone copy needed */
                    content = rdBuffer->buffer + rdBuffer->offset;
                    contentLen = fragLen;
                    break;

                default:
                    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                     "Invalid protocol fragment index %d",
                                     fragIdx);
                    goto msg_error;
            }
            
            /* Varint already read, everyone else needs a skip */
            rdBuffer->offset += fragLen;
        }

        /* Needs to be an exact fit */
        if (rdBuffer->offset != msgLimit) goto msg_error;

        /* And pretty much everything is required */
        if ((msgProtoVersion != 0) || (namespace == NS_UNKNOWN) ||
                (isSenderSession < 0) || (isPortalReceiver < 0) ||
                (contentType == -1) || (content == NULL)) {
            php_error_docref(NULL TSRMLS_CC, E_WARNING,
                             "Missing /invalid elements in the msg response");
            goto msg_error;
        }

        /* Filter according to indicated details for callback (with any's) */
        retval = NULL;
        matched = TRUE;
        if (forSenderSession >= 0) {
            if ((forSenderSession) && (isSenderSession)) matched = FALSE;
            if ((!forSenderSession) && (isSenderSession)) matched = FALSE;
        }
        if (fromPortalReceiver >= 0) {
            if ((fromPortalReceiver) && (!isPortalReceiver)) matched = FALSE;
            if ((!fromPortalReceiver) && (isPortalReceiver)) matched = FALSE;
        }
        if (targNamespace != NS_ANY) {
            if (namespace != targNamespace) matched = FALSE;
        }
        if (expJsonResponse >= 0) {
            /* Note that the contentType is backwards to the expect flag */
            if ((contentType == 0) && (!expJsonResponse)) matched = FALSE;
            if ((contentType != 0) && (expJsonResponse)) matched = FALSE;
        }

        if (matched) {
            if (contentType == 0) {
                /* Strings are always JSON */
                /* Not a pretty thing but we can muck the buffer backwards */
                (void) memmove(content - 1, content, contentLen); content--;
                content[contentLen] = '\0';
                jsonVal = WXJSON_Decode(content);
                if (jsonVal == NULL) {
                    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                     "Allocation failure in JSON parsing");
                    goto msg_error;
                } else if (jsonVal->type == WXJSONVALUE_ERROR) {
                    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                     "Invalid JSON response: %s",
                                     WXJSON_GetErrorStr(
                                               jsonVal->value.error.errorCode));
                    WXJSON_Destroy(jsonVal);
                    jsonVal = NULL;
                    /* Not fatal from a message stream perspective */
                } else {
                    retval = (*responseCallback)(conn, jsonVal, -1);
                    if (retval != (void *) jsonVal) {
                        /* Discard source JSON unless it's the return value */
                        WXJSON_Destroy(jsonVal);
                        jsonVal = NULL;
                    }
                }
            } else {
                retval = (*responseCallback)(conn, content, contentLen);
            }
        } else {
            /* TODO - do we debug the general status messages? */
        }

        /* Consume message content */
        consumeBuffer(rdBuffer, msgLen + 4);
    }

    return retval;

    /* I hate goto's but this is the one case I agree with them */
msg_error:
    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                     "Invalid/unparsable content in response message buffer");
    if (msgLen != 0) consumeBuffer(rdBuffer, msgLen + 4);
    return CPTL_RESP_ERROR;
}

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
 * @return Non-null if a valid response was determined by the response callback
 *         function (value returned from callback is passed through) or NULL
 *         for any processing error (logged internally).  CPTL_RESP_ERROR is
 *         not returned by this method.
 */
void *castReceiveMessage(CastDeviceConnection *conn, int forSenderSession,
                         int fromPortalReceiver, CastNamespace namespace,
                         ProcessResponseCB responseCallback,
                         int expJsonResponse) { 
    int32_t reqTimeout = CPTL_G(messageTimeout);
    uint8_t rdBuffer[1024];
    unsigned long sslErrNo;
    void *retval = NULL;
    char errBuff[512];
    int rc = 0, wrc;

    /* Munch until we munch no more... */
    while ((rc >= 0) && (reqTimeout > 0)) {
        if ((_cptl_tstmode != 0) && (conn->ssl == NULL)) {
            rc = _cptl_tstresplen;
            (void) memcpy(rdBuffer, _cptl_tstresp, rc);
        } else {
            rc = SSL_read(conn->ssl, rdBuffer, sizeof(rdBuffer));
        }
        if (rc <= 0) {
            sslErrNo = SSL_get_error(conn->ssl, rc);
            switch (sslErrNo) {
                case SSL_ERROR_WANT_READ:
                    /* TODO TIMEOUT HERE */
                    wrc = WXSocket_Wait(conn->scktHandle,
                                        WXNRC_READ_REQUIRED, &reqTimeout);
                    if (wrc == WXNRC_READ_REQUIRED) {
                        /* Ready to read */
                        rc = 0;
                    } else if (wrc == WXNRC_TIMEOUT) {
                        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                         "Timeout on wait for socket response");
                        rc = -1;
                    } else {
                        /* Any other response is an explicit error */
                        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                         "Error in socket READ_WAIT %s",
                                         WXSocket_GetErrorStr(wrc));
                        rc = -1;
                    }
                    break;

                 default:
                    /* Everything else is an SSL protocol error */
                    ERR_error_string_n(sslErrNo, errBuff, sizeof(errBuff));
                    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                     "Failed to read inbound content [%s]",
                                     errBuff);
                    rc = -1;
                    break;
            }
            if (rc < 0) {
                /* On general error, flush existing buffer */
                WXBuffer_Empty(&(conn->readBuffer));
            }
        } else {
            /* Append content to rolling buffer */
            if (WXBuffer_Append(&(conn->readBuffer), rdBuffer, rc,
                                FALSE) == NULL) {
                php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                 "Error assembling read response");
                WXBuffer_Empty(&(conn->readBuffer));
                rc = WXNRC_MEM_ERROR;
                break;
            }

            /* And attempt to parse inbound message elements */
            // dump("READ", &(conn->readBuffer));
            retval = parseInboundMessages(conn, forSenderSession,
                                          fromPortalReceiver, namespace,
                                          responseCallback, expJsonResponse);
            if (retval != NULL) {
                /* There was some matching response, good or bad */
                return (retval == CPTL_RESP_ERROR) ? NULL: retval;
            }
        }
    }

    return NULL;
}
