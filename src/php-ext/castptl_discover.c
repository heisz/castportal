/*
 * Functional implementation for processing MDNS GoogleCast discovery.
 *
 * Copyright (C) 2016-2019 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "php_castptl.h"
#include "socket.h"
#include "buffer.h"

#ifdef PHP_WIN32
#include <mstcpip.h>
#else
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

/* Utility methods to enable multicast options for the discovery sockets */
static int multicastIPv4(WXSocket sckt) {
    unsigned char loop = 1, ttl = 1;
    struct sockaddr_in addr;
    struct ip_mreq mreq;

    /* Loopback multicase, but only on the local network */
    if (setsockopt(sckt, IPPROTO_IP, IP_MULTICAST_LOOP,
                                     &loop, sizeof(loop)) < 0) return -1;
    if (setsockopt(sckt, IPPROTO_IP, IP_MULTICAST_TTL,
                                     &ttl, sizeof(ttl)) < 0) return -1;

    /* Express interest in responses to the target address */
    (void) memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = htonl(0xE00000FB /* 224.0.0.251 */);
    mreq.imr_interface.s_addr = INADDR_ANY;
    if (setsockopt(sckt, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                                     &mreq, sizeof(mreq)) < 0) return -1;
    return 0;
}
static int multicastIPv6(WXSocket sckt) {
    unsigned int loop = 1, hops = 1;
    struct sockaddr_in6 addr;
    struct ipv6_mreq mreq;

    /* Same as IPv4, just stated differently */
    if (setsockopt(sckt, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                                       &loop, sizeof(loop)) < 0) return -1;
    if (setsockopt(sckt, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                                       &hops, sizeof(hops)) < 0) return -1;

    /* Ditto, aside from the different IPv6 address */
    (void) memset(&mreq, 0, sizeof(mreq));
    mreq.ipv6mr_multiaddr.s6_addr[0] = 0xFF;
    mreq.ipv6mr_multiaddr.s6_addr[1] = 0x02;
    mreq.ipv6mr_multiaddr.s6_addr[15] = 0xFB;
    if (setsockopt(sckt, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                                       &mreq, sizeof(mreq)) < 0) return -1;
    return 0;
}

/* Use static definitions for the cast name components */
static char *_googlecast = "_googlecast";
static char *_tcp = "_tcp";
static char *local = "local";

/* Maximum packet response size for discovery, must be maximum due to UDP */
/* Refer to RFC6762 for details on UDP Multicast DNS message limit */
#define MDNS_MSG_LIMIT 9000

/* Common methods for managing DNS names, including funky compression... */
typedef struct _qNameSegment {
    char fragment[257];
    struct _qNameSegment *next;
} QNameSegment;

static void _freeQName(QNameSegment *segment) {
    QNameSegment *next;
    while (segment != NULL) {
        next = segment->next;
        WXFree(segment);
        segment = next;
    }
}
#define freeQName(seg) _freeQName(seg); seg = NULL;

static QNameSegment *parseQName(WXBuffer *msgBuffer, ssize_t maxLen) {
    QNameSegment *retVal = NULL, *last = NULL, *seg;
    size_t offset = msgBuffer->offset, limit;
    unsigned int slen;
    int redirect = 0;
    uint8_t *ptr;

    ptr = msgBuffer->buffer + offset;
    limit = (maxLen < 0) ? msgBuffer->length : offset + maxLen;
    while (offset < limit) {
        slen = *(ptr++); if (!redirect) offset++;

        /* Handle compression redirection of name remainder (non-rentrant) */
        if ((slen & 0xC0) == 0xC0) {
            slen = ((slen & 0x3F) << 8) | *ptr; if (!redirect) offset++;
            ptr = msgBuffer->buffer + slen;
            limit = msgBuffer->length;
            slen = *(ptr++);
            redirect = 1;
        }

        /* Null terminates the name fragment sequence */
        if (slen == 0) break;

        /* Otherwise here's another segment */
        seg = (QNameSegment *) WXMalloc(sizeof(QNameSegment));
        if (seg == NULL) {
            /* Shouldn't happen but clean up anyways */
            php_error_docref(NULL TSRMLS_CC, E_WARNING,
                             "Allocation error in name retrieval");
            _freeQName(retVal);
            return NULL;
        }
        if (retVal == NULL) retVal = seg;
        if (last != NULL) last->next = seg;
        last = seg; seg->next = NULL;

        /* And it's all about the name fragment itself */
        (void) memcpy(seg->fragment, ptr, slen);
        seg->fragment[slen] = '\0';
        ptr += slen; if (!redirect) offset += slen;
    }
    if (maxLen < 0) msgBuffer->offset = offset;

    /* Error if overflowed or unterminated */
    if ((offset > limit) || (slen != 0)) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Invalid/unterminated name segments/set");
        _freeQName(retVal);
        return NULL;
    }

    return retVal;
}

static int skipQName(WXBuffer *msgBuffer) {
    size_t offset = msgBuffer->offset;
    unsigned int slen;
    uint8_t *ptr;

    ptr = msgBuffer->buffer + offset;
    while (offset < msgBuffer->length) {
        slen = *(ptr++); offset++;
        if ((slen & 0xC0) == 0xC0) {
            /* Redirect ends this segment, just skip offset and terminate */
            offset++;
            slen = 0;
            break;
        }

        /* Null terminates the name fragment sequence */
        if (slen == 0) break;

        /* Otherwise just skip this fragment content */
        ptr += slen; offset += slen;
    }
    msgBuffer->offset = offset;

    /* Error if overflowed or unterminated */
    if ((offset > msgBuffer->length) || (slen != 0)) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING,
                         "Invalid/unterminated name segments/set");
        return -1;
    }

    return 0;
}

/* Test data instances captured via wireshark */
static uint8_t tstRespOne[] = {
    0xFE, 0xED, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x03, 0x0B, 0x5F, 0x67, 0x6F,
    0x6F, 0x67, 0x6C, 0x65, 0x63, 0x61, 0x73, 0x74,
    0x04, 0x5F, 0x74, 0x63, 0x70, 0x05, 0x6C, 0x6F,
    0x63, 0x61, 0x6C, 0x00, 0x00, 0x0C, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x78, 0x00, 0x2E, 0x2B, 0x43,
    0x68, 0x72, 0x6F, 0x6D, 0x65, 0x63, 0x61, 0x73,
    0x74, 0x2D, 0x32, 0x62, 0x36, 0x33, 0x39, 0x37,
    0x30, 0x68, 0x62, 0x63, 0x32, 0x32, 0x68, 0x32,
    0x36, 0x62, 0x36, 0x62, 0x32, 0x61, 0x30, 0x34,
    0x39, 0x32, 0x38, 0x32, 0x35, 0x64, 0x62, 0x38,
    0x64, 0x32, 0xC0, 0x0C, 0xC0, 0x2E, 0x00, 0x10,
    0x80, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0xB3,
    0x23, 0x69, 0x64, 0x3D, 0x36, 0x33, 0x39, 0x37,
    0x30, 0x68, 0x62, 0x63, 0x32, 0x32, 0x68, 0x32,
    0x36, 0x62, 0x36, 0x62, 0x32, 0x61, 0x30, 0x34,
    0x39, 0x32, 0x38, 0x32, 0x35, 0x64, 0x62, 0x38,
    0x64, 0x32, 0x66, 0x34, 0x23, 0x63, 0x64, 0x3d,
    0x43, 0x42, 0x33, 0x30, 0x31, 0x31, 0x41, 0x35,
    0x34, 0x46, 0x46, 0x46, 0x46, 0x34, 0x46, 0x36,
    0x41, 0x45, 0x41, 0x30, 0x44, 0x37, 0x43, 0x39,
    0x43, 0x36, 0x42, 0x46, 0x44, 0x41, 0x37, 0x44,
    0x13, 0x72, 0x6D, 0x3D, 0x46, 0x38, 0x43, 0x41,
    0x46, 0x42, 0x39, 0x37, 0x41, 0x46, 0x41, 0x33,
    0x36, 0x31, 0x30, 0x46, 0x05, 0x76, 0x65, 0x3D,
    0x30, 0x35, 0x0D, 0x6D, 0x64, 0x3D, 0x43, 0x68,
    0x72, 0x6F, 0x6D, 0x65, 0x63, 0x61, 0x73, 0x74,
    0x12, 0x69, 0x63, 0x3D, 0x2F, 0x73, 0x65, 0x74,
    0x75, 0x70, 0x2F, 0x69, 0x63, 0x6F, 0x6E, 0x2E,
    0x70, 0x6E, 0x67, 0x09, 0x66, 0x6E, 0x3D, 0x44,
    0x65, 0x6E, 0x20, 0x54, 0x56, 0x07, 0x63, 0x61,
    0x3D, 0x34, 0x31, 0x30, 0x31, 0x04, 0x73, 0x74,
    0x3D, 0x30, 0x0F, 0x62, 0x73, 0x3D, 0x46, 0x41,
    0x38, 0x46, 0x43, 0x41, 0x39, 0x32, 0x31, 0x30,
    0x41, 0x32, 0x04, 0x6E, 0x66, 0x3D, 0x31, 0x03,
    0x72, 0x73, 0x3D, 0xC0, 0x2E, 0x00, 0x21, 0x80,
    0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x2D, 0x00,
    0x00, 0x00, 0x00, 0x1F, 0x49, 0x24, 0x30, 0x35,
    0x34, 0x32, 0x37, 0x39, 0x30, 0x66, 0x2D, 0x61,
    0x66, 0x30, 0x36, 0x2D, 0x66, 0x38, 0x36, 0x61,
    0x2D, 0x31, 0x66, 0x31, 0x62, 0x2D, 0x36, 0x34,
    0x38, 0x39, 0x38, 0x30, 0x39, 0x30, 0x66, 0x39,
    0x66, 0x34, 0xC0, 0x1D, 0xC1, 0x2D, 0x00, 0x01,
    0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04,
    0x0A, 0x0C, 0x01, 0x8D
};

static uint8_t tstRespTwo[] = {
    0xFE, 0xED, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x04, 0x0B, 0x5F, 0x67, 0x6F,
    0x6F, 0x67, 0x6C, 0x65, 0x63, 0x61, 0x73, 0x74,
    0x04, 0x5F, 0x74, 0x63, 0x70, 0x05, 0x6C, 0x6F,
    0x63, 0x61, 0x6C, 0x00, 0x00, 0x0C, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x78, 0x00, 0x2E, 0x2B, 0x43,
    0x68, 0x72, 0x6F, 0x6D, 0x65, 0x63, 0x61, 0x73,
    0x74, 0x2D, 0x36, 0x62, 0x30, 0x68, 0x33, 0x62,
    0x32, 0x36, 0x30, 0x32, 0x33, 0x64, 0x32, 0x33,
    0x32, 0x65, 0x30, 0x37, 0x32, 0x61, 0x32, 0x62,
    0x65, 0x32, 0x38, 0x61, 0x32, 0x34, 0x62, 0x37,
    0x62, 0x37, 0xC0, 0x0C, 0xC0, 0x2E, 0x00, 0x10,
    0x80, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0xC3,
    0x23, 0x69, 0x64, 0x3D, 0x36, 0x62, 0x30, 0x68,
    0x33, 0x62, 0x32, 0x36, 0x30, 0x32, 0x33, 0x64,
    0x32, 0x33, 0x32, 0x65, 0x30, 0x37, 0x32, 0x61,
    0x32, 0x62, 0x65, 0x32, 0x38, 0x61, 0x32, 0x34,
    0x62, 0x37, 0x62, 0x37, 0x23, 0x63, 0x64, 0x3D,
    0x43, 0x34, 0x45, 0x32, 0x41, 0x41, 0x37, 0x42,
    0x41, 0x43, 0x33, 0x44, 0x41, 0x30, 0x41, 0x30,
    0x39, 0x37, 0x38, 0x37, 0x44, 0x34, 0x45, 0x44,
    0x36, 0x32, 0x30, 0x35, 0x35, 0x44, 0x44, 0x37,
    0x13, 0x72, 0x6D, 0x3D, 0x37, 0x32, 0x32, 0x45,
    0x34, 0x31, 0x41, 0x36, 0x35, 0x30, 0x33, 0x36,
    0x34, 0x36, 0x43, 0x45, 0x05, 0x76, 0x65, 0x3D,
    0x30, 0x35, 0x13, 0x6D, 0x64, 0x3D, 0x43, 0x68,
    0x72, 0x6F, 0x6D, 0x65, 0x63, 0x61, 0x73, 0x74,
    0x20, 0x55, 0x6C, 0x74, 0x72, 0x61, 0x12, 0x69,
    0x63, 0x3D, 0x2F, 0x73, 0x65, 0x74, 0x75, 0x70,
    0x2F, 0x69, 0x63, 0x6F, 0x6E, 0x2E, 0x70, 0x6E,
    0x67, 0x13, 0x66, 0x6E, 0x3D, 0x54, 0x53, 0x54,
    0x20, 0x43, 0x68, 0x72, 0x6F, 0x6D, 0x65, 0x20,
    0x50, 0x61, 0x6E, 0x65, 0x6C, 0x07, 0x63, 0x61,
    0x3D, 0x34, 0x31, 0x30, 0x31, 0x04, 0x73, 0x74,
    0x3D, 0x30, 0x0F, 0x62, 0x73, 0x3D, 0x46, 0x41,
    0x38, 0x46, 0x43, 0x41, 0x37, 0x38, 0x34, 0x35,
    0x41, 0x32, 0x04, 0x6E, 0x66, 0x3D, 0x31, 0x03,
    0x72, 0x73, 0x3D, 0xC0, 0x2E, 0x00, 0x21, 0x80,
    0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x2D, 0x00,
    0x00, 0x00, 0x00, 0x1F, 0x49, 0x24, 0x38, 0x32,
    0x32, 0x66, 0x36, 0x61, 0x34, 0x30, 0x2D, 0x34,
    0x32, 0x39, 0x38, 0x2D, 0x32, 0x32, 0x37, 0x63,
    0x2D, 0x32, 0x39, 0x39, 0x63, 0x2D, 0x30, 0x64,
    0x37, 0x34, 0x39, 0x33, 0x38, 0x32, 0x66, 0x39,
    0x64, 0x39, 0xC0, 0x1D, 0xC1, 0x37, 0x00, 0x01,
    0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04,
    0x0A, 0x0C, 0x01, 0x74, 0xC1, 0x37, 0x00, 0x1C,
    0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x10,
    0x20, 0x16, 0x0C, 0XD8, 0x45, 0x67, 0x2C, 0xD0,
    0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00
};

/* Once again, hex array */
static char hexNibble[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

/* Conversion methods for IP addr to strings */
static void cvtIPv4(char *addrBuff, uint8_t *data) {
    (void) sprintf(addrBuff, "%d.%d.%d.%d",
                   *data, *(data + 1), *(data + 2), *(data + 3));
}
static void cvtIPv6(char *addrBuff, uint8_t *data) {
    uint16_t quad, *sptr = (uint16_t *) data;
    int addrIdx, hexIdx;

    for (addrIdx = 0; addrIdx < 8; addrIdx++) {
        quad = ntohs(*(sptr++));
        if (quad != 0) {
            for (hexIdx = 0; hexIdx < 4; hexIdx++) {
                *(addrBuff + 3 - hexIdx) =
                                hexNibble[quad & 0x0F];
                quad = quad >> 4;
            }
            addrBuff += 4;
        }
        if (addrIdx != 7) *(addrBuff++) = ':';
    }
    *addrBuff = '\0';
}

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
CastDeviceInfo *castDiscover(int ipMode, int waitTm) {
    uint8_t *ptr, msgBufferData[MDNS_MSG_LIMIT], respBuffer[MDNS_MSG_LIMIT];
    uint16_t rTxnId, rFlags, rQueries, rAnswers, rAuthority, rAdditional;
    CastDeviceInfo *device, wrk, *retVal = NULL, *last = NULL;
    uint16_t *sptr, rType, rClass, rLen;
    struct addrinfo *addrInfo = NULL;
    struct sockaddr_storage respAddr;
    char *targetAddr, txtBuff[256];
    QNameSegment *names = NULL;
    socklen_t respAddrLen;
    WXSocket scktHandle;
    int rc, modeIdx, idx;
    WXBuffer msgBuffer;
    unsigned int slen;
    ssize_t respLen;
    int32_t timeout;
    uint32_t rTTL;

    /* Use the global configuration fallback */
    if (waitTm <= 0) waitTm = CPTL_G(discoveryTimeout);

    /* Two passes, one per network type */
    for (modeIdx = 1; modeIdx <= 2; modeIdx++) {
        /* Scan only mode filter indicates such */
        if ((modeIdx & ipMode) == 0) continue;

        /* Open socket, extract address information */
        targetAddr = (modeIdx == 1) ? "224.0.0.251" : "ff02::fb";
        if (WXSocket_OpenUDPClient(targetAddr, "mdns", &scktHandle,
                                   (void **) &addrInfo) != WXNRC_OK) {
            php_error_docref(NULL TSRMLS_CC, E_WARNING,
                             "Error opening discovery socket for %s: %s",
                             targetAddr, WXSocket_GetErrorStr(
                                                WXSocket_GetLastErrNo()));
            continue;
        }

        /* Force non-blocking to properly handle timeout */
        if (WXSocket_SetNonBlockingState(scktHandle, TRUE) != WXNRC_OK) {
            php_error_docref(NULL TSRMLS_CC, E_WARNING,
                             "Error marking socket for non-blocking: %s",
                             WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
            WXSocket_Close(scktHandle);
            freeaddrinfo(addrInfo);
            continue;
        }

        /* Join the multicast group for proper message handling */
        rc = (addrInfo->ai_family == AF_INET) ?
                       multicastIPv4(scktHandle) : multicastIPv6(scktHandle);
        if (rc < 0) {
            php_error_docref(NULL TSRMLS_CC, E_WARNING,
                             "Error marking multicast options: %s",
                             WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
            WXSocket_Close(scktHandle);
            freeaddrinfo(addrInfo);
            continue;
        }

        /* Send the discovery query (presuming non-buffer) */
        WXBuffer_InitLocal(&msgBuffer, msgBufferData, sizeof(msgBufferData));

        /*
         * DNS header (RFC1035):
         *     - network-order 16-bit transaction id (feed me!)
         *     - network-order 16-bit flagset
         *     - network-order 16-bit question count (just one here)
         *     - network-order 16-bit answer resource record count
         *     - network-order 16-bit authority resource record count
         *     - network-order 16-bit additional resource record count
         */
        WXBuffer_Pack(&msgBuffer, "nnnnnn",
                      0xFEED, 0x00, 0x01, 0x00, 0x00, 0x00);

        /*
         * Single query, chromecast service name '_googlecast._tcp.local',
         * query type PTR, QU/IN query class
         */
        WXBuffer_Pack(&msgBuffer, "Ca*Ca*cA*cnn",
                      strlen(_googlecast), _googlecast,
                      strlen(_tcp), _tcp, strlen(local), local, 0x00,
                      0x0C, 0x8001);

        /* There she blows! */
        if (WXSocket_SendTo(scktHandle, msgBuffer.buffer, msgBuffer.length, 0,
                            addrInfo->ai_addr, addrInfo->ai_addrlen) < 0) {
            php_error_docref(NULL TSRMLS_CC, E_WARNING,
                             "Error broadcasting mDNS query: %s",
                             WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
            WXSocket_Close(scktHandle);
            freeaddrinfo(addrInfo);
            continue;
        }

        /* Grab some answers */
        timeout = waitTm;
        while (timeout > 0) {
            /* Wait for something to read, until timeout has been reached */
            rc = WXSocket_Wait(scktHandle, WXNRC_READ_REQUIRED, &timeout);
            if (rc == WXNRC_TIMEOUT) {
                if (_cptl_tstmode == 0) break;
            } else if (rc < 0) {
                php_error_docref(NULL TSRMLS_CC, E_WARNING,
                              "Unexpected error on wait response: %s",
                              WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
                break;
            }

            /* Note: for UDP, reads the entire inbound packet */
            (void) memset(&respAddr, 0, sizeof(respAddr));
            respAddrLen = sizeof(respAddr);
            respLen = WXSocket_RecvFrom(scktHandle, respBuffer,
                                        sizeof(respBuffer), 0,
                                        &respAddr, &respAddrLen);
            if (_cptl_tstmode != 0) {
                if ((respLen == 0) && (timeout <= 0)) {
                    /* Timeout in test mode, simulate fixed responses */
                    if (modeIdx == 1) {
                        respLen = sizeof(tstRespOne);
                        (void) memcpy(respBuffer, tstRespOne, respLen);
                        respAddr.ss_family = AF_INET;
                        (void) inet_pton(AF_INET, "10.11.12.13",
                               &(((struct sockaddr_in *) &respAddr)->sin_addr));
                    } else {
                        respLen = sizeof(tstRespTwo);
                        (void) memcpy(respBuffer, tstRespTwo, respLen);
                        respAddr.ss_family = AF_INET6;
                        (void) inet_pton(AF_INET6, "2016:cd8:4567:2cd0::12",
                             &(((struct sockaddr_in6 *) &respAddr)->sin6_addr));
                    }
                } else {
                    /* Skip real instances in test mode... */
                    continue;
                }
            }
            if (respLen <= 0) {
                php_error_docref(NULL TSRMLS_CC, E_WARNING,
                              "Error on response read: %s",
                              WXSocket_GetErrorStr(WXSocket_GetLastErrNo()));
                break;
            }

            /* Prepare to add a device information record */
            (void) memset(&wrk, 0, sizeof(wrk));
            (void) strcpy(wrk.model, "Chromecast");
            wrk.port = 8009;

            /* Device located at response origin address */
            inet_ntop(respAddr.ss_family,
                      (respAddr.ss_family == AF_INET) ?
                          (void *) &(((struct sockaddr_in *)
                                                   &respAddr)->sin_addr) :
                          (void *) &(((struct sockaddr_in6 *)
                                                   &respAddr)->sin6_addr),
                      txtBuff, sizeof(txtBuff));
            (void) strcpy(wrk.ipAddr, txtBuff);

            /* Note: from this point it's just a bad message, so continue */

            /* Push to buffer for unpack and extract header (see above) */
            WXBuffer_Empty(&msgBuffer);
            (void) WXBuffer_Append(&msgBuffer, respBuffer, respLen, TRUE);
            if (WXBuffer_Unpack(&msgBuffer, "nnnnnn",
                                &rTxnId, &rFlags, &rQueries, &rAnswers,
                                &rAuthority, &rAdditional) == NULL) {
                php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                 "Error on mDNS response header unpack");
                continue;
            }

            /* Must be an appropriate response to the direct request */
            if ((rTxnId != 0xFEED) || (rFlags != 0x8400) ||
                    (rQueries != 0) || (rAnswers != 1)) {
                continue;
            }

            /* Validate the answer (source name, PTR response) */
            if (((names = parseQName(&msgBuffer, -1)) == NULL) ||
                (WXBuffer_Unpack(&msgBuffer, "nnNn",
                                 &rType, &rClass, &rTTL, &rLen) == NULL)) {
                php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                 "Error on answer record data unpack");
                freeQName(names);
                break;
            }
            if ((rType != 0x0c) || ((rClass & 0x7FFF) != 0x01)) {
                freeQName(names);
                continue;
            }
            if ((names == NULL) ||
                (strcmp(names->fragment, _googlecast) != 0) ||
                    (names->next == NULL) ||
                    (strcmp(names->next->fragment, _tcp) != 0) ||
                        (names->next->next == NULL) ||
                        (strcmp(names->next->next->fragment, local) != 0) ||
                            (names->next->next->next != NULL)) {
                freeQName(names);
                continue;
            }
            freeQName(names);

            /* The PTR response contains the fqname, grab base as dflt name */
            if ((names = parseQName(&msgBuffer, rLen)) != NULL) {
                (void) strncpy(wrk.name, names->fragment, 256);
                wrk.name[255] = '\0';
                freeQName(names);
            }
            msgBuffer.offset += rLen;

            /* Should be no authorities, but just in case... */
            for (idx = 0; idx < rAuthority; idx++) {
                if ((skipQName(&msgBuffer) < 0) ||
                    (WXBuffer_Unpack(&msgBuffer, "nnNn",
                                     &rType, &rClass, &rTTL, &rLen) == NULL)) {
                    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                     "Error on authority record data unpack");
                    break;
                }
                msgBuffer.offset += rLen;
            }
            if (idx < rAuthority) continue;

            /* Additional records is where the action is */
            for (idx = 0; idx < rAdditional; idx++) {
                if ((skipQName(&msgBuffer) < 0) ||
                    (WXBuffer_Unpack(&msgBuffer, "nnNn",
                                     &rType, &rClass, &rTTL, &rLen) == NULL)) {
                    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                     "Error on additional record data unpack");
                    break;
                }

                /* Content of interest is based on record type */
                if (rType == 1 /* A */) {
                    if (rLen == 4) {
                        cvtIPv4(txtBuff, msgBuffer.buffer + msgBuffer.offset);
                    }
                } else if (rType == 16 /* TXT */) {
                    ptr = msgBuffer.buffer + msgBuffer.offset;
                    while (rLen > 0) {
                        slen = *(ptr++);
                        if (slen >= rLen) break;
                        (void) strncpy(txtBuff, ptr, slen);
                        txtBuff[slen] = '\0';

                        /* Keyset lookup for relevant data values */
                        if (strncmp(txtBuff, "id=", 3) == 0) {
                            (void) strcpy(wrk.id, txtBuff + 3);
                        } else if (strncmp(txtBuff, "fn=", 3) == 0) {
                            (void) strcpy(wrk.name, txtBuff + 3);
                        } else if (strncmp(txtBuff, "md=", 3) == 0) {
                            (void) strcpy(wrk.model, txtBuff + 3);
                        }
                        ptr += (slen++);
                        rLen -= slen;
                        msgBuffer.offset += slen;
                    }
                } else if (rType == 28 /* AAA */) {
                    if (rLen == 16) {
                        cvtIPv6(txtBuff, msgBuffer.buffer + msgBuffer.offset);
                    }
                } else if (rType == 33 /* SRV */) {
                    if (rLen >= 6) {
                        sptr = (uint16_t *) (msgBuffer.buffer +
                                                         msgBuffer.offset + 4);
                        wrk.port = ntohs(*sptr);
                    }
                }

                msgBuffer.offset += rLen;
            }
            freeQName(names);
            if (idx < rAdditional) continue;

            /* If we got to here, it's official! */
            device = (CastDeviceInfo *) WXMalloc(sizeof(CastDeviceInfo));
            if (device == NULL) continue;
            (void) memcpy(device, &wrk, sizeof(wrk));
            if (retVal == NULL) retVal = device;
            if (last != NULL) last->next = device;
            last = device;
        }
    }

    return retVal;
}
