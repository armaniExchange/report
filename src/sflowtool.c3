/*
 * File name: sflowtool.c
 *
 * Copyright(C) 2007-2014, A10 Networks Inc. All rights reserved.
 * Software for all A10 products contain trade secrets and confidential
 * information of A10 Networks and its subsidiaries and may not be
 * disclosed, copied, reproduced or distributed to anyone outside of
 * A10 Networks without prior written consent of A10 Networks, Inc.
 */
/*
 * Filn name: sflowtool.c
 *
 * Copyright(C) 2007-2014, A10 Networks Inc. All rights reserved.
 * Software for all A10 products contain trade secrets and confidential
 * information of A10 Networks and its subsidiaries and may not be
 * disclosed, copied, reproduced or distributed to anyone outside of
 * A10 Networks without prior written consent of A10 Networks, Inc.
 */
/* Copyright (c) 2002-2011 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#if defined(__cplusplus)
extern "C" {
#endif

#ifdef WIN32
#include "config_windows.h"
#else
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <setjmp.h>

#ifdef WIN32
#else
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#endif
#include <signal.h>
#include "sflow.h" // sFlow v5
#include "sflowtool.h" // sFlow v2/4
#include "sflowtool_ddos_ext.h"

// If the platform is Linux, enable the source-spoofing feature too.
#ifdef linux
#define SPOOFSOURCE 1
#endif

#include <syslog.h>

/*
#ifdef DARWIN
#include <architecture/byte_order.h>
#define bswap_16(x) NXSwapShort(x)
#define bswap_32(x) NXSwapInt(x)
#else
#include <byteswap.h>
#endif
*/

/* just do it in a portable way... */
static uint32_t MyByteSwap32(uint32_t n)
{
    return (((n & 0x000000FF) << 24) +
            ((n & 0x0000FF00) << 8) +
            ((n & 0x00FF0000) >> 8) +
            ((n & 0xFF000000) >> 24));
}
static uint16_t MyByteSwap16(uint16_t n)
{
    return ((n >> 8) | (n << 8));
}

#ifndef PRIu64
# ifdef WIN32
#  define PRIu64 "I64u"
# else
#  define PRIu64 "llu"
# endif
#endif

#define YES 1
#define NO 0

#if !defined ( WIN32 )
#define min(a,b)                    \
   ({ __typeof__ (a) _a = (a);      \
       __typeof__ (b) _b = (b);     \
     _a < _b ? _a : _b; })
#endif

#if defined ( WIN32 )
#define __func__ __FUNCTION__
#endif

#define LEN_U64 sizeof(u64)
#define LEN_U32 sizeof(u32)
/* define my own IP header struct - to ease portability */
struct myiphdr {
    uint8_t version_and_headerLen;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

/* same for tcp */
struct mytcphdr {
    uint16_t th_sport;      /* source port */
    uint16_t th_dport;      /* destination port */
    uint32_t th_seq;        /* sequence number */
    uint32_t th_ack;        /* acknowledgement number */
    uint8_t th_off_and_unused;
    uint8_t th_flags;
    uint16_t th_win;        /* window */
    uint16_t th_sum;        /* checksum */
    uint16_t th_urp;        /* urgent pointer */
};

/* and UDP */
struct myudphdr {
    uint16_t uh_sport;           /* source port */
    uint16_t uh_dport;           /* destination port */
    uint16_t uh_ulen;            /* udp length */
    uint16_t uh_sum;             /* udp checksum */
};

/* and ICMP */
struct myicmphdr {
    uint8_t type;       /* message type */
    uint8_t code;       /* type sub-code */
    /* ignore the rest */
};

#ifdef SPOOFSOURCE
#define SPOOFSOURCE_SENDPACKET_SIZE 2000
struct mySendPacket {
    struct myiphdr ip;
    struct myudphdr udp;
    u_char data[SPOOFSOURCE_SENDPACKET_SIZE];
};
#endif

struct sflow_flex_kv {
    u32 key;
    u64 value;
}__attribute__((__packed__));

/* tcpdump file format */

struct pcap_file_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t thiszone;  /* gmt to local correction */
    uint32_t sigfigs;   /* accuracy of timestamps */
    uint32_t snaplen;   /* max length saved portion of each pkt */
    uint32_t linktype;  /* data link type (DLT_*) */
};

struct pcap_pkthdr {
    uint32_t ts_sec;    /* time stamp - used to be struct timeval, but time_t can be 64 bits now */
    uint32_t ts_usec;
    uint32_t caplen;    /* length of portion present */
    uint32_t len;   /* length this packet (off wire) */
    /* some systems expect to see more information here. For example,
     * on some versions of RedHat Linux, there are three extra fields:
     *   int index;
     *   unsigned short protocol;
     *   unsigned char pkt_type;
     * To pad the header with zeros, use the tcpdumpHdrPad option.
     */
};

typedef struct _SFForwardingTarget {
    struct _SFForwardingTarget *nxt;
    struct in_addr host;
    uint32_t port;
    struct sockaddr_in addr;
    int sock;
} SFForwardingTarget;

typedef enum { SFLFMT_FULL = 0, SFLFMT_PCAP, SFLFMT_LINE, SFLFMT_NETFLOW, SFLFMT_FWD, SFLFMT_CLF, SFLFMT_TSD } EnumSFLFormat;

typedef struct _SFConfig {
    /* sflow(R) options */
    uint16_t sFlowInputPort;
    /* netflow(TM) options */
    uint16_t netFlowOutputPort;
    struct in_addr netFlowOutputIP;
    int netFlowOutputSocket;
    uint16_t netFlowPeerAS;
    int disableNetFlowScale;
    /* tcpdump options */
    char *readPcapFileName;
    FILE *readPcapFile;
    struct pcap_file_header readPcapHdr;
    char *writePcapFile;
    EnumSFLFormat outputFormat;
    uint32_t tcpdumpHdrPad;
    u_char zeroPad[100];
    int pcapSwap;

#ifdef SPOOFSOURCE
    int spoofSource;
    uint16_t ipid;
    struct mySendPacket sendPkt;
    uint32_t packetLen;
#endif

    SFForwardingTarget *forwardingTargets;

    /* vlan filtering */
    int gotVlanFilter;
#define FILTER_MAX_VLAN 4096
    u_char vlanFilter[FILTER_MAX_VLAN + 1];

    /* content stripping */
    int removeContent;

    /* options to restrict IP socket / bind */
    int listen4;
    int listen6;
    int listenControlled;
} SFConfig;

/* make the options structure global to the program */
static SFConfig sfConfig;

/* define a separate global we can use to construct the common-log-file format */
typedef struct _SFCommonLogFormat {
#define SFLFMT_CLF_MAX_LINE 2000
    int valid;
    char client[64];
    char http_log[SFLFMT_CLF_MAX_LINE];
} SFCommonLogFormat;

#define UUID_SIZE 37
struct sfl_a10_custom_info {
        u8 uuid[UUID_SIZE];
        u32 schema_oid;
        u32 vnp_id;
}__attribute__((packed));


static SFCommonLogFormat sfCLF;
static const char *SFHTTP_method_names[] = { "-", "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT" };
static inline void sfl_log_ex_string_fmt(char *data, char *description);
typedef struct _SFSample {
    SFLAddress sourceIP;
    SFLAddress agent_addr;
    uint32_t agentSubId;

    /* the raw pdu */
    u_char *rawSample;
    uint32_t rawSampleLen;
    u_char *endp;
    time_t pcapTimestamp;

    /* decode cursor */
    uint32_t *datap;

    uint32_t datagramVersion;
    uint32_t sampleType;
    uint32_t ds_class;
    uint32_t ds_index;
    uint8_t  uuid[UUID_SIZE];
    uint32_t schema_oid;


    /* generic interface counter sample */
    SFLIf_counters ifCounters;

    /* sample stream info */
    uint32_t sysUpTime;
    uint32_t sequenceNo;
    uint32_t sampledPacketSize;
    uint32_t samplesGenerated;
    uint32_t meanSkipCount;
    uint32_t samplePool;
    uint32_t dropEvents;

    /* the sampled header */
    uint32_t packet_data_tag;
    uint32_t headerProtocol;
    u_char *header;
    int headerLen;
    uint32_t stripped;

    /* header decode */
    int gotIPV4;
    int gotIPV4Struct;
    int offsetToIPV4;
    int gotIPV6;
    int gotIPV6Struct;
    int offsetToIPV6;
    int offsetToPayload;
    SFLAddress ipsrc;
    SFLAddress ipdst;
    uint32_t dcd_ipProtocol;
    uint32_t dcd_ipTos;
    uint32_t dcd_ipTTL;
    uint32_t dcd_sport;
    uint32_t dcd_dport;
    uint32_t dcd_tcpFlags;
    uint32_t ip_fragmentOffset;
    uint32_t udp_pduLen;

    /* ports */
    uint32_t inputPortFormat;
    uint32_t outputPortFormat;
    uint32_t inputPort;
    uint32_t outputPort;

    /* ethernet */
    uint32_t eth_type;
    uint32_t eth_len;
    u_char eth_src[8];
    u_char eth_dst[8];

    /* vlan */
    uint32_t in_vlan;
    uint32_t in_priority;
    uint32_t internalPriority;
    uint32_t out_vlan;
    uint32_t out_priority;
    int vlanFilterReject;

    /* extended data fields */
    uint32_t num_extended;
    uint32_t extended_data_tag;
#define SASAMPLE_EXTENDED_DATA_SWITCH 1
#define SASAMPLE_EXTENDED_DATA_ROUTER 4
#define SASAMPLE_EXTENDED_DATA_GATEWAY 8
#define SASAMPLE_EXTENDED_DATA_USER 16
#define SASAMPLE_EXTENDED_DATA_URL 32
#define SASAMPLE_EXTENDED_DATA_MPLS 64
#define SASAMPLE_EXTENDED_DATA_NAT 128
#define SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL 256
#define SASAMPLE_EXTENDED_DATA_MPLS_VC 512
#define SASAMPLE_EXTENDED_DATA_MPLS_FTN 1024
#define SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC 2048
#define SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL 4096
#define SASAMPLE_EXTENDED_DATA_NAT_PORT 8192

    /* IP forwarding info */
    SFLAddress nextHop;
    uint32_t srcMask;
    uint32_t dstMask;

    /* BGP info */
    SFLAddress bgp_nextHop;
    uint32_t my_as;
    uint32_t src_as;
    uint32_t src_peer_as;
    uint32_t dst_as_path_len;
    uint32_t *dst_as_path;
    /* note: version 4 dst as path segments just get printed, not stored here, however
     * the dst_peer and dst_as are filled in, since those are used for netflow encoding
     */
    uint32_t dst_peer_as;
    uint32_t dst_as;

    uint32_t communities_len;
    uint32_t *communities;
    uint32_t localpref;

    /* user id */
#define SA_MAX_EXTENDED_USER_LEN 200
    uint32_t src_user_charset;
    uint32_t src_user_len;
    char src_user[SA_MAX_EXTENDED_USER_LEN + 1];
    uint32_t dst_user_charset;
    uint32_t dst_user_len;
    char dst_user[SA_MAX_EXTENDED_USER_LEN + 1];

    /* url */
#define SA_MAX_EXTENDED_URL_LEN 200
#define SA_MAX_EXTENDED_HOST_LEN 200
    uint32_t url_direction;
    uint32_t url_len;
    char url[SA_MAX_EXTENDED_URL_LEN + 1];
    uint32_t host_len;
    char host[SA_MAX_EXTENDED_HOST_LEN + 1];

    /* mpls */
    SFLAddress mpls_nextHop;

    /* nat */
    SFLAddress nat_src;
    SFLAddress nat_dst;

    /* counter blocks */
    uint32_t statsSamplingInterval;
    uint32_t counterBlockVersion;

    struct sflow_ddos_counters ddos;

    /* Current Sample/Counterblock length */
    uint32_t current_context_length;

    /* DDoS counter sample description string */
#define SFL_DDOS_DESCRIPTION_LEN    64
    char sfl_ddos_desc[SFL_DDOS_DESCRIPTION_LEN];

    /* exception handler context */
    jmp_buf env;

#define ERROUT stderr

#ifdef DEBUG
# define SFABORT(s, r) abort()
# undef ERROUT
# define ERROUT stdout
#else
# define SFABORT(s, r) longjmp((s)->env, (r))
#endif

#define SF_ABORT_EOS 1
#define SF_ABORT_DECODE_ERROR 2
#define SF_ABORT_LENGTH_ERROR 3

} SFSample;

/* Cisco netflow version 5 record format */

typedef struct _NFFlow5 {
    uint32_t srcIP;
    uint32_t dstIP;
    uint32_t nextHop;
    uint16_t if_in;
    uint16_t if_out;
    uint32_t frames;
    uint32_t bytes;
    uint32_t firstTime;
    uint32_t lastTime;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t pad1;
    uint8_t tcpFlags;
    uint8_t ipProto;
    uint8_t ipTos;
    uint16_t srcAS;
    uint16_t dstAS;
    uint8_t srcMask;  /* No. bits */
    uint8_t dstMask;  /* No. bits */
    uint16_t pad2;
} NFFlow5;

typedef struct _NFFlowHdr5 {
    uint16_t version;
    uint16_t count;
    uint32_t sysUpTime;
    uint32_t unixSeconds;
    uint32_t unixNanoSeconds;
    uint32_t flowSequence;
    uint8_t engineType;
    uint8_t engineId;
    uint16_t sampling_interval;
} NFFlowHdr5;

typedef struct _NFFlowPkt5 {
    NFFlowHdr5 hdr;
    NFFlow5 flow; /* normally an array, but here we always send just 1 at a time */
} NFFlowPkt5;

static void readFlowSample_header(SFSample *sample);
static void readFlowSample(SFSample *sample, int expanded);

static u64 packet_anomaly_passed = 0;
static u64 packet_anomaly_dropped = 0;

static u64 dst_rates_dropped = 0;

static u64 port_wildcards_dropped = 0;

static u64 port_cm_dropped = 0;

static u64 src_rates_dropped = 0;

static u64 http_dropped = 0;

static u64 http_excl_src_dropped = 0;

static u64 http_challenge_sent = 0;

static u64 dst_http_challenge_sent = 0;

static u64 dns_dropped = 0;

static u64 dns_excl_src_dropped = 0;

static u64 src_auth_dropped = 0;

static u64 ip_proto_dropped = 0;

static u64 icmp_dropped = 0;

char tsdb_buff[5000];
extern int opentsdb_simple_connect(char *data);

int g_opentsdb_socket_connected = 0;
int g_opentsdb_sock;

void
ignore_sigpipe(void)
{
    struct sigaction act;
    int r;
    memset(&act, 0, sizeof(act));
    act.sa_handler = SIG_IGN;
    act.sa_flags = SA_RESTART;
    r = sigaction(SIGPIPE, &act, NULL);
    if (r)
        fprintf(stderr, "Failed to ignore the SIGPIPE...\n");
       
}


/**********************************************************
                     dump_syslog
***********************************************************/
//#define  LOG_CRITICAL	1
//#define  LOG_ERROR	2
//#define	 LOG_INFO	3

char * alevel [] = { "", "CRITICAL", "ERROR", "INFO" };

void dump_syslog(int level, char *fmt, ...)
{
    char buf[256];
    va_list args;

    va_start(args, fmt);
    vsprintf (buf, fmt, args);

    openlog ("sflowtool", LOG_PID, LOG_USER);
    syslog (level, "%s", buf);
    closelog ();
}


void custom_exit(int code)
{
    dump_syslog(LOG_CRIT, "Unexpected program exit with code %d", code);
    exit(code);
}

/*_________________---------------------------__________________
  _________________        sf_log             __________________
  -----------------___________________________------------------
*/

void sf_log(char *fmt, ...)
{
    /* don't print anything if we are exporting tcpdump format or tabular format instead */
    if (sfConfig.outputFormat == SFLFMT_FULL) {
        va_list args;
        va_start(args, fmt);
        if (vprintf(fmt, args) < 0) {
            custom_exit(-40);
        }
    }
}

/*_________________---------------------------__________________
  _________________        printHex           __________________
  -----------------___________________________------------------
*/

static u_char bin2hex(int nib)
{
    return (nib < 10) ? ('0' + nib) : ('A' - 10 + nib);
}

int printHex(const u_char *a, int len, u_char *buf, int bufLen, int marker, int bytesPerOutputLine)
{
    int b = 0, i = 0;
    for (; i < len; i++) {
        u_char byte;
        if (b > (bufLen - 10)) {
            break;
        }
        if (marker > 0 && i == marker) {
            buf[b++] = '<';
            buf[b++] = '*';
            buf[b++] = '>';
            buf[b++] = '-';
        }
        byte = a[i];
        buf[b++] = bin2hex(byte >> 4);
        buf[b++] = bin2hex(byte & 0x0f);
        if (i > 0 && (i % bytesPerOutputLine) == 0) {
            buf[b++] = '\n';
        } else {
            // separate the bytes with a dash
            if (i < (len - 1)) {
                buf[b++] = '-';
            }
        }
    }
    buf[b] = '\0';
    return b;
}

/*_________________---------------------------__________________
  _________________       URLEncode           __________________
  -----------------___________________________------------------
*/

char *URLEncode(char *in, char *out, int outlen)
{
    register char c, *r = in, *w = out;
    int maxlen = (strlen(in) * 3) + 1;
    if (outlen < maxlen) {
        return "URLEncode: not enough space";
    }
    while (c = *r++) {
        if (isalnum(c)) {
            *w++ = c;
        } else if (isspace(c)) {
            *w++ = '+';
        } else {
            *w++ = '%';
            *w++ = bin2hex(c >> 4);
            *w++ = bin2hex(c & 0x0f);
        }
    }
    *w++ = '\0';
    return out;
}


/*_________________---------------------------__________________
  _________________      IP_to_a              __________________
  -----------------___________________________------------------
*/

char *IP_to_a(uint32_t ipaddr, char *buf)
{
    u_char *ip = (u_char *)&ipaddr;
    sprintf(buf, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buf;
}

static char *printAddress(SFLAddress *address, char *buf, int bufLen)
{
    if (address->type == SFLADDRESSTYPE_IP_V4) {
        IP_to_a(address->address.ip_v4.addr, buf);
    } else {
        u_char *b = address->address.ip_v6.addr;
        // should really be: snprintf(buf, buflen,...) but snprintf() is not always available
        sprintf(buf, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    }
    return buf;
}

static char *printAddress_no_conversion(SFLAddress *address, char *buf, int bufLen)
{
    if (address->type == SFLADDRESSTYPE_IP_V4) {
        uint32_t ipaddr = address->address.ip_v4.addr;
        u_char *ip = (u_char *)&ipaddr;
        sprintf(buf, "%u.%u.%u.%u", ip[3], ip[2], ip[1], ip[0]);
    } else {
        u_char *b = address->address.ip_v6.addr;
        sprintf(buf, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    }
    return buf;
}

/*_________________---------------------------__________________
  _________________    sampleFilterOK         __________________
  -----------------___________________________------------------
*/

int sampleFilterOK(SFSample *sample)
{
    // the vlan filter will only reject a sample if both in_vlan and out_vlan are rejected. If the
    // vlan was not reported in an SFLExtended_Switch struct, but was only picked up from the 802.1q header
    // then the out_vlan will be 0,  so to be sure you are rejecting vlan 1,  you may need to reject both
    // vlan 0 and vlan 1.
    return (sfConfig.gotVlanFilter == NO
            || sfConfig.vlanFilter[sample->in_vlan]
            || sfConfig.vlanFilter[sample->out_vlan]);
}

/*_________________---------------------------__________________
  _________________    writeFlowLine          __________________
  -----------------___________________________------------------
*/

static void writeFlowLine(SFSample *sample)
{
    char agentIP[51], srcIP[51], dstIP[51];
    // source
    if (printf("FLOW,%s,%d,%d,",
               printAddress(&sample->agent_addr, agentIP, 50),
               sample->inputPort,
               sample->outputPort) < 0) {
        custom_exit(-41);
    }
    // layer 2
    if (printf("%02x%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x%02x,0x%04x,%d,%d",
               sample->eth_src[0],
               sample->eth_src[1],
               sample->eth_src[2],
               sample->eth_src[3],
               sample->eth_src[4],
               sample->eth_src[5],
               sample->eth_dst[0],
               sample->eth_dst[1],
               sample->eth_dst[2],
               sample->eth_dst[3],
               sample->eth_dst[4],
               sample->eth_dst[5],
               sample->eth_type,
               sample->in_vlan,
               sample->out_vlan) < 0) {
        custom_exit(-42);
    }
    // layer 3/4
    if (printf(",%s,%s,%d,0x%02x,%d,%d,%d,0x%02x",
               printAddress(&sample->ipsrc, srcIP, 50),
               printAddress(&sample->ipdst, dstIP, 50),
               sample->dcd_ipProtocol,
               sample->dcd_ipTos,
               sample->dcd_ipTTL,
               sample->dcd_sport,
               sample->dcd_dport,
               sample->dcd_tcpFlags) < 0) {
        custom_exit(-43);
    }
    // bytes
    if (printf(",%d,%d,%d\n",
               sample->sampledPacketSize,
               sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4,
               sample->meanSkipCount) < 0) {
        custom_exit(-44);
    }
}

/*_________________---------------------------__________________
  _________________    writeCountersLine      __________________
  -----------------___________________________------------------
*/

static void writeCountersLine(SFSample *sample)
{
    // source
    char agentIP[51];
    if (printf("CNTR,%s,", printAddress(&sample->agent_addr, agentIP, 50)) < 0) {
        custom_exit(-45);
    }
    if (printf("%u,%u,%"PRIu64",%u,%u,%"PRIu64",%u,%u,%u,%u,%u,%u,%"PRIu64",%u,%u,%u,%u,%u,%u\n",
               sample->ifCounters.ifIndex,
               sample->ifCounters.ifType,
               sample->ifCounters.ifSpeed,
               sample->ifCounters.ifDirection,
               sample->ifCounters.ifStatus,
               sample->ifCounters.ifInOctets,
               sample->ifCounters.ifInUcastPkts,
               sample->ifCounters.ifInMulticastPkts,
               sample->ifCounters.ifInBroadcastPkts,
               sample->ifCounters.ifInDiscards,
               sample->ifCounters.ifInErrors,
               sample->ifCounters.ifInUnknownProtos,
               sample->ifCounters.ifOutOctets,
               sample->ifCounters.ifOutUcastPkts,
               sample->ifCounters.ifOutMulticastPkts,
               sample->ifCounters.ifOutBroadcastPkts,
               sample->ifCounters.ifOutDiscards,
               sample->ifCounters.ifOutErrors,
               sample->ifCounters.ifPromiscuousMode) < 0) {
        custom_exit(-46);
    }
}

/*_________________---------------------------__________________
  _________________    receiveError           __________________
  -----------------___________________________------------------
*/

static void dumpSample(SFSample *sample)
{
    u_char hex[6000];
    uint32_t markOffset = (u_char *)sample->datap - sample->rawSample;
    printHex(sample->rawSample, sample->rawSampleLen, hex, 6000, markOffset, 16);
    if (printf("dumpSample:\n%s\n", hex) < 0) {
        custom_exit(-47);
    }
}


static void receiveError(SFSample *sample, char *errm, int hexdump)
{
    char ipbuf[51];
    char scratch[6000];
    char *msg = "";
    char *hex = "";
    uint32_t markOffset = (u_char *)sample->datap - sample->rawSample;
    if (errm) {
        msg = errm;
    }
    if (hexdump) {
        printHex(sample->rawSample, sample->rawSampleLen, (u_char *)scratch, 6000, markOffset, 16);
        hex = scratch;
    }
    fprintf(ERROUT, "%s (source IP = %s) %s\n",
            msg,
            printAddress(&sample->sourceIP, ipbuf, 50),
            hex);

    SFABORT(sample, SF_ABORT_DECODE_ERROR);
}

/*_________________---------------------------__________________
  _________________    lengthCheck            __________________
  -----------------___________________________------------------
*/

static void lengthCheck(SFSample *sample, char *description, u_char *start, int len)
{
    uint32_t actualLen = (u_char *)sample->datap - start;
    actualLen = ((actualLen + 3) >> 2) << 2;
    uint32_t adjustedLen = ((len + 3) >> 2) << 2;
    if (actualLen != adjustedLen) {
        fprintf(ERROUT, "%s length error (expected %d, found %d)\n", description, len, actualLen);
        SFABORT(sample, SF_ABORT_LENGTH_ERROR);
    }
}

/*_________________---------------------------__________________
  _________________     decodeLinkLayer       __________________
  -----------------___________________________------------------
  store the offset to the start of the ipv4 header in the sequence_number field
  or -1 if not found. Decode the 802.1d if it's there.
*/

#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500

#define NFT_MIN_SIZ (NFT_ETHHDR_SIZ + sizeof(struct myiphdr))

static void decodeLinkLayer(SFSample *sample)
{
    u_char *start = (u_char *)sample->header;
    u_char *end = start + sample->headerLen;
    u_char *ptr = start;
    uint16_t type_len;

    /* assume not found */
    sample->gotIPV4 = NO;
    sample->gotIPV6 = NO;

    if (sample->headerLen < NFT_ETHHDR_SIZ) {
        return;    /* not enough for an Ethernet header */
    }

    sf_log("dstMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
    memcpy(sample->eth_dst, ptr, 6);
    ptr += 6;

    sf_log("srcMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
    memcpy(sample->eth_src, ptr, 6);
    ptr += 6;
    type_len = (ptr[0] << 8) + ptr[1];
    ptr += 2;

    if (type_len == 0x8100) {
        /* VLAN  - next two bytes */
        uint32_t vlanData = (ptr[0] << 8) + ptr[1];
        uint32_t vlan = vlanData & 0x0fff;
        uint32_t priority = vlanData >> 13;
        ptr += 2;
        /*  _____________________________________ */
        /* |   pri  | c |         vlan-id        | */
        /*  ------------------------------------- */
        /* [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] */
        sf_log("decodedVLAN %u\n", vlan);
        sf_log("decodedPriority %u\n", priority);
        sample->in_vlan = vlan;
        /* now get the type_len again (next two bytes) */
        type_len = (ptr[0] << 8) + ptr[1];
        ptr += 2;
    }

    /* now we're just looking for IP */
    if (sample->headerLen < NFT_MIN_SIZ) {
        return;    /* not enough for an IPv4 header */
    }

    /* peek for IPX */
    if (type_len == 0x0200 || type_len == 0x0201 || type_len == 0x0600) {
#define IPX_HDR_LEN 30
#define IPX_MAX_DATA 546
        int ipxChecksum = (ptr[0] == 0xff && ptr[1] == 0xff);
        int ipxLen = (ptr[2] << 8) + ptr[3];
        if (ipxChecksum &&
            ipxLen >= IPX_HDR_LEN &&
            ipxLen <= (IPX_HDR_LEN + IPX_MAX_DATA))
            /* we don't do anything with IPX here */
        {
            return;
        }
    }

    if (type_len <= NFT_MAX_8023_LEN) {
        /* assume 802.3+802.2 header */
        /* check for SNAP */
        if (ptr[0] == 0xAA &&
            ptr[1] == 0xAA &&
            ptr[2] == 0x03) {
            ptr += 3;
            if (ptr[0] != 0 ||
                ptr[1] != 0 ||
                ptr[2] != 0) {
                sf_log("VSNAP_OUI %02X-%02X-%02X\n", ptr[0], ptr[1], ptr[2]);
                return; /* no further decode for vendor-specific protocol */
            }
            ptr += 3;
            /* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
            type_len = (ptr[0] << 8) + ptr[1];
            ptr += 2;
        } else {
            if (ptr[0] == 0x06 &&
                ptr[1] == 0x06 &&
                (ptr[2] & 0x01)) {
                /* IP over 8022 */
                ptr += 3;
                /* force the type_len to be IP so we can inline the IP decode below */
                type_len = 0x0800;
            } else {
                return;
            }
        }
    }

    /* assume type_len is an ethernet-type now */
    sample->eth_type = type_len;

    if (type_len == 0x0800) {
        /* IPV4 */
        if ((end - ptr) < sizeof(struct myiphdr)) {
            return;
        }
        /* look at first byte of header.... */
        /*  ___________________________ */
        /* |   version   |    hdrlen   | */
        /*  --------------------------- */
        if ((*ptr >> 4) != 4) {
            return;    /* not version 4 */
        }
        if ((*ptr & 15) < 5) {
            return;    /* not IP (hdr len must be 5 quads or more) */
        }
        /* survived all the tests - store the offset to the start of the ip header */
        sample->gotIPV4 = YES;
        sample->offsetToIPV4 = (ptr - start);
    }

    if (type_len == 0x86DD) {
        /* IPV6 */
        /* look at first byte of header.... */
        if ((*ptr >> 4) != 6) {
            return;    /* not version 6 */
        }
        /* survived all the tests - store the offset to the start of the ip6 header */
        sample->gotIPV6 = YES;
        sample->offsetToIPV6 = (ptr - start);
    }
}

/*_________________---------------------------__________________
  _________________       decode80211MAC      __________________
  -----------------___________________________------------------
  store the offset to the start of the ipv4 header in the sequence_number field
  or -1 if not found.
*/

#define WIFI_MIN_HDR_SIZ 24

static void decode80211MAC(SFSample *sample)
{
    u_char *start = (u_char *)sample->header;
    u_char *end = start + sample->headerLen;
    u_char *ptr = start;

    /* assume not found */
    sample->gotIPV4 = NO;
    sample->gotIPV6 = NO;

    if (sample->headerLen < WIFI_MIN_HDR_SIZ) {
        return;    /* not enough for an 80211 MAC header */
    }

    uint32_t fc = (ptr[1] << 8) + ptr[0];  // [b7..b0][b15..b8]
    uint32_t protocolVersion = fc & 3;
    uint32_t control = (fc >> 2) & 3;
    uint32_t subType = (fc >> 4) & 15;
    uint32_t toDS = (fc >> 8) & 1;
    uint32_t fromDS = (fc >> 9) & 1;
    uint32_t moreFrag = (fc >> 10) & 1;
    uint32_t retry = (fc >> 11) & 1;
    uint32_t pwrMgt = (fc >> 12) & 1;
    uint32_t moreData = (fc >> 13) & 1;
    uint32_t encrypted = (fc >> 14) & 1;
    uint32_t order = fc >> 15;

    ptr += 2;

    uint32_t duration_id = (ptr[1] << 8) + ptr[0]; // not in network byte order either?
    ptr += 2;

    switch (control) {
        case 0: // mgmt
        case 1: // ctrl
        case 3: // rsvd
            break;

        case 2: { // data

            u_char *macAddr1 = ptr;
            ptr += 6;
            u_char *macAddr2 = ptr;
            ptr += 6;
            u_char *macAddr3 = ptr;
            ptr += 6;
            uint32_t sequence = (ptr[0] << 8) + ptr[1];
            ptr += 2;

            // ToDS   FromDS   Addr1   Addr2  Addr3   Addr4
            // 0      0        DA      SA     BSSID   N/A (ad-hoc)
            // 0      1        DA      BSSID  SA      N/A
            // 1      0        BSSID   SA     DA      N/A
            // 1      1        RA      TA     DA      SA  (wireless bridge)

            u_char *rxMAC = macAddr1;
            u_char *txMAC = macAddr2;
            u_char *srcMAC = NULL;
            u_char *dstMAC = NULL;

            if (toDS) {
                dstMAC = macAddr3;
                if (fromDS) {
                    srcMAC = ptr; // macAddr4.  1,1 => (wireless bridge)
                    ptr += 6;
                } else {
                    srcMAC = macAddr2;    // 1,0
                }
            } else {
                dstMAC = macAddr1;
                if (fromDS) {
                    srcMAC = macAddr3;    // 0,1
                } else {
                    srcMAC = macAddr2;    // 0,0
                }
            }

            if (srcMAC) {
                sf_log("srcMAC %02x%02x%02x%02x%02x%02x\n", srcMAC[0], srcMAC[1], srcMAC[2], srcMAC[3], srcMAC[4], srcMAC[5]);
                memcpy(sample->eth_src, srcMAC, 6);
            }
            if (dstMAC) {
                sf_log("dstMAC %02x%02x%02x%02x%02x%02x\n", dstMAC[0], dstMAC[1], dstMAC[2], dstMAC[3], dstMAC[4], dstMAC[5]);
                memcpy(sample->eth_dst, srcMAC, 6);
            }
            if (txMAC) {
                sf_log("txMAC %02x%02x%02x%02x%02x%02x\n", txMAC[0], txMAC[1], txMAC[2], txMAC[3], txMAC[4], txMAC[5]);
            }
            if (rxMAC) {
                sf_log("rxMAC %02x%02x%02x%02x%02x%02x\n", rxMAC[0], rxMAC[1], rxMAC[2], rxMAC[3], rxMAC[4], rxMAC[5]);
            }
        }
    }
}

/*_________________---------------------------__________________
  _________________     decodeIPLayer4        __________________
  -----------------___________________________------------------
*/

static void decodeIPLayer4(SFSample *sample, u_char *ptr)
{
    u_char *end = sample->header + sample->headerLen;
    if (ptr > (end - 8)) {
        // not enough header bytes left
        return;
    }
    switch (sample->dcd_ipProtocol) {
        case 1: { /* ICMP */
            struct myicmphdr icmp;
            memcpy(&icmp, ptr, sizeof(icmp));
            sf_log("ICMPType %u\n", icmp.type);
            sf_log("ICMPCode %u\n", icmp.code);
            sample->dcd_sport = icmp.type;
            sample->dcd_dport = icmp.code;
            sample->offsetToPayload = ptr + sizeof(icmp) - sample->header;
        }
        break;
        case 6: { /* TCP */
            struct mytcphdr tcp;
            int headerBytes;
            memcpy(&tcp, ptr, sizeof(tcp));
            sample->dcd_sport = ntohs(tcp.th_sport);
            sample->dcd_dport = ntohs(tcp.th_dport);
            sample->dcd_tcpFlags = tcp.th_flags;
            sf_log("TCPSrcPort %u\n", sample->dcd_sport);
            sf_log("TCPDstPort %u\n", sample->dcd_dport);
            sf_log("TCPFlags %u\n", sample->dcd_tcpFlags);
            headerBytes = (tcp.th_off_and_unused >> 4) * 4;
            ptr += headerBytes;
            sample->offsetToPayload = ptr - sample->header;
        }
        break;
        case 17: { /* UDP */
            struct myudphdr udp;
            memcpy(&udp, ptr, sizeof(udp));
            sample->dcd_sport = ntohs(udp.uh_sport);
            sample->dcd_dport = ntohs(udp.uh_dport);
            sample->udp_pduLen = ntohs(udp.uh_ulen);
            sf_log("UDPSrcPort %u\n", sample->dcd_sport);
            sf_log("UDPDstPort %u\n", sample->dcd_dport);
            sf_log("UDPBytes %u\n", sample->udp_pduLen);
            sample->offsetToPayload = ptr + sizeof(udp) - sample->header;
        }
        break;
        default: /* some other protcol */
            sample->offsetToPayload = ptr - sample->header;
            break;
    }
}

/*_________________---------------------------__________________
  _________________     decodeIPV4            __________________
  -----------------___________________________------------------
*/

static void decodeIPV4(SFSample *sample)
{
    if (sample->gotIPV4) {
        char buf[51];
        u_char *ptr = sample->header + sample->offsetToIPV4;
        /* Create a local copy of the IP header (cannot overlay structure in case it is not quad-aligned...some
           platforms would core-dump if we tried that).  It's OK coz this probably performs just as well anyway. */
        struct myiphdr ip;
        memcpy(&ip, ptr, sizeof(ip));
        /* Value copy all ip elements into sample */
        sample->ipsrc.type = SFLADDRESSTYPE_IP_V4;
        sample->ipsrc.address.ip_v4.addr = ip.saddr;
        sample->ipdst.type = SFLADDRESSTYPE_IP_V4;
        sample->ipdst.address.ip_v4.addr = ip.daddr;
        sample->dcd_ipProtocol = ip.protocol;
        sample->dcd_ipTos = ip.tos;
        sample->dcd_ipTTL = ip.ttl;
        sf_log("ip.tot_len %d\n", ntohs(ip.tot_len));
        /* Log out the decoded IP fields */
        sf_log("srcIP %s\n", printAddress(&sample->ipsrc, buf, 50));
        sf_log("dstIP %s\n", printAddress(&sample->ipdst, buf, 50));
        sf_log("IPProtocol %u\n", sample->dcd_ipProtocol);
        sf_log("IPTOS %u\n", sample->dcd_ipTos);
        sf_log("IPTTL %u\n", sample->dcd_ipTTL);
        /* check for fragments */
        sample->ip_fragmentOffset = ntohs(ip.frag_off) & 0x1FFF;
        if (sample->ip_fragmentOffset > 0) {
            sf_log("IPFragmentOffset %u\n", sample->ip_fragmentOffset);
        } else {
            /* advance the pointer to the next protocol layer */
            /* ip headerLen is expressed as a number of quads */
            ptr += (ip.version_and_headerLen & 0x0f) * 4;
            decodeIPLayer4(sample, ptr);
        }
    }
}

/*_________________---------------------------__________________
  _________________     decodeIPV6            __________________
  -----------------___________________________------------------
*/

static void decodeIPV6(SFSample *sample)
{
    uint16_t payloadLen;
    uint32_t label;
    uint32_t nextHeader;
    u_char *end = sample->header + sample->headerLen;

    if (sample->gotIPV6) {
        u_char *ptr = sample->header + sample->offsetToIPV6;

        // check the version
        {
            int ipVersion = (*ptr >> 4);
            if (ipVersion != 6) {
                sf_log("header decode error: unexpected IP version: %d\n", ipVersion);
                return;
            }
        }

        // get the tos (priority)
        sample->dcd_ipTos = *ptr++ & 15;
        sf_log("IPTOS %u\n", sample->dcd_ipTos);
        // 24-bit label
        label = *ptr++;
        label <<= 8;
        label += *ptr++;
        label <<= 8;
        label += *ptr++;
        sf_log("IP6_label 0x%lx\n", label);
        // payload
        payloadLen = (ptr[0] << 8) + ptr[1];
        ptr += 2;
        // if payload is zero, that implies a jumbo payload
        if (payloadLen == 0) {
            sf_log("IPV6_payloadLen <jumbo>\n");
        } else {
            sf_log("IPV6_payloadLen %u\n", payloadLen);
        }

        // next header
        nextHeader = *ptr++;

        // TTL
        sample->dcd_ipTTL = *ptr++;
        sf_log("IPTTL %u\n", sample->dcd_ipTTL);

        {
            // src and dst address
            char buf[101];
            sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
            memcpy(&sample->ipsrc.address, ptr, 16);
            ptr += 16;
            sf_log("srcIP6 %s\n", printAddress(&sample->ipsrc, buf, 100));
            sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
            memcpy(&sample->ipdst.address, ptr, 16);
            ptr += 16;
            sf_log("dstIP6 %s\n", printAddress(&sample->ipdst, buf, 100));
        }

        // skip over some common header extensions...
        // http://searchnetworking.techtarget.com/originalContent/0,289142,sid7_gci870277,00.html
        while (nextHeader == 0 || // hop
               nextHeader == 43 || // routing
               nextHeader == 44 || // fragment
               // nextHeader == 50 || // encryption - don't bother coz we'll not be able to read any further
               nextHeader == 51 || // auth
               nextHeader == 60) { // destination options
            uint32_t optionLen, skip;
            sf_log("IP6HeaderExtension: %d\n", nextHeader);
            nextHeader = ptr[0];
            optionLen = 8 * (ptr[1] + 1);  // second byte gives option len in 8-byte chunks, not counting first 8
            skip = optionLen - 2;
            ptr += skip;
            if (ptr > end) {
                return;    // ran off the end of the header
            }
        }

        // now that we have eliminated the extension headers, nextHeader should have what we want to
        // remember as the ip protocol...
        sample->dcd_ipProtocol = nextHeader;
        sf_log("IPProtocol %u\n", sample->dcd_ipProtocol);
        decodeIPLayer4(sample, ptr);
    }
}

/*_________________---------------------------__________________
  _________________   readPcapHeader          __________________
  -----------------___________________________------------------
*/

#define TCPDUMP_MAGIC 0xa1b2c3d4  /* from libpcap-0.5: savefile.c */
#define DLT_EN10MB  1     /* from libpcap-0.5: net/bpf.h */
#define PCAP_VERSION_MAJOR 2      /* from libpcap-0.5: pcap.h */
#define PCAP_VERSION_MINOR 4      /* from libpcap-0.5: pcap.h */

static void readPcapHeader()
{
    struct pcap_file_header hdr;
    if (fread(&hdr, sizeof(hdr), 1, sfConfig.readPcapFile) != 1) {
        fprintf(ERROUT, "unable to read pcap header from %s : %s\n", sfConfig.readPcapFileName, strerror(errno));
        custom_exit(-30);
    }
    if (hdr.magic != TCPDUMP_MAGIC) {
        if (hdr.magic == MyByteSwap32(TCPDUMP_MAGIC)) {
            sfConfig.pcapSwap = YES;
            hdr.version_major = MyByteSwap16(hdr.version_major);
            hdr.version_minor = MyByteSwap16(hdr.version_minor);
            hdr.thiszone = MyByteSwap32(hdr.thiszone);
            hdr.sigfigs = MyByteSwap32(hdr.sigfigs);
            hdr.snaplen = MyByteSwap32(hdr.snaplen);
            hdr.linktype = MyByteSwap32(hdr.linktype);
        } else {
            fprintf(ERROUT, "%s not recognized as a tcpdump file\n(magic number = %08x instead of %08x)\n",
                    sfConfig.readPcapFileName,
                    hdr.magic,
                    TCPDUMP_MAGIC);
            custom_exit(-31);
        }
    }
    fprintf(ERROUT, "pcap version=%d.%d snaplen=%d linktype=%d \n",
            hdr.version_major,
            hdr.version_minor,
            hdr.snaplen,
            hdr.linktype);
    sfConfig.readPcapHdr = hdr;
}

/*_________________---------------------------__________________
  _________________   writePcapHeader         __________________
  -----------------___________________________------------------
*/

#define DLT_EN10MB  1     /* from libpcap-0.5: net/bpf.h */
#define PCAP_VERSION_MAJOR 2      /* from libpcap-0.5: pcap.h */
#define PCAP_VERSION_MINOR 4      /* from libpcap-0.5: pcap.h */

static void writePcapHeader()
{
    struct pcap_file_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.snaplen = 128;
    hdr.sigfigs = 0;
    hdr.linktype = DLT_EN10MB;
    if (fwrite((char *)&hdr, sizeof(hdr), 1, stdout) != 1) {
        fprintf(ERROUT, "failed to write tcpdump header: %s\n", strerror(errno));
        custom_exit(-1);
    }
    fflush(stdout);
}

/*_________________---------------------------__________________
  _________________   writePcapPacket         __________________
  -----------------___________________________------------------
*/

static void writePcapPacket(SFSample *sample)
{
    char buf[2048];
    int bytes = 0;
    struct pcap_pkthdr hdr;
    hdr.ts_sec = (uint32_t)time(NULL);
    hdr.ts_usec = 0;
    hdr.len = sample->sampledPacketSize;
    hdr.caplen = sample->headerLen;
    if (sfConfig.removeContent && sample->offsetToPayload) {
        // shorten the captured header to ensure no payload bytes are included
        hdr.caplen = sample->offsetToPayload;
    }

    // prepare the whole thing in a buffer first, in case we are piping the output
    // to another process and the reader expects it all to appear at once...
    memcpy(buf, &hdr, sizeof(hdr));
    bytes = sizeof(hdr);
    if (sfConfig.tcpdumpHdrPad > 0) {
        memcpy(buf + bytes, sfConfig.zeroPad, sfConfig.tcpdumpHdrPad);
        bytes += sfConfig.tcpdumpHdrPad;
    }
    memcpy(buf + bytes, sample->header, hdr.caplen);
    bytes += hdr.caplen;

    if (fwrite(buf, bytes, 1, stdout) != 1) {
        fprintf(ERROUT, "writePcapPacket: packet write failed: %s\n", strerror(errno));
        custom_exit(-3);
    }
    fflush(stdout);
}

#ifdef SPOOFSOURCE

/*_________________---------------------------__________________
  _________________      in_checksum          __________________
  -----------------___________________________------------------
*/
static uint16_t in_checksum(uint16_t *addr, int len)
{
    int nleft = len;
    u_short *w = addr;
    u_short answer;
    int sum = 0;

    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        sum += *(u_char *)w;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

/*_________________---------------------------__________________
  _________________   openNetFlowSocket_spoof __________________
  -----------------___________________________------------------
*/

static void openNetFlowSocket_spoof()
{
    int on;

    if ((sfConfig.netFlowOutputSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1) {
        fprintf(ERROUT, "netflow output raw socket open failed\n");
        custom_exit(-11);
    }
    on = 1;
    if (setsockopt(sfConfig.netFlowOutputSocket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0) {
        fprintf(ERROUT, "setsockopt( IP_HDRINCL ) failed\n");
        custom_exit(-13);
    }
    on = 1;
    if (setsockopt(sfConfig.netFlowOutputSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
        fprintf(ERROUT, "setsockopt( SO_REUSEADDR ) failed\n");
        custom_exit(-14);
    }

    memset(&sfConfig.sendPkt, 0, sizeof(sfConfig.sendPkt));
    sfConfig.sendPkt.ip.version_and_headerLen = 0x45;
    sfConfig.sendPkt.ip.protocol = IPPROTO_UDP;
    sfConfig.sendPkt.ip.ttl = 64; // IPDEFTTL
    sfConfig.ipid = 12000; // start counting from 12000 (just an arbitrary number)
    // sfConfig.ip->frag_off = htons(0x4000); // don't fragment
    // can't set the source address yet, but the dest address is known
    sfConfig.sendPkt.ip.daddr = sfConfig.netFlowOutputIP.s_addr;
    // can't do the ip_len and checksum until we know the size of the packet
    sfConfig.sendPkt.udp.uh_dport = htons(sfConfig.netFlowOutputPort);
    // might as well set the source port to be the same
    sfConfig.sendPkt.udp.uh_sport = htons(sfConfig.netFlowOutputPort);
    // can't do the udp_len or udp_checksum until we know the size of the packet
}



/*_________________---------------------------__________________
  _________________ sendNetFlowDatagram_spoof __________________
  -----------------___________________________------------------
*/

static void sendNetFlowDatagram_spoof(SFSample *sample, NFFlowPkt5 *pkt)
{
    uint16_t packetLen = sizeof(*pkt) + sizeof(struct myiphdr) + sizeof(struct myudphdr);
    // copy the data into the send packet
    memcpy(sfConfig.sendPkt.data, (char *)pkt, sizeof(*pkt));
    // increment the ip-id
    sfConfig.sendPkt.ip.id = htons(++sfConfig.ipid);
    // set the length fields in the ip and udp headers
    sfConfig.sendPkt.ip.tot_len = htons(packetLen);
    sfConfig.sendPkt.udp.uh_ulen = htons(packetLen - sizeof(struct myiphdr));
    // set the source address to the source address of the input event
    sfConfig.sendPkt.ip.saddr = sample->agent_addr.address.ip_v4.addr;
    // IP header checksum
    sfConfig.sendPkt.ip.check = in_checksum((uint16_t *)&sfConfig.sendPkt.ip, sizeof(struct myiphdr));
    if (sfConfig.sendPkt.ip.check == 0) {
        sfConfig.sendPkt.ip.check = 0xffff;
    }
    // UDP Checksum
    // copy out those parts of the IP header that are supposed to be in the UDP checksum,
    // and blat them in front of the udp header (after saving what was there before).
    // Then compute the udp checksum.  Then patch the saved data back again.
    {
        char *ptr;
        struct udpmagichdr {
            uint32_t src;
            uint32_t dst;
            u_char zero;
            u_char proto;
            u_short len;
        } h, saved;

        h.src = sfConfig.sendPkt.ip.saddr;
        h.dst = sfConfig.sendPkt.ip.daddr;
        h.zero = 0;
        h.proto = IPPROTO_UDP;
        h.len = sfConfig.sendPkt.udp.uh_ulen;
        // set the pointer to 12 bytes before the start of the udp header
        ptr = (char *)&sfConfig.sendPkt.udp;
        ptr -= sizeof(struct udpmagichdr);
        // save what's there
        memcpy(&saved, ptr, sizeof(struct udpmagichdr));
        // blat in the replacement bytes
        memcpy(ptr, &h, sizeof(struct udpmagichdr));
        // compute the checksum
        sfConfig.sendPkt.udp.uh_sum = 0;
        sfConfig.sendPkt.udp.uh_sum = in_checksum((uint16_t *)ptr,
                                                  ntohs(sfConfig.sendPkt.udp.uh_ulen) + sizeof(struct udpmagichdr));
        if (sfConfig.sendPkt.udp.uh_sum == 0) {
            sfConfig.sendPkt.udp.uh_sum = 0xffff;
        }
        // copy the save bytes back again
        memcpy(ptr, &saved, sizeof(struct udpmagichdr));

        {
            // now send the packet
            int bytesSent;
            struct sockaddr dest;
            struct sockaddr_in *to = (struct sockaddr_in *)&dest;
            memset(&dest, 0, sizeof(dest));
            to->sin_family = AF_INET;
            to->sin_addr.s_addr = sfConfig.sendPkt.ip.daddr;
            if ((bytesSent = sendto(sfConfig.netFlowOutputSocket,
                                    &sfConfig.sendPkt,
                                    packetLen,
                                    0,
                                    &dest,
                                    sizeof(dest))) != packetLen) {
                fprintf(ERROUT, "sendto returned %d (expected %d): %s\n", bytesSent, packetLen, strerror(errno));
            }
        }
    }
}

#endif /* SPOOFSOURCE */

/*_________________---------------------------__________________
  _________________   openNetFlowSocket       __________________
  -----------------___________________________------------------
*/

static void openNetFlowSocket()
{

#ifdef SPOOFSOURCE
    if (sfConfig.spoofSource) {
        return openNetFlowSocket_spoof();
    }
#endif

    {
        struct sockaddr_in addr;
        memset((char *)&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = ntohs(sfConfig.netFlowOutputPort);
        addr.sin_addr.s_addr = sfConfig.netFlowOutputIP.s_addr;

        // open an ordinary UDP socket
        if ((sfConfig.netFlowOutputSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
            fprintf(ERROUT, "netflow output socket open failed\n");
            custom_exit(-4);
        }
        /* connect to it so we can just use send() or write() to send on it */
        if (connect(sfConfig.netFlowOutputSocket, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            fprintf(ERROUT, "connect() to netflow output socket failed\n");
            custom_exit(-5);
        }
    }
}

/*_________________---------------------------__________________
  _________________   sendNetFlowDatagram     __________________
  -----------------___________________________------------------
*/

static int NFFlowSequenceNo = 0;

static void sendNetFlowDatagram(SFSample *sample)
{
    NFFlowPkt5 pkt;
    uint32_t now = (uint32_t)time(NULL);
    uint32_t bytes;
    // ignore fragments
    if (sample->ip_fragmentOffset > 0) {
        return;
    }
    // count the bytes from the start of IP header, with the exception that
    // for udp packets we use the udp_pduLen. This is because the udp_pduLen
    // can be up tp 65535 bytes, which causes fragmentation at the IP layer.
    // Since the sampled fragments are discarded, we have to use this field
    // to get the total bytes estimates right.
    if (sample->udp_pduLen > 0) {
        bytes = sample->udp_pduLen;
    } else {
        bytes = sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4;
    }

    memset(&pkt, 0, sizeof(pkt));
    pkt.hdr.version = htons(5);
    pkt.hdr.count = htons(1);
    pkt.hdr.sysUpTime = htonl(now % (3600 * 24)) * 1000;  /* pretend we started at midnight (milliseconds) */
    pkt.hdr.unixSeconds = htonl(now);
    pkt.hdr.unixNanoSeconds = 0; /* no need to be more accurate than 1 second */
    pkt.hdr.flowSequence = htonl(NFFlowSequenceNo++);

    pkt.flow.srcIP = sample->ipsrc.address.ip_v4.addr;
    pkt.flow.dstIP = sample->ipdst.address.ip_v4.addr;
    pkt.flow.nextHop = sample->nextHop.address.ip_v4.addr;
    pkt.flow.if_in = htons((uint16_t)sample->inputPort);
    pkt.flow.if_out = htons((uint16_t)sample->outputPort);

    if (!sfConfig.disableNetFlowScale) {
        pkt.flow.frames = htonl(sample->meanSkipCount);
        pkt.flow.bytes = htonl(sample->meanSkipCount * bytes);
    } else {
        /* set the sampling_interval header field too (used to be a 16-bit reserved field) */
        uint16_t samp_ival = (uint16_t)sample->meanSkipCount;
        pkt.hdr.sampling_interval = htons(samp_ival & 0x4000);
        pkt.flow.frames = htonl(1);
        pkt.flow.bytes = htonl(bytes);
    }

    pkt.flow.firstTime = pkt.hdr.sysUpTime;  /* set the start and end time to be now (in milliseconds since last boot) */
    pkt.flow.lastTime =  pkt.hdr.sysUpTime;
    pkt.flow.srcPort = htons((uint16_t)sample->dcd_sport);
    pkt.flow.dstPort = htons((uint16_t)sample->dcd_dport);
    pkt.flow.tcpFlags = sample->dcd_tcpFlags;
    pkt.flow.ipProto = sample->dcd_ipProtocol;
    pkt.flow.ipTos = sample->dcd_ipTos;

    if (sfConfig.netFlowPeerAS) {
        pkt.flow.srcAS = htons((uint16_t)sample->src_peer_as);
        pkt.flow.dstAS = htons((uint16_t)sample->dst_peer_as);
    } else {
        pkt.flow.srcAS = htons((uint16_t)sample->src_as);
        pkt.flow.dstAS = htons((uint16_t)sample->dst_as);
    }

    pkt.flow.srcMask = (uint8_t)sample->srcMask;
    pkt.flow.dstMask = (uint8_t)sample->dstMask;

#ifdef SPOOFSOURCE
    if (sfConfig.spoofSource) {
        sendNetFlowDatagram_spoof(sample, &pkt);
        return;
    }
#endif /* SPOOFSOURCE */

    /* send non-blocking */
    send(sfConfig.netFlowOutputSocket, (char *)&pkt, sizeof(pkt), 0);

}

/*_________________---------------------------__________________
  _________________   read data fns           __________________
  -----------------___________________________------------------
*/

static uint32_t getData32_nobswap(SFSample *sample)
{
    uint32_t ans = *(sample->datap)++;
    // make sure we didn't run off the end of the datagram.  Thanks to
    // Sven Eschenberg for spotting a bug/overrun-vulnerabilty that was here before.
    if ((u_char *)sample->datap > sample->endp) {
        SFABORT(sample, SF_ABORT_EOS);
    }
    return ans;
}

static uint32_t getData32(SFSample *sample)
{
    return ntohl(getData32_nobswap(sample));
}

static float getFloat(SFSample *sample)
{
    float fl;
    uint32_t reg = getData32(sample);
    memcpy(&fl, &reg, 4);
    return fl;
}

static uint64_t getData64(SFSample *sample)
{
    uint64_t tmpLo, tmpHi;
    tmpHi = getData32(sample);
    tmpLo = getData32(sample);
    return (tmpHi << 32) + tmpLo;
}

static void skipBytes(SFSample *sample, uint32_t skip)
{
    int quads = (skip + 3) / 4;
    sample->datap += quads;
    if (skip > sample->rawSampleLen || (u_char *)sample->datap > sample->endp) {
        SFABORT(sample, SF_ABORT_EOS);
    }
}

static uint16_t getData16(SFSample *sample)
{
    uint16_t ans = *(sample->datap);
    sample->datap = (uint32_t *)((uint16_t *)sample->datap + 1);
    // make sure we didn't run off the end of the datagram.  Thanks to
    // Sven Eschenberg for spotting a bug/overrun-vulnerabilty that was here before.
    if ((u_char *)sample->datap > sample->endp) {
        SFABORT(sample, SF_ABORT_EOS);
    }
    return ntohs(ans);
}

static uint8_t getData_u8(SFSample *sample)
{
    uint8_t ans = *(((uint8_t *)sample->datap));
    sample->datap = (uint32_t *)((uint8_t *)sample->datap + 1);
    // make sure we didn't run off the end of the datagram.  Thanks to
    // Sven Eschenberg for spotting a bug/overrun-vulnerabilty that was here before.
    if ((u_char *)sample->datap > sample->endp) {
        SFABORT(sample, SF_ABORT_EOS);
    }
    return ans;
}

static void  getData8(SFSample *sample, char *buffer, unsigned short len)
{
    strncpy(buffer, (void *)(sample->datap), len);
    buffer[len - 1] = '\0';
    sample->datap = (uint32_t *)((uint8_t *)sample->datap + len);
    if ((u_char *)sample->datap > sample->endp) {
        SFABORT(sample, SF_ABORT_EOS);
    }
}

static void sf_log_string(char *buffer)
{
    sf_log("%s", buffer);
}


static void sf_log_u32(uint32_t val, char *fieldName)
{
    sf_log("%-35s %-20u\n", fieldName, val);
}

static void sf_log_u64(uint64_t val, char *fieldName)
{
    sf_log("%-35s %-20u\n", fieldName, val);
}


static void sf_log_next8(SFSample *sample, char *fieldName, char *buffer, unsigned short len)
{
    getData8(sample, buffer, len);
    sf_log("%-35s %-20s\n", fieldName, buffer);
}

static uint16_t sf_log_next16(SFSample *sample, char *fieldName)
{
    uint16_t val = getData16(sample);
    sf_log("%-35s %-20u\n", fieldName, val);
    return val;
}

static uint32_t sf_log_next32_skip_print_if_null(SFSample *sample, char *fieldName)
{
    uint32_t val = getData32(sample);
    if (val) {
        sf_log("%-35s %-20u\n", fieldName, val);
    }
    return val;
}

static uint32_t sf_log_next32(SFSample *sample, char *fieldName)
{
    uint32_t val = getData32(sample);
    sf_log("%-35s %-20u\n", fieldName, val);
    return val;
}

static uint64_t sf_log_next64_skip_print_if_null(SFSample *sample, char *fieldName)
{
    uint64_t val64 = getData64(sample);
    if (val64) {
        sf_log("%-35s %-20"PRIu64"\n", fieldName, val64);
    }
    return val64;
}

static uint64_t sf_log_next64_skip_print(SFSample *sample, char *fieldName)
{
    uint64_t val64 = getData64(sample);
    return 0;
}

static uint64_t sf_log_next64(SFSample *sample, char *fieldName)
{
    uint64_t val64 = getData64(sample);
    sf_log("%-35s %-20"PRIu64"\n", fieldName, val64);
    return val64;
}

int opentsdb_print_next64(SFSample *sample, char *tbuf, int len, char *fieldName)
{
        long tstamp = time(NULL);
        uint64_t val64 = getData64(sample);
        len = sprintf (tsdb_buff + len, "%s%lu %lu %s", fieldName, (long )tstamp, (long )val64, tbuf);
        //len = sprintf (tsdb_buff + len, "%s %lu %lu", fieldName, tstamp, val64);
        return len;
}

void sf_log_percentage(SFSample *sample, char *fieldName)
{
    uint32_t hundredths = getData32(sample);
    if (hundredths == (uint32_t) - 1) {
        sf_log("%s unknown\n", fieldName);
    } else {
        float percent = (float)hundredths / (float)100.0;
        sf_log("%s %.2f\n", fieldName, percent);
    }
}

static float sf_log_nextFloat(SFSample *sample, char *fieldName)
{
    float val = getFloat(sample);
    sf_log("%s %.3f\n", fieldName, val);
    return val;
}

void sf_log_nextMAC(SFSample *sample, char *fieldName)
{
    u_char *mac = (u_char *)sample->datap;
    sf_log("%s %02x%02x%02x%02x%02x%02x\n", fieldName, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    skipBytes(sample, 6);
}

static uint32_t getString(SFSample *sample, char *buf, uint32_t bufLen)
{
    uint32_t len, read_len;
    len = getData32(sample);
    // truncate if too long
    read_len = (len >= bufLen) ? (bufLen - 1) : len;
    memcpy(buf, sample->datap, read_len);
    buf[read_len] = '\0';   // null terminate
    skipBytes(sample, len);
    return len;
}

static uint32_t getAddress(SFSample *sample, SFLAddress *address)
{
    address->type = getData32(sample);
    if (address->type == SFLADDRESSTYPE_IP_V4) {
        address->address.ip_v4.addr = getData32_nobswap(sample);
    } else {
        memcpy(&address->address.ip_v6.addr, sample->datap, 16);
        skipBytes(sample, 16);
    }
    return address->type;
}

static char *printTag(uint32_t tag, char *buf, int bufLen)
{
    // should really be: snprintf(buf, buflen,...) but snprintf() is not always available
    sprintf(buf, "%u:%u", (tag >> 12), (tag & 0x00000FFF));
    return buf;
}

static void skipTLVRecord(SFSample *sample, uint32_t tag, uint32_t len, char *description)
{
    char buf[51];
    sf_log("skipping unknown %s: %s len=%d\n", description, printTag(tag, buf, 50), len);
    skipBytes(sample, len);
}

/*_________________---------------------------__________________
  _________________    readExtendedSwitch     __________________
  -----------------___________________________------------------
*/

static void readExtendedSwitch(SFSample *sample)
{
    sf_log("extendedType SWITCH\n");
    sample->in_vlan = getData32(sample);
    sample->in_priority = getData32(sample);
    sample->out_vlan = getData32(sample);
    sample->out_priority = getData32(sample);

    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_SWITCH;

    sf_log("in_vlan %u\n", sample->in_vlan);
    sf_log("in_priority %u\n", sample->in_priority);
    sf_log("out_vlan %u\n", sample->out_vlan);
    sf_log("out_priority %u\n", sample->out_priority);
}

/*_________________---------------------------__________________
  _________________    readExtendedRouter     __________________
  -----------------___________________________------------------
*/

static void readExtendedRouter(SFSample *sample)
{
    char buf[51];
    sf_log("extendedType ROUTER\n");
    getAddress(sample, &sample->nextHop);
    sample->srcMask = getData32(sample);
    sample->dstMask = getData32(sample);

    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_ROUTER;

    sf_log("nextHop %s\n", printAddress(&sample->nextHop, buf, 50));
    sf_log("srcSubnetMask %u\n", sample->srcMask);
    sf_log("dstSubnetMask %u\n", sample->dstMask);
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway_v2   __________________
  -----------------___________________________------------------
*/

static void readExtendedGateway_v2(SFSample *sample)
{
    sf_log("extendedType GATEWAY\n");

    sample->my_as = getData32(sample);
    sample->src_as = getData32(sample);
    sample->src_peer_as = getData32(sample);

    // clear dst_peer_as and dst_as to make sure we are not
    // remembering values from a previous sample - (thanks Marc Lavine)
    sample->dst_peer_as = 0;
    sample->dst_as = 0;

    sample->dst_as_path_len = getData32(sample);
    /* just point at the dst_as_path array */
    if (sample->dst_as_path_len > 0) {
        sample->dst_as_path = sample->datap;
        /* and skip over it in the input */
        skipBytes(sample, sample->dst_as_path_len * 4);
        // fill in the dst and dst_peer fields too
        sample->dst_peer_as = ntohl(sample->dst_as_path[0]);
        sample->dst_as = ntohl(sample->dst_as_path[sample->dst_as_path_len - 1]);
    }

    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;

    sf_log("my_as %u\n", sample->my_as);
    sf_log("src_as %u\n", sample->src_as);
    sf_log("src_peer_as %u\n", sample->src_peer_as);
    sf_log("dst_as %u\n", sample->dst_as);
    sf_log("dst_peer_as %u\n", sample->dst_peer_as);
    sf_log("dst_as_path_len %u\n", sample->dst_as_path_len);
    if (sample->dst_as_path_len > 0) {
        uint32_t i = 0;
        for (; i < sample->dst_as_path_len; i++) {
            if (i == 0) {
                sf_log("dst_as_path ");
            } else {
                sf_log("-");
            }
            sf_log("%u", ntohl(sample->dst_as_path[i]));
        }
        sf_log("\n");
    }
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway      __________________
  -----------------___________________________------------------
*/

static void readExtendedGateway(SFSample *sample)
{
    uint32_t segments;
    uint32_t seg;
    char buf[51];

    sf_log("extendedType GATEWAY\n");

    if (sample->datagramVersion >= 5) {
        getAddress(sample, &sample->bgp_nextHop);
        sf_log("bgp_nexthop %s\n", printAddress(&sample->bgp_nextHop, buf, 50));
    }

    sample->my_as = getData32(sample);
    sample->src_as = getData32(sample);
    sample->src_peer_as = getData32(sample);
    sf_log("my_as %u\n", sample->my_as);
    sf_log("src_as %u\n", sample->src_as);
    sf_log("src_peer_as %u\n", sample->src_peer_as);
    segments = getData32(sample);

    // clear dst_peer_as and dst_as to make sure we are not
    // remembering values from a previous sample - (thanks Marc Lavine)
    sample->dst_peer_as = 0;
    sample->dst_as = 0;

    if (segments > 0) {
        sf_log("dst_as_path ");
        for (seg = 0; seg < segments; seg++) {
            uint32_t seg_type;
            uint32_t seg_len;
            uint32_t i;
            seg_type = getData32(sample);
            seg_len = getData32(sample);
            for (i = 0; i < seg_len; i++) {
                uint32_t asNumber;
                asNumber = getData32(sample);
                /* mark the first one as the dst_peer_as */
                if (i == 0 && seg == 0) {
                    sample->dst_peer_as = asNumber;
                } else {
                    sf_log("-");
                }
                /* make sure the AS sets are in parentheses */
                if (i == 0 && seg_type == SFLEXTENDED_AS_SET) {
                    sf_log("(");
                }
                sf_log("%u", asNumber);
                /* mark the last one as the dst_as */
                if (seg == (segments - 1) && i == (seg_len - 1)) {
                    sample->dst_as = asNumber;
                }
            }
            if (seg_type == SFLEXTENDED_AS_SET) {
                sf_log(")");
            }
        }
        sf_log("\n");
    }
    sf_log("dst_as %u\n", sample->dst_as);
    sf_log("dst_peer_as %u\n", sample->dst_peer_as);

    sample->communities_len = getData32(sample);
    /* just point at the communities array */
    if (sample->communities_len > 0) {
        sample->communities = sample->datap;
    }
    /* and skip over it in the input */
    skipBytes(sample, sample->communities_len * 4);

    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
    if (sample->communities_len > 0) {
        uint32_t j = 0;
        for (; j < sample->communities_len; j++) {
            if (j == 0) {
                sf_log("BGP_communities ");
            } else {
                sf_log("-");
            }
            sf_log("%u", ntohl(sample->communities[j]));
        }
        sf_log("\n");
    }

    sample->localpref = getData32(sample);
    sf_log("BGP_localpref %u\n", sample->localpref);

}

/*_________________---------------------------__________________
  _________________    readExtendedUser       __________________
  -----------------___________________________------------------
*/

static void readExtendedUser(SFSample *sample)
{
    sf_log("extendedType USER\n");

    if (sample->datagramVersion >= 5) {
        sample->src_user_charset = getData32(sample);
        sf_log("src_user_charset %d\n", sample->src_user_charset);
    }

    sample->src_user_len = getString(sample, sample->src_user, SA_MAX_EXTENDED_USER_LEN);

    if (sample->datagramVersion >= 5) {
        sample->dst_user_charset = getData32(sample);
        sf_log("dst_user_charset %d\n", sample->dst_user_charset);
    }

    sample->dst_user_len = getString(sample, sample->dst_user, SA_MAX_EXTENDED_USER_LEN);

    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_USER;

    sf_log("src_user %s\n", sample->src_user);
    sf_log("dst_user %s\n", sample->dst_user);
}

/*_________________---------------------------__________________
  _________________    readExtendedUrl        __________________
  -----------------___________________________------------------
*/

static void readExtendedUrl(SFSample *sample)
{
    sf_log("extendedType URL\n");

    sample->url_direction = getData32(sample);
    sf_log("url_direction %u\n", sample->url_direction);
    sample->url_len = getString(sample, sample->url, SA_MAX_EXTENDED_URL_LEN);
    sf_log("url %s\n", sample->url);
    if (sample->datagramVersion >= 5) {
        sample->host_len = getString(sample, sample->host, SA_MAX_EXTENDED_HOST_LEN);
        sf_log("host %s\n", sample->host);
    }
    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_URL;
}


/*_________________---------------------------__________________
  _________________       mplsLabelStack      __________________
  -----------------___________________________------------------
*/

static void mplsLabelStack(SFSample *sample, char *fieldName)
{
    SFLLabelStack lstk;
    uint32_t lab;
    lstk.depth = getData32(sample);
    /* just point at the lablelstack array */
    if (lstk.depth > 0) {
        lstk.stack = (uint32_t *)sample->datap;
    }
    /* and skip over it in the input */
    skipBytes(sample, lstk.depth * 4);

    if (lstk.depth > 0) {
        uint32_t j = 0;
        for (; j < lstk.depth; j++) {
            if (j == 0) {
                sf_log("%s ", fieldName);
            } else {
                sf_log("-");
            }
            lab = ntohl(lstk.stack[j]);
            sf_log("%u.%u.%u.%u",
                   (lab >> 12),     // label
                   (lab >> 9) & 7,  // experimental
                   (lab >> 8) & 1,  // bottom of stack
                   (lab &  255));   // TTL
        }
        sf_log("\n");
    }
}

/*_________________---------------------------__________________
  _________________    readExtendedMpls       __________________
  -----------------___________________________------------------
*/

static void readExtendedMpls(SFSample *sample)
{
    char buf[51];
    sf_log("extendedType MPLS\n");
    getAddress(sample, &sample->mpls_nextHop);
    sf_log("mpls_nexthop %s\n", printAddress(&sample->mpls_nextHop, buf, 50));

    mplsLabelStack(sample, "mpls_input_stack");
    mplsLabelStack(sample, "mpls_output_stack");

    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS;
}

/*_________________---------------------------__________________
  _________________    readExtendedNat        __________________
  -----------------___________________________------------------
*/

static void readExtendedNat(SFSample *sample)
{
    char buf[51];
    sf_log("extendedType NAT\n");
    getAddress(sample, &sample->nat_src);
    sf_log("nat_src %s\n", printAddress(&sample->nat_src, buf, 50));
    getAddress(sample, &sample->nat_dst);
    sf_log("nat_dst %s\n", printAddress(&sample->nat_dst, buf, 50));
    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_NAT;
}

/*_________________---------------------------__________________
  _________________    readExtendedNatPort    __________________
  -----------------___________________________------------------
*/

static void readExtendedNatPort(SFSample *sample)
{
    sf_log("extendedType NAT PORT\n");
    sf_log_next32(sample, "nat_src_port");
    sf_log_next32(sample, "nat_dst_port");
}


/*_________________---------------------------__________________
  _________________    readExtendedMplsTunnel __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsTunnel(SFSample *sample)
{
#define SA_MAX_TUNNELNAME_LEN 100
    char tunnel_name[SA_MAX_TUNNELNAME_LEN + 1];
    uint32_t tunnel_id, tunnel_cos;

    if (getString(sample, tunnel_name, SA_MAX_TUNNELNAME_LEN) > 0) {
        sf_log("mpls_tunnel_lsp_name %s\n", tunnel_name);
    }
    tunnel_id = getData32(sample);
    sf_log("mpls_tunnel_id %u\n", tunnel_id);
    tunnel_cos = getData32(sample);
    sf_log("mpls_tunnel_cos %u\n", tunnel_cos);
    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL;
}

/*_________________---------------------------__________________
  _________________    readExtendedMplsVC     __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsVC(SFSample *sample)
{
#define SA_MAX_VCNAME_LEN 100
    char vc_name[SA_MAX_VCNAME_LEN + 1];
    uint32_t vll_vc_id, vc_cos;
    if (getString(sample, vc_name, SA_MAX_VCNAME_LEN) > 0) {
        sf_log("mpls_vc_name %s\n", vc_name);
    }
    vll_vc_id = getData32(sample);
    sf_log("mpls_vll_vc_id %u\n", vll_vc_id);
    vc_cos = getData32(sample);
    sf_log("mpls_vc_cos %u\n", vc_cos);
    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_VC;
}

/*_________________---------------------------__________________
  _________________    readExtendedMplsFTN    __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsFTN(SFSample *sample)
{
#define SA_MAX_FTN_LEN 100
    char ftn_descr[SA_MAX_FTN_LEN + 1];
    uint32_t ftn_mask;
    if (getString(sample, ftn_descr, SA_MAX_FTN_LEN) > 0) {
        sf_log("mpls_ftn_descr %s\n", ftn_descr);
    }
    ftn_mask = getData32(sample);
    sf_log("mpls_ftn_mask %u\n", ftn_mask);
    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_FTN;
}

/*_________________---------------------------__________________
  _________________  readExtendedMplsLDP_FEC  __________________
  -----------------___________________________------------------
*/

static void readExtendedMplsLDP_FEC(SFSample *sample)
{
    uint32_t fec_addr_prefix_len = getData32(sample);
    sf_log("mpls_fec_addr_prefix_len %u\n", fec_addr_prefix_len);
    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC;
}

/*_________________---------------------------__________________
  _________________  readExtendedVlanTunnel   __________________
  -----------------___________________________------------------
*/

static void readExtendedVlanTunnel(SFSample *sample)
{
    uint32_t lab;
    SFLLabelStack lstk;
    lstk.depth = getData32(sample);
    /* just point at the lablelstack array */
    if (lstk.depth > 0) {
        lstk.stack = (uint32_t *)sample->datap;
    }
    /* and skip over it in the input */
    skipBytes(sample, lstk.depth * 4);

    if (lstk.depth > 0) {
        uint32_t j = 0;
        for (; j < lstk.depth; j++) {
            if (j == 0) {
                sf_log("vlan_tunnel ");
            } else {
                sf_log("-");
            }
            lab = ntohl(lstk.stack[j]);
            sf_log("0x%04x.%u.%u.%u",
                   (lab >> 16),       // TPI
                   (lab >> 13) & 7,   // priority
                   (lab >> 12) & 1,   // CFI
                   (lab & 4095));     // VLAN
        }
        sf_log("\n");
    }
    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL;
}

/*_________________---------------------------__________________
  _________________  readExtendedWifiPayload  __________________
  -----------------___________________________------------------
*/

static void readExtendedWifiPayload(SFSample *sample)
{
    sf_log_next32(sample, "cipher_suite");
    readFlowSample_header(sample);
}

/*_________________---------------------------__________________
  _________________  readExtendedWifiRx       __________________
  -----------------___________________________------------------
*/

static void readExtendedWifiRx(SFSample *sample)
{
    uint32_t i;
    u_char *bssid;
    char ssid[SFL_MAX_SSID_LEN + 1];
    if (getString(sample, ssid, SFL_MAX_SSID_LEN) > 0) {
        sf_log("rx_SSID %s\n", ssid);
    }

    bssid = (u_char *)sample->datap;
    sf_log("rx_BSSID ");
    for (i = 0; i < 6; i++) {
        sf_log("%02x", bssid[i]);
    }
    sf_log("\n");
    skipBytes(sample, 6);

    sf_log_next32(sample, "rx_version");
    sf_log_next32(sample, "rx_channel");
    sf_log_next64(sample, "rx_speed");
    sf_log_next32(sample, "rx_rsni");
    sf_log_next32(sample, "rx_rcpi");
    sf_log_next32(sample, "rx_packet_uS");
}

/*_________________---------------------------__________________
  _________________  readExtendedWifiTx       __________________
  -----------------___________________________------------------
*/

static void readExtendedWifiTx(SFSample *sample)
{
    uint32_t i;
    u_char *bssid;
    char ssid[SFL_MAX_SSID_LEN + 1];
    if (getString(sample, ssid, SFL_MAX_SSID_LEN) > 0) {
        sf_log("tx_SSID %s\n", ssid);
    }

    bssid = (u_char *)sample->datap;
    sf_log("tx_BSSID ");
    for (i = 0; i < 6; i++) {
        sf_log("%02x", bssid[i]);
    }
    sf_log("\n");
    skipBytes(sample, 6);

    sf_log_next32(sample, "tx_version");
    sf_log_next32(sample, "tx_transmissions");
    sf_log_next32(sample, "tx_packet_uS");
    sf_log_next32(sample, "tx_retrans_uS");
    sf_log_next32(sample, "tx_channel");
    sf_log_next64(sample, "tx_speed");
    sf_log_next32(sample, "tx_power_mW");
}

/*_________________---------------------------__________________
  _________________  readExtendedAggregation  __________________
  -----------------___________________________------------------
*/

static void readExtendedAggregation(SFSample *sample)
{
    uint32_t i, num_pdus = getData32(sample);
    sf_log("aggregation_num_pdus %u\n", num_pdus);
    for (i = 0; i < num_pdus; i++) {
        sf_log("aggregation_pdu %u\n", i);
        readFlowSample(sample, NO); // not sure if this the right one here $$$
    }
}

/*_________________---------------------------__________________
  _________________  readFlowSample_header    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_header(SFSample *sample)
{
    sf_log("flowSampleType HEADER\n");
    sample->headerProtocol = getData32(sample);
    sf_log("headerProtocol %u\n", sample->headerProtocol);
    sample->sampledPacketSize = getData32(sample);
    sf_log("sampledPacketSize %u\n", sample->sampledPacketSize);
    if (sample->datagramVersion > 4) {
        // stripped count introduced in sFlow version 5
        sample->stripped = getData32(sample);
        sf_log("strippedBytes %u\n", sample->stripped);
    }
    sample->headerLen = getData32(sample);
    sf_log("headerLen %u\n", sample->headerLen);

    sample->header = (u_char *)sample->datap; /* just point at the header */
    skipBytes(sample, sample->headerLen);
    {
        char scratch[2000];
        printHex(sample->header, sample->headerLen, (u_char *)scratch, 2000, 0, 2000);
        sf_log("headerBytes %s\n", scratch);
    }

    switch (sample->headerProtocol) {
            /* the header protocol tells us where to jump into the decode */
        case SFLHEADER_ETHERNET_ISO8023:
            decodeLinkLayer(sample);
            break;
        case SFLHEADER_IPv4:
            sample->gotIPV4 = YES;
            sample->offsetToIPV4 = 0;
            break;
        case SFLHEADER_IPv6:
            sample->gotIPV6 = YES;
            sample->offsetToIPV6 = 0;
            break;
        case SFLHEADER_IEEE80211MAC:
            decode80211MAC(sample);
            break;
        case SFLHEADER_ISO88024_TOKENBUS:
        case SFLHEADER_ISO88025_TOKENRING:
        case SFLHEADER_FDDI:
        case SFLHEADER_FRAME_RELAY:
        case SFLHEADER_X25:
        case SFLHEADER_PPP:
        case SFLHEADER_SMDS:
        case SFLHEADER_AAL5:
        case SFLHEADER_AAL5_IP:
        case SFLHEADER_MPLS:
        case SFLHEADER_POS:
        case SFLHEADER_IEEE80211_AMPDU:
        case SFLHEADER_IEEE80211_AMSDU_SUBFRAME:
            sf_log("NO_DECODE headerProtocol=%d\n", sample->headerProtocol);
            break;
        default:
            fprintf(ERROUT, "undefined headerProtocol = %d\n", sample->headerProtocol);
            custom_exit(-12);
    }

    if (sample->gotIPV4) {
        // report the size of the original IPPdu (including the IP header)
        sf_log("IPSize %d\n",  sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4);
        decodeIPV4(sample);
    } else if (sample->gotIPV6) {
        // report the size of the original IPPdu (including the IP header)
        sf_log("IPSize %d\n",  sample->sampledPacketSize - sample->stripped - sample->offsetToIPV6);
        decodeIPV6(sample);
    }

}

/*_________________---------------------------__________________
  _________________  readFlowSample_ethernet  __________________
  -----------------___________________________------------------
*/

static void readFlowSample_ethernet(SFSample *sample, char *prefix)
{
    u_char *p;
    sf_log("flowSampleType %sETHERNET\n", prefix);
    sample->eth_len = getData32(sample);
    memcpy(sample->eth_src, sample->datap, 6);
    skipBytes(sample, 6);
    memcpy(sample->eth_dst, sample->datap, 6);
    skipBytes(sample, 6);
    sample->eth_type = getData32(sample);
    sf_log("%sethernet_type %u\n", prefix, sample->eth_type);
    sf_log("%sethernet_len %u\n", prefix, sample->eth_len);
    p = sample->eth_src;
    sf_log("%sethernet_src %02x%02x%02x%02x%02x%02x\n", prefix, p[0], p[1], p[2], p[3], p[4], p[5]);
    p = sample->eth_dst;
    sf_log("%sethernet_dst %02x%02x%02x%02x%02x%02x\n", prefix, p[0], p[1], p[2], p[3], p[4], p[5]);
}


/*_________________---------------------------__________________
  _________________    readFlowSample_IPv4    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_IPv4(SFSample *sample, char *prefix)
{
    sf_log("flowSampleType %sIPV4\n", prefix);
    sample->headerLen = sizeof(SFLSampled_ipv4);
    sample->header = (u_char *)sample->datap; /* just point at the header */
    skipBytes(sample, sample->headerLen);
    {
        char buf[51];
        SFLSampled_ipv4 nfKey;
        memcpy(&nfKey, sample->header, sizeof(nfKey));
        sample->sampledPacketSize = ntohl(nfKey.length);
        sf_log("%ssampledPacketSize %u\n", prefix, sample->sampledPacketSize);
        sf_log("%sIPSize %u\n", prefix,  sample->sampledPacketSize);
        sample->ipsrc.type = SFLADDRESSTYPE_IP_V4;
        sample->ipsrc.address.ip_v4 = nfKey.src_ip;
        sample->ipdst.type = SFLADDRESSTYPE_IP_V4;
        sample->ipdst.address.ip_v4 = nfKey.dst_ip;
        sample->dcd_ipProtocol = ntohl(nfKey.protocol);
        sample->dcd_ipTos = ntohl(nfKey.tos);
        sf_log("%ssrcIP %s\n", prefix, printAddress(&sample->ipsrc, buf, 50));
        sf_log("%sdstIP %s\n", prefix, printAddress(&sample->ipdst, buf, 50));
        sf_log("%sIPProtocol %u\n", prefix, sample->dcd_ipProtocol);
        sf_log("%sIPTOS %u\n", prefix, sample->dcd_ipTos);
        sample->dcd_sport = ntohl(nfKey.src_port);
        sample->dcd_dport = ntohl(nfKey.dst_port);
        switch (sample->dcd_ipProtocol) {
            case 1: /* ICMP */
                sf_log("%sICMPType %u\n", prefix, sample->dcd_dport);
                /* not sure about the dest port being icmp type
                - might be that src port is icmp type and dest
                 port is icmp code.  Still, have seen some
                 implementations where src port is 0 and dst
                 port is the type, so it may be safer to
                 assume that the destination port has the type */
                break;
            case 6: /* TCP */
                sf_log("%sTCPSrcPort %u\n", prefix, sample->dcd_sport);
                sf_log("%sTCPDstPort %u\n", prefix, sample->dcd_dport);
                sample->dcd_tcpFlags = ntohl(nfKey.tcp_flags);
                sf_log("%sTCPFlags %u\n", prefix, sample->dcd_tcpFlags);
                break;
            case 17: /* UDP */
                sf_log("%sUDPSrcPort %u\n", prefix, sample->dcd_sport);
                sf_log("%sUDPDstPort %u\n", prefix, sample->dcd_dport);
                break;
            default: /* some other protcol */
                break;
        }
    }
}

/*_________________---------------------------__________________
  _________________    readFlowSample_IPv6    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_IPv6(SFSample *sample, char *prefix)
{
    sf_log("flowSampleType %sIPV6\n", prefix);
    sample->header = (u_char *)sample->datap; /* just point at the header */
    sample->headerLen = sizeof(SFLSampled_ipv6);
    skipBytes(sample, sample->headerLen);
    {
        char buf[51];
        SFLSampled_ipv6 nfKey6;
        memcpy(&nfKey6, sample->header, sizeof(nfKey6));
        sample->sampledPacketSize = ntohl(nfKey6.length);
        sf_log("%ssampledPacketSize %u\n", prefix, sample->sampledPacketSize);
        sf_log("%sIPSize %u\n", prefix, sample->sampledPacketSize);
        sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
        memcpy(&sample->ipsrc.address.ip_v6, &nfKey6.src_ip, 16);
        sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
        memcpy(&sample->ipdst.address.ip_v6, &nfKey6.dst_ip, 16);
        sample->dcd_ipProtocol = ntohl(nfKey6.protocol);
        sf_log("%ssrcIP6 %s\n", prefix, printAddress(&sample->ipsrc, buf, 50));
        sf_log("%sdstIP6 %s\n", prefix, printAddress(&sample->ipdst, buf, 50));
        sf_log("%sIPProtocol %u\n", prefix, sample->dcd_ipProtocol);
        sf_log("%spriority %u\n", prefix, ntohl(nfKey6.priority));
        sample->dcd_sport = ntohl(nfKey6.src_port);
        sample->dcd_dport = ntohl(nfKey6.dst_port);
        switch (sample->dcd_ipProtocol) {
            case 1: /* ICMP */
                sf_log("%sICMPType %u\n", prefix, sample->dcd_dport);
                /* not sure about the dest port being icmp type
                - might be that src port is icmp type and dest
                 port is icmp code.  Still, have seen some
                 implementations where src port is 0 and dst
                 port is the type, so it may be safer to
                 assume that the destination port has the type */
                break;
            case 6: /* TCP */
                sf_log("%sTCPSrcPort %u\n", prefix, sample->dcd_sport);
                sf_log("%sTCPDstPort %u\n", prefix, sample->dcd_dport);
                sample->dcd_tcpFlags = ntohl(nfKey6.tcp_flags);
                sf_log("%sTCPFlags %u\n", prefix, sample->dcd_tcpFlags);
                break;
            case 17: /* UDP */
                sf_log("%sUDPSrcPort %u\n", prefix, sample->dcd_sport);
                sf_log("%sUDPDstPort %u\n", prefix, sample->dcd_dport);
                break;
            default: /* some other protcol */
                break;
        }
    }
}

/*_________________----------------------------__________________
  _________________  readFlowSample_memcache   __________________
  -----------------____________________________------------------
*/

static void readFlowSample_memcache(SFSample *sample)
{
    char key[SFL_MAX_MEMCACHE_KEY + 1];
#define ENC_KEY_BYTES (SFL_MAX_MEMCACHE_KEY * 3) + 1
    char enc_key[ENC_KEY_BYTES];
    sf_log("flowSampleType memcache\n");
    sf_log_next32(sample, "memcache_op_protocol");
    sf_log_next32(sample, "memcache_op_cmd");
    if (getString(sample, key, SFL_MAX_MEMCACHE_KEY) > 0) {
        sf_log("memcache_op_key %s\n", URLEncode(key, enc_key, ENC_KEY_BYTES));
    }
    sf_log_next32(sample, "memcache_op_nkeys");
    sf_log_next32(sample, "memcache_op_value_bytes");
    sf_log_next32(sample, "memcache_op_duration_uS");
    sf_log_next32(sample, "memcache_op_status");
}

/*_________________----------------------------__________________
  _________________  readFlowSample_http       __________________
  -----------------____________________________------------------
*/

static void readFlowSample_http(SFSample *sample, uint32_t tag)
{
    char uri[SFL_MAX_HTTP_URI + 1];
    char host[SFL_MAX_HTTP_HOST + 1];
    char referrer[SFL_MAX_HTTP_REFERRER + 1];
    char useragent[SFL_MAX_HTTP_USERAGENT + 1];
    char xff[SFL_MAX_HTTP_XFF + 1];
    char authuser[SFL_MAX_HTTP_AUTHUSER + 1];
    char mimetype[SFL_MAX_HTTP_MIMETYPE + 1];
    uint32_t method;
    uint32_t protocol;
    uint32_t status;
    uint64_t req_bytes;
    uint64_t resp_bytes;

    sf_log("flowSampleType http\n");
    method = sf_log_next32(sample, "http_method");
    protocol = sf_log_next32(sample, "http_protocol");
    if (getString(sample, uri, SFL_MAX_HTTP_URI) > 0) {
        sf_log("http_uri %s\n", uri);
    }
    if (getString(sample, host, SFL_MAX_HTTP_HOST) > 0) {
        sf_log("http_host %s\n", host);
    }
    if (getString(sample, referrer, SFL_MAX_HTTP_REFERRER) > 0) {
        sf_log("http_referrer %s\n", referrer);
    }
    if (getString(sample, useragent, SFL_MAX_HTTP_USERAGENT) > 0) {
        sf_log("http_useragent %s\n", useragent);
    }
    if (tag == SFLFLOW_HTTP2) {
        if (getString(sample, xff, SFL_MAX_HTTP_XFF) > 0) {
            sf_log("http_xff %s\n", xff);
        }
    }
    if (getString(sample, authuser, SFL_MAX_HTTP_AUTHUSER) > 0) {
        sf_log("http_authuser %s\n", authuser);
    }
    if (getString(sample, mimetype, SFL_MAX_HTTP_MIMETYPE) > 0) {
        sf_log("http_mimetype %s\n", mimetype);
    }
    if (tag == SFLFLOW_HTTP2) {
        req_bytes = sf_log_next64(sample, "http_request_bytes");
    }
    resp_bytes = sf_log_next64(sample, "http_bytes");
    sf_log_next32(sample, "http_duration_uS");
    status = sf_log_next32(sample, "http_status");

    if (sfConfig.outputFormat == SFLFMT_CLF) {
        time_t now = time(NULL);
        char nowstr[200];
        strftime(nowstr, 200, "%d/%b/%Y:%H:%M:%S %z", localtime(&now));
        snprintf(sfCLF.http_log, SFLFMT_CLF_MAX_LINE, "- %s [%s] \"%s %s HTTP/%u.%u\" %u %"PRIu64" \"%s\" \"%s\"",
                 authuser[0] ? authuser : "-",
                 nowstr,
                 SFHTTP_method_names[method],
                 uri[0] ? uri : "-",
                 protocol / 1000,
                 protocol % 1000,
                 status,
                 resp_bytes,
                 referrer[0] ? referrer : "-",
                 useragent[0] ? useragent : "-");
        sfCLF.valid = YES;
    }
}

/*_________________----------------------------__________________
  _________________  readFlowSample_APP        __________________
  -----------------____________________________------------------
*/

static void readFlowSample_APP(SFSample *sample)
{
    char application[SFLAPP_MAX_APPLICATION_LEN];
    char operation[SFLAPP_MAX_OPERATION_LEN];
    char attributes[SFLAPP_MAX_ATTRIBUTES_LEN];
    char status[SFLAPP_MAX_STATUS_LEN];

    sf_log("flowSampleType applicationOperation\n");

    if (getString(sample, application, SFLAPP_MAX_APPLICATION_LEN) > 0) {
        sf_log("application %s\n", application);
    }
    if (getString(sample, operation, SFLAPP_MAX_OPERATION_LEN) > 0) {
        sf_log("operation %s\n", operation);
    }
    if (getString(sample, attributes, SFLAPP_MAX_ATTRIBUTES_LEN) > 0) {
        sf_log("attributes %s\n", attributes);
    }
    if (getString(sample, status, SFLAPP_MAX_STATUS_LEN) > 0) {
        sf_log("status_descr %s\n", status);
    }
    sf_log_next64(sample, "request_bytes");
    sf_log_next64(sample, "response_bytes");
    sf_log("status %s\n", SFL_APP_STATUS_names[getData32(sample)]);
    sf_log_next32(sample, "duration_uS");
}


/*_________________----------------------------__________________
  _________________  readFlowSample_APP_CTXT   __________________
  -----------------____________________________------------------
*/

static void readFlowSample_APP_CTXT(SFSample *sample)
{
    char application[SFLAPP_MAX_APPLICATION_LEN];
    char operation[SFLAPP_MAX_OPERATION_LEN];
    char attributes[SFLAPP_MAX_ATTRIBUTES_LEN];
    if (getString(sample, application, SFLAPP_MAX_APPLICATION_LEN) > 0) {
        sf_log("server_context_application %s\n", application);
    }
    if (getString(sample, operation, SFLAPP_MAX_OPERATION_LEN) > 0) {
        sf_log("server_context_operation %s\n", operation);
    }
    if (getString(sample, attributes, SFLAPP_MAX_ATTRIBUTES_LEN) > 0) {
        sf_log("server_context_attributes %s\n", attributes);
    }
}

/*_________________---------------------------------__________________
  _________________  readFlowSample_APP_ACTOR_INIT  __________________
  -----------------_________________________________------------------
*/

static void readFlowSample_APP_ACTOR_INIT(SFSample *sample)
{
    char actor[SFLAPP_MAX_ACTOR_LEN];
    if (getString(sample, actor, SFLAPP_MAX_ACTOR_LEN) > 0) {
        sf_log("actor_initiator %s\n", actor);
    }
}

/*_________________---------------------------------__________________
  _________________  readFlowSample_APP_ACTOR_TGT   __________________
  -----------------_________________________________------------------
*/

static void readFlowSample_APP_ACTOR_TGT(SFSample *sample)
{
    char actor[SFLAPP_MAX_ACTOR_LEN];
    if (getString(sample, actor, SFLAPP_MAX_ACTOR_LEN) > 0) {
        sf_log("actor_target %s\n", actor);
    }
}

/*_________________----------------------------__________________
  _________________   readExtendedSocket4      __________________
  -----------------____________________________------------------
*/

static void readExtendedSocket4(SFSample *sample)
{
    char buf[51];
    sf_log("extendedType socket4\n");
    sf_log_next32(sample, "socket4_ip_protocol");
    sample->ipsrc.type = SFLADDRESSTYPE_IP_V4;
    sample->ipsrc.address.ip_v4.addr = getData32_nobswap(sample);
    sample->ipdst.type = SFLADDRESSTYPE_IP_V4;
    sample->ipdst.address.ip_v4.addr = getData32_nobswap(sample);
    sf_log("socket4_local_ip %s\n", printAddress(&sample->ipsrc, buf, 50));
    sf_log("socket4_remote_ip %s\n", printAddress(&sample->ipdst, buf, 50));
    sf_log_next32(sample, "socket4_local_port");
    sf_log_next32(sample, "socket4_remote_port");

    if (sfConfig.outputFormat == SFLFMT_CLF) {
        memcpy(sfCLF.client, buf, 50);
        sfCLF.client[50] = '\0';
    }

}

/*_________________----------------------------__________________
  _________________ readExtendedProxySocket4   __________________
  -----------------____________________________------------------
*/

static void readExtendedProxySocket4(SFSample *sample)
{
    char buf[51];
    SFLAddress ipsrc, ipdst;
    sf_log("extendedType proxy_socket4\n");
    sf_log_next32(sample, "proxy_socket4_ip_protocol");
    ipsrc.type = SFLADDRESSTYPE_IP_V4;
    ipsrc.address.ip_v4.addr = getData32_nobswap(sample);
    ipdst.type = SFLADDRESSTYPE_IP_V4;
    ipdst.address.ip_v4.addr = getData32_nobswap(sample);
    sf_log("proxy_socket4_local_ip %s\n", printAddress(&ipsrc, buf, 50));
    sf_log("proxy_socket4_remote_ip %s\n", printAddress(&ipdst, buf, 50));
    sf_log_next32(sample, "proxy_socket4_local_port");
    sf_log_next32(sample, "proxy_socket4_remote_port");
}

/*_________________----------------------------__________________
  _________________  readExtendedSocket6       __________________
  -----------------____________________________------------------
*/

static void readExtendedSocket6(SFSample *sample)
{
    char buf[51];
    sf_log("extendedType socket6\n");
    sf_log_next32(sample, "socket6_ip_protocol");
    sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&sample->ipsrc.address.ip_v6, sample->datap, 16);
    skipBytes(sample, 16);
    sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&sample->ipdst.address.ip_v6, sample->datap, 16);
    skipBytes(sample, 16);
    sf_log("socket6_local_ip %s\n", printAddress(&sample->ipsrc, buf, 50));
    sf_log("socket6_remote_ip %s\n", printAddress(&sample->ipdst, buf, 50));
    sf_log_next32(sample, "socket6_local_port");
    sf_log_next32(sample, "socket6_remote_port");

    if (sfConfig.outputFormat == SFLFMT_CLF) {
        memcpy(sfCLF.client, buf, 51);
        sfCLF.client[50] = '\0';
    }
}

/*_________________----------------------------__________________
  _________________ readExtendedProxySocket6   __________________
  -----------------____________________________------------------
*/

static void readExtendedProxySocket6(SFSample *sample)
{
    char buf[51];
    SFLAddress ipsrc, ipdst;
    sf_log("extendedType proxy_socket6\n");
    sf_log_next32(sample, "proxy_socket6_ip_protocol");
    ipsrc.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&ipsrc.address.ip_v6, sample->datap, 16);
    skipBytes(sample, 16);
    ipdst.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&ipdst.address.ip_v6, sample->datap, 16);
    skipBytes(sample, 16);
    sf_log("proxy_socket6_local_ip %s\n", printAddress(&ipsrc, buf, 50));
    sf_log("proxy_socket6_remote_ip %s\n", printAddress(&ipdst, buf, 50));
    sf_log_next32(sample, "proxy_socket6_local_port");
    sf_log_next32(sample, "proxy_socket6_remote_port");
}

/*_________________----------------------------__________________
  _________________    readExtendedDecap       __________________
  -----------------____________________________------------------
*/

static void readExtendedDecap(SFSample *sample, char *prefix)
{
    uint32_t offset = getData32(sample);
    sf_log("extendedType %sdecap\n", prefix);
    sf_log("%sdecap_inner_header_offset %u\n", prefix, offset);
}

/*_________________----------------------------__________________
  _________________    readExtendedVNI         __________________
  -----------------____________________________------------------
*/

static void readExtendedVNI(SFSample *sample, char *prefix)
{
    uint32_t vni = getData32(sample);
    sf_log("extendedType %sVNI\n", prefix);
    sf_log("%sVNI %u\n", prefix, vni);
}

/*_________________---------------------------__________________
  _________________    readFlowSample_v2v4    __________________
  -----------------___________________________------------------
*/

static void readFlowSample_v2v4(SFSample *sample)
{
    sf_log("sampleType FLOWSAMPLE\n");

    sample->samplesGenerated = getData32(sample);
    sf_log("sampleSequenceNo %u\n", sample->samplesGenerated);
    {
        uint32_t samplerId = getData32(sample);
        sample->ds_class = samplerId >> 24;
        sample->ds_index = samplerId & 0x00ffffff;
        sf_log("sourceId %u:%u\n", sample->ds_class, sample->ds_index);
    }

    sample->meanSkipCount = getData32(sample);
    sample->samplePool = getData32(sample);
    sample->dropEvents = getData32(sample);
    sample->inputPort = getData32(sample);
    sample->outputPort = getData32(sample);
    sf_log("meanSkipCount %u\n", sample->meanSkipCount);
    sf_log("samplePool %u\n", sample->samplePool);
    sf_log("dropEvents %u\n", sample->dropEvents);
    sf_log("inputPort %u\n", sample->inputPort);
    if (sample->outputPort & 0x80000000) {
        uint32_t numOutputs = sample->outputPort & 0x7fffffff;
        if (numOutputs > 0) {
            sf_log("outputPort multiple %d\n", numOutputs);
        } else {
            sf_log("outputPort multiple >1\n");
        }
    } else {
        sf_log("outputPort %u\n", sample->outputPort);
    }

    sample->packet_data_tag = getData32(sample);

    switch (sample->packet_data_tag) {

        case INMPACKETTYPE_HEADER:
            readFlowSample_header(sample);
            break;
        case INMPACKETTYPE_IPV4:
            sample->gotIPV4Struct = YES;
            readFlowSample_IPv4(sample, "");
            break;
        case INMPACKETTYPE_IPV6:
            sample->gotIPV6Struct = YES;
            readFlowSample_IPv6(sample, "");
            break;
        default:
            receiveError(sample, "unexpected packet_data_tag", YES);
            break;
    }

    sample->extended_data_tag = 0;
    {
        uint32_t x;
        sample->num_extended = getData32(sample);
        for (x = 0; x < sample->num_extended; x++) {
            uint32_t extended_tag;
            extended_tag = getData32(sample);
            switch (extended_tag) {
                case INMEXTENDED_SWITCH:
                    readExtendedSwitch(sample);
                    break;
                case INMEXTENDED_ROUTER:
                    readExtendedRouter(sample);
                    break;
                case INMEXTENDED_GATEWAY:
                    if (sample->datagramVersion == 2) {
                        readExtendedGateway_v2(sample);
                    } else {
                        readExtendedGateway(sample);
                    }
                    break;
                case INMEXTENDED_USER:
                    readExtendedUser(sample);
                    break;
                case INMEXTENDED_URL:
                    readExtendedUrl(sample);
                    break;
                default:
                    receiveError(sample, "unrecognized extended data tag", YES);
                    break;
            }
        }
    }

    if (sampleFilterOK(sample)) {
        switch (sfConfig.outputFormat) {
            case SFLFMT_NETFLOW:
                /* if we are exporting netflow and we have an IPv4 layer, compose the datagram now */
                if (sfConfig.netFlowOutputSocket && (sample->gotIPV4 || sample->gotIPV4Struct)) {
                    sendNetFlowDatagram(sample);
                }
                break;
            case SFLFMT_PCAP:
                /* if we are writing tcpdump format, write the next packet record now */
                writePcapPacket(sample);
                break;
            case SFLFMT_LINE:
                /* or line-by-line output... */
                writeFlowLine(sample);
                break;
            case SFLFMT_CLF:
            case SFLFMT_FULL:
            default:
                /* if it was full-detail output then it was done as we went along */
                break;
        }
    }
}

/*_________________---------------------------__________________
  _________________    readFlowSample         __________________
  -----------------___________________________------------------
*/

static void readFlowSample(SFSample *sample, int expanded)
{
    uint32_t num_elements, sampleLength;
    u_char *sampleStart;

    sf_log("sampleType FLOWSAMPLE\n");
    sampleLength = getData32(sample);
    sampleStart = (u_char *)sample->datap;
    sample->samplesGenerated = getData32(sample);
    sf_log("sampleSequenceNo %u\n", sample->samplesGenerated);
    if (expanded) {
        sample->ds_class = getData32(sample);
        sample->ds_index = getData32(sample);
    } else {
        uint32_t samplerId = getData32(sample);
        sample->ds_class = samplerId >> 24;
        sample->ds_index = samplerId & 0x00ffffff;
    }
    sf_log("sourceId %u:%u\n", sample->ds_class, sample->ds_index);

    sample->meanSkipCount = getData32(sample);
    sample->samplePool = getData32(sample);
    sample->dropEvents = getData32(sample);
    sf_log("meanSkipCount %u\n", sample->meanSkipCount);
    sf_log("samplePool %u\n", sample->samplePool);
    sf_log("dropEvents %u\n", sample->dropEvents);
    if (expanded) {
        sample->inputPortFormat = getData32(sample);
        sample->inputPort = getData32(sample);
        sample->outputPortFormat = getData32(sample);
        sample->outputPort = getData32(sample);
    } else {
        uint32_t inp, outp;
        inp = getData32(sample);
        outp = getData32(sample);
        sample->inputPortFormat = inp >> 30;
        sample->outputPortFormat = outp >> 30;
        sample->inputPort = inp & 0x3fffffff;
        sample->outputPort = outp & 0x3fffffff;
    }

    switch (sample->inputPortFormat) {
        case 3:
            sf_log("inputPort format==3 %u\n", sample->inputPort);
            break;
        case 2:
            sf_log("inputPort multiple %u\n", sample->inputPort);
            break;
        case 1:
            sf_log("inputPort dropCode %u\n", sample->inputPort);
            break;
        case 0:
            sf_log("inputPort %u\n", sample->inputPort);
            break;
    }

    switch (sample->outputPortFormat) {
        case 3:
            sf_log("outputPort format==3 %u\n", sample->outputPort);
            break;
        case 2:
            sf_log("outputPort multiple %u\n", sample->outputPort);
            break;
        case 1:
            sf_log("outputPort dropCode %u\n", sample->outputPort);
            break;
        case 0:
            sf_log("outputPort %u\n", sample->outputPort);
            break;
    }

    // clear the CLF record
    sfCLF.valid = NO;
    sfCLF.client[0] = '\0';

    num_elements = getData32(sample);
    {
        uint32_t el;
        for (el = 0; el < num_elements; el++) {
            uint32_t tag, length;
            u_char *start;
            char buf[51];
            tag = getData32(sample);
            sf_log("flowBlock_tag %s\n", printTag(tag, buf, 50));
            length = getData32(sample);
            start = (u_char *)sample->datap;

            switch (tag) {
                case SFLFLOW_HEADER:
                    readFlowSample_header(sample);
                    break;
                case SFLFLOW_ETHERNET:
                    readFlowSample_ethernet(sample, "");
                    break;
                case SFLFLOW_IPV4:
                    readFlowSample_IPv4(sample, "");
                    break;
                case SFLFLOW_IPV6:
                    readFlowSample_IPv6(sample, "");
                    break;
                case SFLFLOW_MEMCACHE:
                    readFlowSample_memcache(sample);
                    break;
                case SFLFLOW_HTTP:
                    readFlowSample_http(sample, tag);
                    break;
                case SFLFLOW_HTTP2:
                    readFlowSample_http(sample, tag);
                    break;
                case SFLFLOW_APP:
                    readFlowSample_APP(sample);
                    break;
                case SFLFLOW_APP_CTXT:
                    readFlowSample_APP_CTXT(sample);
                    break;
                case SFLFLOW_APP_ACTOR_INIT:
                    readFlowSample_APP_ACTOR_INIT(sample);
                    break;
                case SFLFLOW_APP_ACTOR_TGT:
                    readFlowSample_APP_ACTOR_TGT(sample);
                    break;
                case SFLFLOW_EX_SWITCH:
                    readExtendedSwitch(sample);
                    break;
                case SFLFLOW_EX_ROUTER:
                    readExtendedRouter(sample);
                    break;
                case SFLFLOW_EX_GATEWAY:
                    readExtendedGateway(sample);
                    break;
                case SFLFLOW_EX_USER:
                    readExtendedUser(sample);
                    break;
                case SFLFLOW_EX_URL:
                    readExtendedUrl(sample);
                    break;
                case SFLFLOW_EX_MPLS:
                    readExtendedMpls(sample);
                    break;
                case SFLFLOW_EX_NAT:
                    readExtendedNat(sample);
                    break;
                case SFLFLOW_EX_NAT_PORT:
                    readExtendedNatPort(sample);
                    break;
                case SFLFLOW_EX_MPLS_TUNNEL:
                    readExtendedMplsTunnel(sample);
                    break;
                case SFLFLOW_EX_MPLS_VC:
                    readExtendedMplsVC(sample);
                    break;
                case SFLFLOW_EX_MPLS_FTN:
                    readExtendedMplsFTN(sample);
                    break;
                case SFLFLOW_EX_MPLS_LDP_FEC:
                    readExtendedMplsLDP_FEC(sample);
                    break;
                case SFLFLOW_EX_VLAN_TUNNEL:
                    readExtendedVlanTunnel(sample);
                    break;
                case SFLFLOW_EX_80211_PAYLOAD:
                    readExtendedWifiPayload(sample);
                    break;
                case SFLFLOW_EX_80211_RX:
                    readExtendedWifiRx(sample);
                    break;
                case SFLFLOW_EX_80211_TX:
                    readExtendedWifiTx(sample);
                    break;
                    /* case SFLFLOW_EX_AGGREGATION: readExtendedAggregation(sample); break; */
                case SFLFLOW_EX_SOCKET4:
                    readExtendedSocket4(sample);
                    break;
                case SFLFLOW_EX_SOCKET6:
                    readExtendedSocket6(sample);
                    break;
                case SFLFLOW_EX_PROXYSOCKET4:
                    readExtendedProxySocket4(sample);
                    break;
                case SFLFLOW_EX_PROXYSOCKET6:
                    readExtendedProxySocket6(sample);
                    break;
                case SFLFLOW_EX_L2_TUNNEL_OUT:
                    readFlowSample_ethernet(sample, "tunnel_l2_out_");
                    break;
                case SFLFLOW_EX_L2_TUNNEL_IN:
                    readFlowSample_ethernet(sample, "tunnel_l2_in_");
                    break;
                case SFLFLOW_EX_IPV4_TUNNEL_OUT:
                    readFlowSample_IPv4(sample, "tunnel_ipv4_out_");
                    break;
                case SFLFLOW_EX_IPV4_TUNNEL_IN:
                    readFlowSample_IPv4(sample, "tunnel_ipv4_in_");
                    break;
                case SFLFLOW_EX_IPV6_TUNNEL_OUT:
                    readFlowSample_IPv6(sample, "tunnel_ipv6_out_");
                    break;
                case SFLFLOW_EX_IPV6_TUNNEL_IN:
                    readFlowSample_IPv6(sample, "tunnel_ipv6_in_");
                    break;
                case SFLFLOW_EX_DECAP_OUT:
                    readExtendedDecap(sample, "out_");
                    break;
                case SFLFLOW_EX_DECAP_IN:
                    readExtendedDecap(sample, "in_");
                    break;
                case SFLFLOW_EX_VNI_OUT:
                    readExtendedVNI(sample, "out_");
                    break;
                case SFLFLOW_EX_VNI_IN:
                    readExtendedVNI(sample, "in_");
                    break;
                default:
                    skipTLVRecord(sample, tag, length, "flow_sample_element");
                    break;
            }
            lengthCheck(sample, "flow_sample_element", start, length);
        }
    }
    lengthCheck(sample, "flow_sample", sampleStart, sampleLength);

    if (sampleFilterOK(sample)) {
        switch (sfConfig.outputFormat) {
            case SFLFMT_NETFLOW:
                /* if we are exporting netflow and we have an IPv4 layer, compose the datagram now */
                if (sfConfig.netFlowOutputSocket && sample->gotIPV4) {
                    sendNetFlowDatagram(sample);
                }
                break;
            case SFLFMT_PCAP:
                /* if we are writing tcpdump format, write the next packet record now */
                writePcapPacket(sample);
                break;
            case SFLFMT_LINE:
                /* or line-by-line output... */
                writeFlowLine(sample);
                break;
            case SFLFMT_CLF:
                if (sfCLF.valid) {
                    if (printf("%s %s\n", sfCLF.client, sfCLF.http_log) < 0) {
                        custom_exit(-48);
                    }
                }
                break;
            case SFLFMT_FULL:
            default:
                /* if it was full-detail output then it was done as we went along */
                break;
        }
    }
}

uint64_t ntohll(uint64_t val) {
    return (((uint64_t) ntohl(val)) << 32) + ntohl(val >> 32);
}

static void readCounters_a10_generic(SFSample *sample)
{
	printf("\n<<Inside readCounters_a10_generic>>>\n");
        int len = 0;
        long tstamp = time(NULL);
        char tbuf [200];
        sprintf (tbuf, "agent=%08x\n", htonl(sample->agent_addr.address.ip_v4.addr));
        tbuf[strlen(tbuf)] = 0;
        struct sfl_a10_custom_info *a10_custom = (struct sfl_a10_custom_info *)(sample->datap);
        sample->datap =  (u_char *)sample->datap + sizeof(struct sfl_a10_custom_info);
        printf("uuid = %s\n", a10_custom->uuid);
        int obj_stats_oid = ntohl(a10_custom->schema_oid);
        printf("obj_stats_oid = %d \n", obj_stats_oid);
        printf("schema oid = %d\n", obj_stats_oid);
        printf("vnp_id of ctr = %d\n", ntohl(a10_custom->vnp_id));
        sample->current_context_length = sample->current_context_length-sizeof(struct sfl_a10_custom_info);
        int number_of_counters =  sample->current_context_length/sizeof(struct sflow_flex_kv);
        printf("Number of counters = %d\n", number_of_counters);
        struct sflow_flex_kv *kv = (struct sflow_flex_kv *)(sample->datap);
        int i;

        for(i = 0; i<number_of_counters; i++){
       //     	len += sprintf(tsdb_buff + len, "put %s.%lu %lu %lu %s", a10_custom->uuid, ntohl(kv[i].key), tstamp, ntohll(kv[i].value), tbuf);
		 if (strlen(a10_custom->uuid) != 36){
			continue;
		 }
       		 //printf( "put %s.%lu %lu %lu %s", a10_custom->uuid, ntohl(kv[i].key), tstamp, ntohll(kv[i].value), tbuf); 
       }
       // int ret = opentsdb_simple_connect(tsdb_buff);
        skipBytes(sample, sample->current_context_length);
}


/*_________________---------------------------__________________
  _________________  readCounters_generic     __________________
  -----------------___________________________------------------
*/

static void readCounters_generic(SFSample *sample)
{
    /* the first part of the generic counters block is really just more info about the interface. */
    sample->ifCounters.ifIndex = sf_log_next32(sample, "ifIndex");
    sample->ifCounters.ifType = sf_log_next32(sample, "networkType");
    sample->ifCounters.ifSpeed = sf_log_next64(sample, "ifSpeed");
    sample->ifCounters.ifDirection = sf_log_next32(sample, "ifDirection");
    sample->ifCounters.ifStatus = sf_log_next32(sample, "ifStatus");
    /* the generic counters always come first */
    sample->ifCounters.ifInOctets = sf_log_next64(sample, "ifInOctets");
    sample->ifCounters.ifInUcastPkts = sf_log_next32(sample, "ifInUcastPkts");
    sample->ifCounters.ifInMulticastPkts = sf_log_next32(sample, "ifInMulticastPkts");
    sample->ifCounters.ifInBroadcastPkts = sf_log_next32(sample, "ifInBroadcastPkts");
    sample->ifCounters.ifInDiscards = sf_log_next32(sample, "ifInDiscards");
    sample->ifCounters.ifInErrors = sf_log_next32(sample, "ifInErrors");
    sample->ifCounters.ifInUnknownProtos = sf_log_next32(sample, "ifInUnknownProtos");
    sample->ifCounters.ifOutOctets = sf_log_next64(sample, "ifOutOctets");
    sample->ifCounters.ifOutUcastPkts = sf_log_next32(sample, "ifOutUcastPkts");
    sample->ifCounters.ifOutMulticastPkts = sf_log_next32(sample, "ifOutMulticastPkts");
    sample->ifCounters.ifOutBroadcastPkts = sf_log_next32(sample, "ifOutBroadcastPkts");
    sample->ifCounters.ifOutDiscards = sf_log_next32(sample, "ifOutDiscards");
    sample->ifCounters.ifOutErrors = sf_log_next32(sample, "ifOutErrors");
    sample->ifCounters.ifPromiscuousMode = sf_log_next32(sample, "ifPromiscuousMode");
}

/*_________________---------------------------__________________
  _________________  readCounters_ethernet    __________________
  -----------------___________________________------------------
*/

static  void readCounters_ethernet(SFSample *sample)
{
    sf_log_next32(sample, "dot3StatsAlignmentErrors");
    sf_log_next32(sample, "dot3StatsFCSErrors");
    sf_log_next32(sample, "dot3StatsSingleCollisionFrames");
    sf_log_next32(sample, "dot3StatsMultipleCollisionFrames");
    sf_log_next32(sample, "dot3StatsSQETestErrors");
    sf_log_next32(sample, "dot3StatsDeferredTransmissions");
    sf_log_next32(sample, "dot3StatsLateCollisions");
    sf_log_next32(sample, "dot3StatsExcessiveCollisions");
    sf_log_next32(sample, "dot3StatsInternalMacTransmitErrors");
    sf_log_next32(sample, "dot3StatsCarrierSenseErrors");
    sf_log_next32(sample, "dot3StatsFrameTooLongs");
    sf_log_next32(sample, "dot3StatsInternalMacReceiveErrors");
    sf_log_next32(sample, "dot3StatsSymbolErrors");
}


/*_________________---------------------------__________________
  _________________  readCounters_tokenring   __________________
  -----------------___________________________------------------
*/

static void readCounters_tokenring(SFSample *sample)
{
    sf_log_next32(sample, "dot5StatsLineErrors");
    sf_log_next32(sample, "dot5StatsBurstErrors");
    sf_log_next32(sample, "dot5StatsACErrors");
    sf_log_next32(sample, "dot5StatsAbortTransErrors");
    sf_log_next32(sample, "dot5StatsInternalErrors");
    sf_log_next32(sample, "dot5StatsLostFrameErrors");
    sf_log_next32(sample, "dot5StatsReceiveCongestions");
    sf_log_next32(sample, "dot5StatsFrameCopiedErrors");
    sf_log_next32(sample, "dot5StatsTokenErrors");
    sf_log_next32(sample, "dot5StatsSoftErrors");
    sf_log_next32(sample, "dot5StatsHardErrors");
    sf_log_next32(sample, "dot5StatsSignalLoss");
    sf_log_next32(sample, "dot5StatsTransmitBeacons");
    sf_log_next32(sample, "dot5StatsRecoverys");
    sf_log_next32(sample, "dot5StatsLobeWires");
    sf_log_next32(sample, "dot5StatsRemoves");
    sf_log_next32(sample, "dot5StatsSingles");
    sf_log_next32(sample, "dot5StatsFreqErrors");
}


/*_________________---------------------------__________________
  _________________  readCounters_vg          __________________
  -----------------___________________________------------------
*/

static void readCounters_vg(SFSample *sample)
{
    sf_log_next32(sample, "dot12InHighPriorityFrames");
    sf_log_next64(sample, "dot12InHighPriorityOctets");
    sf_log_next32(sample, "dot12InNormPriorityFrames");
    sf_log_next64(sample, "dot12InNormPriorityOctets");
    sf_log_next32(sample, "dot12InIPMErrors");
    sf_log_next32(sample, "dot12InOversizeFrameErrors");
    sf_log_next32(sample, "dot12InDataErrors");
    sf_log_next32(sample, "dot12InNullAddressedFrames");
    sf_log_next32(sample, "dot12OutHighPriorityFrames");
    sf_log_next64(sample, "dot12OutHighPriorityOctets");
    sf_log_next32(sample, "dot12TransitionIntoTrainings");
    sf_log_next64(sample, "dot12HCInHighPriorityOctets");
    sf_log_next64(sample, "dot12HCInNormPriorityOctets");
    sf_log_next64(sample, "dot12HCOutHighPriorityOctets");
}



/*_________________---------------------------__________________
  _________________  readCounters_vlan        __________________
  -----------------___________________________------------------
*/

static void readCounters_vlan(SFSample *sample)
{
    sample->in_vlan = getData32(sample);
    sf_log("in_vlan %u\n", sample->in_vlan);
    sf_log_next64(sample, "octets");
    sf_log_next32(sample, "ucastPkts");
    sf_log_next32(sample, "multicastPkts");
    sf_log_next32(sample, "broadcastPkts");
    sf_log_next32(sample, "discards");
}

/*_________________---------------------------__________________
  _________________  readCounters_80211       __________________
  -----------------___________________________------------------
*/

static void readCounters_80211(SFSample *sample)
{
    sf_log_next32(sample, "dot11TransmittedFragmentCount");
    sf_log_next32(sample, "dot11MulticastTransmittedFrameCount");
    sf_log_next32(sample, "dot11FailedCount");
    sf_log_next32(sample, "dot11RetryCount");
    sf_log_next32(sample, "dot11MultipleRetryCount");
    sf_log_next32(sample, "dot11FrameDuplicateCount");
    sf_log_next32(sample, "dot11RTSSuccessCount");
    sf_log_next32(sample, "dot11RTSFailureCount");
    sf_log_next32(sample, "dot11ACKFailureCount");
    sf_log_next32(sample, "dot11ReceivedFragmentCount");
    sf_log_next32(sample, "dot11MulticastReceivedFrameCount");
    sf_log_next32(sample, "dot11FCSErrorCount");
    sf_log_next32(sample, "dot11TransmittedFrameCount");
    sf_log_next32(sample, "dot11WEPUndecryptableCount");
    sf_log_next32(sample, "dot11QoSDiscardedFragmentCount");
    sf_log_next32(sample, "dot11AssociatedStationCount");
    sf_log_next32(sample, "dot11QoSCFPollsReceivedCount");
    sf_log_next32(sample, "dot11QoSCFPollsUnusedCount");
    sf_log_next32(sample, "dot11QoSCFPollsUnusableCount");
    sf_log_next32(sample, "dot11QoSCFPollsLostCount");
}

/*_________________---------------------------__________________
  _________________  readCounters_processor   __________________
  -----------------___________________________------------------
*/

static void readCounters_processor(SFSample *sample)
{
    sf_log_percentage(sample, "5s_cpu");
    sf_log_percentage(sample, "1m_cpu");
    sf_log_percentage(sample, "5m_cpu");
    sf_log_next64(sample, "total_memory_bytes");
    sf_log_next64(sample, "free_memory_bytes");
}

/*_________________---------------------------__________________
  _________________  readCounters_radio       __________________
  -----------------___________________________------------------
*/

static void readCounters_radio(SFSample *sample)
{
    sf_log_next32(sample, "radio_elapsed_time");
    sf_log_next32(sample, "radio_on_channel_time");
    sf_log_next32(sample, "radio_on_channel_busy_time");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_hid    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_hid(SFSample *sample)
{
    uint32_t i;
    u_char *uuid;
    char hostname[SFL_MAX_HOSTNAME_LEN + 1];
    char os_release[SFL_MAX_OSRELEASE_LEN + 1];
    if (getString(sample, hostname, SFL_MAX_HOSTNAME_LEN) > 0) {
        sf_log("hostname %s\n", hostname);
    }
    uuid = (u_char *)sample->datap;
    sf_log("UUID ");
    for (i = 0; i < 16; i++) {
        sf_log("%02x", uuid[i]);
    }
    sf_log("\n");
    skipBytes(sample, 16);
    sf_log_next32(sample, "machine_type");
    sf_log_next32(sample, "os_name");
    if (getString(sample, os_release, SFL_MAX_OSRELEASE_LEN) > 0) {
        sf_log("os_release %s\n", os_release);
    }
}

/*_________________---------------------------__________________
  _________________  readCounters_adaptors    __________________
  -----------------___________________________------------------
*/

static void readCounters_adaptors(SFSample *sample)
{
    u_char *mac;
    uint32_t i, j, ifindex, num_macs, num_adaptors = getData32(sample);
    for (i = 0; i < num_adaptors; i++) {
        ifindex = getData32(sample);
        sf_log("adaptor_%u_ifIndex %u\n", i, ifindex);
        num_macs = getData32(sample);
        sf_log("adaptor_%u_MACs %u\n", i, num_macs);
        for (j = 0; j < num_macs; j++) {
            mac = (u_char *)sample->datap;
            sf_log("adaptor_%u_MAC_%u %02x%02x%02x%02x%02x%02x\n",
                   i, j,
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            skipBytes(sample, 8);
        }
    }
}


/*_________________----------------------------__________________
  _________________  readCounters_host_parent  __________________
  -----------------____________________________------------------
*/

static void readCounters_host_parent(SFSample *sample)
{
    sf_log_next32(sample, "parent_dsClass");
    sf_log_next32(sample, "parent_dsIndex");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_cpu    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_cpu(SFSample *sample)
{
    sf_log_nextFloat(sample, "cpu_load_one");
    sf_log_nextFloat(sample, "cpu_load_five");
    sf_log_nextFloat(sample, "cpu_load_fifteen");
    sf_log_next32(sample, "cpu_proc_run");
    sf_log_next32(sample, "cpu_proc_total");
    sf_log_next32(sample, "cpu_num");
    sf_log_next32(sample, "cpu_speed");
    sf_log_next32(sample, "cpu_uptime");
    sf_log_next32(sample, "cpu_user");
    sf_log_next32(sample, "cpu_nice");
    sf_log_next32(sample, "cpu_system");
    sf_log_next32(sample, "cpu_idle");
    sf_log_next32(sample, "cpu_wio");
    sf_log_next32(sample, "cpuintr");
    sf_log_next32(sample, "cpu_sintr");
    sf_log_next32(sample, "cpuinterrupts");
    sf_log_next32(sample, "cpu_contexts");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_mem    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_mem(SFSample *sample)
{
    sf_log_next64(sample, "mem_total");
    sf_log_next64(sample, "mem_free");
    sf_log_next64(sample, "mem_shared");
    sf_log_next64(sample, "mem_buffers");
    sf_log_next64(sample, "mem_cached");
    sf_log_next64(sample, "swap_total");
    sf_log_next64(sample, "swap_free");
    sf_log_next32(sample, "page_in");
    sf_log_next32(sample, "page_out");
    sf_log_next32(sample, "swap_in");
    sf_log_next32(sample, "swap_out");
}


/*_________________---------------------------__________________
  _________________  readCounters_host_dsk    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_dsk(SFSample *sample)
{
    sf_log_next64(sample, "disk_total");
    sf_log_next64(sample, "disk_free");
    sf_log_percentage(sample, "disk_partition_max_used");
    sf_log_next32(sample, "disk_reads");
    sf_log_next64(sample, "disk_bytes_read");
    sf_log_next32(sample, "disk_read_time");
    sf_log_next32(sample, "disk_writes");
    sf_log_next64(sample, "disk_bytes_written");
    sf_log_next32(sample, "disk_write_time");
}

/*_________________---------------------------__________________
  _________________  readCounters_host_nio    __________________
  -----------------___________________________------------------
*/

static void readCounters_host_nio(SFSample *sample)
{
    sf_log_next64(sample, "nio_bytes_in");
    sf_log_next32(sample, "nio_pkts_in");
    sf_log_next32(sample, "nio_errs_in");
    sf_log_next32(sample, "nio_drops_in");
    sf_log_next64(sample, "nio_bytes_out");
    sf_log_next32(sample, "nio_pkts_out");
    sf_log_next32(sample, "nio_errs_out");
    sf_log_next32(sample, "nio_drops_out");
}

/*_________________-----------------------------__________________
  _________________  readCounters_host_vnode    __________________
  -----------------_____________________________------------------
*/

static void readCounters_host_vnode(SFSample *sample)
{
    sf_log_next32(sample, "vnode_mhz");
    sf_log_next32(sample, "vnode_cpus");
    sf_log_next64(sample, "vnode_memory");
    sf_log_next64(sample, "vnode_memory_free");
    sf_log_next32(sample, "vnode_num_domains");
}

/*_________________----------------------------__________________
  _________________  readCounters_host_vcpu    __________________
  -----------------____________________________------------------
*/

static void readCounters_host_vcpu(SFSample *sample)
{
    sf_log_next32(sample, "vcpu_state");
    sf_log_next32(sample, "vcpu_cpu_mS");
    sf_log_next32(sample, "vcpu_cpuCount");
}

/*_________________----------------------------__________________
  _________________  readCounters_host_vmem    __________________
  -----------------____________________________------------------
*/

static void readCounters_host_vmem(SFSample *sample)
{
    sf_log_next64(sample, "vmem_memory");
    sf_log_next64(sample, "vmem_maxMemory");
}

/*_________________----------------------------__________________
  _________________  readCounters_host_vdsk    __________________
  -----------------____________________________------------------
*/

static void readCounters_host_vdsk(SFSample *sample)
{
    sf_log_next64(sample, "vdsk_capacity");
    sf_log_next64(sample, "vdsk_allocation");
    sf_log_next64(sample, "vdsk_available");
    sf_log_next32(sample, "vdsk_rd_req");
    sf_log_next64(sample, "vdsk_rd_bytes");
    sf_log_next32(sample, "vdsk_wr_req");
    sf_log_next64(sample, "vdsk_wr_bytes");
    sf_log_next32(sample, "vdsk_errs");
}

/*_________________----------------------------__________________
  _________________  readCounters_host_vnio    __________________
  -----------------____________________________------------------
*/

static void readCounters_host_vnio(SFSample *sample)
{
    sf_log_next64(sample, "vnio_bytes_in");
    sf_log_next32(sample, "vnio_pkts_in");
    sf_log_next32(sample, "vnio_errs_in");
    sf_log_next32(sample, "vnio_drops_in");
    sf_log_next64(sample, "vnio_bytes_out");
    sf_log_next32(sample, "vnio_pkts_out");
    sf_log_next32(sample, "vnio_errs_out");
    sf_log_next32(sample, "vnio_drops_out");
}

/*_________________------------------------------__________________
  _________________  readCounters_host_gpu_nvml  __________________
  -----------------______________________________------------------
*/

static void readCounters_host_gpu_nvml(SFSample *sample)
{
    sf_log_next32(sample, "nvml_device_count");
    sf_log_next32(sample, "nvml_processes");
    sf_log_next32(sample, "nvml_gpu_mS");
    sf_log_next32(sample, "nvml_mem_mS");
    sf_log_next64(sample, "nvml_mem_bytes_total");
    sf_log_next64(sample, "nvml_mem_bytes_free");
    sf_log_next32(sample, "nvml_ecc_errors");
    sf_log_next32(sample, "nvml_energy_mJ");
    sf_log_next32(sample, "nvml_temperature_C");
    sf_log_next32(sample, "nvml_fan_speed_pc");
}

/*_________________----------------------------__________________
  _________________  readCounters_memcache     __________________
  -----------------____________________________------------------
 for structure 2200 (deprecated)
*/

static void readCounters_memcache(SFSample *sample)
{
    sf_log_next32(sample, "memcache_uptime");
    sf_log_next32(sample, "memcache_rusage_user");
    sf_log_next32(sample, "memcache_rusage_system");
    sf_log_next32(sample, "memcache_curr_connections");
    sf_log_next32(sample, "memcache_total_connections");
    sf_log_next32(sample, "memcache_connection_structures");
    sf_log_next32(sample, "memcache_cmd_get");
    sf_log_next32(sample, "memcache_cmd_set");
    sf_log_next32(sample, "memcache_cmd_flush");
    sf_log_next32(sample, "memcache_get_hits");
    sf_log_next32(sample, "memcache_get_misses");
    sf_log_next32(sample, "memcache_delete_misses");
    sf_log_next32(sample, "memcache_delete_hits");
    sf_log_next32(sample, "memcache_incr_misses");
    sf_log_next32(sample, "memcache_incr_hits");
    sf_log_next32(sample, "memcache_decr_misses");
    sf_log_next32(sample, "memcache_decr_hits");
    sf_log_next32(sample, "memcache_cas_misses");
    sf_log_next32(sample, "memcache_cas_hits");
    sf_log_next32(sample, "memcache_cas_badval");
    sf_log_next32(sample, "memcache_auth_cmds");
    sf_log_next32(sample, "memcache_auth_errors");
    sf_log_next64(sample, "memcache_bytes_read");
    sf_log_next64(sample, "memcache_bytes_written");
    sf_log_next32(sample, "memcache_limit_maxbytes");
    sf_log_next32(sample, "memcache_accepting_conns");
    sf_log_next32(sample, "memcache_listen_disabled_num");
    sf_log_next32(sample, "memcache_threads");
    sf_log_next32(sample, "memcache_conn_yields");
    sf_log_next64(sample, "memcache_bytes");
    sf_log_next32(sample, "memcache_curr_items");
    sf_log_next32(sample, "memcache_total_items");
    sf_log_next32(sample, "memcache_evictions");
}

/*_________________----------------------------__________________
  _________________  readCounters_memcache2    __________________
  -----------------____________________________------------------
  for structure 2204
*/

static void readCounters_memcache2(SFSample *sample)
{
    sf_log_next32(sample, "memcache_cmd_set");
    sf_log_next32(sample, "memcache_cmd_touch");
    sf_log_next32(sample, "memcache_cmd_flush");
    sf_log_next32(sample, "memcache_get_hits");
    sf_log_next32(sample, "memcache_get_misses");
    sf_log_next32(sample, "memcache_delete_hits");
    sf_log_next32(sample, "memcache_delete_misses");
    sf_log_next32(sample, "memcache_incr_hits");
    sf_log_next32(sample, "memcache_incr_misses");
    sf_log_next32(sample, "memcache_decr_hits");
    sf_log_next32(sample, "memcache_decr_misses");
    sf_log_next32(sample, "memcache_cas_hits");
    sf_log_next32(sample, "memcache_cas_misses");
    sf_log_next32(sample, "memcache_cas_badval");
    sf_log_next32(sample, "memcache_auth_cmds");
    sf_log_next32(sample, "memcache_auth_errors");
    sf_log_next32(sample, "memcache_threads");
    sf_log_next32(sample, "memcache_conn_yields");
    sf_log_next32(sample, "memcache_listen_disabled_num");
    sf_log_next32(sample, "memcache_curr_connections");
    sf_log_next32(sample, "memcache_rejected_connections");
    sf_log_next32(sample, "memcache_total_connections");
    sf_log_next32(sample, "memcache_connection_structures");
    sf_log_next32(sample, "memcache_evictions");
    sf_log_next32(sample, "memcache_reclaimed");
    sf_log_next32(sample, "memcache_curr_items");
    sf_log_next32(sample, "memcache_total_items");
    sf_log_next64(sample, "memcache_bytes_read");
    sf_log_next64(sample, "memcache_bytes_written");
    sf_log_next64(sample, "memcache_bytes");
    sf_log_next64(sample, "memcache_limit_maxbytes");
}

/*_________________----------------------------__________________
  _________________  readCounters_http         __________________
  -----------------____________________________------------------
*/

static void readCounters_http(SFSample *sample)
{
    sf_log_next32(sample, "http_method_option_count");
    sf_log_next32(sample, "http_method_get_count");
    sf_log_next32(sample, "http_method_head_count");
    sf_log_next32(sample, "http_method_post_count");
    sf_log_next32(sample, "http_method_put_count");
    sf_log_next32(sample, "http_method_delete_count");
    sf_log_next32(sample, "http_method_trace_count");
    sf_log_next32(sample, "http_methd_connect_count");
    sf_log_next32(sample, "http_method_other_count");
    sf_log_next32(sample, "http_status_1XX_count");
    sf_log_next32(sample, "http_status_2XX_count");
    sf_log_next32(sample, "http_status_3XX_count");
    sf_log_next32(sample, "http_status_4XX_count");
    sf_log_next32(sample, "http_status_5XX_count");
    sf_log_next32(sample, "http_status_other_count");
}

/*_________________----------------------------__________________
  _________________  readCounters_JVM          __________________
  -----------------____________________________------------------
*/

static void readCounters_JVM(SFSample *sample)
{
    char vm_name[SFLJVM_MAX_VMNAME_LEN];
    char vendor[SFLJVM_MAX_VENDOR_LEN];
    char version[SFLJVM_MAX_VERSION_LEN];
    if (getString(sample, vm_name, SFLJVM_MAX_VMNAME_LEN) > 0) {
        sf_log("jvm_name %s\n", vm_name);
    }
    if (getString(sample, vendor, SFLJVM_MAX_VENDOR_LEN) > 0) {
        sf_log("jvm_vendor %s\n", vendor);
    }
    if (getString(sample, version, SFLJVM_MAX_VERSION_LEN) > 0) {
        sf_log("jvm_version %s\n", version);
    }
}

/*_________________----------------------------__________________
  _________________  readCounters_JMX          __________________
  -----------------____________________________------------------
*/

static void readCounters_JMX(SFSample *sample, uint32_t length)
{
    sf_log_next64(sample, "heap_mem_initial");
    sf_log_next64(sample, "heap_mem_used");
    sf_log_next64(sample, "heap_mem_committed");
    sf_log_next64(sample, "heap_mem_max");
    sf_log_next64(sample, "non_heap_mem_initial");
    sf_log_next64(sample, "non_heap_mem_used");
    sf_log_next64(sample, "non_heap_mem_committed");
    sf_log_next64(sample, "non_heap_mem_max");
    sf_log_next32(sample, "gc_count");
    sf_log_next32(sample, "gc_mS");
    sf_log_next32(sample, "classes_loaded");
    sf_log_next32(sample, "classes_total");
    sf_log_next32(sample, "classes_unloaded");
    sf_log_next32(sample, "compilation_mS");
    sf_log_next32(sample, "threads_live");
    sf_log_next32(sample, "threads_daemon");
    sf_log_next32(sample, "threads_started");
    if (length > 100) {
        sf_log_next32(sample, "fds_open");
        sf_log_next32(sample, "fds_max");
    }
}

/*_________________----------------------------__________________
  _________________  readCounters_APP          __________________
  -----------------____________________________------------------
*/

static void readCounters_APP(SFSample *sample)
{
    char application[SFLAPP_MAX_APPLICATION_LEN];
    if (getString(sample, application, SFLAPP_MAX_APPLICATION_LEN) > 0) {
        sf_log("application %s\n", application);
    }
    sf_log_next32(sample, "status_OK");
    sf_log_next32(sample, "errors_OTHER");
    sf_log_next32(sample, "errors_TIMEOUT");
    sf_log_next32(sample, "errors_INTERNAL_ERROR");
    sf_log_next32(sample, "errors_BAD_REQUEST");
    sf_log_next32(sample, "errors_FORBIDDEN");
    sf_log_next32(sample, "errors_TOO_LARGE");
    sf_log_next32(sample, "errors_NOT_IMPLEMENTED");
    sf_log_next32(sample, "errors_NOT_FOUND");
    sf_log_next32(sample, "errors_UNAVAILABLE");
    sf_log_next32(sample, "errors_UNAUTHORIZED");
}

/*_________________----------------------------__________________
  _________________  readCounters_APP_RESOURCE __________________
  -----------------____________________________------------------
*/

static void readCounters_APP_RESOURCE(SFSample *sample)
{
    sf_log_next32(sample, "user_time");
    sf_log_next32(sample, "system_time");
    sf_log_next64(sample, "memory_used");
    sf_log_next64(sample, "memory_max");
    sf_log_next32(sample, "files_open");
    sf_log_next32(sample, "files_max");
    sf_log_next32(sample, "connections_open");
    sf_log_next32(sample, "connections_max");
}

/*_________________----------------------------__________________
  _________________  readCounters_APP_WORKERS  __________________
  -----------------____________________________------------------
*/

static void readCounters_APP_WORKERS(SFSample *sample)
{
    sf_log_next32(sample, "workers_active");
    sf_log_next32(sample, "workers_idle");
    sf_log_next32(sample, "workers_max");
    sf_log_next32(sample, "requests_delayed");
    sf_log_next32(sample, "requests_dropped");
}

/*_________________----------------------------__________________
  _________________       readCounters_VDI     __________________
  -----------------____________________________------------------
*/

static void readCounters_VDI(SFSample *sample)
{
    sf_log_next32(sample, "vdi_sessions_current");
    sf_log_next32(sample, "vdi_sessions_total");
    sf_log_next32(sample, "vdi_sessions_duration");
    sf_log_next32(sample, "vdi_rx_bytes");
    sf_log_next32(sample, "vdi_tx_bytes");
    sf_log_next32(sample, "vdi_rx_packets");
    sf_log_next32(sample, "vdi_tx_packets");
    sf_log_next32(sample, "vdi_rx_packets_lost");
    sf_log_next32(sample, "vdi_tx_packets_lost");
    sf_log_next32(sample, "vdi_rtt_min_ms");
    sf_log_next32(sample, "vdi_rtt_max_ms");
    sf_log_next32(sample, "vdi_rtt_avg_ms");
    sf_log_next32(sample, "vdi_audio_rx_bytes");
    sf_log_next32(sample, "vdi_audio_tx_bytes");
    sf_log_next32(sample, "vdi_audio_tx_limit");
    sf_log_next32(sample, "vdi_img_rx_bytes");
    sf_log_next32(sample, "vdi_img_tx_bytes");
    sf_log_next32(sample, "vdi_img_frames");
    sf_log_next32(sample, "vdi_img_qual_min");
    sf_log_next32(sample, "vdi_img_qual_max");
    sf_log_next32(sample, "vdi_img_qual_avg");
    sf_log_next32(sample, "vdi_usb_rx_bytes");
    sf_log_next32(sample, "vdi_usb_tx_bytes");
}

/*_________________------------------------------__________________
  _________________     readCounters_LACP        __________________
  -----------------______________________________------------------
*/

static void readCounters_LACP(SFSample *sample)
{
    SFLLACP_portState portState;
    sf_log_nextMAC(sample, "actorSystemID");
    sf_log_nextMAC(sample, "partnerSystemID");
    sf_log_next32(sample, "attachedAggID");
    portState.all = getData32_nobswap(sample);
    sf_log("actorAdminPortState %u\n", portState.v.actorAdmin);
    sf_log("actorOperPortState %u\n", portState.v.actorOper);
    sf_log("partnerAdminPortState %u\n", portState.v.partnerAdmin);
    sf_log("partnerOperPortState %u\n", portState.v.partnerOper);
    sf_log_next32(sample, "LACPDUsRx");
    sf_log_next32(sample, "markerPDUsRx");
    sf_log_next32(sample, "markerResponsePDUsRx");
    sf_log_next32(sample, "unknownRx");
    sf_log_next32(sample, "illegalRx");
    sf_log_next32(sample, "LACPDUsTx");
    sf_log_next32(sample, "markerPDUsTx");
    sf_log_next32(sample, "markerResponsePDUsTx");
}

/*_________________---------------------------__________________
  _________________  readCountersSample_v2v4  __________________
  -----------------___________________________------------------
*/

static void readCountersSample_v2v4(SFSample *sample)
{
    sf_log("sampleType COUNTERSSAMPLE\n");
    sample->samplesGenerated = getData32(sample);
    sf_log("sampleSequenceNo %u\n", sample->samplesGenerated);
    {
        uint32_t samplerId = getData32(sample);
        sample->ds_class = samplerId >> 24;
        sample->ds_index = samplerId & 0x00ffffff;
    }
    sf_log("sourceId %u:%u\n", sample->ds_class, sample->ds_index);


    sample->statsSamplingInterval = getData32(sample);
    sf_log("statsSamplingInterval %u\n", sample->statsSamplingInterval);
    /* now find out what sort of counter blocks we have here... */
    sample->counterBlockVersion = getData32(sample);
    sf_log("counterBlockVersion %u\n", sample->counterBlockVersion);

    /* first see if we should read the generic stats */
    switch (sample->counterBlockVersion) {
        case INMCOUNTERSVERSION_GENERIC:
        case INMCOUNTERSVERSION_ETHERNET:
        case INMCOUNTERSVERSION_TOKENRING:
        case INMCOUNTERSVERSION_FDDI:
        case INMCOUNTERSVERSION_VG:
        case INMCOUNTERSVERSION_WAN:
            readCounters_generic(sample);
            break;
        case INMCOUNTERSVERSION_VLAN:
            break;
        default:
            receiveError(sample, "unknown stats version", YES);
            break;
    }

    /* now see if there are any specific counter blocks to add */
    switch (sample->counterBlockVersion) {
        case INMCOUNTERSVERSION_GENERIC: /* nothing more */
            break;
        case INMCOUNTERSVERSION_ETHERNET:
            readCounters_ethernet(sample);
            break;
        case INMCOUNTERSVERSION_TOKENRING:
            readCounters_tokenring(sample);
            break;
        case INMCOUNTERSVERSION_FDDI:
            break;
        case INMCOUNTERSVERSION_VG:
            readCounters_vg(sample);
            break;
        case INMCOUNTERSVERSION_WAN:
            break;
        case INMCOUNTERSVERSION_VLAN:
            readCounters_vlan(sample);
            break;
        default:
            receiveError(sample, "unknown INMCOUNTERSVERSION", YES);
            break;
    }
    /* line-by-line output... */
    if (sfConfig.outputFormat == SFLFMT_LINE) {
        writeCountersLine(sample);
    }
}

#ifdef A10_SFLOW

inline static void sfl_ddos_description(SFSample *sample, char *description)
{
    strncpy(&sample->sfl_ddos_desc[0], description, strlen(description));
    return;
}
static int sfl_ddos_update_ctx_len(SFSample *sample, unsigned short len)
{

    int ctx_len = sample->current_context_length;
    if (len > sample->current_context_length) {
        sf_log("[%s-%d] Sample Ctx length Update failed.\n", __func__, __LINE__);
        SFABORT(sample, SF_ABORT_EOS);
        return;
    }

    ctx_len = ctx_len - len;
    if (ctx_len > 0) {
        sample->current_context_length = ctx_len;
    } else {
        SFABORT(sample, SF_ABORT_EOS);
        sf_log("[%s-%d] Sample Ctx length Update failed.\n", __func__, __LINE__);
        return;
    }

    return;
}

/* routines handles parsing of ddos counters */

static int populate_sflow_struct_u64(SFSample *sample, void *sfl_struct_ptr, unsigned short sfl_length)
{

    unsigned short parse_length = sample->current_context_length;

    if (!parse_length || (parse_length % LEN_U64)) {
        sf_log("[%s-%d] Invalid parse length detected.\n", __func__, __LINE__);
        SFABORT(sample, SF_ABORT_EOS);
        return -1;
    }

    /* Check for over-flow and under-flow:
    Overflow: Incoming sample length > struct length.
    Underflow: Incoming sample length < struct length.
    Solution: Parse length should be the minimum of 'sample length' & 'struct length'
    */

    unsigned short sample_counter_length = (parse_length / LEN_U64);
    unsigned short sfl_struct_length = (sfl_length / LEN_U64);
    unsigned short iter_length = min(sample_counter_length, sfl_struct_length);
    unsigned short fast_forward_length = (parse_length > sfl_length) ? (parse_length - sfl_length) : (sfl_length - parse_length);
    int i = 0;
    u64 data;

    for (i = 0; i < iter_length; i++) {
        data = (u64)getData64(sample);
        memcpy((void *)((size_t)sfl_struct_ptr + (i * (LEN_U64))), (const void *)&data, LEN_U64);
    }

    if (sfl_length < parse_length) {
        sf_log("Counter Length mismatch detected for %s, continuing...\n", sample->sfl_ddos_desc);
        u8 *datap = (u8 *)sample->datap;
        sample->datap = (uint32_t *)(datap + fast_forward_length);
    }
    return 0;
}

static int populate_sflow_struct_u32(SFSample *sample, void *sfl_struct_ptr, unsigned short sfl_length)
{

    unsigned short parse_length = sample->current_context_length;

    if (!parse_length || (parse_length % LEN_U32)) {
        sf_log("[%s-%d] Invalid parse length detected.\n", __func__, __LINE__);
        SFABORT(sample, SF_ABORT_EOS);
        return -1;
    }

    /* Check for over-flow and under-flow:
    Overflow: Incoming sample length > struct length.
    Underflow: Incoming sample length < struct length.
    Solution: Parse length should be the minimum of 'sample length' & 'struct length'
    */

    unsigned short sample_counter_length = (parse_length / LEN_U32);
    unsigned short sfl_struct_length = (sfl_length / LEN_U32);
    unsigned short iter_length = min(sample_counter_length, sfl_struct_length);
    unsigned short fast_forward_length = (parse_length > sfl_length) ? (parse_length - sfl_length) : (sfl_length - parse_length);
    int i = 0;
    u32 data;

    for (i = 0; i < iter_length; i++) {
        data = (u32)getData32(sample);
        memcpy((void *)((size_t)sfl_struct_ptr + (i * (LEN_U32))), (const void *)&data, LEN_U32);
    }

    if (sfl_length < parse_length) {
        sf_log("Counter Length mismatch detected for %s, continuing...", sample->sfl_ddos_desc);
        u8 *datap = (u8 *)sample->datap;
        sample->datap = (uint32_t *)(datap + fast_forward_length);
    }
    return 0;
}

static void readCounters_DDOS_GENERAL_HTTP_COUNTER(SFSample *sample)
{
    sf_log_next32(sample, "HTTP HEADER_TIMEOUT:");
    sf_log_next32(sample, "HTTP BODY_TIMEMOUT:");
    sf_log_next32(sample, "HTTP OFO_TIMEOUT:");
    sf_log_next32(sample, "HTTP OFO_QUEUE_SIZE_EXCEED:");
    sf_log_next32(sample, "HTTP LESS_THAN_MSS_EXCEED:");
    sf_log_next32(sample, "HTTP DDOS_ERROR_CONDITION:");
    sf_log_next32(sample, "HTTP DDOS_POLICY_VIOLATION:");
    sf_log_next32(sample, "HTTP DDOS_DST_REQ_RATE_EXCEED:");
    sf_log_next32(sample, "HTTP DDOS_SRC_REQ_RATE_EXCEED:");
    sf_log_next32(sample, "HTTP DDOS_HTTP_PROCESSED:");
    sf_log_next32(sample, "HTTP DDOS_HTTP_POLICY_DROP:");
    sf_log_next32(sample, "HTTP DDOS_HTTP_NEW_SYN:");
}

static void readCounters_DDOS_COUNTER(SFSample *sample)
{
    sflow_ddos_l4_global_counters_t *global_l4_t1 = &sample->ddos.l4;
    populate_sflow_struct_u64(sample, (void *)global_l4_t1, sizeof(sflow_ddos_l4_global_counters_t));

    sf_log_u64(global_l4_t1->intcp, "TCP received:");
    sf_log_u64(global_l4_t1->tcp_est, "L4 TCP Established :");
    sf_log_u64(global_l4_t1->tcp_outrst, "TCP out RST:");
    sf_log_u64(global_l4_t1->tcp_synreceived, "TCP SYN received:");
    sf_log_u64(global_l4_t1->tcp_syncookiessent, "TCP SYN cookie snt:");
    sf_log_u64(global_l4_t1->tcp_syncookiessentfailed, "TCP SYN cookie snt fail:");
    sf_log_u64(global_l4_t1->tcp_syncookiescheckfailed, "TCP SYN cookie failed:");
    sf_log_u64(global_l4_t1->tcp_syn_rate, "TCP SYN rate per sec:");
    sf_log_u64(global_l4_t1->tcp_exceed_drop, "TCP drop:");
    sf_log_u64(global_l4_t1->src_tcp_exceed_drop, "TCP src drop :");
    sf_log_u64(global_l4_t1->tcp_exceed_drop_crate_src, "TCP src conn rate drop:");
    sf_log_u64(global_l4_t1->tcp_exceed_drop_prate_src, "TCP src pkt rate drop:");
    sf_log_u64(global_l4_t1->tcp_exceed_drop_climit_src, "TCP src conn limit drop:");
    sf_log_u64(global_l4_t1->tcp_exceed_drop_black_src, "TCP src black list drop:");
    sf_log_u64(global_l4_t1->tcp_exceed_drop_crate_dst, "TCP dst conn rate drop:");
    sf_log_u64(global_l4_t1->tcp_exceed_drop_prate_dst, "TCP dst pkt rate drop:");
    sf_log_u64(global_l4_t1->tcp_exceed_drop_climit_dst, "TCP dst conn limit drop:");
    sf_log_u64(global_l4_t1->tcp_exceed_drop_black_dst, "TCP dst black list drop:");
    sf_log_u64(global_l4_t1->tcp_exceed_drop_crate_src_dst, "TCP src dst crate drop:");
    sf_log_u64(global_l4_t1->tcp_exceed_drop_prate_src_dst, "TCP src dst prate drop:");
    sf_log_u64(global_l4_t1->tcp_exceed_drop_climit_src_dst, "TCP src dst climit drop:");
    sf_log_u64(global_l4_t1->tcp_reset_client, "Reset TCP client:");
    sf_log_u64(global_l4_t1->tcp_reset_server, "Reset TCP server:");
    sf_log_u64(global_l4_t1->inudp, "UDP received:");
    sf_log_u64(global_l4_t1->udp_exceed_drop, "UDP drop:");
    sf_log_u64(global_l4_t1->src_udp_exceed_drop, "UDP src drop:");
    sf_log_u64(global_l4_t1->udp_exceed_drop_crate_src, "UDP src conn rate drop:");
    sf_log_u64(global_l4_t1->udp_exceed_drop_prate_src, "UDP src pkt rate drop:");
    sf_log_u64(global_l4_t1->udp_exceed_drop_climit_src, "UDP src conn limit drop:");
    sf_log_u64(global_l4_t1->udp_exceed_drop_black_src, "UDP src black list drop:");
    sf_log_u64(global_l4_t1->udp_exceed_drop_crate_dst, "UDP dst conn rate drop:");
    sf_log_u64(global_l4_t1->udp_exceed_drop_prate_dst, "UDP dst pkt rate drop:");
    sf_log_u64(global_l4_t1->udp_exceed_drop_climit_dst, "UDP dst climit drop:");
    sf_log_u64(global_l4_t1->udp_exceed_drop_black_dst, "UDP dst black list drop:");
    sf_log_u64(global_l4_t1->udp_exceed_drop_crate_src_dst, "UDP src dst crate drop:");
    sf_log_u64(global_l4_t1->udp_exceed_drop_prate_src_dst, "UDP src dst prate drop:");
    sf_log_u64(global_l4_t1->udp_exceed_drop_climit_src_dst, "UDP src dst conn limit drop:");
    sf_log_u64(global_l4_t1->instateless, "Stateless packets:");
    sf_log_u64(global_l4_t1->ip_outnoroute, "IP out noroute:");
    sf_log_u64(global_l4_t1->other_exceed_drop, "Other proto drop:");
    sf_log_u64(global_l4_t1->src_other_exceed_drop, "Other src drop:");
    sf_log_u64(global_l4_t1->l2_dsr, "TCP SYN cookie pass:");
    sf_log_u64(global_l4_t1->dst_learn, "Dest entry learned:");
    sf_log_u64(global_l4_t1->src_learn, "Src entry learn :");
    sf_log_u64(global_l4_t1->src_hit, "Src entry hit:");
    sf_log_u64(global_l4_t1->dst_hit, "Dest entry hit:");
    sf_log_u64(global_l4_t1->inicmp, "ICMP received:");
    sf_log_u64(global_l4_t1->icmp_exceed_drop, "ICMP drop:");
    sf_log_u64(global_l4_t1->src_icmp_exceed_drop, "ICMP src drop:");
    sf_log_u64(global_l4_t1->icmp_exceed_drop_prate_dst, "ICMP pkt rate exceed drop:");
    sf_log_u64(global_l4_t1->dns_malform_drop, "DNS malform drop :");
    sf_log_u64(global_l4_t1->dns_qry_any_drop, "DNS query any drop:");
    sf_log_u64(global_l4_t1->sync_src_wl_sent, "Sync src sent:");
    sf_log_u64(global_l4_t1->sync_src_dst_wl_sent, "Sync src dst sent:");
    sf_log_u64(global_l4_t1->sync_dst_wl_sent, "Sync dst sent:");
    sf_log_u64(global_l4_t1->sync_src_wl_rcv, "Sync src rcv:");
    sf_log_u64(global_l4_t1->sync_src_dst_wl_rcv, "Sync src dst rcv:");
    sf_log_u64(global_l4_t1->sync_dst_wl_rcv, "Sync dst rcv:");
    sf_log_u64(global_l4_t1->sync_wl_no_dst_drop, "Sync WL No dst drop:");
    sf_log_u64(global_l4_t1->ip_rcvd, "IPv4 rcv:");
    sf_log_u64(global_l4_t1->ipv6_rcvd, "IPv6 rcv:");
    sf_log_u64(global_l4_t1->ip_sent, "IPv4 sent:");
    sf_log_u64(global_l4_t1->ipv6_sent, "IPv6 sent:");
    sf_log_u64(global_l4_t1->inother, "OTHER received:");
    sf_log_u64(global_l4_t1->ip_tunnel_rcvd, "IPv4 tunnel rcv:");
    sf_log_u64(global_l4_t1->ipv6_tunnel_rcvd, "IPv6 tunnel rcv:");
    sf_log_u64(global_l4_t1->ip_tunnel_encap, "IPv4 tunnel encap:");
    sf_log_u64(global_l4_t1->ip_tunnel_decap, "IPv4 tunnel decap:");
    sf_log_u64(global_l4_t1->ip_tunnel_fail_encap_rcvd, "IPv4 tun fail encap rcv:");
    sf_log_u64(global_l4_t1->ip_tunnel_rate, "IPv4 tunnel rate:");
    sf_log_u64(global_l4_t1->gre_tunnel_encap, "GRE tunnel encap:");
    sf_log_u64(global_l4_t1->gre_tunnel_fail_encap_rcvd, "GRE tun fail encap rcv:");
    sf_log_u64(global_l4_t1->gre_tunnel_decap, "GRE tunnel decap:");
    sf_log_u64(global_l4_t1->gre_tunnel_rate, "GRE tunnel rate:");
    sf_log_u64(global_l4_t1->gre_tunnel_encap_key, "GRE tunnel encap w/ key:");
    sf_log_u64(global_l4_t1->gre_tunnel_decap_key, "GRE tunnel decap w/ key:");
    sf_log_u64(global_l4_t1->gre_tunnel_decap_drop_no_key, "GRE tun decap drp key mismatch:");
    sf_log_u64(global_l4_t1->gre_v6_tunnel_rcvd, "GRE v6 tunnel rcv:");
    sf_log_u64(global_l4_t1->gre_v6_tunnel_fail_encap_rcvd, "GRE v6 tun fail encap rcv :");
    sf_log_u64(global_l4_t1->gre_v6_tunnel_decap, "GRE v6 tunnel decap:");
    sf_log_u64(global_l4_t1->gre_v6_tunnel_rate, "GRE v6 tunnel rate:");
    sf_log_u64(global_l4_t1->dst_port_deny, "Dest port deny:");
    sf_log_u64(global_l4_t1->dst_port_undef_drop, "Dest port undef drop:");
    sf_log_u64(global_l4_t1->dst_port_bl, "Dest port black list:");
    sf_log_u64(global_l4_t1->dst_port_pkt_rate_exceed, "Dest port pkt rate excd :");
    sf_log_u64(global_l4_t1->dst_port_conn_limm_exceed, "Dest port conn lim excd:");
    sf_log_u64(global_l4_t1->dst_port_conn_rate_exceed, "Dest port conn rate excd:");
    sf_log_u64(global_l4_t1->dst_sport_bl, "Dest sport BL:");
    sf_log_u64(global_l4_t1->dst_sport_pkt_rate_exceed, "Dest sport pkt rate excd:");
    sf_log_u64(global_l4_t1->dst_sport_conn_limm_exceed, "Dest sport conn lim excd:");
    sf_log_u64(global_l4_t1->dst_sport_conn_rate_exceed, "Dest sport conn rate excd:");
    sf_log_u64(global_l4_t1->tcp_ack_no_syn, "TCP ACK no SYN:");
    sf_log_u64(global_l4_t1->tcp_out_of_order, "TCP out of order:");
    sf_log_u64(global_l4_t1->tcp_zero_window, "TCP zero window:");
    sf_log_u64(global_l4_t1->tcp_retransmit, "TCP rexmit:");
    sf_log_u64(global_l4_t1->tcp_action_on_ack_drop, "TCP action-on-ack drop:");
    sf_log_u64(global_l4_t1->tcp_action_on_ack_matched, "TCP action-on-ack matched:");
    sf_log_u64(global_l4_t1->tcp_action_on_ack_timeout, "TCP action-on-ack timeout :");
    sf_log_u64(global_l4_t1->tcp_action_on_ack_reset, "TCP action-on-ack reset");
    sf_log_u64(global_l4_t1->src_entry_aged, "Src entry aged:");
    sf_log_u64(global_l4_t1->dst_entry_aged, "Dest entry aged:");
    sf_log_u64(global_l4_t1->zero_wind_fail_bl, "Zero win Fail BL:");
    sf_log_u64(global_l4_t1->out_of_seq_fail_bl, "Out of seq Fail BL:");
    sf_log_u64(global_l4_t1->tcp_retransmit_fail_bl, "TCP re-xmit Fail BL:");
    sf_log_u64(global_l4_t1->tcp_action_on_ack_passed, "TCP action-on-ack passed:");
    sf_log_u64(global_l4_t1->syn_authn_skipped, "TCP SYN auth skipped:");
    sf_log_u64(global_l4_t1->syn_cookie_fail_bl, "TCP SYN cookie failed BL:");
    sf_log_u64(global_l4_t1->udp_learn, "UDP learn:");
    sf_log_u64(global_l4_t1->icmp_learn, "ICMP learn:");
    sf_log_u64(global_l4_t1->udp_pass, "UDP passed:");
    sf_log_u64(global_l4_t1->dns_auth_pass, "DNS auth passed:");
    sf_log_u64(global_l4_t1->src_dst_other_frag_exceed_drop, "Src-Dest frag exc drop:");
    sf_log_u64(global_l4_t1->src_other_frag_exceed_drop, "Src frag exc drop:");
    sf_log_u64(global_l4_t1->dst_other_frag_exceed_drop, "Dest frag exc drop:");
    sf_log_u64(global_l4_t1->over_conn_limit_tcp_syn_auth, "TCP over policy auth:");
    sf_log_u64(global_l4_t1->over_conn_limit_tcp_port_syn_auth, "TCP port over policy auth :");
    sf_log_u64(global_l4_t1->max_rexmit_syn_drop, "Re-xmit SYN excd drop:");
    sf_log_u64(global_l4_t1->max_rexmit_syn_bl, "Re-xmit SYN excd bl:");
    sf_log_u64(global_l4_t1->wellknown_port_drop, "Wellknown port drop:");
    sf_log_u64(global_l4_t1->ntp_monlist_req_drop, "NTP monlist req drop:");
    sf_log_u64(global_l4_t1->ntp_monlist_resp_drop, "NTP monlist resp drop:");
    sf_log_u64(global_l4_t1->udp_payload_too_big_drop, "UDP payload too big drop");
    sf_log_u64(global_l4_t1->udp_payload_too_small_drop, "UDP payload too small drop");
    sf_log_u64(global_l4_t1->tcp_bl_drop_user_config, "TCP Src BL Deny User Cfg:");
    sf_log_u64(global_l4_t1->udp_bl_drop_user_config, "UDP Src BL Deny User Cfg:");
    sf_log_u64(global_l4_t1->icmp_bl_drop_user_config, "ICMP Src BL Deny User Cfg:");
    sf_log_u64(global_l4_t1->other_bl_drop_user_config, "Other Src BL Deny User Cfg:");
    sf_log_u64(global_l4_t1->over_conn_limit_tcp_syn_cookie, "TCP over policy SYN cookie :");
    sf_log_u64(global_l4_t1->over_conn_limit_tcp_port_syn_cookie, "TCP port over policy cookie :");
    sf_log_u64(global_l4_t1->dst_ipproto_pkt_rate_exceed, "Dest IP protcol pkt rate excd:");
    sf_log_u64(global_l4_t1->tcp_action_on_ack_failed, "Action on ACK Failed:");
    sf_log_u64(global_l4_t1->udp_exceed_drop_conn_prate_dst, "UDP conn dst prate drop:");
    sf_log_u64(global_l4_t1->tcp_exceed_drop_conn_prate_dst, "TCP conn dst prate drop:");
    sf_log_u64(global_l4_t1->dns_tcp_auth_pass, "DNS TCP Auth Passed:");

}

//DDOS_PROTO: proto
enum {
    DDOS_UDP = 0,
    DDOS_TCP = 1,
    DDOS_ICMP = 2,
    DDOS_OTHER = 3,
    /* keep the total size as last element always */
    DDOS_TOTAL_PROTOCOL_SIZE,
    DDOS_INVALID_PROTO_TYPE,
};

static inline u_char getChar(SFSample *sample)
{
    u_char c = *(u_char *)sample->datap;
    sample->datap = (uint32_t *)((u_char *)sample->datap + 1);
    return c;
}
static inline unsigned short getShort(SFSample *sample)
{
    unsigned short c = *(unsigned short *)sample->datap;
    sample->datap = (uint32_t *)((u_char *)sample->datap + 2);
    return ntohs(c);
}
static uint32_t getDDoSAddress(SFSample *sample, char ip_type, SFLAddress *address)
{
    if (ip_type == 1) {
        address->type = SFLADDRESSTYPE_IP_V4;
        address->address.ip_v4.addr = getData32(sample);
        skipBytes(sample, 12);
    } else {
        address->type = SFLADDRESSTYPE_IP_V6;
        memcpy(&address->address.ip_v6.addr, sample->datap, 16);
        skipBytes(sample, 16);
    }
    return address->type;
}
static const char *ddos_proto_str[] = {
    "UDP",
    "TCP",
    "ICM",
    "OTH",
    "HTTP",
    "DNST",
    "DNSU",
    "SSL-L4"
};

static const char *ddos_state_flag[] = {
    "-",
    "W",
    "B",
    "?",
};
static const char *ddos_table_type[] = {
    "DST table",
    "SRC table",
    "SRC-DST table",
};
static const char *ddos_ip_type[] = {
    "DDOS IPv6",
    "DDOS IPv4",
};

// A10 DDET:

static void readCounters_DDOS_DST_INDICATORS(SFSample *sample)
{

    sflow_ddos_dst_indicators_t *dst_indicators = &(sample->ddos.ddos_dst_indicators);

    dst_indicators->tcp.seq_num = sf_log_next32(sample, "Sequence #:");
    dst_indicators->tcp.num_data_points = sf_log_next16(sample, "Num Data Points:");
    dst_indicators->tcp.elapsed_sec = sf_log_next16(sample, "Elapsed sec:");

    dst_indicators->tcp.in_pkt_rate.mean_x100 = sf_log_next32(sample, "In Packet rate: Mean");
    dst_indicators->tcp.in_pkt_rate.variance_x100 = sf_log_next32(sample, "In Packet rate: Variance");
    dst_indicators->tcp.in_pkt_rate.min_x100 = sf_log_next32(sample, "In Packet rate: Min");
    dst_indicators->tcp.in_pkt_rate.nonzero_min_x100 = sf_log_next32(sample, "In Packet rate: Nonzero Min");
    dst_indicators->tcp.in_pkt_rate.max_x100 = sf_log_next32(sample, "In Packet rate: Max");

    dst_indicators->tcp.in_syn_rate.mean_x100 = sf_log_next32(sample, "In SYN rate: Mean");
    dst_indicators->tcp.in_syn_rate.variance_x100 = sf_log_next32(sample, "In SYN rate: Variance");
    dst_indicators->tcp.in_syn_rate.min_x100 = sf_log_next32(sample, "In SYN rate: Min");
    dst_indicators->tcp.in_syn_rate.nonzero_min_x100 = sf_log_next32(sample, "In SYN rate: Nonzero Min");
    dst_indicators->tcp.in_syn_rate.max_x100 = sf_log_next32(sample, "In SYN rate: Max");

    dst_indicators->tcp.in_fin_rate.mean_x100 = sf_log_next32(sample, "In FIN rate: Mean");
    dst_indicators->tcp.in_fin_rate.variance_x100 = sf_log_next32(sample, "In FIN rate: Variance");
    dst_indicators->tcp.in_fin_rate.min_x100 = sf_log_next32(sample, "In FIN rate: Min");
    dst_indicators->tcp.in_fin_rate.nonzero_min_x100 = sf_log_next32(sample, "In FIN rate: Nonzero Min");
    dst_indicators->tcp.in_fin_rate.max_x100 = sf_log_next32(sample, "In FIN rate: Max");

    dst_indicators->tcp.in_rst_rate.mean_x100 = sf_log_next32(sample, "In RST rate: Mean");
    dst_indicators->tcp.in_rst_rate.variance_x100 = sf_log_next32(sample, "In RST rate: Variance");
    dst_indicators->tcp.in_rst_rate.min_x100 = sf_log_next32(sample, "In RST rate: Min");
    dst_indicators->tcp.in_rst_rate.nonzero_min_x100 = sf_log_next32(sample, "In RST rate: Nonzero Min");
    dst_indicators->tcp.in_rst_rate.max_x100 = sf_log_next32(sample, "In RST rate: Max");

    dst_indicators->tcp.small_window_ack_rate.mean_x100 = sf_log_next32(sample, "Small Window ACK rate: Mean");
    dst_indicators->tcp.small_window_ack_rate.variance_x100 = sf_log_next32(sample, "Small Window ACK rate: Variance");
    dst_indicators->tcp.small_window_ack_rate.min_x100 = sf_log_next32(sample, "Small Window ACK rate: Min");
    dst_indicators->tcp.small_window_ack_rate.nonzero_min_x100 = sf_log_next32(sample, "Small Window ACK rate: Nonzero Min");
    dst_indicators->tcp.small_window_ack_rate.max_x100 = sf_log_next32(sample, "Small Window ACK rate: Max");

    dst_indicators->tcp.empty_ack_rate.mean_x100 = sf_log_next32(sample, "Empty ACK rate: Mean");
    dst_indicators->tcp.empty_ack_rate.variance_x100 = sf_log_next32(sample, "Empty ACK rate: Variance");
    dst_indicators->tcp.empty_ack_rate.min_x100 = sf_log_next32(sample, "Empty ACK rate: Min");
    dst_indicators->tcp.empty_ack_rate.nonzero_min_x100 = sf_log_next32(sample, "Empty ACK rate: Nonzero Min");
    dst_indicators->tcp.empty_ack_rate.max_x100 = sf_log_next32(sample, "Empty ACK rate: Max");

    dst_indicators->tcp.small_payload_rate.mean_x100 = sf_log_next32(sample, "Small Payload rate: Mean");
    dst_indicators->tcp.small_payload_rate.variance_x100 = sf_log_next32(sample, "Small Payload rate: Variance");
    dst_indicators->tcp.small_payload_rate.min_x100 = sf_log_next32(sample, "Small Payload rate: Min");
    dst_indicators->tcp.small_payload_rate.nonzero_min_x100  = sf_log_next32(sample, "Small Payload rate: Nonzero Min");
    dst_indicators->tcp.small_payload_rate.max_x100 = sf_log_next32(sample, "Small Payload rate: Max");

    dst_indicators->tcp.in_byte_over_out_byte.mean_x100 = sf_log_next32(sample, "In byte over Out byte: Mean");
    dst_indicators->tcp.in_byte_over_out_byte.variance_x100 = sf_log_next32(sample, "In byte over Out byte: Variance");
    dst_indicators->tcp.in_byte_over_out_byte.min_x100  = sf_log_next32(sample, "In byte over Out byte: Min");
    dst_indicators->tcp.in_byte_over_out_byte.nonzero_min_x100 = sf_log_next32(sample, "In byte over Out byte: Nonzero Min");
    dst_indicators->tcp.in_byte_over_out_byte.max_x100 = sf_log_next32(sample, "In byte over Out byte: Max");

    dst_indicators->tcp.syn_over_fin.mean_x100 = sf_log_next32(sample, "SYN over FIN: Mean");
    dst_indicators->tcp.syn_over_fin.variance_x100 = sf_log_next32(sample, "SYN over FIN: Variance");
    dst_indicators->tcp.syn_over_fin.min_x100 = sf_log_next32(sample, "SYN over FIN: Min");
    dst_indicators->tcp.syn_over_fin.nonzero_min_x100 = sf_log_next32(sample, "SYN over FIN: Nonzero Min");
    dst_indicators->tcp.syn_over_fin.max_x100 = sf_log_next32(sample, "SYN over FIN: Max");

    dst_indicators->tcp.conn_miss_rate.mean_x100 = sf_log_next32(sample, "Conn miss rate: Mean");
    dst_indicators->tcp.conn_miss_rate.variance_x100 = sf_log_next32(sample, "Conn miss rate: Variance");
    dst_indicators->tcp.conn_miss_rate.min_x100 = sf_log_next32(sample, "Conn miss rate: Min");
    dst_indicators->tcp.conn_miss_rate.nonzero_min_x100 = sf_log_next32(sample, "Conn miss rate: Nonzero Min");
    dst_indicators->tcp.conn_miss_rate.max_x100 = sf_log_next32(sample, "Conn miss rate: Max");

    dst_indicators->tcp.concurrent_conns.mean_x100 = sf_log_next32(sample, "Conncurrent conns: Mean");
    dst_indicators->tcp.concurrent_conns.variance_x100 = sf_log_next32(sample, "Conncurrent conns: Variance");
    dst_indicators->tcp.concurrent_conns.min_x100 = sf_log_next32(sample, "Conncurrent conns: Min");
    dst_indicators->tcp.concurrent_conns.nonzero_min_x100 = sf_log_next32(sample, "Conncurrent conns: Nonzero Min");
    dst_indicators->tcp.concurrent_conns.max_x100 = sf_log_next32(sample, "Conncurrent conns: Max");

    dst_indicators->tcp.pkt_drop_rate.mean_x100 = sf_log_next32(sample, "TCP Pkt Drop Rate: Mean");
    dst_indicators->tcp.pkt_drop_rate.variance_x100 = sf_log_next32(sample, "TCP Pkt Drop Rate: Variance");
    dst_indicators->tcp.pkt_drop_rate.min_x100 = sf_log_next32(sample, "TCP Pkt Drop Rate: Min");
    dst_indicators->tcp.pkt_drop_rate.nonzero_min_x100 = sf_log_next32(sample, "TCP Pkt Drop Rate: Nonzero Min");
    dst_indicators->tcp.pkt_drop_rate.max_x100 = sf_log_next32(sample, "TCP Pkt Drop Rate: Max");

    dst_indicators->tcp.pkt_drop_recv_ratio.mean_x100 = sf_log_next32(sample, "TCP Pkt Drop / Pkt Rcvd: Mean");
    dst_indicators->tcp.pkt_drop_recv_ratio.variance_x100 = sf_log_next32(sample, "TCP Pkt Drop / Pkt Rcvd: Variance");
    dst_indicators->tcp.pkt_drop_recv_ratio.min_x100 = sf_log_next32(sample, "TCP Pkt Drop / Pkt Rcvd: Min");
    dst_indicators->tcp.pkt_drop_recv_ratio.nonzero_min_x100 = sf_log_next32(sample, "TCP Pkt Drop / Pkt Rcvd: Nonzero Min");
    dst_indicators->tcp.pkt_drop_recv_ratio.max_x100 = sf_log_next32(sample, "TCP Pkt Drop / Pkt Rcvd: Max");

    dst_indicators->udp.seq_num = sf_log_next32(sample, "Sequence #:");
    dst_indicators->udp.num_data_points = sf_log_next16(sample, "Num Data Points:");
    dst_indicators->udp.elapsed_sec = sf_log_next16(sample, "Elapsed sec:");

    dst_indicators->udp.in_pkt_rate.mean_x100 = sf_log_next32(sample, "In Packet rate: Mean");
    dst_indicators->udp.in_pkt_rate.variance_x100 = sf_log_next32(sample, "In Packet rate: Variance");
    dst_indicators->udp.in_pkt_rate.min_x100 = sf_log_next32(sample, "In Packet rate: Min");
    dst_indicators->udp.in_pkt_rate.nonzero_min_x100 = sf_log_next32(sample, "In Packet rate: Nonzero Min");
    dst_indicators->udp.in_pkt_rate.max_x100 = sf_log_next32(sample, "In Packet rate: Max");

    dst_indicators->udp.small_payload_rate.mean_x100 = sf_log_next32(sample, "Small Payload rate: Mean");
    dst_indicators->udp.small_payload_rate.variance_x100 = sf_log_next32(sample, "Small Payload rate: Variance");
    dst_indicators->udp.small_payload_rate.min_x100 = sf_log_next32(sample, "Small Payload rate: Min");
    dst_indicators->udp.small_payload_rate.nonzero_min_x100 = sf_log_next32(sample, "Small Payload rate: Nonzero Min");
    dst_indicators->udp.small_payload_rate.max_x100 = sf_log_next32(sample, "Small Payload rate: Max");

    dst_indicators->udp.in_byte_over_out_byte.mean_x100 = sf_log_next32(sample, "In byte over Out byte: Mean");
    dst_indicators->udp.in_byte_over_out_byte.variance_x100 = sf_log_next32(sample, "In byte over Out byte: Variance");
    dst_indicators->udp.in_byte_over_out_byte.min_x100  = sf_log_next32(sample, "In byte over Out byte: Min");
    dst_indicators->udp.in_byte_over_out_byte.nonzero_min_x100  = sf_log_next32(sample, "In byte over Out byte: Nonzero Min");
    dst_indicators->udp.in_byte_over_out_byte.max_x100  = sf_log_next32(sample, "In byte over Out byte: Max");

    dst_indicators->udp.pkt_drop_rate.mean_x100 = sf_log_next32(sample, "UDP Pkt Drop Rate: Mean");
    dst_indicators->udp.pkt_drop_rate.variance_x100 = sf_log_next32(sample, "UDP Pkt Drop Rate: Variance");
    dst_indicators->udp.pkt_drop_rate.min_x100 = sf_log_next32(sample, "UDP Pkt Drop Rate: Min");
    dst_indicators->udp.pkt_drop_rate.nonzero_min_x100 = sf_log_next32(sample, "UDP Pkt Drop Rate: Nonzero Min");
    dst_indicators->udp.pkt_drop_rate.max_x100 = sf_log_next32(sample, "UDP Pkt Drop Rate: Max");

    dst_indicators->udp.pkt_drop_recv_ratio.mean_x100 = sf_log_next32(sample, "UDP Pkt Drop / Pkt Rcvd: Mean");
    dst_indicators->udp.pkt_drop_recv_ratio.variance_x100 = sf_log_next32(sample, "UDP Pkt Drop / Pkt Rcvd: Variance");
    dst_indicators->udp.pkt_drop_recv_ratio.min_x100 = sf_log_next32(sample, "UDP Pkt Drop / Pkt Rcvd: Min");
    dst_indicators->udp.pkt_drop_recv_ratio.nonzero_min_x100 = sf_log_next32(sample, "UDP Pkt Drop / Pkt Rcvd: Nonzero Min");
    dst_indicators->udp.pkt_drop_recv_ratio.max_x100 = sf_log_next32(sample, "UDP Pkt Drop / Pkt Rcvd: Max");

    dst_indicators->icmp.seq_num  = sf_log_next32(sample, "Sequence #:");
    dst_indicators->icmp.num_data_points = sf_log_next16(sample, "Num Data Points:");
    dst_indicators->icmp.elapsed_sec = sf_log_next16(sample, "Elapsed sec:");

    dst_indicators->icmp.in_pkt_rate.mean_x100 = sf_log_next32(sample, "In Packet rate: Mean");
    dst_indicators->icmp.in_pkt_rate.variance_x100 = sf_log_next32(sample, "In Packet rate: Variance");
    dst_indicators->icmp.in_pkt_rate.min_x100 = sf_log_next32(sample, "In Packet rate: Min");
    dst_indicators->icmp.in_pkt_rate.nonzero_min_x100 = sf_log_next32(sample, "In Packet rate: Nonzero Min");
    dst_indicators->icmp.in_pkt_rate.max_x100 = sf_log_next32(sample, "In Packet rate: Max");

    dst_indicators->icmp.in_byte_over_out_byte.mean_x100 = sf_log_next32(sample, "In byte over Out byte: Mean");
    dst_indicators->icmp.in_byte_over_out_byte.variance_x100 = sf_log_next32(sample, "In byte over Out byte: Variance");
    dst_indicators->icmp.in_byte_over_out_byte.min_x100 = sf_log_next32(sample, "In byte over Out byte: Min");
    dst_indicators->icmp.in_byte_over_out_byte.nonzero_min_x100 = sf_log_next32(sample, "In byte over Out byte: Nonzero Min");
    dst_indicators->icmp.in_byte_over_out_byte.max_x100 = sf_log_next32(sample, "In byte over Out byte: Max");

    dst_indicators->icmp.pkt_drop_rate.mean_x100 = sf_log_next32(sample, "ICMP Pkt Drop Rate: Mean");
    dst_indicators->icmp.pkt_drop_rate.variance_x100 = sf_log_next32(sample, "ICMP Pkt Drop Rate: Variance");
    dst_indicators->icmp.pkt_drop_rate.min_x100 = sf_log_next32(sample, "ICMP Pkt Drop Rate: Min");
    dst_indicators->icmp.pkt_drop_rate.nonzero_min_x100 = sf_log_next32(sample, "ICMP Pkt Drop Rate: Nonzero Min");
    dst_indicators->icmp.pkt_drop_rate.max_x100 = sf_log_next32(sample, "ICMP Pkt Drop Rate: Max");

    dst_indicators->icmp.pkt_drop_recv_ratio.mean_x100 = sf_log_next32(sample, "ICMP Pkt Drop / Pkt Rcvd: Mean");
    dst_indicators->icmp.pkt_drop_recv_ratio.variance_x100 = sf_log_next32(sample, "ICMP Pkt Drop / Pkt Rcvd: Variance");
    dst_indicators->icmp.pkt_drop_recv_ratio.min_x100 = sf_log_next32(sample, "ICMP Pkt Drop / Pkt Rcvd: Min");
    dst_indicators->icmp.pkt_drop_recv_ratio.nonzero_min_x100 = sf_log_next32(sample, "ICMP Pkt Drop / Pkt Rcvd: Nonzero Min");
    dst_indicators->icmp.pkt_drop_recv_ratio.max_x100 = sf_log_next32(sample, "ICMP Pkt Drop / Pkt Rcvd: Max");

    dst_indicators->other.seq_num  = sf_log_next32(sample, "Sequence #:");
    dst_indicators->other.num_data_points = sf_log_next16(sample, "Num Data Points:");
    dst_indicators->other.elapsed_sec = sf_log_next16(sample, "Elapsed sec:");

    dst_indicators->other.in_pkt_rate.mean_x100 = sf_log_next32(sample, "OTHER In Packet rate: Mean");
    dst_indicators->other.in_pkt_rate.variance_x100 = sf_log_next32(sample, "OTHER In Packet rate: Variance");
    dst_indicators->other.in_pkt_rate.min_x100 = sf_log_next32(sample, "OTHER In Packet rate: Min");
    dst_indicators->other.in_pkt_rate.nonzero_min_x100 = sf_log_next32(sample, "OTHER In Packet rate: Nonzero Min");
    dst_indicators->other.in_pkt_rate.max_x100 = sf_log_next32(sample, "OTHER In Packet rate: Max");

    dst_indicators->other.in_frag_rate.mean_x100 = sf_log_next32(sample, "OTHER In Frag rate: Mean");
    dst_indicators->other.in_frag_rate.variance_x100 = sf_log_next32(sample, "OTHER In Frag rate: Variance");
    dst_indicators->other.in_frag_rate.min_x100 = sf_log_next32(sample, "OTHER In Frag rate: Min");
    dst_indicators->other.in_frag_rate.nonzero_min_x100 = sf_log_next32(sample, "OTHER In Frag rate: Nonzero Min");
    dst_indicators->other.in_frag_rate.max_x100 = sf_log_next32(sample, "OTHER In Frag rate: Max");

    dst_indicators->other.in_byte_over_out_byte.mean_x100 = sf_log_next32(sample, "OTHER In byte over Out byte: Mean");
    dst_indicators->other.in_byte_over_out_byte.variance_x100 = sf_log_next32(sample, "OTHER In byte over Out byte: Variance");
    dst_indicators->other.in_byte_over_out_byte.min_x100 = sf_log_next32(sample, "OTHER In byte over Out byte: Min");
    dst_indicators->other.in_byte_over_out_byte.nonzero_min_x100 = sf_log_next32(sample, "OTHER In byte over Out byte: Nonzero Min");
    dst_indicators->other.in_byte_over_out_byte.max_x100 = sf_log_next32(sample, "OTHER In byte over Out byte: Max");

    dst_indicators->other.pkt_drop_rate.mean_x100 = sf_log_next32(sample, "OTHER Pkt Drop Rate: Mean");
    dst_indicators->other.pkt_drop_rate.variance_x100 = sf_log_next32(sample, "OTHER Pkt Drop Rate: Variance");
    dst_indicators->other.pkt_drop_rate.min_x100 = sf_log_next32(sample, "OTHER Pkt Drop Rate: Min");
    dst_indicators->other.pkt_drop_rate.nonzero_min_x100 = sf_log_next32(sample, "OTHER Pkt Drop Rate: Nonzero Min");
    dst_indicators->other.pkt_drop_rate.max_x100 = sf_log_next32(sample, "OTHER Pkt Drop Rate: Max");

    dst_indicators->other.pkt_drop_recv_ratio.mean_x100 = sf_log_next32(sample, "OTHER Pkt Drop / Pkt Rcvd: Mean");
    dst_indicators->other.pkt_drop_recv_ratio.variance_x100 = sf_log_next32(sample, "OTHER Pkt Drop / Pkt Rcvd: Variance");
    dst_indicators->other.pkt_drop_recv_ratio.min_x100 = sf_log_next32(sample, "OTHER Pkt Drop / Pkt Rcvd: Min");
    dst_indicators->other.pkt_drop_recv_ratio.nonzero_min_x100 = sf_log_next32(sample, "OTHER Pkt Drop / Pkt Rcvd: Nonzero Min");
    dst_indicators->other.pkt_drop_recv_ratio.max_x100 = sf_log_next32(sample, "OTHER Pkt Drop / Pkt Rcvd: Max");
}

static void readCounters_DDOS_DST_TCP_INDICATORS(SFSample *sample)
{

    sflow_ddos_dst_tcp_indicators_t *dst_tcp_indicators = &(sample->ddos.ddos_dst_tcp_indicators);

    dst_tcp_indicators->seq_num = sf_log_next32(sample, "Sequence #:");
    dst_tcp_indicators->num_data_points = sf_log_next16(sample, "Num Data Points:");
    dst_tcp_indicators->elapsed_sec = sf_log_next16(sample, "Elapsed sec:");

    dst_tcp_indicators->in_pkt_rate.mean_x100 = sf_log_next32(sample, "In Packet rate: Mean");
    dst_tcp_indicators->in_pkt_rate.variance_x100 = sf_log_next32(sample, "In Packet rate: Variance");
    dst_tcp_indicators->in_pkt_rate.min_x100 = sf_log_next32(sample, "In Packet rate: Min");
    dst_tcp_indicators->in_pkt_rate.nonzero_min_x100 = sf_log_next32(sample, "In Packet rate: Nonzero Min");
    dst_tcp_indicators->in_pkt_rate.max_x100 = sf_log_next32(sample, "In Packet rate: Max");

    dst_tcp_indicators->in_syn_rate.mean_x100 = sf_log_next32(sample, "In SYN rate: Mean");
    dst_tcp_indicators->in_syn_rate.variance_x100 = sf_log_next32(sample, "In SYN rate: Variance");
    dst_tcp_indicators->in_syn_rate.min_x100 = sf_log_next32(sample, "In SYN rate: Min");
    dst_tcp_indicators->in_syn_rate.nonzero_min_x100 = sf_log_next32(sample, "In SYN rate: Nonzero Min");
    dst_tcp_indicators->in_syn_rate.max_x100 = sf_log_next32(sample, "In SYN rate: Max");

    dst_tcp_indicators->in_fin_rate.mean_x100 = sf_log_next32(sample, "In FIN rate: Mean");
    dst_tcp_indicators->in_fin_rate.variance_x100 = sf_log_next32(sample, "In FIN rate: Variance");
    dst_tcp_indicators->in_fin_rate.min_x100 = sf_log_next32(sample, "In FIN rate: Min");
    dst_tcp_indicators->in_fin_rate.nonzero_min_x100 = sf_log_next32(sample, "In FIN rate: Nonzero Min");
    dst_tcp_indicators->in_fin_rate.max_x100 = sf_log_next32(sample, "In FIN rate: Max");

    dst_tcp_indicators->in_rst_rate.mean_x100 = sf_log_next32(sample, "In RST rate: Mean");
    dst_tcp_indicators->in_rst_rate.variance_x100 = sf_log_next32(sample, "In RST rate: Variance");
    dst_tcp_indicators->in_rst_rate.min_x100 = sf_log_next32(sample, "In RST rate: Min");
    dst_tcp_indicators->in_rst_rate.nonzero_min_x100 = sf_log_next32(sample, "In RST rate: Nonzero Min");
    dst_tcp_indicators->in_rst_rate.max_x100 = sf_log_next32(sample, "In RST rate: Max");

    dst_tcp_indicators->small_window_ack_rate.mean_x100 = sf_log_next32(sample, "Small Window ACK rate: Mean");
    dst_tcp_indicators->small_window_ack_rate.variance_x100 = sf_log_next32(sample, "Small Window ACK rate: Variance");
    dst_tcp_indicators->small_window_ack_rate.min_x100 = sf_log_next32(sample, "Small Window ACK rate: Min");
    dst_tcp_indicators->small_window_ack_rate.nonzero_min_x100 = sf_log_next32(sample, "Small Window ACK rate: Nonzero Min");
    dst_tcp_indicators->small_window_ack_rate.max_x100 = sf_log_next32(sample, "Small Window ACK rate: Max");

    dst_tcp_indicators->empty_ack_rate.mean_x100 = sf_log_next32(sample, "Empty ACK rate: Mean");
    dst_tcp_indicators->empty_ack_rate.variance_x100 = sf_log_next32(sample, "Empty ACK rate: Variance");
    dst_tcp_indicators->empty_ack_rate.min_x100 = sf_log_next32(sample, "Empty ACK rate: Min");
    dst_tcp_indicators->empty_ack_rate.nonzero_min_x100 = sf_log_next32(sample, "Empty ACK rate: Nonzero Min");
    dst_tcp_indicators->empty_ack_rate.max_x100 = sf_log_next32(sample, "Empty ACK rate: Max");

    dst_tcp_indicators->small_payload_rate.mean_x100 = sf_log_next32(sample, "Small Payload rate: Mean");
    dst_tcp_indicators->small_payload_rate.variance_x100 = sf_log_next32(sample, "Small Payload rate: Variance");
    dst_tcp_indicators->small_payload_rate.min_x100 = sf_log_next32(sample, "Small Payload rate: Min");
    dst_tcp_indicators->small_payload_rate.nonzero_min_x100  = sf_log_next32(sample, "Small Payload rate: Nonzero Min");
    dst_tcp_indicators->small_payload_rate.max_x100 = sf_log_next32(sample, "Small Payload rate: Max");

    dst_tcp_indicators->in_byte_over_out_byte.mean_x100 = sf_log_next32(sample, "In byte over Out byte: Mean");
    dst_tcp_indicators->in_byte_over_out_byte.variance_x100 = sf_log_next32(sample, "In byte over Out byte: Variance");
    dst_tcp_indicators->in_byte_over_out_byte.min_x100  = sf_log_next32(sample, "In byte over Out byte: Min");
    dst_tcp_indicators->in_byte_over_out_byte.nonzero_min_x100 = sf_log_next32(sample, "In byte over Out byte: Nonzero Min");
    dst_tcp_indicators->in_byte_over_out_byte.max_x100 = sf_log_next32(sample, "In byte over Out byte: Max");

    dst_tcp_indicators->syn_over_fin.mean_x100 = sf_log_next32(sample, "SYN over FIN: Mean");
    dst_tcp_indicators->syn_over_fin.variance_x100 = sf_log_next32(sample, "SYN over FIN: Variance");
    dst_tcp_indicators->syn_over_fin.min_x100 = sf_log_next32(sample, "SYN over FIN: Min");
    dst_tcp_indicators->syn_over_fin.nonzero_min_x100 = sf_log_next32(sample, "SYN over FIN: Nonzero Min");
    dst_tcp_indicators->syn_over_fin.max_x100 = sf_log_next32(sample, "SYN over FIN: Max");

    dst_tcp_indicators->conn_miss_rate.mean_x100 = sf_log_next32(sample, "Conn miss rate: Mean");
    dst_tcp_indicators->conn_miss_rate.variance_x100 = sf_log_next32(sample, "Conn miss rate: Variance");
    dst_tcp_indicators->conn_miss_rate.min_x100 = sf_log_next32(sample, "Conn miss rate: Min");
    dst_tcp_indicators->conn_miss_rate.nonzero_min_x100 = sf_log_next32(sample, "Conn miss rate: Nonzero Min");
    dst_tcp_indicators->conn_miss_rate.max_x100 = sf_log_next32(sample, "Conn miss rate: Max");

    dst_tcp_indicators->concurrent_conns.mean_x100 = sf_log_next32(sample, "Conncurrent conns: Mean");
    dst_tcp_indicators->concurrent_conns.variance_x100 = sf_log_next32(sample, "Conncurrent conns: Variance");
    dst_tcp_indicators->concurrent_conns.min_x100 = sf_log_next32(sample, "Conncurrent conns: Min");
    dst_tcp_indicators->concurrent_conns.nonzero_min_x100 = sf_log_next32(sample, "Conncurrent conns: Nonzero Min");
    dst_tcp_indicators->concurrent_conns.max_x100 = sf_log_next32(sample, "Conncurrent conns: Max");

    dst_tcp_indicators->pkt_drop_rate.mean_x100 = sf_log_next32(sample, "Pkt Drop Rate: Mean");
    dst_tcp_indicators->pkt_drop_rate.variance_x100 = sf_log_next32(sample, "Pkt Drop Rate: Variance");
    dst_tcp_indicators->pkt_drop_rate.min_x100 = sf_log_next32(sample, "Pkt Drop Rate: Min");
    dst_tcp_indicators->pkt_drop_rate.nonzero_min_x100 = sf_log_next32(sample, "Pkt Drop Rate: Nonzero Min");
    dst_tcp_indicators->pkt_drop_rate.max_x100 = sf_log_next32(sample, "Pkt Drop Rate: Max");

    dst_tcp_indicators->pkt_drop_recv_ratio.mean_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Mean");
    dst_tcp_indicators->pkt_drop_recv_ratio.variance_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Variance");
    dst_tcp_indicators->pkt_drop_recv_ratio.min_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Min");
    dst_tcp_indicators->pkt_drop_recv_ratio.nonzero_min_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Nonzero Min");
    dst_tcp_indicators->pkt_drop_recv_ratio.max_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Max");
}

static void readCounters_DDOS_DST_UDP_INDICATORS(SFSample *sample)
{

    sflow_ddos_dst_udp_indicators_t *dst_udp_indicators = &(sample->ddos.ddos_dst_udp_indicators);

    dst_udp_indicators->seq_num = sf_log_next32(sample, "Sequence #:");
    dst_udp_indicators->num_data_points = sf_log_next16(sample, "Num Data Points:");
    dst_udp_indicators->elapsed_sec = sf_log_next16(sample, "Elapsed sec:");

    dst_udp_indicators->in_pkt_rate.mean_x100 = sf_log_next32(sample, "In Packet rate: Mean");
    dst_udp_indicators->in_pkt_rate.variance_x100 = sf_log_next32(sample, "In Packet rate: Variance");
    dst_udp_indicators->in_pkt_rate.min_x100 = sf_log_next32(sample, "In Packet rate: Min");
    dst_udp_indicators->in_pkt_rate.nonzero_min_x100 = sf_log_next32(sample, "In Packet rate: Nonzero Min");
    dst_udp_indicators->in_pkt_rate.max_x100 = sf_log_next32(sample, "In Packet rate: Max");

    dst_udp_indicators->small_payload_rate.mean_x100 = sf_log_next32(sample, "Small Payload rate: Mean");
    dst_udp_indicators->small_payload_rate.variance_x100 = sf_log_next32(sample, "Small Payload rate:: Variance");
    dst_udp_indicators->small_payload_rate.min_x100 = sf_log_next32(sample, "Small Payload rate:: Min");
    dst_udp_indicators->small_payload_rate.nonzero_min_x100 = sf_log_next32(sample, "Small Payload rate:: Nonzero Min");
    dst_udp_indicators->small_payload_rate.max_x100 = sf_log_next32(sample, "Small Payload rate:: Max");

    dst_udp_indicators->in_byte_over_out_byte.mean_x100 = sf_log_next32(sample, "In byte over Out byte: Mean");
    dst_udp_indicators->in_byte_over_out_byte.variance_x100 = sf_log_next32(sample, "In byte over Out byte: Variance");
    dst_udp_indicators->in_byte_over_out_byte.min_x100  = sf_log_next32(sample, "In byte over Out byte: Min");
    dst_udp_indicators->in_byte_over_out_byte.nonzero_min_x100  = sf_log_next32(sample, "In byte over Out byte: Nonzero Min");
    dst_udp_indicators->in_byte_over_out_byte.max_x100  = sf_log_next32(sample, "In byte over Out byte: Max");

    dst_udp_indicators->pkt_drop_rate.mean_x100 = sf_log_next32(sample, "Pkt Drop Rate: Mean");
    dst_udp_indicators->pkt_drop_rate.variance_x100 = sf_log_next32(sample, "Pkt Drop Rate: Variance");
    dst_udp_indicators->pkt_drop_rate.min_x100 = sf_log_next32(sample, "Pkt Drop Rate: Min");
    dst_udp_indicators->pkt_drop_rate.nonzero_min_x100 = sf_log_next32(sample, "Pkt Drop Rate: Nonzero Min");
    dst_udp_indicators->pkt_drop_rate.max_x100 = sf_log_next32(sample, "Pkt Drop Rate: Max");

    dst_udp_indicators->pkt_drop_recv_ratio.mean_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Mean");
    dst_udp_indicators->pkt_drop_recv_ratio.variance_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Variance");
    dst_udp_indicators->pkt_drop_recv_ratio.min_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Min");
    dst_udp_indicators->pkt_drop_recv_ratio.nonzero_min_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Nonzero Min");
    dst_udp_indicators->pkt_drop_recv_ratio.max_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Max");
}

static void readCounters_DDOS_DST_ICMP_INDICATORS(SFSample *sample)
{

    sflow_ddos_dst_icmp_indicators_t *dst_icmp_indicators = &(sample->ddos.ddos_dst_icmp_indicators);
    dst_icmp_indicators->seq_num  = sf_log_next32(sample, "Sequence #:");
    dst_icmp_indicators->num_data_points = sf_log_next16(sample, "Num Data Points:");
    dst_icmp_indicators->elapsed_sec = sf_log_next16(sample, "Elapsed sec:");

    dst_icmp_indicators->in_pkt_rate.mean_x100 = sf_log_next32(sample, "In Packet rate: Mean");
    dst_icmp_indicators->in_pkt_rate.variance_x100 = sf_log_next32(sample, "In Packet rate: Variance");
    dst_icmp_indicators->in_pkt_rate.min_x100 = sf_log_next32(sample, "In Packet rate: Min");
    dst_icmp_indicators->in_pkt_rate.nonzero_min_x100 = sf_log_next32(sample, "In Packet rate: Nonzero Min");
    dst_icmp_indicators->in_pkt_rate.max_x100 = sf_log_next32(sample, "In Packet rate: Max");

    dst_icmp_indicators->in_byte_over_out_byte.mean_x100 = sf_log_next32(sample, "In byte over Out byte: Mean");
    dst_icmp_indicators->in_byte_over_out_byte.variance_x100 = sf_log_next32(sample, "In byte over Out byte: Variance");
    dst_icmp_indicators->in_byte_over_out_byte.min_x100 = sf_log_next32(sample, "In byte over Out byte: Min");
    dst_icmp_indicators->in_byte_over_out_byte.nonzero_min_x100 = sf_log_next32(sample, "In byte over Out byte: Nonzero Min");
    dst_icmp_indicators->in_byte_over_out_byte.max_x100 = sf_log_next32(sample, "In byte over Out byte: Max");

    dst_icmp_indicators->pkt_drop_rate.mean_x100 = sf_log_next32(sample, "Pkt Drop Rate: Mean");
    dst_icmp_indicators->pkt_drop_rate.variance_x100 = sf_log_next32(sample, "Pkt Drop Rate: Variance");
    dst_icmp_indicators->pkt_drop_rate.min_x100 = sf_log_next32(sample, "Pkt Drop Rate: Min");
    dst_icmp_indicators->pkt_drop_rate.nonzero_min_x100 = sf_log_next32(sample, "Pkt Drop Rate: Nonzero Min");
    dst_icmp_indicators->pkt_drop_rate.max_x100 = sf_log_next32(sample, "Pkt Drop Rate: Max");

    dst_icmp_indicators->pkt_drop_recv_ratio.mean_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Mean");
    dst_icmp_indicators->pkt_drop_recv_ratio.variance_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Variance");
    dst_icmp_indicators->pkt_drop_recv_ratio.min_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Min");
    dst_icmp_indicators->pkt_drop_recv_ratio.nonzero_min_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Nonzero Min");
    dst_icmp_indicators->pkt_drop_recv_ratio.max_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Max");

}

static void readCounters_DDOS_DST_OTHER_INDICATORS(SFSample *sample)
{

    sflow_ddos_dst_other_indicators_t *dst_other_indicators = &(sample->ddos.ddos_dst_other_indicators);
    dst_other_indicators->seq_num  = sf_log_next32(sample, "Sequence #:");
    dst_other_indicators->num_data_points = sf_log_next16(sample, "Num Data Points:");
    dst_other_indicators->elapsed_sec = sf_log_next16(sample, "Elapsed sec:");

    dst_other_indicators->in_pkt_rate.mean_x100 = sf_log_next32(sample, "In Packet rate: Mean");
    dst_other_indicators->in_pkt_rate.variance_x100 = sf_log_next32(sample, "In Packet rate: Variance");
    dst_other_indicators->in_pkt_rate.min_x100 = sf_log_next32(sample, "In Packet rate: Min");
    dst_other_indicators->in_pkt_rate.nonzero_min_x100 = sf_log_next32(sample, "In Packet rate: Nonzero Min");
    dst_other_indicators->in_pkt_rate.max_x100 = sf_log_next32(sample, "In Packet rate: Max");

    dst_other_indicators->in_frag_rate.mean_x100 = sf_log_next32(sample, "In Frag rate: Mean");
    dst_other_indicators->in_frag_rate.variance_x100 = sf_log_next32(sample, "In Frag rate: Variance");
    dst_other_indicators->in_frag_rate.min_x100 = sf_log_next32(sample, "In Frag rate: Min");
    dst_other_indicators->in_frag_rate.nonzero_min_x100 = sf_log_next32(sample, "In Frag rate: Nonzero Min");
    dst_other_indicators->in_frag_rate.max_x100 = sf_log_next32(sample, "In Frag rate: Max");

    dst_other_indicators->in_byte_over_out_byte.mean_x100 = sf_log_next32(sample, "In byte over Out byte: Mean");
    dst_other_indicators->in_byte_over_out_byte.variance_x100 = sf_log_next32(sample, "In byte over Out byte: Variance");
    dst_other_indicators->in_byte_over_out_byte.min_x100 = sf_log_next32(sample, "In byte over Out byte: Min");
    dst_other_indicators->in_byte_over_out_byte.nonzero_min_x100 = sf_log_next32(sample, "In byte over Out byte: Nonzero Min");
    dst_other_indicators->in_byte_over_out_byte.max_x100 = sf_log_next32(sample, "In byte over Out byte: Max");

    dst_other_indicators->pkt_drop_rate.mean_x100 = sf_log_next32(sample, "Pkt Drop Rate: Mean");
    dst_other_indicators->pkt_drop_rate.variance_x100 = sf_log_next32(sample, "Pkt Drop Rate: Variance");
    dst_other_indicators->pkt_drop_rate.min_x100 = sf_log_next32(sample, "Pkt Drop Rate: Min");
    dst_other_indicators->pkt_drop_rate.nonzero_min_x100 = sf_log_next32(sample, "Pkt Drop Rate: Nonzero Min");
    dst_other_indicators->pkt_drop_rate.max_x100 = sf_log_next32(sample, "Pkt Drop Rate: Max");

    dst_other_indicators->pkt_drop_recv_ratio.mean_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Mean");
    dst_other_indicators->pkt_drop_recv_ratio.variance_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Variance");
    dst_other_indicators->pkt_drop_recv_ratio.min_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Min");
    dst_other_indicators->pkt_drop_recv_ratio.nonzero_min_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Nonzero Min");
    dst_other_indicators->pkt_drop_recv_ratio.max_x100 = sf_log_next32(sample, "Pkt Drop / Pkt Rcvd: Max");

}


static void readCounters_DDOS_HTTP_COUNTER(SFSample *sample, sflow_ddos_http_ext_counters_t *http)
{
    int len = 0;
    long tstamp = time(NULL);
    char tbuf [200];
    char buf [50];

    sprintf (tbuf, "agent=%08x\n", htonl(sample->agent_addr.address.ip_v4.addr));

    populate_sflow_struct_u64(sample, (void *)http, sizeof(sflow_ddos_http_ext_counters_t));

    len += sprintf (tsdb_buff + len, "put global_http_other_drop %lu %lu %s", tstamp, http->ddos_policy_violation + http->challenge_ud_sent + http->challenge_js_sent, tbuf);

    int ret = opentsdb_simple_connect(tsdb_buff);

    sf_log_u64(http->ofo_timer_expired, "OFO Timer Expired:");
    sf_log_u64(http->partial_hdr, "Partial Header:");
    sf_log_u64(http->ofo, "Out of Order Packets:");
    sf_log_u64(http->retrans_fin, "TCP FIN Retransmit:");
    sf_log_u64(http->retrans_rst, "TCP RST Retransmit:");
    sf_log_u64(http->retrans_push, "TCP PSH Retransmit:");
    sf_log_u64(http->retrans, "TCP Retransmit:");
    sf_log_u64(http->chunk_bad, "Bad HTTP Chunk:");
    sf_log_u64(http->chunk_sz_512, "Payload chunk size < 512:");
    sf_log_u64(http->chunk_sz_1k, "Payload chunk size < 1K:");
    sf_log_u64(http->chunk_sz_2k, "Payload chunk size < 2K:");
    sf_log_u64(http->chunk_sz_4k, "Payload chunk size < 4K:");
    sf_log_u64(http->chunk_sz_gt_4k, "Payload chunk size > 4K:");
    sf_log_u64(http->neg_rsp_remain, "Negative response remain:");
    sf_log_u64(http->too_many_headers, "Too many HTTP Headers:");
    sf_log_u64(http->header_name_too_long, "HTTP Header Name too long:");
    sf_log_u64(http->http11, "Request HTTP 1.1:");
    sf_log_u64(http->http10, "Request HTTP 1.0:");
    sf_log_u64(http->get, "Request method GET:");
    sf_log_u64(http->head, "Request method HEAD:");
    sf_log_u64(http->put, "Request method PUT:");
    sf_log_u64(http->post, "Request method POST:");
    sf_log_u64(http->trace, "Request method TRACE:");
    sf_log_u64(http->options, "Request method OPTIONS:");
    sf_log_u64(http->connect, "Request method CONNECT:");
    sf_log_u64(http->del, "Request method DELETE:");
    sf_log_u64(http->unknown, "Request method UNKNOWN:");
    sf_log_u64(http->line_too_long, "Line too long:");
    sf_log_u64(http->req_content_len, "Request Content-Length:");
    sf_log_u64(http->rsp_chunk, "Response Chunk:");
    sf_log_u64(http->parsereq_fail, "Parse request failure:");
    sf_log_u64(http->request, "Request:");
    sf_log_u64(http->neg_req_remain, "Negative request remain:");
    sf_log_u64(http->client_rst, "Client TCP RST recv:");
    sf_log_u64(http->req_retrans, "Request retransmit:");
    sf_log_u64(http->req_ofo, "Request OFO:");
    sf_log_u64(http->invalid_header, "Invalid HTTP Header:");
    sf_log_u64(http->ddos_policy_violation, "Policy violation:");
    sf_log_u64(http->lower_than_mss_exceed, "Fail min payload exceeded:");
    sf_log_u64(http->dst_req_rate_exceed, "Dst request rate exceeded:");
    sf_log_u64(http->src_req_rate_exceed, "Src request rate exceeded:");
    sf_log_u64(http->req_processed, "Packets processed:");
    sf_log_u64(http->new_syn, "TCP SYN:");
    sf_log_u64(http->policy_drop, "Policy Drop:");
    sf_log_u64(http->error_condition, "Error condition:");
    sf_log_u64(http->ofo_queue_exceed, "OFO queue exceeded:");
    sf_log_u64(http->alloc_fail, "Alloc Failed:");
    sf_log_u64(http->alloc_hdr_fail, "Alloc header Failed:");
    sf_log_u64(http->invalid_hdr_name, "Invalid HTTP header Name:");
    sf_log_u64(http->invalid_hdr_val, "Invalid HTTP header Value:");
    sf_log_u64(http->challenge_ud_fail, "Challenge URL redirect Fail:");
    sf_log_u64(http->challenge_js_fail, "Challenge javascript Fail:");
    sf_log_u64(http->challenge_fail, "challenge fail:");
    sf_log_u64(http->challenge_js_sent, "Challenge javascript Sent:");
    sf_log_u64(http->challenge_ud_sent, "Challenge URL redirect Sent:");
    sf_log_u64(http->malform_bad_chunk, "Malform bad Chunk:");
    sf_log_u64(http->malform_content_len_too_long, "Malform content len too long:");
    sf_log_u64(http->malform_too_many_headers, "Malform too many headers:");
    sf_log_u64(http->malform_header_name_too_long, "Malform header name too long:");
    sf_log_u64(http->malform_line_too_long, "Malform line too long:");
    sf_log_u64(http->malform_req_line_too_long, "Malform req line too long:");
    sf_log_u64(http->window_small, "Window size small:");
    sf_log_u64(http->window_small_drop, "Window size small Drop:");
    sf_log_u64(http->use_hdr_ip_as_source, "Use ip in hdr as src:");
    sf_log_u64(http->agent_filter_match, "Agent filter matched :");
    sf_log_u64(http->agent_filter_blacklist, "Agent filter blacklisted:");
    sf_log_u64(http->referer_filter_match, "Referer filter matched:");
    sf_log_u64(http->referer_filter_blacklist, "Referer filter blacklisted:");
    sf_log_u64(http->http_idle_timeout, "HTTP Idle Timeout:");
    sf_log_u64(http->hps_rsp_10, "Response HTTP 1.0:");
    sf_log_u64(http->hps_rsp_11, "Response HTTP 1.1:");
    sf_log_u64(http->hps_req_sz_1k, "Request payload Size < 1K:");
    sf_log_u64(http->hps_req_sz_2k, "Request payload Size < 2K:");
    sf_log_u64(http->hps_req_sz_4k, "Request payload Size < 4K:");
    sf_log_u64(http->hps_req_sz_8k, "Request payload Size < 8K:");
    sf_log_u64(http->hps_req_sz_16k, "Request payload Size < 16K:");
    sf_log_u64(http->hps_req_sz_32k, "Request payload Size < 32K:");
    sf_log_u64(http->hps_req_sz_64k, "Request payload Size < 64K:");
    sf_log_u64(http->hps_req_sz_256k, "Request payload Size < 256K:");
    sf_log_u64(http->hps_req_sz_256k_plus, "Request payload Size > 256K:");
    sf_log_u64(http->hps_rsp_sz_1k, "Response payload Size < 1K:");
    sf_log_u64(http->hps_rsp_sz_2k, "Response payload Size < 2K:");
    sf_log_u64(http->hps_rsp_sz_4k, "Response payload Size < 4K:");
    sf_log_u64(http->hps_rsp_sz_8k, "Response payload Size < 8K:");
    sf_log_u64(http->hps_rsp_sz_16k, "Response payload Size < 16K:");
    sf_log_u64(http->hps_rsp_sz_32k, "Response payload Size < 32K:");
    sf_log_u64(http->hps_rsp_sz_64k, "Response payload Size < 64K:");
    sf_log_u64(http->hps_rsp_sz_256k, "Response payload Size < 256K:");
    sf_log_u64(http->hps_rsp_sz_256k_plus, "Response payload Size > 256K:");
    sf_log_u64(http->hps_rsp_status_1xx, "Status code 1XX:");
    sf_log_u64(http->hps_rsp_status_2xx, "Status code 2XX:");
    sf_log_u64(http->hps_rsp_status_3xx, "Status code 3XX:");
    sf_log_u64(http->hps_rsp_status_4xx, "Status code 4XX:");
    sf_log_u64(http->hps_rsp_status_5xx, "Status code 5XX:");
    sf_log_u64(http->hps_rsp_status_504_AX, "Status code 504 AX-gen:");
    sf_log_u64(http->hps_rsp_status_6xx, "Status code 6XX:");
    sf_log_u64(http->hps_rsp_status_unknown, "Status code unknown:");
    sf_log_u64(http->header_processing_time_0, "Header processing time < 1s:");
    sf_log_u64(http->header_processing_time_1, "Header processing time < 10s:");
    sf_log_u64(http->header_processing_time_2, "Header processing time < 30s:");
    sf_log_u64(http->header_processing_time_3, "Header processing time >= 30s:");
    sf_log_u64(http->header_processing_incomplete, "Header processing incomplete:");
    sf_log_u64(http->hps_server_rst, "Server TCP RST recv:");
    sf_log_u64(http->filter_hdr_match, "Dst Filter Hdr Match:");
    sf_log_u64(http->filter_hdr_not_match, "Dst Filter Hdr Not Match:");
    sf_log_u64(http->filter_hdr_action_blacklist, "Dst Filter Hdr Action BL:");
    sf_log_u64(http->filter_hdr_action_drop, "Dst Filter Hdr Action Drop:");
    sf_log_u64(http->filter_hdr_action_default_pass, "Dst Filter Hdr Action Default Pass:");
    sf_log_u64(http->dst_post_rate_exceed, "Dst post rate exceeded:");
    sf_log_u64(http->src_post_rate_exceed, "Src post rate exceeded:");
    sf_log_u64(http->dst_resp_rate_exceed, "Dst resp rate exceeded:");
    sf_log_u64(http->filter_hdr_action_whitelist, "Dst Filter Hdr Action WL:");
    sf_log_u64(http->src_filter_hdr_match, "Src Filter Hdr Match:");
    sf_log_u64(http->src_filter_hdr_not_match, "Src Filter Hdr Not Match:");
    sf_log_u64(http->src_filter_hdr_action_blacklist, "Src Filter Hdr Action BL:");
    sf_log_u64(http->src_filter_hdr_action_drop, "Src Filter Hdr Action Drop:");
    sf_log_u64(http->src_filter_hdr_action_default_pass, "Src Filter Hdr Action Default Pass:");
    sf_log_u64(http->src_filter_hdr_action_whitelist, "Src Filter Hdr Action WL:");
    sf_log_u64(http->src_dst_filter_hdr_match, "SrcDst Filter Hdr Match:");
    sf_log_u64(http->src_dst_filter_hdr_not_match, "SrcDst Filter Hdr Not Match:");
    sf_log_u64(http->src_dst_filter_hdr_action_blacklist, "SrcDst Filter Hdr Action BL:");
    sf_log_u64(http->src_dst_filter_hdr_action_drop, "SrcDst Filter Hdr Action Drop:");
    sf_log_u64(http->src_dst_filter_hdr_action_default_pass, "SrcDst Filter Hdr Action Default Pass:");
    sf_log_u64(http->src_dst_filter_hdr_action_whitelist, "SrcDst Filter Hdr Action WL:");

}

static void readCounters_DDOS_HTTP_T2_COUNTER(SFSample *sample, sflow_ddos_ip_counter_http_t2_data_t *http_t2)
{
    int len = 0;
    long tstamp = time(NULL);
    char tbuf [200];

    populate_sflow_struct_u64(sample, (void *)http_t2, sizeof(sflow_ddos_ip_counter_http_t2_data_t));

    if (sample->ddos.http_perip.common.ip_type == 1) {
        sprintf (tbuf, "ip=%08x prefix=%d port=%d agent=%08x type=%x\n",
                    sample->ddos.http_perip.common.ip_addr,
                    sample->ddos.http_perip.common.subnet_mask,
                    sample->ddos.http_perip.http.port,
                    htonl(sample->agent_addr.address.ip_v4.addr),
                    sample->ddos.http_perip.common.ip_type);
    } else {
        unsigned char *i;
        i = sample->ddos.http_perip.common.ip6_addr.s6_addr;

        sprintf (tbuf, "ip=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x prefix=%d port=%d agent=%08x\n",
                    i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8],
                    i[9], i[10], i[11], i[12], i[13], i[14], i[15],
                    sample->ddos.http_perip.common.subnet_mask, sample->ddos.http_perip.http.port,
                    htonl(sample->agent_addr.address.ip_v4.addr));
    }

    sf_log_u64(http_t2->ofo_timer_expired, "OFO Timer Expired:");
    sf_log_u64(http_t2->partial_hdr, "Partial Header:");
    sf_log_u64(http_t2->ofo, "Out of Order Packets:");
    sf_log_u64(http_t2->retrans_fin, "TCP FIN Retransmit:");
    sf_log_u64(http_t2->retrans_rst, "TCP RST Retransmit:");
    sf_log_u64(http_t2->retrans_push, "TCP PSH Retransmit:");
    sf_log_u64(http_t2->retrans, "TCP Retransmit:");
    sf_log_u64(http_t2->chunk_bad, "Bad HTTP Chunk:");
    sf_log_u64(http_t2->chunk_sz_512, "Payload chunk size < 512:");
    sf_log_u64(http_t2->chunk_sz_1k, "Payload chunk size < 1K:");
    sf_log_u64(http_t2->chunk_sz_2k, "Payload chunk size < 2K:");
    sf_log_u64(http_t2->chunk_sz_4k, "Payload chunk size < 4K:");
    sf_log_u64(http_t2->chunk_sz_gt_4k, "Payload chunk size > 4K:");
    sf_log_u64(http_t2->neg_rsp_remain, "Negative response remain:");
    sf_log_u64(http_t2->too_many_headers, "Too many HTTP Headers:");
    sf_log_u64(http_t2->header_name_too_long, "HTTP Header Name too long:");
    sf_log_u64(http_t2->http11, "Request HTTP 1.1:");
    sf_log_u64(http_t2->http10, "Request HTTP 1.0:");
    sf_log_u64(http_t2->get, "Request method GET:");
    sf_log_u64(http_t2->head, "Request method HEAD:");
    sf_log_u64(http_t2->put, "Request method PUT:");
    sf_log_u64(http_t2->post, "Request method POST:");
    sf_log_u64(http_t2->trace, "Request method TRACE:");
    sf_log_u64(http_t2->options, "Request method OPTIONS:");
    sf_log_u64(http_t2->connect, "Request method CONNECT:");
    sf_log_u64(http_t2->del, "Request method DELETE:");
    sf_log_u64(http_t2->unknown, "Request method UNKNOWN:");
    sf_log_u64(http_t2->line_too_long, "Line too long:");
    sf_log_u64(http_t2->req_content_len, "Request Content-Length:");
    sf_log_u64(http_t2->rsp_chunk, "Response Chunk:");
    sf_log_u64(http_t2->parsereq_fail, "Parse request failure:");
    sf_log_u64(http_t2->request, "Request:");
    sf_log_u64(http_t2->neg_req_remain, "Negative request remain:");
    sf_log_u64(http_t2->client_rst, "Client TCP RST recv:");
    sf_log_u64(http_t2->req_retrans, "Request retransmit:");
    sf_log_u64(http_t2->req_ofo, "Request OFO:");
    sf_log_u64(http_t2->invalid_header, "Invalid HTTP Header:");
    sf_log_u64(http_t2->ddos_policy_violation, "Policy violation:");
    sf_log_u64(http_t2->lower_than_mss_exceed, "Fail min payload exceeded:");
    sf_log_u64(http_t2->dst_req_rate_exceed, "Dst request rate exceeded:");
    sf_log_u64(http_t2->src_req_rate_exceed, "Src request rate exceeded:");
    sf_log_u64(http_t2->req_processed, "Packets processed:");
    sf_log_u64(http_t2->new_syn, "TCP SYN:");
    sf_log_u64(http_t2->policy_drop, "Policy Drop:");
    sf_log_u64(http_t2->error_condition, "Error condition:");
    sf_log_u64(http_t2->ofo_queue_exceed, "OFO queue exceeded:");
    sf_log_u64(http_t2->alloc_fail, "Alloc Failed:");
    sf_log_u64(http_t2->alloc_hdr_fail, "Alloc header Failed:");
    sf_log_u64(http_t2->get_line_fail, "Get line Failed:");
    sf_log_u64(http_t2->invalid_hdr_name, "Invalid HTTP header Name:");
    sf_log_u64(http_t2->invalid_hdr_val, "Invalid HTTP header Value:");
    sf_log_u64(http_t2->challenge_ud_fail, "Challenge URL redirect Fail:");
    sf_log_u64(http_t2->challenge_js_fail, "Challenge javascript Fail:");
    sf_log_u64(http_t2->challenge_fail, "challenge fail:");
    sf_log_u64(http_t2->challenge_js_sent, "Challenge javascript Sent:");
    sf_log_u64(http_t2->challenge_ud_sent, "Challenge URL redirect Sent:");
    sf_log_u64(http_t2->malform_bad_chunk, "Malform bad Chunk:");
    sf_log_u64(http_t2->malform_content_len_too_long, "Malform content len too long:");
    sf_log_u64(http_t2->malform_too_many_headers, "Malform too many headers:");
    sf_log_u64(http_t2->malform_header_name_too_long, "Malform header name too long:");
    sf_log_u64(http_t2->malform_line_too_long, "Malform line too long:");
    sf_log_u64(http_t2->malform_req_line_too_long, "Malform req line too long:");
    sf_log_u64(http_t2->window_small, "Window size small:");
    sf_log_u64(http_t2->window_small_drop, "Window size small Drop:");
    sf_log_u64(http_t2->use_hdr_ip_as_source, "Use ip in hdr as src:");
    sf_log_u64(http_t2->agent_filter_match, "Agent filter matched :");
    sf_log_u64(http_t2->agent_filter_blacklist, "Agent filter blacklisted:");
    sf_log_u64(http_t2->referer_filter_match, "Referer filter matched:");
    sf_log_u64(http_t2->referer_filter_blacklist, "Referer filter blacklisted:");
    sf_log_u64(http_t2->http_idle_timeout, "HTTP Idle Timeout:");
    sf_log_u64(http_t2->header_processing_time_0, "Header processing time < 1s:");
    sf_log_u64(http_t2->header_processing_time_1, "Header processing time < 10s:");
    sf_log_u64(http_t2->header_processing_time_2, "Header processing time < 30s:");
    sf_log_u64(http_t2->header_processing_time_3, "Header processing time >= 30s:");
    sf_log_u64(http_t2->header_processing_incomplete, "Header processing incomplete:");
    sf_log_u64(http_t2->req_sz_1k, "Request payload Size < 1K:");
    sf_log_u64(http_t2->req_sz_2k, "Request payload Size < 2K:");
    sf_log_u64(http_t2->req_sz_4k, "Request payload Size < 4K:");
    sf_log_u64(http_t2->req_sz_8k, "Request payload Size < 8K:");
    sf_log_u64(http_t2->req_sz_16k, "Request payload Size < 16K:");
    sf_log_u64(http_t2->req_sz_32k, "Request payload Size < 32K:");
    sf_log_u64(http_t2->req_sz_64k, "Request payload Size < 64K:");
    sf_log_u64(http_t2->req_sz_256k, "Request payload Size < 256K:");
    sf_log_u64(http_t2->req_sz_gt_256k, "Request payload Size > 256K:");
    sf_log_u64(http_t2->filter_hdr_match, "Filter Hdr Match:");
    sf_log_u64(http_t2->filter_hdr_not_match, "Filter Hdr Not Match:");
    sf_log_u64(http_t2->filter_hdr_action_blacklist, "Filter Hdr Action BL:");
    sf_log_u64(http_t2->filter_hdr_action_drop, "Filter Hdr Action Drop:");
    sf_log_u64(http_t2->filter_hdr_action_default_pass, "Filter Hdr Action Default Pass:");
    sf_log_u64(http_t2->resp_code_1xx, "HTTP Status Code 1XX:");
    sf_log_u64(http_t2->resp_code_2xx, "HTTP Status Code 2XX:");
    sf_log_u64(http_t2->resp_code_3xx, "HTTP Status Code 3XX:");
    sf_log_u64(http_t2->resp_code_4xx, "HTTP Status Code 4XX:");
    sf_log_u64(http_t2->resp_code_5xx, "HTTP Status Code 5XX:");
    sf_log_u64(http_t2->resp_code_other, "HTTP Status Code OTHER:");
    sf_log_u64(http_t2->dst_post_rate_exceed, "Dst post rate exceeded:");
    sf_log_u64(http_t2->src_post_rate_exceed, "Src post rate exceeded:");
    sf_log_u64(http_t2->dst_resp_rate_exceed, "Dst response rate exceeded:");
    sf_log_u64(http_t2->filter_hdr_action_whitelist, "Filter Hdr Action WL:");
    sf_log_u64(http_t2->filter_hdr_match, "Filter1 Hdr Match:");
    sf_log_u64(http_t2->filter_hdr_match, "Filter2 Hdr Match:");
    sf_log_u64(http_t2->filter_hdr_match, "Filter3 Hdr Match:");
    sf_log_u64(http_t2->filter_hdr_match, "Filter4 Hdr Match:");
    sf_log_u64(http_t2->filter_hdr_match, "Filter5 Hdr Match:");
    sf_log_u64(http_t2->filter_hdr_match, "Filter None Hdr Match:");

    sf_log_u64(http_t2->src_partial_hdr, "Src Partial Header:");
    sf_log_u64(http_t2->src_parsereq_fail, "Src Parse request failure:");
    sf_log_u64(http_t2->src_neg_req_remain, "Src Negative request remain:");
    sf_log_u64(http_t2->src_ddos_policy_violation, "Src Policy violation:");
    sf_log_u64(http_t2->src_lower_than_mss_exceed, "Src Fail min payload exceeded:");
    sf_log_u64(http_t2->src_policy_drop, "Src Policy Drop:");
    sf_log_u64(http_t2->src_malform_bad_chunk, "Src Malform bad Chunk:");
    sf_log_u64(http_t2->src_challenge_ud_fail, "Src Challenge URL redirect Fail:");
    sf_log_u64(http_t2->src_challenge_js_fail, "Src Challenge javascript Fail:");
    sf_log_u64(http_t2->src_challenge_fail, "Src challenge fail:");
    sf_log_u64(http_t2->src_window_small_drop, "Src Window size small Drop:");
    sf_log_u64(http_t2->src_filter_hdr_action_drop, "Src Filter Hdr Action Drop:");
    sf_log_u64(http_t2->src_challenge_js_sent, "Src Challenge javascript Sent:");
    sf_log_u64(http_t2->src_challenge_ud_sent, "Src Challenge URL redirect Sent:");

    http_dropped = http_t2->src_challenge_ud_fail + http_t2->src_challenge_js_fail + http_t2->src_policy_drop + http_t2->src_ddos_policy_violation + http_t2->src_challenge_ud_sent + http_t2->src_challenge_js_sent; 

    http_challenge_sent = http_t2->challenge_ud_sent + http_t2->challenge_js_sent + http_t2->src_challenge_ud_sent + http_t2->src_challenge_js_sent + http_t2->challenge_ud_fail + http_t2->challenge_js_fail + http_t2->src_challenge_ud_fail + http_t2->src_challenge_js_fail;

    dst_http_challenge_sent = http_t2->challenge_js_sent + http_t2->challenge_ud_sent + http_t2->challenge_ud_fail + http_t2->challenge_js_fail;

    http_excl_src_dropped = http_t2->src_policy_drop;

    len += sprintf (tsdb_buff + len, "put http_dropped %lu %lu %s", tstamp, http_dropped, tbuf);
    len += sprintf (tsdb_buff + len, "put http_challenge_sent %lu %lu %s", tstamp, http_challenge_sent, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_http_challenge_sent %lu %lu %s", tstamp, dst_http_challenge_sent, tbuf);
    len += sprintf (tsdb_buff + len, "put http_policy_violation %lu %lu %s", tstamp, http_t2->ddos_policy_violation + http_t2->src_ddos_policy_violation, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_http_policy_violation %lu %lu %s", tstamp, http_t2->ddos_policy_violation, tbuf);
    len += sprintf (tsdb_buff + len, "put http_excl_src_dropped %lu %lu %s", tstamp, http_excl_src_dropped, tbuf);
    int ret = opentsdb_simple_connect(tsdb_buff);
}

static void readCounters_DDOS_UDP_T2_COUNTER(SFSample *sample, sflow_ddos_ip_counter_udp_t2_data_t *udp_t2)
{

    populate_sflow_struct_u64(sample, (void *)udp_t2, sizeof(sflow_ddos_ip_counter_udp_t2_data_t));

    sf_log_u64(udp_t2->filter1_match, "Filter1 Match:");
    sf_log_u64(udp_t2->filter2_match, "Filter2 Match:");
    sf_log_u64(udp_t2->filter3_match, "Filter3 Match:");
    sf_log_u64(udp_t2->filter4_match, "Filter4 Match:");
    sf_log_u64(udp_t2->filter5_match, "Filter5 Match:");
    sf_log_u64(udp_t2->filter_none_match, "Filter None Match:");

}

static void readCounters_DDOS_TCP_T2_COUNTER(SFSample *sample, sflow_ddos_ip_counter_tcp_t2_data_t *tcp_t2)
{

    populate_sflow_struct_u64(sample, (void *)tcp_t2, sizeof(sflow_ddos_ip_counter_tcp_t2_data_t));

    sf_log_u64(tcp_t2->filter1_match, "Filter1 Match:");
    sf_log_u64(tcp_t2->filter2_match, "Filter2 Match:");
    sf_log_u64(tcp_t2->filter3_match, "Filter3 Match:");
    sf_log_u64(tcp_t2->filter4_match, "Filter4 Match:");
    sf_log_u64(tcp_t2->filter5_match, "Filter5 Match:");
    sf_log_u64(tcp_t2->filter_none_match, "Filter None Match:");

}

static void readCounters_DDOS_OTHER_T2_COUNTER(SFSample *sample, sflow_ddos_ip_counter_other_t2_data_t *other_t2)
{

    populate_sflow_struct_u64(sample, (void *)other_t2, sizeof(sflow_ddos_ip_counter_other_t2_data_t));

    sf_log_u64(other_t2->filter1_match, "Filter1 Match:");
    sf_log_u64(other_t2->filter2_match, "Filter2 Match:");
    sf_log_u64(other_t2->filter3_match, "Filter3 Match:");
    sf_log_u64(other_t2->filter4_match, "Filter4 Match:");
    sf_log_u64(other_t2->filter5_match, "Filter5 Match:");
    sf_log_u64(other_t2->filter_none_match, "Filter None Match:");

}

static void readCounters_DDOS_SSL_L4_T2_COUNTER(SFSample *sample, sflow_ddos_ip_counter_ssl_l4_t2_data_t *ssl_l4_t2)
{

    int len = 0;
    long tstamp = time(NULL);
    char tbuf [200];

    populate_sflow_struct_u64(sample, (void *)ssl_l4_t2, sizeof(sflow_ddos_ip_counter_ssl_l4_t2_data_t));

    if (sample->ddos.ssl_l4_perip.common.ip_type == 1) {
        sprintf (tbuf, "ip=%08x prefix=%d port=%d agent=%08x type=%x\n",
                    sample->ddos.ssl_l4_perip.common.ip_addr,
                    sample->ddos.ssl_l4_perip.common.subnet_mask,
                    sample->ddos.ssl_l4_perip.ssl_l4.port,
                    htonl(sample->agent_addr.address.ip_v4.addr),
                    sample->ddos.ssl_l4_perip.common.ip_type);
    } else {
        unsigned char *i;
        i = sample->ddos.ssl_l4_perip.common.ip6_addr.s6_addr;

        sprintf (tbuf, "ip=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x prefix=%d  port=%d agent=%08x\n",
                    i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8],
                    i[9], i[10], i[11], i[12], i[13], i[14], i[15],
                    sample->ddos.ssl_l4_perip.common.subnet_mask,
                    sample->ddos.ssl_l4_perip.ssl_l4.port,
                    htonl(sample->agent_addr.address.ip_v4.addr));
    }

    sf_log_u64(ssl_l4_t2->ssll4_policy_reset, "Policy Reset:");
    sf_log_u64(ssl_l4_t2->ssll4_policy_drop, "Policy Drop:");
    sf_log_u64(ssl_l4_t2->ssll4_drop_packet, "Drop packets:");
    sf_log_u64(ssl_l4_t2->ssll4_er_condition, "Error condition:");
    sf_log_u64(ssl_l4_t2->ssll4_processed, "Processed:");
    sf_log_u64(ssl_l4_t2->ssll4_new_syn, "New TCP SYN:");
    sf_log_u64(ssl_l4_t2->ssll4_is_ssl3, "SSL v3:");
    sf_log_u64(ssl_l4_t2->ssll4_is_tls1_1, "TLS v1.0:");
    sf_log_u64(ssl_l4_t2->ssll4_is_tls1_2, "TLS v1.1:");
    sf_log_u64(ssl_l4_t2->ssll4_is_tls1_3, "TLS v1.2:");
    sf_log_u64(ssl_l4_t2->ssll4_is_renegotiation, "SSL Renegotiation:");
    sf_log_u64(ssl_l4_t2->ssll4_renegotiation_exceed, "Renegotiation exceeded:");
    sf_log_u64(ssl_l4_t2->ssll4_is_dst_req_rate_exceed, "Dst rate exceeded:");
    sf_log_u64(ssl_l4_t2->ssll4_is_src_req_rate_exceed, "Src rate exceeded:");
    sf_log_u64(ssl_l4_t2->ssll4_do_auth_handshake, "Do Auth Handshake:");
    sf_log_u64(ssl_l4_t2->ssll4_reset_for_handshake, "Reset While Others in HS:");
    sf_log_u64(ssl_l4_t2->ssll4_handshake_timeout, "Auth handshake timeout:");
    sf_log_u64(ssl_l4_t2->ssll4_auth_handshake_ok, "Auth handshake success:");
    sf_log_u64(ssl_l4_t2->ssll4_auth_handshake_bl, "Auth handshake blacklisted:");

    sf_log_u64(ssl_l4_t2->src_ssll4_policy_drop, "Src Policy Drop:");
    sf_log_u64(ssl_l4_t2->src_ssll4_drop_packet, "Src Drop packets:");
    sf_log_u64(ssl_l4_t2->src_ssll4_renegotiation_exceed, "Src Renegotiation exceeded:");
    sf_log_u64(ssl_l4_t2->src_ssll4_auth_handshake_bl, "Src Auth handskake blacklisted:");
    sf_log_u64(ssl_l4_t2->src_ssll4_policy_reset, "Src Policy Reset:");

    len += sprintf (tsdb_buff + len, "put ssl_dropped %lu %lu %s", tstamp, ssl_l4_t2->src_ssll4_drop_packet + ssl_l4_t2->src_ssll4_policy_reset, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_ssl_dropped %lu %lu %s", tstamp, ssl_l4_t2->ssll4_drop_packet + ssl_l4_t2->ssll4_policy_reset, tbuf);
    int ret = opentsdb_simple_connect(tsdb_buff);

}

static void readCounters_DDOS_IP_COUNTER_COMMON(SFSample *sample, sflow_ddos_ip_counter_common_t *hdr)
{
    uint32_t table_type = getData32(sample);
    sf_log("%-35s %s[%u]\n", "Table Type:", ddos_table_type[table_type], table_type);
    hdr->table_type = table_type;
    uint32_t ip_type = getData32(sample);
    sf_log("%-35s %s[%u]\n", "IP Type:", ddos_ip_type[ip_type], ip_type);
    hdr->ip_type = ip_type;
    //sf_log("%s %u\n", "bwlist", bwlist);
    hdr->static_entry = sf_log_next32(sample, "Static:");
    SFLAddress addr;
    char buf[50];
    getDDoSAddress(sample, ip_type, &addr);
    if (ip_type == 1) {
        hdr->ip_addr = addr.address.ip_v4.addr;
    } else {
        memcpy(&hdr->ip6_addr, addr.address.ip_v6.addr, 16);
    }
    sf_log("%-35s %-20s\n", "Address:", printAddress_no_conversion(&addr, buf, 50));
    getDDoSAddress(sample, ip_type, &addr);
    if (ip_type == 1) {
        hdr->dst_ip_addr = addr.address.ip_v4.addr;
    } else {
        memcpy(&hdr->dst_ip6_addr, addr.address.ip_v6.addr, 16);
    }
    if (table_type == 2) {
        sf_log("Dst Address: %s\n", printAddress_no_conversion(&addr, buf, 50));
    }

    hdr->subnet_mask = sf_log_next16(sample, "Subnet/Prefix:");
    hdr->age = sf_log_next16(sample, "Age:");
}

static void readCounters_DDOS_HTTP_IP_COUNTER(SFSample *sample)
{
    sample->ddos.http_perip.http.port = sf_log_next16(sample, "Port:");
    sample->ddos.http_perip.http.app_type = getData16(sample);
    if (sample->ddos.http_perip.http.app_type > DDOS_TOTAL_APP_TYPE_SIZE) {
        return;
    }
    sfl_log_ex_string_fmt((char *)ddos_proto_str[sample->ddos.http_perip.http.app_type], "App type:");
}

static void readCounters_DDOS_SSL_L4_IP_COUNTER(SFSample *sample)
{

    sample->ddos.ssl_l4_perip.ssl_l4.port = sf_log_next16(sample, "Port:");
    sample->ddos.ssl_l4_perip.ssl_l4.app_type = getData16(sample);
    if (sample->ddos.ssl_l4_perip.ssl_l4.app_type > DDOS_TOTAL_APP_TYPE_SIZE) {
        return;
    }
    sfl_log_ex_string_fmt((char *)ddos_proto_str[sample->ddos.ssl_l4_perip.ssl_l4.app_type], "App type:");
}

static void readCounters_DDOS_UDP_IP_COUNTER(SFSample *sample)
{

    sample->ddos.udp_perip.udp.port = sf_log_next16(sample, "Port:");
    sample->ddos.udp_perip.udp.app_type = getData16(sample);
    if (sample->ddos.udp_perip.udp.app_type > DDOS_TOTAL_APP_TYPE_SIZE) {
        return;
    }
    sfl_log_ex_string_fmt((char *)ddos_proto_str[sample->ddos.udp_perip.udp.app_type], "App type:");
}

static void readCounters_DDOS_TCP_IP_COUNTER(SFSample *sample)
{

    sample->ddos.tcp_perip.tcp.port = sf_log_next16(sample, "Port:");
    sample->ddos.tcp_perip.tcp.app_type = getData16(sample);
    if (sample->ddos.tcp_perip.tcp.app_type > DDOS_TOTAL_APP_TYPE_SIZE) {
        return;
    }
    sfl_log_ex_string_fmt((char *)ddos_proto_str[sample->ddos.tcp_perip.tcp.app_type], "App type:");
}

static void readCounters_DDOS_OTHER_IP_COUNTER(SFSample *sample)
{

    sample->ddos.other_perip.other.port = sf_log_next16(sample, "IP-Proto:");
    sample->ddos.other_perip.other.app_type = getData16(sample);
    if (sample->ddos.other_perip.other.app_type > DDOS_TOTAL_APP_TYPE_SIZE) {
        return;
    }
    sfl_log_ex_string_fmt((char *)ddos_proto_str[sample->ddos.other_perip.other.app_type], "App type:");
}

static void readCounters_DDOS_FPGA_ANOMALY_COUNTER(SFSample *sample)
{

    int len = 0;
    long tstamp = time(NULL);
    char tbuf [200];
    char buf [50];

    sprintf (tbuf, "agent=%08x\n", htonl(sample->agent_addr.address.ip_v4.addr));

    sflow_ddos_anomaly_counters_t *anomaly_t1 = &sample->ddos.anomaly;
    populate_sflow_struct_u64(sample, (void *)anomaly_t1, sizeof(sflow_ddos_anomaly_counters_t));

    packet_anomaly_dropped = anomaly_t1->land_attack_drop + anomaly_t1->empty_frag_drop + anomaly_t1->micro_frag_drop + anomaly_t1->ipv4_opt_drop + 
                             anomaly_t1->ip_frag_drop + anomaly_t1->bad_ip_hdr_len_drop + anomaly_t1->bad_ip_flags_drop + anomaly_t1->bad_ip_ttl_drop + 
                             anomaly_t1->no_ip_payload_drop + anomaly_t1->oversize_ip_pl_drop + anomaly_t1->bad_ip_pl_len_drop + anomaly_t1->bad_ip_frag_off_drop + 
                             anomaly_t1->bad_ip_csum_drop + anomaly_t1->icmp_pod_drop + anomaly_t1->tcp_bad_urg_off_drop + anomaly_t1->tcp_short_hdr_drop +
                             anomaly_t1->tcp_bad_ip_len_drop + anomaly_t1->tcp_null_flags_drop + anomaly_t1->tcp_null_scan_drop + anomaly_t1->tcp_syn_and_fin_drop +
                             anomaly_t1->tcp_xmas_flags_drop + anomaly_t1->tcp_xmas_scan_drop + anomaly_t1->tcp_syn_frag_drop + anomaly_t1->tcp_frag_header_drop +
                             anomaly_t1->tcp_bad_csum_drop + anomaly_t1->udp_short_hdr_drop + anomaly_t1->udp_bad_leng_drop + anomaly_t1->udp_kb_frag_drop + 
                             anomaly_t1->udp_port_lb_drop + anomaly_t1->udp_bad_csum_drop + anomaly_t1->runt_ip_hdr_drop + anomaly_t1->runt_tcpudp_hdr_drop +
                             anomaly_t1->tun_mismatch_drop + anomaly_t1->tcp_opt_err;

    len += sprintf(tsdb_buff + len, "put packet_anomaly_dropped %lu %lu %s", tstamp, packet_anomaly_dropped, tbuf);

    int ret = opentsdb_simple_connect(tsdb_buff);


    sf_log_u64(anomaly_t1->land_attack_drop, "Land attack Drop:");
    sf_log_u64(anomaly_t1->empty_frag_drop, "Empty frag Drop:");
    sf_log_u64(anomaly_t1->micro_frag_drop, "Micro frag Drop:");
    sf_log_u64(anomaly_t1->ipv4_opt_drop, "IPv4 opt Drop:");
    sf_log_u64(anomaly_t1->ip_frag_drop, "IP Frag Drop:");
    sf_log_u64(anomaly_t1->bad_ip_hdr_len_drop, "Bad IP hdr len Drop:");
    sf_log_u64(anomaly_t1->bad_ip_flags_drop, "Bad IP Flags Drop:");
    sf_log_u64(anomaly_t1->bad_ip_ttl_drop, "Bad IP TTL Drop:");
    sf_log_u64(anomaly_t1->no_ip_payload_drop, "No IP payload Drop:");
    sf_log_u64(anomaly_t1->oversize_ip_pl_drop, "Oversize IP payload Drop:");
    sf_log_u64(anomaly_t1->bad_ip_pl_len_drop, "Bad IP payload length Drop:");
    sf_log_u64(anomaly_t1->bad_ip_frag_off_drop, "Bad IP frag offset Drop:");
    sf_log_u64(anomaly_t1->bad_ip_csum_drop, "Bad IP Checksum Drop:");
    sf_log_u64(anomaly_t1->icmp_pod_drop, "ICMP ping of death Drop:");
    sf_log_u64(anomaly_t1->tcp_bad_urg_off_drop, "TCP Bad urg off Drop:");
    sf_log_u64(anomaly_t1->tcp_short_hdr_drop, "TCP short hdr Drop:");
    sf_log_u64(anomaly_t1->tcp_bad_ip_len_drop, "TCP bad IP len Drop:");
    sf_log_u64(anomaly_t1->tcp_null_flags_drop, "TCP NULL Flags Drop:");
    sf_log_u64(anomaly_t1->tcp_null_scan_drop, "TCP NULL scan Drop:");
    sf_log_u64(anomaly_t1->tcp_syn_and_fin_drop, "TCP SYN and FIN Drop:");
    sf_log_u64(anomaly_t1->tcp_xmas_flags_drop, "TCP XMAS flags Drop:");
    sf_log_u64(anomaly_t1->tcp_xmas_scan_drop, "TCP XMAS scan Drop:");
    sf_log_u64(anomaly_t1->tcp_syn_frag_drop, "TCP SYN Frag Drop:");
    sf_log_u64(anomaly_t1->tcp_frag_header_drop, "TCP Frag header Drop:");
    sf_log_u64(anomaly_t1->tcp_bad_csum_drop, "TCP bad csum Drop:");
    sf_log_u64(anomaly_t1->udp_short_hdr_drop, "UDP short hdr Drop:");
    sf_log_u64(anomaly_t1->udp_bad_leng_drop, "UDP bad length Drop:");
    sf_log_u64(anomaly_t1->udp_kb_frag_drop, "UDP kerberos Frag Drop:");
    sf_log_u64(anomaly_t1->udp_port_lb_drop, "UDP port LB Drop:");
    sf_log_u64(anomaly_t1->udp_bad_csum_drop, "UDP bad checksum Drop:");
    sf_log_u64(anomaly_t1->runt_ip_hdr_drop, "Runt IP header Drop:");
    sf_log_u64(anomaly_t1->runt_tcpudp_hdr_drop, "Runt TCP/UDP header Drop:");
    sf_log_u64(anomaly_t1->tun_mismatch_drop, "Tun mismatch Drop:");
    sf_log_u64(anomaly_t1->tcp_opt_err, "TCP OPTIONS error Drop:");

}

//  Record Enterprise:- 40842:60

static void readCounters_DDOS_POLLING_ENTRY_MAP(SFSample *sample)
{
    sflow_ddos_entry_map_t *entry_map = &sample->ddos.polling_entry_map;

    entry_map->is_src = getData_u8(sample);
    char *buffer_source_type = entry_map->is_src ? "Source" : "Destination";
    sf_log("%-35s %-20s\n", "Port Direction", buffer_source_type);

    entry_map->port_type = getData_u8(sample);
    char *buffer_port_app_type = (entry_map->port_type > 0) ? ((char *)ddos_proto_str[entry_map->port_type - 1]) : "None";
    sf_log("%-35s %-20s\n", "Port Type", buffer_port_app_type);

    entry_map->port = sf_log_next16(sample, "Port #");
    unsigned short len = 64;
    char buffer[len];
    sf_log_next8(sample, "Entry name", &buffer[0], len);

}

// Record Enterprise:- 40842:64

static void readCounters_DDOS_POLLING_PACKETS(SFSample *sample)
{

    sflow_ddos_packet_counters_t *packets = &sample->ddos.polling_packets;
    populate_sflow_struct_u64(sample, (void *)packets, sizeof(sflow_ddos_packet_counters_t));

    sf_log_u64(packets->ingress_bytes, "Ingress bytes:");
    sf_log_u64(packets->egress_bytes, "Egress bytes:");
    sf_log_u64(packets->packets_dropped_by_countermeasures, "Packets dropped by countermeasures:");
    sf_log_u64(packets->total_ingress_packets, "Total ingress packets:");
    sf_log_u64(packets->total_egress_packets, "Total egress packets:");

}

// Record Enterprise:- 40842:65 L4 PROTOCOL

static void readCounters_DDOS_POLLING_L4_PROTOCOL(SFSample *sample)
{

    sflow_ddos_l4_counters_t *l4 = &sample->ddos.polling_l4;
    populate_sflow_struct_u32(sample, (void *)l4, sizeof(sflow_ddos_l4_counters_t));

    u16 i = 0;
    for (i = 0; i < 256; i++) {
        sf_log_u32(l4->protocol[i], g_l4_protocol_list[i]);
    }

}

// Record Enterprise:- 40842:66 TCP BASIC

static void readCounters_DDOS_POLLING_TCP_BASIC(SFSample *sample)
{

    sflow_ddos_tcp_basic_counters_t *tcp_basic = &sample->ddos.polling_tcp_basic;

    populate_sflow_struct_u32(sample, (void *) & (tcp_basic->rcvd), sizeof(sflow_ddos_tcp_basic_counters_t));
    sf_log_string("RECEIVED:\n");

    sf_log_u32(tcp_basic->rcvd.syn, "SYN:");
    sf_log_u32(tcp_basic->rcvd.syn_ack, "SYN/ACK:");
    sf_log_u32(tcp_basic->rcvd.fin, "FIN:");
    sf_log_u32(tcp_basic->rcvd.rst, "RST:");
    sf_log_u32(tcp_basic->rcvd.psh, "PUSH:");
    sf_log_u32(tcp_basic->rcvd.ack, "ACK:");
    sf_log_u32(tcp_basic->rcvd.urg, "URGENT:");
    sf_log_u32(tcp_basic->rcvd.ece, "ECE:");
    sf_log_u32(tcp_basic->rcvd.cwr, "CWR:");
    sf_log_u32(tcp_basic->rcvd.ns, "NS:");
    sf_log_u32(tcp_basic->rcvd.reserved_flag9, "FLAG-09:");
    sf_log_u32(tcp_basic->rcvd.reserved_flag10, "FLAG-10:");
    sf_log_u32(tcp_basic->rcvd.reserved_flag11, "FLAG-11");
    sf_log_u32(tcp_basic->rcvd.no_flags, "No FLAGS");
    sf_log_u32(tcp_basic->rcvd.option_mss, "OPTIONS-MSS:");
    sf_log_u32(tcp_basic->rcvd.option_wscale, "OPTIONS-WSCALE:");
    sf_log_u32(tcp_basic->rcvd.option_sack, "OPTIONS-SACK:");
    sf_log_u32(tcp_basic->rcvd.option_ts, "OPTIONS-TIME STAMP:");
    sf_log_u32(tcp_basic->rcvd.option_other, "OPTIONS-OTHER:");

    sf_log_string("SENT:\n");

    sf_log_u32(tcp_basic->sent.syn, "SYN:");
    sf_log_u32(tcp_basic->sent.syn_ack, "SYN/ACK:");
    sf_log_u32(tcp_basic->sent.fin, "FIN:");
    sf_log_u32(tcp_basic->sent.rst, "RST:");
    sf_log_u32(tcp_basic->sent.psh, "PUSH:");
    sf_log_u32(tcp_basic->sent.ack, "ACK:");
    sf_log_u32(tcp_basic->sent.urg, "URGENT:");
    sf_log_u32(tcp_basic->sent.ece, "ECE:");
    sf_log_u32(tcp_basic->sent.cwr, "CWR:");
    sf_log_u32(tcp_basic->sent.ns, "NS:");
    sf_log_u32(tcp_basic->sent.reserved_flag9, "FLAG-09:");
    sf_log_u32(tcp_basic->sent.reserved_flag10, "FLAG-10:");
    sf_log_u32(tcp_basic->sent.reserved_flag11, "FLAG-11");
    sf_log_u32(tcp_basic->sent.no_flags, "No FLAGS");
    sf_log_u32(tcp_basic->sent.option_mss, "OPTIONS-MSS:");
    sf_log_u32(tcp_basic->sent.option_wscale, "OPTIONS-WSCALE:");
    sf_log_u32(tcp_basic->sent.option_sack, "OPTIONS-SACK:");
    sf_log_u32(tcp_basic->sent.option_ts, "OPTIONS-TIME STAMP:");
    sf_log_u32(tcp_basic->sent.option_other, "OPTIONS-OTHER:");

}

// Record Enterprise:- 40842:68 TCP STATEFUL

static void readCounters_DDOS_POLLING_TCP_STATEFUL(SFSample *sample)
{

    /* Skipping this one, Mix bunch u16, u32, u64 */
    sflow_ddos_tcp_stateful_counters_t *tcp_stateful = &sample->ddos.polling_tcp_stateful;

    tcp_stateful->conn_open = sf_log_next64(sample, "Connections Open:");
    tcp_stateful->conn_est = sf_log_next64(sample, "Connections Established:");

    sf_log_string("Connections Closed when it was in the OPEN state:\n");

    tcp_stateful->open_closed.client_fin = sf_log_next64(sample, "Client FIN:");
    tcp_stateful->open_closed.client_rst = sf_log_next64(sample, "Client RST:");
    tcp_stateful->open_closed.server_fin = sf_log_next64(sample, "Server FIN:");
    tcp_stateful->open_closed.server_rst = sf_log_next64(sample, "Server RST:");
    tcp_stateful->open_closed.idle = sf_log_next64(sample, "Idle:");
    tcp_stateful->open_closed.other = sf_log_next64(sample, "Other:");

    sf_log_string("Connections Closed when it was in the ESTABLISHED state:\n");

    tcp_stateful->est_closed.client_fin = sf_log_next64(sample, "Client FIN:");
    tcp_stateful->est_closed.client_rst = sf_log_next64(sample, "Client RST:");
    tcp_stateful->est_closed.server_fin = sf_log_next64(sample, "Server FIN:");
    tcp_stateful->est_closed.server_rst = sf_log_next64(sample, "Server RST:");
    tcp_stateful->est_closed.idle = sf_log_next64(sample, "Idle:");
    tcp_stateful->est_closed.other = sf_log_next64(sample, "Other:");

    sf_log_string("TCP Handshake details:\n");

    tcp_stateful->handshake.avg_syn_ack_delay_ms = sf_log_next16(sample, "Avg SYN/ACK delay(ms):");
    tcp_stateful->handshake.max_syn_ack_delay_ms = sf_log_next16(sample, "Max SYN/ACK delay(ms):");
    tcp_stateful->handshake.avg_ack_delay_ms = sf_log_next16(sample, "Avg ACK delay(ms):");
    tcp_stateful->handshake.max_ack_delay_ms = sf_log_next16(sample, "Max ACK delay(ms):");

    tcp_stateful->syn_retransmit = sf_log_next32(sample, "SYN rexmit:");
    tcp_stateful->psh_retransmit = sf_log_next32(sample, "PUSH rexmit:");
    tcp_stateful->ack_retransmit = sf_log_next32(sample, "ACK rexmit:");
    tcp_stateful->fin_retransmit = sf_log_next32(sample, "FIN rexmit:");
    tcp_stateful->total_retransmit = sf_log_next32(sample, "Total rexmit:");

    tcp_stateful->syn_ofo = sf_log_next32(sample, "SYN OFO:");
    tcp_stateful->psh_ofo = sf_log_next32(sample, "PUSH OFO:");
    tcp_stateful->ack_ofo = sf_log_next32(sample, "ACK OFO:");
    tcp_stateful->fin_ofo = sf_log_next32(sample, "FIN OFO:");
    tcp_stateful->total_ofo = sf_log_next32(sample, "Total OFO:");

}

static void readCounters_DDOS_POLLING_HTTP(SFSample *sample)
{

    /* Skipping this one, Mix bunch u16, u32 */
    sflow_ddos_http_counters_t *http = &sample->ddos.polling_http;
    http->method_option_count = sf_log_next32(sample, "OPTION:");
    http->method_get_count =  sf_log_next32(sample, "GET:");
    http->method_head_count = sf_log_next32(sample, "HEAD:");
    http->method_post_count = sf_log_next32(sample, "POST:");
    http->method_put_count = sf_log_next32(sample, "PUT:");
    http->method_delete_count = sf_log_next32(sample, "DELETE:");
    http->method_trace_count = sf_log_next32(sample, "TRACE:");
    http->method_connect_count = sf_log_next32(sample, "CONNECT:");
    http->method_other_count = sf_log_next32(sample, "OTHER:");
    http->status_1XX_count = sf_log_next32(sample, "Status 1XX:");
    http->status_2XX_count = sf_log_next32(sample, "Status 2XX:");
    http->status_3XX_count = sf_log_next32(sample, "Status 3XX:");
    http->status_4XX_count = sf_log_next32(sample, "Status 4XX:");
    http->status_5XX_count = sf_log_next32(sample, "Status 5XX:");
    http->status_other_count = sf_log_next32(sample, "Status OTHER:");

    http->avg_response_time_ms = sf_log_next16(sample, "Average response time(ms):");
    http->max_response_time_ms = sf_log_next16(sample, "Max response time(ms):");

    http->avg_health_check_time_ms = sf_log_next16(sample, "Average Health check time(ms):");
    http->max_health_check_time_ms = sf_log_next16(sample, "Max Health check time(ms):");

}

static void readCounters_DDOS_DNS_COUNTER(SFSample *sample)
{
    int len = 0;
    long tstamp = time(NULL);
    char tbuf [200];
    char buf [50];

    sprintf (tbuf, "agent=%08x\n", htonl(sample->agent_addr.address.ip_v4.addr));

    sflow_ddos_dns_stats_t *dns_t1 = &sample->ddos.dns;
    populate_sflow_struct_u64(sample, (void *)dns_t1, sizeof(sflow_ddos_dns_stats_t));

    len += sprintf (tsdb_buff + len, "put global_force_tcp_auth %lu %lu %s", tstamp, dns_t1->force_tcp_auth, tbuf);
    int ret = opentsdb_simple_connect(tsdb_buff);

    sf_log_u64(dns_t1->force_tcp_auth, "Force TCP auth:");
    sf_log_u64(dns_t1->dns_auth_udp, "DNS Auth UDP:");
    sf_log_u64(dns_t1->dns_malform_drop, "DNS malform query Drop:");
    sf_log_u64(dns_t1->dns_qry_any_drop, "DNS query ANY Drop:");
    sf_log_u64(dns_t1->dst_rate_limit0, "Dest rate 0 Drop:");
    sf_log_u64(dns_t1->dst_rate_limit1, "Dest rate 1 Drop:");
    sf_log_u64(dns_t1->dst_rate_limit2, "Dest rate 2 Drop:");
    sf_log_u64(dns_t1->dst_rate_limit3, "Dest rate 3 Drop:");
    sf_log_u64(dns_t1->dst_rate_limit4, "Dest rate 4 Drop:");
    sf_log_u64(dns_t1->src_rate_limit0, "Src rate 0 Drop:");
    sf_log_u64(dns_t1->src_rate_limit1, "Src rate 1 Drop");
    sf_log_u64(dns_t1->src_rate_limit2, "Src rate 2 Drop:");
    sf_log_u64(dns_t1->src_rate_limit3, "Src rate 3 Drop:");
    sf_log_u64(dns_t1->src_rate_limit4, "Src rate 4 Drop:");
    sf_log_u64(dns_t1->dns_auth_udp_pass, "DNS Auth UDP Pass:");
    sf_log_u64(dns_t1->dns_nx_bl, "NXDOMAIN query black-list:");
    sf_log_u64(dns_t1->dns_nx_drop, "NXDOMAIN query drop:");
    sf_log_u64(dns_t1->dns_fqdn_stage2_exceed, "FQDN stage-II Rate exceed/Src Drop:");
    sf_log_u64(dns_t1->dns_is_nx, "Response is NXDOMAIN:");
    sf_log_u64(dns_t1->dns_fqdn_label_len_exceed, "FQDN Label Length Exceed");
    sf_log_u64(dns_t1->dns_pkt_processed, "DNS Packets Processed");
    sf_log_u64(dns_t1->dns_query_type_a, "DNS Query type A");
    sf_log_u64(dns_t1->dns_query_type_aaaa, "DNS Query type AAAA");
    sf_log_u64(dns_t1->dns_query_type_ns, "DNS Query type NS");
    sf_log_u64(dns_t1->dns_query_type_cname, "DNS Query type CNAME");
    sf_log_u64(dns_t1->dns_query_type_any, "DNS Query type ANY");
    sf_log_u64(dns_t1->dns_query_type_srv, "DNS Query type SRV");
    sf_log_u64(dns_t1->dns_query_type_mx, "DNS Query type MX");
    sf_log_u64(dns_t1->dns_query_type_soa, "DNS Query type SOA");
    sf_log_u64(dns_t1->dns_query_type_opt, "DNS Query type OPT");
    sf_log_u64(dns_t1->dns_tcp_auth_pass, "DNS TCP Auth Pass:");
    sf_log_u64(dns_t1->dns_auth_udp_fail, "DNS Auth UDP Fail:");
    sf_log_u64(dns_t1->dns_auth_udp_timeout, "DNS Auth UDP Timeout:");

}

/* SSL L4 CounterBlockTag read: */

static void readCounters_DDOS_SSL_L4_COUNTER(SFSample *sample)
{
    int len = 0;
    long tstamp = time(NULL);
    char tbuf [200];
    char buf [50];

    sprintf (tbuf, "agent=%08x\n", htonl(sample->agent_addr.address.ip_v4.addr));

    sflow_ddos_ssl_l4_t *ssl_l4_t1 = &sample->ddos.ssl_l4;
    populate_sflow_struct_u64(sample, (void *)ssl_l4_t1, sizeof(sflow_ddos_ssl_l4_t));

    len += sprintf (tsdb_buff + len, "put global_ssl_drop %lu %lu %s", tstamp, ssl_l4_t1->ssll4_policy_reset + ssl_l4_t1->ssll4_drop_packet, tbuf);

    int ret = opentsdb_simple_connect(tsdb_buff);

    sf_log_u64(ssl_l4_t1->ssll4_policy_reset, "Policy Reset:");
    sf_log_u64(ssl_l4_t1->ssll4_policy_drop, "Policy Drop:");
    sf_log_u64(ssl_l4_t1->ssll4_drop_packet, "Pkt Drop:");
    sf_log_u64(ssl_l4_t1->ssll4_er_condition, "Error Condition:");
    sf_log_u64(ssl_l4_t1->ssll4_processed, "Process:");
    sf_log_u64(ssl_l4_t1->ssll4_new_syn, "New TCP SYN:");
    sf_log_u64(ssl_l4_t1->ssll4_is_ssl3, "SSL v3:");
    sf_log_u64(ssl_l4_t1->ssll4_is_tls1_1, "TLS v1.0:");
    sf_log_u64(ssl_l4_t1->ssll4_is_tls1_2, "TLS v1.1:");
    sf_log_u64(ssl_l4_t1->ssll4_is_tls1_3, "TLS v1.2:");
    sf_log_u64(ssl_l4_t1->ssll4_is_renegotiation, "SSL Renegotiation:");
    sf_log_u64(ssl_l4_t1->ssll4_renegotiation_exceed, "Renegotiation Excd:");
    sf_log_u64(ssl_l4_t1->ssll4_is_dst_req_rate_exceed, "Dst Rate Excd Drop:");
    sf_log_u64(ssl_l4_t1->ssll4_is_src_req_rate_exceed, "Src Rate Excd Drop:");
    sf_log_u64(ssl_l4_t1->ssll4_do_auth_handshake, "Do Auth Handshake:");
    sf_log_u64(ssl_l4_t1->ssll4_reset_for_handshake, "Reset While Others in HS:");
    sf_log_u64(ssl_l4_t1->ssll4_handshake_timeout, "Auth handshake timeout:");
    sf_log_u64(ssl_l4_t1->ssll4_auth_handshake_ok, "Auth handskake success:");
    sf_log_u64(ssl_l4_t1->ssll4_auth_handshake_bl, "Auth handskake blacklisted:");

}

/* L4 TCP CounterBlockTag read: */

static void readCounters_DDOS_L4_TCP_COUNTER(SFSample *sample)
{
    int len = 0;
    long tstamp = time(NULL);
    char tbuf [200];
    char buf [50];
    sprintf (tbuf, "agent=%08x\n", htonl(sample->agent_addr.address.ip_v4.addr));

    sflow_ddos_l4_tcp_stats_t *l4_tcp_t1 = &sample->ddos.l4_tcp;
    populate_sflow_struct_u64(sample, (void *)l4_tcp_t1, sizeof(sflow_ddos_l4_tcp_stats_t));
    len += sprintf (tsdb_buff + len, "put global_tcp_auth %lu %lu %s", tstamp, l4_tcp_t1->tcp_syncookie_sent + l4_tcp_t1->tcp_syncookie_sent_fail, tbuf);
    len += sprintf (tsdb_buff + len, "put tcp_invalid_syn %lu %lu %s", tstamp, l4_tcp_t1->tcp_invalid_syn_rcvd, tbuf);
    int ret = opentsdb_simple_connect(tsdb_buff);

    sf_log_u64(l4_tcp_t1->tcp_sess_create, "TCP Session Create:");
    sf_log_u64(l4_tcp_t1->intcp, "TCP Rcv:");
    sf_log_u64(l4_tcp_t1->tcp_syn_rcvd, "TCP SYN Rcv:");
    sf_log_u64(l4_tcp_t1->tcp_invalid_syn_rcvd, "TCP Invalid SYN Rcv:");
    sf_log_u64(l4_tcp_t1->tcp_syn_ack_rcvd, "TCP SYN ACK Rcv:");
    sf_log_u64(l4_tcp_t1->tcp_ack_rcvd, "TCP ACK Rcv:");
    sf_log_u64(l4_tcp_t1->tcp_fin_rcvd, "TCP FIN Rcv:");
    sf_log_u64(l4_tcp_t1->tcp_rst_rcvd, "TCP RST Rcv:");
    sf_log_u64(l4_tcp_t1->tcp_outrst, "TCP Out RST:");
    sf_log_u64(l4_tcp_t1->tcp_reset_client, "TCP Reset Client:");
    sf_log_u64(l4_tcp_t1->tcp_reset_server, "TCP Reset Server:");
    sf_log_u64(l4_tcp_t1->tcp_syn_rate, "TCP SYN Rate Per Sec:");
    sf_log_u64(l4_tcp_t1->tcp_total_drop, "TCP Total Drop:");
    sf_log_u64(l4_tcp_t1->tcp_drop_dst, "TCP Dst Drop:");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_any_dst, "TCP Dst Excd Drop:");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_prate_dst, "TCP Dst Pkt Rate Drop:");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_crate_dst, "TCP Dst Conn Rate Drop:");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_climit_dst, "TCP Dst Conn Limit Drop:");
    sf_log_u64(l4_tcp_t1->tcp_drop_black_dst, "TCP Dst BL Drop:");
    sf_log_u64(l4_tcp_t1->tcp_drop_src, "TCP Src Drop:");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_any_src, "TCP Src Excd Drop:");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_prate_src, "TCP Src Pkt Rate Drop:");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_crate_src, "TCP Src Conn Rate Drop:");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_climit_src, "TCP Src Conn Limit Drop:");
    sf_log_u64(l4_tcp_t1->tcp_drop_black_src, "TCP Src BL Drop:");
    sf_log_u64(l4_tcp_t1->tcp_drop_black_user_cfg_src, "TCP Src BL User Drop:");
    sf_log_u64(l4_tcp_t1->tcp_drop_src_dst, "TCP SrcDst Drop:");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_any_src_dst, "TCP SrcDst Excd Drop:");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_prate_src_dst, "TCP SrcDst Pkt Rate Drop:");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_crate_src_dst, "TCP SrcDst Conn Rate Drop:");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_climit_src_dst, "TCP SrcDst Conn Limit Drop:");
    sf_log_u64(l4_tcp_t1->tcp_drop_black_src_dst, "TCP SrcDst BL Drop:");
    sf_log_u64(l4_tcp_t1->tcp_drop_black_user_cfg_src_dst, "TCP SrcDst BL User Drop:");
    sf_log_u64(l4_tcp_t1->tcp_port_zero_drop, "TCP Port Zero Drop:");
    sf_log_u64(l4_tcp_t1->tcp_syncookie_sent, "TCP SYN Cookie Sent:");
    sf_log_u64(l4_tcp_t1->tcp_syncookie_sent_fail, "TCP SYN Cookie Sent Fail:");
    sf_log_u64(l4_tcp_t1->tcp_syncookie_check_fail, "TCP SYN Cookie Check Fail:");
    sf_log_u64(l4_tcp_t1->tcp_syncookie_hw_missing, "TCP SYN Cookie HW Miss:");
    sf_log_u64(l4_tcp_t1->tcp_syncookie_fail_bl, "TCP SYN Cookie BL Fail:");
    sf_log_u64(l4_tcp_t1->tcp_syncookie_pass, "TCP SYN Cookie Pass:");
    sf_log_u64(l4_tcp_t1->syn_auth_pass, "TCP SYN Auth Pass:");
    sf_log_u64(l4_tcp_t1->syn_auth_skip, "TCP SYN Auth Skip:");
    sf_log_u64(l4_tcp_t1->over_conn_limit_tcp_syn_auth, "TCP SYN Auth Limit Excd:");
    sf_log_u64(l4_tcp_t1->over_conn_limit_tcp_syn_cookie, "TCP SYN Cookie Limit Excd:");
    sf_log_u64(l4_tcp_t1->over_conn_limit_tcp_port_syn_auth, "TCP Port SYN Auth Limit Excd:");
    sf_log_u64(l4_tcp_t1->over_conn_limit_tcp_port_syn_cookie, "TCP Port SYN Cookie Limit Excd:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_ack_start, "TCP Action-On-Ack Init:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_ack_matched, "TCP Action-On-Ack Match:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_ack_passed, "TCP Action-On-Ack Pass:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_ack_failed, "TCP Action-On-Ack Fail:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_ack_timeout, "TCP Action-On-Ack Timeout:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_ack_reset, "TCP Action-On-Ack Reset:");
    sf_log_u64(l4_tcp_t1->tcp_ack_no_syn, "TCP ACK No SYN:");
    sf_log_u64(l4_tcp_t1->tcp_out_of_order, "TCP Out-Of-Seq:");
    sf_log_u64(l4_tcp_t1->tcp_zero_window, "TCP Zero Window:");
    sf_log_u64(l4_tcp_t1->tcp_retransmit, "TCP ReXmit:");
    sf_log_u64(l4_tcp_t1->tcp_rexmit_syn_limit_drop, "TCP Rexmit SYN Excd Drop:");
    sf_log_u64(l4_tcp_t1->tcp_zero_wind_bl, "TCP Zero Window BL:");
    sf_log_u64(l4_tcp_t1->tcp_out_of_seq_bl, "TCP Out-Of-Seq BL:");
    sf_log_u64(l4_tcp_t1->tcp_retransmit_bl, "TCP ReXmit BL:");
    sf_log_u64(l4_tcp_t1->tcp_rexmit_syn_limit_bl, "TCP ReXmit SYN Excd BL:");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_conn_prate, "TCP Conn Pkt Rate Drop:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_ack_gap_drop, "TCP Action-On-Ack Retry-Gap Drop:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_ack_gap_pass, "TCP Action-On-Ack Retry-Gap Pass:");
    sf_log_u64(l4_tcp_t1->tcp_new_conn_ack_retry_gap_start, "TCP New-Conn-Ack-Retry-Gap Init:");
    sf_log_u64(l4_tcp_t1->tcp_new_conn_ack_retry_gap_passed, "TCP New-Conn-Ack-Retry-Gap Pass:");
    sf_log_u64(l4_tcp_t1->tcp_new_conn_ack_retry_gap_failed, "TCP New-Conn-Ack-Retry-Gap Fail:");
    sf_log_u64(l4_tcp_t1->tcp_new_conn_ack_retry_gap_timeout, "TCP New-Conn-Ack-Retry-Gap Timeout:");
    sf_log_u64(l4_tcp_t1->tcp_new_conn_ack_retry_gap_reset, "TCP New-Conn-Ack-Retry-Gap Reset:");
    sf_log_u64(l4_tcp_t1->tcp_new_conn_ack_retry_gap_drop, "TCP New-Conn-Ack-Retry-Gap Drop:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_syn_start, "TCP Action-On-Syn Init:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_syn_passed, "TCP Action-On-Syn Pass:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_syn_failed, "TCP Action-On-Syn Fail:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_syn_timeout, "TCP Action-On-Syn Timeout:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_syn_reset, "TCP Action-On-Syn Reset:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_syn_gap_drop, "TCP Action-On-Syn Retry-Gap Drop:");
    sf_log_u64(l4_tcp_t1->tcp_action_on_syn_gap_pass, "TCP Action-On-Syn Retry-Gap Pass:");
    sf_log_u64(l4_tcp_t1->tcp_unauth_rst_drop, "TCP Unauth RST Drop:");
    sf_log_u64(l4_tcp_t1->tcp_filter_match, "Dst Filter Match:");
    sf_log_u64(l4_tcp_t1->tcp_filter_not_match, "Dst Filter Not Match:");
    sf_log_u64(l4_tcp_t1->tcp_filter_action_blacklist, "Dst Filter Action BL:");
    sf_log_u64(l4_tcp_t1->tcp_filter_action_drop, "Dst Filter Action Drop:");
    sf_log_u64(l4_tcp_t1->tcp_filter_action_default_pass, "Dst Filter Action Default Pass:");
    sf_log_u64(l4_tcp_t1->tcp_over_limit_syn_auth_src, "TCP Src Over Limit Auth:");
    sf_log_u64(l4_tcp_t1->tcp_over_limit_syn_auth_src_dst, "TCP SrcDst Over Limit Auth:");
    sf_log_u64(l4_tcp_t1->tcp_over_limit_syn_cookie_src, "TCP Src Over Limit Cookie:");
    sf_log_u64(l4_tcp_t1->tcp_over_limit_syn_cookie_src_dst, "TCP SrcDst Over Limit Cookie:");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_brate_dst, "TCP Dst KiBit Rate Drop (KiBit):");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_brate_src, "TCP Src KiBit Rate Drop (KiBit):");
    sf_log_u64(l4_tcp_t1->tcp_exceed_drop_brate_src_dst, "TCP SrcDst KiBit Rate Drop (KiBit):");
    sf_log_u64(l4_tcp_t1->tcp_concurrent, "TCP Concurrent Port Access:");
    sf_log_u64(l4_tcp_t1->tcp_filter_action_whitelist, "Dst Filter Action WL:");
    sf_log_u64(l4_tcp_t1->src_tcp_filter_match, "Src Filter Match:");
    sf_log_u64(l4_tcp_t1->src_tcp_filter_not_match, "Src Filter Not Match:");
    sf_log_u64(l4_tcp_t1->src_tcp_filter_action_blacklist, "Src Filter Action BL:");
    sf_log_u64(l4_tcp_t1->src_tcp_filter_action_drop, "Src Filter Action Drop:");
    sf_log_u64(l4_tcp_t1->src_tcp_filter_action_default_pass, "Src Filter Action Default Pass:");
    sf_log_u64(l4_tcp_t1->src_tcp_filter_action_whitelist, "Src Filter Action WL:");
    sf_log_u64(l4_tcp_t1->src_dst_tcp_filter_match, "SrcDst Filter Match:");
    sf_log_u64(l4_tcp_t1->src_dst_tcp_filter_not_match, "SrcDst Filter Not Match:");
    sf_log_u64(l4_tcp_t1->src_dst_tcp_filter_action_blacklist, "SrcDst Filter Action BL:");
    sf_log_u64(l4_tcp_t1->src_dst_tcp_filter_action_drop, "SrcDst Filter Action Drop:");
    sf_log_u64(l4_tcp_t1->src_dst_tcp_filter_action_default_pass, "SrcDst Filter Action Default Pass:");
    sf_log_u64(l4_tcp_t1->src_dst_tcp_filter_action_whitelist, "SrcDst Filter Action WL:");

}

/* L4 UDP CounterBlockTag read: */

static void readCounters_DDOS_L4_UDP_COUNTER(SFSample *sample)
{

    sflow_ddos_l4_udp_stats_t *l4_udp_t1 = &sample->ddos.l4_udp;
    populate_sflow_struct_u64(sample, (void *)l4_udp_t1, sizeof(sflow_ddos_l4_udp_stats_t));

    sf_log_u64(l4_udp_t1->udp_sess_create, "UDP Session Create:");
    sf_log_u64(l4_udp_t1->inudp, "UDP Rcv:");
    sf_log_u64(l4_udp_t1->instateless, "UDP Stateless:");
    sf_log_u64(l4_udp_t1->udp_total_drop, "UDP Total Drop:");
    sf_log_u64(l4_udp_t1->udp_drop_dst, "UDP Dst Drop:");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_any_dst, "UDP Dst Excd Drop:");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_prate_dst, "UDP Dst Pkt Rate Drop:");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_crate_dst, "UDP Dst Conn Rate Drop:");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_climit_dst, "UDP Dst Conn Limit Drop:");
    sf_log_u64(l4_udp_t1->udp_drop_black_dst, "UDP Dst BL Drop:");
    sf_log_u64(l4_udp_t1->udp_drop_src, "UDP Src Drop:");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_any_src, "UDP Src Excd Drop:");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_prate_src, "UDP Src Pkt Rate Drop:");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_crate_src, "UDP Src Conn Rate Drop:");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_climit_src, "UDP Src Conn Limit Drop:");
    sf_log_u64(l4_udp_t1->udp_drop_black_src, "UDP Src BL Drop:");
    sf_log_u64(l4_udp_t1->udp_drop_black_user_cfg_src, "UDP Src BL User Drop:");
    sf_log_u64(l4_udp_t1->udp_drop_src_dst, "UDP SrcDst Drop:");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_any_src_dst, "UDP SrcDst Excd Drop:");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_prate_src_dst, "UDP SrcDst Pkt Rate Drop:");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_crate_src_dst, "UDP SrcDst Conn Rate Drop:");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_climit_src_dst, "UDP SrcDst Conn Limit Drop:");
    sf_log_u64(l4_udp_t1->udp_drop_black_src_dst, "UDP SrcDst BL Drop:");
    sf_log_u64(l4_udp_t1->udp_drop_black_user_cfg_src_dst, "UDP SrcDst BL User Drop:");
    sf_log_u64(l4_udp_t1->udp_port_zero_drop, "UDP Port Zero Drop:");
    sf_log_u64(l4_udp_t1->udp_wellknown_src_port_drop, "UDP SrcPort Wellknown Drop:");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_conn_prate, "UDP Conn Pkt Rate Drop:");
    sf_log_u64(l4_udp_t1->udp_retry_start, "UDP Retry Init:");
    sf_log_u64(l4_udp_t1->udp_retry_pass, "UDP Retry Pass:");
    sf_log_u64(l4_udp_t1->udp_retry_fail, "UDP Retry Fail:");
    sf_log_u64(l4_udp_t1->udp_retry_timeout, "UDP Retry Timeout:");
    sf_log_u64(l4_udp_t1->udp_payload_too_big_drop, "UDP Payload Too Large Drop:");
    sf_log_u64(l4_udp_t1->udp_payload_too_small_drop, "UDP Payload Too Small Drop:");
    sf_log_u64(l4_udp_t1->ntp_monlist_req_drop, "NTP Monlist Req Drop:");
    sf_log_u64(l4_udp_t1->ntp_monlist_resp_drop, "NTP Monlist Resp Drop:");
    sf_log_u64(l4_udp_t1->udp_filter_match, "Dst Filter Match:");
    sf_log_u64(l4_udp_t1->udp_filter_not_match, "Dst Filter Not Match:");
    sf_log_u64(l4_udp_t1->udp_filter_action_blacklist, "Dst Filter Action BL:");
    sf_log_u64(l4_udp_t1->udp_filter_action_whitelist, "Dst Filter Action WL:");
    sf_log_u64(l4_udp_t1->udp_filter_action_drop, "Dst Filter Action Drop:");
    sf_log_u64(l4_udp_t1->udp_filter_action_default_pass, "Dst Filter Action Default Pass:");
    sf_log_u64(l4_udp_t1->udp_auth_pass, "UDP Auth Pass:");
    sf_log_u64(l4_udp_t1->udp_over_limit_auth_dst, "UDP Dst Over Limit Auth:");
    sf_log_u64(l4_udp_t1->udp_over_limit_auth_dst_port, "UDP Dst Port Over Limit Auth:");
    sf_log_u64(l4_udp_t1->udp_over_limit_auth_src, "UDP Src Over Limit Auth:");
    sf_log_u64(l4_udp_t1->udp_over_limit_auth_src_dst, "UDP SrcDst Over Limit Auth:");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_brate_dst, "UDP Dst KiBit Rate Drop (KiBit):");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_brate_src, "UDP Src KiBit Rate Drop (KiBit):");
    sf_log_u64(l4_udp_t1->udp_exceed_drop_brate_src_dst, "UDP SrcDst KiBit Rate Drop (KiBit):");
    sf_log_u64(l4_udp_t1->src_udp_filter_match, "Src Filter Match:");
    sf_log_u64(l4_udp_t1->src_udp_filter_not_match, "Src Filter Not Match:");
    sf_log_u64(l4_udp_t1->src_udp_filter_action_blacklist, "Src Filter Action BL:");
    sf_log_u64(l4_udp_t1->src_udp_filter_action_whitelist, "Src Filter Action WL:");
    sf_log_u64(l4_udp_t1->src_udp_filter_action_drop, "Src Filter Action Drop:");
    sf_log_u64(l4_udp_t1->src_udp_filter_action_default_pass, "Src Filter Action Default Pass:");
    sf_log_u64(l4_udp_t1->src_dst_udp_filter_match, "SrcDst Filter Match:");
    sf_log_u64(l4_udp_t1->src_dst_udp_filter_not_match, "SrcDst Filter Not Match:");
    sf_log_u64(l4_udp_t1->src_dst_udp_filter_action_blacklist, "SrcDst Filter Action BL:");
    sf_log_u64(l4_udp_t1->src_dst_udp_filter_action_whitelist, "SrcDst Filter Action WL:");
    sf_log_u64(l4_udp_t1->src_dst_udp_filter_action_drop, "SrcDst Filter Action Drop:");
    sf_log_u64(l4_udp_t1->src_dst_udp_filter_action_default_pass, "SrcDst Filter Action Default Pass:");

}

/* L4 ICMP CounterBlockTag read: */

static void readCounters_DDOS_L4_ICMP_COUNTER(SFSample *sample)
{

    sflow_ddos_l4_icmp_stats_t *l4_icmp_t1 = &sample->ddos.l4_icmp;
    populate_sflow_struct_u64(sample, (void *)l4_icmp_t1, sizeof(sflow_ddos_l4_icmp_stats_t));

    sf_log_u64(l4_icmp_t1->inicmp, "ICMP Rcv:");
    sf_log_u64(l4_icmp_t1->icmp_echo_rcvd, "ICMP Echo Rcv:");
    sf_log_u64(l4_icmp_t1->icmp_other_rcvd, "ICMP other Rcv:");
    sf_log_u64(l4_icmp_t1->icmp_total_drop, "ICMP Total Drop:");
    sf_log_u64(l4_icmp_t1->icmp_drop_dst, "ICMP Dst Drop:");
    sf_log_u64(l4_icmp_t1->icmp_exceed_drop_any_dst, "ICMP Dst Excd Drop:");
    sf_log_u64(l4_icmp_t1->icmp_exceed_drop_prate_dst, "ICMP Dst Pkt Rate Drop:");
    sf_log_u64(l4_icmp_t1->icmp_drop_black_dst, "ICMP Dst BL Drop:");
    sf_log_u64(l4_icmp_t1->icmp_drop_src, "ICMP Src Drop:");
    sf_log_u64(l4_icmp_t1->icmp_exceed_drop_any_src, "ICMP Src Excd Drop:");
    sf_log_u64(l4_icmp_t1->icmp_exceed_drop_prate_src, "ICMP Src Pkt Rate Drop:");
    sf_log_u64(l4_icmp_t1->icmp_drop_black_src, "ICMP Src BL Drop:");
    sf_log_u64(l4_icmp_t1->icmp_drop_black_user_cfg_src, "ICMP Src BL User Drop:");
    sf_log_u64(l4_icmp_t1->icmp_drop_src_dst, "ICMP SrcDst Drop:");
    sf_log_u64(l4_icmp_t1->icmp_exceed_drop_any_src_dst, "ICMP SrcDst Excd Drop:");
    sf_log_u64(l4_icmp_t1->icmp_exceed_drop_prate_src_dst, "ICMP SrcDst Pkt Rate Drop:");
    sf_log_u64(l4_icmp_t1->icmp_drop_black_src_dst, "ICMP SrcDst BL Drop:");
    sf_log_u64(l4_icmp_t1->icmp_drop_black_user_cfg_src_dst, "ICMP SrcDst BL User Drop:");
    sf_log_u64(l4_icmp_t1->icmp_type_deny_drop, "ICMP Type Deny Drop:");
    sf_log_u64(l4_icmp_t1->icmp_v4_rfc_undef_drop, "ICMPv4 RFC Undef Type Drop:");
    sf_log_u64(l4_icmp_t1->icmp_v6_rfc_undef_drop, "ICMPv6 RFC Undef Type Drop:");
    sf_log_u64(l4_icmp_t1->icmp_wildcard_deny_drop, "ICMP Wildcard Deny Drop:");
    sf_log_u64(l4_icmp_t1->icmp_rate_exceed0, "ICMP Type Code Rate Excd 1:");
    sf_log_u64(l4_icmp_t1->icmp_rate_exceed1, "ICMP Type Code Rate Excd 2:");
    sf_log_u64(l4_icmp_t1->icmp_rate_exceed2, "ICMP Type Code Rate Excd 3:");
    sf_log_u64(l4_icmp_t1->icmp_exceed_drop_brate_dst, "ICMP Dst KiBit Rate Drop (KiBit):");
    sf_log_u64(l4_icmp_t1->icmp_exceed_drop_brate_src, "ICMP Src KiBit Rate Drop (KiBit):");
    sf_log_u64(l4_icmp_t1->icmp_exceed_drop_brate_src_dst, "ICMP SrcDst KiBit Rate Drop (KiBit):");

}

/* L4 OTHER CounterBlockTag read: */

static void readCounters_DDOS_L4_OTHER_COUNTER(SFSample *sample)
{

    sflow_ddos_l4_other_stats_t *l4_other_t1 = &sample->ddos.l4_other;
    populate_sflow_struct_u64(sample, (void *)l4_other_t1, sizeof(sflow_ddos_l4_other_stats_t));

    sf_log_u64(l4_other_t1->inother, "OTHER Rcv:");
    sf_log_u64(l4_other_t1->infrag, "OTHER Frag Rcv:");
    sf_log_u64(l4_other_t1->other_total_drop, "OTHER Total Drop:");
    sf_log_u64(l4_other_t1->other_drop_dst, "OTHER Dst Drop:");
    sf_log_u64(l4_other_t1->frag_drop, "OTHER Frag Drop:");
    sf_log_u64(l4_other_t1->other_exceed_drop_any_dst, "OTHER Dst Excd Drop:");
    sf_log_u64(l4_other_t1->other_exceed_drop_prate_dst, "OTHER Dst Pkt Rate Drop:");
    sf_log_u64(l4_other_t1->other_exceed_drop_fprate_dst, "OTHER Dst Frag Rate Drop:");
    sf_log_u64(l4_other_t1->other_frag_exceed_drop_dst, "OTHER Dst Frag Excd Drop:");
    sf_log_u64(l4_other_t1->other_drop_black_dst, "OTHER Dst BL Drop:");
    sf_log_u64(l4_other_t1->other_drop_src, "OTHER Src Drop:");
    sf_log_u64(l4_other_t1->other_exceed_drop_any_src, "OTHER Src Excd Drop:");
    sf_log_u64(l4_other_t1->other_exceed_drop_prate_src, "OTHER Src Pkt Rate Drop:");
    sf_log_u64(l4_other_t1->other_exceed_drop_fprate_src, "OTHER Src Frag Rate Drop:");
    sf_log_u64(l4_other_t1->other_frag_exceed_drop_src, "OTHER Src Frag Excd Drop:");
    sf_log_u64(l4_other_t1->other_drop_black_src, "OTHER Src BL Drop:");
    sf_log_u64(l4_other_t1->other_drop_black_user_cfg_src, "OTHER Src BL User Drop:");
    sf_log_u64(l4_other_t1->other_drop_src_dst, "OTHER SrcDst Drop:");
    sf_log_u64(l4_other_t1->other_exceed_drop_any_src_dst, "OTHER SrcDst Excd Drop:");
    sf_log_u64(l4_other_t1->other_exceed_drop_prate_src_dst, "OTHER SrcDst Pkt Rate Drop:");
    sf_log_u64(l4_other_t1->other_exceed_drop_fprate_src_dst, "OTHER SrcDst Frag Rate Drop:");
    sf_log_u64(l4_other_t1->other_frag_exceed_drop_src_dst, "OTHER SrcDst Frag Excd Drop:");
    sf_log_u64(l4_other_t1->other_drop_black_src_dst, "OTHER SrcDst BL Drop:");
    sf_log_u64(l4_other_t1->other_drop_black_user_cfg_src_dst, "OTHER SrcDst BL User Drop:");
    sf_log_u64(l4_other_t1->other_exceed_drop_brate_dst, "OTHER Dst KiBit Rate Drop (KiBit):");
    sf_log_u64(l4_other_t1->other_exceed_drop_brate_src, "OTHER Src KiBit Rate Drop (KiBit):");
    sf_log_u64(l4_other_t1->other_exceed_drop_brate_src_dst, "OTHER SrcDst KiBit Rate Drop (KiBit):");
    sf_log_u64(l4_other_t1->other_filter_match, "Dst Filter Match:");
    sf_log_u64(l4_other_t1->other_filter_not_match, "Dst Filter Not Match:");
    sf_log_u64(l4_other_t1->other_filter_action_blacklist, "Dst Filter Action BL:");
    sf_log_u64(l4_other_t1->other_filter_action_drop, "Dst Filter Action Drop:");
    sf_log_u64(l4_other_t1->other_filter_action_default_pass, "Dst Filter Action Default Pass:");
    sf_log_u64(l4_other_t1->other_filter_action_whitelist, "Dst Filter Action WL:");
    sf_log_u64(l4_other_t1->other_filter_match, "Src Filter Match:");
    sf_log_u64(l4_other_t1->src_other_filter_not_match, "Src Filter Not Match:");
    sf_log_u64(l4_other_t1->src_other_filter_action_blacklist, "Src Filter Action BL:");
    sf_log_u64(l4_other_t1->src_other_filter_action_drop, "Src Filter Action Drop:");
    sf_log_u64(l4_other_t1->src_other_filter_action_default_pass, "Src Filter Action Default Pass:");
    sf_log_u64(l4_other_t1->src_other_filter_action_whitelist, "Src Filter Action WL:");
    sf_log_u64(l4_other_t1->src_dst_other_filter_match, "SrcDst Filter Match:");
    sf_log_u64(l4_other_t1->src_dst_other_filter_not_match, "SrcDst Filter Not Match:");
    sf_log_u64(l4_other_t1->src_dst_other_filter_action_blacklist, "SrcDst Filter Action BL:");
    sf_log_u64(l4_other_t1->src_dst_other_filter_action_drop, "SrcDst Filter Action Drop:");
    sf_log_u64(l4_other_t1->src_dst_other_filter_action_default_pass, "SrcDst Filter Action Default Pass:");
    sf_log_u64(l4_other_t1->src_dst_other_filter_action_whitelist, "SrcDst Filter Action WL:");

}

/* L4 SWITCH CounterBlockTag read: */

static void readCounters_DDOS_L4_SWITCH_COUNTER(SFSample *sample)
{

    sflow_ddos_switch_stats_t *l4_switch_t1 = &sample->ddos.l4_switch;
    populate_sflow_struct_u64(sample, (void *)l4_switch_t1, sizeof(sflow_ddos_switch_stats_t));

    sf_log_u64(l4_switch_t1->ip_rcvd, "IPv4 Rcv:");
    sf_log_u64(l4_switch_t1->ip_sent, "IPv4 Sent:");
    sf_log_u64(l4_switch_t1->ipv6_rcvd, "IPv6 Rcv:");
    sf_log_u64(l4_switch_t1->ipv6_sent, "IPv6 Sent:");
    sf_log_u64(l4_switch_t1->instateless, "Stateless Pkt Rcv:");
    sf_log_u64(l4_switch_t1->out_no_route, "IPv4/v6 Out No Route:");
    sf_log_u64(l4_switch_t1->not_for_ddos, "Not For DDOS:");
    sf_log_u64(l4_switch_t1->mpls_rcvd, "MPLS Rcv:");
    sf_log_u64(l4_switch_t1->mpls_drop, "MPLS Drop:");
    sf_log_u64(l4_switch_t1->mpls_malformed, "MPLS Malformed:");

}

/* L4 SESSION CounterBlockTag read: */

static void readCounters_DDOS_L4_SESSION_COUNTER(SFSample *sample)
{

    sflow_ddos_sess_stats_t *l4_session_t1 = &sample->ddos.l4_session;
    populate_sflow_struct_u64(sample, (void *)l4_session_t1, sizeof(sflow_ddos_sess_stats_t));

    sf_log_u64(l4_session_t1->v4_sess_create, "IPv4 Session Create:");
    sf_log_u64(l4_session_t1->v6_sess_create, "IPv6 Session Create:");
    sf_log_u64(l4_session_t1->tcp_sess_create, "TCP Session Create:");
    sf_log_u64(l4_session_t1->tcp_conn_est_w_syn, "TCP Conn Est WL SYN:");
    sf_log_u64(l4_session_t1->tcp_conn_est_w_ack, "TCP Conn Est WL ACK:");
    sf_log_u64(l4_session_t1->tcp_conn_est, "TCP Conn Est:");
    sf_log_u64(l4_session_t1->tcp_conn_close_w_rst, "TCP Conn Close WL RST:");
    sf_log_u64(l4_session_t1->tcp_conn_close_w_fin, "TCP Conn Close WL FIN:");
    sf_log_u64(l4_session_t1->tcp_conn_close_w_idle, "TCP Conn Close WL Idle:");
    sf_log_u64(l4_session_t1->tcp_conn_close_w_half_open, "TCP Conn Close WL Half Open:");
    sf_log_u64(l4_session_t1->tcp_conn_close, "TCP Conn Close:");
    sf_log_u64(l4_session_t1->udp_sess_create, "UDP Session Create:");
    sf_log_u64(l4_session_t1->udp_conn_est, "UDP Conn Est:");
    sf_log_u64(l4_session_t1->udp_conn_close, "UDP Conn Close:");

}

/* L4 SYNC CounterBlockTag read: */

static void readCounters_DDOS_L4_SYNC_COUNTER(SFSample *sample)
{


    sflow_ddos_sync_stats_t *l4_sync_t1 = &sample->ddos.l4_sync;
    populate_sflow_struct_u64(sample, (void *)l4_sync_t1, sizeof(sflow_ddos_sync_stats_t));

    sf_log_u64(l4_sync_t1->sync_dst_wl_rcv, "Sync Dst Rcv:");
    sf_log_u64(l4_sync_t1->sync_dst_wl_sent, "Sync Dst Sent:");
    sf_log_u64(l4_sync_t1->sync_src_wl_rcv, "Sync Src Rcv:");
    sf_log_u64(l4_sync_t1->sync_src_wl_sent, "Sync Src Sent:");
    sf_log_u64(l4_sync_t1->sync_src_dst_wl_rcv, "Sync SrcDst Rcv:");
    sf_log_u64(l4_sync_t1->sync_src_dst_wl_sent, "Sync SrcDst Sent:");
    sf_log_u64(l4_sync_t1->sync_src_dst_wl_no_dst_drop, "Sync SrcDst No Dst Drop:");
    sf_log_u64(l4_sync_t1->sync_hello_rcv, "Sync Hello Rcv:");
    sf_log_u64(l4_sync_t1->sync_hello_sent, "Sync Hello Sent:");
    sf_log_u64(l4_sync_t1->sync_sent_fail, "Sync Sent Fail:");
    sf_log_u64(l4_sync_t1->sync_sent_no_peer, "Sync Sent No Peer:");
    sf_log_u64(l4_sync_t1->sync_rcv_fail, "Sync Rcv Fail:");
    sf_log_u64(l4_sync_t1->sync_dst_tcp_wl_sent, "Sync Sent Dst TCP WL:");
    sf_log_u64(l4_sync_t1->sync_dst_udp_wl_sent, "Sync Sent Dst UDP WL:");
    sf_log_u64(l4_sync_t1->sync_dst_icmp_wl_sent, "Sync Sent Dst ICMP WL:");
    sf_log_u64(l4_sync_t1->sync_dst_other_wl_sent, "Sync Sent Dst OTHER WL:");
    sf_log_u64(l4_sync_t1->sync_dst_tcp_bl_sent, "Sync Sent Dst TCP BL:");
    sf_log_u64(l4_sync_t1->sync_dst_udp_bl_sent, "Sync Sent Dst UDP BL:");
    sf_log_u64(l4_sync_t1->sync_dst_icmp_bl_sent, "Sync Sent Dst ICMP BL:");
    sf_log_u64(l4_sync_t1->sync_dst_other_bl_sent, "Sync Sent Dst OTHER BL:");
    sf_log_u64(l4_sync_t1->sync_src_tcp_wl_sent, "Sync Sent Src TCP WL:");
    sf_log_u64(l4_sync_t1->sync_src_udp_wl_sent, "Sync Sent Src UDP WL:");
    sf_log_u64(l4_sync_t1->sync_src_icmp_wl_sent, "Sync Sent Src ICMP WL:");
    sf_log_u64(l4_sync_t1->sync_src_other_wl_sent, "Sync Sent Src OTHER WL:");
    sf_log_u64(l4_sync_t1->sync_src_tcp_bl_sent, "Sync Sent Src TCP BL:");
    sf_log_u64(l4_sync_t1->sync_src_udp_bl_sent, "Sync Sent Src UDP BL:");
    sf_log_u64(l4_sync_t1->sync_src_icmp_bl_sent, "Sync Sent Src ICMP BL:");
    sf_log_u64(l4_sync_t1->sync_src_other_bl_sent, "Sync Sent Src OTHER BL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_tcp_wl_sent, "Sync Sent SrcDst TCP WL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_udp_wl_sent, "Sync Sent SrcDst UDP WL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_icmp_wl_sent, "Sync Sent SrcDst ICMP WL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_other_wl_sent, "Sync Sent SrcDst OTHER WL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_tcp_bl_sent, "Sync Sent SrcDst UDP BL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_udp_bl_sent, "Sync Sent SrcDst TCP BL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_icmp_bl_sent, "Sync Sent SrcDst ICMP BL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_other_bl_sent, "Sync Sent SrcDst OTHER BL:");
    sf_log_u64(l4_sync_t1->sync_dst_tcp_wl_rcvd, "Sync Rcv Dst UDP WL:");
    sf_log_u64(l4_sync_t1->sync_dst_udp_wl_rcvd, "Sync Rcv Dst TCP WL:");
    sf_log_u64(l4_sync_t1->sync_dst_icmp_wl_rcvd, "Sync Rcv Dst ICMP WL:");
    sf_log_u64(l4_sync_t1->sync_dst_other_wl_rcvd, "Sync Rcv Dst OTHER WL:");
    sf_log_u64(l4_sync_t1->sync_dst_tcp_bl_rcvd, "Sync Rcv Dst TCP BL:");
    sf_log_u64(l4_sync_t1->sync_dst_udp_bl_rcvd, "Sync Rcv Dst UDP BL:");
    sf_log_u64(l4_sync_t1->sync_dst_icmp_bl_rcvd, "Sync Rcv Dst ICMP BL:");
    sf_log_u64(l4_sync_t1->sync_dst_other_bl_rcvd, "Sync Rcv Dst OTHER BL:");
    sf_log_u64(l4_sync_t1->sync_src_tcp_wl_rcvd, "Sync Rcv Src TCP WL:");
    sf_log_u64(l4_sync_t1->sync_src_udp_wl_rcvd, "Sync Rcv Src UDP WL:");
    sf_log_u64(l4_sync_t1->sync_src_icmp_wl_rcvd, "Sync Rcv Src ICMP WL:");
    sf_log_u64(l4_sync_t1->sync_src_other_wl_rcvd, "Sync Rcv Src OTHER WL:");
    sf_log_u64(l4_sync_t1->sync_src_tcp_bl_rcvd, "Sync Rcv Src TCP BL:");
    sf_log_u64(l4_sync_t1->sync_src_udp_bl_rcvd, "Sync Rcv Src UDP BL:");
    sf_log_u64(l4_sync_t1->sync_src_icmp_bl_rcvd, "Sync Rcv Src ICMP BL:");
    sf_log_u64(l4_sync_t1->sync_src_other_bl_rcvd, "Sync Rcv Src OTHER BL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_tcp_wl_rcvd, "Sync Rcv SrcDst TCP WL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_udp_wl_rcvd, "Sync Rcv SrcDst UDP WL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_icmp_wl_rcvd, "Sync Rcv SrcDst ICMP WL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_other_wl_rcvd, "Sync Rcv SrcDst OTHER WL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_tcp_bl_rcvd, "Sync Rcv SrcDst TCP BL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_udp_bl_rcvd, "Sync Rcv SrcDst UDP BL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_icmp_bl_rcvd, "Sync Rcv SrcDst ICMP BL:");
    sf_log_u64(l4_sync_t1->sync_src_dst_other_bl_rcvd, "Sync Rcv SrcDst OTHER BL:");

}

/* L4 TUNNEL CounterBlockTag read:*/

static void readCounters_DDOS_L4_TUNNEL_COUNTER(SFSample *sample)
{

    sflow_ddos_tunnel_stats_t *tunnel_t1 = &(sample->ddos.l4_tunnel);
    populate_sflow_struct_u64(sample, (void *)tunnel_t1, sizeof(sflow_ddos_tunnel_stats_t));

    sf_log_u64(tunnel_t1->ip_tunnel_rcvd, "IPv4 Tunnel Rcv:");
    sf_log_u64(tunnel_t1->ip_tunnel_rate, "IPv4 Tunnel Encap:");
    sf_log_u64(tunnel_t1->ip_tunnel_encap, "IPv4 Tunnel Encap Fail:");
    sf_log_u64(tunnel_t1->ip_tunnel_encap_fail, "IPv4 Tunnel Decap:");
    sf_log_u64(tunnel_t1->ip_tunnel_decap, "IPv4 Tunnel Decap Fail:");
    sf_log_u64(tunnel_t1->ip_tunnel_decap_fail, "IPv4 Tunnel Rate:");
    sf_log_u64(tunnel_t1->ipv6_tunnel_rcvd, "IPv6 Tunnel Rcv:");
    sf_log_u64(tunnel_t1->ipv6_tunnel_rate, "IPv6 Tunnel Encap:");
    sf_log_u64(tunnel_t1->ipv6_tunnel_encap, "IPv6 Tunnel Encap Fail:");
    sf_log_u64(tunnel_t1->ipv6_tunnel_encap_fail, "IPv6 Tunnel Decap:");
    sf_log_u64(tunnel_t1->ipv6_tunnel_decap, "IPv6 Tunnel Decap Fail:");
    sf_log_u64(tunnel_t1->ipv6_tunnel_decap_fail, "IPv6 Tunnel Rate:");
    sf_log_u64(tunnel_t1->gre_tunnel_rcvd, "GRE Tunnel Rcv:");
    sf_log_u64(tunnel_t1->gre_tunnel_rate, "GRE Tunnel Encap:");
    sf_log_u64(tunnel_t1->gre_tunnel_encap, "GRE Tunnel Encap Fail:");
    sf_log_u64(tunnel_t1->gre_tunnel_encap_fail, "GRE Tunnel Decap:");
    sf_log_u64(tunnel_t1->gre_tunnel_decap, "GRE Tunnel Decap Fail:");
    sf_log_u64(tunnel_t1->gre_tunnel_decap_fail, "GRE Tunnel Rate:");
    sf_log_u64(tunnel_t1->gre_tunnel_encap_key, "GRE Tunnel Encap W/ Key:");
    sf_log_u64(tunnel_t1->gre_tunnel_decap_key, "GRE Tunnel Decap W/ Key:");
    sf_log_u64(tunnel_t1->gre_tunnel_decap_drop_no_key, "GRE Tunnel Decap Key Mismatch Drop:");
    sf_log_u64(tunnel_t1->gre_v6_tunnel_rcvd, "GRE V6 Tunnel Rcv:");
    sf_log_u64(tunnel_t1->gre_v6_tunnel_rate, "GRE V6 Tunnel Encap:");
    sf_log_u64(tunnel_t1->gre_v6_tunnel_encap, "GRE V6 Tunnel Encap Rcv Fail:");
    sf_log_u64(tunnel_t1->gre_v6_tunnel_encap_fail, "GRE V6 Tunnel Decap:");
    sf_log_u64(tunnel_t1->gre_v6_tunnel_decap, "GRE V6 Tunnel Decap Fail:");
    sf_log_u64(tunnel_t1->gre_v6_tunnel_decap_fail, "GRE V6 Tunnel Rate:");
    sf_log_u64(tunnel_t1->gre_v6_tunnel_encap_key, "GRE V6 Tunnel Encap W/ Key:");
    sf_log_u64(tunnel_t1->gre_v6_tunnel_decap_key, "GRE V6 Tunnel Decap W/ Key:");
    sf_log_u64(tunnel_t1->gre_v6_tunnel_decap_drop_no_key, "GRE V6 Tunnel Decap No Key Drop:");

}

/* DDOS Entry Table CounterBlockTag read: */

static void readCounters_DDOS_ENTRY_TABLE_COUNTER(SFSample *sample)
{

    sflow_ddos_table_stats_t *table_t1 = &(sample->ddos.entry_table);
    populate_sflow_struct_u64(sample, (void *)table_t1, sizeof(sflow_ddos_table_stats_t));

    sf_log_u64(table_t1->dst_entry_learn, "Dst Entry Learn:");
    sf_log_u64(table_t1->dst_entry_hit, "Dst Entry Hit:");
    sf_log_u64(table_t1->dst_entry_miss, "Dst Entry Miss:");
    sf_log_u64(table_t1->dst_entry_aged, "Dst Entry Aged:");
    sf_log_u64(table_t1->src_entry_learn, "Src Entry Learn:");
    sf_log_u64(table_t1->src_entry_hit, "Src Entry Hit:");
    sf_log_u64(table_t1->src_entry_miss, "Src Entry Miss:");
    sf_log_u64(table_t1->src_entry_aged, "Src Entry Aged:");
    sf_log_u64(table_t1->src_dst_entry_learn, "SrcDst Entry Learn:");
    sf_log_u64(table_t1->src_dst_entry_hit, "SrcDst Entry Hit:");
    sf_log_u64(table_t1->src_dst_entry_miss, "SrcDst Entry Miss:");
    sf_log_u64(table_t1->src_dst_entry_aged, "SrcDst Entry Aged:");
    sf_log_u64(table_t1->src_wl_tcp, "TCP Src WL:");
    sf_log_u64(table_t1->src_wl_udp, "UDP Src WL:");
    sf_log_u64(table_t1->src_wl_icmp, "ICMP Src WL:");
    sf_log_u64(table_t1->src_wl_other, "OTHER Src WL:");
    sf_log_u64(table_t1->src_bl_tcp, "TCP Src BL:");
    sf_log_u64(table_t1->src_bl_udp, "UDP Src BL:");
    sf_log_u64(table_t1->src_bl_icmp, "ICMP Src BL:");
    sf_log_u64(table_t1->src_bl_other, "OTHER Src BL:");
    sf_log_u64(table_t1->src_dst_wl_tcp, "TCP SrcDst WL:");
    sf_log_u64(table_t1->src_dst_wl_udp, "UDP SrcDst WL:");
    sf_log_u64(table_t1->src_dst_wl_icmp, "ICMP SrcDst WL:");
    sf_log_u64(table_t1->src_dst_wl_other, "OTHER SrcDst WL:");
    sf_log_u64(table_t1->src_dst_bl_tcp, "TCP SrcDst BL:");
    sf_log_u64(table_t1->src_dst_bl_udp, "UDP SrcDst BL:");
    sf_log_u64(table_t1->src_dst_bl_icmp, "ICMP SrcDst BL:");
    sf_log_u64(table_t1->src_dst_bl_other, "OTHER SrcDst BL:");
    sf_log_u64(table_t1->dst_over_limit_on, "Dst Over Limit Trigger ON:");
    sf_log_u64(table_t1->dst_port_over_limit_on, "Dst Port Over Limit Trigger ON:");
    sf_log_u64(table_t1->src_over_limit_on, "Src Over Limit Trigger ON:");
    sf_log_u64(table_t1->src_dst_over_limit_on, "SrcDst Over Limit Trigger ON:");
    sf_log_u64(table_t1->dst_over_limit_off, "Dst Over Limit Trigger OFF:");
    sf_log_u64(table_t1->dst_port_over_limit_off, "Dst Port Over Limit Trigger OFF:");
    sf_log_u64(table_t1->src_over_limit_off, "Src Over Limit Trigger OFF:");
    sf_log_u64(table_t1->src_dst_over_limit_off, "SrcDst Over Limit Trigger OFF:");

}

/* DDOS BRIEF STAT CounterBlockTag read: */

static void readCounters_DDOS_BRIEF_STATS_COUNTER(SFSample *sample)
{
    int len = 0;
    long tstamp = time(NULL);
    char tbuf [200];
    char buf [50];

    sprintf (tbuf, "agent=%08x\n", htonl(sample->agent_addr.address.ip_v4.addr));

    sflow_ddos_brief_stats_t *ddos_brief_stats_t1 = &(sample->ddos.ddos_brief_stats);
    populate_sflow_struct_u64(sample, (void *)ddos_brief_stats_t1, sizeof(sflow_ddos_brief_stats_t));

    len += sprintf (tsdb_buff + len, "put intcp %lu %lu %s", tstamp, ddos_brief_stats_t1->intcp, tbuf);
    len += sprintf (tsdb_buff + len, "put inudp %lu %lu %s", tstamp, ddos_brief_stats_t1->inudp, tbuf);
    len += sprintf (tsdb_buff + len, "put inicmp %lu %lu %s", tstamp, ddos_brief_stats_t1->inicmp, tbuf);
    len += sprintf (tsdb_buff + len, "put inother %lu %lu %s", tstamp, ddos_brief_stats_t1->inother, tbuf);
    len += sprintf (tsdb_buff + len, "put tcp_total_drop %lu %lu %s", tstamp, ddos_brief_stats_t1->tcp_total_drop, tbuf);
    len += sprintf (tsdb_buff + len, "put udp_total_drop %lu %lu %s", tstamp, ddos_brief_stats_t1->udp_total_drop, tbuf);
    len += sprintf (tsdb_buff + len, "put icmp_total_drop %lu %lu %s", tstamp, ddos_brief_stats_t1->icmp_total_drop, tbuf);
    len += sprintf (tsdb_buff + len, "put other_total_drop %lu %lu %s", tstamp, ddos_brief_stats_t1->other_total_drop, tbuf);
    len += sprintf (tsdb_buff + len, "put tcp_sess_create %lu %lu %s", tstamp, ddos_brief_stats_t1->tcp_sess_create, tbuf);
    len += sprintf (tsdb_buff + len, "put udp_sess_create %lu %lu %s", tstamp, ddos_brief_stats_t1->udp_sess_create, tbuf);
    len += sprintf (tsdb_buff + len, "put global_dst_packet_sent %lu %lu %s", tstamp, ddos_brief_stats_t1->dst_fwd_pkt_sent, tbuf);
    len += sprintf (tsdb_buff + len, "put global_dst_ingress_bytes %lu %lu %s", tstamp, ddos_brief_stats_t1->dst_ingress_bytes, tbuf);
    len += sprintf (tsdb_buff + len, "put global_dst_egress_bytes %lu %lu %s", tstamp, ddos_brief_stats_t1->dst_fwd_byte_sent, tbuf);
    packet_anomaly_passed = ddos_brief_stats_t1->ip_rcvd + ddos_brief_stats_t1->ipv6_rcvd - packet_anomaly_dropped;
    len += sprintf (tsdb_buff + len, "put packet_anomaly_passed %lu %lu %s", tstamp, packet_anomaly_passed, tbuf);
//    len += sprintf (tsdb_buff + len, "put %lu %lu %s", tstamp, ddos_brief_stats_t1->, tbuf);

    int ret = opentsdb_simple_connect(tsdb_buff);

//    printf ("ret - %d\n", ret);
    sf_log_u64(ddos_brief_stats_t1->ip_rcvd, "IPv4 Rcv:");
    sf_log_u64(ddos_brief_stats_t1->ip_sent, "IPv4 Sent:");
    sf_log_u64(ddos_brief_stats_t1->ipv6_rcvd, "IPv6 Rcv:");
    sf_log_u64(ddos_brief_stats_t1->ipv6_sent, "IPv6 Sent:");
    sf_log_u64(ddos_brief_stats_t1->out_no_route, "IPv4/v6 Out No Route:");
    sf_log_u64(ddos_brief_stats_t1->not_for_ddos, "Not For DDOS:");
    sf_log_u64(ddos_brief_stats_t1->instateless, "Stateless Pkt Rcv:");
    sf_log_u64(ddos_brief_stats_t1->intcp, "TCP Rcv:");
    sf_log_u64(ddos_brief_stats_t1->inudp, "UDP Rcv:");
    sf_log_u64(ddos_brief_stats_t1->inicmp, "ICMP Rcv:");
    sf_log_u64(ddos_brief_stats_t1->inother, "OTHER Rcv:");
    sf_log_u64(ddos_brief_stats_t1->v4_sess_create, "IPv4 Session Create:");
    sf_log_u64(ddos_brief_stats_t1->v6_sess_create, "IPv6 Session Create:");
    sf_log_u64(ddos_brief_stats_t1->tcp_sess_create, "TCP Session Create:");
    sf_log_u64(ddos_brief_stats_t1->udp_sess_create, "UDP Session Create:");
    sf_log_u64(ddos_brief_stats_t1->sess_aged_out, "Session Age Out:");
    sf_log_u64(ddos_brief_stats_t1->tcp_total_drop, "TCP Total Drop:");
    sf_log_u64(ddos_brief_stats_t1->tcp_dst_drop, "TCP Dst Drop:");
    sf_log_u64(ddos_brief_stats_t1->tcp_src_drop, "TCP Src Drop:");
    sf_log_u64(ddos_brief_stats_t1->tcp_src_dst_drop, "TCP SrcDst Drop:");
    sf_log_u64(ddos_brief_stats_t1->tcp_drop_black_dst, "TCP Dst BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->tcp_drop_black_src, "TCP Src BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->tcp_drop_black_src_dst, "TCP SrcDst BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->tcp_exceed_drop_any_dst, "TCP Dst Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->tcp_exceed_drop_any_src, "TCP Src Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->tcp_exceed_drop_any_src_dst, "TCP SrcDst Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->udp_total_drop, "UDP Total Drop:");
    sf_log_u64(ddos_brief_stats_t1->udp_dst_drop, "UDP Dst Drop:");
    sf_log_u64(ddos_brief_stats_t1->udp_src_drop, "UDP Src Drop:");
    sf_log_u64(ddos_brief_stats_t1->udp_src_dst_drop, "UDP SrcDst Drop:");
    sf_log_u64(ddos_brief_stats_t1->udp_drop_black_dst, "UDP Dst BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->udp_drop_black_src, "UDP Src BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->udp_drop_black_src_dst, "UDP SrcDst BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->udp_exceed_drop_any_dst, "UDP Dst Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->udp_exceed_drop_any_src, "UDP Src Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->udp_exceed_drop_any_src_dst, "UDP SrcDst Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->icmp_total_drop, "ICMP Total Drop:");
    sf_log_u64(ddos_brief_stats_t1->icmp_dst_drop, "ICMP Dst Drop:");
    sf_log_u64(ddos_brief_stats_t1->icmp_src_drop, "ICMP Src Drop:");
    sf_log_u64(ddos_brief_stats_t1->icmp_src_dst_drop, "ICMP SrcDst Drop:");
    sf_log_u64(ddos_brief_stats_t1->icmp_drop_black_dst, "ICMP Dst BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->icmp_drop_black_src, "ICMP Src BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->icmp_drop_black_src_dst, "ICMP SrcDst BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->icmp_exceed_drop_any_dst, "ICMP Dst Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->icmp_exceed_drop_any_src, "ICMP Src Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->icmp_exceed_drop_any_src_dst, "ICMP SrcDst Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->other_total_drop, "OTHER Total Drop:");
    sf_log_u64(ddos_brief_stats_t1->other_dst_drop, "OTHER Dst Drop:");
    sf_log_u64(ddos_brief_stats_t1->other_src_drop, "OTHER Src Drop:");
    sf_log_u64(ddos_brief_stats_t1->other_src_dst_drop, "OTHER SrcDst Drop:");
    sf_log_u64(ddos_brief_stats_t1->other_drop_black_dst, "OTHER Dst BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->other_drop_black_src, "OTHER Src BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->other_drop_black_src_dst, "OTHER SrcDst BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->other_exceed_drop_any_dst, "OTHER Dst Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->other_exceed_drop_src, "OTHER Src Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->other_exceed_drop_src_dst, "OTHER SrcDst Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->infrag, "OTHER Frag Rcv:");
    sf_log_u64(ddos_brief_stats_t1->frag_drop, "OTHER Frag Drop:");
    sf_log_u64(ddos_brief_stats_t1->http_drop_total, "HTTP Total Drop:");
    sf_log_u64(ddos_brief_stats_t1->http_drop_dst, "HTTP Dst Drop:");
    sf_log_u64(ddos_brief_stats_t1->http_drop_src, "HTTP Src Drop:");
    sf_log_u64(ddos_brief_stats_t1->http_drop_src_dst, "HTTP SrcDst Drop:");
    sf_log_u64(ddos_brief_stats_t1->dns_udp_drop_total, "DNS-UDP Total Drop:");
    sf_log_u64(ddos_brief_stats_t1->dns_udp_drop_dst, "DNS-UDP Dst Drop:");
    sf_log_u64(ddos_brief_stats_t1->dns_udp_drop_src, "DNS-UDP Src Drop:");
    sf_log_u64(ddos_brief_stats_t1->dns_udp_drop_src_dst, "DNS-UDP SrcDst Drop:");
    sf_log_u64(ddos_brief_stats_t1->dns_tcp_drop_total, "DNS-TCP Total Drop:");
    sf_log_u64(ddos_brief_stats_t1->dns_tcp_drop_dst, "DNS-TCP Dst Drop:");
    sf_log_u64(ddos_brief_stats_t1->dns_tcp_drop_src, "DNS-TCP Src Drop:");
    sf_log_u64(ddos_brief_stats_t1->dns_tcp_drop_src_dst, "DNS-TCP SrcDst Drop:");
    sf_log_u64(ddos_brief_stats_t1->ssl_l4_drop_total, "SSL-L4 Total Drop:");
    sf_log_u64(ddos_brief_stats_t1->ssl_l4_drop_dst, "SSL-L4 Dst Drop:");
    sf_log_u64(ddos_brief_stats_t1->ssl_l4_drop_src, "SSL-L4 Src Drop:");
    sf_log_u64(ddos_brief_stats_t1->ssl_l4_drop_src_dst, "SSL-L4 SrcDst Drop:");
    sf_log_u64(ddos_brief_stats_t1->dst_port_undef_drop, "Dst Port Undef Drop:");
    sf_log_u64(ddos_brief_stats_t1->dst_port_exceed_drop_any, "Dst Port Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->dst_ipproto_bl, "Dst IP-Proto BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->dst_port_bl, "Dst Port BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->dst_sport_bl, "Dst SrcPort BL Drop:");
    sf_log_u64(ddos_brief_stats_t1->dst_sport_exceed_drop_any, "Dst SrcPort Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->dst_ipproto_rcvd, "Dst IP-Proto Rcv:");
    sf_log_u64(ddos_brief_stats_t1->dst_ipproto_drop, "Dst IP-Proto Drop:");
    sf_log_u64(ddos_brief_stats_t1->dst_ipproto_exceed_drop_any, "Dst IP-Proto Excd Drop:");
    sf_log_u64(ddos_brief_stats_t1->src_ip_bypass, "Src IP Bypass:");
    sf_log_u64(ddos_brief_stats_t1->mpls_rcvd, "MPLS Rcv:");
    sf_log_u64(ddos_brief_stats_t1->mpls_drop, "MPLS Drop:");
    sf_log_u64(ddos_brief_stats_t1->mpls_malformed, "MPLS Malformed:");
    sf_log_u64(ddos_brief_stats_t1->dst_scanning_detected, "Dst Scanning Detected:");
    sf_log_u64(ddos_brief_stats_t1->dst_ingress_bytes, "Ingress Bytes:");
    sf_log_u64(ddos_brief_stats_t1->dst_egress_bytes, "Egress Bytes:");
    sf_log_u64(ddos_brief_stats_t1->dst_ingress_packets, "Ingress Packets:");
    sf_log_u64(ddos_brief_stats_t1->dst_egress_packets, "Egress Packets:");
    sf_log_u64(ddos_brief_stats_t1->dst_ip_bypass, "Dst IP Bypass:");
    sf_log_u64(ddos_brief_stats_t1->dst_blackhole_inject, "Dst Blackhole Inject:");
    sf_log_u64(ddos_brief_stats_t1->dst_blackhole_withdraw, "Dst Blackhole Withdraw:");
    sf_log_u64(ddos_brief_stats_t1->dst_fwd_pkt_sent, "Incoming Packets Sent:");
    sf_log_u64(ddos_brief_stats_t1->dst_rev_pkt_sent, "Outgoing Packets Sent:");
    sf_log_u64(ddos_brief_stats_t1->dst_fwd_byte_sent, "Incoming Bytes Sent:");
    sf_log_u64(ddos_brief_stats_t1->dst_rev_byte_sent, "Outgoing Bytes Sent:");

}

/* DDOS LONG STAT CounterBlockTag read: */

static void readCounters_DDOS_LONG_STATS_COUNTER(SFSample *sample)
{

    sflow_ddos_long_stats_t *ddos_long_stats_t1 = &(sample->ddos.ddos_long_stats);
    populate_sflow_struct_u64(sample, (void *)ddos_long_stats_t1, sizeof(sflow_ddos_long_stats_t));

    sf_log_u64(ddos_long_stats_t1->tcp_syncookie_sent, "TCP SYN Cookie Sent:");
    sf_log_u64(ddos_long_stats_t1->tcp_syncookie_pass, "TCP SYN Cookie Pass:");
    sf_log_u64(ddos_long_stats_t1->tcp_syncookie_sent_fail, "TCP SYN Cookie Sent Fail:");
    sf_log_u64(ddos_long_stats_t1->tcp_syncookie_check_fail, "TCP SYN Cookie Check Fail:");
    sf_log_u64(ddos_long_stats_t1->tcp_syncookie_fail_bl, "TCP SYN Cookie BL Fail:");
    sf_log_u64(ddos_long_stats_t1->tcp_outrst, "TCP Out RST:");
    sf_log_u64(ddos_long_stats_t1->tcp_syn_received, "TCP SYN Rcv:");
    sf_log_u64(ddos_long_stats_t1->tcp_syn_rate, "TCP SYN Rate Per Sec:");
    sf_log_u64(ddos_long_stats_t1->tcp_exceed_drop_prate_dst, "TCP Dst Pkt Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->tcp_exceed_drop_crate_dst, "TCP Dst Conn Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->tcp_exceed_drop_climit_dst, "TCP Dst Conn Limit Drop:");
    sf_log_u64(ddos_long_stats_t1->tcp_exceed_drop_prate_src, "TCP Src Pkt Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->tcp_exceed_drop_crate_src, "TCP Src Conn Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->tcp_exceed_drop_climit_src, "TCP Src Conn Limit Drop:");
    sf_log_u64(ddos_long_stats_t1->tcp_exceed_drop_prate_src_dst, "TCP SrcDst Pkt Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->tcp_exceed_drop_crate_src_dst, "TCP SrcDst Conn Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->tcp_exceed_drop_climit_src_dst, "TCP SrcDst Conn Limit Drop:");
    sf_log_u64(ddos_long_stats_t1->udp_exceed_drop_prate_dst, "UDP Dst Pkt Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->udp_exceed_drop_crate_dst, "UDP Dst Conn Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->udp_exceed_drop_climit_dst, "UDP Dst Conn Limit Drop:");
    sf_log_u64(ddos_long_stats_t1->udp_exceed_drop_prate_src, "UDP Src Pkt Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->udp_exceed_drop_crate_src, "UDP Src Conn Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->udp_exceed_drop_climit_src, "UDP Src Conn Limit Drop:");
    sf_log_u64(ddos_long_stats_t1->udp_exceed_drop_prate_src_dst, "UDP SrcDst Pkt Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->udp_exceed_drop_crate_src_dst, "UDP SrcDst Conn Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->udp_exceed_drop_climit_src_dst, "UDP SrcDst Conn Limit Drop:");
    sf_log_u64(ddos_long_stats_t1->udp_exceed_drop_conn_prate, "UDP Conn Pkt Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->dns_malform_drop, "DNS Malform Drop:");
    sf_log_u64(ddos_long_stats_t1->dns_qry_any_drop, "DNS Query Any Drop:");
    sf_log_u64(ddos_long_stats_t1->tcp_reset_client, "TCP Reset Client:");
    sf_log_u64(ddos_long_stats_t1->tcp_reset_server, "TCP Reset Server:");
    sf_log_u64(ddos_long_stats_t1->dst_entry_learn, "Dst Entry Learn:");
    sf_log_u64(ddos_long_stats_t1->dst_entry_hit, "Dst Entry Hit:");
    sf_log_u64(ddos_long_stats_t1->src_entry_learn, "Src Entry Learn:");
    sf_log_u64(ddos_long_stats_t1->src_entry_hit, "Src Entry Hit:");
    sf_log_u64(ddos_long_stats_t1->sync_src_wl_sent, "Sync Src Sent:");
    sf_log_u64(ddos_long_stats_t1->sync_src_dst_wl_sent, "Sync SrcDst Sent:");
    sf_log_u64(ddos_long_stats_t1->sync_dst_wl_sent, "Sync Dst Sent:");
    sf_log_u64(ddos_long_stats_t1->sync_src_wl_rcv, "Sync Src Rcv:");
    sf_log_u64(ddos_long_stats_t1->sync_src_dst_wl_rcv, "Sync SrcDst Rcv:");
    sf_log_u64(ddos_long_stats_t1->sync_dst_wl_rcv, "Sync Dst Rcv:");
    sf_log_u64(ddos_long_stats_t1->dst_port_pkt_rate_exceed, "Dst Port Pkt Rate Excd:");
    sf_log_u64(ddos_long_stats_t1->dst_port_conn_limm_exceed, "Dst Port Conn Limit Excd:");
    sf_log_u64(ddos_long_stats_t1->dst_port_conn_rate_exceed, "Dst Port Conn Rate Excd:");
    sf_log_u64(ddos_long_stats_t1->dst_sport_pkt_rate_exceed, "Dst SrcPort Pkt Rate Excd:");
    sf_log_u64(ddos_long_stats_t1->dst_sport_conn_limm_exceed, "Dst SrcPort Conn Limit Excd:");
    sf_log_u64(ddos_long_stats_t1->dst_sport_conn_rate_exceed, "Dst SrcPort Conn Rate Excd:");
    sf_log_u64(ddos_long_stats_t1->dst_ipproto_pkt_rate_exceed, "Dst IP-Proto Pkt Rate Excd:");

    sf_log_u64(ddos_long_stats_t1->tcp_ack_no_syn, "TCP ACK No SYN:");
    sf_log_u64(ddos_long_stats_t1->tcp_ofo, "TCP Out-Of-Seq:");
    sf_log_u64(ddos_long_stats_t1->tcp_zero_window, "TCP 0 Window:");
    sf_log_u64(ddos_long_stats_t1->tcp_retransmit, "TCP ReXmit");
    sf_log_u64(ddos_long_stats_t1->tcp_retransmit_bl, "TCP ReXmit BL:");

    sf_log_u64(ddos_long_stats_t1->tcp_action_on_ack_start, "TCP Action-On-Ack Init:");
    sf_log_u64(ddos_long_stats_t1->tcp_action_on_ack_matched, "TCP Action-On-Ack Match:");
    sf_log_u64(ddos_long_stats_t1->tcp_action_on_ack_passed, "TCP Action-On-Ack Pass:");
    sf_log_u64(ddos_long_stats_t1->tcp_action_on_ack_failed, "TCP Action-On-Ack Fail:");
    sf_log_u64(ddos_long_stats_t1->tcp_action_on_ack_timeout, "TCP Action-On-Ack Timeout:");
    sf_log_u64(ddos_long_stats_t1->tcp_action_on_ack_reset, "TCP Action-On-Ack Reset:");
    sf_log_u64(ddos_long_stats_t1->src_entry_aged, "Src Entry Aged:");
    sf_log_u64(ddos_long_stats_t1->dst_entry_aged, "Dst Entry Aged:");
    sf_log_u64(ddos_long_stats_t1->tcp_zero_wind_bl, "TCP Zero Window BL:");
    sf_log_u64(ddos_long_stats_t1->tcp_ofo_bl, "TCP Out-Of-Seq BL:");
    sf_log_u64(ddos_long_stats_t1->syn_auth_skip, "TCP SYN Auth Skip:");
    sf_log_u64(ddos_long_stats_t1->udp_retry_pass, "UDP Retry Pass:");
    sf_log_u64(ddos_long_stats_t1->dns_auth_udp_pass, "DNS Auth UDP Pass:");
    sf_log_u64(ddos_long_stats_t1->dst_port_udp_wellknown_port_drop, "UDP Wellknown Port Drop:");
    sf_log_u64(ddos_long_stats_t1->ntp_monlist_req_drop, "NTP Monlist Req Drop:");
    sf_log_u64(ddos_long_stats_t1->ntp_monlist_resp_drop, "NTP Monlist Resp Drop:");
    sf_log_u64(ddos_long_stats_t1->udp_payload_too_big_drop, "UDP Payload Too Large Drop:");
    sf_log_u64(ddos_long_stats_t1->udp_payload_too_small_drop, "UDP Payload Too Small Drop:");
    sf_log_u64(ddos_long_stats_t1->other_frag_exceed_drop_dst, "OTHER Dst Frag Excd Drop:");
    sf_log_u64(ddos_long_stats_t1->other_frag_exceed_drop_src, "OTHER Src Frag Excd Drop:");
    sf_log_u64(ddos_long_stats_t1->other_frag_exceed_drop_src_dst, "OTHER SrcDst Frag Excd Drop:");
    sf_log_u64(ddos_long_stats_t1->tcp_rexmit_syn_limit_drop, "TCP Rexmit SYN Excd Drop:");
    sf_log_u64(ddos_long_stats_t1->tcp_rexmit_syn_limit_bl, "TCP ReXmit SYN Excd BL:");

    sf_log_u64(ddos_long_stats_t1->over_conn_limit_tcp_syn_auth, "Over conn limit TCP SYN Auth");
    sf_log_u64(ddos_long_stats_t1->over_conn_limit_tcp_syn_cookie, "Over conn limit TCP SYN Cookie");
    sf_log_u64(ddos_long_stats_t1->over_conn_limit_tcp_port_syn_auth, "Over conn limit TCP port SYN Auth");
    sf_log_u64(ddos_long_stats_t1->over_conn_limit_tcp_port_syn_cookie, "Over conn limit TCP port SYN Cookie");

    sf_log_u64(ddos_long_stats_t1->tcp_exceed_drop_conn_prate, "TCP Conn Pkt Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->syn_auth_pass, "TCP SYN Auth Pass:");
    sf_log_u64(ddos_long_stats_t1->udp_retry_start, "UDP Retry Init:");
    sf_log_u64(ddos_long_stats_t1->udp_retry_fail, "UDP Retry Fail:");
    sf_log_u64(ddos_long_stats_t1->udp_retry_timeout, "UDP Retry Timeout:");
    sf_log_u64(ddos_long_stats_t1->ip_tunnel_rcvd, "IPv4 Tunnel Rcv:");
    sf_log_u64(ddos_long_stats_t1->ipv6_tunnel_rcvd, "IPv6 Tunnel Rcv:");
    sf_log_u64(ddos_long_stats_t1->gre_tunnel_rcvd, "GRE Tunnel Rcv:");
    sf_log_u64(ddos_long_stats_t1->gre_v6_tunnel_rcvd, "GRE V6 Tunnel Rcv");
    sf_log_u64(ddos_long_stats_t1->dst_entry_miss, "Dst Entry Miss:");
    sf_log_u64(ddos_long_stats_t1->src_entry_miss, "Src Entry Miss:");
    sf_log_u64(ddos_long_stats_t1->src_dst_entry_hit, "SrcDst Entry Hit:");
    sf_log_u64(ddos_long_stats_t1->src_dst_entry_miss, "SrcDst Entry Miss:");
    sf_log_u64(ddos_long_stats_t1->src_dst_entry_aged, "SrcDst Entry Aged:");
    sf_log_u64(ddos_long_stats_t1->icmp_exceed_drop_prate_dst, "ICMP Dst Pkt Rate Drop:");
    sf_log_u64(ddos_long_stats_t1->sync_wl_no_dst_drop, "Sync SrcDst No Dst Drop:");
    sf_log_u64(ddos_long_stats_t1->src_dst_entry_learn, "SrcDst Entry Learn:");
    sf_log_u64(ddos_long_stats_t1->dns_tcp_auth_pass, "DNS TCP Auth Pass:");
    sf_log_u64(ddos_long_stats_t1->dst_port_kbit_rate_exceed, "Dst Port KiBit Rate Excd:");
    sf_log_u64(ddos_long_stats_t1->dst_sport_kbit_rate_exceed, "Dst SrcPort KiBit Rate Excd:");
} 

static void readCounters_DDOS_DNS_COUNTER_T2(SFSample *sample, sflow_ddos_ip_counter_dns_t2_data_t *dns_t2)
{

    int len = 0;
    long tstamp = time(NULL);
    char tbuf [200];

    populate_sflow_struct_u64(sample, (void *)dns_t2, sizeof(sflow_ddos_ip_counter_dns_t2_data_t));

    if (sample->ddos.dns_perip.common.ip_type == 1) {
        sprintf (tbuf, "ip=%08x prefix=%d port=%d app-type=%d agent=%08x type=%x\n",
                    sample->ddos.dns_perip.common.ip_addr,
                    sample->ddos.dns_perip.common.subnet_mask,
                    sample->ddos.dns_perip.dns.port,
                    sample->ddos.dns_perip.dns.app_type,
                    htonl(sample->agent_addr.address.ip_v4.addr),
                    sample->ddos.dns_perip.common.ip_type);
    } else {
        unsigned char *i;
        i = sample->ddos.dns_perip.common.ip6_addr.s6_addr;

        sprintf (tbuf, "ip=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x prefix=%d port=%d app-type=%d agent=%08x\n",
                    i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8],
                    i[9], i[10], i[11], i[12], i[13], i[14], i[15],
                    sample->ddos.dns_perip.common.subnet_mask, 
                    sample->ddos.dns_perip.dns.port, 
                    sample->ddos.dns_perip.dns.app_type,
                    htonl(sample->agent_addr.address.ip_v4.addr));
    }

    sf_log_u64(dns_t2->force_tcp_auth, "Force TCP auth:");
    sf_log_u64(dns_t2->udp_auth, "UDP auth:");
    sf_log_u64(dns_t2->dst_rate_limit0, "Dest rate 0 Drop:");
    sf_log_u64(dns_t2->dst_rate_limit1, "Dest rate 1 Drop:");
    sf_log_u64(dns_t2->dst_rate_limit2, "Dest rate 2 Drop:");
    sf_log_u64(dns_t2->dst_rate_limit3, "Dest rate 3 Drop:");
    sf_log_u64(dns_t2->dst_rate_limit4, "Dest rate 4 Drop:");
    sf_log_u64(dns_t2->dst_is_nx, "Response is NXDOMAIN:");
    sf_log_u64(dns_t2->dst_fqdn_stage2_rate_exceed, "FQDN stage-II Exceed:");
    sf_log_u64(dns_t2->dst_nx_bl, "NXDOMAIN query BL:");
    sf_log_u64(dns_t2->dst_nx_drop, "NXDOMAIN Drop:");
    sf_log_u64(dns_t2->dns_req_sent, "Request:");
    sf_log_u64(dns_t2->dns_req_size_exceed, "UDP req size exceed:");
    sf_log_u64(dns_t2->dns_req_retrans, "UDP req retrans:");
    sf_log_u64(dns_t2->dns_tcp_req_incomplete, "TCP req incomplete:");
    sf_log_u64(dns_t2->dns_fqdn_label_len_exceed, "FQDN Label Length Exceed:");
    sf_log_u64(dns_t2->dns_query_type_a, "DNS Query A:");
    sf_log_u64(dns_t2->dns_query_type_aaaa, "DNS Query AAAA:");
    sf_log_u64(dns_t2->dns_query_type_ns, "DNS Query NS:");
    sf_log_u64(dns_t2->dns_query_type_cname, "DNS Query CNAME:");
    sf_log_u64(dns_t2->dns_query_type_any, "DNS Query ANY:");
    sf_log_u64(dns_t2->dns_query_type_srv, "DNS Query SRV:");
    sf_log_u64(dns_t2->dns_query_type_mx, "DNS Query MX:");
    sf_log_u64(dns_t2->dns_query_type_soa, "DNS Query SOA:");
    sf_log_u64(dns_t2->dns_query_type_opt, "DNS Query OPTIONS:");
    sf_log_u64(dns_t2->dns_udp_auth_fail, "UDP Auth Fail:");
    sf_log_u64(dns_t2->dns_malform_drop, "DNS Malformed Query Drop:");
    sf_log_u64(dns_t2->src_rate_limit0, "Src rate 0 Drop:");
    sf_log_u64(dns_t2->src_rate_limit1, "Src rate 1 Drop:");
    sf_log_u64(dns_t2->src_rate_limit2, "Src rate 2 Drop:");
    sf_log_u64(dns_t2->src_rate_limit3, "Src rate 3 Drop:");
    sf_log_u64(dns_t2->src_rate_limit4, "Src rate 4 Drop:");

    sf_log_u64(dns_t2->src_dns_fqdn_label_len_exceed, "Src FQDN Label Length Exceed:");
    sf_log_u64(dns_t2->src_dns_udp_auth_fail, "Src UDP Auth Fail:");
    sf_log_u64(dns_t2->src_force_tcp_auth, "Src Force TCP auth:");
    sf_log_u64(dns_t2->src_dns_malform_drop, "Src DNS Malformed Query Drop:");

    dns_dropped = dns_t2->src_force_tcp_auth + dns_t2->src_dns_udp_auth_fail + dns_t2->src_dns_malform_drop + dns_t2->dst_nx_bl + dns_t2->dst_nx_drop + dns_t2->src_dns_fqdn_label_len_exceed + dns_t2->src_rate_limit0 + dns_t2->src_rate_limit1 + dns_t2->src_rate_limit2 + dns_t2->src_rate_limit3 + dns_t2->src_rate_limit4; 

    len += sprintf (tsdb_buff + len, "put dns_dropped %lu %lu %s", tstamp, dns_dropped, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_force_tcp %lu %lu %s", tstamp, dns_t2->force_tcp_auth, tbuf);
    len += sprintf (tsdb_buff + len, "put force_tcp %lu %lu %s", tstamp, dns_t2->force_tcp_auth + dns_t2->src_force_tcp_auth, tbuf);
    len += sprintf (tsdb_buff + len, "put dns_excl_src_dropped %lu %lu %s", tstamp, dns_excl_src_dropped, tbuf);
    int ret = opentsdb_simple_connect(tsdb_buff);

}

static void readCounters_DDOS_DNS_IP_COUNTER(SFSample *sample)
{
    sample->ddos.dns_perip.dns.port = sf_log_next16(sample, "Port:");
    sample->ddos.dns_perip.dns.app_type = getData16(sample);
    if (sample->ddos.dns_perip.dns.app_type > DDOS_TOTAL_APP_TYPE_SIZE) {
        return;
    }
    sfl_log_ex_string_fmt((char *)ddos_proto_str[sample->ddos.dns_perip.dns.app_type], "App type:");
}

static void readCounters_DDOS_ICMP_COUNTER_T2(SFSample *sample, sflow_ddos_ip_counter_icmp_t2_data_t *icmp_t2)
{
    int len = 0;
    long tstamp = time(NULL);
    char tbuf [200];

    populate_sflow_struct_u64(sample, (void *)icmp_t2, sizeof(sflow_ddos_ip_counter_icmp_t2_data_t));

    if (sample->ddos.icmp_perip.common.ip_type == 1) {
        sprintf (tbuf, "ip=%08x prefix=%d agent=%08x type=%x\n",
                    sample->ddos.icmp_perip.common.ip_addr,
                    sample->ddos.icmp_perip.common.subnet_mask,
                    htonl(sample->agent_addr.address.ip_v4.addr),
                    sample->ddos.icmp_perip.common.ip_type);
    } else {
        unsigned char *i;
        i = sample->ddos.icmp_perip.common.ip6_addr.s6_addr;

        sprintf (tbuf, "ip=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x prefix=%d agent=%08x\n",
                    i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8],
                    i[9], i[10], i[11], i[12], i[13], i[14], i[15],
                    sample->ddos.icmp_perip.common.subnet_mask,
                    htonl(sample->agent_addr.address.ip_v4.addr));
    }
    
    icmp_dropped = icmp_t2->icmp_type_deny_drop + icmp_t2->icmpv4_rfc_undef_drop + icmp_t2->icmpv6_rfc_undef_drop + icmp_t2->icmp_rate_exceed0 + icmp_t2->icmp_rate_exceed1 + icmp_t2->icmp_rate_exceed2 + icmp_t2->icmp_wildcard_deny_drop;

    len += sprintf (tsdb_buff + len, "put icmp_dropped %lu %lu %s", tstamp, icmp_dropped, tbuf);

    int ret = opentsdb_simple_connect(tsdb_buff);

    sf_log_u64(icmp_t2->icmp_type_deny_drop, "ICMP Type Deny Drop :");
    sf_log_u64(icmp_t2->icmpv4_rfc_undef_drop, "ICMPv4 RFC Undef Type Drop:");
    sf_log_u64(icmp_t2->icmpv6_rfc_undef_drop, "ICMPv6 RFC Undef Type Drop:");
    sf_log_u64(icmp_t2->icmp_rate_exceed0, "ICMP Type Code Rate Excd 1 :");
    sf_log_u64(icmp_t2->icmp_rate_exceed1, "ICMP Type Code Rate Excd 2 :");
    sf_log_u64(icmp_t2->icmp_rate_exceed2, "ICMP Type Code Rate Excd 3 :");
    sf_log_u64(icmp_t2->icmp_wildcard_deny_drop, "ICMP Wildcard Deny Drop:");

}

static void readCounters_DDOS_ICMP_IP_COUNTER(SFSample *sample)
{

    readCounters_DDOS_IP_COUNTER_COMMON(sample, &sample->ddos.icmp_perip.common);
    readCounters_DDOS_ICMP_COUNTER_T2(sample, &sample->ddos.icmp_perip.icmp);

}


static void readCounters_DDOS_L4_IP_COUNTER_T2(SFSample *sample, sflow_ddos_ip_counter_l4_t2_data_t *ddos_stat_t2)
{
    int len = 0;
    long tstamp = time(NULL);
    char tbuf [200];

    populate_sflow_struct_u64(sample, (void *)ddos_stat_t2, sizeof(sflow_ddos_ip_counter_l4_t2_data_t));

    if (sample->ddos.l4_perip.common.ip_type == 1) {
        sprintf (tbuf, "ip=%08x prefix=%d agent=%08x type=%x\n",
                    sample->ddos.l4_perip.common.ip_addr, 
                    sample->ddos.l4_perip.common.subnet_mask,
                    htonl(sample->agent_addr.address.ip_v4.addr),
                    sample->ddos.l4_perip.common.ip_type);
    } else {
        unsigned char *i;
        i = sample->ddos.l4_perip.common.ip6_addr.s6_addr;

        sprintf (tbuf, "ip=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x prefix=%d agent=%08x\n",
                    i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8], 
                    i[9], i[10], i[11], i[12], i[13], i[14], i[15],
                    sample->ddos.l4_perip.common.subnet_mask,
                    htonl(sample->agent_addr.address.ip_v4.addr));
    }


    len += sprintf (tsdb_buff + len, "put dst_tcp_pkt %lu %lu %s", tstamp, ddos_stat_t2->dst_tcp_pkt, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_udp_pkt %lu %lu %s", tstamp, ddos_stat_t2->dst_udp_pkt, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_icmp_pkt %lu %lu %s", tstamp, ddos_stat_t2->dst_icmp_pkt, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_other_pkt %lu %lu %s", tstamp, ddos_stat_t2->dst_other_pkt, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_tcp_syn %lu %lu %s", tstamp, ddos_stat_t2->dst_tcp_syn, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_tcp_fin_rcvd %lu %lu %s", tstamp, ddos_stat_t2->tcp_fin_rcvd, tbuf);

    len += sprintf (tsdb_buff + len, "put dst_tcp_pkt_rcvd %lu %lu %s", tstamp, ddos_stat_t2->dst_tcp_pkt_rcvd, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_udp_pkt_rcvd %lu %lu %s", tstamp, ddos_stat_t2->dst_udp_pkt_rcvd, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_icmp_pkt_rcvd %lu %lu %s", tstamp, ddos_stat_t2->dst_icmp_pkt_rcvd, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_other_pkt_rcvd %lu %lu %s", tstamp, ddos_stat_t2->dst_other_pkt_rcvd, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_tcp_drop %lu %lu %s", tstamp, ddos_stat_t2->dst_tcp_drop + ddos_stat_t2->dst_tcp_auth + ddos_stat_t2->src_tcp_auth, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_udp_drop %lu %lu %s", tstamp, ddos_stat_t2->dst_udp_drop, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_icmp_drop %lu %lu %s", tstamp, ddos_stat_t2->dst_icmp_drop, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_other_drop %lu %lu %s", tstamp, ddos_stat_t2->dst_other_drop, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_tcp_session_created %lu %lu %s", tstamp, ddos_stat_t2->dst_tcp_session_created, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_udp_session_created %lu %lu %s", tstamp, ddos_stat_t2->dst_udp_session_created, tbuf);
    u64 dst_recvd_total = ddos_stat_t2->ingress_packets;
    u64 dst_pass_total = ddos_stat_t2->dst_fwd_pkt_sent;
    len += sprintf (tsdb_buff + len, "put dst_recvd_total %lu %lu %s", tstamp, dst_recvd_total, tbuf);
    u64 dst_drop_total = ddos_stat_t2->dst_tcp_drop + ddos_stat_t2->dst_udp_drop +
                    ddos_stat_t2->dst_icmp_drop + ddos_stat_t2->dst_other_drop + ddos_stat_t2->dst_tcp_auth + ddos_stat_t2->src_tcp_auth;
    len += sprintf (tsdb_buff + len, "put dst_drop_total %lu %lu %s", tstamp, dst_drop_total, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_total_packet_pass %lu %lu %s", tstamp, dst_pass_total, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_total_packet_drop %lu %lu %s", tstamp, dst_drop_total, tbuf);
    len += sprintf (tsdb_buff + len, "put dst.ingress_packets %lu %lu %s", tstamp, ddos_stat_t2->ingress_packets, tbuf);
    len += sprintf (tsdb_buff + len, "put dst.ingress_bytes %lu %lu %s", tstamp, ddos_stat_t2->ingress_bytes, tbuf);
    len += sprintf (tsdb_buff + len, "put dst.egress_packets %lu %lu %s", tstamp, ddos_stat_t2->egress_packets, tbuf);
    len += sprintf (tsdb_buff + len, "put dst.egress_bytes %lu %lu %s", tstamp, ddos_stat_t2->egress_bytes, tbuf);

    port_wildcards_dropped = ddos_stat_t2->dst_port_undef_drop;

    dst_rates_dropped = ddos_stat_t2->dst_tcp_any_exceed + ddos_stat_t2->dst_udp_any_exceed + ddos_stat_t2->dst_icmp_any_exceed + ddos_stat_t2->dst_other_any_exceed + ddos_stat_t2->dst_l4_tcp_blacklist_drop + ddos_stat_t2->dst_l4_udp_blacklist_drop + ddos_stat_t2->dst_l4_icmp_blacklist_drop + ddos_stat_t2->dst_l4_other_blacklist_drop + ddos_stat_t2->dst_drop_frag_pkt;

    src_auth_dropped = ddos_stat_t2->src_tcp_out_of_seq_excd + ddos_stat_t2->src_tcp_retransmit_excd + ddos_stat_t2->src_tcp_zero_window_excd + ddos_stat_t2->src_tcp_conn_prate_excd + ddos_stat_t2->src_tcp_action_on_ack_gap_drop + ddos_stat_t2->src_tcp_action_on_ack_fail + ddos_stat_t2->src_tcp_action_on_syn_gap_drop + ddos_stat_t2->src_tcp_action_on_syn_fail + ddos_stat_t2->src_udp_conn_prate_excd + ddos_stat_t2->src_udp_wellknown_sport_drop + ddos_stat_t2->src_udp_min_payload + ddos_stat_t2->src_udp_max_payload + ddos_stat_t2->src_other_filter_action_blacklist + ddos_stat_t2->src_other_filter_action_drop + ddos_stat_t2->src_udp_filter_action_blacklist + ddos_stat_t2->src_udp_filter_action_drop + ddos_stat_t2->src_tcp_filter_action_blacklist + ddos_stat_t2->src_tcp_filter_action_drop + ddos_stat_t2->src_tcp_syn_cookie_fail + ddos_stat_t2->src_tcp_action_on_ack_init + ddos_stat_t2->src_tcp_action_on_syn_init + ddos_stat_t2->src_udp_ntp_monlist_req + ddos_stat_t2->src_udp_ntp_monlist_resp + ddos_stat_t2->src_udp_retry_init + ddos_stat_t2->src_tcp_auth + ddos_stat_t2->src_tcp_rst_cookie_fail + ddos_stat_t2->src_tcp_unauth_drop;

    src_rates_dropped = ddos_stat_t2->dst_tcp_src_rate_drop + ddos_stat_t2->dst_udp_src_rate_drop + ddos_stat_t2->dst_icmp_src_rate_drop + ddos_stat_t2->dst_other_src_rate_drop + ddos_stat_t2->src_dst_l4_tcp_blacklist_drop + ddos_stat_t2->src_dst_l4_udp_blacklist_drop + ddos_stat_t2->src_dst_l4_icmp_blacklist_drop + ddos_stat_t2->src_dst_l4_other_blacklist_drop;

    ip_proto_dropped = ddos_stat_t2->dst_other_drop - ddos_stat_t2->dst_other_any_exceed - ddos_stat_t2->dst_other_src_drop - ddos_stat_t2->dst_drop_frag_pkt - ddos_stat_t2->dst_l4_other_blacklist_drop;

    port_cm_dropped = (ddos_stat_t2->dst_tcp_drop + ddos_stat_t2->dst_udp_drop + ddos_stat_t2->dst_icmp_drop + ddos_stat_t2->dst_tcp_auth) - (ddos_stat_t2->dst_tcp_any_exceed + ddos_stat_t2->dst_udp_any_exceed + ddos_stat_t2->dst_icmp_any_exceed + ddos_stat_t2->dst_l4_tcp_blacklist_drop + ddos_stat_t2->dst_l4_udp_blacklist_drop + ddos_stat_t2->dst_l4_icmp_blacklist_drop + ddos_stat_t2->dst_port_undef_drop + ddos_stat_t2->dst_tcp_src_drop + ddos_stat_t2->dst_udp_src_drop + ddos_stat_t2->dst_icmp_src_drop);

    if (port_cm_dropped < 0) {
        port_cm_dropped = 0;
    }


    len += sprintf (tsdb_buff + len, "put dst_rates_dropped %lu %lu %s", tstamp, dst_rates_dropped, tbuf);
    len += sprintf (tsdb_buff + len, "put port_wildcards_dropped %lu %lu %s", tstamp, port_wildcards_dropped, tbuf);
    len += sprintf (tsdb_buff + len, "put src_rates_dropped %lu %lu %s", tstamp, src_rates_dropped, tbuf);
    len += sprintf (tsdb_buff + len, "put port_cm_dropped %lu %lu %s", tstamp, port_cm_dropped, tbuf);
    len += sprintf (tsdb_buff + len, "put src_auth_dropped %lu %lu %s", tstamp, src_auth_dropped, tbuf);
    len += sprintf (tsdb_buff + len, "put ip_proto_dropped %lu %lu %s", tstamp, ip_proto_dropped, tbuf);
    len += sprintf (tsdb_buff + len, "put out_no_route %lu %lu %s", tstamp, ddos_stat_t2->dst_out_no_route, tbuf);


    int ret = opentsdb_simple_connect(tsdb_buff);

//    printf ("%s\n", tsdb_buff);
//    printf ("ret - %d\n", ret);
    sf_log_u64(ddos_stat_t2->dst_frag_pkt_rate_exceed, "OTHER drop - Frag rate exceed:");
    sf_log_u64(ddos_stat_t2->dst_icmp_pkt_rate_exceed, "ICMP drop - Pkt rate exceed:");
    sf_log_u64(ddos_stat_t2->dst_other_pkt_rate_exceed, "OTHER drop - Pkt rate exceed:");
    sf_log_u64(ddos_stat_t2->dst_tcp_src_drop, "SRC dst src drop");
    sf_log_u64(ddos_stat_t2->dst_udp_src_drop, "UDP dst src drop");
    sf_log_u64(ddos_stat_t2->dst_icmp_src_drop, "ICMP dst src drop");
    sf_log_u64(ddos_stat_t2->dst_other_src_drop, "OTHER dst src drop");
    sf_log_u64(ddos_stat_t2->dst_tcp_pkt_rcvd, "TCP dst pkt rcvd");
    sf_log_u64(ddos_stat_t2->dst_tcp_conn_limit_exceed, "TCP drop - Conn limit exceed:");
    sf_log_u64(ddos_stat_t2->dst_tcp_any_exceed, "TCP drop:total rate excd:");
    sf_log_u64(ddos_stat_t2->dst_tcp_pkt, "TCP pkt rcvd:");
    sf_log_u64(ddos_stat_t2->dst_tcp_pkt_rate_exceed, "TCP drop - Pkt rate excd:");
    sf_log_u64(ddos_stat_t2->dst_tcp_syn, "TCP dst SYN pkt rcvd:");
    sf_log_u64(ddos_stat_t2->dst_tcp_syn_drop, "TCP dst SYN pkt drop:");
    sf_log_u64(ddos_stat_t2->dst_tcp_conn_rate_exceed, "TCP drop - Conn rate exceed:");
    sf_log_u64(ddos_stat_t2->dst_frag_src_rate_drop, "Frag dst src rate drop:");
    sf_log_u64(ddos_stat_t2->dst_udp_conn_limit_exceed, "UDP drop - Conn limit exceed:");
    sf_log_u64(ddos_stat_t2->dst_udp_pkt, "UDP pkt rcvd:");
    sf_log_u64(ddos_stat_t2->dst_udp_pkt_rate_exceed, "UDP drop - Pkt rate exceed:");
    sf_log_u64(ddos_stat_t2->dst_tcp_auth, "TCP Auth Sent:");
    sf_log_u64(ddos_stat_t2->dst_udp_conn_rate_exceed, "UDP drop - Conn rate exceed:");
    sf_log_u64(ddos_stat_t2->dst_tcp_drop, "TCP drop:");
    sf_log_u64(ddos_stat_t2->dst_udp_drop, "UDP drop:");
    sf_log_u64(ddos_stat_t2->dst_icmp_drop, "ICMP drop:");
    sf_log_u64(ddos_stat_t2->dst_frag_drop, "Frag drop:");
    sf_log_u64(ddos_stat_t2->dst_other_drop, "Other drop:");
    sf_log_u64(ddos_stat_t2->dst_pkt_sent, "Packets Forwarded:");
    sf_log_u64(ddos_stat_t2->dst_fwd_pkt_sent, "Incoming Packets Forwarded:");
    sf_log_u64(ddos_stat_t2->dst_rev_pkt_sent, "Outgoing Packets Forwarded:");
    sf_log_u64(ddos_stat_t2->dst_udp_pkt_sent, "UDP Packets Forwarded:");
    sf_log_u64(ddos_stat_t2->dst_tcp_pkt_sent, "TCP Packets Forwarded:");
    sf_log_u64(ddos_stat_t2->dst_icmp_pkt_sent, "ICMP Packets Forwarded:");
    sf_log_u64(ddos_stat_t2->dst_other_pkt_sent, "Other Packets Forwarded:");
    sf_log_u64(ddos_stat_t2->dst_icmp_pkt, "ICMP pkt rcvd:");
    sf_log_u64(ddos_stat_t2->dst_other_pkt, "OTHER pkt rcvd:");
    sf_log_u64(ddos_stat_t2->dst_tcp_src_rate_drop, "TCP dst src rate drop:");
    sf_log_u64(ddos_stat_t2->dst_udp_src_rate_drop, "UDP dst src rate drop:");
    sf_log_u64(ddos_stat_t2->dst_icmp_src_rate_drop, "ICMP dst src rate drop:");
    sf_log_u64(ddos_stat_t2->dst_other_src_rate_drop, "Other dst src rate drop:");
    sf_log_u64(ddos_stat_t2->dst_port_pkt_rate_exceed, "PORT drop - Pkt rate exceed:");
    sf_log_u64(ddos_stat_t2->dst_port_kbit_rate_exceed, "PORT drop - KiBit rate exceed:");
    sf_log_u64(ddos_stat_t2->dst_port_conn_limit_exceed, "PORT drop - Conn limit exceed:");
    sf_log_u64(ddos_stat_t2->dst_port_conn_rate_exceed, "PORT drop - Conn rate exceed:");
    sf_log_u64(ddos_stat_t2->dst_udp_any_exceed, "UDP drop:total rate excd:");
    sf_log_u64(ddos_stat_t2->dst_udp_filter_match, "UDP Filter Match:");
    sf_log_u64(ddos_stat_t2->dst_udp_filter_not_match, "UDP Filter Not Match:");
    sf_log_u64(ddos_stat_t2->dst_udp_filter_action_blacklist, "UDP Filter Action BL:");
    sf_log_u64(ddos_stat_t2->dst_udp_filter_action_drop, "UDP Filter Action Drop:");
    sf_log_u64(ddos_stat_t2->dst_udp_filter_action_default_pass, "UDP Filter Action Default Pass:");
    sf_log_u64(ddos_stat_t2->dst_tcp_filter_match, "TCP Filter Match:");
    sf_log_u64(ddos_stat_t2->dst_tcp_filter_not_match, "TCP Filter Not Match:");
    sf_log_u64(ddos_stat_t2->dst_tcp_filter_action_blacklist, "TCP Filter Action BL:");
    sf_log_u64(ddos_stat_t2->dst_tcp_filter_action_drop, "TCP Filter Action Drop:");
    sf_log_u64(ddos_stat_t2->dst_tcp_filter_action_default_pass, "TCP Filter Action Default Pass:");
    sf_log_u64(ddos_stat_t2->dst_udp_filter_action_whitelist, "UDP Filter Action WL:");
    sf_log_u64(ddos_stat_t2->dst_udp_pkt_rcvd, "UDP dst pkt rcvd");
    sf_log_u64(ddos_stat_t2->dst_icmp_pkt_rcvd, "ICMP dst pkt rcvd");
    sf_log_u64(ddos_stat_t2->dst_icmp_any_exceed, "ICMP drop:total rate excd:");
    sf_log_u64(ddos_stat_t2->dst_other_pkt_rcvd, "OTHER dst pkt rcvd");
    sf_log_u64(ddos_stat_t2->dst_other_any_exceed, "OTHER drop:total rate excd:");
    sf_log_u64(ddos_stat_t2->tcp_syn_cookie_fail, "TCP Syn Cookie Failed");
    sf_log_u64(ddos_stat_t2->tcp_rst_cookie_fail, "TCP RST Cookie Failed");
    sf_log_u64(ddos_stat_t2->tcp_unauth_drop, "TCP Un-Auth Packet Drop");
    sf_log_u64(ddos_stat_t2->tcp_syn_rcvd, "TCP SYN Rcv");
    sf_log_u64(ddos_stat_t2->tcp_syn_ack_rcvd, "TCP SYN ACK Rcv");
    sf_log_u64(ddos_stat_t2->tcp_ack_rcvd, "TCP ACK Rcv");
    sf_log_u64(ddos_stat_t2->tcp_fin_rcvd, "TCP FIN ACK Rcv");
    sf_log_u64(ddos_stat_t2->tcp_rst_rcvd, "TCP RST Rcv");
    sf_log_u64(ddos_stat_t2->ingress_bytes, "Ingress Bytes");
    sf_log_u64(ddos_stat_t2->egress_bytes, "Egress Bytes");
    sf_log_u64(ddos_stat_t2->ingress_packets, "Ingress Packets");
    sf_log_u64(ddos_stat_t2->egress_packets, "Egress Packets");
    sf_log_u64(ddos_stat_t2->tcp_fwd_recv, "TCP FWD recv");
    sf_log_u64(ddos_stat_t2->udp_fwd_recv, "UDP FWD recv");
    sf_log_u64(ddos_stat_t2->icmp_fwd_recv, "ICMP FWD recv");
    sf_log_u64(ddos_stat_t2->dst_over_limit_on, "DST overlimit on trigger");
    sf_log_u64(ddos_stat_t2->dst_over_limit_off, "DST overlimit off trigger");
    sf_log_u64(ddos_stat_t2->dst_port_over_limit_on, "DST port overlimit on trigger");
    sf_log_u64(ddos_stat_t2->dst_port_over_limit_off, "DST port overlimit off trig");
    sf_log_u64(ddos_stat_t2->dst_over_limit_action, "DST overlimit action");
    sf_log_u64(ddos_stat_t2->dst_port_over_limit_action, "DST port overlimit action");
    sf_log_u64(ddos_stat_t2->scanning_detected_drop, "Scanning Detected drop");
    sf_log_u64(ddos_stat_t2->scanning_detected_blacklist, "Scanning Detected blacklist");
    sf_log_u64(ddos_stat_t2->dst_udp_kibit_rate_drop, "UDP drop:KiBit rate excd");
    sf_log_u64(ddos_stat_t2->dst_tcp_kibit_rate_drop, "TCP drop:KiBit rate excd");
    sf_log_u64(ddos_stat_t2->dst_icmp_kibit_rate_drop, "ICMP drop:KiBit rate excd");
    sf_log_u64(ddos_stat_t2->dst_other_kibit_rate_drop, "OTHER drop:KiBit rate excd");
    sf_log_u64(ddos_stat_t2->dst_port_undef_drop, "Dst Port Undef Drop");
    sf_log_u64(ddos_stat_t2->dst_port_bl, "Dst Port BL Drop");
    sf_log_u64(ddos_stat_t2->dst_src_port_bl, "Dst SrcPort BL");
    sf_log_u64(ddos_stat_t2->dst_tcp_session_created, "Dst TCP Session Created");
    sf_log_u64(ddos_stat_t2->dst_udp_session_created, "Dst UDP Session Created");
    sf_log_u64(ddos_stat_t2->dst_tcp_filter_action_whitelist, "TCP Filter Action WL:");
    sf_log_u64(ddos_stat_t2->dst_other_filter_match, "OTHER Filter Match:");
    sf_log_u64(ddos_stat_t2->dst_other_filter_not_match, "OTHER Filter Not Match:");
    sf_log_u64(ddos_stat_t2->dst_other_filter_action_blacklist, "OTHER Filter Action BL:");
    sf_log_u64(ddos_stat_t2->dst_other_filter_action_drop, "OTHER Filter Action Drop:");
    sf_log_u64(ddos_stat_t2->dst_other_filter_action_default_pass, "OTHER Filter Action Default Pass:");
    sf_log_u64(ddos_stat_t2->dst_other_filter_action_whitelist, "Other Filter Action WL:");
    sf_log_u64(ddos_stat_t2->dst_blackhole_inject, "Dst Blackhole Inject");
    sf_log_u64(ddos_stat_t2->dst_blackhole_withdraw, "Dst Blackhole Withdraw");
    sf_log_u64(ddos_stat_t2->dst_out_no_route, "Dst IPv4/v6 Out No Route"); 
    sf_log_u64(ddos_stat_t2->dst_tcp_out_of_seq_excd, "Dst TCP Out-Of-Seq BL");
    sf_log_u64(ddos_stat_t2->dst_tcp_retransmit_excd, "Dst TCP ReXmit BL");
    sf_log_u64(ddos_stat_t2->dst_tcp_zero_window_excd, "Dst TCP 0 Window BL");
    sf_log_u64(ddos_stat_t2->dst_tcp_conn_prate_excd, "Dst TCP Conn Pkt Rate Drop");
    sf_log_u64(ddos_stat_t2->dst_tcp_action_on_ack_init, "Dst TCP Action-On-Ack Init");
    sf_log_u64(ddos_stat_t2->dst_tcp_action_on_ack_gap_drop, "Dst TCP Action-On-Ack Retry-Gap Drop");
    sf_log_u64(ddos_stat_t2->dst_tcp_action_on_ack_fail, "Dst TCP Action-On-Ack Fail");
    sf_log_u64(ddos_stat_t2->dst_tcp_action_on_ack_pass, "Dst TCP Action-On-Ack Pass");
    sf_log_u64(ddos_stat_t2->dst_tcp_action_on_syn_init, "Dst TCP Action-On-Syn Init");
    sf_log_u64(ddos_stat_t2->dst_tcp_action_on_syn_gap_drop, "Dst TCP Action-On-Syn Retry-Gap Drop");
    sf_log_u64(ddos_stat_t2->dst_tcp_action_on_syn_fail, "Dst TCP Action-On-Syn Fail");
    sf_log_u64(ddos_stat_t2->dst_tcp_action_on_syn_pass, "Dst TCP Action-On-Syn Pass");
    sf_log_u64(ddos_stat_t2->dst_udp_min_payload, "Dst UDP Payload Too Small Drop");
    sf_log_u64(ddos_stat_t2->dst_udp_max_payload, "Dst UDP Payload Too Large Drop");
    sf_log_u64(ddos_stat_t2->dst_udp_conn_prate_excd, "Dst UDP Conn Pkt Rate Drop");
    sf_log_u64(ddos_stat_t2->dst_udp_ntp_monlist_req, "Dst UDP Monlist Req Drop");
    sf_log_u64(ddos_stat_t2->dst_udp_ntp_monlist_resp, "Dst UDP Monlist Resp Drop");
    sf_log_u64(ddos_stat_t2->dst_udp_wellknown_sport_drop, "Dst UDP Wellknown Port Drop");
    sf_log_u64(ddos_stat_t2->dst_udp_retry_init, "Dst UDP Retry Init");
    sf_log_u64(ddos_stat_t2->dst_udp_retry_pass, "Dst UDP Retry Fail");
    sf_log_u64(ddos_stat_t2->dst_drop_frag_pkt, "Dst Drop Frag Pkt");
    sf_log_u64(ddos_stat_t2->dst_l4_tcp_blacklist_drop, "Dst L4-type TCP Blacklist Drop");
    sf_log_u64(ddos_stat_t2->dst_l4_udp_blacklist_drop, "Dst L4-type UDP Blacklist Drop");
    sf_log_u64(ddos_stat_t2->dst_l4_icmp_blacklist_drop, "Dst L4-type ICMP Blacklist Drop");
    sf_log_u64(ddos_stat_t2->dst_l4_other_blacklist_drop, "Dst L4-type OTHER Blacklist Drop");

    sf_log_u64(ddos_stat_t2->src_udp_min_payload, "Src UDP Payload Too Small Drop");
    sf_log_u64(ddos_stat_t2->src_udp_max_payload, "Src UDP Payload Too Large Drop");
    sf_log_u64(ddos_stat_t2->src_udp_ntp_monlist_req, "Src UDP Monlist Req Drop");
    sf_log_u64(ddos_stat_t2->src_udp_ntp_monlist_resp, "Src UDP Monlist Resp Drop");
    sf_log_u64(ddos_stat_t2->src_tcp_action_on_ack_gap_drop, "Src TCP Action-On-Ack Retry-Gap Drop");
    sf_log_u64(ddos_stat_t2->src_tcp_action_on_syn_gap_drop, "Src TCP Action-On-Syn Retry-Gap Drop");
    sf_log_u64(ddos_stat_t2->tcp_new_conn_ack_retry_gap_drop, "Dst TCP New Conn Ack Retry-Gap Drop");
    sf_log_u64(ddos_stat_t2->src_tcp_new_conn_ack_retry_gap_drop, "Src Dst TCP New Conn Ack Retry-Gap Drop");
    sf_log_u64(ddos_stat_t2->src_tcp_filter_action_blacklist, "Src TCP Filter Action BL:");
    sf_log_u64(ddos_stat_t2->src_tcp_filter_action_drop, "Src TCP Filter Action Drop:");
    sf_log_u64(ddos_stat_t2->src_tcp_out_of_seq_excd, "Src TCP Out-Of-Seq BL");
    sf_log_u64(ddos_stat_t2->src_tcp_retransmit_excd, "Src TCP ReXmit BL");
    sf_log_u64(ddos_stat_t2->src_tcp_zero_window_excd, "Src TCP 0 Window BL");
    sf_log_u64(ddos_stat_t2->src_tcp_conn_prate_excd, "Src TCP Conn Pkt Rate Drop");
    sf_log_u64(ddos_stat_t2->src_udp_filter_action_blacklist, "Src UDP Filter Action BL:");
    sf_log_u64(ddos_stat_t2->src_udp_filter_action_drop, "Src UDP Filter Action Drop:");
    sf_log_u64(ddos_stat_t2->src_udp_conn_prate_excd, "Src UDP Conn Pkt Rate Drop");
    sf_log_u64(ddos_stat_t2->src_other_filter_action_blacklist, "Src OTHER Filter Action BL:");
    sf_log_u64(ddos_stat_t2->src_other_filter_action_drop, "Src OTHER Filter Action Drop:");
    sf_log_u64(ddos_stat_t2->dst_port_src_over_limit_action, "DST port Src overlimit action");
    sf_log_u64(ddos_stat_t2->src_tcp_auth, "Src TCP Auth Sent");
    sf_log_u64(ddos_stat_t2->src_tcp_action_on_ack_fail, "DST port Src overlimit action");
    sf_log_u64(ddos_stat_t2->src_tcp_action_on_syn_fail, "DST port Src overlimit action");
    sf_log_u64(ddos_stat_t2->src_udp_wellknown_sport_drop, "DST port Src overlimit action");
    sf_log_u64(ddos_stat_t2->src_tcp_syn_cookie_fail, "DST port Src overlimit action");
    sf_log_u64(ddos_stat_t2->src_tcp_rst_cookie_fail, "Src TCP RST Cookie Failed");
    sf_log_u64(ddos_stat_t2->src_tcp_unauth_drop, "Src TCP Un-Auth Packet Drop");
    sf_log_u64(ddos_stat_t2->src_tcp_action_on_ack_init, "DST port Src overlimit action");
    sf_log_u64(ddos_stat_t2->src_tcp_action_on_syn_init, "DST port Src overlimit action");
    sf_log_u64(ddos_stat_t2->src_udp_retry_init, "DST port Src overlimit action");
    
    sf_log_u64(ddos_stat_t2->src_dst_l4_tcp_blacklist_drop, "Src Dst L4-type TCP Blacklist Drop");
    sf_log_u64(ddos_stat_t2->src_dst_l4_udp_blacklist_drop, "Src Dst L4-type UDP Blacklist Drop");
    sf_log_u64(ddos_stat_t2->src_dst_l4_icmp_blacklist_drop, "Src Dst L4-type ICMP Blacklist Drop");
    sf_log_u64(ddos_stat_t2->src_dst_l4_other_blacklist_drop, "Src Dst L4-type OTHER Blacklist Drop");
}

static void readCounters_DDOS_L4_EXT_IP_COUNTER_T2(SFSample *sample, sflow_ddos_ip_counter_l4_ext_t2_data_t *ddos_stat_t2)
{
    int len = 0;
    long tstamp = time(NULL);
    char tbuf [200];

    populate_sflow_struct_u64(sample, (void *)ddos_stat_t2, sizeof(sflow_ddos_ip_counter_l4_ext_t2_data_t));

    if (sample->ddos.l4_ext_perip.common.ip_type == 1) {
        sprintf (tbuf, "ip=%08x prefix=%d agent=%08x type=%x\n",
                    sample->ddos.l4_ext_perip.common.ip_addr,
                    sample->ddos.l4_ext_perip.common.subnet_mask,
                    htonl(sample->agent_addr.address.ip_v4.addr),
                    sample->ddos.l4_ext_perip.common.ip_type);
    } else {
        unsigned char *i;
        i = sample->ddos.l4_ext_perip.common.ip6_addr.s6_addr;

        sprintf (tbuf, "ip=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x prefix=%d agent=%08x\n",
                    i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8],
                    i[9], i[10], i[11], i[12], i[13], i[14], i[15],
                    sample->ddos.l4_ext_perip.common.subnet_mask,
                    htonl(sample->agent_addr.address.ip_v4.addr));
    }

    len += sprintf (tsdb_buff + len, "put dst_fwd_bytes_sent %lu %lu %s", tstamp, ddos_stat_t2->dst_fwd_bytes_sent, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_rev_bytes_sent %lu %lu %s", tstamp, ddos_stat_t2->dst_rev_bytes_sent, tbuf);
    len += sprintf (tsdb_buff + len, "put tcp_l4_syn_cookie_fail %lu %lu %s", tstamp, ddos_stat_t2->tcp_l4_syn_cookie_fail, tbuf);
    len += sprintf (tsdb_buff + len, "put tcp_l4_rst_cookie_fail %lu %lu %s", tstamp, ddos_stat_t2->tcp_l4_rst_cookie_fail, tbuf);
    len += sprintf (tsdb_buff + len, "put tcp_l4_unauth_drop %lu %lu %s", tstamp, ddos_stat_t2->tcp_l4_unauth_drop, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_l4_tcp_auth %lu %lu %s", tstamp, ddos_stat_t2->dst_l4_tcp_auth, tbuf);
    len += sprintf (tsdb_buff + len, "put src_frag_pkt_rate_exceed %lu %lu %s", tstamp, ddos_stat_t2->src_frag_pkt_rate_exceed, tbuf);
    len += sprintf (tsdb_buff + len, "put src_frag_drop %lu %lu %s", tstamp, ddos_stat_t2->src_frag_drop, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_frag_timeout_drop %lu %lu %s", tstamp, ddos_stat_t2->dst_frag_timeout_drop, tbuf);
    len += sprintf (tsdb_buff + len, "put dst_tcp_invalid_syn %lu %lu %s", tstamp, ddos_stat_t2->dst_tcp_invalid_syn, tbuf);
    int ret = opentsdb_simple_connect(tsdb_buff);

    sf_log_u64(ddos_stat_t2->dst_fwd_bytes_sent, "Incoming Bytes Forwarded");
    sf_log_u64(ddos_stat_t2->dst_rev_bytes_sent, "Outgoing Bytes Forwarded");
    sf_log_u64(ddos_stat_t2->tcp_l4_syn_cookie_fail, "L4-type TCP Syn Cookie Failed");
    sf_log_u64(ddos_stat_t2->tcp_l4_rst_cookie_fail, "L4-type TCP RST Cookie Failed");
    sf_log_u64(ddos_stat_t2->tcp_l4_unauth_drop, "L4-type TCP Un-Auth Packet Drop");
    sf_log_u64(ddos_stat_t2->dst_l4_tcp_auth, "L4-type TCP Auth Sent");
    sf_log_u64(ddos_stat_t2->src_frag_pkt_rate_exceed, "OTHER drop - Src Frag rate exceed:");
    sf_log_u64(ddos_stat_t2->src_frag_drop, "Src Frag drop:");
    sf_log_u64(ddos_stat_t2->dst_frag_timeout_drop, "Frag timeout drop:");
    sf_log_u64(ddos_stat_t2->dst_tcp_invalid_syn, "TCP Invalid SYN Received:");
}

static void readCounters_DDOS_IP_COUNTER_RES_STAT(SFSample *sample, sflow_ddos_limit_result_stat_t *stat)
{
    stat->curr_conn = sf_log_next32(sample, "Curr Conn:");
    stat->conn_limit = sf_log_next32(sample, "Conn Limit:");
    stat->curr_conn_rate = sf_log_next32(sample, "Curr ConnR:");
    stat->conn_rate_limit = sf_log_next32(sample, "ConnR Limit:");
    stat->curr_pkt_rate = sf_log_next32(sample, "Curr PktR:");
    stat->pkt_rate_limit = sf_log_next32(sample, "PktR Limit:");
    stat->curr_syn_cookie = getData32(sample);
    stat->syn_cookie_thr = getData32(sample);
    stat->bl_drop_ct = sf_log_next64(sample, "BL Drop:");
    stat->conn_rate_exceed_ct = sf_log_next64(sample, "CRate Drop:");
    stat->pkt_rate_exceed_ct = sf_log_next64(sample, "PRate Drop:");
    stat->conn_limit_exceed_ct = sf_log_next64(sample, "CLimit Drop:");
}

static void readCounters_DDOS_PORT_IP_COUNTER(SFSample *sample)
{
    readCounters_DDOS_IP_COUNTER_COMMON(sample, &sample->ddos.port.common);
    sample->ddos.port.port = sf_log_next32(sample, "Port:");
    sample->ddos.port.app_type = getData32(sample);
    if (sample->ddos.port.app_type <= DDOS_TOTAL_APP_TYPE_SIZE) {
        sfl_log_ex_string_fmt((char *)ddos_proto_str[sample->ddos.port.app_type], "App type:");
    }
    sample->ddos.port.port_exceed_check = sf_log_next32(sample, "Exceed:");
    sample->ddos.port.lockup_period = sf_log_next32(sample, "LockU Time:");
    readCounters_DDOS_IP_COUNTER_RES_STAT(sample, &sample->ddos.port.port_stat);
}

static void readCounters_DDOS_L4_IP_COUNTER(SFSample *sample)
{
    readCounters_DDOS_IP_COUNTER_COMMON(sample, &sample->ddos.l4_perip.common);
    readCounters_DDOS_L4_IP_COUNTER_T2(sample, &sample->ddos.l4_perip.l4);
}

static void readCounters_DDOS_PROTOCOL(SFSample *sample, sflow_ddos_limit_proto_stat_t *stat)
{
    uint32_t proto = getData32(sample);
    sf_log("%-35s %s[%u]\n", "Protocol:", ddos_proto_str[proto], proto);
    stat->protocol = proto;
    uint32_t state = getData32(sample);
    sf_log("%-35s %s[%u]\n", "State:", ddos_state_flag[state], state);
    stat->state = state;
    stat->exceed_byte = sf_log_next32(sample, "Exceed:");
    stat->lockup_period = sf_log_next32(sample, "LockU Time:");
    readCounters_DDOS_IP_COUNTER_RES_STAT(sample, &stat->stat);
}

static void readCounters_DDOS_APP(SFSample *sample, sflow_ddos_limit_app_stat_t *stat)
{
    uint32_t app = getData32(sample);
    sf_log("%s %s[%u]\n", "App:", ddos_proto_str[app], app);
    stat->app = app;
    uint32_t state = getData32(sample);
    sf_log("%s %s[%u]\n", "State:", ddos_state_flag[state], state);
    stat->state = state;
    stat->exceed_byte = sf_log_next32(sample, "Exceed:");
    stat->lockup_period = sf_log_next32(sample, "LockU Time:");
    stat->app_rate1 = sf_log_next32(sample, "App rate1:");
    stat->config_app_rate1 = sf_log_next32(sample, "Config app rate1:");
    stat->app_rate2 = sf_log_next32(sample, "App rate2:");
    stat->config_app_rate2 = sf_log_next32(sample, "Config app rate2:");
    stat->app_rate3 = sf_log_next32(sample, "App rate3:");
    stat->config_app_rate3 = sf_log_next32(sample, "Config app rate3:");
    stat->app_rate4 = sf_log_next32(sample, "App rate4:");
    stat->config_app_rate4 = sf_log_next32(sample, "Config app rate4:");
    stat->app_rate5 = sf_log_next32(sample, "App rate5:");
    stat->config_app_rate5 = sf_log_next32(sample, "Config app rate5:");
    stat->app_rate6 = sf_log_next32(sample, "App rate6:");
    stat->config_app_rate6 = sf_log_next32(sample, "Config app rate6:");
    stat->app_rate7 = sf_log_next32(sample, "App rate7:");
    stat->config_app_rate7 = sf_log_next32(sample, "Config app rate7:");
    stat->app_rate8 = sf_log_next32(sample, "App rate8:");
    stat->config_app_rate8 = sf_log_next32(sample, "Config app rate8:");

}

static void readCounters_DDOS_IP_COUNTER(SFSample *sample)
{
    uint32_t table_type = getData32(sample);
    sample->ddos.entry.common.table_type = table_type;
    sf_log("%-35s %s[%u]\n", "Table Type:", ddos_table_type[table_type], table_type);
    uint32_t ip_type = getData32(sample);
    sample->ddos.entry.common.ip_type = ip_type;
    sf_log("%-35s %s[%u]\n", "IP Type:", ddos_ip_type[ip_type], ip_type);
    //sf_log("%s %u\n", "bwlist", bwlist);
    sample->ddos.entry.common.static_entry = sf_log_next32(sample, "Static:");
    SFLAddress addr, daddr;
    char buf[50];
    getDDoSAddress(sample, ip_type, &addr);
    sf_log("%-35s %s\n", "Address:",  printAddress_no_conversion(&addr, buf, 50));
    getDDoSAddress(sample, ip_type, &daddr);
    if (table_type == 2) {
        sf_log("%-35s %s\n", "Dst Address:", printAddress_no_conversion(&daddr, buf, 50));
    }
    if (ip_type == 1) {
        sample->ddos.entry.common.ip_addr = addr.address.ip_v4.addr;
        sample->ddos.entry.common.dst_ip_addr = daddr.address.ip_v4.addr;
    } else {
        memcpy(&sample->ddos.entry.common.ip6_addr, addr.address.ip_v6.addr, 16);
        memcpy(&sample->ddos.entry.common.dst_ip6_addr, daddr.address.ip_v6.addr, 16);
    }
    sample->ddos.entry.common.subnet_mask = sf_log_next16(sample, "Subnet/Prefix:");
    sample->ddos.entry.common.age = sf_log_next16(sample, "Age:");
    uint32_t num = getData32(sample);
    sf_log("%-35s %u\n", "Protocol Num:", num);
    sample->ddos.entry.proto_num = num;
    int i;
    /*
    if (num >= DDOS_TOTAL_PROTOCOL_SIZE){
        sf_log("Error for ddos protocol numbers\n");
        return;
    }
    */
    //num = DDOS_TOTAL_PROTOCOL_SIZE;
    for (i = 0; i < num; i++) {
        readCounters_DDOS_PROTOCOL(sample, &sample->ddos.entry.stat[i]);
    }
    num = getData32(sample);
    sf_log("%-35s %u\n", "App Num:", num);
    sample->ddos.entry.app_num = num;
    for (i = 0; i < num; i++) {
        readCounters_DDOS_APP(sample, &sample->ddos.entry.app_stat[i]);
    }
}

static inline void sfl_log_32_ex(uint32_t data, char *description)
{
    printf("%s %u,", description, data);
}

static inline void sfl_log_16_ex(uint16_t data, char *description)
{
    printf("%s %u,", description, data);
}

static inline void sfl_log_ex_string_fmt(char *data, char *description)
{
    printf("%-35s %s\n", description, data);
}

static inline void sfl_log_64_ex(uint64_t data, char *description)
{
    printf("%s %lu,", description, data);
}

static void sflow_ddos_write_res_stat_line(sflow_ddos_limit_result_stat_t *stat)
{
    sfl_log_32_ex(stat->curr_conn, "Curr Conn:");
    sfl_log_32_ex(stat->conn_limit, "Conn Limit:");
    sfl_log_32_ex(stat->curr_conn_rate, "Curr ConnR:");
    sfl_log_32_ex(stat->conn_rate_limit, "ConnR Limit:");
    sfl_log_32_ex(stat->curr_pkt_rate, "Curr PktR:");
    sfl_log_32_ex(stat->pkt_rate_limit, "PktR Limit:");
    sfl_log_64_ex(stat->bl_drop_ct, "BL Drop:");
    sfl_log_64_ex(stat->conn_rate_exceed_ct, "CRate Drop:");
    sfl_log_64_ex(stat->pkt_rate_exceed_ct, "PRate Drop:");
    sfl_log_64_ex(stat->conn_limit_exceed_ct, "CLimit Drop:");
}
static void sflow_ddos_write_proto_line(sflow_ddos_limit_proto_stat_t *stat)
{
    printf("%s %s[%u],", "Protocol:", ddos_proto_str[stat->protocol], stat->protocol);
    printf("%s %s[%u],", "State:", ddos_state_flag[stat->state], stat->state);
    sfl_log_32_ex(stat->exceed_byte, "Exceed:");
    sfl_log_32_ex(stat->lockup_period, "LockU Time:");
    sflow_ddos_write_res_stat_line(&stat->stat);
}
static void sflow_ddos_write_app_line(sflow_ddos_limit_app_stat_t *stat)
{

    printf("%s %s[%u]\n", "App:", ddos_proto_str[stat->app], stat->app);
    printf("%s %s[%u]\n", "State:", ddos_state_flag[stat->state], stat->state);
    sfl_log_32_ex(stat->exceed_byte, "Exceed:");
    sfl_log_32_ex(stat->lockup_period, "LockU Time:");
    sfl_log_32_ex(stat->app_rate1, "App rate1:");
    sfl_log_32_ex(stat->config_app_rate1, "Config app rate1:");
    sfl_log_32_ex(stat->app_rate2, "App rate2:");
    sfl_log_32_ex(stat->config_app_rate2, "Config app rate2:");
    sfl_log_32_ex(stat->app_rate3, "App rate3:");
    sfl_log_32_ex(stat->config_app_rate3, "Config app rate3:");
    sfl_log_32_ex(stat->app_rate4, "App rate4:");
    sfl_log_32_ex(stat->config_app_rate4, "Config app rate4:");
    sfl_log_32_ex(stat->app_rate5, "App rate5:");
    sfl_log_32_ex(stat->config_app_rate5, "Config app rate5:");
    sfl_log_32_ex(stat->app_rate6, "App rate6:");
    sfl_log_32_ex(stat->config_app_rate6, "Config app rate6:");
    sfl_log_32_ex(stat->app_rate7, "App rate7:");
    sfl_log_32_ex(stat->config_app_rate7, "Config app rate7:");
    sfl_log_32_ex(stat->app_rate8, "App rate8:");
    sfl_log_32_ex(stat->config_app_rate8, "Config app rate8:");

}
static void sflow_ddos_write_ip_counter_common_line(sflow_ddos_ip_counter_common_t *hdr)
{
    printf("%s %s[%u],", "Table Type:", ddos_table_type[hdr->table_type], hdr->table_type);
    printf("%s %s[%u],", "IP Type:", ddos_ip_type[hdr->ip_type], hdr->ip_type);
    sfl_log_32_ex(hdr->static_entry, "Static:");
    SFLAddress addr;
    if (hdr->ip_type == 1) {
        addr.type = SFLADDRESSTYPE_IP_V4;
        addr.address.ip_v4.addr = hdr->ip_addr;
    } else {
        addr.type = SFLADDRESSTYPE_IP_V6;
        memcpy(addr.address.ip_v6.addr, &hdr->ip6_addr, 16);
    }
    char buf[50];
    printf("%-35s %s,", "Address:", printAddress(&addr, buf, 50));
    if (hdr->table_type == 2) {
        if (hdr->ip_type == 1) {
            addr.address.ip_v4.addr = hdr->dst_ip_addr;
        } else {
            memcpy(addr.address.ip_v6.addr, &hdr->dst_ip6_addr, 16);
        }

        printf("%s %s,", "Dst Address:", printAddress(&addr, buf, 50));
    }

    sfl_log_16_ex(hdr->subnet_mask, "Subnet/Prefix:");
    sfl_log_32_ex(hdr->age, "Age:");
}
static void sflow_ddos_write_ip_counters_line(sflow_ddos_ip_counter_t *entry)
{
    sflow_ddos_write_ip_counter_common_line(&entry->common);
    sfl_log_32_ex(entry->proto_num, "Protocol Num:");
    int i;
    for (i = 0; i < entry->proto_num; i++) {
        sflow_ddos_write_proto_line(&entry->stat[i]);
    }
    sfl_log_32_ex(entry->app_num, "App Num:");
    for (i = 0; i < entry->app_num; i++) {
        sflow_ddos_write_app_line(&entry->app_stat[i]);
    }
}

#endif /* A10_SFLOW */

/*_________________---------------------------__________________
  _________________   readCountersSample      __________________
  -----------------___________________________------------------
*/

struct sflow_enterprise {
    /* TODO get the proper endian defines in here */
    u32 format: 12;
    u32 id: 20;
} __attribute__((packed));

typedef union {
    u32 raw;
    struct sflow_enterprise ent;
} sflow_enterprise_u;


static void readCountersSample(SFSample *sample, int expanded)
{
    uint32_t sampleLength;
    uint32_t num_elements;
    u_char *sampleStart;
    sf_log("%-35s COUNTERSSAMPLE\n", "sampleType:");
    sampleLength = getData32(sample);
    sampleStart = (u_char *)sample->datap;
    sample->samplesGenerated = getData32(sample);

    sf_log("%-35s %u\n", "sampleSequenceNo", sample->samplesGenerated);
    if (expanded) {
        sample->ds_class = getData32(sample);
        sample->ds_index = getData32(sample);
    } else {
        uint32_t samplerId = getData32(sample);
        sample->ds_class = samplerId >> 24;
        sample->ds_index = samplerId & 0x00ffffff;
    }
    sf_log("%-35s %u:%u\n", "sourceId", sample->ds_class, sample->ds_index);

    num_elements = getData32(sample);
    {
        uint32_t el;
	for (el = 0; el < num_elements; el++) {
		uint32_t tag, length;
		u_char *start;
		char buf[51];
		tag = getData32(sample);
		u32 tag1 = 0;
		tag1 = ntohl(tag);
		sf_log("%-35s %s\n", "counterBlock_tag",  printTag(tag, buf, 50));
		length = getData32(sample);
		sample->current_context_length = length;
		start = (u_char *)sample->datap;
		sflow_enterprise_u * pz = (sflow_enterprise_u *)(&tag1);
		printf("format %lu == id ==%lu \n", pz->ent.format, pz->ent.id);

		pz = (sflow_enterprise_u *)(&tag);
		printf("format %lu == id ==%lu \n", pz->ent.format, pz->ent.id);

		if (tag == SFLCOUNTERS_GENERIC){
			//	return;	
		}
		printf("!!!!!!!!!!!tag == %lu; tag1 = %lu\n", tag, tag1);
		switch (tag) {
			//	prinf("!!!!!!!!!!!tag == %ul", tag);
			case SFLCOUNTERS_GENERIC:
				//readCounters_generic(sample);
				printf("\nhit SFLCOUNTERS_GENERIC:\n");
				// readCounters_a10_generic(sample);
				break;
			case SFLCOUNTERS_ETHERNET:
				readCounters_ethernet(sample);
				break;
			case SFLCOUNTERS_TOKENRING:
				readCounters_tokenring(sample);
				break;
			case SFLCOUNTERS_VG:
				readCounters_vg(sample);
				break;
			case SFLCOUNTERS_VLAN:
				readCounters_vlan(sample);
				break;
			case SFLCOUNTERS_80211:
				readCounters_80211(sample);
				break;
			case SFLCOUNTERS_LACP:
				readCounters_LACP(sample);
				break;
			case SFLCOUNTERS_PROCESSOR:
				readCounters_processor(sample);
				break;
			case SFLCOUNTERS_RADIO:
				readCounters_radio(sample);
				break;
			case SFLCOUNTERS_HOST_HID:
				readCounters_host_hid(sample);
				break;
			case SFLCOUNTERS_ADAPTORS:
				readCounters_adaptors(sample);
				break;
			case SFLCOUNTERS_HOST_PAR:
				readCounters_host_parent(sample);
				break;
			case SFLCOUNTERS_HOST_CPU:
				readCounters_host_cpu(sample);
				break;
			case SFLCOUNTERS_HOST_MEM:
				readCounters_host_mem(sample);
				break;
			case SFLCOUNTERS_HOST_DSK:
				readCounters_host_dsk(sample);
				break;
			case SFLCOUNTERS_HOST_NIO:
				readCounters_host_nio(sample);
				break;
			case SFLCOUNTERS_HOST_VRT_NODE:
				readCounters_host_vnode(sample);
				break;
			case SFLCOUNTERS_HOST_VRT_CPU:
				readCounters_host_vcpu(sample);
				break;
			case SFLCOUNTERS_HOST_VRT_MEM:
				readCounters_host_vmem(sample);
				break;
			case SFLCOUNTERS_HOST_VRT_DSK:
				readCounters_host_vdsk(sample);
				break;
			case SFLCOUNTERS_HOST_VRT_NIO:
				readCounters_host_vnio(sample);
				break;
			case SFLCOUNTERS_HOST_GPU_NVML:
				readCounters_host_gpu_nvml(sample);
				break;
			case SFLCOUNTERS_MEMCACHE:
				readCounters_memcache(sample);
				break;
			case SFLCOUNTERS_MEMCACHE2:
				readCounters_memcache2(sample);
				break;
			case SFLCOUNTERS_HTTP:
				readCounters_http(sample);
				break;
			case SFLCOUNTERS_JVM:
				readCounters_JVM(sample);
				break;
			case SFLCOUNTERS_JMX:
				readCounters_JMX(sample, length);
				break;
			case SFLCOUNTERS_APP:
				readCounters_APP(sample);
				break;
			case SFLCOUNTERS_APP_RESOURCE:
				readCounters_APP_RESOURCE(sample);
				break;
			case SFLCOUNTERS_APP_WORKERS:
				readCounters_APP_WORKERS(sample);
				break;
			case SFLCOUNTERS_VDI:
				readCounters_VDI(sample);
				break;
#ifdef A10_SFLOW
			case SFLCOUNTERS_DDOS_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS generic Global Ctrs"); /* Deprecated, No longer Maintained */
				readCounters_DDOS_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_IP_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Entry Ctrs");
				readCounters_DDOS_IP_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_HTTP_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS HTTP Global Ctrs");
				readCounters_DDOS_HTTP_COUNTER(sample, &sample->ddos.http);
				break;
			case SFLCOUNTERS_DDOS_DNS_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS DNS Global Ctrs");
				readCounters_DDOS_DNS_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_FPGA_ANOMALY_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Anomaly Global Ctrs");
				readCounters_DDOS_FPGA_ANOMALY_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_HTTP_IP_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS HTTP Per-entry Ctrs");
				readCounters_DDOS_IP_COUNTER_COMMON(sample, &sample->ddos.http_perip.common);
				readCounters_DDOS_HTTP_IP_COUNTER(sample);
				sfl_ddos_update_ctx_len(sample, sizeof(sflow_ddos_ip_counter_common_t) + 4/* Port & App-tpe */);
				readCounters_DDOS_HTTP_T2_COUNTER(sample, &sample->ddos.http_perip.http.stats);
				break;
			case SFLCOUNTERS_DDOS_DNS_IP_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS DNS Per-entry Ctrs");
				readCounters_DDOS_IP_COUNTER_COMMON(sample, &sample->ddos.dns_perip.common);
				readCounters_DDOS_DNS_IP_COUNTER(sample);
				sfl_ddos_update_ctx_len(sample, sizeof(sflow_ddos_ip_counter_common_t) + 4/* Port & App-tpe */);
				readCounters_DDOS_DNS_COUNTER_T2(sample, &sample->ddos.dns_perip.dns.stats);
				break;
			case SFLCOUNTERS_DDOS_L4_IP_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS General Per-entry Ctrs");
				readCounters_DDOS_IP_COUNTER_COMMON(sample, &sample->ddos.l4_perip.common);
				sfl_ddos_update_ctx_len(sample, sizeof(sflow_ddos_ip_counter_common_t));
				readCounters_DDOS_L4_IP_COUNTER_T2(sample, &sample->ddos.l4_perip.l4);
				break;
			case SFLCOUNTERS_DDOS_L4_EXT_IP_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Extended Per-entry Ctrs");
				readCounters_DDOS_IP_COUNTER_COMMON(sample, &sample->ddos.l4_ext_perip.common);
				sfl_ddos_update_ctx_len(sample, sizeof(sflow_ddos_ip_counter_common_t));
				readCounters_DDOS_L4_EXT_IP_COUNTER_T2(sample, &sample->ddos.l4_ext_perip.l4_ext);
				break;
			case SFLCOUNTERS_DDOS_PORT_IP_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Entry Port Ctrs");
				readCounters_DDOS_PORT_IP_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_ENTRY_MAP:
				sfl_ddos_description(sample, "Sflow DDoS Entry Map Ctrs");
				readCounters_DDOS_POLLING_ENTRY_MAP(sample);
				break;
			case SFLCOUNTERS_DDOS_POLLING_PACKETS_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Polling Packet Ctrs");
				readCounters_DDOS_POLLING_PACKETS(sample);
				break;
			case SFLCOUNTERS_DDOS_POLLING_L4_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Polling L4 protocol Ctrs");
				readCounters_DDOS_POLLING_L4_PROTOCOL(sample);
				break;
			case SFLCOUNTERS_DDOS_POLLING_TCP_BASIC_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Polling TCP basic Ctrs");
				readCounters_DDOS_POLLING_TCP_BASIC(sample);
				break;
			case SFLCOUNTERS_DDOS_POLLING_TCP_STATEFUL_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Polling TCP stateful Ctrs");
				readCounters_DDOS_POLLING_TCP_STATEFUL(sample);
				break;
			case SFLCOUNTERS_DDOS_POLLING_HTTP_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Polling HTTP Ctrs");
				readCounters_DDOS_POLLING_HTTP(sample);
				break;

			case SFLCOUNTERS_DDOS_SSL_L4_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS SSL-L4 Global Ctrs");
				readCounters_DDOS_SSL_L4_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_SSL_L4_T2_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS SSL-L4 Per-entry Ctrs");
				readCounters_DDOS_IP_COUNTER_COMMON(sample, &sample->ddos.ssl_l4_perip.common);
				readCounters_DDOS_SSL_L4_IP_COUNTER(sample);
				sfl_ddos_update_ctx_len(sample, sizeof(sflow_ddos_ip_counter_common_t) + 4/* Port & App-tpe */);
				readCounters_DDOS_SSL_L4_T2_COUNTER(sample, &sample->ddos.ssl_l4_perip.ssl_l4.stats);
				break;
			case SFLCOUNTERS_DDOS_ICMP_T2_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS ICMP Per-entry Ctrs");
				readCounters_DDOS_IP_COUNTER_COMMON(sample, &sample->ddos.icmp_perip.common);
				sfl_ddos_update_ctx_len(sample, sizeof(sflow_ddos_ip_counter_common_t));
				readCounters_DDOS_ICMP_COUNTER_T2(sample, &sample->ddos.icmp_perip.icmp);
				break;
			case SFLCOUNTERS_DDOS_UDP_T2_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS UDP Per-entry Ctrs");
				readCounters_DDOS_IP_COUNTER_COMMON(sample, &sample->ddos.udp_perip.common);
				readCounters_DDOS_UDP_IP_COUNTER(sample);
				sfl_ddos_update_ctx_len(sample, sizeof(sflow_ddos_ip_counter_common_t) + 4/* Port & App-tpe */);
				readCounters_DDOS_UDP_T2_COUNTER(sample, &sample->ddos.udp_perip.udp.stats);
				break;
			case SFLCOUNTERS_DDOS_TCP_T2_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS TCP Per-entry Ctrs");
				readCounters_DDOS_IP_COUNTER_COMMON(sample, &sample->ddos.tcp_perip.common);
				readCounters_DDOS_TCP_IP_COUNTER(sample);
				sfl_ddos_update_ctx_len(sample, sizeof(sflow_ddos_ip_counter_common_t) + 4/* Port & App-tpe */);
				readCounters_DDOS_TCP_T2_COUNTER(sample, &sample->ddos.tcp_perip.tcp.stats);
				break;
			case SFLCOUNTERS_DDOS_OTHER_T2_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS OTHER Per-entry Ctrs");
				readCounters_DDOS_IP_COUNTER_COMMON(sample, &sample->ddos.other_perip.common);
				readCounters_DDOS_OTHER_IP_COUNTER(sample);
				sfl_ddos_update_ctx_len(sample, sizeof(sflow_ddos_ip_counter_common_t) + 4/* Port & App-tpe */);
				readCounters_DDOS_OTHER_T2_COUNTER(sample, &sample->ddos.other_perip.other.stats);
				break;
			case SFLCOUNTERS_DDOS_L4_TCP_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS L4 TCP Global Ctrs");
				readCounters_DDOS_L4_TCP_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_L4_UDP_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS L4 UDP Global Ctrs");
				readCounters_DDOS_L4_UDP_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_L4_ICMP_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS L4 ICMP Global Ctrs");
				readCounters_DDOS_L4_ICMP_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_L4_OTHER_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS L4 Other Global Ctrs");
				readCounters_DDOS_L4_OTHER_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_L4_SWITCH_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Switch Global Ctrs");
				readCounters_DDOS_L4_SWITCH_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_L4_SYNC_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Sync Global Ctrs");
				readCounters_DDOS_L4_SYNC_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_L4_TUNNEL_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Tunnel Global Ctrs");
				readCounters_DDOS_L4_TUNNEL_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_L4_SESSION_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS session Global Ctrs");
				readCounters_DDOS_L4_SESSION_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_L4_TABLE_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Table Global Ctrs");
				readCounters_DDOS_ENTRY_TABLE_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_STATS_BRIEF_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Brief Global Ctrs");
				readCounters_DDOS_BRIEF_STATS_COUNTER(sample);
				break;
			case SFLCOUNTERS_DDOS_STATS_LONG_COUNTER:
				sfl_ddos_description(sample, "Sflow DDoS Detailed Global Ctrs");
				readCounters_DDOS_LONG_STATS_COUNTER(sample);
				break;

				// A10 DDET:

			case SFL_COUNTER_DDOS_DST_INDICATORS:
				readCounters_DDOS_DST_INDICATORS(sample);
				break;
			case SFL_COUNTER_DDOS_DST_TCP_INDICATORS:
				readCounters_DDOS_DST_TCP_INDICATORS(sample);
				break;
			case SFL_COUNTER_DDOS_DST_UDP_INDICATORS:
				readCounters_DDOS_DST_UDP_INDICATORS(sample);
				break;
			case SFL_COUNTER_DDOS_DST_ICMP_INDICATORS:
				readCounters_DDOS_DST_ICMP_INDICATORS(sample);
				break;
			case SFL_COUNTER_DDOS_DST_OTHER_INDICATORS:
				readCounters_DDOS_DST_OTHER_INDICATORS(sample);
				break;
				// A10 3.2/4.1 SFlow Packet
				//   case SFLCOUNTERS_DDOS_FLEX:
			case SFL_COUNTER_REC_GENERIC_A10:    
				{ 
					printf("\nhit SFL_COUNTER_REC_GENERIC_A10:\n");
					readCounters_a10_generic(sample);
					break;
				}

#endif /* A10_SFLOW */
			default:
				skipTLVRecord(sample, tag, length, "Skip_counters_sample_element");
				break;
		}

		if (tag != SFLCOUNTERS_GENERIC){
			lengthCheck(sample, "length_check_counters_sample_element", start, length);
			//      return;
		}
	}
    }
    lengthCheck(sample, "length_check_2_counters_sample", sampleStart, sampleLength);
    /* line-by-line output... */
    if (sfConfig.outputFormat == SFLFMT_LINE) {
        writeCountersLine(sample);
    }
}

/*_________________---------------------------__________________
  _________________      readSFlowDatagram    __________________
  -----------------___________________________------------------
*/

static void readSFlowDatagram(SFSample *sample)
{
    uint32_t samplesInPacket;
    struct timeval now;
    char buf[51];

    /* log some datagram info */
    now.tv_sec = (long)time(NULL);
    now.tv_usec = 0;
    sf_log("%-35s %s\n", "datagramSourceIP", printAddress(&sample->sourceIP, buf, 50));
    sf_log("%-35s %u\n", "datagramSize", sample->rawSampleLen);
    sf_log("%-35s %u\n", "unixSecondsUTC", now.tv_sec);
    if (sample->pcapTimestamp) {
        sf_log("pcapTimestamp %s\n", ctime(&sample->pcapTimestamp));    // thanks to Richard Clayton for this bugfix
    }

    /* check the version */
    sample->datagramVersion = getData32(sample);
    sf_log("%-35s %d\n", "datagramVersion", sample->datagramVersion);
    if (sample->datagramVersion != 2 &&
        sample->datagramVersion != 4 &&
        sample->datagramVersion != 5) {
        receiveError(sample,  "unexpected datagram version number\n", YES);
    }

    /* get the agent address */
    getAddress(sample, &sample->agent_addr);

    /* version 5 has an agent sub-id as well */
    if (sample->datagramVersion >= 5) {
        sample->agentSubId = getData32(sample);
        sf_log("%-35s %u\n", "AgentSubId", sample->agentSubId);
    }

    sample->sequenceNo = getData32(sample);  /* this is the packet sequence number */
    sample->sysUpTime = getData32(sample);
    samplesInPacket = getData32(sample);
    sf_log("%-35s %s\n", "Agent", printAddress(&sample->agent_addr, buf, 50));
    sf_log("%-35s %u\n", "PacketSequenceNo", sample->sequenceNo);
    sf_log("%-35s %u\n", "SysUpTime", sample->sysUpTime);
    sf_log("%-35s %u\n", "samplesInPacket", samplesInPacket);

    /* now iterate and pull out the flows and counters samples */
    {
        uint32_t samp = 0;
        for (; samp < samplesInPacket; samp++) {
            if ((u_char *)sample->datap >= sample->endp) {
                fprintf(ERROUT, "unexpected end of datagram after sample %d of %d\n", samp, samplesInPacket);
                SFABORT(sample, SF_ABORT_EOS);
            }
            // just read the tag, then call the approriate decode fn
            sample->sampleType = getData32(sample);
            sf_log("==================== StartSample ======================\n");
            sf_log("%-35s %s\n", "sampleType_tag", printTag(sample->sampleType, buf, 50));
            if (sample->datagramVersion >= 5) {
                switch (sample->sampleType) {
                    case SFLFLOW_SAMPLE:
                        readFlowSample(sample, NO);
                        break;
                    case SFLCOUNTERS_SAMPLE:
                        readCountersSample(sample, NO);
                        break;
                    case SFLFLOW_SAMPLE_EXPANDED:
                        readFlowSample(sample, YES);
                        break;
                    case SFLCOUNTERS_SAMPLE_EXPANDED:
                        readCountersSample(sample, YES);
                        break;
                    default:
                        skipTLVRecord(sample, sample->sampleType, getData32(sample), "sample");
                        break;
                }
            } else {
                switch (sample->sampleType) {
                    case FLOWSAMPLE:
                        readFlowSample_v2v4(sample);
                        break;
                    case COUNTERSSAMPLE:
                        readCountersSample_v2v4(sample);
                        break;
                    default:
                        receiveError(sample, "unexpected sample type", YES);
                        break;
                }
            }
            sf_log("==================== EndSample ========================\n");
        }
    }
}

/*_________________---------------------------__________________
  _________________  receiveSFlowDatagram     __________________
  -----------------___________________________------------------
*/

static void receiveSFlowDatagram(SFSample *sample)
{
    if (sfConfig.forwardingTargets) {
        // if we are forwarding, then do nothing else (it might
        // be important from a performance point of view).
        SFForwardingTarget *tgt = sfConfig.forwardingTargets;
        for (; tgt != NULL; tgt = tgt->nxt) {
            int bytesSent;
            if ((bytesSent = sendto(tgt->sock,
                                    (const char *)sample->rawSample,
                                    sample->rawSampleLen,
                                    0,
                                    (struct sockaddr *)(&tgt->addr),
                                    sizeof(tgt->addr))) != sample->rawSampleLen) {
                fprintf(ERROUT, "sendto returned %d (expected %d): %s\n",
                        bytesSent,
                        sample->rawSampleLen,
                        strerror(errno));
            }
        }
    } else {
        int exceptionVal;
        sf_log("==================== StartDatagram ====================\n\n");
        if ((exceptionVal = setjmp(sample->env)) == 0)  {
            // TRY
            sample->datap = (uint32_t *)sample->rawSample;
            sample->endp = (u_char *)sample->rawSample + sample->rawSampleLen;
            readSFlowDatagram(sample);
        } else {
            // CATCH
            fprintf(ERROUT, "caught exception: %d\n", exceptionVal);
        }
        sf_log("==================== EndDatagram ======================\n\n");
        fflush(stdout);
    }
}

/*__________________-----------------------------__________________
   _________________    openInputUDPSocket       __________________
   -----------------_____________________________------------------
*/

static int openInputUDPSocket(uint16_t port)
{
    int soc;
    struct sockaddr_in myaddr_in;

    /* Create socket */
    memset((char *)&myaddr_in, 0, sizeof(struct sockaddr_in));
    myaddr_in.sin_family = AF_INET;
    //myaddr_in6.sin6_addr.s_addr = INADDR_ANY;
    myaddr_in.sin_port = htons(port);

    if ((soc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        fprintf(ERROUT, "v4 socket() creation failed, %s\n", strerror(errno));
        return -1;
    }

#ifndef WIN32
    /* make socket non-blocking */
    int save_fd = fcntl(soc, F_GETFL);
    save_fd |= O_NONBLOCK;
    fcntl(soc, F_SETFL, save_fd);
#endif /* WIN32 */

    /* Bind the socket */
    if (bind(soc, (struct sockaddr *)&myaddr_in, sizeof(struct sockaddr_in)) == -1) {
        fprintf(ERROUT, "v4 bind() failed, port = %d : %s\n", port, strerror(errno));
        return -1;
    }
    return soc;
}

/*__________________-----------------------------__________________
   _________________    openInputUDP6Socket      __________________
   -----------------_____________________________------------------
*/

static int openInputUDP6Socket(uint16_t port)
{
    int soc;
    struct sockaddr_in6 myaddr_in6;

    /* Create socket */
    memset((char *)&myaddr_in6, 0, sizeof(struct sockaddr_in6));
    myaddr_in6.sin6_family = AF_INET6;
    //myaddr_in6.sin6_addr = INADDR_ANY;
    myaddr_in6.sin6_port = htons(port);

    if ((soc = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        fprintf(ERROUT, "v6 socket() creation failed, %s\n", strerror(errno));
        custom_exit(-6);
    }

#ifndef WIN32
    /* make socket non-blocking */
    int save_fd = fcntl(soc, F_GETFL);
    save_fd |= O_NONBLOCK;
    fcntl(soc, F_SETFL, save_fd);
#endif /* WIN32 */

    /* Bind the socket */
    if (bind(soc, (struct sockaddr *)&myaddr_in6, sizeof(struct sockaddr_in6)) == -1) {
        fprintf(ERROUT, "v6 bind() failed, port = %d : %s\n", port, strerror(errno));
        return -1;
    }
    return soc;
}

/*_________________---------------------------__________________
  _________________   ipv4MappedAddress       __________________
  -----------------___________________________------------------
*/

static int ipv4MappedAddress(SFLIPv6 *ipv6addr, SFLIPv4 *ip4addr)
{
    static u_char mapped_prefix[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
    static u_char compat_prefix[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    if (!memcmp(ipv6addr->addr, mapped_prefix, 12) ||
        !memcmp(ipv6addr->addr, compat_prefix, 12)) {
        memcpy(ip4addr, ipv6addr->addr + 12, 4);
        return YES;
    }
    return NO;
}

/*_________________---------------------------__________________
  _________________       readPacket          __________________
  -----------------___________________________------------------
*/

static void readPacket(int soc)
{
    struct sockaddr_in6 peer;
    int alen, cc;
#define MAX_PKT_SIZ 65536
    char buf[MAX_PKT_SIZ];
    alen = sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    cc = recvfrom(soc, buf, MAX_PKT_SIZ, 0, (struct sockaddr *)&peer, &alen);
    if (cc <= 0) {
        fprintf(ERROUT, "recvfrom() failed, %s\n", strerror(errno));
        return;
    }
    SFSample sample;
    memset(&sample, 0, sizeof(sample));
    sample.rawSample = (u_char *)buf;
    sample.rawSampleLen = cc;
    if (alen == sizeof(struct sockaddr_in)) {
        struct sockaddr_in *peer4 = (struct sockaddr_in *)&peer;
        sample.sourceIP.type = SFLADDRESSTYPE_IP_V4;
        memcpy(&sample.sourceIP.address.ip_v4, &peer4->sin_addr, 4);
    } else {
        SFLIPv4 v4src;
        sample.sourceIP.type = SFLADDRESSTYPE_IP_V6;
        memcpy(sample.sourceIP.address.ip_v6.addr, &peer.sin6_addr, 16);
        if (ipv4MappedAddress(&sample.sourceIP.address.ip_v6, &v4src)) {
            sample.sourceIP.type = SFLADDRESSTYPE_IP_V4;
            sample.sourceIP.address.ip_v4 = v4src;
        }
    }
    receiveSFlowDatagram(&sample);
}

/*_________________---------------------------__________________
  _________________     readPcapPacket        __________________
  -----------------___________________________------------------
*/




/*_________________---------------------------__________________
  _________________     decodeLinkLayer       __________________
  -----------------___________________________------------------
  store the offset to the start of the ipv4 header in the sequence_number field
  or -1 if not found. Decode the 802.1d if it's there.
*/

static int pcapOffsetToSFlow(u_char *start, int len)
{
    u_char *end = start + len;
    u_char *ptr = start;
    uint16_t type_len;

    // assume Ethernet header
    if (len < NFT_ETHHDR_SIZ) {
        return -1;    /* not enough for an Ethernet header */
    }
    ptr += 6; // dst
    ptr += 6; // src
    type_len = (ptr[0] << 8) + ptr[1];
    ptr += 2;

    while (type_len == 0x8100
           || type_len == 0x9100) {
        /* VLAN  - next two bytes */
        /*  _____________________________________ */
        /* |   pri  | c |         vlan-id        | */
        /*  ------------------------------------- */
        ptr += 2;
        /* now get the type_len again (next two bytes) */
        type_len = (ptr[0] << 8) + ptr[1];
        ptr += 2;
        if (ptr >= end) {
            return -1;
        }
    }

    /* now we're just looking for IP */
    if (end - ptr < NFT_MIN_SIZ) {
        return -1;    /* not enough for an IPv4 header */
    }

    /* peek for IPX */
    if (type_len == 0x0200 || type_len == 0x0201 || type_len == 0x0600) {
#define IPX_HDR_LEN 30
#define IPX_MAX_DATA 546
        int ipxChecksum = (ptr[0] == 0xff && ptr[1] == 0xff);
        int ipxLen = (ptr[2] << 8) + ptr[3];
        if (ipxChecksum &&
            ipxLen >= IPX_HDR_LEN &&
            ipxLen <= (IPX_HDR_LEN + IPX_MAX_DATA))
            /* we don't do anything with IPX here */
        {
            return -1;
        }
    }

    if (type_len <= NFT_MAX_8023_LEN) {
        /* assume 802.3+802.2 header */
        /* check for SNAP */
        if (ptr[0] == 0xAA &&
            ptr[1] == 0xAA &&
            ptr[2] == 0x03) {
            ptr += 3;
            if (ptr[0] != 0 ||
                ptr[1] != 0 ||
                ptr[2] != 0) {
                return -1; /* no further decode for vendor-specific protocol */
            }
            ptr += 3;
            /* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
            type_len = (ptr[0] << 8) + ptr[1];
            ptr += 2;
        } else {
            if (ptr[0] == 0x06 &&
                ptr[1] == 0x06 &&
                (ptr[2] & 0x01)) {
                /* IP over 8022 */
                ptr += 3;
                /* force the type_len to be IP so we can inline the IP decode below */
                type_len = 0x0800;
            } else {
                return -1;
            }
        }
    }
    if (ptr >= end) {
        return -1;
    }

    /* assume type_len is an ethernet-type now */

    if (type_len == 0x0800) {
        /* IPV4 */
        if ((end - ptr) < sizeof(struct myiphdr)) {
            return -1;
        }
        /* look at first byte of header.... */
        /*  ___________________________ */
        /* |   version   |    hdrlen   | */
        /*  --------------------------- */
        if ((*ptr >> 4) != 4) {
            return -1;    /* not version 4 */
        }
        if ((*ptr & 15) < 5) {
            return -1;    /* not IP (hdr len must be 5 quads or more) */
        }
        ptr += (*ptr & 15) << 2; /* skip over header */
    }

    if (type_len == 0x86DD) {
        /* IPV6 */
        /* look at first byte of header.... */
        if ((*ptr >> 4) != 6) {
            return -1;    /* not version 6 */
        }
        /* just assume no header options */
        ptr += 40;
    }

    // still have to skip over UDP header
    ptr += 8;
    if (ptr >= end) {
        return -1;
    }
    return (ptr - start);
}




static int readPcapPacket(FILE *file)
{
    u_char buf[2048];
    struct pcap_pkthdr hdr;
    SFSample sample;
    int skipBytes = 0;

    if (fread(&hdr, sizeof(hdr), 1, file) != 1) {
        if (feof(file)) {
            return 0;
        }
        fprintf(ERROUT, "unable to read pcap packet header from %s : %s\n", sfConfig.readPcapFileName, strerror(errno));
        custom_exit(-32);
    }
    if (sfConfig.tcpdumpHdrPad > 0) {
        if (fread(buf, sfConfig.tcpdumpHdrPad, 1, file) != 1) {
            fprintf(ERROUT, "unable to read pcap header pad (%d bytes)\n", sfConfig.tcpdumpHdrPad);
            custom_exit(-33);
        }
    }

    if (sfConfig.pcapSwap) {
        hdr.ts_sec = MyByteSwap32(hdr.ts_sec);
        hdr.ts_usec = MyByteSwap32(hdr.ts_usec);
        hdr.caplen = MyByteSwap32(hdr.caplen);
        hdr.len = MyByteSwap32(hdr.len);
    }

    if (fread(buf, hdr.caplen, 1, file) != 1) {
        fprintf(ERROUT, "unable to read pcap packet from %s : %s\n", sfConfig.readPcapFileName, strerror(errno));
        custom_exit(-34);
    }


    if (hdr.caplen < hdr.len) {
        fprintf(ERROUT, "incomplete datagram (pcap snaplen too short)\n");
    } else {
        // need to skip over the encapsulation in the captured packet.
        // -- should really do this by checking for 802.2, IP options etc.  but
        // for now we just assume ethernet + IP + UDP
        skipBytes = pcapOffsetToSFlow(buf, hdr.caplen);
        memset(&sample, 0, sizeof(sample));
        sample.rawSample = buf + skipBytes;
        sample.rawSampleLen = hdr.caplen - skipBytes;
        sample.pcapTimestamp = hdr.ts_sec;
        receiveSFlowDatagram(&sample);
    }
    return 1;
}


/*_________________---------------------------__________________
  _________________     parseVlanFilter       __________________
  -----------------___________________________------------------
*/

static void peekForNumber(char *p)
{
    if (*p < '0' || *p > '9') {
        fprintf(ERROUT, "error parsing vlan filter ranges (next char = <%c>)\n", *p);
        custom_exit(-19);
    }
}

static void testVlan(uint32_t num)
{
    if (num > FILTER_MAX_VLAN) {
        fprintf(ERROUT, "error parsing vlan filter (vlan = <%d> out of range)\n", num);
        custom_exit(-20);
    }
}

static void parseVlanFilter(u_char *array, u_char flag, char *start)
{
    char *p = start;
    char *sep = " ,";
    do {
        uint32_t first, last;
        p += strspn(p, sep); // skip separators
        peekForNumber(p);
        first = strtol(p, &p, 0); // read an integer
        testVlan(first);
        array[first] = flag;
        if (*p == '-') {
            // a range. skip the '-' (so it doesn't get interpreted as unary minus)
            p++;
            // and read the second integer
            peekForNumber(p);
            last = strtol(p, &p, 0);
            testVlan(last);
            if (last > first) {
                uint32_t i;
                // iterate over the range
                for (i = first; i <= last; i++) {
                    array[i] = flag;
                }
            }
        }
    } while (*p != '\0');
}

/*_________________---------------------------__________________
  _________________   addForwardingTarget     __________________
  -----------------___________________________------------------

  return boolean for success or failure
*/

static int addForwardingTarget(char *hostandport)
{
    SFForwardingTarget *tgt = (SFForwardingTarget *)calloc(1, sizeof(SFForwardingTarget));
    // expect <host>/<port>
#define MAX_HOSTANDPORT_LEN 100
    char hoststr[MAX_HOSTANDPORT_LEN + 1];
    char *p;
    if (hostandport == NULL) {
        fprintf(ERROUT, "expected <host>/<port>\n");
        return NO;
    }
    if (strlen(hostandport) > MAX_HOSTANDPORT_LEN) {
        return NO;
    }
    // take a copy
    strcpy(hoststr, hostandport);
    // find the '/'
    for (p = hoststr; *p != '\0'; p++) if (*p == '/') {
            break;
        }
    if (*p == '\0') {
        // not found
        fprintf(ERROUT, "host/port - no '/' found\n");
        return NO;
    }
    (*p) = '\0'; // blat in a zero
    p++;
    // now p points to port string, and hoststr is just the hostname or IP
    {
        struct hostent *ent = gethostbyname(hoststr);
        if (ent == NULL) {
            fprintf(ERROUT, "hostname %s lookup failed\n", hoststr);
            return NO;
        } else {
            tgt->host.s_addr = ((struct in_addr *)(ent->h_addr))->s_addr;
        }
    }
    sscanf(p, "%u", &tgt->port);
    if (tgt->port <= 0 || tgt->port >= 65535) {
        fprintf(ERROUT, "invalid port: %u\n", tgt->port);
        return NO;
    }

    /* set up the destination socket-address */
    tgt->addr.sin_family = AF_INET;
    tgt->addr.sin_port = ntohs(tgt->port);
    tgt->addr.sin_addr = tgt->host;
    /* and open the socket */
    if ((tgt->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        fprintf(ERROUT, "socket open (for %s) failed: %s", hostandport, strerror(errno));
        return NO;
    }

    /* got this far, so must be OK */
    tgt->nxt = sfConfig.forwardingTargets;
    sfConfig.forwardingTargets = tgt;
    return YES;
}

/*_________________---------------------------__________________
  _________________      instructions         __________________
  -----------------___________________________------------------
*/

static void instructions(char *command)
{
    fprintf(ERROUT, "Copyright (c) InMon Corporation 2000-2011 ALL RIGHTS RESERVED\n");
    fprintf(ERROUT, "This software provided with NO WARRANTY WHATSOEVER\n");
    fprintf(ERROUT, "\n");
    fprintf(ERROUT, "Usage: %s [-p port]\n", command);
    fprintf(ERROUT, "\n");
    fprintf(ERROUT, "%s version: %s\n", command, VERSION);
    fprintf(ERROUT, "\n");
    fprintf(ERROUT, "forwarding:\n");
    fprintf(ERROUT, "   -f host/port       -  (forward sflow to another collector\n");
    fprintf(ERROUT, "                      -   ...repeat for multiple collectors)\n");
    fprintf(ERROUT, "\n");
    fprintf(ERROUT, "csv output:\n");
    fprintf(ERROUT, "   -l                 -  (output in line-by-line format)\n");
    fprintf(ERROUT, "   -H                 -  (output HTTP common log file format)\n");
    fprintf(ERROUT, "\n");
    fprintf(ERROUT, "tcpdump output:\n");
    fprintf(ERROUT, "   -t                 -  (output in binary tcpdump(1) format)\n");
    fprintf(ERROUT, "   -r file            -  (read binary tcpdump(1) format)\n");
    fprintf(ERROUT, "   -x                 -  (remove all IPV4 content)\n");
    fprintf(ERROUT, "   -z pad             -  (extend tcpdump pkthdr with this many zeros\n");
    fprintf(ERROUT, "                          e.g. try -z 8 for tcpdump on Red Hat Linux 6.2)\n");
    fprintf(ERROUT, "\n");
    fprintf(ERROUT, "NetFlow output:\n");
    fprintf(ERROUT, "   -c hostname_or_IP  -  (netflow collector host)\n");
    fprintf(ERROUT, "   -d port            -  (netflow collector UDP port)\n");
    fprintf(ERROUT, "   -e                 -  (netflow collector peer_as (default = origin_as))\n");
    fprintf(ERROUT, "   -s                 -  (disable scaling of netflow output by sampling rate)\n");
#ifdef SPOOFSOURCE
    fprintf(ERROUT, "   -S                 -  spoof source of netflow packets to input agent IP\n");
#endif
    fprintf(ERROUT, "\n");
    fprintf(ERROUT, "Filters:\n");
    fprintf(ERROUT, "   +v <vlans>         -  include vlans (e.g. +v 0-20,4091)\n");
    fprintf(ERROUT, "   -v <vlans>         -  exclude vlans\n");
    fprintf(ERROUT, "   -4                 -  listen on IPv4 socket only\n");
    fprintf(ERROUT, "   -6                 -  listen on IPv6 socket only\n");
    fprintf(ERROUT, "   +4                 -  listen on both IPv4 and IPv6 sockets\n");
    fprintf(ERROUT, "\n");
    fprintf(ERROUT, "=============== Advanced Tools ==============================================\n");
    fprintf(ERROUT, "| sFlowTrend (FREE)     - http://www.inmon.com/products/sFlowTrend.php      |\n");
    fprintf(ERROUT, "| Traffic Sentinel      - http://www.inmon.com/support/sentinel_release.php |\n");
    fprintf(ERROUT, "=============================================================================\n");
    custom_exit(1);
}

/*_________________---------------------------__________________
  _________________   process_command_line    __________________
  -----------------___________________________------------------
*/

static void process_command_line(int argc, char *argv[])
{
    int arg = 1, in = 0;
    int i;
    int plus, minus;

    /* set defaults */
    sfConfig.sFlowInputPort = 6343;
#ifdef WIN32
    sfConfig.listen4 = YES;
    sfConfig.listen6 = NO;
#else
    sfConfig.listen4 = YES;
    sfConfig.listen6 = NO;
#endif

    /* walk though the args */
    while (arg < argc) {
        plus = (argv[arg][0] == '+');
        minus = (argv[arg][0] == '-');
        if (plus == NO && minus == NO) {
            instructions(*argv);
        }
        in = argv[arg++][1];
        /* some options expect an argument - check for that first */
        switch (in) {
            case 'p':
            case 'r':
            case 'z':
            case 'c':
            case 'd':
            case 'f':
            case 'v':
                if (arg >= argc) {
                    instructions(*argv);
                }
                break;
            default:
                break;
        }

        switch (in) {
            case 'p':
                sfConfig.sFlowInputPort = atoi(argv[arg++]);
                break;
            case 't':
                sfConfig.outputFormat = SFLFMT_PCAP;
                break;
            case 'l':
                sfConfig.outputFormat = SFLFMT_LINE;
                break;
            case 'H':
                sfConfig.outputFormat = SFLFMT_CLF;
                break;
            case 'T':
                sfConfig.outputFormat = SFLFMT_TSD;
                break;
            case 'r':
                sfConfig.readPcapFileName = strdup(argv[arg++]);
                break;
            case 'x':
                sfConfig.removeContent = YES;
                break;
            case 'z':
                sfConfig.tcpdumpHdrPad = atoi(argv[arg++]);
                break;
            case 'c': {
                struct hostent *ent = gethostbyname(argv[arg++]);
                if (ent == NULL) {
                    fprintf(ERROUT, "netflow collector hostname lookup failed\n");
                    custom_exit(-8);
                }
                sfConfig.netFlowOutputIP.s_addr = ((struct in_addr *)(ent->h_addr))->s_addr;
                sfConfig.outputFormat = SFLFMT_NETFLOW;
            }
            break;
            case 'd':
                sfConfig.netFlowOutputPort = atoi(argv[arg++]);
                sfConfig.outputFormat = SFLFMT_NETFLOW;
                break;
            case 'e':
                sfConfig.netFlowPeerAS = YES;
                break;
            case 's':
                sfConfig.disableNetFlowScale = YES;
                break;
#ifdef SPOOFSOURCE
            case 'S':
                sfConfig.spoofSource = YES;
                break;
#endif
            case 'f':
                if (addForwardingTarget(argv[arg++]) == NO) {
                    custom_exit(-35);
                }
                sfConfig.outputFormat = SFLFMT_FWD;
                break;
            case 'v':
                if (plus) {
                    // +v => include vlans
                    sfConfig.gotVlanFilter = YES;
                    parseVlanFilter(sfConfig.vlanFilter, YES, argv[arg++]);
                } else {
                    // -v => exclude vlans
                    if (! sfConfig.gotVlanFilter) {
                        // when we start with an exclude list, that means the default should be YES
                        for (i = 0; i < FILTER_MAX_VLAN; i++) {
                            sfConfig.vlanFilter[i] = YES;
                        }
                        sfConfig.gotVlanFilter = YES;
                    }
                    parseVlanFilter(sfConfig.vlanFilter, NO, argv[arg++]);
                }
                break;
            case '4':
                sfConfig.listenControlled = YES;
                sfConfig.listen4 = YES;
                sfConfig.listen6 = plus;
                break;
            case '6':
                sfConfig.listenControlled = YES;
                sfConfig.listen4 = NO;
                sfConfig.listen6 = YES;
                break;
            case '?':
            case 'h':
            default:
                instructions(*argv);
        }
    }
}

/*_________________---------------------------__________________
  _________________         main              __________________
  -----------------___________________________------------------
*/

int main(int argc, char *argv[])
{
    int32_t soc4 = -1, soc6 = -1;

#ifdef WIN32
    WSADATA wsadata;
    WSAStartup(0xffff, &wsadata);
    /* TODO: supposed to call WSACleanup() on termination */
#endif

    /* read the command line */
    process_command_line(argc, argv);

    if (sfConfig.outputFormat == SFLFMT_TSD) {
        ignore_sigpipe();
    }

#ifdef WIN32
    // on windows we need to tell stdout if we want it to be binary
    if (sfConfig.outputFormat == SFLFMT_PCAP) {
        setmode(1, O_BINARY);
    }
#endif

    /* reading from file or socket? */
    if (sfConfig.readPcapFileName) {
        if (strcmp(sfConfig.readPcapFileName, "-") == 0) {
            sfConfig.readPcapFile = stdin;
        } else {
            sfConfig.readPcapFile = fopen(sfConfig.readPcapFileName, "rb");
        }
        if (sfConfig.readPcapFile == NULL) {
            fprintf(ERROUT, "cannot open %s : %s\n", sfConfig.readPcapFileName, strerror(errno));
            custom_exit(-1);
        }
        readPcapHeader();
    } else {
        /* open the input socket -- for now it's either a v4 or v6 socket, but in future
           we may allow both to be opened so that platforms that refuse to allow v4 packets
           to be received on a v6 socket can still get both. I think for that to really work,
           however,  we will probably need to allow the bind() to be on a particular v4 or v6
           address.  Otherwise it seems likely that we will get a clash(?) */
        if (sfConfig.listen6) {
            soc6 = openInputUDP6Socket(sfConfig.sFlowInputPort);
        }
        if (sfConfig.listen4 || (soc6 == -1 && !sfConfig.listenControlled)) {
            soc4 = openInputUDPSocket(sfConfig.sFlowInputPort);
        }
        if (soc4 == -1 && soc6 == -1) {
            fprintf(ERROUT, "unable to open UDP read socket\n");
            custom_exit(-7);
        }
    }

    /* possible open an output socket for netflow */
    if (sfConfig.netFlowOutputPort != 0 && sfConfig.netFlowOutputIP.s_addr != 0) {
        openNetFlowSocket();
    }
    /* if tcpdump format, write the header */
    if (sfConfig.outputFormat == SFLFMT_PCAP) {
        writePcapHeader();
    }
    if (sfConfig.readPcapFile) {
        /* just use a blocking read */
        while (readPcapPacket(sfConfig.readPcapFile));
    } else {
        fd_set readfds;
        /* set the select mask */
        FD_ZERO(&readfds);
        /* loop reading packets */
        for (;;) {
            int nfds;
            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000;

            if (soc4 != -1) {
                FD_SET(soc4, &readfds);
            }
            if (soc6 != -1) {
                FD_SET(soc6, &readfds);
            }

            nfds = select((soc4 > soc6 ? soc4 : soc6) + 1,
                          &readfds,
                          (fd_set *)NULL,
                          (fd_set *)NULL,
                          &timeout);
            /* we may return prematurely if a signal was caught, in which case
             * nfds will be -1 and errno will be set to EINTR.  If we get any other
             * error, abort.
             */
            if (nfds < 0 && errno != EINTR) {
                fprintf(ERROUT, "select() returned %d\n", nfds);
                custom_exit(-9);
            }
            if (nfds > 0) {
                if (soc4 != -1 && FD_ISSET(soc4, &readfds)) {
                    readPacket(soc4);
                }
                if (soc6 != -1 && FD_ISSET(soc6, &readfds)) {
                    readPacket(soc6);
                }
            }
        }
    }
    return 0;
}



int opentsdb_connect_socket()
{
    struct sockaddr_in echoServAddr; /* Echo server address */
    unsigned short echoServPort;     /* Echo server port */
    static int error_flag = 0;
    //    int bytesRcvd, totalBytesRcvd;   /* Bytes read in single recv()
    //                                        and total bytes read */

    char *servIP = "127.0.0.1";             /* First arg: server IP address (dotted quad) */
    echoServPort = 4242;

    /* Create a reliable, stream socket using TCP */
    if ((g_opentsdb_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        dump_syslog (LOG_ERR, "Unable to create opentsdb socket\n"); 
        return 1;
    }

    int option_val = 1;
    setsockopt( g_opentsdb_sock, IPPROTO_TCP, TCP_NODELAY, (void *)&option_val, sizeof(option_val));

    option_val = 4024;
    setsockopt( g_opentsdb_sock, IPPROTO_TCP, TCP_MAXSEG, (void *)&option_val, sizeof(option_val));

    /* Construct the server address structure */
    echoServAddr.sin_family      = AF_INET;             /* Internet address family */
    echoServAddr.sin_addr.s_addr = inet_addr(servIP);   /* Server IP address */
    echoServAddr.sin_port        = htons(echoServPort); /* Server port */

    /* Establish the connection to the echo server */
    if (connect(g_opentsdb_sock, (struct sockaddr *) &echoServAddr, sizeof(echoServAddr)) < 0) {
        if (!error_flag) {
            dump_syslog (LOG_ERR, "Unable to connect to opentsdb server %s port %d\n", servIP, echoServPort); 
        }

        error_flag = 1;
        close(g_opentsdb_sock);
        return 1;
    } else {
        g_opentsdb_socket_connected = 1;
        dump_syslog (LOG_INFO, "Connected to opentsdb server %s port %d\n", servIP, echoServPort); 
        error_flag = 0;
        return 0;
    }
}


int opentsdb_simple_connect(char *data)
{

    if (!g_opentsdb_socket_connected) {
        if (opentsdb_connect_socket()) {
            return 1;
        }
    }

    /* Send the string to the server */
    if (send(g_opentsdb_sock, data, strlen(data), MSG_DONTWAIT ) < 0) {
        close(g_opentsdb_sock);
        g_opentsdb_socket_connected = 0;
        if (opentsdb_connect_socket()) {
            return 1;
        }
        if (send(g_opentsdb_sock, data, strlen(data), MSG_DONTWAIT ) < 0) {
            close(g_opentsdb_sock);
            g_opentsdb_socket_connected = 0;
            dump_syslog (LOG_ERR, "Unable to send data to opentsdb server\n"); 
            return 1;
        }
    }

    return 0;
}





#if defined(__cplusplus)
}  /* extern "C" */
#endif
