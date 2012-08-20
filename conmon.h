/*
  conmon.h
  

  Created by Varun Singh on 8/8/2012.
  Copyright (c) 2012 Varun. All rights reserved.
*/

#ifndef _conmon_h
#define _conmon_h


#define APP_NAME        "conmon"
#define APP_DESC        "based on Sniffer example using libpcap"
#define APP_COPYRIGHT   "extended by Varun Singh / Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER  "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.\n"

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/util.h>

#include <pthread.h>

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>

#define __USE_BSD         /* Using BSD IP header           */ 
#include <netinet/ip.h>   /* Internet Protocol             */ 
#define __FAVOR_BSD       /* Using BSD TCP header          */ 
#include <netinet/tcp.h>  /* Transmission Control Protocol */

#define TIMEOUT 1
#define EV_PERSIST_FLAG 1

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define ETHHDRSIZE 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* IPv4, TCP, UDP header sizes */
#define IPHDRSIZE   sizeof(struct sniff_ip)
#define TCPHDRSIZE  sizeof(struct sniff_tcp)
#define UDPHDRSIZE  sizeof(struct sniff_udp)    /* 8: length of UDP header */	

/* INET_ADDRSTRLEN is 16 */

#define CAPTURE_COUNT -1           /* number of packets to capture, -1: non-stop */

#define LOG_SIZE 10    /* Size of the vLog array or map*/

#define DIR "logs"
#define PKT_LIST "pkt_list"
#define TIME_LIST "time_list"

#define FILE_STORE 1

/*
 from: http://www.beej.us/guide/bgnet/output/html/singlepage/bgnet.html#getnameinfoman
 Finally, there are several flags you can pass, but here a a couple good ones. 
 NI_NOFQDN will cause the host to only contain the host name, not the whole domain name. 
 NI_NAMEREQD will cause the function to fail if the name cannot be found with a DNS lookup
 
 (if you don't specify this flag and the name can't be found, 
 getnameinfo() will put a string version of the IP address in host instead.)
 */
#ifndef NI_NUMERICHOST
  #define NI_NUMERICHOST 2
#endif

/* Ethernet header */
struct sniff_ethernet {
  u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
  u_short ether_type;                     /* IP? ARP? RARP? etc */
};


/* 
 IP header: http://tools.ietf.org/html/rfc791#section-3.1
 
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |Version|  IHL  |Type of Service|          Total Length         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |         Identification        |Flags|      Fragment Offset    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Time to Live |    Protocol   |         Header Checksum       |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                       Source Address                          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Destination Address                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Options                    |    Padding    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct sniff_ip {
  u_char  ip_vhl;               /* version << 4 | header length >> 2 */
  u_char  ip_tos;               /* type of service */
  u_short ip_len;               /* total length */
  u_short ip_id;                /* identification */
  u_short ip_off;               /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
  u_char  ip_ttl;               /* time to live */
  u_char  ip_p;                 /* protocol */
  u_short ip_sum;               /* checksum */
  struct  in_addr ip_src,ip_dst;/* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


/* 
 TCP header: http://tools.ietf.org/html/rfc793#section-3.1
 
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |          Source Port          |       Destination Port        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                        Sequence Number                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Acknowledgment Number                      |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Data |           |U|A|P|R|S|F|                               |
 | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 |       |           |G|K|H|T|N|N|                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           Checksum            |         Urgent Pointer        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Options                    |    Padding    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                             data                              |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
 */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport;       /* source port */
  u_short th_dport;       /* destination port */
  tcp_seq th_seq;         /* sequence number */
  tcp_seq th_ack;         /* acknowledgement number */
  u_char  th_offx2;       /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  u_char  th_flags;
#define TH_FIN  0x01    /* 1  */
#define TH_SYN  0x02    /* 2  */
#define TH_RST  0x04    /* 4  */
#define TH_PUSH 0x08    /* 8  */
#define TH_ACK  0x10    /* 16 */
#define TH_URG  0x20    /* 32 */
#define TH_ECE  0x40    /* 64 */
#define TH_CWR  0x80    /* 128*/
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;         /* window */
  u_short th_sum;         /* checksum */
  u_short th_urp;         /* urgent pointer */
};


/* UDP header: http://tools.ietf.org/html/rfc768
 0      7 8     15 16    23 24    31
 +--------+--------+--------+--------+
 |     Source      |   Destination   |
 |      Port       |      Port       |
 +--------+--------+--------+--------+
 |                 |                 |
 |     Length      |    Checksum     |
 +--------+--------+--------+--------+
 |
 |          data octets ...
 +---------------- ...
 */

struct sniff_udp {
  u_short uh_sport;               /* source port */
  u_short uh_dport;               /* destination port */
  u_short uh_ulen;                /* udp length */
  u_short uh_sum;                 /* udp checksum */
  
};


/* flag for CROSS, INCOMING or OUTGOING Traffic*/
typedef enum XIO {
  XIO_CROSS = 0,
  XIO_INCOMING,
  XIO_OUTGOING
}xio_flag;                      

/* a structure to hold all the bytes sent and received 
 every second. */
typedef struct bwLogger {
  u_int time;
  u_int total;
  u_int xostr;  /* cross traffic*/
  u_int inctr;
  u_int outtr;
  u_int tcp;  /* TCP */
  u_int tcp_inc;
  u_int tcp_out;
  u_int tcp_xos;
  u_int udp;  /* UDP */
  u_int udp_inc;
  u_int udp_out;
  u_int udp_xos;
  u_int local;  /* local */
  u_int loc_inc;
  u_int loc_out;
  u_int loc_xos;
  u_int external; /* external */
  u_int ext_inc;
  u_int ext_out;
  u_int ext_xos;
}vLog;                        
/* probably need a list to store this information*/

/* app banner and usage*/
void print_app_banner(void);

void print_app_usage(void);

/* print */

void print_payload(const u_char *payload, u_int len);

void print_hex_ascii_line(const u_char *payload, u_int len, int offset);

void print_empty_string(char *str);

/* time functions*/

double gettime();

/* Traffic Classifiers*/

u_short checkIfIpLocal(u_long lIpAddr, int af_flag);

xio_flag checkInboundOrOutbound(char *sIp, char *dIp);

/* PCAP: */

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

u_int ParseUDPPacket (const u_char *packet, u_int &src_port, u_int &dst_port);

u_int ParseTCPPacket(const u_char *packet, u_int &src_port, u_int &dst_port);

void showPacketDetails(const struct sniff_ip *iph, const struct sniff_tcp *tcph);

void readTCPflag(u_char tcp_flags);

char* iptos(struct sockaddr *sockAddress, int af_flag, char *address, int addrlen);

void print_interface(pcap_if_t *d);

void update_vlog(u_int sec, int location, u_char proto, xio_flag isXIO, u_int isLocal, u_int payload);

void reset_vlog(int location);

/* EVENT: */
void *timer_event_initialize(void *threadid);


/* EVENT: */
struct timeval lasttime;
struct event_base *base;        /* to initialize eventing */


/* PCAP: */
struct bpf_program fp;          /* compiled filter program (expression) */

/* dot notation of the host address*/
char strHostIP[INET_ADDRSTRLEN];
/*host socket*/
struct sockaddr *hostSockAddr;

/* dot notation of the network address */
char cnet[INET_ADDRSTRLEN];    
/* network address */
bpf_u_int32 net;     


/* dot notation of the network mask    */
char cmask[INET_ADDRSTRLEN];
/* subnet mask */
bpf_u_int32 mask;

/* packet capture handle */
pcap_t *handle;            

/* packet counter */
u_int pkt_count = 1;

/* vLog should be a list, but using Array for convenience.*/
vLog vlog_pkt[LOG_SIZE], vlog_bw[LOG_SIZE];
int calc_log, store_log;

/* File names to store data */
char *filestore_pkt;
char *filestore_tsc;

#endif
