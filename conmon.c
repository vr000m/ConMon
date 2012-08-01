/*

  conmon

  Created by Varun Singh on 10/3/2012.


 Note a lot of code is borrowed from here and there.
 
 gcc -Wall -pedantic conmon.c -lpcap -o conmon
 http://www.tcpdump.org/pcap.html
 
 http://tools.ietf.org/html/rfc768
 http://tools.ietf.org/html/rfc793
 http://tools.ietf.org/html/rfc1071
 
 Tested to run on the MAC.
 http://www.winpcap.org/docs/docs_412/html/group__wpcap__tut2.html
 */

#define APP_NAME        "conmon"
#define APP_DESC        "based on Sniffer example using libpcap"
#define APP_COPYRIGHT   "extended by Varun Singh / Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER  "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.\n"

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

#define __USE_BSD         /* Using BSD IP header           */ 
#include <netinet/ip.h>   /* Internet Protocol             */ 
#define __FAVOR_BSD       /* Using BSD TCP header          */ 
#include <netinet/tcp.h>  /* Transmission Control Protocol */


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

/*
 from: http://www.beej.us/guide/bgnet/output/html/singlepage/bgnet.html#getnameinfoman
 Finally, there are several flags you can pass, but here a a couple good ones. 
 NI_NOFQDN will cause the host to only contain the host name, not the whole domain name. 
 NI_NAMEREQD will cause the function to fail if the name cannot be found with a DNS lookup 
 (if you don't specify this flag and the name can't be found, getnameinfo() will put a string version of the IP address in host instead.)
 */
#ifndef NI_NUMERICHOST
# define NI_NUMERICHOST 2
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

/* device */
struct bpf_program fp;          /* compiled filter program (expression) */

char strHostIP[INET_ADDRSTRLEN];

struct sockaddr *hostSockAddr;

char cnet[INET_ADDRSTRLEN];     /* dot notation of the network address */
bpf_u_int32 net;                /* network address */

char cmask[INET_ADDRSTRLEN];    /* dot notation of the network mask    */
bpf_u_int32 mask;               /* subnet mask */

pcap_t *handle;                 /* packet capture handle */
u_int pkt_count = 1;              /* packet counter */



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


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_app_banner(void);

void print_app_usage(void);

void readTCPflag(u_char tcp_flags);

void showPacketDetails(const struct sniff_ip *iph, const struct sniff_tcp *tcph);

u_int ParseUDPPacket (const u_char *packet);

u_int ParseTCPPacket(const u_char *packet);

void print_payload(const u_char *payload, u_int len);

void print_hex_ascii_line(const u_char *payload, u_int len, int offset);

char* iptos(struct sockaddr *sockAddress, int af_flag, char *address, int addrlen);

void print_interface(pcap_if_t *d);

void printEmptyFormat(char *str);


void print_app_banner(void)
{
  
  printf("%s - %s\n", APP_NAME, APP_DESC);
  printf("%s\n", APP_COPYRIGHT);
  printf("%s\n", APP_DISCLAIMER);
  
  return;
}

void signal_handler(int signal)
{
  /* cleanup */
  pcap_freecode(&fp);
  pcap_close(handle);
  exit(0);
}

void print_app_usage(void)
{
  
  printf("Usage: %s [interface] [filter]\n", APP_NAME);
  printf("\n");
  printf("Options:\n");
  printf("    interface     Listen on <interface> for packets.\n");
  printf("    filter        PCAP Filter to apply on packets.\n");
  printf("\n");
  
  return;
}

/*
 * print data in rows of 16 bytes: 
 * offset  hex                                                ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, u_int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);
    
    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");
    
    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");
    
    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    printf("\n");
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, u_int len)
{

    int len_rem = len;
    int line_width = 16;            /* number of bytes per line */
    int line_len;
    int offset = 0;                 /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
}

void printEmptyFormat(char *str)
{
  printf("%s\t--\t->\t--\t", str);
}

u_short checkIfIpLocal(u_long lIpAddr, int af_flag)
{
  /*
   compare given address with host address and 
   if they belong to the same subnet then return true
   else return false
  */
   
  if (((u_long)net&lIpAddr) == (u_long)net)
    return 1;
  else 
    return 0;
  /*
   struct sockaddr_in sockIpAddr;
   inet_pton(AF_INET, ipaddr, &(sockIpAddr.sin_addr));
   printf("IP.. %s \t", ipaddr);*/
}


void checkInboundOrOutbound(char *sIp, char *dIp)
{
  if (strcmp(sIp, strHostIP)==0) {
    printf("Out\t");
  }
  else if (strcmp(dIp, strHostIP)==0) {
    printf("Inc\t");
  }
  else {
    printf("Xos\t");
  }
}

/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  const struct sniff_ip *ip;              /* The IP header */
  int size_ip;
  int ip_version;
  char srcPkt[INET_ADDRSTRLEN];
  char dstPkt[INET_ADDRSTRLEN];
  
  int size_payload;
  unsigned long int sec;
  
  sec = time(NULL);
  /* define ethernet header */
  ethernet = (struct sniff_ethernet*)(packet);
  
  /* define/compute ip header offset */
  ip = (struct sniff_ip*)(packet + ETHHDRSIZE);

  ip_version = IP_V(ip);
  size_ip = IP_HL(ip)*4;
  if (size_ip < IPHDRSIZE) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }
  
  inet_ntop(AF_INET, &(ip->ip_src), srcPkt, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip->ip_dst), dstPkt, INET_ADDRSTRLEN);
  

  printf("%d:\t%ld\tv%d\t", pkt_count++, sec, ip_version);
  /*
   First AND both src and destination ipaddress with netmask
   if the IP address are equal then the endpoints communicating locally.

   Possible combinations:
   If both src and destination match then local else external.
   In each categoy the comunication can be inbound/outbound/cross traffic
  */
  if(checkIfIpLocal((ip->ip_src).s_addr, AF_INET)==1 && checkIfIpLocal((ip->ip_dst).s_addr, AF_INET)==1){
    printf ("Loc\t");
    checkInboundOrOutbound(srcPkt, dstPkt);
  }
  else {
    printf ("Ext\t");
    checkInboundOrOutbound(srcPkt, dstPkt);
  }
    
  
  
  size_payload = ntohs(ip->ip_len);
/*  printf("%d\t", size_payload); */
  
  
  switch(ip->ip_p) {
      /*
       IP IANA numbers
       http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
       */
    case IPPROTO_TCP:
      printf("TCP\t");
      size_payload =ParseTCPPacket((u_char *)ip);
      break;
    case IPPROTO_UDP:
      printf("UDP\t");
      size_payload = ParseUDPPacket((u_char *)ip);
      break;
    case IPPROTO_ICMP:
      printEmptyFormat("ICMP");
      break;
    case IPPROTO_IP:
      printEmptyFormat("IP");
      break;
    case IPPROTO_IGMP:
      printEmptyFormat("IGMP");
      break;
    case IPPROTO_PIM:
      printEmptyFormat("PIM");
      break;  
    default:
      printf("%d", ip->ip_p);
      printEmptyFormat("");
      break;
  }
  printf("%d\t",size_payload);
  printf("%s\t->\t", srcPkt);
  printf("%s\t", dstPkt);
  
  printf("\n");
}

u_int ParseUDPPacket (const u_char *packet)
{
  const struct sniff_ip *ip;              /* The IP header */
  const struct sniff_udp *udp;            /* The UDP header */
  const u_char *payload;                  /* Packet payload */

  u_int size_payload =0;
  
  u_int srcport=0;
  u_int dstport=0;
  
  ip = (struct sniff_ip*)(packet);
  udp = (struct sniff_udp*)(packet + IPHDRSIZE);
  srcport = ntohs(udp->uh_sport);
  dstport = ntohs(udp->uh_dport);
  
  /* define/compute tcp payload (segment) offset */
  payload = (u_char *)(packet + IPHDRSIZE + UDPHDRSIZE);
  
  /* compute tcp payload (segment) size */
  size_payload = ntohs(ip->ip_len) - (IPHDRSIZE + UDPHDRSIZE);
  
  printf("%d\t->\t", srcport);
  printf(" %d\t", dstport);

  
  return size_payload;
}

u_int ParseTCPPacket(const u_char *packet)
{
  const struct sniff_ip *ip;              /* The IP header */
  const struct sniff_tcp *tcp;            /* The TCP header */
  const u_char *payload;                  /* Packet payload */
  
  u_int size_tcp=0;
  u_int size_payload=0;

  u_int srcport=0;
  u_int dstport=0;
  
  ip = (struct sniff_ip*)(packet);
  
  /*if((strcmp(srcHost, strHostIP)==0)|| (strcmp(dstHost, strHostIP)==0))*/
  {
    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + IPHDRSIZE);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < TCPHDRSIZE) {
      printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
      return 0;
    }
    srcport = ntohs(tcp->th_sport);
    dstport = ntohs(tcp->th_dport);
    
    /* define/compute tcp payload (segment) offset */
    payload = (u_char *)(packet + IPHDRSIZE + TCPHDRSIZE);
    
    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (IPHDRSIZE + size_tcp);
    
    printf("%d\t->\t", srcport);
    printf(" %d\t", dstport);
    
    #if _DEBUG
    printf("id: %d\t", htons(ip->ip_id));
    printf("seq: %u\t", ntohl(tcp->th_seq));  
    printf("ack: %u\t", ntohl(tcp->th_ack));  
    printf("sum: %x\n", (ip->ip_sum));
    if (size_payload > 0) {
      printf("   Payload (%d bytes)", size_payload);
      print_payload(payload, size_payload);
    }      
    showPacketDetails(ip, tcp); 
    #endif
  }
  return size_payload;
}

void showPacketDetails(const struct sniff_ip *iph, const struct sniff_tcp *tcph)
{
  /*should cleanup: 0 to _DEBUG*/
#if _DEBUG
  printf(" vhl=%x\n",iph->ip_vhl);       
  printf(" tos=%x\n",iph->ip_tos);       
  printf(" len=%d IP+TCP hdr len=%ld\n",ntohs(iph->ip_len), IPHDRSIZE + TCPHDRSIZE);
  printf(" ide=%d\n",ntohs(iph->ip_id));
  printf(" off=%d\n",ntohs(iph->ip_off));
  printf(" ttl=%x\n",iph->ip_ttl);
  printf(" pro=%x\n",iph->ip_p);
  printf(" src=%s\n",inet_ntoa(iph->ip_src));
  printf(" dst=%s\n",inet_ntoa(iph->ip_dst));
  printf(" sum=%x\n",(iph->ip_sum)); /* no ntohs */
  
  printf(" sport=%d\n", ntohs(tcph->th_sport));
  printf(" dport=%d\n", ntohs(tcph->th_dport));
  printf(" seq=%x\n"  , ntohl(tcph->th_seq));  
  printf(" ack=%x\n"  , ntohl(tcph->th_ack));  
  printf(" offx2=%d\n", tcph->th_offx2);
  printf(" win=%d\n"  , ntohs(tcph->th_win));
  printf(" sum=%x\n"  , (tcph->th_sum)); /* no ntohs */
  printf(" urp=%d\n"  , tcph->th_urp);
  /*Print which flag is set in TCP*/
  readTCPflag(tcph->th_flags);
  printf("\n");
#endif
}

void readTCPflag(u_char tcp_flags)
{
  /*printf("   th_flags (%x, %x)\t", tcp_flags, tcp_flags & TH_FLAGS);
   printf("   Flag: "); */
  if (tcp_flags & TH_FIN) { printf(" FIN"); }
  if (tcp_flags & TH_SYN) { printf(" SYN"); }
  if (tcp_flags & TH_RST) { printf(" RST"); }
  if (tcp_flags & TH_PUSH){ printf(" PUSH"); }
  if (tcp_flags & TH_ACK) { printf(" ACK"); }
  if (tcp_flags & TH_URG) { printf(" URG"); }
  if (tcp_flags & TH_ECE) { printf(" ECE"); }
  if (tcp_flags & TH_CWR) { printf(" CWR"); }
}

char* iptos(struct sockaddr *sockAddress, int af_flag, char *address, int addrlen)
{
  socklen_t sockaddrlen;
  
  sockaddrlen = sizeof(struct sockaddr_storage);  
  
  if(getnameinfo(sockAddress, 
                 sockaddrlen, 
                 address, 
                 addrlen, 
                 NULL, 
                 0, 
                 NI_NUMERICHOST) != 0) address = NULL;
  
  return address;
}

void print_interface(pcap_if_t *d)
{
  /*
   from http://www.winpcap.org/docs/docs_412/html/group__wpcap__tut2.html 
   */
  pcap_addr_t *a;
  char ip46str[128];
  
  for(a=d->addresses;a;a=a->next) {        
    switch(a->addr->sa_family)
    {
      case AF_INET:
        if (a->addr)
          printf("\tIPv4: %s\t", iptos(a->addr, AF_INET, ip46str, sizeof(ip46str)));
        break;
        
      /* we could enable IPv6.
      case AF_INET6:
        if (a->addr)
          printf("\tIPv6: %s\t", iptos(a->addr, AF_INET6, ip46str, sizeof(ip46str)));
        break;*/
        
      default:
        /*printf("\tAddress Family Name: Unknown\n");*/
        break;
    }
  }
  printf("\n");  
}

int main(int argc, char **argv)
{
  char *dev = NULL;               /* capture device name */
  char errbuf[PCAP_ERRBUF_SIZE];  /* error buffer */
  /*
   * Expression			Description
   * ----------			-----------
   * ip					Capture all IP packets.
   * tcp					Capture only TCP packets.
   * tcp port 80			Capture only TCP packets with a port equal to 80.
   * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
   *
   ****************************************************************************
   *   tcp[13] == 0x10) or (tcp[13] == 0x18) for ACK and ACK+PUSH
   *  (tcp[13] == 0x10) for only ACK packets
   *  ip for any IP packet
   */
  char filter_exp[] = "ip";
  pcap_if_t *alldevices, *device, *chosendevice;
  pcap_addr_t *a;
  int i =0, j=0;
  int choice=-1;
  
  /* Ctrl+C */
  signal ( SIGINT, signal_handler);
  
  print_app_banner();
  
  if (argc > 3 ) {
    fprintf(stderr, "error: unrecognized command-line options\n\n");
    print_app_usage();
    exit(EXIT_FAILURE);
  }
  
  /* check for capture device name on command-line */
  if (argc >= 2) {
    dev = argv[1];
  }
  
  if (argc == 3) {
    strcpy(filter_exp,argv[2]);
  }
  
  
  if (pcap_findalldevs(&alldevices, errbuf) == -1) {
    fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);
  }
  
  if (argc == 1 ){
    /* Print the list */
    for(device=alldevices; device; device=device->next) {
      if(device->flags & PCAP_IF_LOOPBACK)
        break;
      printf("%d. %s", ++i, device->name);
      if (device->description)
        printf(" (%s)\t", device->description);
      else
        printf(" (No description available)\t");
      print_interface(device);
    }
    if(i==0) {
      printf("\nNo interfaces found! Make sure libpcap is installed.\n");
      return -1;
    }
    
    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &choice);
    
    if(choice < 1 || choice > i) {
      printf("\nInterface number out of range.\n");
      /* Free the device list */
      pcap_freealldevs(alldevices);
      return -1;
    }
  }
    
  /* Iterate the link list to the chosen device 
      based on choice or device name*/
  for(device=alldevices, j=1; device ;device=device->next, j++){
    if( (dev!=NULL && strcmp(device->name, dev)==0) || choice==j)
    {
      chosendevice=device;
      break;
    }               
  }
  
  dev=chosendevice->name;
  
  for(a=chosendevice->addresses;a;a=a->next) {        
    switch(a->addr->sa_family)
    {
      case AF_INET:
        if (a->addr) {
        /*
          address->addr
          address->netmask
          address->broadaddr
          address->dstaddr
        */
          iptos(a->addr, AF_INET, strHostIP, sizeof(strHostIP));
          hostSockAddr = a->addr;
          iptos(a->netmask, AF_INET, cmask, sizeof(strHostIP));
        }
        break;
    }
  }
  printf("IP ADDR: %s\tMASK: %s\t",strHostIP, cmask);  
  if (dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  /* get network number and mask associated with capture device*/
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
            dev, errbuf);
    net = 0;
    mask = 0;
  }
  
  /* print capture info */
  printf("Device: %s\t", dev);
  /*printf("Number of packets: %d\n", CAPTURE_COUNT);*/
  printf("Filter expression: %s\n", filter_exp);
  
  printf("SNo.\ttime in sec\tIPv\tLoc/Ext\tO/I/X\tProto\tSPort\t->\tDPort\tSize\tSrc. IP Addr\t->\tDest. IP Addr\n");

  /* open capture device */
  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf); 
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }
  
  /* make sure we're capturing on an Ethernet device [2] */
  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "%s is not an Ethernet\n", dev);
    exit(EXIT_FAILURE);
  }
  
  /* compile the filter expression */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  
  /* apply the compiled filter */
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  
  /* now we can set our callback function */
  pcap_loop(handle, CAPTURE_COUNT, got_packet, NULL);
  printf("\nCapture complete.\n");
  
  return 0;
}

