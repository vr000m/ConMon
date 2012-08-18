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

#include "conmon.h"

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
#if EV_PERSIST_FLAG
/*BUG: remove event*/
#endif
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

    u_int i;
    u_int gap;
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

    u_int len_rem = len;
    u_int line_width = 16;            /* number of bytes per line */
    u_int line_len;
    u_int offset = 0;                 /* zero-based offset counter */
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

void print_empty_string(char *str)
{
  printf("%s\t--\t->\t--\t", str);
}

double gettime()
{
  int errno;
  struct timeval t_now;
  
  
	errno = gettimeofday(&t_now, NULL);
  
	return (t_now.tv_sec+t_now.tv_usec/1000000.0);
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


xio_flag checkInboundOrOutbound(char *sIp, char *dIp)
{
  xio_flag x;
  if (strcmp(sIp, strHostIP)==0) {
    /*printf("Out\t");*/
    x= XIO_OUTGOING;
  }
  else if (strcmp(dIp, strHostIP)==0) {
    /*printf("Inc\t");*/
    x= XIO_INCOMING;
  }
  else {
    /*printf("Xos\t");*/
    x= XIO_CROSS;
  }
  return x;
}

/*
 * Store stats routinely
 */
void timeout_callback(evutil_socket_t fd, short event, void *arg)
{
	struct timeval newtime, difference;

#if !EV_PERSIST_FLAG
 struct event *timeout = arg; 
 struct timeval tv;
#endif
  double elapsed;
  
	evutil_gettimeofday(&newtime, NULL);
	evutil_timersub(&newtime, &lasttime, &difference);
	elapsed = difference.tv_sec + (difference.tv_usec / 1.0e6);
  
/*	printf("timeout_callback called at %d: %.3f seconds elapsed.\n", \
         (int)newtime.tv_sec, elapsed); */
	lasttime = newtime;
  
/*  printf ("reset %f %f\n", newtime.tv_sec+(newtime.tv_usec/1.0e6), \
          lasttime.tv_sec+(lasttime.tv_usec/1.0e6)); */
  if(vlog_pkt[calc_log].time != 0)
  {
    calc_log++;
    store_log++;
    if(calc_log == 10)
      calc_log = 0;
    if(store_log == 10)
      store_log = 0;
    
    reset_vlog(calc_log);
    FILE *f2p;
    f2p = fopen ("time_list.txt", "a+");
    fprintf(f2p, "%d\t%d\t%f\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
           vlog_pkt[store_log].time,
           (u_int)gettime(),
           elapsed,
           vlog_pkt[store_log].total,
           vlog_bw[store_log].total,
           vlog_pkt[store_log].inctr,
           vlog_bw[store_log].inctr,
           vlog_pkt[store_log].outtr,
           vlog_bw[store_log].outtr,
           vlog_pkt[store_log].xostr,
           vlog_bw[store_log].xostr,
           vlog_pkt[store_log].tcp,
           vlog_bw[store_log].tcp,
           vlog_pkt[store_log].tcp_inc,
           vlog_bw[store_log].tcp_inc,
           vlog_pkt[store_log].tcp_out,
           vlog_bw[store_log].tcp_out,
           vlog_pkt[store_log].tcp_xos,
           vlog_bw[store_log].tcp_xos,
           vlog_pkt[store_log].udp,
           vlog_bw[store_log].udp,
           vlog_pkt[store_log].udp_inc,
           vlog_bw[store_log].udp_inc,
           vlog_pkt[store_log].udp_out,
           vlog_bw[store_log].udp_out,
           vlog_pkt[store_log].udp_xos,
           vlog_bw[store_log].udp_xos,
           vlog_pkt[store_log].local,
           vlog_bw[store_log].local,
           vlog_pkt[store_log].loc_inc,
           vlog_bw[store_log].loc_inc,
           vlog_pkt[store_log].loc_out,
           vlog_bw[store_log].loc_out,
           vlog_pkt[store_log].loc_xos,
           vlog_bw[store_log].loc_xos,
           vlog_pkt[store_log].external,
           vlog_bw[store_log].external,
           vlog_pkt[store_log].ext_inc,
           vlog_bw[store_log].ext_inc,
           vlog_pkt[store_log].ext_out,
           vlog_bw[store_log].ext_out,
           vlog_pkt[store_log].ext_xos,         
           vlog_bw[store_log].ext_xos);
    fclose(f2p);
/*  printf("timeout(): %d (%f) log c: %d s: %d\n",(int)(newtime.tv_sec+(newtime.tv_usec/1.0e6)), elapsed, calc_log, store_log);*/
  }
  
#if !EV_PERSIST_FLAG
  evutil_timerclear(&tv);
  tv.tv_sec = TIMEOUT;
  event_add(timeout, &tv);
#endif
}


/* maybe this should be inside a MUTEX*/
void update_vlog(u_int sec, int location, u_char proto, xio_flag isXIO, u_int isLocal, u_int payload) 
{
  vlog_pkt[location].time = sec;
  vlog_bw[location].time = sec;
  
  vlog_pkt[location].total++;
  vlog_bw[location].total += payload;
  
  if(isLocal==1) {
    vlog_pkt[location].local++;
    vlog_bw[location].local += payload;
  }
  else {
    vlog_pkt[location].external++;
    vlog_bw[location].external += payload;
  }
  
  switch(isXIO) {
    case XIO_CROSS:
      vlog_pkt[location].xostr++;
      vlog_bw[location].xostr +=payload;
      if(isLocal==1) {
        vlog_pkt[location].loc_xos++;
        vlog_bw[location].loc_xos += payload;
      }
      else {
        vlog_pkt[location].ext_xos++;
        vlog_bw[location].ext_xos += payload;
      }
      break;
    case XIO_INCOMING:
      vlog_pkt[location].inctr++;
      vlog_bw[location].inctr +=payload;
      if(isLocal==1) {
        vlog_pkt[location].loc_inc++;
        vlog_bw[location].loc_inc += payload;
      }
      else {
        vlog_pkt[location].ext_inc++;
        vlog_bw[location].ext_inc += payload;
      }
      break;
    case XIO_OUTGOING:
      vlog_pkt[location].outtr++;
      vlog_bw[location].outtr +=payload;
      if(isLocal==1) {
        vlog_pkt[location].loc_out++;
        vlog_bw[location].loc_out += payload;
      }
      else {
        vlog_pkt[location].ext_out++;
        vlog_bw[location].ext_out += payload;
      }
      break;
  }
  
  switch(proto) {
    case IPPROTO_TCP:
      vlog_pkt[location].tcp++;
      vlog_bw[location].tcp += payload;
      
      switch(isXIO){
        case XIO_CROSS:
          vlog_pkt[location].tcp_xos++;
          vlog_bw[location].tcp_xos +=payload;
          break;
        case XIO_INCOMING:
          vlog_pkt[location].tcp_inc++;
          vlog_bw[location].tcp_inc +=payload;
          break;
        case XIO_OUTGOING:
          vlog_pkt[location].tcp_out++;
          vlog_bw[location].tcp_out +=payload;
          break;
      }
      break;
    case IPPROTO_UDP:
      vlog_pkt[location].udp++;
      vlog_bw[location].udp += payload;
      
      switch(isXIO){
        case XIO_CROSS:
          vlog_pkt[location].udp_xos++;
          vlog_bw[location].udp_xos +=payload;
          break;
        case XIO_INCOMING:
          vlog_pkt[location].udp_inc++;
          vlog_bw[location].udp_inc +=payload;
          break;
        case XIO_OUTGOING:
          vlog_pkt[location].udp_out++;
          vlog_bw[location].udp_out +=payload;
          break;
      }
      break;
  }
  /*printf("packets(): %d log c: %d s: %d\n", sec, calc_log, store_log);*/
}

/*
 * dissect packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  const struct sniff_ethernet *ethernet;  /* The ethernet header */
  const struct sniff_ip *ip;              /* The IP header */
  u_int size_ip;
  int ip_version;
  char srcPkt[INET_ADDRSTRLEN];
  char dstPkt[INET_ADDRSTRLEN];
  
  xio_flag isXIO;
  
  int isLocal=-1;
  
  u_int srcport=0;
  u_int dstport=0;
  
  u_int size_payload=0, size_ip_payload=0;
  u_int sec;
  
  /* define ethernet header */
  ethernet = (struct sniff_ethernet*)(packet);
  
  sec = (u_int)gettime();
  
  /* BUG:? we need to handle v4 and v6 methods here*/
  /* getting to the IP header */
  ip = (struct sniff_ip*)(packet + ETHHDRSIZE);
  /* parsing IP header*/
  ip_version = IP_V(ip);
  size_ip = IP_HL(ip)*4;
  if (size_ip < IPHDRSIZE) {
    fprintf(stderr,"* Invalid IP header length: %u bytes\n", size_ip);
    return;
  }
  
  inet_ntop(AF_INET, &(ip->ip_src), srcPkt, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip->ip_dst), dstPkt, INET_ADDRSTRLEN);
  
  /*
   First "logical AND" both src and destination ipaddress with netmask
   if the IP address are equal then the endpoints communicating locally.

   Possible combinations:
   If both src and destination match then local else external.
   In each categoy the comunication can be inbound/outbound/cross traffic
  */
  isXIO = checkInboundOrOutbound(srcPkt, dstPkt);
  
  if(checkIfIpLocal((ip->ip_src).s_addr, AF_INET)==1 && checkIfIpLocal((ip->ip_dst).s_addr, AF_INET)==1){
    isLocal = 1;
  }
  else {
    isLocal = 0;
  }
  
  size_ip_payload = ntohs(ip->ip_len);

  switch(ip->ip_p) {
      /*
       IP IANA numbers
       http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
       */
    case IPPROTO_TCP:
      size_payload =ParseTCPPacket((u_char *)ip, srcport, dstport);
      break;
    case IPPROTO_UDP:
      size_payload = ParseUDPPacket((u_char *)ip, srcport, dstport);
      break;
    case IPPROTO_ICMP:
      break;
    case IPPROTO_IP:
      break;
    case IPPROTO_IGMP:
      break;
    case IPPROTO_PIM:
      break;  
    default:
      break;
  }
  
  update_vlog(sec, calc_log, ip->ip_p, isXIO, isLocal, size_ip_payload);
  
  FILE *fp;
  fp = fopen ("pkt_list.txt", "a+");
  fprintf(fp, "%d:\t%d\tv%d\t%s\t%s\t%d\t%s\t%d\t%d\t%s\t%s\n", 
          pkt_count++, sec, ip_version, (isLocal==1)?"LOC":"EXT", 
          (isXIO==0)?"XOS":(isXIO==1)?"INC":"OUT", size_ip_payload, 
          (ip->ip_p==IPPROTO_TCP)?"TCP":(ip->ip_p==IPPROTO_UDP)?"UDP":"OTH", 
          srcport, dstport, srcPkt, dstPkt);
  fclose(fp);
}

void reset_vlog(int location)
{ 
  memset(&vlog_pkt[location], 0, sizeof(vLog));
  memset(&vlog_bw[location], 0, sizeof(vLog));
}

u_int ParseUDPPacket (const u_char *packet, u_int &src_port, u_int &dst_port)
{
  const struct sniff_ip *ip;              /* The IP header */
  const struct sniff_udp *udp;            /* The UDP header */
  const u_char *payload;                  /* Packet payload */

  u_int size_payload =0;
    
  ip = (struct sniff_ip*)(packet);
  udp = (struct sniff_udp*)(packet + IPHDRSIZE);
  src_port = ntohs(udp->uh_sport);
  dst_port = ntohs(udp->uh_dport);
  
  /* define/compute tcp payload (segment) offset */
  payload = (u_char *)(packet + IPHDRSIZE + UDPHDRSIZE);
  
  /* compute tcp payload (segment) size */
  size_payload = ntohs(ip->ip_len) - (IPHDRSIZE + UDPHDRSIZE);
  
  return size_payload;
}

u_int ParseTCPPacket(const u_char *packet, u_int &src_port, u_int &dst_port)
{
  const struct sniff_ip *ip;              /* The IP header */
  const struct sniff_tcp *tcp;            /* The TCP header */
  const u_char *payload;                  /* Packet payload */
  
  u_int size_tcp=0;
  u_int size_payload=0;
  
  ip = (struct sniff_ip*)(packet);
  
  /* define/compute tcp header offset */
  tcp = (struct sniff_tcp*)(packet + IPHDRSIZE);
  size_tcp = TH_OFF(tcp)*4;
  if (size_tcp < TCPHDRSIZE) {
    fprintf (stderr,"* Invalid TCP header length: %u bytes\n", size_tcp);
    return 0;
  }
  src_port = ntohs(tcp->th_sport);
  dst_port = ntohs(tcp->th_dport);
  
  /* define/compute tcp payload (segment) offset */
  payload = (u_char *)(packet + IPHDRSIZE + TCPHDRSIZE);
  
  /* compute tcp payload (segment) size */
  size_payload = ntohs(ip->ip_len) - (IPHDRSIZE + size_tcp);
  
  #if _DEBUG
  printf("id: %d\t", htons(ip->ip_id));
  printf("seq: %u\t", ntohl(tcp->th_seq));  
  printf("ack: %u\t", ntohl(tcp->th_ack));  
  printf("sum: %x\n", (ip->ip_sum));
  if (size_payload > 0) {
    printf("\tPayload (%d bytes)", size_payload);
    print_payload(payload, size_payload);
  }      
  showPacketDetails(ip, tcp); 
  #endif
  
  return size_payload;
}

void showPacketDetails(const struct sniff_ip *iph, const struct sniff_tcp *tcph)
{
  /*should cleanup: 0 to _DEBUG*/
#if _DEBUG
  printf(" vhl=%x\n",iph->ip_vhl);       
  printf(" tos=%x\n",iph->ip_tos);       
  printf(" len=%d IP+TCP hdr len=%ld\n",ntohs(iph->ip_len), 
         IPHDRSIZE + TCPHDRSIZE);
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
        
      /* we could enable IPv6.*/
      case AF_INET6:
        if (a->addr)
          printf("\tIPv6: %s\t", iptos(a->addr, AF_INET6, ip46str, sizeof(ip46str)));
        break;
        
      default:
        /*printf("\tAddress Family Name: Unknown\n");*/
        break;
    }
  }
  printf("\n");  
}

/* TIMER */
void *timer_event_initialize(void *threadid)
{
  /* EVENT: */
 	struct event timeout;
	struct timeval tv;
  
	/* EVENT: Initalize the event library */
	base = event_base_new();
 
  /* EVENT: Initalize one event */
#if EV_PERSIST_FLAG  /*EV_PERSIST*/
	event_assign(&timeout, base, -1, EV_PERSIST, timeout_callback, (void*) &timeout); 
#else
  event_assign(&timeout, base, -1, 0, timeout_callback, (void*) &timeout); 
#endif

  
  evutil_timerclear(&tv);
	tv.tv_sec = TIMEOUT;
	event_add(&timeout, &tv);
	evutil_gettimeofday(&lasttime, NULL);
 	event_base_dispatch(base);
  
	return (0);
}

/*MAIN()*/
int main(int argc, char **argv)
{
  /* thread for the 1s TIMER */
  int rc;
  pthread_t threads;
  /* PCAP: */
  /* capture device name */
  char *dev = NULL;
  
  /* error buffer */
  char errbuf[PCAP_ERRBUF_SIZE];  
  
  /* Example expressions:
   *
   * Expression         Description
   * ----------         -----------
   * ip                 Capture all IP packets.
   * tcp                Capture only TCP packets.
   * tcp port 80        Capture only TCP packets with a port equal to 80.
   * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
   ****************************************************************************
   * (tcp[13] == 0x10) or (tcp[13] == 0x18) for ACK and ACK+PUSH
   * (tcp[13] == 0x10) for only ACK packets
   */
  
  /* default filter expression is "IP" */
  char filter_exp[] = "ip";
  pcap_if_t *alldevices, *device, *chosendevice;
  pcap_addr_t *a;
  int i =0, j=0;
  int choice=-1;
  
  calc_log = 0;
  store_log = -1;
  reset_vlog(calc_log);
  
  /* Ctrl+C, should this be in its own thread? */
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

  /* check for capture filter expression on command-line */
  if (argc == 3) {
    strncpy(filter_exp,argv[2], strlen(argv[2]));
  }
  
  /* find all interfaces, en0, en1, eth0, p2p0, lo, ..., etc. */
  if (pcap_findalldevs(&alldevices, errbuf) == -1) {
    fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);
  }
  
  if (argc == 1 ){
    /* Print the list of interfaces */
    for(device=alldevices; device; device=device->next) {
      if(device->flags & PCAP_IF_LOOPBACK)
        break;
      printf("%d. %s", ++i, device->name);
      if (device->description)
        printf("(%s)\t", device->description);
      else
        fprintf(stderr,"(No description available)\t");
      print_interface(device);
    }
    if(i==0) {
      fprintf (stderr,"\nNo interfaces found! Make sure libpcap is installed.\n");
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
  printf("IP ADDR: %s\tMASK: %s\t", strHostIP, cmask);  
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
  
  /* PCAP: open capture device */
  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf); 
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }
  
  /* PCAP: make sure we're capturing on an Ethernet device [2] */
  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "%s is not an Ethernet\n", dev);
    exit(EXIT_FAILURE);
  }
  
  /* PCAP: compile the filter expression */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  
  /* PCAP: apply the compiled filter */
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  
  /*printf("In main(): creating timer thread\n");*/
  rc = pthread_create(&threads, NULL, timer_event_initialize, NULL);
  if (rc){
    fprintf(stderr, "ERROR: in pthread_create(). Error No: %d\n", rc);
    exit(-1);
  }
  
  /*  
   printf("No.\ttime in sec\tIPv\tLoc/Ext\tO/I/X\tProto\tSPort\t->\tDPort\tSize\t \
   Src. IP Addr\t->\tDest. IP Addr\n");
  printf("No.\ttime in sec\tIPv\tLoc/Ext\tO/I/X\tSize\tProto\tSPort\tDPort \
         \tSrc. IP Addr\tDest. IP Addr\n");
  */
  
  /* PCAP: now we can set our callback function */
  pcap_loop(handle, CAPTURE_COUNT, got_packet, NULL);
  printf("\nCapture complete.\n");
  
  /*kill thread*/
  pthread_exit(NULL);
  return 0;
}

