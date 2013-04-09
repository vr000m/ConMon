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

void cleanup()
{
  /* cleanup */
  pcap_freecode(&filter_prog);
  
  if(handle!=NULL)
    pcap_close(handle);
  
  /*freeing allocated memory */
  if(filter_exp!=NULL)
    free(filter_exp);
  if(filestore_pkt!=NULL)
    free(filestore_pkt);
  if(filestore_tsc!=NULL)
    free(filestore_tsc);  
}

void signal_handler(int signal)
{
  cleanup();
  
#if EV_PERSIST_FLAG
  /*BUG: remove event*/
#endif
  exit(0);
}

void print_app_usage(void)
{
  
  printf("Usage: sudo ./%s [interface] [filter] [experimental flag]\n", APP_NAME);
  printf("\n");
  printf("Options:\n");
  printf("    interface     Listen on <interface> for packets.\n");
  printf("    filter        PCAP Filter to apply on packets.\n");
  printf("\n");
  printf("    [only one experimental flag allowed at the end]\n");
  printf("    --rtp         enable RTP detection\n");
  printf("    --http        enable HTTP detection\n");
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

double gettime()
{
  int errno;
  struct timeval t_now;
  
  
	errno = gettimeofday(&t_now, NULL);
  
	return (t_now.tv_sec+t_now.tv_usec/1000000.0);
}

void reset_vlog(int location)
{ 
  memset(&vlog_pkt[location], 0, sizeof(vLog));
  memset(&vlog_bw[location], 0, sizeof(vLog));
}

u_long createHash(u_long ipSrc, u_int srcport, u_long ipDest, u_int dstport)
{
  //probably use some openssl API here?
  return 1;
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
  
  if ((strcmp(sIp, strHostIP)==0) && (strcmp(dIp, strHostIP)==0)) 
  {
    x= XIO_HOST;
  }
  else if (strcmp(sIp, strHostIP)==0) {
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
  double elapsed;
  
#if !EV_PERSIST_FLAG
  struct event *timeout = arg; 
  struct timeval tv;
#endif
  
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
    if(calc_log == LOG_SIZE)
      calc_log = 0;
    if(store_log == LOG_SIZE)
      store_log = 0;
    
    reset_vlog(calc_log);
#if FILE_STORE
    FILE *f2p;
    f2p = fopen (filestore_tsc, "a+");

    if(f2p==NULL){
  	  perror("Unable to open filestore_tsc \n");
  	  exit(1);
    }
    
    if(using_loopback ==1) {
      fprintf(f2p, "%d\t%d\t%f\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
              vlog_pkt[store_log].time,
              (u_int)gettime(),
              elapsed,
              vlog_pkt[store_log].host,
              vlog_bw[store_log].host,
              vlog_pkt[store_log].host_tcp,
              vlog_bw[store_log].host_tcp,
              vlog_pkt[store_log].host_udp,
              vlog_bw[store_log].host_udp,
              vlog_pkt[store_log].host_oth,
              vlog_bw[store_log].host_oth);
    }
    else {
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
    }

    fclose(f2p);
#endif
    /*  printf("timeout(): %d (%f) log c: %d s: %d\n",(int)(newtime.tv_sec+(newtime.tv_usec/1.0e6)), elapsed, calc_log, store_log);*/
  }
  
#if !EV_PERSIST_FLAG
  evutil_timerclear(&tv);
  tv.tv_sec = TIMEOUT;
  event_add(timeout, &tv);
#endif
}

/* TODO: maybe this should be inside a MUTEX*/
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
    case XIO_HOST:
      /*if we are not doing loopback then we can ignore these packets?*/
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
        case XIO_HOST:
      	  /*if we are not doing loopback then we can ignore these packets?*/
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
        case XIO_HOST:
      	  /*if we are not doing loopback then we can ignore these packets?*/
      	  break;
      }
      break;
  }
  /*printf("packets(): %d log c: %d s: %d\n", sec, calc_log, store_log);*/
}

/* TODO: if we put update_vlog() in a mutex then maybe this should also be inside a MUTEX*/
void update_vlog_lo(u_int sec, int location, u_char proto, u_int isLocal, u_int payload)
{
  vlog_pkt[location].time = sec;
  vlog_bw[location].time = sec;
  
  vlog_pkt[location].host++;
  vlog_bw[location].host += payload;
  
  switch(proto) {
    case IPPROTO_TCP:
      vlog_pkt[location].host_tcp++;
      vlog_bw[location].host_tcp += payload;
      break;
    case IPPROTO_UDP:
      vlog_pkt[location].host_udp++;
      vlog_bw[location].host_udp += payload;
      break;
    default:
      vlog_pkt[location].host_oth++;
      vlog_bw[location].host_oth += payload;
      break;
  }
}

/*
 * dissect packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  const struct sniff_ethernet *ethernet;  /* The ethernet header */
  const struct sniff_ip *ip;              /* The IP header */
  const u_char *payload;                  /* Packet payload */
  
  u_int size_ip;
  int ip_version;
  char srcIPaddr[INET_ADDRSTRLEN];
  char dstIPaddr[INET_ADDRSTRLEN];
  
  xio_flag isXIO;
  
  int isLocal=-1;
  int rtp_flag = 0;
  
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
    fprintf(stderr,"Error: Invalid IP header length: %u bytes\n", size_ip);
    return;
  }
  
  inet_ntop(AF_INET, &(ip->ip_src), srcIPaddr, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip->ip_dst), dstIPaddr, INET_ADDRSTRLEN);
  
  /*
   First "logical AND" both src and destination ipaddress with netmask
   if the IP address are equal then the endpoints communicating locally.
   
   Possible combinations:
   If both src and destination match then local else external.
   In each categoy the comunication can be inbound/outbound/cross traffic
   */
  isXIO = checkInboundOrOutbound(srcIPaddr, dstIPaddr);
  
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
      if (((srcport==80||dstport==80)||(srcport==443||dstport==443)) && allow_http && (size_payload > 0))
      {
        payload = (u_char *)(packet + IPHDRSIZE + TCPHDRSIZE);
        ParseHTTPPacket(payload, size_payload);        
      }
      break;
    case IPPROTO_UDP:
      size_payload = ParseUDPPacket((u_char *)ip, srcport, dstport);
      /* TODO: Check if this is an RTP packet? */
      if(allow_rtp) {
        if(size_payload>RTP_HDR_SZ )//&& isXIO != XIO_CROSS)
        {
          /*
           HASH the srcip, port, destip, port to create a unique filename
           concat with $pt_$ssrc.txt     
           createHash((ip->ip_src).s_addr, srcport, (ip->ip_dst).s_addr, dstport);
           printf("%s\t%d\t%s\t%d\t%d", srcIPaddr, srcport, dstIPaddr, dstport, size_ip_payload);*/

          payload = (u_char *)(packet+ ETHHDRSIZE + IPHDRSIZE + UDPHDRSIZE);
          rtp_flag = isRTP(payload, size_payload);
#if _DEBUG
          if (size_payload > 0 && rtp_flag) {
            printf("Payload (%d bytes)\n", size_payload);
            print_payload(payload, size_payload);
          }
#endif
        }
      }
      break;
    /*
    case IPPROTO_ICMP:
      break;
    case IPPROTO_IP:
      break;
    case IPPROTO_IGMP:
      break;
    case IPPROTO_PIM:
      break;  
    */
    default:
      break;
  }
  if(isXIO==XIO_HOST)
  	update_vlog_lo(sec, calc_log, ip->ip_p, isLocal, size_ip_payload);
  else
  	update_vlog(sec, calc_log, ip->ip_p, isXIO, isLocal, size_ip_payload);
  
#if FILE_STORE
  FILE *fp1;
  fp1 = fopen (filestore_pkt, "a+");

  if(fp1==NULL){
    perror("Unable to open filestore_pkt \n");
    exit(1);
  }
  
  fprintf(fp1, "%d:\t%d\tv%d\t%d\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n", 
          pkt_count++, sec, ip_version, size_ip_payload,
          (isLocal==1)?"LOC":"EXT", 
          (isXIO==XIO_CROSS)?"XOS":(isXIO==XIO_INCOMING)?"INC":(isXIO==XIO_OUTGOING)?"OUT":"HOST",  
          (ip->ip_p==IPPROTO_TCP)?"TCP":(ip->ip_p==IPPROTO_UDP)?(rtp_flag==0)?"UDP":(rtp_flag==1)?"RTP":"RTCP":"OTH", 
          srcport, dstport, srcIPaddr, dstIPaddr);
  
  fclose(fp1);
#endif
}

void ParseHTTPPacket(const u_char *packet, const u_int &size_payload)
{
#if 1//_DEBUG 
  printf("Payload (%d bytes)\n", size_payload);
  print_payload(packet, size_payload);
#endif
}

u_int isRTP (const u_char *packet, const u_int &size_payload)
{
  sniff_rtp_t *pRtp;
  sniff_rtcp_t *pRtcp;
  u_int rtp_ver, marker, pt, seqno, timestamp, ssrc, alt_ver, mpt; 
  u_int detector, rflag;
  u_int rtcp_ver, rtcp_pt, rtcp_len, rtcp_ssrc;

  u_int filelen_rtp=0;
  pRtp = (sniff_rtp_t*) packet;
  pRtcp = (sniff_rtcp_t*) packet;
  char *rtpstore_pkt;
  
  /* Extract header information from RTP */
  alt_ver = (u_int)(pRtp->vpxcc & 0xc0); /*shift right? or value will be 0x80*/
  detector = (u_int)(pRtp->vpxcc);
  mpt = (u_int)(pRtp->mpt);
  rtp_ver =RTP_V(pRtp);
  marker = RTP_M(pRtp);
  pt  =RTP_PT(pRtp);
  seqno=(u_int)ntohs(pRtp->seq);
  timestamp=(u_int)ntohl(pRtp->timestamp);
  ssrc=(u_int)ntohl(pRtp->ssrc);

  /* Extract header information from RTCP */
  rtcp_ver = RTCP_V(pRtcp);
  rtcp_pt = (pRtcp->pt);
  rtcp_len = (u_int)ntohs(pRtcp->length);
  rtcp_ssrc = (u_int)ntohl(pRtcp->ssrc);

  /*
  From http://tools.ietf.org/html/rfc5764#section-5.1.2
                 +----------------+
                 | 127 < B < 192 -+--> forward to RTP
                 |                |
     packet -->  |  19 < B < 64  -+--> forward to DTLS
                 |                |
                 |       B < 2   -+--> forward to STUN
                 +----------------+

  Figure 3: The DTLS-SRTP receiver's packet demultiplexing algorithm.
       Here the field B denotes the leading byte of the packet.
  */

  if (detector<2)
  {
    return 0; /* is STUN packet */
  }
  else if (detector<64 && detector > 19)
  {
    return 0; /* is DTLS packet*/
  }
  else if( detector<192 && detector > 127)
  { 
    if((rtp_ver==2) && ((ssrc > 0x0)||(ssrc < 0xffffffff)))
    {
      /*
       Read: 
       http://tools.ietf.org/html/rfc3550#appendix-A.1
       http://tools.ietf.org/html/rfc3550#section-12

       What other heuristic should I use to validate that the packet is RTP/RTCP
       http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xml
       */
      rflag = 0;
      /* printf("pt %d (mpt=%d) and marker %d\n", pt, mpt, marker); */

      if((pt <= 127) && (pt < 35 || pt > 95))
      {
        /*
        there are some unassigned blocks 
        should we cater for them?
        Yes.
        35-71 Unassigned
        72-76 Reserved for RTCP conflict avoidance
        77-95 Unassigned
        */
        rflag=1; /* is RTP */  

        #if _DEBUG
          printf ("%d (%d)\t", rtp_ver, alt_ver);
          printf ("%d\t", RTP_P(pRtp));
          printf ("%d\t", RTP_X(pRtp));
          printf ("%d\t", RTP_CC(pRtp));
          printf ("%d\t", marker);
          printf ("%d\t", pt);
          printf ("%d\t", seqno);
          /* 
           BUG: something wierd is happening with the RTP timestamps
           it seems to be jumping around? maybe an endian-ness problem?
           */
          printf ("%d\t", timestamp);
          printf ("%x\n", ssrc);
        #endif

        #if FILE_STORE
          //start_time is 10, rtp is 3, pt is 3, ssrc is 8(in hex, 10 in dec) and txt is 3 + 6 special chars(_, /, '\0')
          filelen_rtp=sizeof(RTP_DIR)+sizeof(char)*(10+3+3+8+3+6);
          rtpstore_pkt = (char*) calloc(1, filelen_rtp);
          
          sprintf(rtpstore_pkt, "%s/rtp_%d_%d_%x.txt", RTP_DIR, start_time, pt, ssrc);
          //printf ("filename: %s\n", rtpstore_pkt);
          
          FILE *fp_rtp;
          fp_rtp = fopen (rtpstore_pkt, "a+");  

          if(fp_rtp==NULL){
            free(rtpstore_pkt);
            perror("Unable to open rtpstore_pkt\n");
            exit(1);
          }
          
          fprintf(fp_rtp,"%f\t%d\t%x\t%d\t%d\t%d\t%d\n", gettime(), pt, ssrc, seqno, timestamp, marker, size_payload);
          
          fclose(fp_rtp);
        #endif 

      }
      else if ((rtcp_pt >= 192 && rtcp_pt <= 255 ) || (pt>=72 && pt <=76))
      {
        /*
        72-76 Reserved for RTCP conflict avoidance
        >=192 see IANA URL
        */
        #if _DEBUG
          printf ("%d\t", rtcp_ver);
          printf ("%d\t", RTCP_P(pRtcp));
          printf ("%d\t", RTCP_RC(pRtcp));
          printf ("%d\t", rtcp_pt);
          printf ("%d\t", rtcp_len);
          printf ("%x\n", rtcp_ssrc);
        #endif
        #if 0
        //FILE_STORE
          //start_time is 10, rtcp is 4, ssrc is 8(in hex, 10 in dec) and txt is 3 + 8 special chars(_, /, '\0')
          filelen_rtp=sizeof(RTP_DIR)+sizeof(char)*(10+4+8+3+5);
          rtpstore_pkt = (char*) calloc(1, filelen_rtp);
          
          sprintf(rtpstore_pkt, "%s/rtcp_%d_%x.txt", RTP_DIR, start_time, ssrc);
          //printf ("filename: %s\n", rtpstore_pkt);
          
          FILE *fp_rtp;
          fp_rtp = fopen (rtpstore_pkt, "a+");  

          if(fp_rtp==NULL){
            free(rtpstore_pkt);
            perror("Unable to open rtpstore_pkt\n");
            exit(1);
          }
          
          fprintf(fp_rtp,"%f\t%x\t%d\t%d\t%d\n", gettime(), rtcp_ssrc, rtcp_pt, rtcp_len, size_payload);
          
          fclose(fp_rtp);
        #endif 
        rflag=2; /* is RTCP */
      }
      else
        return 0; /* not RTP/RTCP*/

      return rflag;
    }
    else
      return 0; /* not RTP/RTCP*/
  }
  return 0; /* we don't know what this is */
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
  
  size_payload = ntohs(ip->ip_len) - (IPHDRSIZE + UDPHDRSIZE);
  
  payload = (u_char *)(packet + IPHDRSIZE + UDPHDRSIZE);
#if _DEBUG
  /* define/compute udp payload (segment) offset */
  
  if (size_payload > 0) {
    printf("Payload (%d bytes)\n", size_payload);
    print_payload(payload, size_payload);
  }    
#endif
  
  /* compute udp payload (segment) size */
  
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
    fprintf (stderr,"Error: Invalid TCP header length: %u bytes\n", size_tcp);
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
    printf("Payload (%d bytes)\n", size_payload);
    print_payload(payload, size_payload);
  }      
  showPacketDetails(ip, tcp); 
#endif
  
  return size_payload;
}

void showPacketDetails(const struct sniff_ip *iph, const struct sniff_tcp *tcph)
{
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
          printf("IPv4: %s\t", iptos(a->addr, AF_INET, ip46str, sizeof(ip46str)));
        break;
        
        /* we could enable IPv6.*/
      case AF_INET6:
        if (a->addr)
          printf("IPv6: %s\t", iptos(a->addr, AF_INET6, ip46str, sizeof(ip46str)));
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
	int flags=0;
  
	/* EVENT: Initalize the event library */
	base = event_base_new();
  
  /* EVENT: Initalize one event */
#if EV_PERSIST_FLAG  /*EV_PERSIST*/
	flags=EV_PERSIST;
#endif
  
  event_assign(&timeout, base, -1, flags, timeout_callback, (void*) &timeout); 
  
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
  
  pcap_if_t *alldevices, *device, *chosendevice;
  pcap_addr_t *a;
  int i =0, j=0;
  int choice=-1;
  u_int filelen1=0, filelen2=0, cap_filter_len=0;
  u_int args=argc;
  
  /* setting global variables */
  pkt_count = 1;
  calc_log = 0;
  store_log = -1;
  using_loopback=0;
  allow_rtp=0;
  
  start_time=(u_int)gettime();
  
  /* resetting the first data buffer */
  reset_vlog(calc_log);
  
  /* Ctrl+C, should this be in its own thread? */
  signal ( SIGINT, signal_handler);
  
  print_app_banner();
  
  /* HACK/BUG: always put --rtp/-http at the end of the command not earlier */
  for (i=0; i<argc; i++)
  {
    if (strncmp(argv[i],"--rtp", strlen("--rtp"))==0){
      allow_rtp=1;
      args--;
    }
    if (strncmp(argv[i],"--http", strlen("--http"))==0){
      allow_http=1;
      args--;
    }
    if (strncmp(argv[i],"-h", strlen("-h"))==0){
      fprintf(stderr, "Showing help for ConMon\n\n");
      print_app_usage();
      exit(EXIT_FAILURE);
    }
  }

  /*reseting the values*/
  i=0, j=0;

  
  if (args > 3 ) {
    fprintf(stderr, "Error: unrecognized command-line options\n\n");
    print_app_usage();
    exit(EXIT_FAILURE);
  }
  
  /* check for capture device name on command-line */
  if (args >= 2) {
    dev = argv[1];
  }
  
  /* check for capture filter expression on command-line */
  if (args >= 3) {
    cap_filter_len=strlen(argv[2]);
    filter_exp = (char*) calloc(1, cap_filter_len);
    strncpy(filter_exp,argv[2], cap_filter_len);
  }
  else {
    cap_filter_len=strlen("ip");
    filter_exp = (char*) calloc(1, cap_filter_len);
    strncpy(filter_exp,"ip", cap_filter_len);	    
  }
    
  /* find all interfaces, en0, en1, eth0, p2p0, lo, ..., etc. */
  if (pcap_findalldevs(&alldevices, errbuf) == -1) {
    fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);
  }
  
  if (args == 1 ){
    /* Print the list of interfaces */
    for(device=alldevices; device; device=device->next) {
#if BLOCK_LOOPBACK
      //should we show LOOPBACK as an option or not.
      if(device->flags & PCAP_IF_LOOPBACK)
        break;
#endif
      printf("%d. %s\t", ++i, device->name);
      if (device->description)
        printf("(%s)\t", device->description);
      else
        printf("(No Desc.)\t");
      print_interface(device);
    }
    if(i==0) {
      fprintf (stderr,"Error: No interfaces found! Make sure libpcap is installed.\n");
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
  if(chosendevice->flags & PCAP_IF_LOOPBACK)
    using_loopback=1;
  
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
    fprintf(stderr, "Error: couldn't find default device: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }
  
  /* get network number and mask associated with capture device*/
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Error: couldn't get netmask for device %s: %s\n",
            dev, errbuf);
    net = 0;
    mask = 0;
    exit(EXIT_FAILURE);
  }
  
  /* print capture info */
  printf("Device: %s\t", dev);
  
  /*printf("Number of packets: %d\n", CAPTURE_COUNT);*/
  printf("Filter expression (%d): %s\n", cap_filter_len, filter_exp);
  
  
  /*Setting up files to store data in */
  filelen1=sizeof(DIR)+sizeof(PKT_LIST)+cap_filter_len+sizeof(dev)+sizeof(char)*7;//7 for special chars+ txt
  filestore_pkt = (char*) calloc(1, filelen1);
  sprintf(filestore_pkt, "%s/%s_%s_%s.txt", DIR, PKT_LIST, filter_exp, dev);
  printf ("filename: %s \n", filestore_pkt);
  
  filelen2=sizeof(DIR)+sizeof(TIME_LIST)+cap_filter_len+sizeof(dev)+sizeof(char)*7;//7 for special chars+ txt
  filestore_tsc = (char*) calloc(1, filelen2);
  sprintf(filestore_tsc, "%s/%s_%s_%s.txt", DIR, TIME_LIST, filter_exp, dev);
  printf ("filename: %s \n", filestore_tsc);
  
  /* PCAP: open capture device */
  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf); 
  if (handle == NULL) {
    fprintf(stderr, "Error: couldn't open device %s: %s\n", dev, errbuf);
    cleanup();
    exit(EXIT_FAILURE);
  }
  
  /* PCAP: make sure we're capturing on an Ethernet device [2] */
  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "Error: %s is not an Ethernet\n", dev);
    exit(EXIT_FAILURE);
  }
  
  /* PCAP: compile the filter expression */
  if (pcap_compile(handle, &filter_prog, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Error: couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
    cleanup();
    exit(EXIT_FAILURE);
  }
  
  /* PCAP: apply the compiled filter */
  if (pcap_setfilter(handle, &filter_prog) == -1) {
    fprintf(stderr, "Error: couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  
  /*printf("In main(): creating timer thread\n");*/
  rc = pthread_create(&threads, NULL, timer_event_initialize, NULL);
  if (rc){
    fprintf(stderr, "Error: in pthread_create(). Error No: %d\n", rc);
    cleanup();
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

