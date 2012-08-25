//
//  rtp.h
//  
//
//  Created by Varun Singh on 20/8/2012.
//  Copyright (c) 2012 Comnet. All rights reserved.
//

#ifndef _rtp_h
#define _rtp_h

#include "conmon.h"

#define RTP_HDR_SZ 12
#define MAXRTPSIZE  (65536 - IPHDRSIZE - UDPHDRSIZE)
#define MAXRTPPAYLOADLEN  (65536 - IPHDRSIZE - UDPHDRSIZE - RTP_HDR_SZ)
#define SSRC  0x12345678               
#define RTP_TR_TIMESTAMP_MULT 1000   


/*
 https://tools.ietf.org/html/rfc3550#section-5.1
 
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |V=2|P|X|  CC   |M|     PT      |       sequence number         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                           timestamp                           |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           synchronization source (SSRC) identifier            |
 +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 |            contributing source (CSRC) identifiers             |
 |                             ....                              |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct
{
  u_char vpxcc;          
  u_char mpt;         
  u_short seq;        
  u_int timestamp;  
  u_int ssrc; 
} sniff_rtp_t;

#define RTP_V(p)    (((p)->vpxcc) >> 6)
#define RTP_P(p)   ((((p)->vpxcc) & 0x2f) >> 5)
#define RTP_X(p)   ((((p)->vpxcc) & 0x1f) >> 4)
#define RTP_CC(p)   (((p)->vpxcc) & 0x0f)
#define RTP_M(p)   ((((p)->mpt)   & 0x80) >> 7)
#define RTP_PT(p)   (((p)->mpt)   & 0x7f)

/*
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |V=2|P|    RC   |     PT=20x    |             length            |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

typedef enum {
  RTCP_SR     = 200,
  RTCP_RR,   
  RTCP_SDES, 
  RTCP_BYE,  
  RTCP_APP   
}e_rtcp_type;

typedef struct
{
  u_short vprpt;     
  u_short length;        
} sniff_rtcp_t;

#endif
