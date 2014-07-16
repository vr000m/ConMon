```
           +----------------+
           | 127 < B < 192 -+--> forward to RTP
           |                |
           |                |   +------------------+
           |                |   | DTLS processing  |
           |                |   |   (CT Field)     |
packet --> |  19 < B < 64  -+-->+ appl. protocol  -+--> SCTP
           |                |   |                  |
           |                |   | other protocols -+--> DTLS
           |                |   |                  |
           |                |   +------------------+
           |                |
           |       B < 2   -+--> forward to STUN/ICE ---> if TURN, parse recursively.
           +----------------+
```

There was a bug in `b<2`, this has been updated: https://tools.ietf.org/html/draft-petithuguenin-avtcore-rfc5764-mux-fixes-00

we should check our code...

```
  The process for demultiplexing a packet is as follows.  The receiver
   looks at the first byte of the packet.  If the value of this byte is
   in between 0 and 19 (inclusive), then the packet is STUN.  If the
   value is in between 128 and 191 (inclusive), then the packet is RTP
   (or RTCP, if both RTCP and RTP are being multiplexed over the same
   destination port).  If the value is between 20 and 63 (inclusive),
   the packet is DTLS.  If the value is between 64 and 127 (inclusive),
   the packet is TURN Channel.  This process is summarized in Figure 3.

                    +----------------+
                    | 127 < B < 192 -+--> forward to RTP
                    |                |
                    |  63 < B < 128 -+--> forward to TURN Channel
        packet -->  |                |
                    |  19 < B < 64  -+--> forward to DTLS
                    |                |
                    |       B < 20  -+--> forward to STUN
                    +----------------+

     Figure 3: The DTLS-SRTP receiver's packet demultiplexing algorithm.
          Here the field B denotes the leading byte of the packet.
```
