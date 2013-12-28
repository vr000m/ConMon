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
