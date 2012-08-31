### RTP media stream detection and measuring throughput

`isRTP (const u_char *packet, ...)` in `conmon.cc` detects RTP and
the RTP and RTCP headers are defined in `rtp.h`. Currently, ConMon is only
tested for RTP but should also work for RTCP. However, it should be noted
that the current implementation produces many false positives because ConMon
does not implement any RTP header validation mechanisms. Upon detection 
each RTP packet is appended to the appropriate RTP logs file. The log 
files are stored in the `rtp/` folder and are of the form 
`rtp_*_$pt_$ssrc.txt`

To generate graphs per RTP media stream execute the `rtp_bitrate.sh` with
the appropriate RTP log file as a command line parameter (NOTE: extension
is skipped from the filename). For example:
```
$ source rtp_bitrate.sh rtp_1345972446_96_aaaabbbb
```

The resulting file is tab-separated and contains the following columns:
```
unix_time payload_type SSRC seqno timestamp marker size_payload
```