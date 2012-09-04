### RTP media stream detection and measuring throughput

`isRTP (const u_char *packet, ...)` in `conmon.cc` detects RTP and
the RTP and RTCP headers are defined in `rtp.h`. Currently, ConMon is only
tested for RTP but should also work for RTCP. However, it should be noted
that the current implementation produces many false positives because ConMon
does not implement any RTP header validation mechanisms. Upon detection 
each RTP packet is appended to the appropriate RTP logs file. The log 
files are stored in the `rtp/` folder and are of the form 
`rtp_*_$pt_$ssrc.txt`


The RTP log file is tab-separated and contains the following columns:
> 1. unix_time 
> 2. payload_type 
> 3. SSRC 
> 4. seqno 
> 5. timestamp 
> 6. marker bit
> 7. size_payload

To generate graphs per RTP media stream execute the `rtp_bitrate.sh` with
the appropriate RTP log file as a command line parameter (NOTE: extension
is skipped from the filename). For example:
```
$ source rtp_bitrate.sh rtp_1345972446_96_aaaabbbb
```

### Example scripts for sending and receiving RTP (Gstreamer)

* `video_streamer.sh` streams two `.mp4` files. The command-line is:
  `./video_streamer.sh $ip_addr $port1 $port2`
* `video_receiver.sh` decodes the two media streams. command-line is:
  `./video_receiver.sh $port1 $port2`
* Also note that the decoder requires the `sprop-parameter-sets` to
  playback the files properly. 
  Example:

>  /GstPipeline:pipeline0/GstRtpH264Pay:rtph264pay0.GstPad:src: 
>  caps = application/x-rtp, media=(string)video, clock-rate=(int)90000,
>  encoding-name=(string)H264,
>  sprop-parameter-sets=(string)\"Z2QAHqw05gLQ9v/ACAAGxAAAAwAEAAADAKA8WLZo\\,aOl4RLIs\",
>  payload=(int)96, ssrc=(guint)2863315899, clock-base=(guint)0,
>  seqnum-base=(guint)0

