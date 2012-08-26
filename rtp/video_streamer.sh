#! /bin/sh
gst-launch filesrc location=IM2-YT-2_128k_20.mp4 ! qtdemux ! rtph264pay seqnum-offset=0 timestamp-offset=0 ssrc=0xaaaabbbb payload=96 mtu=1450 perfect-rtptime=true ! udpsink clients=$1:$2 &
gst-launch filesrc location=ducati.ffx.na.15.128.mp4 ! qtdemux ! rtph264pay seqnum-offset=0 timestamp-offset=0 ssrc=0xccccdddd payload=97 mtu=1450 perfect-rtptime=true ! udpsink clients=$1:$2 & &

