#! /bin/sh
# NOTE: Use -v at the end of sending side to see the file caps, which you can later use at the decoder side.
# IM2-YT-2_128k_20.mp4 has sprop-parameter-sets=(string)\"Z2QAHqw05gLQ9v/ACAAGxAAAAwAEAAADAKA8WLZo\\,aOl4RLIs\"
# ducati.ffx.na.15.128.mp4 has sprop-parameter-sets=(string)\"Z0LADZpzAoP2AiAAAAMAIAAAAwPR4oVN\\,aM48gA\\=\\=\"
gst-launch-0.10 udpsrc port=$1 caps='application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264, sprop-parameter-sets=(string)\"Z2QAHqw05gLQ9v/ACAAGxAAAAwAEAAADAKA8WLZo\\,aOl4RLIs\", payload=(int)96, ssrc=(guint)2863315899, clock-base=(guint)0, seqnum-base=(guint)0' ! .recv_rtp_sink_0 gstrtpbin ! rtph264depay ! ffdec_h264 ! ffmpegcolorspace ! videoscale ! autovideosink --gst-debug=*:1 &
gst-launch-0.10 udpsrc port=$2 caps='application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264, sprop-parameter-sets=(string)\"Z0LADZpzAoP2AiAAAAMAIAAAAwPR4oVN\\,aM48gA\\=\\=\", payload=(int)97, ssrc=(guint)3435978205, clock-base=(guint)0, seqnum-base=(guint)0' ! .recv_rtp_sink_0 gstrtpbin ! rtph264depay ! ffdec_h264 ! ffmpegcolorspace ! videoscale ! autovideosink --gst-debug=*:1 &

