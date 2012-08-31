### Output Logs

ConMon creates two files in tab-separated format
* Packet Logs: `pkt_list_$filter_$interface.txt` (e.g.: pkt_list_ip_en1.txt)
```
pkt_count time IPv4/6 size_ip_payload LOC/EXT XOS/INC/OUT/HOST
TCP/UDP/RTP/OTH srcport dstport srcIPaddr dstIPaddr
```
* Time Logs: `time_list_$filter_$interface.txt` (e.g.: time_list_ip_en1.txt)
```
time time_monitor elapsed ALL(pkt_count, bw) TCP(pkt_count, bw)
UDP(pkt_count, bw) LOCAL(pkt_count, bw) EXTERNAL(pkt_count, bw)
```

Each FUNC(pkt_count, bw) creates two columns for pkt_count and throughput
for each sub-category: Total, Incoming, Outgoing and Cross-traffic

We use [Gnuplot](http://gnuplot.sourceforge.net/demo_cvs/) to generate the
[PDF plots](http://www.gnuplot.info/docs_4.6/gnuplot.pdf).
`../plots/plots.sh or plot-loopback.sh` takes as command line argument the
filename of the "time logs" (without the file extension).

