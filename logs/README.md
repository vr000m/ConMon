### Output Logs

ConMon creates two files in tab-separated format
* Packet Logs: `pkt_list_$filter_$interface.txt` (e.g.: pkt_list_ip_en1.txt)

The columns are:
1. pkt_count 
2. time 
3. IPv4/6 
4. size_ip_payload 
5. LOC/EXT 
6. XOS/INC/OUT/HOST
7. TCP/UDP/RTP/OTH 
8. srcport 
9. dstport 
10. srcIPaddr 
11. dstIPaddr

* Time Logs: `time_list_$filter_$interface.txt` (e.g.: time_list_ip_en1.txt)

The columns are:
1. time_current 
2. time_at_monitor 
3. elapsed 
4-11. ALL(pkt_count, bw) 
12-19. TCP(pkt_count, bw)
20-27. UDP(pkt_count, bw) 
28-35. LOCAL(pkt_count, bw) 
36-43. EXTERNAL(pkt_count, bw)


Each FUNC(pkt_count, bw) creates two columns for pkt_count and throughput
and further 2-columns for each sub-category: Total, Incoming, Outgoing and Cross-traffic

We use [Gnuplot](http://gnuplot.sourceforge.net/demo_cvs/) to generate the
[PDF plots](http://www.gnuplot.info/docs_4.6/gnuplot.pdf).
`../plots/plots.sh or plot-loopback.sh` takes as command line argument the
filename of the "time logs" (without the file extension).

