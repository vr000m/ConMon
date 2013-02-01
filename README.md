### Synopsis 
ConMon is a command line utility that measures the traffic to and from an
endpoint. ConMon passively monitors the IP packets and classifies them to 
measure the bit rate for each of the classifiers. 

It is based on the [Sniffer example](http://www.tcpdump.org/sniffex.c) in
`libpcap (tcpdump)`.

### Current classifiers:
* Total, TCP, UDP, local, external [done]
* Each is further classified as combined, inbound, outbound and background
  [done]
* Additionally: can detect RTP/UDP (if no hint is available on which port
  the RTP is received then there are still some false-positives).

#### Extras (yet to be implemented)
* IPv4 and IPv6
* STUN packets
* HTTP(S): port 80 and 443
* LEDBAT: e.g., Bittorrent

### Compiling ConMon
The project comes with a basic Makefile (`Makefile.backup` or `Makefile.ubuntu`) 
and depends on the following libraries:
* [libpcap](http://www.tcpdump.org/release/libpcap-1.2.1.tar.gz)
* [libevent](https://github.com/downloads/libevent/libevent/libevent-2.0.19-stable.tar.gz)
* [pthreads]

ConMon has two threads:
1. Main Thread: captures packets based on `filter expression` and store packets to "Packet Logs".
2. Event Thread: times out every `1s` and stores the {num_pkts, bytes} per classifier to the "Time Logs".

Alternatively, generate the Makefile using autotools, for which execute 
the following steps:
```
$ ./autogen.sh
$ ./configure
$ make
```

### Running ConMon
ConMon requires root privileges to capture packets. Until [ConMon
v0.3.2](https://github.com/vr000m/conmon/tree/v0.3.2) the captured packets
are stored locally (in files at `logs/`) and therefore the "user" has full
control of their data. If we implement a backend service to capture the
logs, we will then add a method to obfuscate the user's IP addresses to
preserve their privacy. 

ConMon creates two files in `logs/` folder
* Packet Logs: `pkt_list_$filter_$interface.txt` (e.g.: pkt_list_ip_en1.txt)
* Time Logs: `time_list_$filter_$interface.txt` (e.g.: time_list_ip_en1.txt)

### ConMon Usage
* ConMon has two command line parameters: interface and filter.

```
$./conmon --help
Usage: sudo ./conmon [interface] [filter] [experimental flag]
Options:
    interface     Listen on <interface> for packets.
    filter        PCAP Filter to apply on packets.

    [only one experimental flag allowed at the end]
    --rtp         enable RTP detection
    --http        enable HTTP detection
```


* Running without any parameters sets default PCAP filter="ip" and 
shows a menu to choose interfaces. For example:

```
$ sudo ./conmon

1. en0  (No Desc.)      IPv6: fe80::*%en0     IPv4: xx.xx.xx.xx   
2. fw0  (No Desc.)      
3. en1  (No Desc.)      IPv6: fe80::*%en1     IPv4: yy.yy.yy.yy    
4. p2p0 (No Desc.)      
Enter the interface number (1-4):
```

* If you do not want the choose the network interface every time then pass
  it as a command-line argument. You can use `ifconfig` to lookup the
  interface names.

For example:

```
$ sudo ./conmon en1
IP ADDR: xx.xx.xx.xx  MASK: 255.255.240.0   Device: en1 Filter expression: ip
```

* You may use an alternate [PCAP filter](http://wiki.wireshark.org/CaptureFilters). 
For example:

```
$ sudo ./conmon en1 tcp
IP ADDR: xx.xx.xx.xx  MASK: 255.255.240.0  Device: en1  Filter expression: tcp
```

* If you know which ports the RTP is received on/sent from, for example:

```
$ sudo ./conmon eth0 "udp port 40500" --rtp
IP ADDR: xx.xx.xx.xx MASK: 255.255.255.0 Device: eth0    Filter expression (14): udp port 40500
filename: logs/pkt_list_udp port 40500_eth0.txt created
filename: logs/time_list_udp port 40500_eth0.txt created
filename: rtp/rtp_1346675553_97_ccccdddd.txt created
filename: rtp/rtp_1346675553_96_aaaabbbb.txt created

[Once complete, to plot run]
$ cd plots/
$ ./plots.sh "time_list_udp port 40500_eth0"
[for generating RTP specific plots do]
$ cd rtp/
$ ./rtp_bitrate.sh rtp_1346675553_97_ccccdddd
$ ./rtp_bitrate.sh rtp_1346675553_96_aaaabbbb
[Note: that .txt extensions are intentionally skipped!
```
More RTP related instructions are available at
[rtp/README.md](https://github.com/vr000m/ConMon/blob/master/rtp/README.md)

**NOTE**: as of version [v0.3.2](https://github.com/vr000m/conmon/tree/v0.3.2) 
-rtp is replaced by --rtp

### Output
For instructions on plotting read
[plots/README.md](https://github.com/vr000m/ConMon/blob/master/plots/README.md)

#### Example Results
Read more about sample results in the [Wiki](https://github.com/vr000m/ConMon/wiki/Example-Results)

### ConMon TODO
* create above classifiers [done]
* create vectors/map of {num_pkts, bytes} for each of the above classifiers
  [done]
* create plots to show changes in bit rate for the above classifiers [done]
* If data is uploaded then hash the source/destination IP addresses. [not
  needed currently, as data is stored locally!]
* Test RTP, RTCP, RTCP-mux, A/V-mux, etc.
* Use some heuristics to reduce false-positives in RTP detection.
* use [DBUS](http://www.freedesktop.org/wiki/Software/dbus) so that
  applications can query the bit rate for a specific classifier
* convert or allow ConMon to run as a daemon
* There may be bugs related to IPv6 in some places. ConMon is a fork from
  my earlier project [Snapper](https://github.com/vr000m/Snapper)


### Contribute/Extend
If you want to parse a packet look at got_packet() there is a switch case
that parses the protocol field. You can add your own code or function to
parse the associated packet (see `ParseUDPPacket()`/`ParseTCPPacket()` in
`conmon.c`).
