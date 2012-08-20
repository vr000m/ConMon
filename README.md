### Synopsis 
ConMon is a command line utility that measures the traffic to and from an endpoint.
It is based on the `Sniffer` example in `libpcap (tcpdump)`.

### Current classifiers:
* Total, TCP, UDP, local, external [done] 
* Each is further classified as combined, inbound, outbound and background [done]

#### Extras (yet to be implemented)
* IPv4 and IPv6?
* RTP (for RTCWEB, MPRTP, RTSP, etc.)?
* port 80 and 443?

### Compiling ConMon
The project comes with a basic Makefile and depends on the following libraries:
* [libpcap](http://www.tcpdump.org/release/libpcap-1.2.1.tar.gz)
* [libevent](https://github.com/downloads/libevent/libevent/libevent-2.0.19-stable.tar.gz)
* [pthreads]

### Running ConMon
ConMon requires root privileges to capture packets. Until [ConMon v0.2.1](https://github.com/vr000m/conmon/tree/v0.2.1)
the captured packets are stored locally (in files at `./logs/`) and therefore the "user" has full control of their data.
If we implement a backend service to capture the logs, we will then add a method to obfuscate the user's IP addresses to preserve their privacy. 
ConMon [currently](https://github.com/vr000m/conmon/tree/v0.2.1) creates two files in `./logs/`
* `pkt_list_$filter_$interface.txt` (e.g.: pkt_list_ip_en1.txt)
* `time_list_$filter_$interface.txt` (e.g.: time_list_ip_en1.txt)

```
$./conmon --help
Usage: conmon [interface] [filter]

Options:
    interface     Listen on <interface> for packets.
    filter        PCAP Filter to apply on packets.
```


* Running without any parameters sets default PCAP filter="ip" and shows a menu to choose interfaces.
For example:
```
$ sudo ./conmon
extended by Varun Singh / Copyright (c) 2005 The Tcpdump Group
THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.

1. en0  (No Desc.)	
2. fw0	(No Desc.)	
3. en1	(No Desc.)	IPv6: fe80::xx:xx:xx:xx%en1	IPv4: xx.xx.xx.xx	
4. p2p0	(No Desc.)	
Enter the interface number (1-4):
```

* If you do not want the choose the network interface then pass it as a command-line argument.
For example:
```
$ sudo ./conmon en1
IP ADDR: xx.xx.xx.xx  MASK: 255.255.240.0	Device: en1	Filter expression: ip
```

* You may use an alternate [PCAP filter](http://wiki.wireshark.org/CaptureFilters). 
For example:
```
$ sudo ./conmon en1 tcp
IP ADDR: xx.xx.xx.xx  MASK: 255.255.240.0  Device: en1	Filter expression: tcp
```

### TODO
* create above classifiers [done]
* create vectors/map of {num_pkts, bytes} for each of the above classifiers [done]
* create plots to show changes in bit rate for the above classifiers [done]
* If data is uploaded then hash the source/destination IP addresses. [not needed currently, as data is stored locally!]
* create an API so that applications can query the bit rate for a specific
  classifier
* There may be bugs related to IPv6 in some places. ConMon is a fork from my
earlier project [Snapper](https://github.com/vr000m/Snapper)


### Contribute/Extend
If you want to parse a packet look at got_packet() there is a
switch case that parses the protocol field. You can add your own code or
function to parse the associated packet (see
`ParseUDPPacket()`/`ParseTCPPacket()` in `conmon.c`).