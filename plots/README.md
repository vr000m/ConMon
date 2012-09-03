## Output

In the `plots/` folder there are two scripts (`plots.sh` and
`plot-loopback.sh`) to generate the plots based on the "Time Logs" (e.g.:
time_list_ip_en1.txt). The `plot-loopback.sh` is used only when monitoring
packet flows on the `local interface (lo)`. By default monitoring on the 
loopback interface is denied, to enable change `#define BLOCK_LOOPBACK 1`
to `#define BLOCK_LOOPBACK 0` in `conmon.h`.


We use [Gnuplot](http://gnuplot.sourceforge.net/demo_cvs/) to generate the
[PDF plots](http://www.gnuplot.info/docs_4.6/gnuplot.pdf) (See Pg. 174 for
list of `terminal` options).


To plot the data, the above shell scripts take the filename of the "time
logs" (without the file extension) as a command-line argument. For example:

```
$./plots.sh time_list_ip_en1
# will generate the following files
time_list_ip_en1_total.pdf
time_list_ip_en1_tcp.pdf
time_list_ip_en1_udp.pdf
time_list_ip_en1_local.pdf
time_list_ip_en1_external.pdf
```

Each graph is a
`multiplot`(http://gnuplot.sourceforge.net/demo_cvs/multiplt.html) that
shows the combined, incoming, outgoing and cross-traffic.