An Example plot of the **UDP traffic** is shown below: 
![Example ConMon plot](https://github.com/vr000m/ConMon/blob/master/plots/Example%20Plots/2_bittorrent_skype_rw.png)

A bit about the graph:
> The first spike (upto 10 Mbps) is caused by Bittorrent. I downloaded
> ~300MB torrent. The second cluster of spikes is caused by Skype. I
> initially started with an audio call and later upgraded to video,
> therefore, we observe larger spikes. You may notice that the plots are a
> bit asymmetric (compare the `incoming` and `outgoing` throughput
> plots,the magnitude of the spikes are different) this is due to the
> rate-control algorithm at the the two ends.


