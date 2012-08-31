#!/bin/bash
#example: ./plot-loopback.sh time_list_ip_lo
#echo $1
sed "s/time_list/$1/g" host-multiplot.plot | gnuplot
