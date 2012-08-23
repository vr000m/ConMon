#!/bin/bash
#example: ./plots.sh time_list_ip_en1
#echo $1
sed "s/time_list/$1/g" host-multiplot.plot | gnuplot
