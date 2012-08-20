#!/bin/bash
#example: ./plots.sh time_list_ip_en1
#echo $1
sed "s/time_list/$1/g" total-multiplot.plot | gnuplot
sed "s/time_list/$1/g" tcp-multiplot.plot | gnuplot
sed "s/time_list/$1/g" udp-multiplot.plot | gnuplot
sed "s/time_list/$1/g" local-multiplot.plot | gnuplot
sed "s/time_list/$1/g" external-multiplot.plot | gnuplot
