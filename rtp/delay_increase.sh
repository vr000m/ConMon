#! /bin/sh

tr '.' ',' < delay_inc.txt > tmp.txt

#plotting bitrate.txt using gnuplot
gnuplot << EOF
set terminal pdf color enhanced rounded size 12,4 fsize 10
set output "delay_inc.pdf"
set origin 0,0
set size ratio 0.29
set key right top inside
set pointsize 2.5

set xlabel "Delay [ms]"
set ylabel "Packets"
set yrange [0:1]
set xrange [0:1000]
set grid
set style fill pattern 5
set xtics border out scale 0,0 mirror offset character 0, 0, 0

plot "tmp.txt" with linespoints lw 3 lt -1 pt 6 ps 1.5 lc -1
EOF
rm delay_inc.txt
rm tmp.txt