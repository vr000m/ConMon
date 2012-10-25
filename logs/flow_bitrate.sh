#! /bin/sh
#plotting flow_rdns_*.txt using gnuplot
filename=$1
fname=${filename#*/}
pname=${filename%/*}
cnt_out_file=${fname/flow_rdns_/flow_cnt_out_rdns_}
cnt_in_file=${fname/flow_rdns_/flow_cnt_in_rdns_}

echo $pname, $fname, $cnt_in_file, $cnt_out_file

gnuplot << EOF
name=system("echo $pname/graph-bitrate") 
time=system("date +%Y%m%d_%H%M%S")
set terminal pdf color enhanced rounded fsize 18 size 10,6
set output name."-".time.".pdf"
set origin 0,0
set border 3 lc rgb "black"
set grid
set size ratio 0.5
set key right top inside
set xlabel "Time [s]"
set ylabel "[kbps]"
set logscale y
set yrange[0.1:100000]
set xtics border out scale 0,0 mirror rotate by -45  offset character 0, 0, 0
#bezier, csplines
plot "$1" using 1:4 notitle with points lw 2 pi 5 pt 1 ps 1 lc 1, \
       "" using 1:5 notitle with points lw 2 pi 5 pt 1 ps 1 lc 2, \
      "$1" using 1:4 smooth csplines title "IN (kbps)" with lines lw 4 lc 6, \
      "" using 1:5 smooth csplines  title "OUT (kbps)"  with lines lw 4 lc 10
EOF
#${filename/flow_rdns_/flow_cnt_in_rdns_}
gnuplot << EOF
name=system("echo $pname/graph-histogram-in") 
time=system("date +%Y%m%d_%H%M%S")
set terminal pdf color enhanced rounded fsize 18 size 10,6
set output name."-".time.".pdf"
set origin 0,0
set border 3 lc rgb "black"
set grid
set size ratio 0.5
set key right top inside
set ylabel "[MB]"
set auto x
set logscale y
set yrange[0.1:10000]
set style data histogram
set style histogram cluster gap 1
set style fill solid border -1
set boxwidth 0.9
set xtics border out scale 0,0 mirror rotate by -45  scale 0 font ",12" offset character 0, 0, 0
#bezier, csplines
plot "$pname/$cnt_in_file" using 3:xtic(1) title "INCOMING" lc 6
EOF
#${filename/flow_rdns_/flow_cnt_out_rdns_}
gnuplot << EOF
name=system("echo $pname/graph-histogram-out") 
time=system("date +%Y%m%d_%H%M%S")
set terminal pdf color enhanced rounded fsize 18 size 10,6
set output name."-".time.".pdf"
set origin 0,0
set border 3 lc rgb "black"
set grid
set size ratio 0.5
set key right top inside
set ylabel "[MB]"
set auto x
set logscale y
set yrange[0.1:10000]
set style data histogram
set style histogram cluster gap 1
set style fill solid border -1
set boxwidth 0.9
set xtics border out scale 0,0 mirror rotate by -45  scale 0 font ",12" offset character 0, 0, 0
#bezier, csplines
plot "$pname/$cnt_out_file" using 3:xtic(1) title "OUTGOING" lc 10
EOF
