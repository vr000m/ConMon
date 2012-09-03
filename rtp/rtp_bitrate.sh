#! /bin/sh
./perinst.awk $1.txt > $1_bitrate.txt

# removing first line from bitrate.txt
mv $1_bitrate.txt $1_bitrate.tmp
sed 1d $1_bitrate.tmp > $1_bitrate.txt
rm $1_bitrate.tmp

#plotting bitrate.txt using gnuplot
gnuplot << EOF
name=system("echo $1") 
time=system("date +%Y%m%d_%H%M%S")
set terminal pdf color enhanced rounded size 12,4 fsize 20
set output name."-".time.".pdf"
set origin 0,0
set size ratio 0.25
set key right top inside
set pointsize 2.5

set xlabel "Time [s]"
set ylabel "Observed rate [kbps]"
set grid
set style fill pattern 5
set xtics border out scale 0,0 mirror rotate by -45  offset character 0, 0, 0

plot "$1_bitrate.txt" using 1:2 title "RTP" with linespoints lw 3 lt -1 pi 30 pt 6 ps 1.5 lc -1
EOF
rm $1_bitrate.txt