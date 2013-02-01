#! /bin/sh
gnuplot << EOF
name=system("echo $1") 
#time=system("date +%Y%m%d_%H%M%S")
set terminal pdf color enhanced rounded size 12,4 fsize 20 rounded dash
#fname '/Library/Fonts/Arial.ttf' 
#Verdana, Helvetica, Arial, sans-serif
set output name.".pdf"
set origin 0,0
set size ratio 0.25
set key right top inside

set xlabel "Time [s]"
set ylabel "Observed delay [s]"

# define axis
# remove border on top and right and set color to gray
set style line 11 lc rgb '#808080' lt 1
set border 3 back ls 11
set tics nomirror
# define grid
set style line 12 lc rgb '#808080' lt 0 lw 1
set grid back ls 12
set yrange [0:2]

# color definitions
set style line 1 lc rgb '#8b1a0e' pt 1 ps 1 lt 1 lw 2 # --- red
set style line 2 lc rgb '#5e9c36' pt 6 ps 1 lt 1 lw 2 # --- green

set xtics border out scale 0,0 mirror rotate by -45  offset character 0, 0, 0

plot "$1.txt" using 1:3 notitle with points ls 2
EOF