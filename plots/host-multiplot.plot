name=system("echo time_list_host") 
#time=0
time=system("date +%Y_%m_%d_%H_%M_%S")
#set term canvas
#set output name."-".time.".html"

timeoffset=0

set terminal pdf color enhanced rounded size 12,12 #fsize 16
set output name."-".time.".pdf"

set size 1,1
set origin 0.0, 0.0
unset key

set multiplot
set size 0.5,0.5
set origin 0.0,0.5
set grid

set title "a) Combined"
#set xrange [0:3600]
#set yrange [0.1:15000]
set ylabel "Throughput (kbps)" offset 1,0
set xtics border out scale 0,0 mirror rotate by -45  offset character 0, 0, 0 #font "Times,12" 0,5
set logscale y

#set xr [0.0:265.0]
#set yr [0:3000]
#unset xtics

plot "../logs/time_list.txt" using ($1-timeoffset):($5/125/$3) title 'Combined' with points lw 1 lt -1 lc -1 pt 1
		
set xtics nomirror
set size 0.5,0.5
set origin 0.0,0.0
set title "c) TCP"
set ylabel "Throughput (kbps)" offset 1,0
set xlabel "time (s)"#set xrange [0:3600]
#set yrange [0.1:15000]
set xtics border out scale 0,0 mirror rotate by -45  offset character 0, 0, 0 #font "Times,12" 0,5
set logscale y
unset key


plot "../logs/time_list.txt" using ($1-timeoffset):($7/125/$3) title 'TCP' with points lw 1 lt -1 lc -1 pt 1
		
		
set size 0.5,0.5
set origin 0.5,0.5
set title "b) UDP"
unset xlabel
unset ylabel
#set xrange [0:3600]
#set yrange [0.1:15000]
set logscale y


plot "../logs/time_list.txt" using ($1-timeoffset):($9/125/$3) title 'UDP' with points lw 1 lt -1 lc -1 pt 1

set size 0.5,0.5
set origin .5,0.
set title "d) Other Packets"
unset ylabel
set xlabel "time (s)"
#set xrange [0:3600]
#set yrange [0.1:15000]
set xtics border out scale 0,0 mirror rotate by -45  offset character 0, 0, 0 #font "Times,12" 0,5
set logscale y

plot "../logs/time_list.txt" using ($1-timeoffset):($11/125/$3) title 'Other' with points lw 1 lt -1 lc -1 pt 1

unset multiplot
