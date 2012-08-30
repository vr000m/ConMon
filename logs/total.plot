name=system("echo time_list") 
time=0
#time=system("date +%Y_%m_%d_%H_%M_%S")
#set term canvas
#set output name."-".time.".html"

set terminal pdf color enhanced rounded size 12,6 fsize 20
set output name."-".time.".pdf"


#set terminal pdf {monochrome|color|colour}
#                      {{no}enhanced}
#                      {fname "<font>"} {fsize <fontsize>}
#                      {font "<fontname>{,<fontsize>}"}
#                      {linewidth <lw>} {rounded|butt}
#                      {solid|dashed} {dl <dashlength>}}
#                      {size <XX>{unit},<YY>{unit}}
#

set origin 0,0
set size ratio 0.5
set key horiz 

set key right top inside
#unset key
#set pointsize 2.5

set xlabel "Time [s]" font "Times, 24"
set ylabel "Throughput [kbps]" font "Times, 24"


#set xrange [0:3600]
set yrange [0.1:15000]
set grid  #linetype 1 linewidth 0.500,  linetype -1 linewidth 0.500
#set style fill pattern 5
set xtics border out scale 0,0 mirror rotate by -45  offset character 0, 0, 0 #font "Times,12" 0,5
set logscale y

plot "time_list_20120818.txt" using ($1):($5/125) title 'Total' with points lw 1 lt -1 lc -1 pt 2