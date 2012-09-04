#!/bin/sh
# types of file conmon might need to delete
# rtp_1346712981_"$i"_*.txt"
# rtp_1346712981_0_{2,5,7,8,a,d}"$i"*.txt"
# 0_521a*

time=1346712981
#for i in {0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f}
for ((i=1; i < 256 ; i++))
do
    test="rtp_"$time"_"$i"_*.txt"
    echo "$test"
    rm -r $test
done