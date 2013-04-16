#!/usr/local/bin/python
# -*- coding: utf-8 -*-
import sys
import os
import csv
import getopt
import sys, urllib, time

from os import listdir
from os.path import isfile, join

import string
import operator

add_path1="/machine1/rtp/"
add_path2="/machine2/rtp/"
packet_count=0
delay_array=[0]*100
delay_gaps=[0]*100

def delay_distribution(counter,delay,name):
    x=10
    global packet_count
    global delay_array
    global delay_gaps
    packet_count+=1
    #Classifies in gaps of 10 ms 100 times, that is a total of 1s delay max
    for i in range(0,100):
        delay_gaps.pop(i)
        delay_gaps.insert(i,x)
        if (delay<x) and (delay>(x-10)):
            z=delay_array[i]+1
            delay_array.pop(i)
            delay_array.insert(i,z)
        x=x+10

def build_output_distribution():
    newList=[]
    z=0
    delayPlot = open("delay_inc.txt", 'wb')
    logWriter = csv.writer(delayPlot, delimiter='\t')
    logWriter.writerow([0, 0]);
    global delay_array
    global delay_gaps
    global packet_count
    for x in delay_array:
        y=(float(x)/packet_count)
        z=z+y
        newList.append(z)
    for i in range(0,100):
        logWriter.writerow([delay_gaps[i], newList[i]]);
    delayPlot.close

def readLog(filename):
    packet = {}
    with open(filename, 'rb') as rtpfile:
        rtp = csv.reader(rtpfile, delimiter='\t')
        #NTP_TS PT SSRC SeqNo RTP_TS ? Size
        for row in rtp:
            packet[int(row[3])]=float(row[0])
    rtpfile.close    
    return packet   

#
def sortDict(d):
    keys = d.keys()
    keys.sort()
    return map(d.get, keys)
    
def main(argv): 
    #path =argv[0]
    base_path1 = argv[0]
    base_path2 = argv[1]
    iteration = argv[2]
    global delay_array
    global delay_gaps
    #base_path1 = argv[0]
    #base_path2 = argv[1]
    # find text files in the two two directories
    # make sure the two machines have synchronized clocks, 
    # else we cannot really make sense of the delay values
    # but we can measure the variation (despite the skew)

    mac1 = [ f for f in listdir(base_path1) if (isfile(join(base_path1,f)) and  f.find(".txt")!=-1)]
    mac2 = [ f for f in listdir(base_path2) if (isfile(join(base_path2,f)) and  f.find(".txt")!=-1)]

    # find matching filenames in both directories
    # e.g., rtp_1359204053_101_faa6f202.txt
    # match _101_faa6f202

    # BUG?: maybe zipping is just a bad idea, the lists may not be of equal lengths
    
    for f1, f2 in zip(mac1, mac2):
        # the filenames will not match because the NTP ts will vary 
        # we skip the first two underscores ("_") rtp_NTP_*. 
        # the * should match in both cases.
        # because the PT and the SSRC MUST match!
        ptssrc=f1.split ("_", 2)[2]
        if (f2.find(ptssrc)!=-1):
            #pick matched filenames
            m1 = readLog(base_path1+f1)
            m2 = readLog(base_path2+f2)
            
            x = m1 if (len(m1) > len(m2)) else m2
            y = m2 if (len(m1) > len(m2)) else m1

            fname="delay_"+iteration+"_"+ptssrc

            delayLog = open(fname, 'wb')
            logWriter = csv.writer(delayLog, delimiter='\t')
            for key, value in x.iteritems():
                #print key
                if (key in y):
                    d=0
                    if (value>y[key]):
                        d = value - y[key]
                        logWriter.writerow([y[key], key, d])
                    else:
                        d = y[key] - value
                        logWriter.writerow([value, key, d])
                    delay_distribution(key,d*1000,ptssrc)
                #print a
                #print b
            os.system("./conmon-rtp-delay.sh "+fname.split (".")[0])
            delayLog.close
    build_output_distribution()
        
if __name__ == "__main__":
    main(sys.argv[1:])