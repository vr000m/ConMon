# -*- coding: utf-8 -*-
# 

import sys
import csv
import socket
import operator

#defines
IN_KBPS = 8.0/1000
DNS_TIMEOUT = 1
IN_MB= (1024.0*1024)
IN_KB= 1024.0
SIZE_THRESHOLD=1.0 #mb

def UpdateDict(key, dictionary, val):
    if(key in dictionary):
        dictionary[key]=dictionary[key]+val
    else:
        dictionary[key]=val


def UpdateDictWithTuple(key, dictionary, val):
    # val is a tuple of [size, count]
    if(key in dictionary):
        val=tuple(map(sum,zip(dictionary[key],val)))
        dictionary[key]=val
        #print key, val
    else:
        dictionary[key]=val
        #print "new", key, val

def writeFlowLog(fn, x):
    sorted_x = sorted(x.iteritems(), key=operator.itemgetter(1), reverse=True)
    flowlog = open(fn, 'w')
    for i in sorted_x:
        # key, [size, count]
        #print i[0], i[1][0], i[1][1]
        key=i[0]
        hostaddr=""
        ipaddr=""
        index = key.find('_')
        if (index>0):
            hostaddr=key[0:index]
            ipaddr = key[index+1:len(key)]
        else:
            hostaddr=key
        
        if(hostaddr=="None"):
            hostaddr=ipaddr
        
        size=round(float(i[1][0])/IN_MB,2)
        if(size>SIZE_THRESHOLD):
            log=str(hostaddr)+'\t'+str(i[1][1])+'\t'+str(size)+'\t'+str(ipaddr)+'\n'
            flowlog.write(log)
    flowlog.close()

def main(argv):
    if(len(argv)==0):
        sys.exit("insufficient arguments")
    filename = argv[0]
    path=""
    fn=""
    index = filename.find('/')
    if (index>0):
        path=filename[0:index+1]
        fn = filename[index+1:len(filename)]
    else:
        fn=filename
    
    logfile  = open(path+fn, "rb")
    rows = csv.reader(logfile, delimiter='\t')
    
    flowlog = open(path+'flow_'+fn, 'w')
    #write_flowlog = csv.writer(flowlog, delimiter='\t')
    i=0
    
    cnt_in_pkt=0
    cnt_out_pkt=0
    cntp_in_pkt=0
    cntp_out_pkt=0
    
    sz_in_pkt = 0
    sz_out_pkt = 0
    szp_in_pkt = 0
    szp_out_pkt = 0
    
    start_time = 0
    prev_time = 0
    time = 0
    
    addr_in = {}
    addr_out = {}
    
    int_addr_in = {}
    int_addr_out = {}
    
    flow_tup_in = {}
    flow_tup_out = {}
    
    for col in rows:
        time = int(col[1])
        size = int(col[3])
        if(i==0):
            start_time = time
            prev_time = time
        '''
        need to change this expression to calculate some other metrics
        at the moment: we are checking for
            external communication (EXT) options: EXT, LOC, XOS, HOST
            and protocol (TCP) options: TCP, UDP
        '''
        if(col[4]=="EXT" and col[6]=="TCP"):
            dns=col[11]
            if(col[5]=="INC"):
                #calculating incoming sources
                cnt_in_pkt = cnt_in_pkt +1
                sz_in_pkt = sz_in_pkt + size
                
                #serverip_serverport_hostport
                key = dns+"-"+col[9]+"-"+col[7]+"-"+col[8]
                UpdateDictWithTuple(key, flow_tup_in, [size, 1])
                UpdateDictWithTuple(col[9], addr_in, [size, 1])
                
                #updating unique flow counts in an interval
                UpdateDict(key, int_addr_in, 1)
                
            elif(col[5]=="OUT"):
                #calculate outgoing sources
                cnt_out_pkt = cnt_out_pkt +1
                sz_out_pkt = sz_out_pkt + size
                
                #serverip_serverport_hostport
                key = dns+"_"+col[10]+"_"+col[8]+"_"+col[7]
                UpdateDictWithTuple(key, flow_tup_out, [size, 1])
                UpdateDictWithTuple(col[10], addr_out, [size, 1])
                
                #updating unique flow counts in an interval
                UpdateDict(key, int_addr_out, 1)
                
        #print time, prev_time
        if (time-prev_time>=1):
            #1s has passed
            int_in_pkt = cnt_in_pkt - cntp_in_pkt
            int_out_pkt = cnt_out_pkt - cntp_out_pkt
            cntp_in_pkt = cnt_in_pkt
            cntp_out_pkt = cnt_out_pkt
            
            int_sz_in_pkt = sz_in_pkt - szp_in_pkt
            int_sz_out_pkt = sz_out_pkt - szp_out_pkt
            szp_in_pkt = sz_in_pkt
            szp_out_pkt = sz_out_pkt
            
            len_addr_in = len(int_addr_in)
            len_addr_out = len(int_addr_out)
            
            int_addr_in = {}
            int_addr_out = {}
            
            prev_time = time
            line=str(time-start_time)+'\t'\
                +str(int_in_pkt)+'\t'+str(int_out_pkt)+'\t'\
                +str(int_sz_in_pkt*IN_KBPS)+'\t'+str(int_sz_out_pkt*IN_KBPS)+'\t'\
                +str(len_addr_in)+'\t'+str(len_addr_out)+'\n'
            flowlog.write(line)
        i=i+1
    #end of file
    flowlog.close()
    logfile.close()
    
    writeFlowLog(path+'flow_cnt_in_'+fn, flow_tup_in)
    writeFlowLog(path+'flow_cnt_out_'+fn, flow_tup_out)
    writeFlowLog(path+'addr_cnt_in_'+fn, addr_in)
    writeFlowLog(path+'addr_cnt_out_'+fn, addr_out)
    
    duration = (time-start_time)/60.0
    print "duration: ", duration
    print "> PKT_CNT: ", cnt_in_pkt, "ADDR_COUNT: ", len(addr_in), len(flow_tup_in)
    print "< PKT_CNT: ", cnt_out_pkt, "ADDR_COUNT: ", len(addr_out), len(flow_tup_out)

if __name__ == "__main__":
    main(sys.argv[1:])
