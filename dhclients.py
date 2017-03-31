#! /usr/bin/env python
# -*- coding: utf-8 -*-

u"""
主要用于模块dhclient发送各种协议包
"""

import random
import sys
import string,binascii,signal,sys,threading,socket,struct,getopt
from scapy.all import *
import re,time
# from scapy.error import log_interactive
conf.checkIPaddr = False
interface = "eth1"
verbose = True
Debug=False

#用于存放Mac地址获取到的IP地址
class dhclient_packet(threading.Thread):
    def __init__(self,**kargs):
        threading.Thread.__init__(self)
        self.parser(**kargs)
        self.filter="icmp or (udp and src port 67 and dst port 68)"
        self.count_ack_IP = []
        if 'nums' in kargs.keys():
            self.clients=int(kargs['nums'])   #配置客户端个数
        else:
            self.clients=1
        if 'mac' in kargs.keys():
            self.start_mac=int("".join(kargs['mac'].replace("-",":").split(":")),16)
        else:
            self.start_mac=0X000000010101
        self.maclist=[]
        for i in range(0,self.clients):
            general_mac=self.createMac(i)
            self.maclist.append(general_mac)
    def parser(self,**kargs):
        for key,value in kargs.items():
            if key == "smac" or key == "dmac":
                value = ":".join(value.split("-"))
            setattr(self,key,value)
    def createMac(self,i):
        new_mac="%012x" %(self.start_mac+i)
        ret_mac=re.sub(r"(?<=\w)(?=(\w\w)+$)",":",new_mac)
        return ret_mac
    def send_discover(self):
        flag = 0
        print "self.clients=",self.clients
        for i in range(0,self.clients):
            #循环发送客户端个数的报文
            mac=self.maclist[i]
            myxid=self.start_mac+i
            hostname="Test%s" %(myxid)
            dhcp_discover =  Ether(src=mac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(mac)],xid=myxid)/DHCP(options=[("message-type","discover"),("hostname",hostname),"end"])
            sendp(dhcp_discover,verbose=0,iface=self.intf)
    def run(self):
        sniff(filter=self.filter,prn=self.detect_parseroffer,store=0,iface=self.intf)
    def discover(self):
        #发送discovery报文
        translate_id=random.randint(1,9000000)
        dhcp_discover=Ether(src=self.smac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(self.smac)],xid=translate_id)/DHCP(options=[("message-type","discover"),("max_dhcp_size",548),("hostname",self.hostname),"end"])
        sendp(dhcp_discover,iface=self.intf)
    def request_broadcast(self):
        #发送广播request 主要用于区别1/2租约时间的报文
        #option 1 子网掩码地址 一般Server提供
        #option 3 网关地址  一般Server提供
        #option 6 域名服务器地址 一般Server提供
        #option 12 客户端主机名hostname
        #option 15 domain 域名服务器域名
        #option 28 广播地址
        #option 50 请求的IP地址
        #option 51 租约时间
        #option 53 dhcp类型 discover request decline release inform force_renew lease_query 等
        #option 54 服务器地址
        #option 58 重新请求地址时间 一般为租约时间的1/2
        #option 59 重新绑定等待时间 一般为租约时间的7/8
        #option 61 客户端Id 需要转换成ASCII
        translate_id=random.randint(1,9000000)
        dhcp_discover=Ether(src=self.smac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(self.smac)],xid=translate_id)/DHCP(options=[("message-type","request"),('requested_addr',self.option50),("hostname",self.hostname),"end"])
        sendp(dhcp_discover,iface=self.intf)
    def request_unicast(self):
        #单播请求地址
        translate_id=random.randint(1,9000000)
        dhcp_discover = Ether(src=self.smac,dst=self.dmac)/IP(src=self.sip,dst=self.dip)/UDP(sport=68,dport=67)/BOOTP(ciaddr=self.sip,chaddr=[mac2str(self.smac)],xid=translate_id)/DHCP(options=[("message-type","request"),('requested_addr',self.sip),("hostname",self.hostname),"end"])
        sendp(dhcp_discover,iface=self.intf)
    def decline(self):
        #这里的表示不需要这个地址requested_addr地址
        translate_id=random.randint(1,9000000)
        dhcp_discover=Ether(src=self.smac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(self.smac)],xid=translate_id)/DHCP(options=[("message-type","decline"),('requested_addr',self.option50),('server_id',self.dip),("hostname",self.hostname),"end"])
        sendp(dhcp_discover,iface=self.intf)
        #重新完成四次交互过程
        self.discover()
        sniff(filter=self.filter,prn=self.detect_parseroffer,store=0,iface=self.intf)
        self.request_broadcast()
    def release(self):
        translate_id=random.randint(1,9000000)
        cid=mac2str("01")
        for i in self.smac.split(":"):
            cid=cid+mac2str(i)
        dhcp_discover = Ether(src=self.smac,dst=self.dmac)/IP(src=self.sip,dst=self.dip)/UDP(sport=68,dport=67)/BOOTP(ciaddr=self.sip,chaddr=[mac2str(self.smac)],xid=translate_id)/DHCP(options=[("message-type","release"),('client_id',cid),('server_id',self.dip),"end"])
        sendp(dhcp_discover,iface=self.intf)
    def detect_parseroffer(self,pkt):
        #解析offer报文
        #打开文件进行配置
        # log_interactive.debug("clients=3")
        sys.stdout.write("clients=3")
        all_info=""
        if DHCP in pkt:
            #判断是否为OFFER报文
            if pkt[DHCP] and pkt[DHCP].options[0][1] == 2:
                self.dhcpcount=0
                dhcpsip = pkt[IP].src
                dhcpsmac = pkt[Ether].src
                smac=pkt[BOOTP].chaddr
                for opt in pkt[DHCP].options:
                    if opt[0] == 'subnet_mask':
                        subnet=opt[1]
                        break
                myip=pkt[BOOTP].yiaddr
                sip=pkt[BOOTP].siaddr
                localxid=pkt[BOOTP].xid
                smac=self.unpackMAC(pkt[BOOTP].chaddr)
                
                if self.clients == 1:
                    myhostname=self.hostname
                    smac=self.smac
                else:
                    myhostname="Test%s" %(localxid)
                dhcp_req = Ether(src=smac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(smac)],xid=localxid)/DHCP(options=[("message-type","request"),("server_id",sip),("requested_addr",myip),("hostname",myhostname),("param_req_list","pad"),"end"])
                sendp(dhcp_req,verbose=0,iface=self.intf)
            elif pkt[DHCP] and pkt[DHCP].options[0][1] == 5:
                if pkt[BOOTP].yiaddr not in self.count_ack_IP:
                    self.count_ack_IP.append(pkt[BOOTP].yiaddr)
                if self.clients == 1:
                    options=pkt[DHCP].options
                    optionlen=len(options)
                    for i in range(optionlen):
                        if options[i][0] == "router":
                            all_info=all_info+"GateWay=%s\n" %(options[i][1])
                        elif options[i][0] == "lease_time":
                            all_info=all_info+"LeaseTime=%s\n" %(options[i][1])
                        elif options[i][0] == "subnet_mask":
                            all_info=all_info+"Mask=%s\n" %(options[i][1])
                        elif options[i][0] == "server_id":
                            all_info=all_info+"ServerId=%s\n" %(options[i][1])
                        elif options[i][0] == "name_server":
                            all_info=all_info+"DnsServer=%s\n" %(",".join(list(options[i][1:])))
                all_info=all_info+"ACKIP=%s\n" %(pkt[BOOTP].yiaddr)
                all_info=all_info+"ACK_IP_SUM=%s\n" %(len(self.count_ack_IP))
            elif pkt[DHCP] and pkt[DHCP].options[0][1] == 6:
                all_info=all_info+"NAK\n"
        elif ICMP in pkt:
            smac=pkt[Ether].dst
            if pkt[ICMP].type==8:
                myip=pkt[IP].dst
                mydst=pkt[IP].src
                icmp_req=Ether(src=smac,dst=pkt.src)/IP(src=myip,dst=mydst)/ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq)/"12345678912345678912"
                all_info=all_info+"ICMP_SIP=%s" %(mydst)
        sys.stdout.write(all_info)
    def unpackMAC(self,binmac):
        mac=binascii.hexlify(binmac)[0:12]
        blocks = [mac[x:x+2] for x in xrange(0, len(mac), 2)]
        return ':'.join(blocks)
def usage(args):
    print u"%s --help" %(args)
    print u"smac=sourcmac dhclient source ethernet hardware address"
    print "dmac=ethernet_dmac dhclient target ethernet hardware address"
    print "sip=sourcer_ip dip=target_ip"
    print u"func= send_discover/discover/request_broadcast/request_unicast/decline/release"
    print u"hostname=hostname intf=interface nums=client_nums filename=logfile option50=request_ip"
if __name__ == '__main__':
    now=time.localtime()
    now_str="%s-%s-%s %s:%s:%s" %(now.tm_year,now.tm_mon,now.tm_mday,now.tm_hour,now.tm_min,now.tm_sec)
    kargs={"smac":"00:aa:bb:cc:dd:ee","sip":"192.168.3.102","dip":"192.168.3.1","dmac":"c8:3a:35:34:be:38","option50":"192.168.3.102","hostname":"CC","intf":"eth6","nums":"1","func":"discover","filename":"c:/dhclient.txt",'timeout':5}
    for i in range(1, len(sys.argv)):
        # print sys.argv[i]
        if sys.argv[i].find("="):
            usage(sys.argv[0])
            exit()
        value=sys.argv[i].split("=")
        if len(value)==2 and len(value[1]) != 0:
            kargs[value[0]]=value[1]
    #
    t=dhclient_packet(**kargs)
    t.setDaemon(True)
    t.start()
    func=kargs['func']
    getattr(t, func)()
    #主线程等待时间
    if 'timeout' in kargs.keys():
        time.sleep(kargs['timeout'])
    else:
        time.sleep(5)