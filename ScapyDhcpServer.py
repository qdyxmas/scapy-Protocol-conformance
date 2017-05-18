#! /usr/bin/env python
# -*- coding: utf-8 -*-

u"""
@auther qdyxmas@gmail.com
scapy-ScapyDhcpServer
"""

import random
import sys
import string,binascii,signal,sys,threading,socket,struct,getopt
from scapy.all import *
import re,time
import IPy
conf.checkIPaddr = False
interface = "eth1"

#用于存放Mac地址获取到的IP地址
class DhcpServer(threading.Thread):
    def __init__(self,**kargs):
        threading.Thread.__init__(self)
        # self.pad=mac2str('00')*20
        self.sip='192.168.3.2'
        self.subnet_mask="255.255.255.0"
        self.router="192.168.3.1"   ;#默认网关
        # self.siaddr="10.123.121.1"   ;#中继地址
        self.giaddr="0.0.0.0"   ;#中继地址
        self.name_server="192.168.3.1" #域名服务器地址
        self.domain="beeline"
        self.hostname="Tenda"
        self.default_ttl=mac2str('40')
        self.broadcast_address="192.168.3.255"
        self.prd="1"
        self.pmd=mac2str("0")
        self.start_sip="192.168.3.100"
        self.start_eip="192.168.3.200"
        self.offer_timeout=0    ;#为0表示不延迟进行回应OFFER报文,为-1表示不回应OFFER报文,为大于1的表示等待该时间回应OFFER
        self.ack_timeout=0  ;#为0 不延迟回应request 为-1不回应 其他为等待回应 
        self.T1=0           ;#为0 不延迟回应  为-1 不回应 为其他延迟回应
        self.T2=0           ;#为0 不延迟回应  为-1 不回应 其他延迟回应
        self.polllist=[]
        self.macip_dict={}
        self.lease_time=3600 ;#默认租约时间 4294967295L表示永久租约
        self.ack_lease_time=3600 ;#默认租约时间 4294967295L表示永久租约
        self.server_id="192.168.3.2" ;#DHCP服务器IP地址
        self.parser_args(**kargs)
        self.renewal_time=self.lease_time/2
        self.rebinding_time = self.lease_time*7/8
        self.filter="arp or icmp or (udp and src port 68 and dst port 67)"
        self.pool_init()
    def parser_args(self,**kargs):
        for key,value in kargs.items():
            if key == "smac" or key == "dmac":
                value = ":".join(value.split("-"))
            setattr(self,key,value)
    def pool_init(self):
        self.startIp=self.ip2int(self.start_sip)
        self.endIp=self.ip2int(self.start_eip)
    def poolfree(self,mac):
        #如果mac地址在macip_dict中则分配该IP地址
        if mac in self.macip_dict.keys():
            return self.macip_dict[mac]
        else:
            for i in range(self.startIp,self.endIp+1):
                cur_ip=self.num2ip(i)
                if  cur_ip not in self.polllist:
                    return cur_ip
        return "0.0.0.0"
    def run(self):
        sniff(filter=self.filter,prn=self.detect_parserDhcp,store=0,iface=self.iface)
    def detect_parserDhcp(self,pkt):
        if DHCP in pkt:
            raw=Ether()/IP()/UDP(sport=67,dport=68)/BOOTP()/DHCP()
            raw[Ether].src,raw[IP].src=self.smac,self.sip
            raw[Ether].dst,raw[IP].dst=pkt[Ether].src,"255.255.255.255"
            send_type="nak"
            #1->Discover 2->OFFER  3->Request 4->Decline 5->ACK  6->NAK  7->Release 8->Inform
            #如果这里不添加DHCP,后面添加DHCP就会报错
            raw[BOOTP]=BOOTP(op=2,xid=pkt[BOOTP].xid,chaddr=self.mac2bin(pkt[Ether].src),yiaddr="0.0.0.0",giaddr=self.giaddr)/DHCP()
            DhcpOption=[("server_id",self.server_id),('lease_time',self.lease_time),("router",self.router),("subnet_mask",self.subnet_mask),('renewal_time',self.renewal_time),('name_server',self.name_server),('rebinding_time',self.rebinding_time),("broadcast_address",self.broadcast_address),('pmd',self.pmd),('prd',self.prd),('default_ttl',self.default_ttl),('hostname',self.hostname)]
            type=pkt[DHCP].options[0][1] ;#获取得到option 53字段的内容
            # raw[]
            if type == 0x01 or type == 0x03:
                dhcpsip = pkt[IP].src
                dhcpsmac = pkt[Ether].src
                cli_mac=pkt[Ether].src
                print "cli_mac=",cli_mac
                localxid=pkt[BOOTP].xid
                your_ip=self.poolfree(dhcpsmac)
                raw[BOOTP].yiaddr=your_ip
                if your_ip == "0.0.0.0":
                    #发送Nak报文
                    BootpHeader.yiaddr=your_ip
                    nak=Ether(src=self.smac,dst="ff:ff:ff:ff:ff:ff")/IP(src=self.server_id,dst="255.255.255.255")/UDP(sport=67,dport=68)/BootpHeader/DHCP(options=[("message-type","nak"),("server_id",self.server_id),"end"])
                    sendp(nak,verbose=0,iface=self.iface)
                else:
                    #  地址池有地址
                    if type == 1:
                        #判断是否需要添加其他的options 33/121/249字段
                        #得到send_
                        DhcpOption.insert(0,("message-type","offer"))
                        options_all=self.add_option(DhcpOption)
                        options_all.append("end")
                        options_all.append(mac2str("00")*20)
                        raw[DHCP]=DHCP(options=options_all)
                        print "raw.summary=",raw.summary
                        if self.waittimeout(self.offer_timeout):
                            sendp(raw,iface=self.iface)
                    elif type == 3:
                        DhcpOption.insert(0,("message-type","ack"))
                        options_all=self.add_option(DhcpOption)
                        options_all.append("end")
                        options_all.append(mac2str("00")*20)
                        raw[DHCP]=DHCP(options=options_all)
                        if pkt[BOOTP].ciaddr == "0.0.0.0":
                            #为回应OFFER的requeest
                            if self.waittimeout(self.ack_timeout):
                                sendp(raw,verbose=0,iface=self.iface)
                                self.macip_dict[dhcpsmac]=your_ip
                                self.polllist.append(your_ip)
                        else:
                            if pkt[IP].src == "0.0.0.0":
                                #为T2广播包
                                if self.waittimeout(self.T2):
                                    sendp(raw,verbose=0,iface=self.iface)
                                    self.macip_dict[dhcpsmac]=your_ip
                                    self.polllist.append(your_ip)
                            else:
                                #为T1广播包
                                if self.waittimeout(self.T1):
                                    sendp(raw,iface=self.iface)
                                    self.macip_dict[dhcpsmac]=your_ip
                                    self.polllist.append(your_ip)
            elif type == 4:
                options=pkt[DHCP].options
                optionlen=len(options)
                for i in range(optionlen):
                    if options[i][0] == "requested_addr":
                        self.polllist.append(options[i][1])
                        break
            elif type == 7:
                dhcpsip = pkt[IP].src
                dhcpsmac = pkt[Ether].src
                self.polllist.remove(dhcpsmac)
        elif ARP in pkt:
            if pkt[ARP].pdst=="10.123.121.1" and pkt[ARP].psrc != "0.0.0.0":
                arp_reply=Ether(src=self.smac,dst=pkt.src)/ARP(op=0x0002,hwsrc=self.smac,psrc="10.123.121.1",hwdst=pkt[ARP].hwsrc,pdst=pkt[ARP].psrc)/"001122334455"
                sendp(arp_reply,verbose=0,iface=self.iface)
    def add_option(self,options_all):
        ret_all=options_all
        if hasattr(self,'static_route_33'):
            print "opt33=",self.static_route_33
            ret_all.append(('static_route_33',self.parser_option33(self.static_route_33)))
        if hasattr(self,'static_route_121'):
            ret_all.append(('static_route_121',self.parser_option33(self.static_route_121)))
        if hasattr(self,'static_route_249'):
            ret_all.append(('static_route_249',self.parser_option33(self.static_route_249)))
        return ret_all
    def parser_option33(self,option):
        header= option[:2]
        if header == "33":
            return self.ip2bin(option[3:])
        elif header in "121 249":
            ip=self.parser_option121(option[3:])
            return self.ip2bin(ip)
    def parser_option121(self,option):
        #先对传入参数进行
        #传入参数格式为 192.168.1.2/24 192.168.100.1 192.168.2.2/24 192.168.100.1 
        optlist=option.strip().split(" ")
        optlen=len(optlist)
        ret=[]
        for i in range(0,optlen,2):
            opt=self.parser_ipnet(optlist[i],optlist[i+1])
            ret.append(opt)
        print "ret=",ret
        return ".".join(ret)
    def parser_ipnet(self,ipnet="",gw=""):
        u"主要根据IP和子网掩码得到网络地址"
        f=lambda x:(int(x)-1)/8+1
        dst=ipnet.split("/")
        ip,mask=str(IPy.IP(dst[0]).make_net(dst[1])).split("/")
        ip=".".join(ip.split(".")[:f(mask)])
        return ".".join([mask,ip,gw])
    def waittimeout(self,num):
        num=int(num)
        if num>=0:
            time.sleep(num)
            return True
        else:
            return False
    def str2hex(self,allstr):
        u"把字符串转换成ASCII的十六进制格式 1=>31"
        return "".join(map(lambda x:"%02X" %(ord(x)),list(allstr)))    
    def str2bin(self,allstr):
        u"把字符串转换成字节流 1=>\x31"
        #steps,str=>ascii(dec)==>ascii(hex)==>binstr
        hexstr="".join(map(lambda x:"%02X" %(ord(x)),list(allstr)))
        strbin=self.hex2bin(hexstr)
        return strbin
    def num2bin(self,num,leng="2"):
        u"把字符串数字转换成字节流 比如1=>\x01"
        hexstr=str("%0"+str(leng)+"X") %(num)
        binnum=self.hex2bin(hexstr)
        return binnum
    def ip2bin(self,ip,flag=". "):
        u"把IP地址转换成字节流 192.168.1.1 =>\xc0\xa8\x01\x01"
        hexlist=re.split(r"[%s]" %(flag),ip)
        hexstr="".join(map(lambda x:"%02x" %(int(x)),hexlist))
        binip=self.hex2bin(hexstr)
        return binip
    def mac2bin(self,mac,flag=":-"):
        u"把Mac地址转换成字节流 00:aa:bb:cc:dd:ee=>\x00\xaa\xbb\xcc\xdd\xee"
        hexlist=re.split(r"[%s]" %(flag),mac)
        hexstr="".join(hexlist)
        binmac=self.hex2bin(hexstr)
        return binmac
    def hex2bin(self,hexstr):
        u"把十六进制转换成字节流 ab=>\xab"
        len_str=len(hexstr)
        substr=""
        for i in range(0,len_str,2):
            substr=substr+chr(int(hexstr[i:i+2],16))
        return substr
    def bin2hex(self,binstr):
        u"把字节流转换成相对应的十六进制数字 \xab=>ab"
        hexstr="".join(map(lambda x:"%02X" %(ord(x)),list(binstr)))
        return hexstr
    def ip2int(self,ip):
        u"IP地址转换成整数"
        return reduce(lambda a,b: a<<8 | b, map(int, ip.split(".")))
    def num2ip(self,ip_num):
        u"整数转换成IP地址"
        return ".".join(map(lambda n: str(ip_num>>n & 0xFF), [24,16,8,0]))
if __name__ == '__main__':
    now=time.localtime()
    now_str="%s-%s-%s %s:%s:%s" %(now.tm_year,now.tm_mon,now.tm_mday,now.tm_hour,now.tm_min,now.tm_sec)
    opt121=""
    opt249=""
    opt33=""
    # "static_route_121":"121 net1/N1 gw net2/N2 gw"
    # "static_route_249":"249 net1/N1 gw net2/N2 gw"
    # "static_route_33":"33 net1 gw net2 gw"
    for i in range(11,24):
        net=random.randint(24,30)
        opt121=opt121+"192.169.%d.0/%d 192.168.3.1 " %(i,net)
        opt33=opt33+"193.168.%d.0 192.168.3.1 " %(i)
        opt249=opt249+"191.169.%d.0/%d 192.168.3.1 " %(i,net)
    kargs={"smac":"00:11:ab:cd:ef:00","iface":"eth6","siaddr":"0.0.0.0","static_route_249":"249 %s" %(opt249.strip())}
    for i in range(1, len(sys.argv)):
        value=sys.argv[i].split("=")
        if len(value)==2 and len(value[1]) != 0:
            kargs[value[0]]=value[1]
    t=DhcpServer(**kargs)
    t.start()
