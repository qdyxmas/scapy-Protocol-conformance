#coding=utf-8
import struct
import uuid
import copy
import string,binascii,signal,sys,threading,socket,struct,getopt
import md5
from scapy.all import *

class PppoeServer(threading.Thread):
    def __init__(self,**kargs):
        threading.Thread.__init__(self)
        self.client_info = {}
        self.smac="c8:3a:35:33:44:55"   # default source mac address
        self.local_ip="11.1.1.1"
        self.iface="eth6"   #default interface
        self.usernames="tenda" #default username
        self.passwords="tenda" #default password
        self.sessionid=1
        self.pppoe_tags={"server_name":"","ac_name":"","ac_cookies":""} #default pppoe tags 
        self.lcp_options={"mru":"1492","auth":"pap","pfc":"","acfp":"","cbcp":"\x06"}   #default lcp options 
        # self.lcp_options={"mru":"1492","auth":"pap"}   #default lcp options 
        self.ipcp_options={"ip":"11.1.1.2","dns1":"223.1.1.1","dns2":"223.2.2.2","nbns1":"223.1.1.1","nbns2":"223.2.2.2"} #default ipcp options 
        self.lcp_id= 1
        self.ipcp_id=1
        self.pap_id = 0
        self.ipcp_flag = 0
        self.chap_id=84
        self.chap_flag = 0 ;#为1表示认证成功
        #loop pppoe_tags lcp_options ipcp_options
        for i in ['pppoe_tags','lcp_options','ipcp_options']:
            _optdict=getattr(self,i)
            for k,v in _optdict.items():
                setattr(self,k,v)
        self.lcp_up = [0,0];  #lcp链路建立起来的标准时 发送ACK和收到ACK ,第一个为收到ACK 第二个为发送ACK
        self.parser(**kargs)
        if kargs.has_key("smac"):
            self.smac=kargs['smac'].replace("-",":")
        self.filter="(pppoed or pppoes) and (ether dst %s or ether dst %s)" %(self.smac,"ff:ff:ff:ff:ff:ff")
        self.client_info[self.smac]=[self.username]
        self.client_info[self.smac].append(self.password)
        self.magicnum = self.random_magicnum()
    def parser(self,**kargs):
        for key,value in kargs.items():
            if key == "smac" or key == "dmac":
                value = ":".join(value.split("-"))
            setattr(self,key,value)
    def mac_incr(self,num):
        macnum=self.macnum+num
        return ":".join(map(lambda n: "%02X" %(macnum>>n & 0xFF),[40,32,24,16,8,0]))
    def add_pppoetags(self):
        #对self.pppoe_tags进行解析,解析后返回load的二进制形式的值
        pppoe_tag_code_dict={"server_name":"0101","ac_name":"0102"}
        load=""
        for k,v in self.pppoe_tags.items():
            if hasattr(self,k):
                #判断是否存在该变量
                value = getattr(self,k)
                load=load+pppoe_tag_code_dict[k]+"%04x" %(len(value))+self.str2hex(value)
        load=load+self.random_hostuiq()
        return self.hex2bin(load)
    def random_accookies(self):
         return "".join(random.sample("abcdefghijklmnopqrstuvwxyz0123456789",20))
    def random_magicnum(self):
        return self.hex2bin("".join(random.sample("0123456789abcdef",8)))
    def run(self):
        sniff(filter=self.filter,prn=self.detect_pppoeclient,store=0,iface=self.iface)
    def detect_pppoeclient(self,pkt):
        _type = {
            0x8863:{
                'code':{
                    0x09:self.send_pado_packet,
                    0x19:self.send_pads_packet
                }
            },
            0x8864:{
                # lcp proto packet
                'proto':{
                    0xc021:self.config_lcp_packet,
                    0xc223:self.send_chap_packet,
                    0xc023:self.send_pap_packet,
                    0x0021:self.send_ip_packet,
                    0x8021:self.send_ipcp_packet,
                    0x8057:self.send_ipv6cp_paket
                }
            }
        }
        if _type.has_key(pkt.type):
            #得到的数据包为PPPOE协议封装的数据包
            _methoddict = _type[pkt.type]   
            for k,v in _methoddict.items():
                _kVal = getattr(pkt,k)
                if _methoddict[k].has_key(_kVal):
                    _obj = _methoddict[k][_kVal]
                    _obj(pkt)
    def send_pado_packet(self,pkt):
        print u"PADO发送"
        #先解析出pppoe tag字段的值
        kargs={'0x0102':self.ac_name,'0x0101':self.server_name,'0x0104':self.random_accookies()}
        loadbin=self.update_option(load=pkt.load,key="pppoe",**kargs)
        #添加codename
        raw=copy.deepcopy(pkt)
        raw.src,raw.dst,raw.code=self.smac,pkt.src,0x07
        raw.len=len(loadbin)
        loadbin=self.appendbin(loadbin,len(loadbin))
        raw.load=loadbin
        sendp(raw,iface=self.iface)
    def send_pads_packet(self,pkt):
        kargs={'0x0101':self.server_name}
        #得到host-uniq
        hexstr=self.bin2hex(pkt.load)
        ret=self.parser_data(hexstr,"pppoe")
        ret.pop('0x0104')
        loadbin=''
        for k,v in ret.iteritems():
            kv_str=k[2:]+"%04x" %(len(v))+self.str2hex(v)
            loadbin=loadbin+self.hex2bin(kv_str)
        raw=copy.deepcopy(pkt)
        raw.src,raw.dst,raw.code=self.smac,pkt.src,0x65
        raw.sessionid=self.sessionid
        raw.len=len(loadbin)
        loadbin=self.appendbin(loadbin,len(loadbin))
        raw.load=loadbin
        sendp(raw,iface=self.iface)
        self.send_lcp_req(raw)
        #发送lcp_requests
    def config_lcp_packet(self,pkt):
        raw = copy.deepcopy(pkt)
        raw.src,raw.dst=pkt.dst,pkt.src
        # length=self.bin2hex(pkt.load[2:4])
        # length=eval("0x%s" %(length))
        length = struct.unpack("!H",pkt.load[2:4])[0]
        loadhex=self.bin2hex(pkt.load[4:length])
        ret=self.parser_data(loadhex,"lcp")
        print "before ret=",ret
        if pkt.load[0] == '\x01':
            # 对于auth不匹配 包含楚MRU和MagicNum其他的字段拒绝掉
            reject_flag = 0
            lcp_dict={'mru':'0x01','auth':'0x03','magic':'0x05'}
            loadbin="\x02" + pkt.load[1:]
            for key in lcp_dict.keys():
                if ret.has_key(lcp_dict[key]):
                    ret.pop(lcp_dict[key])
            print "after ret=",ret
            if ret:
                reject_flag=1 #表示要发送reject报文
                loadbin='\x04'+pkt.load[1]
                hexstr=''
                for key,value in ret.iteritems():
                    hexstr =hexstr+key[2:]+"%02x" %(2+len(value))+self.bin2hex(value)
                loadbin_len="%04x" %(len(hexstr)/2+4)
                loadbin=loadbin+self.hex2bin(loadbin_len)+self.hex2bin(hexstr)
                raw[PPPoE].len=len(hexstr)/2+6
            
            loadbin=self.appendbin(loadbin,raw[PPPoE].len)
            raw.load = loadbin
            sendp(raw,iface=self.iface)
            if not reject_flag:
                self.lcp_up[0]=1
        elif pkt.load[0] == '\x02':
            # print "ack_ ret=",ret
            self.echo_reply_magicnum=ret['0x05']
            self.lcp_up[1]=1
        elif pkt.load[0]=='\x03' or  pkt.load[0] == '\x04':
            #从字典中删除拒绝的字段
            #获取load中拒绝的字段代码,先得到长度字段,然后解析长度后面的字段
            #判断是否需要把拒绝字段踢掉
            print "lcp reject code=",ret
            for key in ret.keys():
                if self.lcp_options_dict.has_key(key):
                    self.lcp_options_dict.pop(key)
            self.send_lcp_req(raw)
            # self.lcp_up[1]=1
        elif pkt.load[0] == '\x09':
            #echo request报文回应
            if hasattr(self,'echo_reply_magicnum') and self.ipcp_flag:
                raw.load = '\x0a'+pkt.load[1:2]+'\x00\x08'+self.echo_reply_magicnum
                sendp(raw,iface=self.iface)
                #发送一个echo-request
                self.send_lcp_echo_request(pkt)
        elif pkt.load[0] == '\x05':
            raw.load='\x06'+pkt.load[1:]
            sendp(raw,iface=self.iface)
        elif pkt.load[0] == '\x0c':
            pass
        if self.lcp_up == [1,1]:
            # self.send_lcp_identifier(pkt)
            self.lcp_up = [0,0]
            if self.auth == "chap":
                #发送chap_requests
                self.send_chap_packet(pkt)
    def send_lcp_echo_request(self,pkt):
        self.lcp_id+=1
        loadbin="\x09" +self.num2bin(self.lcp_id)+'\x00\x08'+self.magicnum
        length=10   ;#2byte ppp header, 4byte lcp header
        loadbin=self.appendbin(loadbin,length)
        lcp_req=Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoED(version=1L,type=1L,code=0x00,sessionid=pkt.sessionid,len=length)/PPP(proto=0xc021)/Raw(load=loadbin)
        self.lcp_id+=1
        sendp(lcp_req,iface=self.iface)
    def send_lcp_req(self,pkt):
        #先组一个字典
        if not hasattr(self,"mrubinstr"):
            self.mrubinstr=self.tobin(int(self.mru),flag="num",leng=4)
        # 认证协商在nak中发送"0x03":_sd['auth'][self.auth]
        _sd={"mru":self.mrubinstr,"pap":'\xc0\x23',"chap":'\xc2\x23\x05'}
        if not hasattr(self,"magicnum"):
            self.magicnum = self.random_magicnum()
        if not hasattr(self,"lcp_options_dict"):
            self.lcp_options_dict={"0x01":_sd["mru"],'0x05':self.magicnum,'0x03':_sd[self.auth]}
        loadbin=self.update_option(load="",key="lcp",**self.lcp_options_dict)
        # print "length=",self.bin2hex(loadbin)
        prefix='\x01'+self.num2bin(self.lcp_id)+self.num2bin(len(loadbin)+4,4)
        loadbin=prefix+loadbin
        length=2+len(loadbin)   ;#2byte ppp header, 4byte lcp header
        loadbin=self.appendbin(loadbin,length) #用0补齐
        lcp_req=Ether(src=pkt.src,dst=pkt.dst,type=0x8864)/PPPoED(version=1L,type=1L,code=0x00,sessionid=pkt.sessionid,len=length)/PPP(proto=0xc021)/Raw(load=loadbin)
        self.lcp_id+=1
        sendp(lcp_req,iface=self.iface)
    def send_chap_packet(self,pkt):
        #先判断pkt里面协议,如果不为chap,则发送req,否则发送suc/fail
        if pkt.proto == 0xc021:
            #
            random_len=random.randint(10,20)*2
            random_value=random.sample(range(0,255),random_len)
            # if not hasattr(self,"channage_number"):
            self.channage_number="".join(map(lambda x:chr(x),list(random_value)))
            # self.channage_number=random_value
            chap_header_len=5+random_len+len(self.username)
            loadhex='01%02x%04x%02x%s%s' %(self.chap_id,chap_header_len,random_len,self.bin2hex(self.channage_number),self.str2hex(self.username))
            loadbin=self.hex2bin(loadhex)
            length=chap_header_len+2
            loadbin=self.appendbin(loadbin,length)
            chap_req=Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoED(version=1L,type=1L,code=0x00,sessionid=pkt.sessionid,len=length)/PPP(proto=0xc223)/Raw(load=loadbin)
            self.chap_id+=1
            sendp(chap_req,iface=self.iface)
        elif pkt.proto == 0xc223:
            if  pkt.load[0] == '\x02':
                ret={}
                ret['id']=pkt.load[1]
                length=struct.unpack("!B",pkt.load[4])[0]
                all_len=struct.unpack("!H",pkt.load[2:4])[0]
                ret['chall']=self.bin2hex(pkt.load[5:5+length])
                ret['username']=pkt.load[5+length:all_len]
                self.chap_response_num=0
                username=self.username
                if ret['username'] == self.username:
                    password=self.password
                    m=md5.new()
                    m.update(ret['id']+password+self.channage_number)
                    md5_value=m.hexdigest()
                    if md5_value.upper() == ret['chall'].upper():
                        #发送认证成功
                        msg="\x03"+ret['id']+'\x00\x12'+self.str2bin("Access granted")
                        self.chap_flag = 1
                    else:
                        msg="\x04"+ret['id']+'\x00\x11'+self.str2bin("Access denied")
                        #发送密码错误
                else:
                    # 发送用户名不存在
                    msg="\x04"+ret['id']+'\x00\x04'
                print "msg=",msg
                new_raw = copy.deepcopy(pkt)
                new_raw.dst, new_raw.src =pkt.src,pkt.dst
                msg=self.appendbin(msg,2+length)
                new_raw.load=msg
                new_raw.len=2+len(msg)
                sendp(new_raw,iface=self.iface)
                self.chap_response_num+=1
                if self.chap_flag:
                    #如果为1发送ipcp-req
                    #否则发送lcp-terminal
                    # time.sleep(0.5)
                    self.send_ipcp_req(pkt)
                else:
                    self.send_lcp_terminal(pkt)
    def send_lcp_terminal(self,pkt):
        randstr="".join(map(lambda x:chr(x),range(0,255)))
        loadbin="\x05"+pkt.load[1]+"\x00\x19"+"".join(random.sample(randstr,21))
        length=len(loadbin)+2
        loadbin=self.appendbin(loadbin,length)
        lcp_ter=Ether(src=pkt.src,dst=pkt.dst,type=0x8864)/PPPoED(version=1L,type=1L,code=0x00,sessionid=pkt.sessionid,len=length)/PPP(proto=0xc021)/Raw(load=loadbin)
        self.lcp_id+=1
        sendp(lcp_ter,iface=self.iface)
    def appendbin(self,loadbin,pppoe_len):
        #主要用于补齐不足64字节的文件
        binstr=loadbin
        randstr="".join(map(lambda x:chr(x),range(1,255)))
        if pppoe_len<40:
            if pppoe_len<36:
                binstr=loadbin+"\x00"*(36-pppoe_len)+'\xea\x94\xa5\xb3'
                # "".join(random.sample(randstr,4))
            else:
                binstr=loadbin+"".join(random.sample(randstr,40-pppoe_len))
            # binstr=loadbin+'\x00'*(40-pppoe_len)
        return binstr
    def send_pap_packet(self,pkt):
        #第一步解析获取得到username和password
        if pkt.proto == 0xc023:
            #得到user长度
            raw=copy.deepcopy(pkt)
            raw.src,raw.dst=pkt.dst,pkt.src
            userlen=ord(pkt.load[4])
            username=pkt.load[5:5+userlen]
            pass_start_pos=5+len(username)
            passlen=ord(pkt.load[pass_start_pos])
            password=pkt.load[pass_start_pos+1:pass_start_pos+1+passlen]
            
            flag=0
            code=3
            if username == self.username:
                if password == self.password:
                    #发送认证成功
                    code=2
                    msghex="08"+self.str2hex("Login ok")
                    flag=1
                else:
                    msghex="0e"+self.str2hex("Password error")
            else:
                msghex=self.str2hex("User invalid")
            #receive auth success
            pkt_len=4+len(msghex)/2
            loadhex="%02x%02x%04x%s" %(code,ord(pkt.load[1]),pkt_len,msghex)
            loadhex=loadhex
            loadbin=self.appendbin(self.hex2bin(loadhex),pkt_len)
            raw.load=loadbin
            raw[PPPoE].len=pkt_len+2
            sendp(raw,iface=self.iface)
            if flag:
                self.send_ipcp_req(pkt)
            else:
                self.send_lcp_terminal(pkt)
    def send_ipcp_req(self,pkt):
        if pkt.proto != 0x8021:
            obj=PPP_IPCP_Option_IPAddress()
            obj.len=6
            obj.data=self.local_ip
            ipcp_option_list=[obj]
        else:
            ipcp_option_list=self.parser_ipcp_options()
        opt_len=len(ipcp_option_list)*6
        pppoe_len=opt_len+4+2
        loadbin=''
        loadbin=self.appendbin(loadbin,pppoe_len)
        ipcp_req=Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoE(version=1L,type=1L,code=0,sessionid=pkt.sessionid,len=pppoe_len)/PPP(proto=0x8021)/PPP_IPCP(code=1,id=self.ipcp_id,len=opt_len+4,options=ipcp_option_list)/Raw(load=loadbin)
        sendp(ipcp_req,iface=self.iface)
    def send_ipcp_packet(self,pkt):
        #如果为认证成功的pap报文或者chap报文
        #进入这里说明收到的IPCP的 requests报文或者
        #如果为NAK(3) 则照着回应一个request(1) 如果为REQ(1) 则回应一个ACK(2)
        #如果为REJECT(4) ,解析拒绝的内容然后继续REQ(1)
        raw = copy.deepcopy(pkt)
        code=pkt[PPP_IPCP].code
        raw[PPP_IPCP].code=2
        #解析出ip dns1 dns2 等地址 ,如果均为0则不进行添加
        if  code== 0x01:
            ret=pkt.options
            ret_len=len(ret)
            map_ipcp_dict={"03":"ip","81":"dns1","82":"nbns1","83":"dns2","84":"nbns2"}
            # ipcp_dict={'ip':PPP_IPCP_Option_IPAddress,'dns1':PPP_IPCP_Option_DNS1,'dns2':PPP_IPCP_Option_DNS2,'nbns1':PPP_IPCP_Option_NBNS1,'nbns2':PPP_IPCP_Option_NBNS2}
            ipcp_dict={'ip':PPP_IPCP_Option_IPAddress,'dns1':PPP_IPCP_Option_DNS1,'dns2':PPP_IPCP_Option_DNS2}
            ipcp_list=[]
            for i in xrange(0,ret_len):
                if ret[i].data == "0.0.0.0":
                    raw[PPP_IPCP].code=3
                    ret[i].data=getattr(self,map_ipcp_dict["%02x" %(ret[i].type)])
            raw[PPP_IPCP].options=ret
            raw.src,raw.dst=pkt.dst,pkt.src
            print "raw.options=",raw.options
            sendp(raw,iface=self.iface)
            self.ipcp_flag=1
    def parser_ipcp_options(self):
        ipcp_dict={'ip':PPP_IPCP_Option_IPAddress,'dns1':PPP_IPCP_Option_DNS1,'dns2':PPP_IPCP_Option_DNS2,'nbns1':PPP_IPCP_Option_NBNS1,'nbns2':PPP_IPCP_Option_NBNS2}
        ret_str=[]
        for key,value in self.ipcp_options.items():
            if key in ipcp_dict.keys():
                obj=ipcp_dict[key]()
                obj.len=6
                obj.data=value
                ret_str.append(obj)
        return ret_str
    def send_ip_packet(self,pkt):
        pass
        #windows拨上号后会请求DNS
        # if DNS in pkt:
            # raw=copy.deepcopy(pkt)
            # print "pkt_raw=",pkt[DNS]
            # dns = pkt[DNS]
            # if dns.opcode == 0:
                # query = dns[DNSQR].qname.decode('ascii')
                # answer=DNSRR(rrname=str(query), type='A',ttl=1234,rdlen=4,rdata='1.1.1.1')
                # raw.src,pkt.dst=pkt.dst,pkt.src
                # raw[IP].src,raw[IP].dst=pkt[IP].src,pkt[IP].dst
                # raw[UDP].sport,raw[UDP].dport,raw[UDP].len=pkt[UDP].sport,pkt[UDP].dport,pkt[UDP].len+len(answer)
                # raw[DNS].an=answer
                # raw[DNS].id,raw[DNS].ancount,raw[DNS].qr=dns.id,1,1
                # print "raw_pkt",
                # sendp(raw,iface=self.iface)
    def send_ipv6cp_paket(self,pkt):
        #直接拒使用protocol reject_flag
        pass
    def update_option(self,load,key="pppoe",**kargs):
        #主要用于添加,删除,修改,查找load中某个字段的值
        #key 分别为pppoe lcp ipcp三种类型
        #第一步,先把load转换成16进制字符串形式,然后按照key进行拆分
        key_dict={"pppoe":4,"lcp":2,"ipcp":2}
        if load:
            loadhex=self.bin2hex(load)
            ret=self.parser_data(loadhex,key)
        else:
            ret={}
        new_ret=dict(ret,**kargs)
        loadbin=''
        for k,v in new_ret.iteritems():
            if len(v) == 0 and k !="0x0101":
                continue
            if key == "pppoe":
                kv_str=k[2:]+"%04x" %(len(v))+self.str2hex(v)
            else:
                kv_str=k[2:]+"%02x" %(len(v)+2)+self.str2hex(v)
            loadbin=loadbin+self.hex2bin(kv_str)
        return loadbin    
        
    def parser_data(self,allstr,key):
        #parser TLV data
        # print "parser_data allstr=",allstr
        key_dict={"pppoe":4,"lcp":2,"ipcp":2}
        par_len=key_dict[key]
        two_len=par_len*2
        x="%0"+str(par_len)+"x"
        ret={}
        #如果为lcp或者ipcp则需要减去头部2byte
        decress_len=0
        left_shift=8
        if par_len == 2:
            decress_len=two_len
            left_shift=0
        while True:
            if allstr:
                type=eval('0x'+allstr[0:par_len])
                length=eval('0x'+allstr[par_len:two_len])
                value=allstr[two_len:two_len+length*2-decress_len]
                ret["0x"+x %(type)]=self.hex2bin(value)
                allstr=allstr[left_shift+length*2:]
            else:
                break
        return ret
        
    def str2hex(self,allstr):
        return "".join(map(lambda x:"%02X" %(ord(x)),list(allstr)))
    def tobin(self,var,flag="str",leng=2):
        function=getattr(self,"%s2bin" %(flag))
        if flag == "num":
            return function(var,leng)
        else:
            return function(var)        
    def str2bin(self,allstr):
        #steps,str=>ascii(dec)==>ascii(hex)==>binstr
        hexstr="".join(map(lambda x:"%02X" %(ord(x)),list(allstr)))
        strbin=self.hex2bin(hexstr)
        return strbin
    def num2bin(self,num,leng="2"):
        hexstr=str("%0"+str(leng)+"X") %(num)
        binnum=self.hex2bin(hexstr)
        return binnum
    def ip2bin(self,ip,flag=". "):
        hexlist=re.split(r"[%s]" %(flag),ip)
        hexstr="".join(map(lambda x:"%02x" %(int(x)),hexlist))
        binip=self.hex2bin(hexstr)
        return binip
    def mac2bin(self,mac,flag=":-"):
        hexlist=re.split(r"[%s]" %(flag),mac)
        hexstr="".join(hexlist)
        binmac=self.hex2bin(hexstr)
        return binmac
    def hex2bin(self,hexstr):
        len_str=len(hexstr)
        retStr=""
        for i in range(0,len_str,2):
            substr=chr(int(hexstr[i:i+2],16))
            retStr=retStr+substr
        return retStr
    def bin2hex(self,binstr):
        hexstr="".join(map(lambda x:"%02X" %(ord(x)),list(binstr)))
        return hexstr
if __name__ == "__main__":
    kargs={'username':"tenda",'password':"tenda","server_name":"","ac_name":"tendatest","auth":"chap"}
    p=PppoeServer(**kargs)
    p.start()
