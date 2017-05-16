#coding=utf-8
import struct
import uuid
import copy
import string,binascii,signal,sys,threading,socket,struct,getopt
import md5
from scapy.all import *

class PppoeClient(threading.Thread):
    def __init__(self,**kargs):
        threading.Thread.__init__(self)
        self.client_info = {}
        self.smac="00:11:22:33:44:55"   # default source mac address
        self.iface="eth6"   #default interface
        self.usernames="tenda" #default username
        self.passwords="tenda" #default password
        self.pppoe_tags={"server_name":"","ac_name":""} #default pppoe tags 
        self.lcp_options={"mru":"1492","auth":"pap","pfc":"","acfp":"","cbcp":"\x06"}   #default lcp options 
        self.ipcp_options={"ip":"0.0.0.0","dns1":"0.0.0.0","dns2":"0.0.0.0","nbns1":"0.0.0.0","nbns2":"0.0.0.0"} #default ipcp options 
        self.lcp_id= 1
        self.ipcp_id=1
        self.pap_id = 0
        self.ipcp_flag = 0
        #loop pppoe_tags lcp_options ipcp_options
        for i in ['pppoe_tags','lcp_options','ipcp_options']:
            _optdict=getattr(self,i)
            for k,v in _optdict.items():
                setattr(self,k,v)
        self.lcp_up = [0,0];  #lcp链路建立起来的标准时 发送ACK和收到ACK ,第一个为收到ACK 第二个为发送ACK
        self.parser(**kargs)
        if kargs.has_key("smac"):
            self.smac=kargs['smac'].replace("-",":")
        self.filter="(pppoed or pppoes) and ether dst %s" %(self.smac)
    def parser(self,**kargs):
        for key,value in kargs.items():
            if key == "smac" or key == "dmac":
                value = ":".join(value.split("-"))
            setattr(self,key,value)
    def mac_incr(self,num):
        macnum=self.macnum+num
        return ":".join(map(lambda n: "%02X" %(macnum>>n & 0xFF),[40,32,24,16,8,0]))
    def toHex(self,num):
        return int(num,16)	
    def send_padi_packet(self,smac=""):
        if smac == "":
            smac=self.smac
        len_sername=0
        loadbin=self.add_pppoetags()
        padi_discover=Ether(src=smac,dst="ff:ff:ff:ff:ff:ff",type=0x8863)/PPPoED(version=1L,type=1L,code=0x09,sessionid=0x0,len=len(loadbin))/Raw(load=loadbin)
        sendp(padi_discover,iface=self.iface)
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
    def random_hostuiq(self):
         return "0103000c"+"".join(random.sample("0123456789abcdef0123456789abcdef",24))
    def random_magicnum(self):
        return self.hex2bin("".join(random.sample("0123456789abcdef",8)))
    def run(self):
        sniff(filter=self.filter,prn=self.detect_pppoeclient,store=0,iface=self.iface)
    def detect_pppoeclient(self,pkt):
        _type = {
            0x8863:{
                'code':{
                    0x07:self.send_padr_packet,
                    0x65:self.config_lcp_packet
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
    def send_padr_packet(self,pkt):
        print u"PADR发送"
        #把数据包的ac-name去掉后重新组数据包,最后发送出去
        #如果需要修改padr值在这里修改
        kargs={'0x0102':self.ac_name,'0x0101':self.server_name}
        loadbin=self.update_option(load=pkt.load,key="pppoe",**kargs)
        #添加codename
        raw=copy.deepcopy(pkt)
        raw.src,raw.dst,raw.code=pkt.dst,pkt.src,0x19
        raw.len=len(loadbin)
        raw.load=loadbin
        # length=len(load_str)
        # padr_packet=Ether(src=smac,dst=dmac,type=0x8863)/PPPoED(version=1L,type=1L,code=code,sessionid=0x0,len=length)/Raw(load=load_str)
        sendp(raw,iface=self.iface)
    def config_lcp_packet(self,pkt):
        if pkt.type == 0x8863:
            self.send_lcp_req(pkt)
        else:
            raw = copy.deepcopy(pkt)
            raw.src,raw.dst=pkt.dst,pkt.src
            length=self.bin2hex(pkt.load[2:4])
            length=eval("0x%s" %(length))
            loadhex=self.bin2hex(pkt.load[4:length])
            ret=self.parser_data(loadhex,"lcp")
            if pkt.load[0] == '\x01':
                # 没有收到确认报文之前 不给服务器回应lcp_ACK
                #判断如果认证方式不一致则拒绝
                raw.load = "\x02" + pkt.load[1:]
                auth_dict={'chap':'\xc2\x23\x05',"pap":'\xc0\x23'}
                print "lcp_req ret=",ret
                auth="0"
                if ret.has_key('0x03'):
                    auth=ret['0x03']
                if auth == auth_dict[self.auth]:
                    if self.lcp_up[1] == 1:
                        sendp(raw,iface=self.iface)
                        self.lcp_up[0]=1
                elif auth != "0":
                    #lcp_request报文
                    auth_length=len(auth_dict[self.auth])+2
                    ipcp_len=4+auth_length
                    ppp_len=2+ipcp_len
                    loadhex="03"+self.bin2hex(pkt.load[1])+"%04x" %(ipcp_len)+'03'+"%02x" %(auth_length)+self.bin2hex(auth_dict[self.auth])
                    loadbin=self.hex2bin(loadhex)
                    raw[PPPoE].len=ppp_len
                    raw.load = loadbin
                    sendp(raw,iface=self.iface)
            elif pkt.load[0] == '\x02':
                print "ack_ ret=",ret
                self.echo_reply_magicnum=ret['0x05']
                self.lcp_up[1]=1
            elif pkt.load[0] in '\x03 \x04':
                #从字典中删除拒绝的字段
                #获取load中拒绝的字段代码,先得到长度字段,然后解析长度后面的字段
                #判断是否需要把拒绝字段踢掉
                for key in ret.keys():
                    if self.lcp_options_dict.has_key(key):
                        self.lcp_options_dict.pop(key)
                self.send_lcp_req(pkt)
                # self.lcp_up[1]=1
            #如果有2个ACK后则进入Identifer发送
            elif pkt.load[0] == '\x09':
                #echo request报文回应
                raw.load = '\x0a'+pkt.load[1:2]+'\x00\x08'+self.echo_reply_magicnum
                sendp(raw,iface=self.iface)
            elif pkt.load[0] == '\x05':
                raw.load='\x06'+pkt.load[1:]
                sendp(raw,iface=self.iface)
            if self.lcp_up == [1,1]:
                self.send_lcp_identifier(pkt)
                self.lcp_up = [0,0]
                if self.auth == "pap":
                    self.send_pap_packet(pkt)
                
    def send_lcp_identifier(self,pkt):
        loadbin="\x0c" + self.num2bin(self.lcp_id)+'\x00\x11'+self.magicnum+self.str2bin("tendatest")
        length=6+len(loadbin)   ;#2byte ppp header, 4byte lcp header
        lcp_req=Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoED(version=1L,type=1L,code=0x00,sessionid=pkt.sessionid,len=length)/PPP(proto=0xc021)/Raw(load=loadbin)
        self.lcp_id+=1
        sendp(lcp_req,iface=self.iface)
    def send_lcp_req(self,pkt):
        #先组一个字典
        if not hasattr(self,"mrubinstr"):
            self.mrubinstr=self.tobin(int(self.mru),flag="num",leng=4)
        # _sd={"mru":self.mrubinstr,"auth":{'chap':"\xc2\x23\x05","pap":"\xc0\x23"}}
        # 认证协商在nak中发送"0x03":_sd['auth'][self.auth]
        _sd={"mru":self.mrubinstr}
        if not hasattr(self,"magicnum"):
            self.magicnum = self.random_magicnum()
        if not hasattr(self,"lcp_options_dict"):
            self.lcp_options_dict={"0x01":_sd["mru"],'0x05':self.magicnum,"0x07":self.pfc,"0x08":self.acfp,"0x0d":self.cbcp}
        loadbin=self.update_option(load="",key="lcp",**self.lcp_options_dict)
        # print "length=",self.bin2hex(loadbin)
        prefix='\x01'+self.num2bin(self.lcp_id)+self.num2bin(len(loadbin)+4,4)
        loadbin=prefix+loadbin
        length=2+len(loadbin)   ;#2byte ppp header, 4byte lcp header
        lcp_req=Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoED(version=1L,type=1L,code=0x00,sessionid=pkt.sessionid,len=length)/PPP(proto=0xc021)/Raw(load=loadbin)
        self.lcp_id+=1
        sendp(lcp_req,iface=self.iface)
    def send_lcp_packet(self,pkt):
        pass
    def send_chap_packet(self,pkt):
        #从pkt.load[4:]表示后面的Data部分
        #第一步解析chap报文得到ID值 chall值,返回的字典中有id:字符串 chall:字符串
        #先判断为requests还是认证成功信息
        #收到请求成功后则开始IPCP协商
        if  pkt.load[0] == '\x03':
            print "receive chap suc ipcp_packet"
            self.send_ipcp_req(pkt)
        elif pkt.load[0] == '\x01':
            ret={}
            ret['id']=pkt.load[1]
            length_str='0x'+self.bin2hex(pkt.load[4])
            length=eval(length_str)
            ret['chall']=pkt.load[5:5+length]
            #md5(id+passwd+chall)
            self.chap_response_num=0
            username=self.client_info[pkt.dst][0]
            password=self.client_info[pkt.dst][1]
            m=md5.new()
            m.update(ret['id']+password+ret['chall'])
            md5_value=m.hexdigest()

            header_len=21+len(username)
            load_str='02'+self.bin2hex(ret['id'])+"%04X" %(header_len)+"10"+md5_value+"".join(self.str2hex(username))
            load=self.hex2bin(load_str)
            new_raw = copy.deepcopy(pkt)
            new_raw.dst, new_raw.src =pkt.src,pkt.dst
            new_raw.load=load
            new_raw.len=2+len(load)
            sendp(new_raw,iface=self.iface)
            self.chap_response_num+=1
    def send_pap_packet(self,pkt):
        if pkt.proto == 0xc023:
            #receive auth success
            self.send_ipcp_req(pkt)
        elif pkt.proto == 0xc021:
            #receive lcp packet
            userpwd=self.client_info[pkt.dst]
            user_len=len(userpwd[0])
            pass_len = len(userpwd[1])
            length_pap = user_len+pass_len+6
            loadhex='01'+"%02x%04x%02x" %(self.pap_id,length_pap,user_len)+self.str2hex(userpwd[0])+"%02x" %(pass_len)+self.str2hex(userpwd[1])
            loadbin=self.hex2bin(loadhex)
            print "loadhex=",loadhex
            pppoe_len=length_pap+2
            raw = Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoE(version=1L,type=1L,code=0,sessionid=pkt.sessionid,len=pppoe_len)/PPP(proto=0xc023)/Raw(load=loadbin)
            sendp(raw,iface=self.iface)
    def send_ipcp_req(self,pkt):
        ipcp_option_list=self.parser_ipcp_options()
        opt_len=len(ipcp_option_list)*6
        pppoe_len=opt_len+4+2
        ipcp_req=Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoE(version=1L,type=1L,code=0,sessionid=pkt.sessionid,len=pppoe_len)/PPP(proto=0x8021)/PPP_IPCP(code=1,id=self.ipcp_id,len=opt_len+4,options=ipcp_option_list)
        sendp(ipcp_req,iface=self.iface)
    def send_ipcp_packet(self,pkt):
        #如果为认证成功的pap报文或者chap报文
        #进入这里说明收到的IPCP的 requests报文或者
        #如果为NAK(3) 则照着回应一个request(1) 如果为REQ(1) 则回应一个ACK(2)
        #如果为REJECT(4) ,解析拒绝的内容然后继续REQ(1)
        raw = copy.deepcopy(pkt)
        code=pkt[PPP_IPCP].code
        if  code== 0x01 or code == 0x03:
            code_dict={1:2,3:1}
            raw.src,raw.dst,raw[PPP_IPCP].code=pkt.dst,pkt.src,code_dict[code]
            sendp(raw,iface=self.iface)
        elif code == 0x04:
            #remove reject options
            reject_code=[]
            for i in pkt.options:
                reject_code.append('0x'+"%02x" %(i.type))
            map_ipcp_dict={"0x03":"ip","0x81":"dns1","0x82":"nbns1","0x83":"dns2","0x84":"nbns2"}
            for k in reject_code:
                if self.ipcp_options.has_key(map_ipcp_dict[k]):
                    self.ipcp_options.pop(map_ipcp_dict[k])
            self.send_ipcp_req(raw)
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
    def send_ipv6cp_paket(self,pkt):
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
    kargs={'username':"tenda2",'password':"tenda2","server_name":"","ac_name":"tendatest","auth":"pap"}
    p=PppoeClient(**kargs)
    p.start()
    p.send_padi_packet()
