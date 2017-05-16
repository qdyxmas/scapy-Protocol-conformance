# scapy-dhcp
ScapyDhclient.py:</br>
  主要通过发包模拟发送指定字段的discover/request/decline/release等报文,并把交互中的关键字段保存到日志中.</br>
  主要功能有:</br>
    1、模拟正常的dhcp客户端四次交互</br>
    2、模拟多个客户端耗尽地址池</br>
    3、直接发送广播的request报文</br>
    4、发送单播的request报文</br></br>
ScapyDhcpd.py</br>
  主要通过发包模拟发送指定字段的offer/ack/nak报文</br>
  主要功能:</br>
      1、正常的DHCP服务器功能 </br>
      2、回应时能够对discover/request/T1时刻的request/T2时刻的request报文 进行延迟响应或者不响应</br>
注意:使用其他options字段时,需要在scapy的dhcp.py的options选项中添加字段,否则不会下发</br>
dhcp<a href="http://www.networksorcery.com/enp/rfc/rfc2132.txt">参考RFC3132</a></br>
ScapyPppoeClient.py:</br>
  主要用于模拟测试pppoe客户端拨号</br>
    pppoe-tags 配置可选的pppoe-tags字段 servername ac-name </br>
    lcp-options 配置可选的lcp-options  mru authentication-protocol 等信息</br>
    ipcp-options 配置可选的ipcp-options ip dns nbns等信息</br>
ScapyPppoeServer.py:</br>
  主要用于模拟测试pppoe客户端拨号</br>
    pppoe-tags 配置可选的pppoe-tags字段 servername ac-name </br>
    lcp-options 配置可选的lcp-options  mru authentication-protocol 等信息</br>
    ipcp-options 配置可选的ipcp-options ip dns nbns等信息</br>

