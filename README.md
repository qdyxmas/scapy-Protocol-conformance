# DhcpProtocal
dhclients.py:
  主要通过发包模拟发送指定字段的discover/request/decline/release等报文,并把交互中的关键字段保存到日志中.
  主要功能有:
    1、模拟正常的dhcp客户端四次交互
    2、模拟多个客户端耗尽地址池
    3、直接发送广播的request报文
    4、发送单播的request报文
dhcpserver.py
  主要通过发包模拟发送指定字段的offer/ack/nak报文
    主要功能:
      1、正常的DHCP服务器功能
      2、回应时能够对discover/request/T1时刻的request/T2时刻的request报文 进行延迟响应或者不响应
