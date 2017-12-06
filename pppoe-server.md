# rp-pppoe配置学习 #
	linux 下的pppoe服务器配置
	1.用户名密码配置文件/etc/ppp/chap-secrets或者/etc/ppp/pap-secrets
		# Secrets for authentication using PAP
		# username    server      password     ip
		username:客户端认证时使用的用户名
		server:服务器端认证时使用的用户名(使用此字段时表示需要双向认证),为*表示任意
		password:认证密码,客户端和服务端必须一样
		ip:如果为*表示接收从服务器端分配的IP地址，如果为指定IP地址时表示请求服务器分配该IP地址给客户端,如果服务器地址池没有该地址，则IPCP协商无法完成
	2.lcp/ipcp协商过程中的选项/etc/ppp/pppoe-server-options(可以在pppoe-server -O指定)
		defaultroute: 如果有此参数 客户端连接播上号以后会下发给客户端一条默认路由 网关为服务器pppN接口地址，ppp断开以后,默认路由自动删除
		mru:lcp协商中的mru
		mtu:lcp 协商中的mtu
		require-chap:表示采用chap认证
		refuse-chap:表示拒绝使用chap认证
		require-mppe:表示需要使用mppe加密(40或者128)
		require-mppe-128:表示只允许mppe 128位加密
		unit:表示生成的ppp接口(unit 1 表示拨号后生成的接口为ppp1)
		ms-dns:表示下发给客户端的dns值
		multilink:表示开启多链路模式
	3.pppoe-server选项
		Usage: pppoe-server [options]
		Options:
		   -I if_name     -- 绑定指定接口 (默认eth0)
		   -T timeout     -- pppoe完成会话阶段等待时间
		   -C name        -- pppoe发现阶段ACNAME字段
		   -L ip          -- 设置本端接口地址
		   -l             -- 
		   -R ip          -- 设置分配的地址池起始地址
		   -S name        -- pppoe协商中ServerName
		   -O fname       -- 设置配置文件
		   -p fname       -- 从指定文件中获取分配的地址池地址
		   -N num         -- 允许多少个会话
		   -u             -- 设置连接后pppN接口的N值
