一、防火墙的基本概念
{
	1、TCP/IP的基本概念
		应用层
		传输层
		网络层
		链路层

	2、端口的分类
		公认的端口：1-1023
		注册的端口：1024-49151
		动态端口：49152-65535

	3、防火墙的判断依据：
		链路层
			MAC地址
		网络层
			Header Length
			Differentiated服务
			Total Length
			Flags
			Time to Live
			Protocol
			Source
			Destination
		网络传输层
			Source Port
			Destination Port
			Header Length
			Flags
	4、防火墙的分类：
		数据包过滤防火墙
			优点：
				数据包过滤防火墙每一次执行检查的最小单位是“一个数据包”
				数据包过滤防火墙对内存和CPU性能的要求较低，由此可知，数据包过滤防火墙的成本较低
			缺点：
				因为数据包过滤防火墙的检查范围只有一个数据包，因此数据包过滤防火墙无法对连接中的数据进行更精准的过滤操作。比如无法使用它检查一封电子邮件中是否携带病毒
		应用层防火墙
			优点：
				应用层防火墙能够检查任何一个连接中的任何字节，因此应用层防火墙能够进行比数据包过滤防火墙更精准的过滤操作
			缺点：
				无法处理应用程序过滤进程不支持的通信协议
				需要更多的内存，对CPU性能的要求也高，导致成本较高

	5、常见的防火墙结构
		单机防火墙
		网关式防火墙
			网关式防火墙类型1（一对一NAT）
			网关式防火墙类型2（防火墙配置3块网卡，DMZ）
			网关式防火墙类似3（2台防火墙）
		透明防火墙
			透明防火墙是一个网桥设备，并且在网桥设备上赋予了过滤器功能。因为网桥是工作在OSI第二层的网络设备，因此不会有任何路由的问题，并且网桥上可以不需要设置任何的IP。所以透明防火墙的部署能力相当强，隐蔽性相当高，即使黑客要攻击这个防火墙，也可能因为没有目的端IP而无功而返。
}

二、Netfilter/iptables
{
	Netfilter模块存放位置：
		/lib/modules/2.6.32-573.12.1.el6.x86_64/kernel/net/ipv4/netfilter
		/lib/modules/2.6.32-573.12.1.el6.x86_64/kernel/net/ipv6/netfilter
	4表，5链
	filter（执行数据包的过滤操作，也就是起到防火墙的作用）
		INPUT
		FORWARD
		OUTPUT
	nat（IP分享器）
		PREROUTING
		POSTROUTING
		OUTPUT
	mangle（经过mangle机制来修改经过防火墙内数据包的内容）
		PREROUTING
		INPUT
		FORWARD
		OUTPUT
		POSTROUTING
	raw（负责加快数据包穿过防火墙机制的速度）
		PREROUTING
		OUTPUT

	Netfilter的filter机制（假定某台主机安装了2个网卡，并且允许了httpd和firefox程序）
		INPUT类型：指网络上其他使用者访问本机的httpd服务时，就会生成这种类型的数据包
		OUTPUT类型：如果是“本机进程”所生成的数据包，即为OUTPUT类型的数据包。例如本机启动firefox去访问网络上的其他主机，就会生成这种类型的数据包
		FORWARD类型：如果数据包对本机而言只是“路过”而已，那么这就属于FORWARD类型的数据包。例如本机扮演的路由器的角色

	iptables配置命令
		-L：将所选择的表内容列出
		-A：在指定的链中添加新规则
		-F：将所选择的表内容清除掉
		-P：设置某个链的默认策略
		-I：插入新规则
		-R：取代规则
		-D：删除规则
		iptables -t TABLE -操作方式 规则条件
			iptables -t filter -L #列出filter表的所有内容
			iptables -t filter -A INPUT -p icmp -j ACCEPT #将规则添加到filter表的INPUT链中
			iptables -t filter -P FORWARD DROP #将FORWARD链的默认策略设置为DROP
	iptables基本语法
		iptables -t filter -A INPUT -p icmp -j DROP
	iptables高级语法
		iptables -t filter -A INPUT -m mac --mac-source 00:E0:18:00:7C:A4 -j DROP

		iptables -A INPUT -p tcp -s 192.168.0.200 --dport 23 -j ACCEPT
		iptables -A INPUT -p all -s 192.168.1.0/24 -d 192.168.0.1 -j ACCEPT
		iptables -A OUTPUT -o eth0 -p tcp -d !edu.uuu.com.tw --dport 80 -j REJECT

	配置防火墙规则的原则：先拒绝所有连接，再逐一开放对外提供的服务

	配置单机防火墙
		1、在主机192.168.0.1启用SSH,TELNET,SMTP,WEB,POP3
		2、测试客户端分别为192.168.0.100，192.168.0.200
		3、网络上的任何主机都能正常访问192.168.0.1主机的SSH及TELNET以为的服务
		4、网络上只有192.168.0.200这台主机可正常访问192.168.0.1主机上的所有服务
			iptables -P INPUT DROP
			iptables -A INPUT -p tcp -d 192.168.0.1 --dport 25 -j ACCEPT
			iptables -A INPUT -p tcp -d 192.168.0.1 --dport 80 -j ACCEPT
			iptables -A INPUT -p tcp -d 192.168.0.1 --dport 110 -j ACCEPT
			iptables -A INPUT -p tcp -s 192.168.0.200 -d 192.168.0.1 --dport 22 -j ACCEPT
			iptables -A INPUT -p tcp -s 192.168.0.200 -d 192.168.0.1 --dport 23 -j ACCEPT
	如何测试防火墙规则正确与否
		1、网络上任意主机对服务器的访问测试
		2、服务器主机对网络上其他主机的访问测试

	防火墙的连接状态
		NEW：指的是每一个连接中的第一个数据包
		ESTABLISHED：
		RELATED：“被动产生的应答数据包，而且这个数据包不属于现在任何的连接”，RELATED状态的数据包与“协议”无关，只要应答的数据包是因为本机先送出一个数据包而导致另一条连接的产生，那么这个新连接的所有数据包都属于RELATED状态的数据包
		INVALID：是指状态不明的数据包。
			iptables -A INPUT -p all -m state --state INVALID -j DROP
		#bash脚本
		#!/bin/bash
		IPT=/sbin/iptables
		SERVER=192.168.0.1
		PARTNER=192.168.0.200

		$IPT -t filter -F

		$IPT -A INPUT -p tcp -m state --state INVALID -j DROP
		$IPT -A INPUT -p tcp -d $SERVER --dport 25 -j ACCEPT
		$IPT -A INPUT -p tcp -d $SERVER --dport 80 -j ACCEPT
		$IPT -A INPUT -p tcp -d $SERVER --dport 110 -j ACCEPT
		$IPT -A INPUT -p tcp -s $PARTNER -d $SERVER --dport 22 -j ACCEPT
		$IPT -A INPUT -p tcp -s $PARTNER -d $SERVER --dport 23 -j ACCEPT
		$IPT -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT

	构建网关式防火墙(eth0接公网，eth1接私网)
		1、10.0.100是因特网上的一台主机，开启了SMTP,POP3,HTTP服务
		2、内部网段为192.168.0.0/24
		3、192.168.0.200只能访问10.0.1.100主机的SMTP,POP3服务
		4、192.168.0.0/24网段上的其他主机只可以访问因特网上的DNS，SMTP,POP3,HTTP,HTTPS服务
		5、因特网上的主机不得访问企业内部的任何主机

		#!/bin/bash
		IPT=/sbin/iptables
		MAIL_SRV=10.0.1.100
		ACC_PC=192.168.0.200

		$IPT -t filter -P INPUT DROP
		$IPT -t filter -P FORWARD DROP

		$IPT -t filter -F

		$IPT -A INPUT -p tcp -m state --state INVALID -j DROP
		$IPT -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT

		$IPT -A FORWARD -i eth0 -o eth1 -m state --state INVALID -j DROP
		$IPT -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT
		$IPT -A FORWARD -i eth1 -o eth0 -p tcp -s $ACC_PC -d $MAIL_SRV --dport 25,110 -j ACCEPT
		$IPT -A FORWARD -i eth1 -o eth0 -p all -s $ACC_PC -j DROP（为啥需要添加这一条规则）

		$IPT -A FORWARD -i eth1 -o eth0 -p tcp --dport 25,110 -j ACCEPT
		$IPT -A FORWARD -i eth1 -o eth0 -p tcp --dport 80,443 -j ACCEPT
		$IPT -A FORWARD -i eth1 -o eth0 -p udp --dport 53 -j ACCEPT

	netfilter的NAT机制
		变更source IP的机制称为SNAT
		变更Destination IP的机制称为DNAT

		PREROUTIN,ROUTING TABLE,POSTROUTING并没有规定在特定的一侧，关键在于数据包的流向

		当我们下发规则要去修改数据包哆点Destination IP时，请将该规则放在PREROUTING链中，因为PREROUTING链的功能在于执行DNAT的任务
		POSTROUTING链的任务是修改数据包的来源IP，也就是说POSTROUTING链的功能在于执行SNAT的任务

	一对多NAT
		iptables -t nat -A POSTROUTING -o eth0 -s 192.168.0.0/24 -j SNAT --to 10.0.1.200
		iptables -t nat -A POSTROUTING -o eth0 -s 192.168.0.0/24 -j MASQUERADE

	多对多NAT
		iptables -t nat -A POSTROUTING -o eth0 -s 192.168.0.0/24 -j SNAT --to 10.0.1.200-10.0.1.205

	一对一NAT（需要考虑数据包进出的问题）
	注意:POSTROUTING链是以数据包“离开”的接口来标明数据包的流向，如-o eth0
		 PREROUTING链则是以数据包“进入”的接口来标明数据包的流向，如-i eth0
		iptables -t nat -A PREROUTING -i eth0 -d 10.0.1.201 -j DNAT --to 192.168.0.1
		iptables -t nat -A POSTROUTING -o eth0 -s 192.168.0.1 -j SNAT --to 10.0.1.201

	NAPT
		iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to 192.168.0.1:80
		iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j DNAT --to 192.168.0.1:443
		iptables -t nat -A POSTROUTING -o eth0 -s 192.168.0.0/24 -j SNAT --to 10.0.1.201

	Mangle提供的功能：
		1、修改IP包头的TTL值
		2、修改IP包头的DSCP值或对特定的数据包设置特征
            QOS的机制可以让我们在有限的带宽中，有效分配不同的带宽给不同的协议使用。
                QOS的机制有两个不同的部分组成，其一为“数据包分类器”，其二为“带宽分配器”
                    通过IP包内的DSCP值来分类
                    使用Mangle机制为数据包标示识别码
            如果想要改变本机进程所生成的数据包内的DSCP值，就必须将规则放置于OUTPUT链之中，或是POSTROUTING链都可以达到我们的目的。
			iptables -t mangle -A OUTPUT -p tcp --dport 22 -j DSCP --set-dscp 43
}

三、Netfilter的匹配方式及处理方法
{
	内置的匹配方式：
		filter：iptable_filter.ko
		NAT：iptable_nat.ko
		mangle：iptable_mangle.ko
		raw：iptable_raw.ko
			1、接口的匹配方式
				-i
				-o
			2、源地址、目标IP匹配
				-s
				-d
			3、协议匹配方式
				-p tcp
				-p udp
				-p icmp
				/etc/protocol
				icmp请求包：type=8、code=0
				icmp应打包：type=0、code=0
	从模块扩展而来的匹配方式：
	/lib/modules/2.6.32-573.12.1.el6.x86_64/kernel/net/netfilter
	/lib/modules/2.6.32-573.12.1.el6.x86_64/kernel/net/ipv4/netfilter
	/lib/modules/2.6.32-573.12.1.el6.x86_64/kernel/net/ipv6/netfilter
		1、TCP/UDP协议的匹配方式
			TCP协议高级匹配
				端口号（源端口、目标端口号）
				TCP-Flags
					位1---fin-->连接终止信号
					位2---syn-->连接请求信号
					位3---reset-->立即终止连接
					位4---ack-->确认应答信号
						iptables -A INPUT -p tcp --syn --dport 22 -m state --state NEW -j ACCEPT
						iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN -j DROP #检查所有TCP-Flags，但只有syn和fin两个标记同时为1时数据包才会筛选出来
						iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP #只检查syn和fin两个标记，而且这两个标记必须同时为1
			UDP协议高级匹配
				--sport
				--dport
		2、MAC地址匹配（模块名称xt_mac.ko）
			iptables -A INPUT -p tcp --dport 3306 -m mac --mac-source 00:50:56:C0:00:01 -j ACCEPT
		3、Multiport匹配（模块名称xt_multiport.ko）
			iptables -A INPUT -p tcp --syn -m state --state NEW -m multiport --dports 21,22,23,25,80,110,443 -j ACCEPT
		4、匹配数据包的MARK值（模块名称xt_MARK.ko）
			iptables -t mangle -A PREROUTING -p tcp --dport 80 -j MARK --set-mark 80
			iptables -A FORWARD -p all -m mark --mark 80 -j DROP
		5、owner的匹配（模块名称ipt_owner.ko）
			--uid -owner userid|username
			--gid -owner groupid|groupname
				iptables -A OUTPUT -p tcp -m owner --uid-owner jacky --dport 80 -j ACCEPT
				iptables -A OUTPUT -p tcp -m owner --gid-owner sales --dport 80 -j ACCEPT
		6、IP范围的匹配
			--src-range
			--dst-range
				iptables -A INPUT -m iprange --src-range 192.168.0.2-192.168.0.61 -j DROP
		7、TTL匹配（模块名称ipt_ttl.ko）
            Windows系统的默认值为128，Linux系统默认值是64
			-m ttl --ttl-eq 64
			-m ttl --ttl-lt 64
			-m ttl --ttl-gt 64
				iptables -A INPUT -m ttl --ttl-eq 64 -j REJECT
		8、数据包状态匹配（模块名称xt_state.ko）
            TCP的连接状态：ESTABLISHED、SYN_SENT、SYN_RECV、FIN_WAIT1、FIN_WAIT2、TIME_WAIT、CLOSED、CLOSE_WAIT、LAST_ACK、LISTEN、CLOSING、UNKNOWN
			Netfilter的状态：NEW,ESTABLISHED,RELATED,INVALID
		9、AH及ESP协议的SPI值匹配（模块名称ipt_ah.ko及xt_esp.ko）
			IPSec的加密通信中包含了两个协议，分别是AH（认证头）及ESP（封装安全负载），其中AH负责进行数据包的“完整性验证”，ESP负责进行数据包的“加密”操作
			iptables -A FORWARD -p ah -m ah --ahspi 300 -j ACCEPT
			iptables -A FORWARD -p esp -m esp --espspi 200 -j ACCEPT
		10、pkttype匹配（模块名称xt_pkttype.ko）
				unicast
				broadcast
				multicast
					iptables -A FORWARD -i eth0 -p icmp -m pkttype --pkt-type broadcast -j DROP
		11、length(MTU)匹配（模块名称xt_length.ko）
				此处以ICMP包为例
				MTU：实体网络层每一次所能传输数据大小的上限。MTU=(ip包头+ICMP包头+DATA)
				MSS：MSS=(ICMP包头+DATA)
				--length---->匹配MTU值刚好为100个字节的数据包
				--length:100--->匹配MTU值小于100个字节的数据包
				--length 50:100--->匹配MTU值介于50-100个字节的数据包
					iptables -A INPUT -p icmp --icmp-type 8 -m length --length 92 -j ACCEPT
		12、limit特定数据包重复率的匹配（模块名称xt_limit.ko）
				#如果每分钟允许进入ICMP包数量为10个，但如果在1分钟内进来了超过10个以上的ICMP包，那么我们就限制每分钟只能进来6个ICMP包
				iptables -A INPUT -p icmp --icmp-type 8 -m limit --limit 6/m --limit-burst 10 -j ACCEPT
				iptables -A INPUT -p icmp --icmp-type 8 -j DROP
		13、recent特定数据包重复率匹配（先取证，后处理）（模块名称xt_recent.ko）
				#希望每分钟只能进来6个ICMP包，如果超过这个数量就将之丢弃掉
				iptables -A INPUT -p icmp --icmp-type 8 -m recent --name icmp_db --rcheck --second 60 --hitcount 6 -j DROP
				iptables -A INPUT -p icmp --icmp-type 8 -m recent --set --name icmp_db
				--name：设置跟踪数据库的文件名
				--set ：将符合条件的来源数据添加到数据库中，但如果来源端数据已经存在，则更新数据库中的记录信息
				--rcheck：只进行数据库中信息的匹配，并不会对已存在的数据做任何变更操作
				--update：如果来源端的数据已存在，则将其更新，若不存在，则不做任何处理
				--remove：如果来源端的数据已存在，则将其删除，若不存在，则不做任何处理
				--seconds second：当事件发生时，只会匹配数据库中前“几秒”内的记录，--seconds必须与--rcheck或--update参数共用
				--hitcount hits：匹配重复发生的次数，必须与--rcheck或--update共用
				modprobe xt_recent ip_list_tot=1024
				modprobe xt_recent ip_pkt_list_tot=50
		14、IP包头内TOS值的匹配（模块名称ipt_tos.ko）
		15、使用string模块匹配数据包内所承载的数据内容（模块名称xt_string.ko）
				string匹配方式可在“网络层”的位置直接匹配数据包所承载的数据内容，而无需将数据包送到“应用层”的位置才能进行匹配的操作，因此string匹配方式比“应用层防火墙”更高效，并且比较而言不太占用系统的存储空间。但string的匹配范围仅局限于单一数据包，也就是说，如果要匹配的“特征”是分散在2个数据包之内，此时,string的匹配方式就会完全失效
					iptables -A FORWARD -i eth0 -o eth1 -p tcp -d $WEB_SERVER --dport 80 -m string --algo bm --string "system32" -j DROP
		16、使用connlimit模块限制连接的最大数量（模块名称xt_connlimit.ko）
			用于以/proc/net/nf_conntrack文件中的数据为依据，来限制一个IP或一个网段同时对目标主机或服务所能建立的最大连接数
			--connlimit-above--->指定最大连接数量
			--connlimit-mask--->此参数为子网掩码，用于匹配范围
				iptables -A FORWARD -i eth0 -o eth1  -p tcp --syn -d $WEB_SERVER --dport 80 -m connlimit --connlimit-above 30 --connlimit-mask 32 -j DROP
		17、使用connbytes模块限制每个连接中所能传输的数据量（模块名称xt_connbytes.ko）
			功能描述：
				用来限制单一连接中所能传输的数据量上限，由此限制使用者在一条连接上长时间的大量数据传输，例如下载超大文件等
				用法举例：
					#限制使用者以HTTP协议下载20M以上的数据
					iptables -A FORWARD -p tcp -d $WEB_SERVER --dport 80 -m connbytes --connbytes-dir reply --connbytes-mode bytes --connbytes 20971520: -j DROP
				参数说明：
					--connbytes-dir
						original：来源方向
						reply：应答方向
						both：双向
					--connbytes-mode：以哪种单位进行统计
						packets：以数据包的数量来计算
						bytes：以传输的数据量来计算
					--connbytes
						10: 匹配10个以上的单位量
						:50 匹配50个以下的单位量
						10:50 匹配10个-50个之间的单位量
		18、使用quota模块限制数据传输量的上限
				#使用quota模块来限制每一个IP使用HTTP通信协议只能下载500MB的数据量
				iptables -A FORWARD -i eth0 -o eth1 -p tcp --sport 80 -m quota --quota 524288000 -j ACCEPT
				iptables -A FORWARD -i eth0 -o eth1 -p tcp --sport 80 -j DROP
		19、使用time模块来设置规则的生效时间（模块名称xt_time.ko）
				用法举例：
					iptables -A FORWARD -o eth1 -d $WEB_SERVER -m time --weekdays Mon,Tue,Wed,Thu,Fri --timestart 09:00 --timestop 21:00 -j ACCEPT
					iptables -A FORWARD -o eth1 -d $WEB_SERVER -j DROP
				命令参数：
					--datestart--->时间格式2010-09-01 T00:00:00
					--datestop
					--timestart--->14:00
					--timestop
					--monthdays--->1,9,19,29
					--weekdays
		20、使用connmark模块来匹配mark值（模块名称xt_connmark.ko）
				功能描述：
					MARK处理方法所设置的mark值的有效范围仅局限于一个数据包。因此，若要对连接单一方向的所有数据包设定mark值，我们必须单独为每个数据包来设置mark值；要为连接上双向的所有数据包设置mark值，就必须借助CONNMARK的功能才有办法实现
					CONNMARK是对一整条连接来设置mark值。也就是说只要连接中的某一个数据包被标记了mark，那么，其后该连接双向的所有数据包都会自动设置这个mark值。
					MARK所标记的值称为nfmark
					CONNMARK则为ctmark
					mark匹配方式只能识别nfmark，而connmark则可以识别nfmark及ctmark
				用法举例：
					iptables -A INPUT -m connmark --mark 1 -j DROP
		21、使用conntrack模块匹配数据包的状态
				功能描述：conntrack模块可视为state模块的加强版。
				命令参数：
				--ctstate
					NEW,ESTABLISHED,RELATED,INVALID,DNAT,SNAT
				--ctproto
					-p tcp
					-p udp
				--ctorigsrc--->匹配连接发起方向的来源ip
				--ctorigdst--->匹配连接发起方向的目的ip
				--ctreplsrc--->匹配数据包应答方向的来源ip
				--ctrepldst--->匹配数据包应答方向的目的ip
				--ctorigsrcport--->匹配连接发起方向的来源端端口
				--ctorigdstport-->匹配连接发起方向的目的端端口
				--ctreplsrcport--->匹配数据包应答方向的来源端端口
				--ctrepldstport--->匹配数据包应答方向的目的端端口
				--ctexpire--->连接在netfilter conntrack数据库的存活时间
				--ctdir
					--ctdir ORIGINAL
					--ctdir REPLY
					若没有设置这个参数，默认会匹配双向的所有数据包
				用法举例：
					iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
					iptables -A INPUT -m conntrack --ctproto tcp --ctorigsrc 192.168.1.0/24 --ctorigdstport 21 --ctstate NEW -j ACCEPT
					iptables -A INPUT -p tcp --dport 21 -j DROP
			22、使用statistic模块进行比率匹配（模块名称xt_statistic.ko）
				功能描述：在必要的时候以随机或者规律的方式丢弃部分数据包
				用法举例：
					iptables -A INPUT -p icmp -m statistic --mode random --probability 0.5 -j DROP #随机丢弃50%送到本机的ICMP包
					iptables -A INPUT -p imcp -m statistic --mode nth --every 10 --packet 1 -j DROP #以规律的方式在每10个ICMP包中丢弃1个IMCP包
				命令参数：
				--mode
					random--->以随机方式丢弃数据包
					nth--->按一定规律丢弃数据包
				--probability--->此参数需结合random模式使用，其中的值为0-1
				--every--->此参数需结合nth模式使用，例如--every 10代表每10个数据包中丢弃1个数据包
				--packet--->此参数需要在nth模式与--every参数结合使用，例如--every 10 --packet 5,因为statistic会在我们下达完iptables命令之后马上执行计数操作，而--packet 5则指在忽略前5个数据之后才开始计数
			23、使用hashlimit模块进行重复率匹配
				功能描述：限制特定行为的重复率
				用法举例：
					iptables -A INPUT -p icmp -m hashlimit --hashlimit-name ICMP --hashlimit-burst 5 --hashlimit-upto 6/minute --hashlimit-mode srcip --hashlimit-htable-size 8192 --hashlimit-htable-expire 60000 --hashlimit-htable-gcinterval 5000 -j ACCEPT
				命令参数：
					--hashlimit-upto--->在单位时间内符合条件的数据包数量超过几个以上，其单位可为N/second,N/minute,N/hour,N/day
					--hashlimit-above--->在单位时间内符合条件的数据包数量低于几个以下，其单位可为N/second,N/minute,N/hour,N/day
					--hashlimit-burst--->设置缓存区
					--hashlimit-mode--->设置匹配依据，依据可为srcip,srcport,dstip,dstport
					--hashlimit--srcmask--->以来源IP作为判断及限制依据
					--hashlimit-dstmask--->目的IP
					--hashlimit-name--->设置hashlimit数据库名称
					--hashlimit-htable-size--->用来设置一个数据库内最多可记录多少条数据，不过最终数据需要乘8才是数据库记录的最大值
					--hashlimit-htable-expire--->设置数据库某一条记录的过期时间
					--hashlimit-htable-gcinterval--->设置数据库中的数据过期之后的多久，自动将这条数据从数据库中删除
			24、多功能匹配模块u32
				功能描述：允许检查数据包各包头的任意数据
	处理方法
		内置的处理方法
			1、ACCEPT及DROP的处理方法
				iptables -A INPUT -p all -s 192.168.1.0/24 -j ACCEPT
				iptables -A INPUT -p all -s 192.168.6.0/24 -j DROP
			2、QUEUE的处理方法
				功能描述：将符合条件的数据包转发给User Space的应用程序来处理。例如“杀毒软件”，“垃圾邮件过滤”
				用法举例：
					iptables -A FORWARD -p tcp -d $MAIL_SRV --dport 25 -j QUEUE
			3、RETURN的处理方法
			功能说明：让符合规则的数据包提前返回其原来的链
				用户自定义链
					iptables -N WEB_SRV
					iptables -E WEB_SRV MAIL_SRV
		由模块扩展的处理方法
			1、REJECT的处理方式（模块名称ipt_REJECT.ko）
				DROP会将数据包丢弃掉，这将使得发送端误以为在网络上传输丢失了，因此发送端将会重复地发送数据包直到超时为止
				REJECT也会将数据包丢掉，但还会回送一个ICMP包给客户端，由此告诉网络或者服务发生问题，当发送端收到ICMP包之后，就会终止服务请求的操作。
					iptables -A INPUT -p tcp --dprot 25 -j REJECT --reject-with icmp-net-unreachable
			2、LOG的处理方法（模块名称ipt_LOG.ko）
				用法举例：
					iptables -A INPUT -p tcp --dport 22 -j LOG
					iptables -A INPUT -p tcp --dport 22 -j ACCEPT
					iptables -A INPUT -p tcp --syn --dport 22 -j LOG --log-level alert
					iptables -A INPUT -p tcp --syn --dport 22 -j LOG --log-level alert --log-prefix "SSH-request "
				参数说明：
					--log-level
					--log-prefix
					--log-tcp-sequence--->记录TCP数据包的序号
					--log-tcp-options--->记录TCP包头Options字段的信息
					--log-ip-options
					--log-uid--->记录数据包是本机的哪一个用户所生成的
			3、ULOG的处理方法（模块名称ipt_ULOG.ko）
					功能描述：将日志叫给特定的User Space机制来处理。目前比较完整的要算ulogd这个机制。
			4、TOS的处理方法（模块名称ipt_TOS.ko）
				功能描述：修改路过mangle机制的数据包，TOS所能改变的对象为IP包头内的TOS值。
			5、DSCP的处理方法（功能模块ipt_DSCP.ko）
				功能描述：修改路过mangle机制的数据包，TOS所能改变的对象为IP包头内的DSCP值。
					#如果数据包的来源端口为80，就把这个数据包内的DSCP值改为1
					iptables -t mangle -A FORWARD -p tcp --sport 80 -j DSCP --set-dscp 1
			6、MARK的处理方法（功能模块xt_MARK.ko）
				功能描述：
					数据包分类方式。MARK的处理方式可以让我们在特定的数据包上标记一个“记号”，而这个记号是由数字构成的。但该“记号”并没有真正的写入到数据包里面，也就是说MARK的操作并不会修改数据包的内容，而是LINUX内核使用一块内存来记录数据包与MARK值的对应关系，因此，当数据包离开本机之后，MARK值也就随之消失了。
				用法举例：
					iptables -t mangle -A FORWARD -p tcp --sport 25 -j MARK --set-mark 25
			7、CONNMARK的处理方法
				功能描述：都是用量对数据包设置mark值。
					CONNMARK：设置的称为ctmark，范围为一个完整的连接
					MARK：设置的称为nfmark，范围局限在单一一个数据包
				用法举例：
					iptables -t mangle -A INPUT -p tcp --dport 80 -j MARK --set-mark 1
					iptables -t filter -A INPUT -m mark --mark 1 -j DROP
			8、TTL的处理方法
				功能描述：TTL模块的功能在于修改“路过”防火墙上数据包的TTL值
				参数说明：
					--ttl-set：把数据包内的TTL值设置为特定值
					--ttl-dec：把数据包内既有的TTL值减掉特定的值
					--ttl-inc：把数据包内既有的TTL值加上特定的值
			9、REDIRECT的处理方法（功能模块ipt_REDIRECT.ko）
				功能描述：是一种特殊的DNAT机制，通常会与代理服务器结合使用，使其称为透明代理结构
			10、MASQUERADE的处理方法
				功能描述：是一种特殊的SNAT机制
			11、NETMAP的处理方法
					一对一NAT是由一个SNAT及一个DNAT组合而成。
					用法举例：
						iptables -t nat -A PREROUTING -i eth0 -d 10.0.0.0/24 -j NETMAP --to 192.168.1.0/24
						iptables -t nat -A POSTROUTING -o eth0 -s 192.168.1.0/24 -j NETMAP --to 10.0.0.0/24
}

四、Netfilter/Iptables的高级技巧
{
	防火墙性能的最优化
		1、调整防火墙规则的顺序
			iptables -L -nv #查看每一条规则的匹配次数
		2、巧妙使用multiport及iprange模块
			举例：
				iptables -A INPUT -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
				iptables -A INPUT -p tcp --syn -m state --state NEW -m multiport --dports 22,23,25,80,110 -j ACCEPT
				iptables -A INPUT -m iprange --src-range 192.168.1.12-192.168.1.16 -j ACCEPT
		3、巧妙使用用户自定义的链
	Netfilter连接处理能力
		1、计算最大连接数
			/pro/sys/net/netfilter/nf_conntrack_max

		2、调整连接跟踪数
			/proc/sys/netfilter/nf_conntrack_max
			centos5：/proc/sys/net/ipv4/netfilter/ip_conntrack_max或者/proc/sys/net/ipv4/ip_conntrack_max
			centos6：/proc/sys/net/netfilter/nf_conntrack_max
			#查看kernel Source配置文件
			grep -i 'CONFIG_NF_CONNTRACK=' /boot/config-Kernel_version
				如果CONFIG_NF_CONNTRACK=y就是静态模块，如果为m，就是动态模块
			#查看内核模块列表
				/lib/modules/kernel_version/modules.dep
					如果能找到nf_conntrack.ko字符串，说明nf_conntrack是动态模块存在，否则就是静态模块
				动态模块加载：modprobe nf_conntrack_hashsize=32768
				静态模块加载：直接将参数nf_conntrack_hashsize=32768添加到/boot/grub/grub.conf的核心参数区
		3、使用raw表
			因为nf_conntrack模块默认会自动跟踪所有连接。如何让nf_conntrack模块不去跟踪某条连接？这时候就得靠raw表了
				iptables -t raw -A PREROUTING -i eth2 -o eth1 -p tcp --dport 25 -j NOTRACK
				iptables -t raw -A PREROUTING -i eth1 -o eth2 -p tcp --sport 25 -j NOTRACK
			raw表的好处在于“加速”，以及增加可跟踪的连接数量，因为被raw表所定义的连接不会被跟踪，也就不会算做连接跟踪数量。此外，raw表所定义的连接会直接跳过NAT TABLE及nf_conntrack模块的处理，因此可以加快数据包进出防火墙的速度，但因为raw表所定义的连接会跳过NAT表，所以任何被raw所定义的连接都无法被NAT机制所处理。
			raw表只有两个链
				PREROUTING:如果是网关式防火墙，PREROUTING链可以用来处理防火墙两侧网络之间所建立的连接（因为这些数据包都会经过PREROUTING链），另外，PREROUTING链也可以处理任何主动连接到防火墙本机的连接
				OUTPUT：用来处理本机对外建立的连接
		4、简单及复杂通信协议的处理
			简单的通信协议：如果客户端访问服务器时只使用“一条连接”的协议，就称为简单通信协议
				HTTP,SSH,TELNET,SMTP,POP3,IMAP,HTTPS等
					iptables -A FORWARD -i eth0 -o eth1 -p tcp -d $MAIL --dport 25 -j ACCEPT
			复杂的通信协议：就是客户端和服务器端之间，需要多条连接才能完成应用的协议
				FTP,PPTP,H.323,SIP等
					FTP的通信协议
						被动模式
						主动模式
							nf_conntrack_ftp.ko
							nf_nat_ftp.ko
				ICMP包处理原则：ICMP的用途是传输控制信号或传输某种信息。
					1、放行所有因特网送来的ESTABLISHED及RELATED状态的ICMP数据包
					2、丢弃所有由因特网送来的其他状态的ICMP数据包
		5、使用Netfilter来防御portscan的攻击
			举例：假如有一台主机允许SSH,SMTP,HTTP,POP3这4项服务，如何运用Portscan的特性来防止portscan的攻击
				1、客户端访问主机端口22、25、80、110都属于正常行为
				2、客户端访问端口22、25、80、110以为的端口都属于不正常行为
				3、portscan想要侦测出我们主机有哪些端口打开，因此，portscan几乎会对我们主机的每一个端口送出探测数据包，而这些数据包在第一及第二点的定义绝大多数都属于不正常行为
				4、当然客户端有可能“不小心”打错IP，而产生不正常的行为，但这种情况的概率很低，几乎可以忽略不计
			总结：整理以上4条规则之后，我们可以运用recent模块来防止Portscan攻击。
				1、先看第4条规则，只要有任何数据包符合本规则，recent模块就会把这个客户端的IP及数据包的信息记录在port_scan这个数据库中
				2、看第3条规则，如果传入的数据包是TCP协议的数据包，而且数据包是要送到端口22、25、80、110的，就符合这条规则，如果数据包符合这条规则就不会被送到第4条规则，当然就不会记录在Port_scan的数据库中。
				3、因为Portscan的特性会对主机的每个端口发出探测包，这些大量的探测包除了有可能匹配到22、25、80、110之外，其他的大多数的探测包都可能会被第4条规则而记录下来
				4、第2条规则为匹配port_scan数据库的内容，如果这个数据包的特征在数据库中有记录，我们就更新数据库中的信息，另外，如果从目前这个时间点往前推1800秒，且在port_scan数据库中有超过10条以上的记录，就把该数据包丢弃。
			配置：
				iptables -A INPUT -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
				iptables -A INPUT -p all -m state --state NEW -m recent --name port_scan --update --seconds 1800 --hitcount 10 -j DROP
				iptables -A INPUT -p tcp --syn -m state --state NEW -m multiport --dports 22,25,80,110 -j ACCEPT
				iptables -A INPUT -p all -m recent --name port_scan --set
		6、Syn Flooding攻击
				TCP三次握手的致命危险
					其实问题就发生在三次握手的第三个步骤，我们知道在第二个步骤中，服务器端会把连接信息记录在TCP队列中，而这一条信息会一直存放在TCP队列中，直到服务器端收到客户端的确认数据包之后，才会从队列中清除掉。但问题来了，如果客户端故意不回送确认包给服务器端，服务器端在经过一段时间后，会重新再发送一次第二个步骤的数据包给客户端，如果经过一段时间之后仍然无法得到客户端的应答，服务器端依然会再次重复第二个步骤中的数据包给客户端，而这样的重试将会持续5次。如果最后还是无法得到客户端的应答，服务器端就会从TCP队列中清楚该条连接的缓存信息。这5次的重试时间将会长达3分15秒之久。
					如果以上情况在网络正常的网络环境中偶尔发生几次，倒也不至于对系统造成什么影响，万一客户端不断地对服务器端发送大量的SYN数据包（三次握手的第一个包），却又故意不回送确认包（三次握手的第三个数据包）给服务器端，服务端的TCP队列很可能被这些无法正常建立连接的信息给占满，因而导致其他正常需要访问的服务的链接无法被排入TCP队列，当然TCP连接也就无法正常建立起来，如此达到SYN flooding攻击的目的。
				单一主机的防御：
					1、调整系统内核中关于TCP连接的参数
						net.ipv4.tcp_synack_retries=3
						net.ipv4.tcp_max_syn_backlog=2048
					2、启动tcp_syncookies机制来对抗syn flooding攻击的目的。
						net.ipv4.tcp_syncookies=1
				网关上的防御
					1、缩短后端服务器端上TCP队列被占用的时间
					2、使用Syn网关
					3、使用反向代理机制
			7、URL攻击防御
				可以通过Netfilter的string模块来检查数据包内所承载的数据内容，以杜绝这样的攻击手段。
			8、管理病毒感染时的连接消耗
				每当客户端对因特网建立一条新的连接，防火墙就必须为这条连接建立一份连接跟踪记录，而防火墙能同时跟踪的连接数量有限。如果全部被病毒感染的连接给占满了，其他正常想要连接到因特网的使用者就无法正常建立连接，也就无法访问因特网上的服务。（P2P软件也是类似的情况）
					#如果一个客户端在60秒之内，对因特网建立超过120新的连接，那我们就认定这个客户端已中毒，或者这个客户端正在使用P2P软件
						iptables -A FORWARD -i eth1 -o eth0 -p all -m state --state NEW -m recent --name virus --update --seconds 60 --hitcount 120 -j REJECT
						iptables -A FORWARD -i eth1 -o eth0 -p all -m state --state NEW -m recent --name virus --set
}
五、代理服务器的应用
{
	1、代理服务器的分类
		缓存代理
		反向代理

}
六、使用Netfilter/iptables保护企业网络
{
	1、防火墙结构的选择
		企业没有提供对外的网络服务时
		企业有提供对外的网络服务时

}

七、Linux内核编译
{

}

八、应用层防火墙
{

}
九、透明防火墙
{
	1、何谓网桥模式
		转发广播数据包
		隔离相同实体网段的单播
		不同实体网段间的单播，网桥只会将数据包转发到相关的实体网段上。
		网桥属于二层设备，因此网桥设备并不需要像路由器一样需要在网络接口设置IP。
	2、透明防火墙的优点
		部署能力强
		隐蔽性好
		安全性高
	3、构建透明防火墙
		使用Linux构建网桥
			yum install bridge-utils

        #!/bin/bash
        echo 1 > /proc/sys/net/ipv4/ip_forward
        brctl addbr br0
        brctl addif br0 eth0
        brctl addif br0 eth1
        ifconfig br0 192.168.0.253 netmask 255.255.255.0 update
        ip route add default via 192.168.0.254
    4、Linux网桥的管理
        查看系统上的网桥接口
            #brctl show
        启用接口的STP
            #brctl stp br0 on
    5、Netfilter在Layer3及Layer2的工作逻辑
        早期kernel2.4版本中是没有这个功能的，需要手工打补丁
        #grep -i 'config_netfilter_advanced=y' /boot/config-Kernel_Version
        在Red hat系统中，这项功能是默认启用的
        不管在第2层还是第3层内部都有一个Filter表的FORWARD链，但这两个链（两块内存空间）其实是同一个。
            #iptables -t filter -A FORWARD -p icmp -j DROP
            这条Netfilter的规则将会同时作用于第2层及第3层的环境中，
}





















