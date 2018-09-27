#/bin/bash
export LC_ALL="en_US.UTF-8"

echo check begin!

checkDIR=/dbbackup/info.txt

DATE=`date +%Y%m%d_%H:%M`
echo " " > $checkDIR
echo "----------------------------" >> $checkDIR
echo "-----Server Information-----">>$checkDIR
echo "     "$(date +"20%y-%m-%d %H:%M:%S") >>$checkDIR
echo "-----------------" >> $checkDIR

echo ======1 Hostname >> $checkDIR
/bin/hostname >>$checkDIR

echo ======2 IP MASK >> $checkDIR
/sbin/ifconfig|grep "inet addr" >>$checkDIR

echo ======3 Route >> $checkDIR
/sbin/route -n >>$checkDIR

echo ======4 System Version >> $checkDIR
/bin/cat /etc/redhat-release >>$checkDIR

echo ======5 Kernel Version >> $checkDIR
/bin/uname -a >>$checkDIR

echo ======6 Uptime >> $checkDIR
/usr/bin/uptime >>$checkDIR
uptime=$(/usr/bin/uptime|awk '{print $3}')
echo "开机时长：$uptime天">> $checkDIR

echo ======7 Df  >> $checkDIR
/bin/df -Th >> $checkDIR

echo ======8 Memery Utilization >> $checkDIR
mem_total=$(free -m |grep Mem|awk '{print $2}')
mem_used=$(free -m|grep -|awk '{print $3}')
mem_rate=$(echo "scale=4;$mem_used / $mem_total" | bc)
percent_part1=$(echo $mem_rate | cut -c 2-3)
percent_part2=$(echo $mem_rate | cut -c 4-5)
/usr/bin/free -m  >>$checkDIR
echo "System memery is already use: $percent_part1.$percent_part2%">>$checkDIR

echo ======9 Top  >> $checkDIR
/usr/bin/top -M -b -d 1 -n 1|head -n 12 >>$checkDIR

echo ======10 Service Status  >> $checkDIR
echo "|--------nginx" >> $checkDIR
if [ -w /etc/init.d/nginx ];
then
status=$(/etc/init.d/nginx status)
port=$(netstat -anptul|grep nginx|grep LISTEN )
echo $status >>$checkDIR;
echo $port >>$checkDIR;
else 
echo "The server doesn't have this service!" >>$checkDIR;
fi;

echo "|--------mysql" >> $checkDIR
if [ -w /etc/init.d/mysql ];
then
status=$(/etc/init.d/mysql status)
port=$(netstat -anptul|grep 3306|grep LISTEN )
echo $status >>$checkDIR;
echo $port >>$checkDIR;
else 
echo "The server doesn't have this service!" >>$checkDIR;
fi;

echo "|--------apache" >> $checkDIR
if [ -w /etc/init.d/httpd ];
then
status=$(/etc/init.d/httpd status)
port=$(netstat -anptul|grep http|grep LISTEN )
echo $status >>$checkDIR;
echo $port >>$checkDIR;
else 
echo "The server doesn't have this service!" >>$checkDIR;
fi;

echo "|--------munin" >> $checkDIR
if [ -w /etc/init.d/munin-node ];
then
status=$(/etc/init.d/munin-node status)
echo $status >>$checkDIR;
else 
echo "The server doesn't have this service!" >>$checkDIR;
fi;

echo "|--------tomcat" >> $checkDIR
if [ -w /drcom/app/drcom/checktomcat ];
then
bash /drcom/app/drcom/checktomcat  &>>$checkDIR ;
connect=$(netstat -n|grep :80 | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}' )  ;
echo $connect >>$checkDIR;
else
echo "The server doesn't have this service!" >>$checkDIR;
fi;

echo "|--------crontab" >> $checkDIR
/usr/bin/crontab -l  &>>$checkDIR

echo "|--------iptables" >> $checkDIR
/etc/init.d/iptables status &>>$checkDIR

echo "  "
echo check ok!
