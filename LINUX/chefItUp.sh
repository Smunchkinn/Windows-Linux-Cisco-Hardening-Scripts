#! /bin/bash

#colors for output customization
RED='\033[0;31m'
LightBlue='\033[1;34m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
NC='\033[0m'

#Team Tag
echo -e "${CYAN}███╗   ███╗██╗███╗   ██╗██╗  ██╗   "                          
echo -e "████╗ ████║██║████╗  ██║██║  ██║   "                         
echo -e "██╔████╔██║██║██╔██╗ ██║███████║   "                         
echo -e "██║╚██╔╝██║██║██║╚██╗██║██╔══██║   "                         
echo -e "██║ ╚═╝ ██║██║██║ ╚████║██║  ██║   "                        
echo -e "╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   "                        
echo -e "                                   "                        
echo -e "██████╗ ██╗   ██╗███╗   ██╗ █████╗ ███████╗████████╗██╗   ██╗ "
echo -e "██╔══██╗╚██╗ ██╔╝████╗  ██║██╔══██╗██╔════╝╚══██╔══╝╚██╗ ██╔╝ "
echo -e "██║  ██║ ╚████╔╝ ██╔██╗ ██║███████║███████╗   ██║    ╚████╔╝  "
echo -e "██║  ██║  ╚██╔╝  ██║╚██╗██║██╔══██║╚════██║   ██║     ╚██╔╝   "
echo -e "██████╔╝   ██║   ██║ ╚████║██║  ██║███████║   ██║      ██║    "
echo -e "╚═════╝    ╚═╝   ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝   ╚═╝      ╚═╝    ${NC}"



#prints list of users and allows user to input which users need to be deleted
deleteUsers () {
echo -e "${LightBlue}deleting users${NC}"
sudo getent passwd {1000..6000}
echo -e "${LightBlue}which users need to be deleted?${NC}"
read -a rmUsers

for value1 in ${rmUsers[@]}
do 
      sudo deluser $value1
done
echo -e "${LightBlue}done deleting users${NC}"
}


#prints list of groups and users and allows user to input which users should not be administrators
verifyAdmins () {
echo -e "${LightBlue}verifying administrators${NC}"
sudo getent group sudo
echo -e "${LightBlue}which users SHOULD NOT be administrators${NC}"
read -a daUsers
for value2 in ${daUsers[@]}
do 
      sudo gpasswd -d $value2 sudo
done
echo -e "${LightBlue}which users SHOULD be administrators${NC}"
read -a aaUsers
for value3 in ${aaUsers[@]}
do 
      sudo usermod -aG sudo $value3
done
echo -e "${LightBlue}done verifying administrators${NC}"
}

#changes all passwords except for the user's automatically
changePasswords () {
echo -e "${LightBlue}Changing Passwords${NC}"
echo -e "${RED}Password: th3CyB3r(g04T!)${NC}"
users=$(getent passwd {1000..6000} | cut -d: -f1)
echo -e "${LightBlue}Who Am I?${NC}"
read thisIsMe
for value in ${users[@]}
do 
      if [ "$value" != "$thisIsMe" ]; then
      echo -e "th3CyB3r(g04T!)\nth3CyB3r(g04T!)" | sudo passwd $value
      fi
done
      echo -e "th3CyB3r(g04T!)\nth3CyB3r(g04T!)" | sudo passwd
      echo -e "${LightBlue}Done Changing Passwords${NC}"
}

#does random stuff with ports
portStuff () {
	echo -e "${LightBlue}Running iptables Commands${NC}"
	sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP         #Block Telnet
	sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
	sudo iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
	sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP  #Block X-Windows
	sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP       #Block X-Windows font server
	sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
	sudo iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
	sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
	sudo iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
	sudo iptables -A INPUT -p all -s localhost  -i eth0 -j DROP            #Deny outside packets from the internet which claim to be from your loopback interface.
    
	#only allow HTTP/HTTPS, NTP and DNS
	sudo iptables -A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	sudo iptables -A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	sudo iptables -A INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	sudo iptables -A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	sudo iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	sudo iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	sudo iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	sudo iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	sudo iptables -A OUTPUT -o lo -j ACCEPT
	sudo iptables -P OUTPUT DROP

 	sudo iptables -A INPUT -s 127.0.0.0/8 -i $interface -j DROP
	sudo iptables -A INPUT -s 0.0.0.0/8 -j DROP
	sudo iptables -A INPUT -s 100.64.0.0/10 -j DROP
	sudo iptables -A INPUT -s 169.254.0.0/16 -j DROP
	sudo iptables -A INPUT -s 192.0.0.0/24 -j DROP
	sudo iptables -A INPUT -s 192.0.2.0/24 -j DROP
	sudo iptables -A INPUT -s 198.18.0.0/15 -j DROP
	sudo iptables -A INPUT -s 198.51.100.0/24 -j DROP
	sudo iptables -A INPUT -s 203.0.113.0/24 -j DROP
	sudo iptables -A INPUT -s 224.0.0.0/3 -j DROP
	#Blocks bogons from leaving the computer
	sudo iptables -A OUTPUT -d 127.0.0.0/8 -o $interface -j DROP
	sudo iptables -A OUTPUT -d 0.0.0.0/8 -j DROP
	sudo iptables -A OUTPUT -d 100.64.0.0/10 -j DROP
	sudo iptables -A OUTPUT -d 169.254.0.0/16 -j DROP
	sudo iptables -A OUTPUT -d 192.0.0.0/24 -j DROP
	sudo iptables -A OUTPUT -d 192.0.2.0/24 -j DROP
	sudo iptables -A OUTPUT -d 198.18.0.0/15 -j DROP
	sudo iptables -A OUTPUT -d 198.51.100.0/24 -j DROP
	sudo iptables -A OUTPUT -d 203.0.113.0/24 -j DROP
	sudo iptables -A OUTPUT -d 224.0.0.0/3 -j DROP
	#Blocks outbound from source bogons - A bit overkill
	sudo iptables -A OUTPUT -s 127.0.0.0/8 -o $interface -j DROP
	sudo iptables -A OUTPUT -s 0.0.0.0/8 -j DROP
	sudo iptables -A OUTPUT -s 100.64.0.0/10 -j DROP
	sudo iptables -A OUTPUT -s 169.254.0.0/16 -j DROP
	sudo iptables -A OUTPUT -s 192.0.0.0/24 -j DROP
	sudo iptables -A OUTPUT -s 192.0.2.0/24 -j DROP
	sudo iptables -A OUTPUT -s 198.18.0.0/15 -j DROP
	sudo iptables -A OUTPUT -s 198.51.100.0/24 -j DROP
	sudo iptables -A OUTPUT -s 203.0.113.0/24 -j DROP
	sudo iptables -A OUTPUT -s 224.0.0.0/3 -j DROP
	#Block receiving bogons intended for bogons - Super overkill
	sudo iptables -A INPUT -d 127.0.0.0/8 -i $interface -j DROP
	sudo iptables -A INPUT -d 0.0.0.0/8 -j DROP
	sudo iptables -A INPUT -d 100.64.0.0/10 -j DROP
	sudo iptables -A INPUT -d 169.254.0.0/16 -j DROP
	sudo iptables -A INPUT -d 192.0.0.0/24 -j DROP
	sudo iptables -A INPUT -d 192.0.2.0/24 -j DROP
	sudo iptables -A INPUT -d 198.18.0.0/15 -j DROP
	sudo iptables -A INPUT -d 198.51.100.0/24 -j DROP
	sudo iptables -A INPUT -d 203.0.113.0/24 -j DROP
	sudo iptables -A INPUT -d 224.0.0.0/3 -j DROP
	sudo iptables -A INPUT -i lo -j ACCEPT
 	echo -e "${LightBlue}Done Running iptables Commands${NC}"
}

#finds media files
findMedia () {
	echo -e "${LightBlue}Listing Media Files${NC}"
 	echo -e "${RED}-------------------- START --------------------${NC}"
    find / -name '*.mp3' 
    find / -name '*.mov' 
    find / -name '*.mp4' 
    find / -name '*.avi' 
    find / -name '*.mpg' 
    find / -name '*.mpeg' 
    find / -name '*.flac' 
    find / -name '*.m4a' 
    find / -name '*.flv' 
    find / -name '*.ogg' 
    find /home -name '*.gif' #might want to run without specified home directory
    find /home -name '*.png' #might want to run without specified home directory
    find /home -name '*.jpg' #might want to run without specified home directory
    find /home -name '*.jpeg' #might want to run without specified home directory
    find /home -name '*.txt' #might want to run without specified home directory
    echo -e "${RED}--------------------- END ---------------------${NC}"
    echo -e "${LightBlue}Done Finding Media Files${NC}"
}

#firewall
ufwFirewall () {
	echo -e "${LightBlue}Configuring UFW${NC}"
	sudo apt install ufw

	#enable the firewall
	sudo ufw enable

	#turn on logging
	sudo ufw logging on high

	#directions and stuff
	sudo ufw default allow outgoing
	sudo ufw default deny incoming

	#deny stuff
	sudo ufw deny 21
	sudo ufw deny 23
	sudo ufw deny cups

	#uninstall these services
	sudo apt-get purge -y cups
	sudo apt-get purge -y bluetooth
	sudo apt-get autoremove -y

	#Config default deny
	sudo iptables -P INPUT DROP
	sudo iptables -P OUTPUT DROP
	sudo iptables -P FORWARD DROP
	#loopback traffic
	sudo iptables -A INPUT -i lo -j ACCEPT
	sudo iptables -A OUTPUT -o lo -j ACCEPT
	sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP
	#outbound and established connections
	sudo iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
	sudo iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
	sudo iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
	sudo iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
	sudo iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
	sudo iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

 	ufw allow ssh
	ufw allow http
	ufw allow https
	ufw deny 23
	ufw deny 2049
	ufw deny 515
	ufw deny 111
	ufw logging high
	ufw status verbose
 	sudo ufw restart
 	echo -e "${LightBlue}Done Configuring UFW${NC}"
}

#checks for zero uid users
zeroUIDUsers () {
	echo -e "${LightBlue}Removing Zero UID Users${NC}"
	touch /zerouidusers
	touch /uidusers

	cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

	if [ -s /zerouidusers ]
	then
		echo "There are Zero UID Users"

		while IFS='' read -r line || [[ -n "$line" ]]; do
			thing=1
			while true; do
				rand=$(( ( RANDOM % 999 ) + 1000))
				cut -d: -f1,3 /etc/passwd | egrep ":$rand$" | cut -d: -f1 > /uidusers
				if [ -s /uidusers ]
				then
					echo "Could not find unused UID. Trying Again"
				else
					break
				fi
			done
			usermod -u $rand -g $rand -o $line
			touch /tmp/oldstring
			old=$(grep "$line" /etc/passwd)
			echo $old > /tmp/oldstring
			sed -i "s~0:0~$rand:$rand~" /tmp/oldstring
			new=$(cat /tmp/oldstring)
			sed -i "s~$old~$new~" /etc/passwd
			echo "ZeroUID User: $line"
			echo "Assigned UID: $rand"
		done < "/zerouidusers"
		update-passwd
		cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

		if [ -s /zerouidusers ]
		then
			echo "UNSUCCESSFUL"
		else
			echo "Successful"
		fi
	else
		echo "There are No Zero UID Users"
	fi
	echo -e "${LightBlue}Done Removing Zero UID Users${NC}"
}

#changes cron to only permit root access and does other things to secure it
secureRootCron () {
	echo -e "${LightBlue}Securing Root Cron${NC}"
	crontab -r
	cd /etc/
	/bin/rm -f cron.deny at.deny
	echo root >cron.allow
	echo root >at.allow
	/bin/chown root:root cron.allow at.allow
	/bin/chmod 644 cron.allow at.allow
	echo -e "${LightBlue}Done Securing Root Cron${NC}"
}

#secures apache configs
secureApache () {
	echo -e "${LightBlue}Securing Apache${NC}"
 	echo -e "${RED}Is Apache a Critical Servcice? (y/n)${NC}"
  	read yon2
   	if [ yon2 == "y" ] ; then
	a2enmod userdir

	chown -R root:root /etc/apache2
	chown -R root:root /etc/apache

	if [ -e /etc/apache2/apache2.conf ]; then
		echo "<Directory />" >> /etc/apache2/apache2.conf
		echo "        AllowOverride None" >> /etc/apache2/apache2.conf
		echo "        Order Deny,Allow" >> /etc/apache2/apache2.conf
		echo "        Deny from all" >> /etc/apache2/apache2.conf
		echo "</Directory>" >> /etc/apache2/apache2.conf
		echo "UserDir disabled root" >> /etc/apache2/apache2.conf
	fi

	systemctl restart apache2.service
 	fi
 	echo -e "${LightBlue}Done Securing Apache${NC}"
}

#automatically secures certain files
secureFiles () {
	echo -e "${LightBlue}Securing Files${NC}"
	#Replace lightdm.conf with safe reference file
	cat $PWDthi/referenceFiles/lightdm.conf > /etc/lightdm/lightdm.conf

	#Replace sshd_config with safe reference file
	cat $PWDthi/referenceFiles/sshd_config > /etc/ssh/sshd_config
	/usr/sbin/sshd -t
	systemctl restart sshd.service

	#/etc/rc.local should be empty except for 'exit 0'
	echo 'exit 0' > /etc/rc.local
	echo -e "${LightBlue}Done Securing Files${NC}"
}

#automatically run some updates
updateStuff () {
	echo -e "${LightBlue}Running apt-get Commands${NC}"
	apt-get update
	apt-get dist-upgrade -y
	apt-get install -f -y
	apt-get autoremove -y
	apt-get autoclean -y
	apt-get check
 	echo -e "${LightBlue}Done Running apt-get Commands${NC}"
}

secureConfigs () {
echo -e "${LightBlue}Securing Random Configs${NC}"
sudo chown root:root //boot/grub/grub.cfg
sudo chmod 700 //boot/grub/grub.cfg
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow
chown root:root //etc/passwd
chmod 700 //etc/passwd
chown root:shadow //etc/shadow
chmod o-rwx,g-wx //etc/shadow
chown root:root //etc/group
chmod 700 //etc/group
chown root:shadow //etc/gshadow
chmod o-rwx,g-rw //etc/gshadow
chown root:root //etc/passwd-
chmod u-x,go-wx //etc/passwd-
chown root:root //etc/shadow-
chown root:shadow //etc/shadow-
chmod o-rwx,g-rw //etc/shadow-
chown root:root //etc/group-
chmod u-x,go-wx //etc/group-
chown root:root //etc/gshadow-
chown root:shadow /etc/gshadow-    
chmod o-rwx,g-rw //etc/gshadow-
chown root:root //etc/motd
chmod 700 //etc/motd
chown root:root //etc/issue
chmod 700 //etc/issue
chown root:root //etc/issue.net
chmod 700 //etc/issue.net
chown root:root //etc/hosts.allow
chmod 700 //etc/hosts.allow
chown root:root //etc/hosts.deny
chmod 700 //etc/hosts.deny
sudo chmod 700 //etc/pam.d/common-auth
chown root:root /etc/securetty
chmod 0600 /etc/securetty
chmod 644 /etc/crontab
chmod 640 /etc/ftpusers
chmod 440 /etc/inetd.conf
chmod 440 /etc/xinted.conf
chmod 400 /etc/inetd.d
chmod 440 /etc/sudoers
chmod 600 /etc/shadow
chown root:root /etc/shadow
chmod 644 /etc/passwd
chown root:root /etc/passwd
chmod 644 /etc/group
chown root:root /etc/group
chmod 600 /etc/gshadow
chown root:root /etc/gshadow
chmod 700 /boot
chown root:root /etc/anacrontab
chmod 600 /etc/anacrontab
chown root:root /etc/crontab
chmod 600 /etc/crontab
chown root:root /etc/cron.hourly
chmod 600 /etc/cron.hourly
chown root:root /etc/cron.daily
chmod 600 /etc/cron.daily
chown root:root /etc/cron.weekly
chmod 600 /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod 600 /etc/cron.monthly
chown root:root /etc/cron.d
chmod 600 /etc/cron.d

sudo chmod 702 //etc/host.conf
echo "order bind,hosts" >> //etc/host.conf
echo "nospoof on" >> //etc/host.conf
sudo chmod 700 //etc/host.conf

sudo chmod 702 //etc/security/limits.conf
echo "* hard core" >> //etc/security/limits.conf
sudo chmod 700 //etc/security/limits.conf
sudo chmod 702 //etc/sysctl.conf
echo "fs.suid_dumpable = 0" >> //etc/sysctl.conf
sudo chmod 700 //etc/sysctl.conf
sudo sysctl -w fs.suid_dumpable=0

sudo chmod 777 //etc/motd
echo "This system is for authorized users only. Individual use of this system and/or network without authority, or in excess of your authority, is strictly prohibited." > //etc/motd
sudo chmod 700 //etc/motd
sudo chmod 777 //etc/issue
echo "This system is for the use of authorized users only.  Individuals using this computer system without authority, or in excess of their authority, are subject to having all of their activities on this system monitored and recorded by system personnel.  In the course of monitoring individuals improperly using this system, or in the course of system maintenance, the activities of authorized users may also be monitored.  Anyone using this system expressly consents to such monitoring and is advised that if such monitoring reveals possible evidence of criminal activity, system personnel may provide the evidence of such monitoring to law enforcement officials." > //etc/issue
sudo chmod 700 //etc/issue
sudo chmod 777 //etc/issue.net
echo "This system is for the use of authorized users only.  Individuals using this computer system without authority, or in excess of their authority, are subject to having all of their activities on this system monitored and recorded by system personnel.  In the course of monitoring individuals improperly using this system, or in the course of system maintenance, the activities of authorized users may also be monitored.  Anyone using this system expressly consents to such monitoring and is advised that if such monitoring reveals possible evidence of criminal activity, system personnel may provide the evidence of such monitoring to law enforcement officials." > //etc/issue.net
sudo chmod 700 //etc/issue.net
touch //etc/dconf/profile/gdm
sudo chmod 777 //etc/dconf/profile/gdm
echo "user-db:user" >> //etc/dconf/profile/gdm
echo "system-db:gdm" >> //etc/dconf/profile/gdm
echo "file-db:/usr/share/gdm/greeter-dconf/defaults" >> //etc/dconf/profile/gdm
sudo chmod 700 //etc/dconf/profile/gdm

sudo chmod 777 //etc/ntp.conf
echo "restrict -4 default kod nomodify notrap nopeer noquery" >> //etc/ntp.conf
echo "restrict -6 default kod nomodify notrap nopeer noquery" >> //etc/ntp.conf
sudo chmod 700 //etc/ntp.conf

sudo chmod 777 //etc/hosts.deny
echo "ALL: ALL" >> //etc/hosts.deny
sudo chmod 700 //etc/hosts.deny

sudo chmod 777 //etc/modprobe.d/CIS.conf
echo "install dccp /bin/true" >> //etc/modprobe.d/CIS.conf
echo "install sctp /bin/true" >> //etc/modprobe.d/CIS.conf
echo "install rds /bin/true" >> //etc/modprobe.d/CIS.conf
echo "install tipc /bin/true" >> //etc/modprobe.d/CIS.conf
sudo chmod 700 //etc/modprobe.d/CIS.conf

sudo chmod 777 //etc/audit/auditd.conf
echo "max_log_file = 16384" >> //etc/audit/auditd.conf
echo "space_left_action = email" >> //etc/audit/auditd.conf
echo "action mail acct = root" >> //etc/audit/auditd.conf
echo "admin_space_left_action = halt" >> //etc/audit/auditd.conf
echo "max_log_file_action = keep_logs" >> //etc/audit/auditd.conf
sudo chmod 700 //etc/audit/auditd.conf
systemctl reload auditd
sudo chmod 777 //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S clock_settime -k time-change -w /etc/localtime -p wa -k time-change" >> //etc/audit/audit.rules
echo "-w /etc/group -p wa -k identity" >> //etc/audit/audit.rules
echo "-w /etc/passwd -p wa -k identity" >> //etc/audit/audit.rules
echo "-w /etc/gshadow -p wa -k identity" >> //etc/audit/audit.rules
echo "-w /etc/shadow -p wa -k identity" >> //etc/audit/audit.rules
echo "-w /etc/security/opasswd -p wa -k identity" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> //etc/audit/audit.rules
echo "-w /etc/issue -p wa -k system-locale" >> //etc/audit/audit.rules
echo "-w /etc/issue.net -p wa -k system-locale" >> //etc/audit/audit.rules
echo "-w /etc/hosts -p wa -k system-locale" >> //etc/audit/audit.rules
echo "-w /etc/sysconfig/network -p wa -k system-locale" >> //etc/audit/audit.rules
echo "-w /etc/apparmor/ -p wa -k MAC-policy" >> //etc/audit/audit.rules
echo "-w /etc/apparmor.d/ -p wa -k MAC-policy" >> //etc/audit/audit.rules
echo "-w /var/log/faillog -p wa -k logins" >> //etc/audit/audit.rules
echo "-w /var/log/lastlog -p wa -k logins" >> //etc/audit/audit.rules
echo "-w /var/log/tallylog -p wa -k logins" >> //etc/audit/audit.rules
echo "-w /var/run/utmp -p wa -k session" >> //etc/audit/audit.rules
echo "-w /var/log/wtmp -p wa -k logins" >> //etc/audit/audit.rules
echo "-w /var/log/btmp -p wa -k logins" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> //etc/audit/audit.rules
echo "-w /etc/sudoers -p wa -k scope" >> //etc/audit/audit.rules
echo "-w /etc/sudoers.d/ -p wa -k scope" >> //etc/audit/audit.rules
echo "-w /var/log/sudo.log -p wa -k actions" >> //etc/audit/audit.rules
echo "-w /sbin/insmod -p x -k modules" >> //etc/audit/audit.rules
echo "-w /sbin/rmmod -p x -k modules" >> //etc/audit/audit.rules
echo "-w /sbin/modprobe -p x -k modules" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> //etc/audit/audit.rules
sudo chmod 700 //etc/audit/auditd.conf
sudo chmod 777 //etc/audit/.rules
echo "-e 2" >> //etc/audit/.rules
sudo chmod 700 //etc/audit/.rules

systemctl enable rsyslog
sudo chmod 777 //etc/rsyslog.conf
echo "$FileCreateMode 0640" >> //etc/rsyslog.conf
sudo chmod 700 //etc/rsyslog.conf
sudo chmod 777 //etc/rsyslog.d/*.conf
echo "$FileCreateMode 0640" >> //etc/rsyslog.d/*.conf
sudo chmod 700 //etc/rsyslog.d/*.conf
sudo chmod -R g-wx,o-rwx //var/log/*

systemctl enable cron

sudo chmod 777 //etc/default/grub
echo "GRUB_CMDLINE_LINUX="ipv6.disable=1"" >> //etc/default/grub
echo "GRUB_CMDLINE_LINUX="audit=1"" >> //etc/default/grub
sudo chmod 700 //etc/default/grub
update-grub

sudo useradd -D -f 30
sudo usermod -g 0 root
sudo chmod 777 //etc/bash.bashrc
echo "umask 027" >> //etc/bash.bashrc
sudo chmod 700 //etc/bash.bashrc
sudo chmod 777 //etc/profile
echo "umask027" >> //etc/profile
echo "TMOUT=600" >> //etc/profile
sudo chmod 700 //etc/profile
sudo chmod 777 //etc/profile.d/*.sh
echo "umask 027" >> //etc/profile.d/*.sh
sudo chmod 700 //etc/profile.d/*.sh
sudo chmod 777 //etc/bashrc
echo "TMOUT=600" >> //etc/bashrc
sudo chmod 700 //etc/bashrc

apt-get install auditd -y
auditctl -e 1 > /var/local/audit.log

  echo "creating /var/local"
  mkdir /var/local/
  echo "creating log files in /var/local"
  echo -n "" > /var/local/netstat.log
  echo -n "" > /var/local/ASAO.log
  echo -n "" > /var/local/mediafiles.log
  echo -n "" > /var/local/cronjoblist.log
  echo -n "" > /var/local/pslist.log
  echo "adding instructions to log file"
  echo "getent group <groupname> |||| Users in group" >> /var/local/ASAO.log
  echo "edit /etc/audit/auditd.conf" >> /var/local/ASAO.log
  echo "Don't Forget to Restart" >> /var/local/ASAO.log
  echo "more password stuff @ https://www.cyberciti.biz/tips/linux-check-passwords-against-a-dictionary-attack.html" >> /var/local/ASAO.log

	apt-get install libpam-cracklib -y

	touch oldSysctl.txt
	sudo cp /etc/sysctl.conf oldSysctl.txt

  	touch oldSSHD.txt
   	sudo cp /

 
	PAMUNIX="$(grep -n 'pam_unix.so' /etc/pam.d/common-password | grep -v '#' | cut -f1 -d:)"
	sed -e "${PAMUNIX}s/.*/password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass sha512 remember=5/" /etc/pam.d/common-password > /var/local/temp.txt
 	PAMCRACKLIB="$(grep -n 'pam_cracklib.so' /etc/pam.d/common-password | grep -v '#' | cut -f1 -d:)"
	sed -e "${PAMCRACKLIB}s/.*/password	requisite	pam_cracklib.so retry=3 minlen=8 difok=3 ucredit=-1 1credit=-2 ocredit=-1/" /var/local/temp.txt > /var/local/temp2.txt
	rm /var/local/temp.txt
	mv /etc/pam.d/common-password /etc/pam.d/common-password.old
	mv /var/local/temp2.txt /etc/pam.d/common-password
 	PASSMAX="$(grep -n 'PASS_MAX_DAYS' /etc/login.defs | grep -v '#' | cut -f1 -d:)"
	sed -e "${PASSMAX}s/.*/PASS_MAX_DAYS	90/" /etc/login.defs > /var/local/temp1.txt
	PASSMIN="$(grep -n 'PASS_MIN_DAYS' /etc/login.defs | grep -v '#' | cut -f1 -d:)"
	sed -e "${PASSMIN}s/.*/PASS_MIN_DAYS	10/" /var/local/temp1.txt > /var/local/temp2.txt
	PASSWARN="$(grep -n 'PASS_WARN_AGE' /etc/login.defs | grep -v '#' | cut -f1 -d:)"
	sed -e "${PASSWARN}s/.*/PASS_WARN_AGE	7/" /var/local/temp2.txt > /var/local/temp3.txt
 	#does this work better?
 	#cp /etc/login.defs /etc/login.defs1
	#sed -i "s/PASS_MAX_DAYS	99999/PASS_MAX_DAYS 90/" /etc/login.defs
	#sed -i "s/PASS_MIN_DAYS	0/PASS_MIN_DAYS 7/" /etc/login.defs
	#sed -i "s/PASS_WARN_AGE	7/PASS_WARN_AGE 14/" /etc/login.defs
	mv /etc/login.defs /etc/login.defs.old
	mv /var/local/temp3.txt /etc/login.defs
	rm /var/local/temp1.txt /var/local/temp2.txt
	cp /etc/pam.d/common-auth /etc/pam.d/common-auth.old
	echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" >> /etc/pam.d/common-auth
 	PRL="$(grep -n 'PermitRootLogin' /etc/ssh/sshd_config | grep -v '#' | cut -f1 -d:)"
	sed -e "${PRL}s/.*/PermitRootLogin no/" /etc/ssh/sshd_config > /var/local/temp1.txt
	mv /etc/ssh/sshd_config /etc/ssh/sshd_config.old
	mv /var/local/temp1.txt /etc/ssh/sshd_config

 	cp /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.conf.old
	echo "allow-guest=false" >> /etc/lightdm/lightdm.conf

 	crontab -l >> /var/local/cronjoblist.log

  	ps axk start_time -o start_time,pid,user,cmd >> /var/local/pslist.log

   	ss -an4 > /var/local/netstat.log
    
	echo -e "${LightBlue}Done Securing Random Configs${NC}"
}

secureSSH () {
	echo -e "${LightBlue}Securing SSH${NC}"
	#asks if ssh is a critical service
	echo -e "${LightBlue}Is SSH a critical service? y/n:${NC}"
 	read yorn
	if [ $yorn == y ]; then
		#install ssh
		apt-get install ssh -y
		apt-get install openssh-server -y
		
		echo -e "${LightBlue}Opening /etc/ssh/sshd_config ..."
		sleep 2s
		#open /etc/ssh/sshd_config
		sudo nano /etc/ssh/sshd_config

		#Restart SSH
		echo -e "${LightBlue}Restarting SSH"
		sleep 2s
		sudo service ssh restart
		sudo service sshd restart
	elif [ $yorn == n ]; then
		#uninstall ssh
  		echo -e "${LightBlue}Uninstalling SSH"
		apt-get autoremove --purge ssh openssh-server
	fi
	echo -e "${LightBlue}Done Securing SSH${NC}"
}

getGoodPrograms () {
	apt-get install rkhunter chkrootkit -y
	echo -e "${LightBlue}installed rkhunter and chrootkit${NC}"
}

echo -e "${GREEN}--------- Start of Script ---------${NC}"
deleteUsers
verifyAdmins
changePasswords
portStuff
ufwFirewall
zeroUIDUsers
secureRootCron
secureFiles
updateStuff
secureSSH
getGoodPrograms
findMedia
echo -e "${GREEN}--------- End of Script ---------${NC}"
