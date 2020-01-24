
1. Создане пользователя во время установки - tasmity

2. Разбивка диска во время установки
	- 4.2 - основной раздел /
	- 1024 - раздел подкачки
	- остальное раздел /home

3 Установк sudo
	apt-get install sudo

4. Добавление пользователя в группу sudo 
	usermod -a -G sudo tasmity
	usermod -a -G ssh tasmity

5. Редактируем файл /etc/network/interfaces
	auto enp0s8
	iface enp0s8 inet static
	address 192.168.100.2
	netmask 255.255.255.252

6 Создание ключей ssh
	ssh-keygen -t rsa
	ssh-copy-id -i ~/.ssh/id_rsa.pub tasmity@192.168.100.2

7. Настрой ssh, редактирование файла
	/etc/ssh/sshd_config
	- смена порта
	- запрет аунтификации по паролю
	- отграничением доступа по группе
		AllowGroups ssh
		DenyGroups root
	sudo systemctl restart sshd

8. Обновление пакетов
	sudo apt update
	sudo apt upgrade

9. Установка parted
	sudo apt-get install parted
	sudo parted -l

10. Настройа брандмауэра
	sudo apt-get install ufw
	- смена порта sudo nano ssh /etc/ufw/applications.d/openssh-server
	sudo ufw default deny incoming
	sudo ufw default allow outgoing
	sudo ufw allow OpenSSH
	sudo ufw allow 'WWW Full'
	sudo ufw enable
	sudo ufw status
	
	sudo apt-get install iptables-persistent
	Источник: https://liberatum.ru/blog/iptables-linux-secure
	# Запрет FIN-сканирования
	sudo iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
	# Запрет X-сканирования
	sudo iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
	# Запрет N-сканирования
	sudo iptables -A INPUT –p tcp –m tcp –-tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE –j DROP
	# Запрет SYN/ACK-сканирования
	sudo iptables -I INPUT -p tcp -m osf --genre NMAP -j DROP
	# Проверка на стук в нерабочие порты (10 в час)
	sudo iptables -A INPUT -m recent --rcheck --seconds 3600 --hitcount 10 --rttl -j RETURN
	# Вторая проверка на стук в нерабочие порты (2 в минуту)
	sudo iptables -A INPUT -m recent --rcheck --seconds 60 --hitcount 2 --rttl -j RETURN
	# Заносим адреса стучащихся в список
	sudo iptables -A INPUT -m recent --set
	# Отбрасываем пакеты всех, кто превысил лимит на количество подключений
	sudo iptables -P INPUT DROP
	sudo iptables-save > /etc/iptables/rules.v4
	sudo systemctl restart ufw

	
11. Защита от DOS атак на открытых портах:
	sudo apt-get install fail2ban
	- /etc/fail2ban/jail.d/defaults-debian.conf
	[DEFAULT]
bantime   = 600
findtime  = 10m
maxretry  = 2


# SSH jail
[sshd]
enabled   = true
port    = 7412
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry  = 3
bantime   = 600
findtime  = 10m

# ddos SSH jail
enabled = true
port = 7412
filter = sshd-ddos
logpath = %(sshd_log)s
maxretry = 2

[ssh-iptables-ipset4]
enabled = true
port = 7412
filter = sshd
action = iptables[name=SSH, port=ssh, protocol=tcp]
logpath = %(sshd_log)s
findtime = 300
maxretry = 3
bantime = 600

[dropbear]
enabled = true
port = 7412
logpath  = %(dropbear_log)s
backend  = %(dropbear_backend)s

# APACHE JAILS
[apache]
enabled = true
port = http,https
filter = apache-auth
logpath  = %(apache_error_log)s
maxretry = 3

[apache-multiport]
enabled = true
port = http,https
filter = apache-auth
logpath  = %(apache_error_log)s
maxretry = 3

[apache-auth]
enabled  = true
port     = http,https
maxretry = 3
bantime  = 10800
findtime = 3600

[apache-noscript]
enabled = true
port     = http,https
logpath  = %(apache_error_log)s
filter = apache-noscript
maxretry = 3

[apache-overflows]
enabled = true
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2


[postfix]
enabled = true
mode    = more
port    = smtp,465,submission
logpath = %(postfix_log)s
backend = %(postfix_backend)s
action = iptables[name=Postfix-smtp, port=smtp, protocol=tcp]
filter = postfix
bantime = 86400
maxretry = 3
findtime = 3600
ignoreip = 127.0.0.1

(разблокировка sudo fail2ban-client set ssh-iptables unbanip 61.147.103.113)


	- sudo apt-get install libapache2-mod-evasive
	Создаем файл настроек mod-evasive  /etc/apache2/mods-available/mod-evasive.conf
	<IfModule mod_evasive20.c>
	DOSHashTableSize 4096
	DOSPageCount 30
	DOSSiteCount 150
	DOSPageInterval 1
	DOSSiteInterval 1
	DOSBlockingPeriod 30
	DOSWhiteList 192.168.0.*
	DOSWhiteList 10.211.55.*
	DOSLogDir "/var/log/mod_evasive"
	DOSEmailNotify root@localhost
	</IfModule>
	-sudo a2enmod mod-evasive
	sudo service apache2 restart
	(скрипт для теста /usr/share/doc/libapache2-mod-evasive/examples/test.pl)
	
12. Защита от сканирования открытых портов:
	sudo apt-get install portsentry
	- отредактировать /etc/default/portsentry
	TCP_MODE="atcp"
	UDP_MODE="audp"
	- отредактировать /etc/portsentry/portsentry.conf
	BLOCK_UDP="1"
	BLOCK_TCP="1"
	KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"
	KILL_HOSTS_DENY="ALL: $TARGET$ : DENY"
	KILL_RUN_CMD=""/sbin/iptables -I INPUT -s $TARGET$ -j DROP && /sbin/iptables -I INPUT -s $TARGET$ -m limit --limit 3/minute --limit-burst 5 -j LOG --log-level debug --log-prefix 'Portsentry: dropping: '"
	PORT_BANNER="** UNAUTHORIZED ACCESS PROHIBITED *** YOUR CONNECTION ATTEMPT HAS BEEN LOGGED. GO AWAY."/"
	- проверка
	nmap 192.168.100.2
	/ets/hosts.deny
	
13. Остановка ненужных услуг:
	- список услуг со статусом
	sudo service --status-all
	- остановка услуг
	sudo systemctl disable console-setup.service
	sudo systemctl disable keyboard-setup.service
	sudo systemctl disable apt-daily.timer
	sudo systemctl disable apt-daily-upgrade.timer
	#sudo systemctl disable syslog.service
	
14. Создание скрипта который обновляет исходные файлы пакетов, а затем и сами пакеты
	- скрипт update.sh
	#!/bin/bash
	date >> /var/log/update_script.log
	apt-get update -y >> /var/log/update_script.log
	apt-get upgrade -y >> /var/log/update_script.log
	- права на выполнение
	sudo chmod +x update.sh
	- sudo crontab -e
	@reboot root /etc/cron.d/scripts/update.sh
	0 4 * * 1 root /etc/cron.d/scripts/update.sh

15. Создание скрипта для отслеживания изменений crontab
	- установка почты:
	sudo apt-get install mailutils
	sudo apt-get install postfix
	sudo dpkg-reconfigure postfix 
	- настройка почты
	редактировть /etc/aliases
	root: root
	- скрипт newcron.sh
	#!/bin/sh
	PRE=$(cat /var/lib/cron.md5)
	NEW=$(md5sum /etc/crontab)

	if [ "$PRE" != "$NEW" ]; then
        md5sum /etc/crontab > /var/lib/cron.md5
        echo "Warning! Crontab" | mail -s "The modified Crontab!" root
	fi
	- права на выполнение
	sudo chmod +x newcron.sh
	sudo md5sum /etc/crontab > /var/lib/cron.md5
	- sudo crontab -e
	0 0 * * * root /etc/cron.d/scripts/newcron.sh
	
16. Установк apache
	sudo apt-get install apache2
	sudo systemctl status apache2

17. Установка PHP
	- sudo apt-get install php
	sudo nano /etc/apache2/mods-enabled/dir.conf
	sudo systemctl restart apache2

18. Настройка SSL
	- создание сертификата
	sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt
	в Common Name вводим ip сервера
	- редактирование файла /etc/apache2/conf-available/ssl-params.conf
	SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
	SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
	SSLHonorCipherOrder On
	# Disable preloading HSTS for now.  You can use the commented out header line that includes
	# the "preload" directive if you understand the implications.
	# Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
	Header always set X-Frame-Options DENY
	Header always set X-Content-Type-Options nosniff
	# Requires Apache >= 2.4
	SSLCompression off
	SSLUseStapling on
	SSLStaplingCache "shmcb:logs/stapling-cache(150000)"
	# Requires Apache >= 2.4.11
	SSLSessionTickets Off
	- настройка хоста
	sudo nano /etc/apache2/sites-available/default-ssl.conf
	ServerAdmin tasmity@localhost
	ServerName 192.168.100.2
	SSLCertificateFile      /etc/ssl/certs/apache-selfsigned.crt
	SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key
	- настройка переадресации
	sudo nano /etc/apache2/sites-available/000-default.conf
	Redirect "/" "https://192.168.100.2/"
	- включите модуль Apache для SSL
	sudo a2enmod ssl
	sudo a2enmod headers
	- включите подготовленный виртуальный хост
	sudo a2ensite default-ssl
	- включить файл ssl-params.conf
	sudo a2enconf ssl-params
	- проверьте синтаксис на наличие ошибок
	sudo apache2ctl configtest
	- перезапуск сервера
	sudo systemctl restart apache2
	Redirect permanent "/" "https://192.168.100.2/"
	sudo apache2ctl configtest
	sudo systemctl restart apache2
	
19. Автоматизация развертывания сайта
	- установки git
	sudo apt-get install git
	- изменение прав на сайт
	sudo chown -R `whoami`:`id -gn` /var/www/html
	- создание репозитория на сервере
	mkdir ~/site.git
	cd site.git/
	git init --bare
	- создание хука#
	nano hooks/post-receive
	#!/bin/bash
	while read oldrev newrev ref
	do
	if [[ $ref =~ .*/master$ ]];
	then
	echo "Master ref received.  Deploying master branch to production..."
	git --work-tree=/var/www/html --git-dir=/home/tasmity/site.git checkout -f
	else
	echo "Ref $ref successfully received.  Doing nothing: only the master branch may be deployed on this server."
	fi
	done
	- установка прав
	chmod +x hooks/post-receive
	- локальные настройки
	git clone ssh://roger:/home/tasmity/site.git repo
	git remote add production ssh://roger:/home/tasmity/site.git
	
