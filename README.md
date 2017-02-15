# fw-scan
A firewall utility for various scanning and dictionary attack

1: Installation
===============

1.1 RPM based systems
---------------------
#yum install epel-release
#yum install php php-cli php-common screen sshpass git vim

1.2 Deb based system
--------------------

2: Cloning repository
======================
#cd /usr/src
#git clone https://github.com/ThihaM/fw-scan.git
#cd fw-scan

3: Using fw-scan
================

3.1 Add log file location in config file
----------------------------------------
#vim fw-scan.conf
Add log file location of the desire services in 'Services' section of the fw-scan.conf

Example fw-scan.conf file

[General]
 message_queue = '500'
 logdir = '/var/log/fw-scan'
 
[Keywords]
 keywords[] = 'forbidden'
 keywords[] = 'wrong password'
 keywords[] = 'failed'
 keywords[] = 'unable to authenticate'
 keywords[] = 'not found'
 
[Services]
 logfiles[] = '/var/log/asterisk/messages'
 logfiles[] = '/var/log/httpd/access_log'
 logfiles[] = '/var/log/secure'

[Linux-Firewall-A]
 type = 'firewall'
 host = 'localhost'
 rule = '/usr/sbin/iptables -A INPUT -s @SRC_IP -j DROP'

;[Linux-Firewall-B]
; type  = 'firewall'
; host  = '10.10.10.254'
; uname = 'firewall-admin'
; pass  = 'secret-password'
; rule  = '/usr/sbin/iptables -A INPUT -s @SRC_IP -j DROP'

3.2 Runing fw-scan.php
----------------------
#screen -Adm php /usr/src/fw-scan/fw-scan.php

Note: fw-scan.php log files can be view in /var/log/fw-scan/ directory
