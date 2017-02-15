# fw-scan
A firewall utility for various scanning and dictionary attack

# 1: Installing Dependencies

1.1 RPM based systems

[~]# yum install epel-release

[~]# yum install php php-cli php-common screen sshpass git vim

1.2 Deb based system

# 2: Cloning repository

[~]# cd /usr/src

[~]# git clone https://github.com/ThihaM/fw-scan.git

[~]# cd fw-scan

# 3: Editing config file

[~]# vim fw-scan.conf

Add log file location of the desire services in 'Services' section of the fw-scan.conf

Example fw-scan.conf

[Services]

; Monitor Asterisk PABX service

 logfiles[] = '/var/log/asterisk/messages'

; Monitor Apache HTTP service

 logfiles[] = '/var/log/httpd/access_log'

; Monitor Open SSH service

 logfiles[] = '/var/log/secure'

# 4: Running fw-scan.php

[~]# screen -Adm php /usr/src/fw-scan/fw-scan.php

Note: fw-scan.php log files can be view in /var/log/fw-scan/ directory
