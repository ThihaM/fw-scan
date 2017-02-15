# fw-scan
A firewall utility for various scanning and dictionary attack

# 1: Installation

1.1 RPM based systems

[~]# yum install epel-release

[~]# yum install php php-cli php-common screen sshpass git vim

1.2 Deb based system

# 2: Cloning repository

[~]# cd /usr/src

[~]# git clone https://github.com/ThihaM/fw-scan.git

[~]# cd fw-scan

# 3: Using fw-scan

Add log file location in config file

[~]# vim fw-scan.conf

Add log file location of the desire services in 'Services' section of the fw-scan.conf

# 4: Running fw-scan.php

[~]# screen -Adm php /usr/src/fw-scan/fw-scan.php

Note: fw-scan.php log files can be view in /var/log/fw-scan/ directory
