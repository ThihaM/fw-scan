# fw-scan
A firewall utility for various scanning and dictionary attack

# Installation

RPM based systems

#yum install epel-release
#yum install php php-cli php-common screen sshpass git vim

Deb based system

# Cloning repository

#cd /usr/src
#git clone https://github.com/ThihaM/fw-scan.git
#cd fw-scan

# Using fw-scan

Add log file location in config file

vim fw-scan.conf
Add log file location of the desire services in 'Services' section of the fw-scan.conf

# Runing fw-scan.php

screen -Adm php /usr/src/fw-scan/fw-scan.php

Note: fw-scan.php log files can be view in /var/log/fw-scan/ directory
