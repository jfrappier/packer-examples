#!/bin/bash
#awslinux2 nginx ami-base script
#Version 0.1
#Date 5.13.2021
#####################################Notes#####################################
#Setup basics for nginx based application
#Created separate AMI to support encrypting volume which was not an option
#In the launch configuration
###############################################################################
#Initial yum update
sudo yum update -y

#Configure aws cli
aws configure set region us-west-2

#Set local time zone
sudo sed -i "/ZONE=/c\ZONE=\"America/New_York\"" /etc/sysconfig/clock
sudo ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime

#Install utilities
sudo amazon-linux-extras install epel nginx1 -y
sudo yum install jq firewalld fail2ban fail2ban-systemd -y
sudo yum update -y

#Configure firewalld
sudo systemctl start firewalld
sudo firewall-cmd --set-default-zone=public
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --zone=internal --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=22/tcp
sudo firewall-cmd --reload
sudo firewall-cmd --list-all

#Configure fail2ban
sudo cp -pf /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo echo "[sshd]" >> ./sshd.local
sudo echo "enabled = true" >> ./sshd.local
sudo echo "port = ssh" >> ./sshd.local
sudo echo "#action = firewallcmd-ipset" >> ./sshd.local
sudo echo "logpath = %(sshd_log)s" >> ./sshd.local
sudo echo "maxretry = 5" >> ./sshd.local
sudo echo "bantime = 3600" >> ./sshd.local
sudo cp ./sshd.local /etc/fail2ban/jail.d/sshd.local
cat /etc/fail2ban/jail.d/sshd.local
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

#Configure ngnix
sudo mkdir /usr/share/nginx/html/site1
sudo mkdir /usr/share/nginx/html/site2
sudo mkdir /usr/share/nginx/html/siteN
