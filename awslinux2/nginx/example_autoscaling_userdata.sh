#!/bin/bash
#opsinsight auto-scaling script
#Version 0.5
#Date 5.19.2021
#####################################Notes#####################################
#This script shows examples to configure additional utilities/integrations such as Okta
#Actual requirements will vary
#OKTA_CLIENT_ID is assumed to be in build artifact being pulled from S3
#OKTA_CLIENT_ID = ************* which will be stored in secrets manager and should be replaced as needed
###############################################################################
#TODO
#Move to certbot/lets encrypt and get new certs on deploy
#TADA!
#Failure to set ENV properly will lead to failures of steps below and incorrect configuration
#Suggest moving these values into secret record or AWS tags and retrieving via meta-data call
bash -c 'echo "ENV=prod" >> /etc/profile.d/site1_envvars.sh'
source /etc/profile.d/site1_envvars.sh

#Initial yum update
yum update -y

#Configure aws cli
aws configure set region us-west-2

#Get installation variables
INSTALL_VARS=$(aws secretsmanager get-secret-value --secret-id ${ENV}/site1/install/vars --query 'SecretString')
OKTA_CLIENT_ID=$(echo $INSTALL_VARS | jq 'fromjson | .okta_client_id' -r)
DEFAULT_OKTA_CLIENT_ID=$(echo $INSTALL_VARS | jq 'fromjson | .default_okta_client_id' -r)
OKTA_URL=$(echo $INSTALL_VARS | jq 'fromjson | .okta_url' -r)
DEFAULT_OKTA_URL=$(echo $INSTALL_VARS | jq 'fromjson | .default_okta_url' -r)
PACKAGEPASSWORD=$(echo $INSTALL_VARS | jq 'fromjson | .packagepassword' -r)
SERVERNAME=$(echo $INSTALL_VARS | jq 'fromjson | .servername' -r)

#Configure ngnix
systemctl enable nginx
systemctl start nginx
sed -i '/^#/d' /etc/nginx/nginx.conf #because sample section at the end...who needs comments anyway
sed -i "s/server_name\s\s_;/\server_name  ${SERVERNAME};/g" /etc/nginx/nginx.conf #Double quotes to get actual variable value
sed -i 's/\/usr\/share\/nginx\/html;/\/usr\/share\/nginx\/html\/site1;/g' /etc/nginx/nginx.conf

#Update nginx.conf to support Okta
sed -i '\/usr\/share\/nginx\/html\/site1;/a\        \location / {\n          try_files $uri $uri\/ \/index.html;\n        }' /etc/nginx/nginx.conf #Single quotes to put actual variable next as oppsed to an actual value
systemctl restart nginx

#Get site1 artifact from S3
aws s3 cp s3://example.com/opsinsight/$ENV/site1.zip ./
#Unzip to Ngnix directory
unzip -oP $PACKAGEPASSWORD site1.zip -d /usr/share/nginx/html/site1/

#Get app javascript file
JSFILE=$(ls /usr/share/nginx/html/site1/*.js)

#Update OKTA_CLIENT_ID
sed -i "s/${DEFAULT_OKTA_CLIENT_ID}/${OKTA_CLIENT_ID}/g" ${JSFILE}
#Update Okta URL
sed -i "s/${DEFAULT_OKTA_URL}/${OKTA_URL}/g" ${JSFILE}

#Change file ownership as user-data runs as root
chown nginx:nginx /usr/share/nginx/html/site1/*

#SSL configuration
aws secretsmanager get-secret-value --secret-id common/ssl-cert-json --query 'SecretString' | jq 'fromjson | .cert' -r >> ./example.com.wildcard.bundle.crt
aws secretsmanager get-secret-value --secret-id common/ssl-chain-json --query 'SecretString' | jq 'fromjson | .chain' -r >> ./example.com.wildcard.bundle.crt
cp ./example.com.wildcard.bundle.crt /etc/pki/tls/certs/wildcard.bundle.crt
rm ./example.com.wildcard.bundle.crt

aws secretsmanager get-secret-value --secret-id common/ssl-pem-json --query 'SecretString' | jq 'fromjson | .pem' -r >> ./example.com.wildcard.private.pem
KWCPW=$(aws secretsmanager get-secret-value --secret-id common/ssl-pass --query 'SecretString' | jq 'fromjson | .password' -r)
echo ${KWCPW} >> ./ssl_passwords
cp ./ssl_passwords /var/lib/nginx/ssl_passwords
chmod 600 /var/lib/nginx/ssl_passwords
shred -zvu -n5 ./ssl_passwords

openssl pkcs8 -in ./example.com.wildcard.private.pem -topk8 -out ./example.com.wildcard.private.enc.pem -passout pass:${KWCPW}
cp ./example.com.wildcard.private.enc.pem /etc/pki/tls/private/example.com.wildcard.private.enc.pem
chmod 600 /etc/pki/tls/private/example.com.wildcard.private.enc.pem
shred -zvu -n 5 ./example.com.wildcard.private.pem #v not necessary here but someday maybe I'll write the output to a log for review? Probably not but its nice to dream
shred -zvu -n 5 ./example.com.wildcard.private.enc.pem

#Configure Ngnix for SSL
sed -i 's/        listen       80;/\        listen       443 ssl;/g' /etc/nginx/nginx.conf
sed -i '/        listen       443 ssl;/a\        ssl_ciphers HIGH:!aNULL:!MD5;' /etc/nginx/nginx.conf
sed -i '/        listen       443 ssl;/a\        ssl_protocols TLSv1.2;' /etc/nginx/nginx.conf
sed -i '/        listen       443 ssl;/a\        ssl_certificate_key /etc/pki/tls/private/example.com.wildcard.private.enc.pem;' /etc/nginx/nginx.conf
sed -i '/        listen       443 ssl;/a\        ssl_certificate /etc/pki/tls/certs/example.com.wildcard.bundle.crt;' /etc/nginx/nginx.conf
sed -i '/        listen       443 ssl;/a\        ssl_password_file /var/lib/nginx/ssl_passwords;' /etc/nginx/nginx.conf
systemctl restart nginx

#Set desired OpenSSH config
sed -i '/#RekeyLimit default none/a\KexAlgorithms curve25519-sha256@libssh.org' /etc/ssh/sshd_config
sed -i '/#RekeyLimit default none/a\Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' /etc/ssh/sshd_config
sed -i '/#RekeyLimit default none/a\MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com' /etc/ssh/sshd_config
systemctl restart sshd

#Install Datadog
DD_API_KEY=$(aws secretsmanager get-secret-value --secret-id common/datadog-install --query 'SecretString' | jq 'fromjson | .apikey' -r) bash -c "$(curl -L https://raw.githubusercontent.com/DataDog/datadog-agent/master/cmd/agent/install_script.sh)"

#Edit /etc/datadog-agent/datadog.yaml to add the appropriate tags, and set logs_enabled to true for the system
sed -i '/# tags/i tags:\n  - app:site1\n  - os:linux\n  - dist:aws\n' /etc/datadog-agent/datadog.yaml
sed -i "/# env: <environment name>/i env: ${ENV}\n" /etc/datadog-agent/datadog.yaml
sed -i '/# logs_enabled: false/i logs_enabled: true\n' /etc/datadog-agent/datadog.yaml
sed -i '/# logs_config:/i logs_config:\n  use_http: true\n  use_compression: true\n' /etc/datadog-agent/datadog.yaml
sed -i '/# process_config:/i process_config:\n  enabled: "true"\n' /etc/datadog-agent/datadog.yaml

#Add logging for user authentication
chmod 644 /var/log/secure #makes log readable by Dataog agent
mkdir /etc/datadog-agent/conf.d/var_log_auth.d 
echo "logs:" >> ./conf.yaml
echo "  - type: file" >> ./conf.yaml
echo "    path: /var/log/secure" >> ./conf.yaml
echo "    service: authentication" >> ./conf.yaml
echo "    source: secure" >> ./conf.yaml
cp ./conf.yaml /etc/datadog-agent/conf.d/var_log_auth.d/conf.yaml
rm ./conf.yaml

#Add ngnix logs to datadog
chmod +x /var/log/ngnix
chmod 644 /var/log/nginx/error.log #makes log readable by Dataog agent
mkdir /etc/datadog-agent/conf.d/var_log_nginx_error.d 
echo "logs:" >> ./conf.yaml
echo "  - type: file" >> ./conf.yaml
echo "    path: /var/log/nginx/error.log" >> ./conf.yaml
echo "    service: site1" >> ./conf.yaml
echo "    source: ngnix_error" >> ./conf.yaml
cp ./conf.yaml /etc/datadog-agent/conf.d/var_log_nginx_error.d/conf.yaml
rm ./conf.yaml

chmod 644 /var/log/nginx/access.log #makes log readable by Dataog agent
mkdir /etc/datadog-agent/conf.d/var_log_nginx_access.d 
echo "logs:" >> ./conf.yaml
echo "  - type: file" >> ./conf.yaml
echo "    path: /var/log/nginx/access.log" >> ./conf.yaml
echo "    service: opsinsight" >> ./conf.yaml
echo "    source: ngnix_accesss" >> ./conf.yaml
echo "    log_processing_rules:" >> ./conf.yaml
echo "    - type: exclude_at_match" >> ./conf.yaml
echo "      name: elb_health_check" >> ./conf.yaml
echo "      pattern: ELB-HealthChecker" >> ./conf.yaml
cp ./conf.yaml /etc/datadog-agent/conf.d/var_log_nginx_access.d/conf.yaml
rm ./conf.yaml

#Add process monitoring for Nginx
#If names in the below code block are not used, Datadog monitors will not work
echo "init_config:" >> ./process.yaml
echo "instances:" >> ./process.yaml
echo "  - name: Nginx" >> ./process.yaml
echo "    search_string: ['nginx']" >> ./process.yaml
echo "    tags:" >> ./process.yaml
echo "      - app:site1" >> ./process.yaml
echo "      - dist:aws" >> ./process.yaml
echo "      - env:${ENV}" >> ./process.yaml
echo "      - os:linux" >> ./process.yaml
cp ./process.yaml /etc/datadog-agent/conf.d/process.d/conf.yaml
rm ./process.yaml
systemctl stop datadog-agent
systemctl start datadog-agent

#Update AWS tags
#Get instance-id so EIP can be associate
METADATA=$(curl http://169.254.169.254/latest/meta-data/instance-id)
aws ec2 create-tags --resources ${METADATA} --tags Key=Name,Value=ngnix1 Key=Application,Value=site1 Key=Environment,Value=production Key=StaticEIP,Value=no Key=Datadog,Value=true Key=LastPatched,Value=7/15

#Set Hostname and reboot
hostnamectl set-hostname ngnix1
shutdown now -r
