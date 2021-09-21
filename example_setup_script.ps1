Set-ExecutionPolicy Bypass -Scope Process -Force

#Setup logging
$UserdataExecution = "C:\ProgramData\Amazon\EC2-Windows\Launch\Log\UserdataExecution.log"

#Get instance ID via metadata
$metadata = Invoke-WebRequest -Uri http://169.254.169.254/latest/meta-data/instance-id

#Install Windows roles and features
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Installing Windows components" | Out-File $UserdataExecution -Append
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
Install-WindowsFeature -Name Web-HTTP-Redirect, Web-Http-Logging, Web-Net-Ext45, Web-AppInit, Web-Asp-Net45, Web-ISAPI-ext, Web-ISAPI-Filter, Web-Includes

#Install Chocolatey to install 3rd party tools
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Installing Chocolatey" | Out-File $UserdataExecution -Append
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

#Update current session for chocolatey
$Env:path = $env:path + ";C:\ProgramData\chocolatey\bin"

#Install 3rd party tools rewrite
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Installing utilities" | Out-File $UserdataExecution -Append
choco install urlrewrite -y --force
choco install 7zip -y --force
choco install awscli -y --force
choco install openssl.light -y --force
choco install notepadplusplus -y --force

#Update current session for new apps
$Env:path = $env:path + ";C:\Program Files\Amazon\AWSCLIv2"
$Env:path = $env:path + ";C:\Program Files\OpenSSL\bin"

#Create App Folders
New-Item -Path "C:\" -Name WebApp -ItemType "directory"
New-Item -Path "C:\" -Name Deploy -ItemType "directory"
New-Item -Path "C:\WebApp" -Name SITE1 -ItemType "directory"
New-Item -Path "C:\WebApp" -Name SITE2 -ItemType "directory"

#Create environment variable for RDS. AWS CLI for Secrets Manager requires region to be set, not only permission to read secret
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Setting up AWS CLI" | Out-File $UserdataExecution -Append
aws configure set region us-west-2

#Get package from from S3
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Getting portal packages" | Out-File $UserdataExecution -Append
Set-Location -Path "C:\Program Files\Amazon\AWSCLIV2\"

.\aws s3 cp s3://somebucket/somepackage C:\Deploy

#Set working directory for getting files
Set-Location -Path c:\deploy

#Remove Default Website
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Setting up IIS" | Out-File $UserdataExecution -Append
Remove-Website -Name "Default Web Site"

#Create IIS website
New-WebAppPool -Name "SITE1"
New-WebSite -Name "SITE1" -Port 8080 -PhysicalPath C:\WebApp\SITE1 -ApplicationPool SITE1

#Chnage default document for health check site
Add-WebConfiguration //defaultDocument/files "IIS:\sites\SITE1" -atIndex 0 -Value @{value="index.html"}

#Add Windows firewall rule for healthcheck
New-NetFirewallRule -DisplayName "Allow healthcheck in on 8080" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow

#Create IIS website
New-WebAppPool -Name "SITE2"
New-WebSite -Name "SITE2" -Port 80 -HostHeader "replaceme.com" -PhysicalPath C:\WebApp\SITE2 -ApplicationPool SITE2

#Set Timezone
Set-TimeZone -Name "Eastern Standard Time"

#Disable old SSL/TLS Ciphers
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Removing old SSL/Cipers" | Out-File $UserdataExecution -Append
#Get IIS Crypto tool
Set-Location -Path "C:\Program Files\Amazon\AWSCLIV2\"
.\aws s3 cp s3://somebucket/utilities/IISCryptoCli.exe C:\Deploy

#Run IIS Crypto with best practices flag
Set-Location -Path c:\deploy
.\iiscryptocli /template strict

#Windows Update
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name PSWindowsUpdate -Force
Get-WindowsUpdate -install -acceptall -ignorereboot

#Sysprep
powershell.exe C:\ProgramData\Amazon\EC2-Windows\Launch\Scripts\InitializeInstance.ps1 -Schedule
powershell.exe C:\ProgramData\Amazon\EC2-Windows\Launch\Scripts\SysprepInstance.ps1
