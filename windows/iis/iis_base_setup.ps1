#Setup logging to existing userdata log
$UserdataExecution = "C:\ProgramData\Amazon\EC2-Windows\Launch\Log\UserdataExecution.log"

#Install required Windows roles and features for portal
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Installing Windows components" | Out-File $UserdataExecution -Append
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
Install-WindowsFeature -Name Web-HTTP-Redirect, Web-Http-Logging, Web-Net-Ext45, Web-AppInit, Web-Asp-Net45, Web-ISAPI-ext, Web-ISAPI-Filter, Web-Includes

#Install Chocolatey to install 3rd party tools
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Installing Chocolatey" | Out-File $UserdataExecution -Append
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

#Update current session for chocolatey
$Env:path = $env:path + ";C:\ProgramData\chocolatey\bin"

#Install 3rd party tools
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
New-Item -Path "C:\WebApp" -Name site1 -ItemType "directory"
New-Item -Path "C:\WebApp" -Name site2 -ItemType "directory"
New-Item -Path "C:\WebApp" -Name siteN -ItemType "directory"

#Confiugre aws cli
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Setting up AWS CLI" | Out-File $UserdataExecution -Append
aws configure set region us-west-2

#Get Latest health check site from S3
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Getting portal packages" | Out-File $UserdataExecution -Append
Set-Location -Path "C:\Program Files\Amazon\AWSCLIV2\"
.\aws s3 cp s3://example.com/iis/health_check.zip C:\Deploy

#Set working directory for getting files
Set-Location -Path c:\deploy

#Extract web contents to WebApp folders
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Deploying packages" | Out-File $UserdataExecution -Append
7z x .\KAGRHC.zip -pCHANGEMEALSOFIXIRL -oC:\WebApp\siteN -spe -y

#Remove Default Website
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Setting up IIS" | Out-File $UserdataExecution -Append
Remove-Website -Name "Default Web Site"

#Create IIS Healthcheck website
New-WebAppPool -Name "kagrhc"
New-WebSite -Name "healthcheck" -Port 8080 -PhysicalPath C:\WebApp\siteN -ApplicationPool siteN

#Chnage default document for health check site
Add-WebConfiguration //defaultDocument/files "IIS:\sites\siteN" -atIndex 0 -Value @{value="hc.html"}

#Add Windows firewall rule for healthcheck
New-NetFirewallRule -DisplayName "Allow healthcheck in on 8080" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow

#Create IIS website
New-WebAppPool -Name "site1"
#repalcemesite1.example.com can be used in subsquent userdata scripts to add the appropriate host header
New-WebSite -Name "site1" -Port 80 -HostHeader "replacemesite1.example.com" -PhysicalPath C:\WebApp\site1 -ApplicationPool site1

#Create IIS kagr api website
New-WebAppPool -Name "site2"
New-WebSite -Name "kagrapi" -Port 80 -HostHeader "replacemesite2.kagr.com" -PhysicalPath C:\WebApp\site2 -ApplicationPool site2

#Stop app websites
Stop-Website -Name "site1"
Stop-Website -Name "site2"
Stop-Website -Name "siteN"

#Set Timezone
Set-TimeZone -Name "Eastern Standard Time"

#Disable old SSL/TLS Ciphers
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Removing old SSL/Cipers" | Out-File $UserdataExecution -Append
#Get IIS Crypto tool
Set-Location -Path "C:\Program Files\Amazon\AWSCLIV2\"
.\aws s3 cp s3://example.com/iis/utilities/IISCryptoCli.exe C:\Deploy

#Run IIS Crypto with best practices flag
Set-Location -Path c:\deploy
.\iiscryptocli /template strict

#Windows Update
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name PSWindowsUpdate -Force
Get-WindowsUpdate -install -acceptall -ignorereboot #will reboot via Packer
