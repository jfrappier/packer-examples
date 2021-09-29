<powershell>
#A role with correct permissions will need to be applied to the instance at launch
#Allow scripts to run for duration of the script
Set-ExecutionPolicy Bypass -Scope Process -Force

#Force time sync
w32tm /resync /rediscover
#Again because some times it fails
w32tm /resync /rediscover

#Setup logging
$UserdataExecution = "C:\ProgramData\Amazon\EC2-Windows\Launch\Log\UserdataExecution.log"

#Get and extract web contents to WebApp folders
aws s3 cp s3://example.com/iis/dev/site1.zip C:\Deploy
aws s3 cp s3://example.com/iis/dev/site2.zip C:\Deploy
aws s3 cp s3://example.com/iis/dev/siteN.zip C:\Deploy

"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Deploying packages" | Out-File $UserdataExecution -Append
Set-Location -Path c:\deploy
7z x .\site1.zip -pZOMGCHANGEMEORMOVEME -oC:\WebApp\site1 -spe -y
7z x .\site2.zip -pZOMGCHANGEMEORMOVEME -oC:\WebApp\site2 -spe -y #example inline comment
7z x .\siteN.zip -pZOMGCHANGEMEORMOVEME -oC:\WebApp\siteN -spe -y

#Example of adding an environment variable
$EnvVarValues = aws secretsmanager get-secret-value --secret-id dev/site1/env-vars | ConvertFrom-Json
$EnvVarValues = $EnvVarValues.SecretString | ConvertFrom-Json
[Environment]::SetEnvironmentVariable("$($EnvVarValues.envvar)", "server=$($EnvVarValues.dbSrv),1433;database=$($EnvVarValues.dbName);Connection Timeout=15; pooling=true;multipleactiveresultsets=True;Persist Security Info=True", "Machine")

$Keys = @(
("example1_from_secretsmanager"),
("example2_from_secretsmanager"),
("exampleN_from_secretsmanager")
)

ForEach ($key in $keys)
{
  [Environment]::SetEnvironmentVariable("$($key)", "$($EnvVarValues.$key)", "Machine")
}

#Set working directory for getting files
Set-Location -Path c:\deploy

#Get Wildcard cert from Secret Manager
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Creating SSL certificate" | Out-File $UserdataExecution -Append
$PoshPEMResponse = aws secretsmanager get-secret-value --secret-id common/ssl-pem | ConvertFrom-Json
$pem = $PoshPEMResponse.SecretString | ConvertFrom-Json
Add-Content -Path "c:\deploy\pk.pem" -Value $pem.sslpem

$PoshWCResponse = aws secretsmanager get-secret-value --secret-id common/ssl-cert | ConvertFrom-Json
$wc = $PoshWCResponse.SecretString | ConvertFrom-Json
Add-Content -Path "c:\deploy\wc.crt" -Value $wc.sslwc

$PoshWCCHNResponse = aws secretsmanager get-secret-value --secret-id common/ssl-chain | ConvertFrom-Json
$wcchn = $PoshWCCHNResponse.SecretString | ConvertFrom-Json
Add-Content -Path "c:\deploy\wc.crt" -Value $wcchn.sslchn

#Create pfx file to import
openssl pkcs12 -export -out certificate.pfx -inkey pk.pem -in wc.crt -password pass:$($EnvVarValues.dbPwd)

#Convert PW to secure string to support Import-PfxCertificate import process
$pfxpw = ConvertTo-SecureString -String $($EnvVarValues.dbPwd) -AsPlainText -Force

#Import Wildcard Certificate
$sslcert = Import-PfxCertificate -FilePath certificate.pfx -CertStoreLocation Cert:\LocalMachine\My -Password $pfxpw

#Add HTTPS binding to site1
Set-WebBinding -Name "site1" -HostHeader "replacemeadm.example.com" -PropertyName "HostHeader" -Value "site1.example.com"
New-WebBinding -Name "site1" -IPAddress "*" -Port 443 -HostHeader "site1.example.com" -Protocol https
$site = Get-Website -Name "site1"
Get-ChildItem IIS:\AppPools\ | Where-Object { $_.Name -eq $site.applicationPool } | Set-ItemProperty -name "startMode" -Value "AlwaysRunning"
$binding = Get-WebBinding -Name site1 -Protocol "https"
$binding.AddSslCertificate($kagrcert.GetCertHashString(), "My")

#Cleanup Files
Remove-Item c:\deploy\*.pfx
Remove-Item c:\deploy\*.crt
Remove-Item c:\deploy\*.pem

#Generate date string for java script and css files
$Date = Get-Date -Format "yyyyMMddHHmmss"

#Update index.html for site1
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Updating index.html" | Out-File $UserdataExecution -Append
$IndexHtml = "C:\WebApp\site1\index.html"

$Keys = @(
("window.env"),
("window.env.BASE_API"),
("window.env.MANAGEMENT_URL"),
("window.env.USER_INTERFACE")
)

$IndexHtmlValues = aws secretsmanager get-secret-value --secret-id iis/site1/index.html | ConvertFrom-Json
$IndexHtmlValues = $IndexHtmlValues.SecretString | ConvertFrom-Json

ForEach ($key in $keys)
{
  (Get-Content -Path $IndexHtml) | ForEach-Object {$_ -Replace "==$key==", $IndexHtmlValues.$key} | Set-Content -Path $IndexHtml
  write-host $key $IndexHtmlValues.$key
}

#Rename css and js files and update index.html
Rename-Item -Path "C:\WebApp\site1\index.css" -NewName "C:\WebApp\site1\index-$date.css"
Rename-Item -Path "C:\WebApp\site1\index.js" -NewName "C:\WebApp\site1\index-$date.js"
((Get-Content -Path $IndexHtml -Raw)) -Replace "./index.js", "./index-$date.js" | Set-Content -Path $IndexHtml
((Get-Content -Path $IndexHtml -Raw)) -Replace "./index.css", "./index-$date.css" | Set-Content -Path $IndexHtml

#Add URL rewrite rule for kagrui IIS site
Set-Location -Path c:\deploy
aws s3 cp s3://example.com/site1/dev/http-to-https.xml C:\Deploy
get-content ".\http-to-https.xml" | & c:\windows\system32\inetsrv\AppCmd.exe set config "kagrui" /in
get-content ".\http-to-https.xml" | & c:\windows\system32\inetsrv\AppCmd.exe set config "kagradm" /in
Start-Website -Name "site1"
Start-Website -Name "site2"
Start-Website -Name "siteN"

#Datadog setup for auto-scaling portal
$apikey = aws secretsmanager get-secret-value --secret-id common/datadog-api-key | ConvertFrom-Json
$apikey = $apikey.SecretString | ConvertFrom-Json
(Get-Content -Path C:\ProgramData\Datadog\datadog.yaml -Raw) -replace "api_key: """"","api_key: ""$($apikey.apikey)""" | Set-Content -Path C:\ProgramData\Datadog\datadog.yaml

#Add tags for Datadog agent
$envtag = "- env:development"
$ostag = "- os:windows"
$apptag = "- app:iis"
(Get-Content -Path C:\ProgramData\Datadog\datadog.yaml -Raw) -replace "\btags\b: `\[`\]","tags:`n$envtag`n$ostag`n$apptag" | Set-Content -Path C:\ProgramData\Datadog\datadog.yaml

#Configure live process monitoring
(Get-Content -Path C:\ProgramData\Datadog\datadog.yaml -Raw) -replace "process_config:`n  enabled: ""false""","process_config:`n  enabled: ""true""" | Set-Content -Path C:\ProgramData\Datadog\datadog.yaml

#Configure login event logging
$evntconffile = "C:\ProgramData\Datadog\conf.d\win32_event_log.d\conf.yaml"
$evntconfcon = "init_config:`ninstances:`n  - event_id:`n    - 4624`n    - 4625`n    - 4672`n    - 4627"
Add-Content -Path $evntconffile -Value $evntconfcon

#Configure service logging - update for required services
$svcconffile = "C:\ProgramData\Datadog\conf.d\windows_service.d\conf.yaml"
$svcconfcon = "init_config:`ninstances:`n  - services:`n    - W3SVC"
Add-Content -Path $svcconffile -Value $svcconfcon

#Configure IIS logging for Datadog
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Configure Datadog agent" | Out-File $UserdataExecution -Append
$iisconffile = "C:\ProgramData\Datadog\conf.d\iis.d\conf.yaml"
$iisconfcon = "init_config:`ninstances:`n  - host: .`n    tags:`n      - env:dev`n      - iis:iis`n    sites:`n      - site1`n      - site2"
Add-Content -Path $iisconffile -Value $iisconfcon

#Enable log processing
(Get-Content -Path C:\ProgramData\Datadog\datadog.yaml -Raw) -replace "logs_enabled: false","logs_enabled: true" | Set-Content -Path C:\ProgramData\Datadog\datadog.yaml

#Configure IIS logs conf.yaml 
$apilogconffile = "C:\ProgramData\Datadog\conf.d\site1.log.d\conf.yaml"
$apilogconfcon = "init_config:`ninstances:`nlogs:`n  - type: file`n    path: C:\WebApp\site1\logs\site1.json`n    service: site1`n    source: site1"
New-Item -Path "C:\ProgramData\Datadog\conf.d" -Name site1.d -ItemType "directory"
Add-Content -Path $apilogconffile -Value $apilogconfcon

#Change Local administrator password
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Adding Local Users" | Out-File $UserdataExecution -Append
$PoshAdminCredsResponse = aws secretsmanager get-secret-value --secret-id prod/windows/localusers | ConvertFrom-Json
$AdminCreds = $PoshAdminCredsResponse.SecretString | ConvertFrom-Json
$AdminCredsPass = ConvertTo-SecureString -String $($AdminCreds.adminpass) -AsPlainText -Force
Set-LocalUser -Name $AdminCreds.adminname -Password $AdminCredsPass

#Now that the site1 code is in place and IIS configured, configure EIPs
"$(Get-Date -Format "yyyy:MM:dd HH:mm:ss") Updating public IPs" | Out-File $UserdataExecution -Append

#Get instance-id so EIP can be associate
#The EIPs are pre-allocated so that they can be added to the instance
$local = curl http://169.254.169.254/latest/meta-data/instance-id

if ($local.Content -eq $null){
  Add-Content -Path $UserdataExecution -Value "Retrieving meta-data produced a null value for the instance-id. Trying again."
  #Try again to get meta-data
  $local = curl http://169.254.169.254/latest/meta-data/instance-id
  Add-Content -Path $UserdataExecution -Value "Results from meta-data on 2nd attempt request failed"
  }
else {
  Add-Content -Path $UserdataExecution -Value "Results from meta-data on 1st request for instance id: $local"
  }

#Loop through pre-allocated EIPs for availability
$pubip = (aws ec2 describe-addresses --public-ip x.x.x.x | ConvertFrom-Json)

If (!$pubip.Addresses.AssociationID) 
{ 
    aws ec2 associate-address --instance-id $local.Content --public-ip x.x.x.x
    aws ec2 create-tags --resources $local.Content --tags Key=Name,Value=site1 Key=Application,Value=site1 Key=Environment,Value=Development Key=StaticEIP,Value=yes Key=Datadog,Value=true Key=LastPatched,Value=4/20
    Set-TimeZone -Name "Eastern Standard Time"
    Rename-Computer -NewName "site1" -LocalCredential $LocalCreds -Restart
} 
Else 
{ 
    aws ec2 associate-address --instance-id $local.Content --public-ip y.y.y.y
    aws ec2 create-tags --resources $local.Content --tags Key=Name,Value=site2 Key=Application,Value=site2 Key=Environment,Value=Development Key=StaticEIP,Value=yes Key=Datadog,Value=true Key=LastPatched,Value=4/20
    Set-TimeZone -Name "Eastern Standard Time"
    Rename-Computer -NewName "site2" -LocalCredential $LocalCreds -Restart
}
</powershell>
