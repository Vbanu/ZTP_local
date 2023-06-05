#Install-Module -Name Posh-SSH
Import-Module -Name Posh-SSH
Import-Module VMware.VimAutomation.Cis.Core
Import-Module VMware.VimAutomation.Core
Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -InvalidCertificateAction ignore -confirm:$false | Out-Null
cls
#$Password = "HP1nvent!"
#$User = "root"
$jsonFile=$args[0]
$data = Get-Content $jsonFile -Raw | ConvertFrom-JSON

$ArubaSwitch = ($data).ArubaSwitch;
$store = ($data).StoreID
$Password = $ArubaSwitch.password
$User = $ArubaSwitch.username
$MDFSwitch = $ArubaSwitch.MDFSwitchIP
$IDFSwitch = $ArubaSwitch.IDFSwitchIP

Write-Host "Executing iLO Port checks on store $store"

# This is what we will return.  True will be set if there is a failure
$status = 0

#ILO network Check

$ILO5 = "sthc05.st"+$store+".homedepot.com"
$ILO6 = "sthc06.st"+$store+".homedepot.com"
$ILO7 = "sthc07.st"+$store+".homedepot.com"

# Check network
"`n"
if(Test-Connection -ComputerName "$ILO5" -count 3 -ErrorAction SilentlyContinue)
{
Write-host " $ILO5 Available ON Network" -BackgroundColor Green -ForegroundColor Black
}
else
{
Write-Host " $ILO5 Network is OFF,Please ask tech to reseat ILO Cable/Connection " -BackgroundColor Red
}
"`n"
if(Test-Connection -ComputerName "$ILO6" -count 3 -ErrorAction SilentlyContinue)
{
Write-host " $ILO6 Available ON Network" -BackgroundColor Green -ForegroundColor Black
}
else
{
Write-Host " $ILO6 Network is OFF,Please ask tech to reseat ILO Cable/Connection " -BackgroundColor Red
}
"`n"
if(Test-Connection -ComputerName "$ILO7" -count 3 -ErrorAction SilentlyContinue)
{
Write-host " $ILO7 Available ON Network" -BackgroundColor Green -ForegroundColor Black
}
else
{
Write-Host " $ILO7 Network is OFF,Please ask tech to reseat ILO Cable/Connection " -BackgroundColor Red
}

"`n"
Write-Host "If All 3 ILOs reachable than please go ahead for Verifying VMNIC ports" -BackgroundColor Yellow -ForegroundColor Black
"`n"
#$IDFSwitch= Read-Host "Please enter the IDF Aruba Switch IP Address For ILO Port Info"
$ILOA="show int br | i 1000 | include Host_1_iLO"
$ILOB="show int br | i 1000 | include Host_2_iLO"
$ILOC="show int br | i 1000 | include Host_3_iLO"
$HostA = "show int br | i 10000 | e IDFA | include Store_Host_1" 
$HostB = "show int br | i 10000 | e IDFA | include Store_Host_2"
$HostC = "show int br | i 10000 | e IDFA | include Store_Host_3"
$HostExtra = "show int br | i 1000 | include 2/1/15"

#show interface brief | include 10000 | e 24

$secpasswd = ConvertTo-SecureString $Password -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential($User, $secpasswd)
$Sessionid_ILO = New-SSHSession -ComputerName $IDFSwitch -Credential $Credentials
Write-host " ILO A Port info" -BackgroundColor Yellow -ForegroundColor Black

$Result_ILO=Invoke-SSHCommand -Index $sessionid_ILO.sessionid -Command $ILOA  # Invoke Command Over SSH
$Result_ILO.output
"`n"
Write-host " ILO B Port info" -BackgroundColor Yellow -ForegroundColor Black

$Result_ILO1=Invoke-SSHCommand -Index $sessionid_ILO.sessionid -Command $ILOB # Invoke Command Over SSH
$Result_ILO1.output
"`n"
Write-host " ILO C Port info" -BackgroundColor Yellow -ForegroundColor Black

$Result_ILO2=Invoke-SSHCommand -Index $sessionid_ILO.sessionid -Command $ILOC # Invoke Command Over SSH
$Result_ILO2.output
"`n"
#$MDFSwitch = Read-Host "Please enter the MDF Aruba Switch IP Address for VMNIC Info"
"`n"
$secpasswd = ConvertTo-SecureString $Password -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential($User, $secpasswd)
$Sessionid = New-SSHSession -ComputerName $MDFSwitch -Credential $Credentials  #Connect Over SSH

Write-host " Host A Connected VMNICs" -BackgroundColor Yellow -ForegroundColor Black

$Result=Invoke-SSHCommand -Index $Sessionid.sessionid -Command $HostA # Invoke Command Over SSH
$Result.output
"`n"
Write-host " Host A Extrahop Port VMNIC" -BackgroundColor Yellow -ForegroundColor Black

$Result=Invoke-SSHCommand -Index $Sessionid.sessionid -Command $HostExtra # Invoke Command Over SSH
$Result.output
"`n"

Write-host " Host B Connected VMNICs" -BackgroundColor Yellow -ForegroundColor Black

$Result1=Invoke-SSHCommand -Index $Sessionid.sessionid -Command $HostB # Invoke Command Over SSH
$Result1.output
"`n"
Write-Host "Host C Connected VMNICs" -BackgroundColor Yellow -ForegroundColor Black
$Result2=Invoke-SSHCommand -Index $Sessionid.sessionid -Command $HostC
$Result2.output
"`n"
#Write-Host "If All 3 ILOs reachable and VMNICs are good Than please Release the Tech from Site" -BackgroundColor Red 
