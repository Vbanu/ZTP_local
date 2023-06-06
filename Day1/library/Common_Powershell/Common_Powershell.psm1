#this line of code is needed to grab a code that is passed into stdin from CS Console
$Script:getEncCode = ""
$PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck", $true)
function VerifyParameter {
	Param
	(    
		[Parameter(Mandatory = $false)]
		[switch]$h,
    
		[Parameter(Mandatory = $false)]
		[switch]$help,

		[Parameter(Mandatory = $false)]
		[string]$report = "",
    
		[Parameter(Mandatory = $false)]
		[string]$result = "",
    
		[Parameter(Mandatory = $false)]
		[string]$progress = "",
            
		[Parameter(Mandatory = $false)]
		[string]$fromversion = "",

		[Parameter(Mandatory = $false)]
		[string]$toversion = "",

		[Parameter(Mandatory = $false)]
		[string]$getenc = "",

		[Parameter(Mandatory = $false)]
		[string]$affectedobjects = "",

		[Parameter(Mandatory = $false)]
		[string]$serviceObjects = "",

		[Parameter(Mandatory = $false)]
		[string]$infraSD = "",

		[Parameter(Mandatory = $false)]
		[string]$baseConfigSD = "",

		[Parameter(Mandatory = $false)]
		[string]$sbparameter = "",
	
		[Parameter(Mandatory = $false)]
		[string]$sppFilePath = "",
	
		[Parameter(Mandatory = $false)]
		[string]$SmartCID = "",
	
		[Parameter(Mandatory = $false)]
		[string]$Validation = "",
	
		[Parameter(Mandatory = $false)]
		[string]$vCenterISOPath = "",
	
		[Parameter(Mandatory = $false)]
		[string]$CBVMOvaFilePath = "",

		[Parameter(Mandatory = $false)]
		[string]$psmVMOvaFilePath = "",	

		[Parameter(Mandatory = $false)]
		[string]$RemoteESXiIP = "",
	
		[Parameter(Mandatory = $false)]
		[string]$RemoteESXiUserName = "",
	
		[Parameter(Mandatory = $false)]
		[string]$RemoteESXiPassword = "",
	
		[Parameter(Mandatory = $false)]
		[string]$ESXi_iso_imagepath = "",
	
		[Parameter(Mandatory = $false)]
		[string]$CentOSISOPath = "",
	
		[Parameter(Mandatory = $false)]
		[string]$RedFishToolKitPath = "",
    
		[Parameter(Mandatory = $false)]
		[string]$ESXi_patch = "",
	
		[Parameter(Mandatory = $false)]
		[string]$iSUTPackagePath = "",
	
		[Parameter(Mandatory = $false)]
		[string]$TempDNSServerIP = "",
	
		[Parameter(Mandatory = $false)]
		[string]$oneviewOvaPath = "",
	
		[Parameter(Mandatory = $false)]
		[string]$vCenterPatchisopath = "",
	
		[Parameter(Mandatory = $false)]
		[string]$NCM_FilePath = "",
	
		[Parameter(Mandatory = $false)]
		[string]$PhysicalNic1 = "",
	
		[Parameter(Mandatory = $false)]
		[string]$PhysicalNic2 = "",

		[Parameter(Mandatory = $false)]
		[string]$WindowsOvaPath = "",

		[Parameter(Mandatory = $false)]
		[string]$switchPort1 = "",
	
		[Parameter(Mandatory = $false)]
		[string]$switchPort2 = "",

		[Parameter(Mandatory = $false)]
		[string]$firmwareFile = "",
	
		[Parameter(Mandatory = $false)]
		[string]$OVGDOvaPath = "",

		[Parameter(Mandatory = $false)]
		[string]$solutionName = "",
		
		[Parameter(Mandatory = $false)]
		[string]$PatchFileName = "",
		
		[Parameter(Mandatory = $false)]
		[string]$ImageFolderPath = "",
	
		[Parameter(Mandatory=$false)]
		[string]$WindowsISOPath = "",
		
		[Parameter(Mandatory=$false)]
		[string]$upgradeMode = "",
		
		[Parameter(Mandatory=$false)]
		[string]$SPPImagepath = "",
		
		[Parameter(Mandatory=$false)]
		[string]$BaselineNameList = "",
		
		[Parameter(Mandatory=$false)]
		[string]$customSPPName = "",

		[Parameter(Mandatory = $false)]
		[string]$SLESOSISOPath = "",
	
		[Parameter(Mandatory=$false)]
		[string]$SLESOSISOPackagesPath = "",
		
		[Parameter(Mandatory=$false)]
		[string]$sppVersion = "",

		[Parameter(Mandatory = $false)]
		[string]$osImagepath = "",

        [Parameter(Mandatory = $false)]
		[string]$UploadFilePath = ""

	)

	$worked = $True

	try {
		Set-Variable -Name h -Value ($h) -Scope Global
        
		Set-Variable -Name help -Value ($help) -Scope Global

		Set-Variable -Name report -Value ($report) -Scope Global

		Set-Variable -Name result -Value ($result) -Scope Global

		Set-Variable -Name progress -Value ($progress) -Scope Global

		Set-Variable -Name getenc -Value ($getenc) -Scope Global

		Set-Variable -Name fromversion -Value ($fromversion) -Scope Global

		Set-Variable -Name toversion -Value ($toversion) -Scope Global

		Set-Variable -Name affectedobjects -Value ($affectedobjects) -Scope Global

		Set-Variable -Name serviceObjects -Value ($serviceObjects) -Scope Global

		Set-Variable -Name infraSD -Value ($infraSD) -Scope Global

		Set-Variable -Name baseConfigSD -Value ($baseConfigSD) -Scope Global

		Set-Variable -Name sbparameter -Value ($sbparameter) -Scope Global
		
		Set-Variable -Name sppFilePath -Value ($sppFilePath) -Scope Global
		
		Set-Variable -Name SmartCID -Value ($SmartCID) -Scope Global
		
		Set-Variable -Name Validation -Value ($Validation) -Scope Global
		
		Set-Variable -Name getenc -Value ($getenc) -Scope Global
		
		Set-Variable -Name vCenterISOPath -Value ($vCenterISOPath) -Scope Global
		
		Set-Variable -Name CBVMOvaFilePath -Value ($CBVMOvaFilePath) -Scope Global

		Set-Variable -Name psmVMOvaFilePath -Value ($psmVMOvaFilePath) -Scope Global
		
		Set-Variable -Name RemoteESXiIP -Value ($RemoteESXiIP) -Scope Global
		
		Set-Variable -Name RemoteESXiUserName -Value ($RemoteESXiUserName) -Scope Global
		
		Set-Variable -Name RemoteESXiPassword -Value ($RemoteESXiPassword) -Scope Global
		
		Set-Variable -Name ESXi_iso_imagepath -Value ($ESXi_iso_imagepath) -Scope Global
		
		Set-Variable -Name CentOSISOPath -Value ($CentOSISOPath) -Scope Global
        
		Set-Variable -Name RedFishToolKitPath -Value ($RedFishToolKitPath) -Scope Global
        
		Set-Variable -Name ESXi_patch -Value ($ESXi_patch) -Scope Global
		
		Set-Variable -Name iSUTPackagePath -Value ($iSUTPackagePath) -Scope Global
		
		Set-Variable -Name TempDNSServerIP -Value ($TempDNSServerIP) -Scope Global
		
		Set-Variable -Name oneviewOvaPath -Value ($oneviewOvaPath) -Scope Global
		
		Set-Variable -Name vCenterPatchisopath -Value ($vCenterPatchISOPath) -Scope Global
		
		Set-Variable -Name NCM_FilePath -Value ($NCM_FilePath) -Scope Global
		
		Set-Variable -Name PhysicalNic1 -Value ($PhysicalNic1) -Scope Global
		
		Set-Variable -Name PhysicalNic2 -Value ($PhysicalNic2) -Scope Global

		Set-Variable -Name WindowsOvaPath -Value ($WindowsOvaPath) -Scope Global
		
		Set-Variable -Name switchPort1 -Value ($switchPort1) -Scope Global
		
		Set-Variable -Name switchPort2 -Value ($switchPort2) -Scope Global

		Set-Variable -Name firmwareFile -Value ($firmwareFile) -Scope Global
		
		Set-Variable -Name OVGDOvaPath -Value ($OVGDOvaPath) -Scope Global

		Set-Variable -Name solutionName -Value ($solutionName) -Scope Global
		
		Set-Variable -Name PatchFileName -Value ($PatchFileName) -Scope Global
		
		Set-Variable -Name ImageFolderPath -Value ($ImageFolderPath) -Scope Global

		Set-Variable -Name WindowsISOPath -Value ($WindowsISOPath) -Scope Global	
		
		Set-Variable -Name upgradeMode -Value ($upgradeMode) -Scope Global
		
		Set-Variable -Name SPPImagepath -Value ($SPPImagepath) -Scope Global

		Set-Variable -Name BaselineNameList -Value ($BaselineNameList) -Scope Global
		
		Set-Variable -Name customSPPName -Value ($customSPPName) -Scope Global

		Set-Variable -Name SLESOSISOPath -Value ($SLESOSISOPath) -Scope Global	

		Set-Variable -Name SLESOSISOPackagesPath -Value ($SLESOSISOPackagesPath) -Scope Global
		
		Set-Variable -Name sppVersion -Value ($sppVersion) -Scope Global
		
		Set-Variable -Name osImagepath -Value ($osImagepath) -Scope Global
		
		Set-Variable -Name UploadFilePath -Value ($UploadFilePath) -Scope Global
			
	}
	catch {
		$worked = $False
		$result = $_.Exception.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($result)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$reader.ReadToEnd()
	}


	return $worked

}

#Prints the report containing a table and the header row
function Report-Intro {
	Param
	(
		#[System.IO.StreamWriter] 
		$reportwriter,
		$category,
		$Validation_Name
	)	

	$status = 'Status'
	$description = 'Description'
	Write-Host $line
	$line = [string]::Format("{0}`t{1}`t{2}", $category, $status, $description)
	if ($reportwriter) {
		$reportwriter.WriteLine($Validation_Name)
		$reportwriter.WriteLine($line)
	}
}

#Prints the report row by row passed in
function Report-Row {
	Param
	(
		#[System.IO.StreamWriter] $reportwriter,
		$reportwriter,
		$category,
		$status,
		$description,
		$Validation_Name
	)

	$line = [string]::Format("{0}`t{1}`t{2}", $category, $status, $description)
	Write-Host $line
	if ($reportwriter) {
		$reportwriter.WriteLine($line)
	}
}

#Importing the Required module.
Function Load-CommonModule($ModuleName, $Reload = $True, $RootPath) {

	try {
		#==============================================================================
		### (***LOCKED***) Path-aware loading of modules
		# Requires modules to reside in folder with same name as module

		# User [IO.Path]::PathSeparator for portability between Windows and Linux
		#if (($env:PSModulePath -split '\s*;\s*') -NotContains $RootPath) {
		if (($env:PSModulePath -split [IO.Path]::PathSeparator) -NotContains $RootPath) {
			write-verbose "Setting PSModulePath"
			#$env:PSModulePath = $RootPath + ";" + $env:PSModulePath

			$env:PSModulePath = $RootPath + [IO.Path]::PathSeparator + $env:PSModulePath
		}

		# Check to see if the module is already loaded
		if (Get-Module $ModuleName) {
			# If a Reload was requested, unload the module
			if ($Reload) {
				Remove-Module $ModuleName -Force:$True
			}
			else {
				# Already loaded, so just return
				return
			}
		}
		# (Re-)Load the module
		Import-Module $ModuleName -DisableNameChecking
	}
 catch {
		throw $_
	}
}

function Disable-SslVerification {
	if (-not ([System.Management.Automation.PSTypeName]"TrustEverything").Type) {
		Add-Type -TypeDefinition  @"
		using System.Net.Security;
		using System.Security.Cryptography.X509Certificates;
		public static class TrustEverything
		{
			private static bool ValidationCallback(object sender, X509Certificate certificate, X509Chain chain,
				SslPolicyErrors sslPolicyErrors) { return true; }
			public static void SetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = ValidationCallback; }
			public static void UnsetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = null; }
		}
"@
	}
	[TrustEverything]::SetCallback()
}

#This func re-enables SSL verfication
function Enable-SslVerification {
	if (([System.Management.Automation.PSTypeName]"TrustEverything").Type) {
		[TrustEverything]::UnsetCallback()
	}
}

# Gets the SAT session token using getEnc
function Get-SATToken {
	Param(
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $ENCURL
	)

	# ENCCode passed to stdin of the script by SAT
	$ENCCODE = [Console]::In.ReadLine()
	if ($ENCCODE.length -eq 0) {
		$counter = 0
		while (!$Host.UI.RawUI.KeyAvailable -and ($counter++ -lt 300)) {
			Start-Sleep -m 100
		}
		if ($Host.UI.RawUI.KeyAvailable) {
			$ENCCODE = Read-Host
		}
	}
	if ($GETENCURL.length -lt 0 -or $ENCCODE.Length -lt 0 ) {
		throw "Unable to get ENCURL/ENCCODE from SAT"
	}
	# get only the code
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	$ENCCODE = $ENCCODE.split(':')[1]
	$dataPart = @{EncCode = $ENCCODE } | ConvertTo-Json
	$uri = "$ENCURL/login"
	Disable-SslVerification
	$headers = @{'Content-Type' = 'application/json' }
	try {
		$output = Invoke-RestMethod -Method Post -Body $dataPart -uri $uri -Headers $headers -ContentType "application/json" -SessionVariable websession
		$token = $($output.sessionId)
	} 
	catch {
		Write-Error $_
		throw "Unable to get Session ID from SAT"
	}

	return $token
}

function Get-HostInfo {
	Param(
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $SolutionId,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $SessionId,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $ENCURL
	)

	try {
		$uri = ($ENCURL -split "/getenc")[0] + "/solutions/$SolutionId/getAllHostInfo"
		$header = @{"Authorization" = $SessionId }
		$JSON_Output = Invoke-RestMethod -Method Get -uri $uri -Headers $header
		$HostDetails = $($JSON_Output.Hosts)
	}
	catch {
		Write-Error $_
		throw "Unable to get Host Info from SAT"
	}

	return $HostDetails
}

function Get-SolutionId {
	Param(
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $SolutionName,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $SessionId,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $ENCURL
	)

	try {
		$uri = ($ENCURL -split "/getenc")[0] + "/getSolutionDetails/$SolutionName"
		$header = @{"Authorization" = $SessionId }
		$JSON_Output = Invoke-RestMethod -Method Get -uri $uri -Headers $header
		return $JSON_Output
	}
	catch {
		Write-Error $_
		throw "Unable to get Solution Info from SAT"
	}
}

function Get-HostCredential {
	Param(
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $SessionId,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $ENCURL,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $IPAddress,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $Protocol,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $SolutionName
	)

	$uri = "$ENCURL/$SolutionName/$IPAddress/$Protocol"
	try {
		$header = @{"Authorization" = $SessionId }
		$JSON_Output = Invoke-RestMethod -Method Get -uri $uri -Headers $header
		return $JSON_Output
	}
	catch {
		Write-Error $_
		throw "Unable to get Credential for [$IPAddress]"
	}
}

function Get-HostConfig {
	param
	(
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string] $PORT
	)
	try {               	
		#Begin processing getenc that was read in from CS Console via stdin
		$getEncUrl = $getenc
		$getEncCode = [Console]::In.ReadLine()
		
		$Host_Info = @{ }
		write-host "Getenc code : $GETENCURL"
		
		if ($GETENCURL.length -gt 0 ) {		
			if ($GETENCCODE.length -eq 0) {
				$counter = 0
				while (!$Host.UI.RawUI.KeyAvailable -and ($counter++ -lt 300)) {
					Start-Sleep -m 100
				}
				if ($Host.UI.RawUI.KeyAvailable) {
					$GETENCCODE = Read-Host
				}
			}
			if ($GETENCCODE.length -gt 0) {
				Write-Host "encCode read successfully from stdin: $GETENCCODE"
				$colPos = $GETENCCODE.indexOf(":")
				if ($colPos -ge 0) {
					$GETENCCODE = $GETENCCODE.subString($colPos + 1)
				}
				$dataPart = @{EncCode = $GETENCCODE } | ConvertTo-Json
				$uri = "$GETENCURL/login"

				[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
				Disable-SslVerification
				$headers = @{'Content-Type' = 'application/json' }
				try {
					$output = Invoke-RestMethod -Method Post -Body $dataPart -uri $uri -Headers $headers -ContentType "application/json" -SessionVariable websession
					$Session_ID = $($output.sessionId)
				} 
				catch {
					$result = $_.Exception.Response.GetResponseStream()
					$reader = New-Object System.IO.StreamReader($result)
					$reader.BaseStream.Position = 0
					$reader.DiscardBufferedData()
					$reader.ReadToEnd()
					Write-Host $reader
				}
			} 
			else {
				$currDate = Get-Date
				Write-Host "Could not read encCode from stdin.  read returned: $exitCode at $currDate"
				if ( $report.length -gt 0 ) {
					$reportwriter.WriteLine("Could not read encCode from stdin.  read returned: $exitCode at $currDate")
				}
			}
		}		
		if ($Session_ID.length -eq 0) {
			Write-Host "Could not find SessionID in login output"
		}
		else {
			try {
				try {
					$Fetch_vCenterIP_uri = ($getEncUrl -split ("/getenc"))[0] + "/getAllHostInfo"
					$header = @{"Authorization" = $Session_ID }
					$JSON_Output = Invoke-RestMethod -Method Get -uri $Fetch_vCenterIP_uri -Headers $header
					$Host_Details = $($JSON_Output.Hosts)
					
					if ($Host_Details) {
						$HostName = $Host_Details.hostName
						$HostIP = $Host_Details.ipAddress
						$Host_Info.add("Hostname", $HostName)
						$Host_Info.add("HostIP", $HostIP)
					}
				}
				catch {
					Write-host "Failed to fetch Host IP: Exiting..."
					throw $_
					exit
				}

				$wantPort = $PORT
				$wantIP = $HostIP

				$Fetch_Host_URI = "$getEncUrl/$wantIP/$wantPort"
				Write-Host "uri is: $Fetch_Host_URI"
				
				$JSONResponse = Invoke-RestMethod -Method Get -uri $Fetch_Host_URI -Headers $header
				$UserName = $JSONResponse.userID
				$Password = $JSONResponse.password
				$Host_Info.add("HostUsername", $UserName)
				$Host_Info.add("HostPassword", $Password)
			}
			catch {
				Write-Host "JSON output: $_"
				$result = $_.Exception.Response.GetResponseStream()
				Write-host "JSON exception Result: $result"
				$reader = New-Object System.IO.StreamReader($result)
				$reader.BaseStream.Position = 0
				$reader.DiscardBufferedData()
				$reader.ReadToEnd()
			}
		}
	}
	catch {
		if (!$wantIP) {
			$wantIP = "Undetermined"
		}
		Write-Host "The Output from invoke-method: $_"
		$_ | Format-List * -Force
		$Script:status = $false
	}
	return $Host_Info
}
function Report-Intro-New {
	Param(
		$reportwriter, #not used
		$category, # Column 1 Name
		$Validation_Name # Table Name
	)

	Write-host ("############################################")
	Write-Host $Validation_Name
	Write-host ("############################################")
	
	$map = @{
		"name" = $Validation_Name
	}

	# Column 1
	$col1 = @{"key" = "col1"; "columnName" = $category }
	# Column 2
	$col2 = @{"key" = "col2"; "columnName" = "Status"; "renderFormat" = "status" }
	# Column 3
	$col3 = @{"key" = "col3"; "columnName" = "Description" }

	$headers = @($col1, $col2, $col3)

	$map.add("headers", $headers)
	$map.add("status", "pass")

	return $map
}

function Report-Row-New {
	Param(
		$reportwriter,
		$category, # column 1
		$status, # column 2
		$description, # column 3
		$Validation_Name
	)

	$contentObject = @{"col1" = $category; "col2" = $status; "col3" = $description }

	return $contentObject
}
Function Mount-ISO {
	param
	(
		[parameter(Mandatory = $true)]
		[String] $isoPath
	)
    
	try {
		$mount = Mount-DiskImage -ImagePath $isoPath -PassThru
		if ($mount) {
			$volume = Get-DiskImage -ImagePath $mount.ImagePath | Get-Volume
			$Mounted_path = $volume.DriveLetter + ":"
			Write-Host "Mounted '$isoPath' to '$Mounted_path'..."
		}
		else {
			Write-Host "ERROR: Could not mount " $isoPath " check if file is already in use"
			$Mounted_path = ""
		}
	}
	catch {
		write-host $_
	}
	return $Mounted_path
}
Function Dismount-ISO {
	param
	(
		[parameter(Mandatory = $true)]
		[Object] $isoPath
	)

	$isSuccess = "Pass"
	try {	 
		$hide = Dismount-DiskImage -ImagePath $isoPath
	}
	catch {
		write-host $_
		Write-Host "ERROR: Could not dismount " $isoPath " check if file is already in use"
		$isSuccess = "Fail"
	}
	return $isSuccess
}

function Convert-IpAddressToMaskLength([string] $dottedIpAddressString) {
	$maskLength = 0; 
	# ensure we have a valid IP address
	[IPAddress] $ip = $dottedIpAddressString;
	$octets = $ip.IPAddressToString.Split('.');
	foreach ($octet in $octets) {
		while (0 -ne $octet) {
			$octet = ($octet -shl 1) -band [byte]::MaxValue
			$maskLength++; 
		}
	}
	return $maskLength;
}

function Get-NodeInfo {
	Param(
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $SolutionId,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $SessionId,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $ENCURL
	)

	try {
		$uri = ($ENCURL -split "/getenc")[0] + "/solutions/$SolutionId/getComAllEntities"
		$header = @{"Authorization" = $SessionId }
		$JSON_Output = Invoke-RestMethod -Method Get -uri $uri -Headers $header
		$NodeDetails = $($JSON_Output.Nodes)
	}
	catch {
		Write-Error $_
		throw "Unable to get Node Info from SAT"
	}

	return $NodeDetails
}

function Get-AllEntities {
	Param(
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $SolutionId,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $SessionId,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $ENCURL
	)

	try {
		$uri = ($ENCURL -split "/getenc")[0] + "/solutions/$SolutionId/getComAllEntities"
		$header = @{"Authorization" = $SessionId }
		$JSON_Output = Invoke-RestMethod -Method Get -uri $uri -Headers $header
		$NodesDetails = ($JSON_Output.Nodes)
	}
	catch {
		Write-Error $_
		throw "Unable to get nodes Info from SAT"
	}

	return $NodesDetails
}

Function New-SequenceReport
{
	Param(
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String] $SCID_ID,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[Object] $SCID_JSON
	)

	$NoOfNimble = ($SCID_JSON.storageArrays | Measure-Object -Property hostname).Count
	$OV_IP = ($SCID_JSON.virtualMachineDetails | Where-Object {$_.componentName -eq "OneView"}).mgmntNetworkIp
	$vC_IP = ($SCID_JSON.virtualMachineDetails | Where-Object {$_.componentName -eq "vcsa"}).mgmntNetworkIp
    $result = "---------------------------------------------------`n"`
		+ "SCID ID - [$SCID_ID]`n"`
		+ "Number of Management DL360 - [$($SCID_JSON.dldeviceDetails.Count)]`n"`
		+ "Number of Nimble Arrays - [$NoOfNimble]`n"`
		+ "OneView IP Address - [$OV_IP]`n"`
		+ "vCenter IP Address - [$vC_IP]`n"`
		+ "---------------------------------------------------`n"`

	return $result
}

#--------------------------------------------------------------------
# EXPORTED METHODS
#--------------------------------------------------------------------
Export-ModuleMember -Function VerifyParameter
Export-ModuleMember -Function Report-Intro
Export-ModuleMember -Function Report-Row
Export-ModuleMember -Function Report-Intro-New
Export-ModuleMember -Function Report-Row-New
Export-ModuleMember -Function Load-CommonModule
Export-ModuleMember -Function Disable-SslVerification
Export-ModuleMember -Function Enable-SslVerification
Export-ModuleMember -Function Get-HostConfig
Export-ModuleMember -Function Mount-ISO
Export-ModuleMember -Function Dismount-ISO
Export-ModuleMember -Function Convert-IpAddressToMaskLength
Export-ModuleMember -Function Get-SATToken
Export-ModuleMember -Function Get-HostInfo
Export-ModuleMember -Function Get-HostCredential
Export-ModuleMember -Function Get-SolutionId
Export-ModuleMember -Function Get-NodeInfo
Export-ModuleMember -Function Get-AllEntities
Export-ModuleMember -Function New-SequenceReport
#--------------------------------------------------------------------
# END EXPORTED METHODS
#--------------------------------------------------------------------
