#Define constants
Set-Variable -Name 'PASS' -Value 'Pass' -Force
Set-Variable -Name 'FAIL' -Value 'Fail' -Force
Set-Variable -Name 'SUCCESS' -Value 'Create Succeeded' -Force
Set-Variable -Name 'FAILED' -Value 'Create Failed' -Force

Function Configure-WebServer {
    param
    (
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $DB_WEBSERVER_LOCATION,
		
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $WEBSERVER_IP,
		
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $WEBSERVER_PORT,
		
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $START_WS = $False,
		
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ISO_Container
    )
	
    $currPath = (Get-Location -PSProvider FileSystem).Path
    if (-not $IsLinux) {
        $nginxPath = $DB_WEBSERVER_LOCATION
        $env:Path = $env:Path + [IO.Path]::PathSeparator + $nginxPath
    }

    try {
        $WS_ConfigLocation = Join-Path (Join-Path $DB_WEBSERVER_LOCATION "conf") "nginx.conf"

        # Create command variable to check nginx task status for Linux and Windows
        # Create variables to check port status and configure firewall on Linux
        if ($IsLinux) {
            $checkTask = "ps -C nginx"
            $hostNameCtl = Invoke-Expression -Command "hostnamectl"
            if ($hostNameCtl -match "SUSE") {
                $firewallListPorts = "firewall-cmd --list-ports"
                $firewallAddPort = "firewall-cmd --add-port=$WEBSERVER_PORT/tcp"
                $firewallRemovePort = "firewall-cmd --remove-port=$WEBSERVER_PORT/tcp"
            }
            elseif ($hostNameCtl -match "Ubuntu") {
                $firewallListPorts = "ufw status"
                $firewallAddPort = "ufw allow $WEBSERVER_PORT/tcp"
                $firewallRemovePort = "ufw delete allow $WEBSERVER_PORT/tcp"
            }
            else {
                Write-Host "Unsupported Linux distribution."
                Write-Host $hostNameCtl
                return $false
            }
        }
        else {
            $checkTask = 'tasklist /fi "imagename eq nginx.exe"'
        }

        if ($START_WS -eq $False) {
            write-host "Configuring web server"

            if (Test-Path (Join-Path (Join-Path $DB_WEBSERVER_LOCATION "html") $ISO_Container)) {
                $WebISoFolder = Get-Item -Path (Join-Path $env:AppData $Custom_ISO_images)
            }
            else {
                $WebISoFolder = New-Item -ItemType directory -Path (Join-Path (Join-Path $DB_WEBSERVER_LOCATION "html") $ISO_Container)
            }
            
            #Modify the WebServer Config file
            if ($WebISoFolder) {
                (Get-Content -Path $WS_ConfigLocation -raw) -replace "@IP_ADDRESS@" , $WEBSERVER_IP | Set-Content -Path $WS_ConfigLocation
                (Get-Content -Path $WS_ConfigLocation -raw) -replace "@PORT_NO@" , $WEBSERVER_PORT | Set-Content -Path $WS_ConfigLocation
                (Get-Content -Path $WS_ConfigLocation -raw) -replace "@CUSTOM_FOLDER@" , $ISO_Container | Set-Content -Path $WS_ConfigLocation
                return $true
            }
        }
        elseif ( $START_WS -eq "start") {
            write-host "Fetching web server status..."
            #Check if the Web server is already running

            $hasWSStarted = Invoke-Expression -Command $checkTask
            if (($hasWSStarted | foreach { $_ -match "nginx" } | where { $_ -eq "true" }).count -gt 1) {
                write-host "Web server already running"
                return (Join-Path (Join-Path $DB_WEBSERVER_LOCATION "html") $ISO_Container)
            }	
            else {
                write-host "Web server not running. Starting the Web Server"
                Set-Location -Path $DB_WEBSERVER_LOCATION
                Write-Host "Starting nginx with arugment list -p `"$DB_WEBSERVER_LOCATION`" -c `"$WS_ConfigLocation`""
                #Invoke-Expression -Command "nginx -p `"$DB_WEBSERVER_LOCATION`" -c `"$WS_ConfigLocation`"" -ErrorAction stop
                Start-Process -FilePath "nginx" -ArgumentList "-p `"$DB_WEBSERVER_LOCATION`" -c `"$WS_ConfigLocation`"" -ErrorAction Stop
                Set-Location -Path $currPath
                #Verify that the webserver started successfully
                #start-sleep -s 150
                Start-Sleep -s 30
                $hasWSStarted = Invoke-Expression -Command $checkTask
                if (($hasWSStarted | ForEach-Object { $_ -match "nginx" } | Where-Object { $_ -eq "true" }).count -gt 1) {
                    write-host "Successfully started the web server"
                    
                    # Configure the firewall to allow iLO to connect to the web server
                    if ($IsLinux) {
                        #$firewallPorts = Invoke-Expression -Command "firewall-cmd --list-ports"
                        $firewallPorts = Invoke-Expression -Command "$firewallListPorts"
                        if ($firewallPorts -match "$WEBSERVER_PORT/tcp") { 
                            write-host "Firewall port already added for the nginx web server."
                        }
                        else { 
                            # Add nginx web server port to firewall
                            write-host "Adding port to firewall for nginx web server."
                            #Invoke-Expression "firewall-cmd --add-port=$WEBSERVER_PORT/tcp" | Out-Null
                            Invoke-Expression "$firewallAddPort" | Out-Null
                        }                     
                    }
                    else {
                        $firewallSetting = Get-NetFirewallRule -DisplayName "nginx" -ErrorAction SilentlyContinue
                        if ($firewallSetting) {
                            write-host "Firewall rule already added for the nginx web server."
                        }
                        else {
                            # Add the firewall rule to allow iLO to connect to the web server
                            write-host "Adding the new firewall rule for nginx web server."
                            $Program = $WebServerPath + "\nginx.exe"
                            New-NetFirewallRule -DisplayName "nginx" -Direction Inbound -Action Allow -EdgeTraversalPolicy Allow -Protocol TCP -LocalPort $WEBSERVER_PORT -Program $Program -ErrorAction Stop | Out-Null
                        }
                    }
                    write-host "Returning ISO container path: (Join-Path (Join-Path $DB_WEBSERVER_LOCATION "html") $ISO_Container)"
                    return (Join-Path (Join-Path $DB_WEBSERVER_LOCATION "html") $ISO_Container)
                }
                if ($hasWSStarted -match "No tasks are running") {
                    write-host "Failed to start the web server"
                    write-host $hasWSStarted
                    return $false
                }
            }
        }
        elseif ($START_WS -eq "stop") {      
            # Check if web server is running and if so gracefully shutdown

            $hasWSStarted = Invoke-Expression -Command $checkTask
            if (($hasWSStarted | ForEach-Object { $_ -match "nginx" } | Where-Object { $_ -eq "true" }).count -gt 1) {
                Set-Location -Path $DB_WEBSERVER_LOCATION
                write-host "Terminating the Nginx web server"
                Invoke-Expression -Command "nginx -s quit"
                Set-Location -Path $currPath

                # Remove firewall configuration to allow iLO to connect to the web server
                if ($IsLinux) {
                    $firewallPorts = Invoke-Expression -Command "$firewallListPorts"
                    if ($firewallPorts -match "$WEBSERVER_PORT/tcp") {
                        # Remove nginx web server port from firewall
                        write-host "Removing port from firewall for nginx web server."
                        #Invoke-Expression "firewall-cmd --remove-port=$WEBSERVER_PORT/tcp"
                        Invoke-Expression "$firewallRemovePort"
                    }
                    else { 
                        write-host "No Firewall port to remove for the nginx web server." 
                    }                     
                }
                else {
                    $firewallSetting = Get-NetFirewallRule -DisplayName "nginx" -ErrorAction SilentlyContinue
                    if ($firewallSetting) {
                        # Remove nginx Firewall Rule
                        write-host "Removing Firewall rule for the nginx web server."
                        Remove-NetFirewallRule -DisplayName "nginx" -ErrorAction SilentlyContinue
                    }
                    else {
                        write-host "No Firewall rule to remove for the nginx web server."
                    }
                
                }
                return (Join-Path (Join-Path $DB_WEBSERVER_LOCATION "html") $ISO_Container)
            }
            else {
                write-host "No web server found running"
                return $false
            }
        }
        else {
            write-host "Invalid request :$START_WS"
            return $false
        }
    }
    catch {
        write-host $_
        return $false
    }
    return $false
}

#--------------------------------------------------------------------
# EXPORTED METHODS
#--------------------------------------------------------------------
Export-ModuleMember -Function Configure-WebServer
