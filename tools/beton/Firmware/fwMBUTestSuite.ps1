#NOTE: Test is valid for setup when 5G Nikki is used as Link Partner
#NOTE: All variables below must be updated for your environment

###MBU######################
$mbu_dir="C:\QA\MBU"                                  #path to MBU.
$test_dir="C:\Users\aquantia\Desktop\Done-Last\Tests" #path to Tests folder
###REMOTE####################
$remoteComputer = "qalab2"                            #Link Partners's hostname 
$remoteUser = "aquantia"                              #Link Partner's credential
$remotePassword = 'aqu$3r'
$serviceName = "AquantiaNDMP"                         #NIC Service Name
$time = 20                                            #Time to wait for link up
############################


##FUNCTIONS####################
function RunMBUTest
{
    param (
     [Parameter (Mandatory = $true)]
        [string] $MBU,
     [Parameter (Mandatory = $true)]
        [string] $script
    )
    python $MBU\main.py -p pci0 -i -f $script
}

function GetNICRemote
#wmic /node:$remoteComputer /user:$remoteUser /password:$remotePassword path win32_networkadapter where ServiceName=""
{
    param (
     [Parameter (Mandatory = $true)]
        [string] $computerName,
     [Parameter (Mandatory = $true)]
        [string] $user,
     [Parameter (Mandatory = $true)]
        [string] $password,
     [Parameter (Mandatory = $true)]
        [string] $serviceName
    )

    $secPassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($user, $secPassword)

    ($nic = Get-WmiObject -ComputerName $computerName -Credential $credential -Class win32_networkadapter -Filter "ServiceName='$serviceName'") > $null
    return $nic
}

function RestartNIC
{
    param (
     [Parameter (Mandatory = $true)]
        [System.Management.ManagementBaseObject] $nic
    )
    Invoke-WmiMethod -InputObject $nic -Name Disable > $null
    Invoke-WmiMethod -InputObject $nic -Name Enable > $null
    Start-Sleep -Seconds $time
}

function SetLinkSpeed
#wmic /node:$remoteComputer /user:$remoteUser /password:$remotePassword process call create "cmd /c reg add HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0009 /v LinkSpeed /f /t reg_sz /d 65535"
{
    param (
     [Parameter (Mandatory = $true)]
        [string] $computerName,
     [Parameter (Mandatory = $true)]
        [string] $user,
     [Parameter (Mandatory = $true)]
        [string] $password,
     [Parameter (Mandatory = $true)]
        [System.Management.ManagementBaseObject] $nic,
     [Parameter (Mandatory = $true)]
        [string] $speed
    )
    $index = $nic.Index.ToString()
    $value = ""
    switch ($speed.Trim().ToLower())
    {
        "auto"  {$value = "65535"}
        "10g"  {$value = "1"}
        "5g"   {$value = "2"}
        "2.5g" {$value = "8"}
        "1g"   {$value = "16"}
        "100m" {$value = "32"}
        Default {$value = "65535"}
    }
    if ($index.Length -eq 1) {$index = "000" + $index}
    if ($index.Length -eq 2) {$index = "00" + $index}
    if ($index.Length -eq 3) {$index = "0" + $index}

    #"cmd /c reg add HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0009 /v LinkSpeed /f /t reg_sz /d 65535"
    $command = "cmd /c reg add HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\" + $index + " /v LinkSpeed /f /t reg_sz /d " +  $value
  
    wmic /node:$computerName /user:$user /password:$password process call create "$command" *>$null
    RestartNIC $nic
    
}

function SetLinkSpeed
#wmic /node:$remoteComputer /user:$remoteUser /password:$remotePassword process call create "cmd /c reg add HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0009 /v LinkSpeed /f /t reg_sz /d 65535"
{
    param (
     [Parameter (Mandatory = $true)]
        [string] $computerName,
     [Parameter (Mandatory = $true)]
        [string] $user,
     [Parameter (Mandatory = $true)]
        [string] $password,
     [Parameter (Mandatory = $true)]
        [string] $serviceName,
     [Parameter (Mandatory = $true)]
        [string] $speed
    )

    $nic = GetNICRemote $computerName $user $password $serviceName
    $index = $nic.Index.ToString()
    $value = ""
    switch ($speed.Trim().ToLower())
    {
        "auto"  {$value = "65535"}
        "10g"  {$value = "1"}
        "5g"   {$value = "2"}
        "2.5g" {$value = "8"}
        "1g"   {$value = "16"}
        "100m" {$value = "32"}
        Default {$value = "65535"}
    }
    if ($index.Length -eq 1) {$index = "000" + $index}
    if ($index.Length -eq 2) {$index = "00" + $index}
    if ($index.Length -eq 3) {$index = "0" + $index}

    #"cmd /c reg add HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0009 /v LinkSpeed /f /t reg_sz /d 65535"
    $command = "cmd /c reg add HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\" + $index + " /v LinkSpeed /f /t reg_sz /d " +  $value
  
    wmic /node:$computerName /user:$user /password:$password process call create "$command" *>$null
    RestartNIC $nic
    
}

function CheckLinkSpeed
{
    param (
     [Parameter (Mandatory = $true)]
        [System.Management.ManagementBaseObject] $nic,
     [Parameter (Mandatory = $true)]
        [string] $speed
    )

    $act = $nic.Speed
    if ($speed -eq $act) 
    {
        echo "PASS: Link Speed is OK"
        return $true
    }
    else 
    {
        echo "FAIL: Link Speed is BAD. Expected: $speed. Actual: $act"
        return $false
    }
}

function CheckLinkSpeed
{
    param (
     [Parameter (Mandatory = $true)]
        [string] $computerName,
     [Parameter (Mandatory = $true)]
        [string] $user,
     [Parameter (Mandatory = $true)]
        [string] $password,
     [Parameter (Mandatory = $true)]
        [string] $serviceName,
     [Parameter (Mandatory = $true)]
        [string] $speed
    )
    $nic = GetNICRemote $computerName $user $password $serviceName
    $act = $nic.Speed
    if ($speed -eq $act) 
    {
        echo "PASS: Link Speed is OK"
        #return $true
    }
    else 
    {
        echo "FAIL: Link Speed is BAD. Expected: $speed. Actual: $act"
        #return $false
    }
}

function PrintHead
{
    
    param (
     [Parameter (Mandatory = $true)]
        [string] $head
    )
    echo "******************************"
    echo $head.ToUpper()
    echo "******************************"
}

############################

###TESTS###################
PrintHead "START"

PrintHead "PRECONDITION"
echo "Setting Link Speed = Autonegatiation on Link Partner"
SetLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "auto"

#Check Version
PrintHead "RUNNING TEST: Check Version"
RunMBUTest $mbu_dir $test_dir\fwCheckVersion.txt

#FW Statistics
PrintHead "RUNNING TEST: FW Statistics"
RunMBUTest $mbu_dir $test_dir\fwStatistics.txt

#Rates
PrintHead "RUNNING TEST: Rates"
echo "DUT->LP(Auto)"
echo "Setting Link Speed = Autonegatiation on Link Partner"
SetLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "auto"
RunMBUTest $mbu_dir $test_dir\fwDUT_2_5g.txt
Start-Sleep -Seconds $time
CheckLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "2500000000"

RunMBUTest $mbu_dir $test_dir\fwDUT_Auto.txt
Start-Sleep -Seconds $time
CheckLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "5000000000"

RunMBUTest $mbu_dir $test_dir\fwDUT_1g.txt
Start-Sleep -Seconds $time
CheckLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "1000000000"

RunMBUTest $mbu_dir $test_dir\fwDUT_5g.txt
Start-Sleep -Seconds $time
CheckLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "5000000000"

RunMBUTest $mbu_dir $test_dir\fwDUT_100m.txt
Start-Sleep -Seconds $time
CheckLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "100000000"


echo "DUT(Auto)<-LP"
echo "Setting Link Speed = Autonegatiation on DUT"
RunMBUTest $mbu_dir $test_dir\fwDUT_Auto.txt

SetLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "2.5G"
CheckLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "2500000000"
RunMBUTest $mbu_dir $test_dir\fwDUT_Auto_2_5g.txt

SetLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "auto"
CheckLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "5000000000"
RunMBUTest $mbu_dir $test_dir\fwDUT_Auto_5g.txt

SetLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "100M"
CheckLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "100000000"
RunMBUTest $mbu_dir $test_dir\fwDUT_Auto_100m.txt

SetLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "5G"
CheckLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "5000000000"
RunMBUTest $mbu_dir $test_dir\fwDUT_Auto_5g.txt

SetLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "1G"
CheckLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "1000000000"
RunMBUTest $mbu_dir $test_dir\fwDUT_Auto_1g.txt


#Sleep Mode
PrintHead "RUNNING TEST: Sleep Mode"
echo "Setting Link Speed = Autonegatiation on Link Partner"
RunMBUTest $mbu_dir $test_dir\fwDUT_Auto.txt
SetLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "auto"

RunMBUTest $mbu_dir $test_dir\fwSleepMode.txt
CheckLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "100000000"

#eFUSE Shadowing
PrintHead "RUNNING TEST: eFUSE Shadowing"
RunMBUTest $mbu_dir $test_dir\fwEFUSEShadowing.txt

PrintHead "POSTCONDITION"
echo "Setting Link Speed = Autonegatiation on Link Partner"
RunMBUTest $mbu_dir $test_dir\fwDUT_Auto.txt
SetLinkSpeed $remoteComputer $remoteUser $remotePassword $serviceName "auto"

PrintHead "FINISH"