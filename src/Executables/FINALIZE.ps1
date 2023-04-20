# Enable MSI mode on USB, GPU, Storage controllers and network adapters
# Deleting DevicePriority sets the priority to Undefined
$deviceClasses = @(
    "CIM_USBController",
    "CIM_VideoController",
    "CIM_NetworkAdapter",
    "Win32_PnPEntity"
)

foreach ($deviceClass in $deviceClasses) {
    if ($deviceClass -eq "Win32_PnPEntity") {
        $devices = Get-WmiObject -Class Win32_PnPEntity | Where-Object {$_.PNPClass -eq "SCSIAdapter"} | Where-Object { $_.PNPDeviceID -like "PCI\VEN_*" } | Select-Object -ExpandProperty DeviceID
    } else {
        $devices = Get-CimInstance -ClassName $deviceClass | Where-Object { $_.PNPDeviceID -like "PCI\VEN_*" } | Select-Object -ExpandProperty PNPDeviceID
    }

    foreach ($device in $devices) {
        $interruptManagement = "HKLM:\SYSTEM\CurrentControlSet\Enum\$device\Device Parameters\Interrupt Management"

        # Create MessageSignaledInterruptProperties subkey in case it does not exist
        New-Item -Path $interruptManagement -Name "MessageSignaledInterruptProperties" -Force

        Set-ItemProperty -Path "$interruptManagement\MessageSignaledInterruptProperties" -Name "MSISupported" -Value 1 -Type DWord -Force
        Remove-ItemProperty -Path "$interruptManagement\Affinity Policy" -Name "DevicePriority" -Force
    }
}

# Set the network adapter to Normal priority if a virtual machine is used as Undefined breaks internet connectivity
$vmList = "hvm", "hyper", "innotek", "kvm", "parallel", "qemu", "virtual", "xen", "vmware"
$manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer.ToLower()

foreach ($platform in $vmList) {
    if ($manufacturer.Contains($platform)) {
        Get-CimInstance -ClassName CIM_NetworkAdapter | Where-Object { $_.PNPDeviceID -like "PCI\VEN_*" } | ForEach-Object {
            $interruptManagement = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($_.PNPDeviceID)\Device Parameters\Interrupt Management"
            Set-ItemProperty -Path "$interruptManagement\Affinity Policy" -Name "DevicePriority" -Value 2 -Type DWord -Force
        }
        break
    }
}

# Disable Direct Memory Access (DMA) remapping
# https://docs.microsoft.com/en-us/windows-hardware/drivers/pci/enabling-dma-remapping-for-device-drivers
New-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\DmaGuard" -Name "DeviceEnumerationPolicy" -Value 2 -PropertyType DWORD -Force
Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services' -Recurse | ForEach-Object {
    if (Get-ItemProperty -Path $_.PsPath -Name "DmaRemappingCompatible") {
        Set-ItemProperty -Path $_.PsPath -Name "DmaRemappingCompatible" -Value 0 -Type DWord -Force
    }
}

## Network Configuration

# Disable NetBIOS over TCP/IP
Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -Recurse | ForEach-Object {
    if (Get-ItemProperty -Path $_.PsPath -Name "NetbiosOptions") {
        Set-ItemProperty -Path $_.PsPath -Name "NetbiosOptions" -Value 2 -Type DWord -Force
    }
}

# Disable Nagle's Algorithm
# https://en.wikipedia.org/wiki/Nagle%27s_algorithm
Get-CimInstance -Class Win32_NetworkAdapter | ForEach-Object {
    $interfaceGUID = $_.GUID
    $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$interfaceGUID"
    Set-ItemProperty -Path $keyPath -Name "TcpAckFrequency" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $keyPath -Name "TCPNoDelay" -Value 1 -Type DWord -Force
}

# Set network driver class key to the classKey variable
Get-CimInstance -Class Win32_NetworkAdapter | Where-Object {$_.PNPDeviceID -like "PCI\VEN_*"} | ForEach-Object {
    $device = $_
    $enumKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($device.PNPDeviceID)"
    $driver = Get-ItemProperty -Path $enumKey -Name Driver | Select-Object -ExpandProperty Driver
    $classKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$($driver -replace '\\', '\')"
}

# Configure internet adapter settings
# Dump of all possible settings found
# TO DO: revise and document each setting
$adapterProp = @(
    "AdvancedEEE",
    "AlternateSemaphoreDelay",
    "ApCompatMode",
    "ARPOffloadEnable",
    "AutoDisableGigabit",
    "AutoPowerSaveModeEnabled",
    "bAdvancedLPs",
    "bLeisurePs",
    "bLowPowerEnable",
    "DeviceSleepOnDisconnect",
    "DMACoalescing",
    "EEE",
    "EEELinkAdvertisement",
    "EeePhyEnable",
    "Enable9KJFTpt",
    "EnableConnectedPowerGating",
    "EnableDynamicPowerGating",
    "EnableEDT",
    "EnableGreenEthernet",
    "EnableModernStandby",
    "EnablePME",
    "EnablePowerManagement",
    "EnableSavePowerNow",
    "EnableWakeOnLan",
    "FlowControl",
    "FlowControlCap",
    "GigaLite",
    "GPPSW",
    "GTKOffloadEnable",
    "InactivePs",
    "LargeSendOffload",
    "LargeSendOffloadJumboCombo",
    "LogLevelWarn",
    "LsoV1IPv4",
    "LsoV2IPv4",
    "LsoV2IPv6",
    "MasterSlave",
    "ModernStandbyWoLMagicPacket",
    "MPC",
    "NicAutoPowerSaver",
    "Node",
    "NSOffloadEnable",
    "PacketCoalescing",
    "PMARPOffload",
    "PMNSOffload",
    "PMWiFiRekeyOffload",
    "PowerDownPll",
    "PowerSaveMode",
    "PowerSavingMode",
    "PriorityVLANTag",
    "ReduceSpeedOnPowerDown",
    "S5WakeOnLan",
    "SavePowerNowEnabled",
    "SelectiveSuspend",
    "SipsEnabled",
    "uAPSDSupport",
    "ULPMode",
    "WakeOnDisconnect",
    "WakeOnLink",
    "WakeOnMagicPacket",
    "WakeOnPattern",
    "WakeOnSlot",
    "WakeUpModeCap",
    "WoWLANLPSLevel",
    "WoWLANS5Support"
)

foreach ($prop in $adapterProp) {
    # Check if the ones with * exist and then disable them
    if (Get-ItemProperty -Path "$classKey" -Name "*$prop") {
        Set-ItemProperty -Path "$classKey" -Name "*$prop" -Value 0 -Type String -Force
    }
    # Check if the ones without * exist and then disable them
    if (Get-ItemProperty -Path "$classKey" -Name "$prop") {
        Set-ItemProperty -Path "$classKey" -Name "$prop" -Value 0 -Type String -Force
    }
}

# Disable other network adapter pover saving
# Dump of all possible settings found.
# TO DO: revise and document each setting
# Set-ItemProperty -Path "$classKey" -Name "PnPCapabilities" -Value 24 -Type DWord -Force
# Set-ItemProperty -Path "$classKey" -Name "MIMOPowerSaveMode" -Value 3 -Type DWord -Force
# Set-ItemProperty -Path "$classKey" -Name "WolShutdownLinkSpeed" -Value 2 -Type DWord -Force
# Set-ItemProperty -Path "$classKey" -Name "EeeCtrlMode" -Value 2 -Type DWord -Force
# Set-ItemProperty -Path "$classKey" -Name "GphyGreenMode" -Value 4 -Type DWord -Force
# Set-ItemProperty -Path "$classKey" -Name "DisableDelayedPowerUp" -Value 1 -Type DWord -Force

## Miscellaneous

# Debloat 'Send To' context menu, hidden files do not show up in the 'Send To' context menu
Set-ItemProperty -Path "$env:APPDATA\Microsoft\Windows\SendTo\Bluetooth File Transfer.LNK" -Name "Attributes" -Value ([IO.FileAttributes]::Hidden)
Set-ItemProperty -Path "$env:APPDATA\Microsoft\Windows\SendTo\Mail Recipient.MAPIMail" -Name "Attributes" -Value ([IO.FileAttributes]::Hidden)
Set-ItemProperty -Path "$env:APPDATA\Microsoft\Windows\SendTo\Documents.mydocs" -Name "Attributes" -Value ([IO.FileAttributes]::Hidden)

# Disable audio exclusive mode on capture devices
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture" -Recurse | ForEach-Object {
    Set-ItemProperty $_.PSPath -Name "{b3f8fa53-0004-438e-9003-51a46e139bfc},3" -Value 0
    Set-ItemProperty $_.PSPath -Name "{b3f8fa53-0004-438e-9003-51a46e139bfc},4" -Value 0
}

# Disable audio exclusive mode on playback devices
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render" -Recurse | ForEach-Object {
    Set-ItemProperty $_.PSPath -Name "{b3f8fa53-0004-438e-9003-51a46e139bfc},3" -Value 0
    Set-ItemProperty $_.PSPath -Name "{b3f8fa53-0004-438e-9003-51a46e139bfc},4" -Value 0
}

# Set sound scheme to 'No Sounds'
Get-ChildItem -Path "Registry::HKEY_USERS\" | ForEach-Object {
    $userKey = $_.Name
    # If the "Volatile Environment" key exists, that means it is a proper user. Built in accounts/SIDs do not have this key.
    if (Test-Path "$userKey\Volatile Environment" -or Test-Path "$userKey\AME_UserHive_") {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
        $schemesPath = "HKU:$userKey\AppEvents\Schemes"
        New-ItemProperty -Path $schemesPath -Name "(Default)" -Value ".None" -Force | Out-Null
        Get-ChildItem "$schemesPath\Apps" | Get-ChildItem | Get-ChildItem | Where-Object {$_.PSChildName -eq '.Current'} | Set-ItemProperty -Name "(Default)" -Value ""
    }
}

# Detect hard drive - Solid State Drive (SSD) or Hard Disk Drive (HDD)
$diskDrive = (Get-PhysicalDisk | ForEach-Object { $physicalDisk = $_ ; $physicalDisk | Get-Disk | Get-Partition | Where-Object { $_.DriveLetter -eq 'C'} | Select-Object @{n='MediaType';e={$physicalDisk.MediaType}}}).MediaType

if ($diskDrive -eq "SSD") {
    # Remove lower filters for rdyboost driver
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}"
    $val = (Get-ItemProperty -Path $key -Name LowerFilters).LowerFilters
    $val = $val -replace "rdyboost\0",""
    $val = $val -replace "\0rdyboost",""
    $val = $val -replace "rdyboost",""
    Set-ItemProperty -Path $key -Name LowerFilters -Value $val -Force

    # Disable ReadyBoost
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\rdyboost" -Name Start -Value 4 -Type DWORD -Force

    # Remove ReadyBoost tab
    Remove-Item -Path "HKCR:\Drive\shellex\PropertySheetHandlers\{55B3A0BD-4D28-42fe-8CFB-FA3EDFF969B8}" -Recurse -Force

    # Disable SysMain (Superfetch and Prefetch)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" -Name Start -Value 4 -Type DWORD -Force

    # Disable Memory Compression
    # SysMain should already disable it, but make sure it is disabled by executing this command.
    Disable-MMAGent -MemoryCompression
}

# Add Auto-Cleaner to run on startup
$taskAction = New-ScheduledTaskAction -Execute 'C:\Windows\AtlasModules\Scripts\Auto-Cleaner.cmd'
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn -Delay '00:00:30'
$taskSettings = New-ScheduledTaskSettingsSet -Compatibility Win8
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "nt authority\system" -LogonType ServiceAccount
Register-ScheduledTask -TaskName "\Atlas\Auto-Cleaner" -Action $taskAction -Trigger $taskTrigger -User "SYSTEM" -Settings $taskSettings -Principal $taskPrincipal -Force
