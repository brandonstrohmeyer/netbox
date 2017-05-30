# Netbox Windows Startup v1.0
#
# Requires:
# Powershell v5
#
# This script is designed to add new Devices and IP Addresses on startup.
# It is expected to be paired with a shutdown script to remove Netbox
# inventory records on shutdown. The intended usage is in a dynamic
# environment where VMs are created and destroyed automatically. The
# script will also add VMs to a manually defined parent.
# Configure physical site ID
#
#  Site   ID
# ------ ----
#  ABC     1
#  DEF     2

$site = "2"

# Configure parent device by hostname
$parentName = "FOO"

# Configure API base url using format "http://example.com/api"
$api_base_url = "https://netbox.example.com/api"

### End Configuration ###

# Set IPv4 variables
$cidr = (Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4 -IncludeAllCompartments).IPAddress`
+ "/" + `
(Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4 -IncludeAllCompartments).PrefixLength

# Set API Headers
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", 'Token asdf123')
$headers.Add("Content-Type", 'application/json')
$headers.Add("Accept", 'application/json')

# Create IP Address record
$ipaddr = @{
    address=$cidr
    description='auto-managed'
}
$ipaddrJson = $ipaddr | ConvertTo-Json
$setIP = Invoke-RestMethod -Uri $api_base_url/ipam/ip-addresses/ -Method Post -Headers $headers -Body $ipaddrJson

# Create Device record
$ip4PK = $setIP.id
$device = @{
    name=$env:computername
    device_role=12
    device_type=32
    site=$site
    primary_ip4=$ip4PK
    tenant=12
    comments='auto-managed'
}
$deviceJson = $device | ConvertTo-Json
$setDevice = Invoke-RestMethod -Uri $api_base_url/dcim/devices/ -Method Post -Headers $headers -Body $deviceJson

# Update interface record
$devicePK = $setDevice.id
$interfacePK = (Invoke-RestMethod -Uri $api_base_url/dcim/interfaces/?device_id=$devicePK -Headers $headers).results.id
$interface = @{
    address=$cidr
    interface=$interfacePK
}
$interfaceJson = $interface | ConvertTo-Json
$setInterface = Invoke-RestMethod -Uri $api_base_url/ipam/ip-addresses/$ip4PK/ -Method Patch -Headers $headers -Body $interfaceJson

# Create Device Bay in pool
$parentNamePK = (Invoke-RestMethod -Uri $api_base_url/dcim/devices/?name=$parentName -Headers $headers).results.id
$bay = @{
    device=$parentNamePK
    name=$devicePK
    installed_device=$devicePK
}
$bayJson = $bay | ConvertTo-Json
$setBay = Invoke-RestMethod -Uri $api_base_url/dcim/device-bays/ -Method Post -Headers $headers -Body $bayJson

# Write summary to console
Write-Host "
Netbox records created!
 Device Name: $env:computername
 Device ID: $devicePK
 IPv4 Addres: $cidr
 IPv4 ID: $ip4PK
"
