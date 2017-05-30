# Netbox Windows Shutdown v1.0
#
# Requires:
# Powershell v5
#
# This script is designed to remove netbox inventory records
# on host shutdown. It is intended to be paired with a Startup
# script to add records on host start.

# Configure API base url
$api_base_url = "https://netbox.example.com/api"

### End Configuration ###

# Set API Headers
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", 'Token asdf123')
$headers.Add("Content-Type", 'application/json')
$headers.Add("Accept", 'application/json')

# Fetch information about host
$getDeviceInfo = (Invoke-RestMethod -Uri $api_base_url/dcim/devices/?name=$env:computername -Headers $headers).results

# Delete IPv4 record from Netbox
$primary_ipPK = $getDeviceInfo.primary_ip.id
Invoke-RestMethod -Uri $api_base_url/ipam/ip-addresses/$primary_ipPK/ -Method Delete -Headers $headers

# Delete device record from Netbox
$devicePK = $getDeviceInfo.id
Invoke-RestMethod -Uri $api_base_url/dcim/devices/$devicePK/ -Method Delete -Headers $headers

# Delete device bay record from Netbox
$bayPK = $getDeviceInfo.parent_device.device_bay.id
Invoke-RestMethod -Uri $api_base_url/dcim/device-bays/$bayPK/ -Method Delete -Headers $headers

# Write summary to console
Write-Host "Netbox records deleted!
 Device ID: $devicePK
 IPv4 ID: $primary_ipPK
"