# Copyright 2023 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
param(
    [parameter(Mandatory=$true)]
    [string] $WinIsoPath,
    [string] $BaseImageDir = $env:TEMP,
    [string] $HyperVSwitchName = "external"
)

$ErrorActionPreference = "Stop"
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition | Split-Path

if (!(Test-Path $WinIsoPath)) {
    throw "Windows ISO path ${WinIsoPath} does not exist."
}
if (!(Get-VMSwitch $HyperVSwitchName -ErrorAction SilentlyContinue)) {
    throw "HyperV switch ${HyperVSwitchName} could not be found.`nPlease enable HyperV module and create ${HyperVSwitchName} switch."
}

git -C $scriptPath submodule update --init
if ($LASTEXITCODE) {
    throw "Failed to update git modules."
}

try {
    Join-Path -Path $scriptPath -ChildPath "\WinImageBuilder.psm1" | Remove-Module -ErrorAction SilentlyContinue
    Join-Path -Path $scriptPath -ChildPath "\Config.psm1" | Remove-Module -ErrorAction SilentlyContinue
    Join-Path -Path $scriptPath -ChildPath "\UnattendResources\ini.psm1" | Remove-Module -ErrorAction SilentlyContinue
} finally {
    Join-Path -Path $scriptPath -ChildPath "\WinImageBuilder.psm1" | Import-Module
    Join-Path -Path $scriptPath -ChildPath "\Config.psm1" | Import-Module
    Join-Path -Path $scriptPath -ChildPath "\UnattendResources\ini.psm1" | Import-Module
}

# Make sure the BaseDir exists
New-Item -Type Directory $BaseImageDir -ErrorAction SilentlyContinue

if (!(Test-Path $BaseImageDir)) {
    throw "Failed to create ${BaseImageDir}."
}

# The Windows image file path that will be generated
$windowsImagePath = Join-Path $BaseImageDir "arm64-image"

# The wim file path is the installation image on the Windows ISO
$isoDriveLetter = (Mount-DiskImage $WinIsoPath -PassThru | Get-Volume).DriveLetter
$wimFilePath = Join-Path "${isoDriveLetter}:" "Sources\install.wim"
Get-PSDrive | Out-Null

if (!(Test-Path $wimFilePath)) {
    throw "Windows wim path ${wimFilePath} does not exist."
}

# Every Windows ISO can contain multiple Windows flavors like Core, Standard, Datacenter
# Usually, the first image version is the Core or Home one
$image = (Get-WimFileImagesInfo -WimFilePath $wimFilePath)[0]
Write-Host "Generating image name: $($image.ImageName)"

# The path were you want to create the config fille
$configFilePath = Join-Path $scriptPath "Examples\arm64-resources\win2k22-arm64.ini"

# UEFI is required for ARM64
Set-IniFileValue -Path $configFilePath -Section "Default" -Key "disk_layout" -Value "UEFI"
# A special build of cloudbase-init installer for ARM64
$cloudbaseInitInstallerLocalPath = "Examples\arm64-resources\CloudbaseInitSetup-1.1.3-x86-installer-with-python-arm64.msi"
Set-IniFileValue -Path $configFilePath -Section "cloudbase_init" -Key "msi_path" -Value $cloudbaseInitInstallerLocalPath

# This is an example how to automate the image configuration file according to your needs
Set-IniFileValue -Path $configFilePath -Section "Default" -Key "wim_file_path" -Value $wimFilePath
Set-IniFileValue -Path $configFilePath -Section "Default" -Key "image_name" -Value $image.ImageName
Set-IniFileValue -Path $configFilePath -Section "Default" -Key "image_path" -Value $windowsImagePath
Set-IniFileValue -Path $configFilePath -Section "Default" -Key "image_type" -Value "HYPERV"
Set-IniFileValue -Path $configFilePath -Section "updates" -Key "install_updates" -Value "True"
Set-IniFileValue -Path $configFilePath -Section "updates" -Key "purge_updates" -Value "True"
Set-IniFileValue -Path $configFilePath -Section "sysprep" -Key "disable_swap" -Value "True"
Set-IniFileValue -Path $configFilePath -Section "vm" -Key "cpu_count" -Value 4
Set-IniFileValue -Path $configFilePath -Section "vm" -Key "ram_size" -Value (4GB)
Set-IniFileValue -Path $configFilePath -Section "vm" -Key "disk_size" -Value (30GB)
Set-IniFileValue -Path $configFilePath -Section "vm" -Key "external_switch" -Value $HyperVSwitchName

# This scripts generates a vhdx image file
New-WindowsOnlineImage -ConfigFilePath $configFilePath

Write-Host "The image has been successfully generated."
Write-Host "Image path: ${windowsImagePath}.vhdx"
