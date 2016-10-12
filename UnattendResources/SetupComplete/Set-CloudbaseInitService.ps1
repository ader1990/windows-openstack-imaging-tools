#ps1
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $env:windir "Setup\Scripts\WindowsUtils.psm1") -Force -DisableNameChecking

Start-ExecuteWithRetry { Set-CloudbaseInitService} -MaxRetryCount 10 -RetryInterval 0