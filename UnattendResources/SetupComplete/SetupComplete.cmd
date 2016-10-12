powershell -NoLogo -NonInteractive -ExecutionPolicy RemoteSigned -File %SystemDrive%\Windows\Setup\Scripts\Set-CloudbaseInitService.ps1
sc config cloudbase-init start= auto && net start cloudbase-init 
