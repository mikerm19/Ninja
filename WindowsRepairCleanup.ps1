#mikerm 
#2022-12-2 - Initial Commit
#2023-02-27 - Switched SFC/DISM run order, added trustedinstaller service check, changed DISM to run through powershell commands instead, removed cleanmgr since it never works right.
#2023-04-05 - Removed custom functions that were either broken or not in use anymore. Added cleaning out minidump and prefetch, fixed commands so that they don't cause the script to report as FAILED in the Ninja log.
#2023-04-06 - Removed the need for writing log files to the host since it's logged in Ninja anyway.

#Script setup
$arch = Get-WMIObject -Class Win32_Processor -ComputerName LocalHost | Select-Object AddressWidth

#---- Begin Script ----
#Make sure the TrustedInstaller service is running.
$ServiceName = 'trustedinstaller'
$arrService = Get-Service -Name $ServiceName
$LoopCount = 0
 # Try several times to restart it
while ($arrService.Status -ne 'Running') {
    Start-Service $ServiceName
    write-host "Trusted Installer $arrService.status"
    write-host 'Trusted Installer service starting'
    Start-Sleep -seconds 10
    $arrService.Refresh()
    if ($arrService.Status -eq 'Running')
    {
        Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Trusted Installer service is now Running"
    }
    $LoopCount += 1
    if ($LoopCount -gt 10) {
      Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): WARNING: Trusted Installer service failed to start, SFC may fail"
      break
    }
}

# Run a DISM restore
Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Running DISM..."
try {
  Repair-WindowsImage -RestoreHealth -Online -NoRestart
} catch {
  try {
    Repair-WindowsImage -RestoreHealth -Online -NoRestart
  } catch {
    Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): WARNING: There was an error running DISM: $_"
  }
}

Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Running SFC..." 
# Workaround for encoding issues preventing SFC from running correctly
$OriginalEncoding = [console]::OutputEncoding
[console]::OutputEncoding = [Text.Encoding]::Unicode
$SFC = & $env:SystemRoot\System32\sfc.exe /ScanNow
[console]::OutputEncoding = $OriginalEncoding
 
# Ninja cuts off the output if theres too much, so limit the number of lines
# This is all just individial progress percentages except the start/end
$SFC | Select-Object -First 10
Write-Host "[...]"
$SFC | Select-Object -Last 10

Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Cleaning Windows temp, minidump, and prefetch folders..."
Remove-Item -Path "$env:SystemRoot\TEMP\*" -Recurse -Force -ErrorAction Ignore
Remove-Item -Path "$env:windir\minidump\*" -Force -Recurse -ErrorAction Ignore
Remove-Item -Path "$env:windir\Prefetch\*" -Force -Recurse -ErrorAction Ignore

Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Stopping Windows Update Services..." 
Stop-Service -Name BITS
Stop-Service -Name wuauserv 
Stop-Service -Name appidsvc 
Stop-Service -Name cryptsvc

Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Removing QMGR Data files..." 
Remove-Item "$env:allusersprofile\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -ErrorAction Ignore 
Remove-Item "$env:allusersprofile\Microsoft\Network\Downloader\qmgr*.dat" -ErrorAction Ignore

Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Removing the Software Distribution and CatRoot Folder..." 
Remove-Item $env:systemroot\SoftwareDistribution -Recurse -ErrorAction Ignore 
Remove-Item $env:systemroot\System32\Catroot2 -Recurse -ErrorAction Ignore 

Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Resetting the Windows Update Services to defualt settings..." 
"sc.exe sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"
"sc.exe sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"

Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Re-Registering Windows Update DLLs..." 
Set-Location $env:systemroot\system32 
Try {
  regsvr32.exe /s atl.dll
  regsvr32.exe /s urlmon.dll 
  regsvr32.exe /s mshtml.dll 
  regsvr32.exe /s shdocvw.dll 
  regsvr32.exe /s browseui.dll 
  regsvr32.exe /s jscript.dll 
  regsvr32.exe /s vbscript.dll 
  regsvr32.exe /s scrrun.dll 
  regsvr32.exe /s msxml.dll 
  regsvr32.exe /s msxml3.dll 
  regsvr32.exe /s msxml6.dll 
  regsvr32.exe /s actxprxy.dll 
  regsvr32.exe /s softpub.dll 
  regsvr32.exe /s wintrust.dll 
  regsvr32.exe /s dssenh.dll 
  regsvr32.exe /s rsaenh.dll 
  regsvr32.exe /s gpkcsp.dll 
  regsvr32.exe /s sccbase.dll 
  regsvr32.exe /s slbcsp.dll 
  regsvr32.exe /s cryptdlg.dll 
  regsvr32.exe /s oleaut32.dll 
  regsvr32.exe /s ole32.dll 
  regsvr32.exe /s shell32.dll 
  regsvr32.exe /s initpki.dll 
  regsvr32.exe /s wuapi.dll 
  regsvr32.exe /s wuaueng.dll 
  regsvr32.exe /s wuaueng1.dll 
  regsvr32.exe /s wucltui.dll 
  regsvr32.exe /s wups.dll 
  regsvr32.exe /s wups2.dll 
  regsvr32.exe /s wuweb.dll 
  regsvr32.exe /s qmgr.dll 
  regsvr32.exe /s qmgrprxy.dll 
  regsvr32.exe /s wucltux.dll 
  regsvr32.exe /s muweb.dll 
  regsvr32.exe /s wuwebv.dll 
} catch {
  Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): There was an error registering DLLs: $_"
}
Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Removing WSUS client settings if they exist..." 
Remove-Item "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Recurse -ErrorAction Ignore
Remove-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Recurse -ErrorAction Ignore
Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Recurse -ErrorAction Ignore
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Recurse -ErrorAction Ignore

Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Deleting all BITS jobs..." 
Get-BitsTransfer | Remove-BitsTransfer 
 
Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Starting Windows Update Services..." 
Start-Service -Name BITS
Start-Service -Name wuauserv
Start-Service -Name appidsvc
Start-Service -Name cryptsvc

Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Resetting TCP/IP and WinSock..." 
netsh int tcp reset
netsh winsock reset

Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Flushing DNS..."
ipconfig /flushdns

Write-Host "$(Get-Date -format 'yyyyMMddHHmmss'): Scheduling disk check on next reboot..."
echo Y | chkdsk $env:systemdrive /f >NULL

If ($Error) {
  Write-Host "$Error"
  Write-Host "This may be ignored. Try rebooting and running the script again."
  Exit 1
} Else {
  Write-Host "Finished, please reboot."
}
