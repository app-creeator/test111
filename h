1. Find every bundled control and DLL
powershell
$app = "C:\Program Files (x86)\Avaya\CMS Supervisor R21"   # adjust
Get-ChildItem $app -Recurse -Include *.ocx,*.dll,*.exe -ErrorAction SilentlyContinue |
  Select FullName, Length, LastWriteTime | Format-Table -Auto

VB6 apps often install their controls into SysWOW64 rather than the app folder. List those too:

powershell
Get-ChildItem C:\Windows\SysWOW64 -Include *.ocx -Recurse -ErrorAction SilentlyContinue |
  Select Name, @{n='Version';e={$_.VersionInfo.FileVersion}}, LastWriteTime
2. Get versions and signature status

Using Sysinternals sigcheck:

cmd
sigcheck.exe -accepteula -a -h -e -s "C:\Program Files (x86)\Avaya\CMS Supervisor R21" > sigcheck_app.txt
sigcheck.exe -accepteula -a -e C:\Windows\SysWOW64\*.ocx > sigcheck_ocx.txt

With plain PowerShell, exported to CSV for the report:

powershell
Get-ChildItem $app, C:\Windows\SysWOW64 -Recurse -Include *.ocx,*.dll -ErrorAction SilentlyContinue |
  ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.FullName
    [pscustomobject]@{
      File        = $_.FullName
      FileVersion = $_.VersionInfo.FileVersion
      Product     = $_.VersionInfo.ProductName
      Company     = $_.VersionInfo.CompanyName
      Signed      = $sig.Status
      Signer      = $sig.SignerCertificate.Subject
      SHA256      = (Get-FileHash $_.FullName).Hash
    }
  } | Export-Csv controls_inventory.csv -NoTypeInformation
3. Confirm which controls Supervisor actually loads

Start the app and open several reports so it loads its controls, then run:

cmd
tasklist /m /fi "imagename eq acsSRV.exe"
listdlls.exe -accepteula -v <PID> > loaded_modules.txt

Swap in the real process name, which Task Manager will show.

You can also capture this in Procmon. Filter on the process with Operation = Load Image, and that gives you the exact path of every DLL and OCX it loaded.

4. List the COM/ActiveX controls it registers
powershell
Get-ChildItem "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID" -ErrorAction SilentlyContinue | ForEach-Object {
  $srv = (Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
  if ($srv -match '\.ocx$|Avaya') {
    [pscustomobject]@{ CLSID=$_.PSChildName; Server=$srv
      Name=(Get-ItemProperty $_.PSPath).'(default)' }
  }
} | Format-Table -Auto
5. Check kill bits on risky controls
powershell
$clsid = "{BDD1F04B-858B-11D1-B16A-00C0F0283628}"   # example: MSCOMCTL ListView; replace with CLSIDs from step 4
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\ActiveX Compatibility\$clsid" /v "Compatibility Flags"

A value of 0x400 means the kill bit is set. If the key is missing, the control isn't killed. This mainly matters if the control is also reachable from IE/Office documents on the same machine.

6. Compare against known vulnerable versions

For each control in controls_inventory.csv, look up the file name and version against these sources:

Microsoft Security Update Guide and the old MS bulletins. Key ones for VB6-era controls are MS12-027 and MS12-060 (MSCOMCTL.OCX, CVE-2012-0158) and MS08-070 (VB6 runtime controls such as MSFlexGrid, MSHFlexGrid and MSChart). Note the "fixed file version" listed in each bulletin's file information table.
NVD: search the control name, such as mscomctl.ocx or msflxgrd.ocx.
Third-party controls (Crystal Reports, ComponentOne, Sheridan and similar): check the vendor's advisories for that product version.

Quick check for the most common culprits:

powershell
"MSCOMCTL.OCX","MSCOMCT2.OCX","COMCTL32.OCX","MSFLXGRD.OCX","MSHFLXGD.OCX","MSCHRT20.OCX","COMDLG32.OCX","MSWINSCK.OCX","RICHTX32.OCX","TABCTL32.OCX","MSVBVM60.DLL" |
 ForEach-Object {
   Get-ChildItem $app, C:\Windows\SysWOW64 -Filter $_ -Recurse -ErrorAction SilentlyContinue |
   Select Name, @{n='Ver';e={$_.VersionInfo.FileVersion}}, DirectoryName
 } | Format-Table -Auto
