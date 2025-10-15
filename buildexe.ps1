$meta = @{
  InputFile   = '.\autol1\Device-Report.ps1'
  OutputFile  = '.\dist\AutoHelpDesk.exe'
  Title       = 'AutoHelpDesk'
  Product     = 'AutoHelpDesk'
  Company     = 'CloudConnected PTY LTD'
  Description = 'AutoHelpDesk device report (collect + analyze)'
  Version     = '1.0.0.0'
  # IconFile  = '.\assets\autohelpdesk.ico'  # optional
  NoConsole   = $false          # you WANT a console
  RequireAdmin= $true           # you said it needs admin
  X64         = $true           # build a 64-bit exe
}
New-Item -ItemType Directory -Force -Path .\dist | Out-Null
Invoke-PS2EXE @meta
