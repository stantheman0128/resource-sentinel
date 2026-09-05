' Launch a .ps1 with no console. Task Scheduler's conhost/powershell
' action is what Windows Terminal titles as a flashing tab.
If WScript.Arguments.Count < 1 Then WScript.Quit 1
Set sh = CreateObject("WScript.Shell")
ps1 = WScript.Arguments(0)
sh.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & ps1 & """", 0, True
