### Capstone - Remote Thread Creation
## Alert looks for remote threads being created across processes
# Severity: Medium

# rule logic

WindowsEvent 
| where Channel == "JonMon/Operational" and EventID == 3 and EventData.SourceProcessIntegrityLevel == "High" and (EventData .TargetProcessIntegrityLevel == "High" or EventData.TargetProcessIntegrityLevel == "System")
| where EventData.SourceProcessFilePath !contains "WindowsTerminal.exe"
| project TimeGenerated, Computer, EventID, EventData.SourceProcessFilePath, EventData.SourceProcessUser, EventData.TargetProcessFilePath, EventData.TargetProcessIntegrityLevel, EventData.TargetProcessUser, EventData.TargetThreadId

# MITRE ATT&CK
Privilege Escalation 
 - T1055 - Process Injection

### Capstone - Rubeus executed via .NET
## Looks at DotNet load events and triggers when the Rubeus assembly is loaded
# Severity - High

# rule logic

WindowsEvent
| where Channel == "JonMon/Operational"
| where EventID == 16 
| where EventData.AssemblyName contains "Rubeus"

### Capstone - WMI Event Subscription
## Alert generates when a WMI Event Subscription is created
# Severity Medium

# rule logic

WindowsEvent
| where Provider == "JonMon"
| where EventID == 17
| project TimeGenerated, Provider, EventID, EventData.ProcessFilePath, EventData.ProcessId, EventData.ProcessUser, EventData.ProcessUserLogonId, EventData.ESS, EventData.Consumer, EventData.PossibleCause

# MITRE ATT&CK
Privilege Escalation 
 - T1055 - Process Injection

### Capstone - Potential Lateral Movement via Network Logon Type
## This alert fires when a network logon type (3) is generated along with process execution. This can be a sign of lateral movement.
# Severity - Medium

# rule logic

WindowsEvent
| where EventID == 4624
| where EventData.LogonType == 3
| project
    TimeGenerated,
    Computer,
    TargetLogonId = tostring(EventData.TargetLogonId),
    TargetUserName = tostring(EventData.TargetUserName),
    TargetDomainName = tostring(EventData.TargetDomainName),
    LogonType = tostring(EventData.LogonType),
    AuthenticationPackageName = tostring(EventData.AuthenticationPackageName)
| join kind=inner (
    WindowsEvent
    | where EventID == 4688
    | project
        TimeGenerated,
        Computer,
        TargetLogonId = tostring(EventData.TargetLogonId),
        NewProcessName = tostring(EventData.NewProcessName),
        CommandLine = tostring(EventData.CommandLine),
        ParentProcessName = tostring(EventData.ParentProcessName),
        SubjectUserName = tostring(EventData.SubjectUserName)
) on TargetLogonId
| project
    TimeGenerated,
    TargetLogonId,
    TargetUserName,
    TargetDomainName,
    LogonType,
    AuthenticationPackageName,
    NewProcessName,
    CommandLine,
    ParentProcessName,
    SubjectUserName,
    Computer
| order by TimeGenerated desc

### Capstone - Possible DCSync
## Alerts when potential DCSync occurs
# Severity - High

# rule logic

WindowsEvent
| where Provider == "Microsoft-Windows-Security-Auditing" and EventID == 4662
| where EventData.SubjectUserName !contains "$" and EventData.Properties contains "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" and EventData.Properties contains "19195a5b-6da0-11d0-afd3-00c04fd930c9"

# MITRE ATT&CK
Credential Access
 - T1003 - OS Credential Dumping
    - T1003.006 - DCSync

### Capstone - Non-Standard Network Connections
## Alert triggers when dllhost.exe and rundll32.exe has a network connection
# Severity - Medium


# rule logic

WindowsEvent 
| where Channel == "JonMon/Operational" and EventID == 3 and EventData.SourceProcessIntegrityLevel == "High" and (EventData .TargetProcessIntegrityLevel == "High" or EventData.TargetProcessIntegrityLevel == "System")
| where EventData.SourceProcessFilePath !contains "WindowsTerminal.exe"
| project TimeGenerated, Computer, EventID, EventData.SourceProcessFilePath, EventData.SourceProcessUser, EventData.TargetProcessFilePath, EventData.TargetProcessIntegrityLevel, EventData.TargetProcessUser, EventData.TargetThreadId

### Capstone - Mshta Execution
## Alert is generated when a HTA file is executed via mshta
# Severity - Medium

# rule logic

WindowsEvent
| where Provider == "JonMon" and EventID == 1
| where EventData.ProcessFilePath endswith "mshta.exe"

### Capstone - CobaltStrike Named Pipes
## Alert triggers when common CobaltStrike named pipes are created
# Severity - High

# rule logic

let CobaltStrikeDefaults= dynamic([@"msagent_", @"MSSE-", @"postex_", @"status_", @"mypipe-f", @"mypipe-h",@"ntsvcs_",@"scerpc_", @"mojo.5688.8052."]);

WindowsEvent
| where Channel == "JonMon/Operational"
| where EventID == 11
| where EventData.FileName has_any(CobaltStrikeDefaults)