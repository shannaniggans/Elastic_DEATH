
#    ______ 
#   | |__ __ _ _ __   ___ _   _  
#   |  __/ _` | '_ \ / __| | | |
#   | | | (_| | | | | (__| |_| |
#   |_|  \__,_|_| |_|\___|\__, |
#                          __/ |                                                 
#                         |___/                                                  







| Operation                                           | Techniques                                                                                       |
|-----------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Fake captcha verification                           | T1566: Phishing                                                                                 |
| Executed the initial PS code                        | T1204: User Execution <br> T1059.001: Command and Scripting Interpreter: PowerShell             |
| Downloaded the payload using mshta, which had overlayed script | T1218.005: System Binary Proxy Execution: Mshta <br> T1027.009: Obfuscated Files or Information: Embedded Payloads |
| Executed the encrypted payload using powershell.exe | T1059.001: Command and Scripting Interpreter: PowerShell <br> T1027.013: Obfuscated Files or Information: Encrypted/Encoded File |
| PowerShell downloaded Lumma Stealer and executed   | T1059.001: Command and Scripting Interpreter: PowerShell                                        |
| Lumma Injected malicious payload in BitLockerToGo  | T1055.012: Process Injection: Process Hollowing                                                 |
| Information collection                              | T1217: Browser Information Discovery <br> T1083: File and Directory Discovery                   |
| Injected process executed killing.bat script       | T1059.003: Command and Scripting Interpreter: Windows Command Shell                             |
| Batch script discovered the process and started AutoIT | T1057: Process Discovery                                                                         |
| AutoIT executes the script                         | T1059.010: Command and Scripting Interpreter: AutoIT                                            |
| Exfiltration                                        | T1041: Exfiltration Over C2 Channel                                                             |






## Initial Access

| Operation                                           | Techniques                                                                                       |
|-----------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Fake captcha verification                           | T1566: Phishing                                                                                 |
| Executed the initial PS code                        | T1204: User Execution <br> T1059.001: Command and Scripting Interpreter: PowerShell             |

### Fake Captcha



* Circumvents general security measures like Safe Browsing[^1].
* Tricking users into installing dangerous stealer malware via a captcha verification page. This seemingly legitimate captcha page appears unexpectedly as you browse a content site, perfectly mimicking a real verification process. It asks you to confirm you’re human through a series of keyboard clicks, which ultimately trigger the Run dialog on your Windows system. Unknowingly, you paste and execute a cleverly crafted PowerShell command, instantly installing stealer malware that targets your social accounts, banking credentials, passwords, and personal files. Vicious, effective, and dangerously evasive!
  
![alt text](image.png)

[^1]: https://labs.guard.io/deceptionads-fake-captcha-driving-infostealer-infections-and-a-glimpse-to-the-dark-side-of-0c516f4dc0b6
[^2]: https://mandarnaik016.in/blog/2024-10-05-malware-analysis-lumma-stealer/

#### Look for a user who has run a powershell command from the Run Prompt.

* In these campaigns the attacker utilised advertising networks in order to serve content. They put PowerShell payloads hidden in the ad.
* A user might be browsing a site and an advertising window pops up asking them to verify their identity. This popup is the fake capture page.
* The captcha page then asks the users to perform the task for verification.

```
data_stream.dataset: endpoint.events.registry and registry.key: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\* and registry.value: powershell*
```

> !!!! Need to test this
    Haven't tested the full discover query yet.

Then correlate with a PowerShell process being spawned containing Base64 encoded text and in a hidden window. This is the first stage that usually goes and grabs another powershell script that is downloaded and ran. The query below looks for a PowerShell script being run from "explorer.exe", with a hidden window and encoded text.

```
data_stream.dataset: endpoint.events.process and process.name: ("powershell.exe") and process.args : (*-EncodedCommand* OR *-ec*) AND process.parent.name: "explorer.exe" 
```

process.name:”powershell.exe” and process.arguments: [“-e”, “-ec”, “-enc”, “-enco”, “encodedCommand”]

This next one is looking for a powershell script running with key indicators 


process.parentname: mshta.exe and action: created and file.type: PE

```
data_stream.dataset: endpoint.events.process and process.name: ("powershell.exe") and process.args : (*System.Net.WebClient* AND *Start-Process*)
```

Some of these initial scripts will clear the clipboard to delete the script:

```
Set-Clipboard
```

And clears the DNS cache

```
Clear-DnsClientCache
```


[^1]: https://labs.guard.io/deceptionads-fake-captcha-driving-infostealer-infections-and-a-glimpse-to-the-dark-side-of-0c516f4dc0b6
[^2]: https://mandarnaik016.in/blog/2024-10-05-malware-analysis-lumma-stealer/





## Persistence
HKEY_USERS{USER Account HERE}\Software\Microsoft\Windows\CurrentVersion\Run.’ This is one of the most common spots for persistence, as it allows the actor to obtain access to the target endpoint. MITRE ATT&CK T1547.001



## Collection

LummaC2 steals extension data from a variety of Chrome-based browsers including Opera, Brave, Chrome, Chromium, and more. The malware accomplishes this by locating the “Local Extension Settings” for each browser, which stores the internal extension information for many extensions. 

While LummaC2 has a large list of targeted extensions that includes 2FA code managing extensions, through our tests, LummaC2 does not actually extract most 2FA code secrets, as these secrets are not stored in “Local Extension Settings” for Chrome browsers. However, LummaC2 does steal passwords and PII stored in extensions for a wide variety of crypto tools. Additionally, as LummaC2 does programmatically decrypt Chrome’s internal .ldb database storage files, LummaC2 could in the future begin extracting 2FA code secrets that are stored locally on a victim’s device, just like passwords or crypto wallets.

Malware initiates a search for sensitive files and data related to cryptocurrency and password txt files across various directories on the compromised system. It specifically looks for files having keywords that suggest they may hold confidential information, such as *seed*.txt, *pass*.txt, *.kbdx, *ledger*.txt, *trezor*.txt, *metamask*.txt, bitcoin*.txt, *word*, *wallet*.txt

Policy.vpol contains settings and policies related to BitLocker that are managed through Group Policy


```
data_stream.dataset: endpoint.events.file AND
event.action: (open OR read) AND
file.path: (
    *\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data* OR
    *\\AppData\\Local\\Google\\Chrome\\User Data\\Local State* OR
    *\\AppData\\Local\\Microsoft\\Windows\\INetCookies* OR
    *\\AppData\\Local\\Microsoft\\Vault* OR
    *\\AppData\\Local\\Microsoft\\Credentials* OR
    *\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default* OR
    *\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State* OR
    *\\AppData\\Roaming\\Opera Software\\Opera Stable\\Last Version* OR
    *\\AppData\\Local\\Microsoft\\TokenBroker\\*
) AND process.executable: *\\AppData\\Local\\Temp\\*
```


## Execution

Could have alow fidelity indicator on Bitlockertogo.exe and dllhost being the parent process for connhost.exe 
* "We have discovered that ‘dllhost.exe’ was created as a child process. Malicious code is injected into ‘Bitlockertogo.exe,’ which then creates two additional processes that finally create ‘dllhost.exe.’ Additionally, we observed ‘dllhost.exe’ being used for command and control, with connections to the IP."

https://www.ontinue.com/resource/obfuscated-powershell-leads-to-lumma-c2-stealer/


\AppData\Local\Temp\ exe files and zip files in here




5. Obfuscation Indicators (Event ID: process_start and file_create)
LummaC2 employs obfuscation to hide its activity.

Fields to Investigate:
process.name: powershell.exe, cmd.exe, mshta.exe.
process.args: Look for encoded or obfuscated commands.
file.path: Suspicious executables or scripts in:
%TEMP%
%APPDATA%
%PROGRAMDATA%


process.executable: *\\AppData\\Local\\Temp\\*

process.executable: *\\AppData\\Local\\Temp\\* AND destination.port: (80 OR 443 OR 22 OR 53)

4. Registry Modifications (Event ID: registry_key)
LummaC2 may manipulate browser configurations or disable security features.

Fields to Investigate:
registry.key:
Chrome: HKCU\Software\Google\Chrome\PreferenceMACs
Edge: HKCU\Software\Microsoft\Edge\PreferenceMACs
event.action: modify or create.

## Command and Control

‘POST’ request to ‘vamplersam[.]info,’ where the request is sending data to the endpoint ‘/cfg.’

POST /c2sock

Another common aspect of Lumma is that it uses the User-Agent ‘TeslaBrowser/5.5.’



host.hostname: "desktop-7ccmvl5" 


data_stream.dataset: endpoint.events.network AND dns.question.name: marshal-zhukov.com (match TI)