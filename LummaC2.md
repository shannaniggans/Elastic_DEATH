**DRAFT**

## Detection Story
1. We use open source threat intel through Elastic that trigger on IP addresses that have been tagged Lumma in various places. These alerts are fairly low fidelity and I wanted a way to incorporate them into some better rules and alerts.
2. Finding ways to alert on some of teh Lumma activity, particularly in the initial access and execution phases will help to limit the impact.


## Research


* https://labs.guard.io/deceptionads-fake-captcha-driving-infostealer-infections-and-a-glimpse-to-the-dark-side-of-0c516f4dc0b6
* https://mandarnaik016.in/blog/2024-10-05-malware-analysis-lumma-stealer/
* https://www.ontinue.com/resource/obfuscated-powershell-leads-to-lumma-c2-stealer/

  
![alt text](image.png)



## 1. Initial Access: Fake Captcha

| Operation                                           | Techniques                                                                                       |
|-----------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Fake captcha verification                           | T1566: Phishing 

* Tricking users into installing dangerous stealer malware via a captcha verification page. This seemingly legitimate captcha page appears unexpectedly as you browse a content site, perfectly mimicking a real verification process. It asks you to confirm you’re human through a series of keyboard clicks, which ultimately trigger the Run dialog on your Windows system. Unknowingly, you paste and execute a cleverly crafted PowerShell command, instantly installing stealer malware that targets your social accounts, banking credentials, passwords, and personal files. Vicious, effective, and dangerously evasive!
* Circumvents general security measures like Safe Browsing.
* In these campaigns the attacker utilised advertising networks in order to serve content. They put PowerShell payloads hidden in the ad that get copied to the clipboard so the user can paste them into the Run command prompt.
* A user might be browsing a site and an advertising window pops up asking them to verify their identity. This popup is the fake capture page.
* The captcha page then asks the users to perform the task for verification.
* When the run command is used, the registry key is updated to include the command. The below KQL is to look for evidence of "PowerShell" being executed from the Run prompt:


  
Threat Hunting Rule: The elastic agent queries the registry data available on files on disk, when those are updated isnt entirely clear by MS so this may not be a key indicator quickly.
The Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\MRUList registry key in Windows contains a list of recently executed commands typed into the "Run" dialog box. This key can be valuable for threat hunting as it may reveal attacker activity, such as commands used for lateral movement, privilege escalation, or reconnaissance.


    ```sql
    data_stream.dataset : endpoint.events.registry AND registry.value: MRUList AND registry.data.strings: *
    ```

    ```osquery
    SELECT path, name, data
    FROM registry
    WHERE path LIKE 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU%';
    ```



* Potential False Positives:
  * Legitimate users might do this, for example, an administrator, but I believe that this activity would be minimal and could be easily identified and exceptions made if indeed it was normal practice in an organisation.

## 2. Execution: PowerShell

| Operation                                           | Techniques                                                                                       |
|-----------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Executed the initial PS code                        | T1204: User Execution <br> T1059.001: Command and Scripting Interpreter: PowerShell             |

* To determine whether or not this is legitimate, we want to review the PowerShell being run, but we can make some assumptions based on the previous activity of the malware that it is most likely an encoded command.
* So the next phase will be to see if a PowerShell process was spawned containing Base64 encoded text and in a hidden window. This is the first stage that usually goes and grabs another powershell script that is downloaded and ran. 
* The query below looks for a PowerShell script being run from "explorer.exe" with encoded text.

    ```sql
    data_stream.dataset: endpoint.events.process AND 
        process.name: ("powershell.exe") AND 
        process.args : (*-encodedCommand* OR *-ec* OR *-e\ * OR *-enco*) AND 
        process.parent.name: "explorer.exe" 
    ```
 cvb
* Potential False Positives:
  * Some software use encoded PowerShell to avoid detection by AV, IT tools etc, so its not uncommon to see encoded PowerShell across the network, but the parent process of explorer.exe can help narrow this down.


## 3. Execution: Payload download & execution

| Operation                                           | Techniques                                                                                       |
|-----------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Downloaded the payload using mshta, which had overlayed script | T1218.005: System Binary Proxy Execution: Mshta <br> T1027.009: Obfuscated Files or Information: Embedded Payloads |
| Executed the encrypted payload using powershell.exe | T1059.001: Command and Scripting Interpreter: PowerShell <br> T1027.013: Obfuscated Files or Information: Encrypted/Encoded File |
| PowerShell downloaded Lumma Stealer and executed   | T1059.001: Command and Scripting Interpreter: PowerShell   |

* This next query is looking for a PowerShell script running with some of the indicators previously seen by decoding the previous PowerShell script:

    ```sql
    data_stream.dataset: endpoint.events.process and 
        process.name: ("powershell.exe") and 
        process.args : (*System.Net.WebClient* AND *Start-Process*)
    ```

* Potential False Positives:
  * Could be a legitimate admin script, but should be easy to recognise.

* Now, knowing that the script uses `mshta.exe` to download the Lumma malware, we might also be able to search on this process leading to a file creation:

    ```kql

    ```

process.parentname: mshta.exe and action: created and file.type: PE





file.path: Suspicious executables or scripts in:
%TEMP%
%APPDATA%
%PROGRAMDATA%




## 4. Defence Evasion
Some of these initial scripts will clear the clipboard to delete the script:

```
Set-Clipboard
```

And clears the DNS cache

```
Clear-DnsClientCache
```








## 5. Persistence
HKEY_USERS{USER Account HERE}\Software\Microsoft\Windows\CurrentVersion\Run.’ This is one of the most common spots for persistence, as it allows the actor to obtain access to the target endpoint. MITRE ATT&CK T1547.001



## 6. Collection

LummaC2 steals extension data from a variety of Chrome-based browsers including Opera, Brave, Chrome, Chromium, and more. The malware accomplishes this by locating the “Local Extension Settings” for each browser, which stores the internal extension information for many extensions. 

While LummaC2 has a large list of targeted extensions that includes 2FA code managing extensions, through our tests, LummaC2 does not actually extract most 2FA code secrets, as these secrets are not stored in “Local Extension Settings” for Chrome browsers. However, LummaC2 does steal passwords and PII stored in extensions for a wide variety of crypto tools. Additionally, as LummaC2 does programmatically decrypt Chrome’s internal .ldb database storage files, LummaC2 could in the future begin extracting 2FA code secrets that are stored locally on a victim’s device, just like passwords or crypto wallets.

Malware initiates a search for sensitive files and data related to cryptocurrency and password txt files across various directories on the compromised system. It specifically looks for files having keywords that suggest they may hold confidential information, such as *seed*.txt, *pass*.txt, *.kbdx, *ledger*.txt, *trezor*.txt, *metamask*.txt, bitcoin*.txt, *word*, *wallet*.txt

Policy.vpol contains settings and policies related to BitLocker that are managed through Group Policy


```sql
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










process.executable: *\\AppData\\Local\\Temp\\*

process.executable: *\\AppData\\Local\\Temp\\* AND destination.port: (80 OR 443 OR 22 OR 53)

4. Registry Modifications (Event ID: registry_key)
LummaC2 may manipulate browser configurations or disable security features.

Fields to Investigate:
registry.key:
Chrome: HKCU\Software\Google\Chrome\PreferenceMACs
Edge: HKCU\Software\Microsoft\Edge\PreferenceMACs
event.action: modify or create.

## 7. Command and Control

‘POST’ request to ‘vamplersam[.]info,’ where the request is sending data to the endpoint ‘/cfg.’

POST /c2sock

Another common aspect of Lumma is that it uses the User-Agent ‘TeslaBrowser/5.5.’



data_stream.dataset: endpoint.events.network AND dns.question.name: marshal-zhukov.com (match TI)
