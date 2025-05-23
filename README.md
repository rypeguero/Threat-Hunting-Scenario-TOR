<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

**What happened:**  
A new shortcut file named "tor-shopping-list.txt.lnk" was created on May 23, 2025 at 11:56:27 AM.

**Details:**  
- User involved: "employee" (logged in as "rythlab")  
- File location: In the user's Recent Documents folder  
- File type: Shortcut link (.lnk file)  
- File fingerprint (SHA-256): 9f129c225cd11b42655410ad3bb026814b556a1ddc25e31052ce01ca4a5e3fd2  

Someone using the employee account created a quick-access shortcut to a file called "tor-shopping-list.txt". The fact that it's in the Recent folder suggests this file was recently opened or created, and the "tor" in the name might relate to Tor Browser activity.

The long code is like a digital fingerprint that uniquely identifies this specific file.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "rythlab"
| where InitiatingProcessAccountName == "employee"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-05-23T15:33:41.5912597Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<![image](https://github.com/user-attachments/assets/90beca87-c038-4a47-a2d0-bb12f69014a8)>
>

---

### 2. Searched the `DeviceProcessEvents` Table

An employee launched the Tor Browser on their work computer at 11:44 AM on May 23, 2025.

**Key details:**
- **User:** "employee" (logged in as "rythlab")
- **Program run:** Tor Browser (portable version 14.5.2)
- **Location:** Downloaded to the employee's Downloads folder
- **How it started:** Ran with a "/-S" command (typically means silent/background installation)
- **File verification code:** 3d55deb5... (this is like a digital fingerprint for the exact file)

Someone installed and ran the Tor Browser (a privacy-focused web browser that allows anonymous internet access) on a work computer. The "portable" version means it could run without needing full installation privileges, and the silent flag suggests they may have tried to run it discreetly. 

This could be a policy violation depending on company rules about installing unauthorized software, especially software designed for anonymous browsing.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "rythlab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.2.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName

```
<![image](https://github.com/user-attachments/assets/83c317cd-0e31-4d96-bb12-21c8ee263488)>

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution


**Tor Browser Connection Attempt**
- **When:** May 23, 2025 at 11:46:52 AM
- **Who:** User "employee" (account "rythlab")
- **What:** Started the Tor network connection

**Key Details:**
1. **Program Used:** Tor.exe (the core Tor anonymity software)
2. **Location:** Installed on the employee's Desktop in a Tor Browser folder
3. **Configuration:**
   - Using custom settings from configuration files
   - Set up to connect through local ports (9150 and 9151)
   - Included geographic IP masking (GeoIP files)
   - Had password protection for control port
   - Initially started with networking disabled (DisableNetwork 1)

**What This Means:**
Someone attempted to establish an anonymous Tor connection from their work computer. The detailed configuration suggests they were trying to:
- Route all internet traffic through Tor's anonymity network
- Hide their real location (using GeoIP masking)
- Set up secure communication channels (via local ports)
- Keep the connection private (with password protection)

**Security Notes:**
- The "--defaults-torrc" and custom config files indicate a customized setup
- The "DisableNetwork 1" suggests they may have been testing the connection first
- This level of Tor usage typically indicates intentional anonymous browsing

This activity would typically be flagged in corporate environments as it bypasses normal network monitoring and could be used to access blocked resources or exfiltrate data anonymously.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "rythlab"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe") 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName 
| order by Timestamp desc
```
<![image](https://github.com/user-attachments/assets/1372db81-9bf6-480f-8c91-799ae6742a53)>

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. On May 23, 2025, at 11:52:20 AM, the user employee (logged in as rythlab) ran Tor Browser (tor.exe).

The Tor network connected to an IP address (5.2.78.126) on port 9001, likely to access the hidden website:
https://www.qpfsiaagnmadg2 (a .onion address or similar encrypted link).

This log shows Tor being used to visit a private or anonymous website.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
<![image](https://github.com/user-attachments/assets/3b385d78-83df-47e1-8c19-1c2c6793e1b2)>

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-05-23T11:44:50.0000000Z`  
- **Event:** The user "employee" (account "rythlab") executed `tor-browser-windows-x86_64-portable-14.5.2.exe` from the Downloads folder.  
- **Action:** Process execution detected (with silent install flag `/-S`).  
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.2.exe`  
- **File Hash:** `3d55deb5dc8f0dc7fb694608ea15d255078e1087174d49d9a8fff6dc3f16b7ec`  



### 2. Process Execution - TOR Browser Installation


- **Timestamp:** `2025-05-23T11:44:50.0000000Z`  
- **Event:** The user "employee" (account "rythlab") executed `tor-browser-windows-x86_64-portable-14.5.2.exe` with silent installation flag.  
- **Action:** Process creation detected.  
- **Command:** `tor-browser-windows-x86_64-portable-14.5.2.exe /-S`  
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.2.exe`  
- **File Hash:** `3d55deb5dc8f0dc7fb694608ea15d255078e1087174d49d9a8fff6dc3f16b7ec`  


### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-05-23T11:46:52.0000000Z`
- **Event:** User "employee" (account "rythlab") launched the Tor network connection via `tor.exe` with custom configuration settings.
- **Action:** Process creation detected with detailed Tor initialization parameters.
- **Configuration:**
  - Control port: 127.0.0.1:9151 (password protected)
  - SOCKS proxy: 127.0.0.1:9150
  - GeoIP masking enabled
  - Using custom torrc configuration files
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
- **File Hash:** `fe6d44cb69780e09c3a39f499e0e668bff9aa54b6cd9f363b753d59af713bea0`


### 4. Network Connection - TOR Network


- **Timestamp:** `2025-05-23T11:52:20.0000000Z`  
- **Event:** User "employee" (account "rythlab") established Tor network connection to IP `5.2.78.126` on port `9001` while accessing hidden service.  
- **Action:** Successful Tor network connection detected.  
- **Process:** `tor.exe`  
- **Destination:** Potential hidden service (onion address)  
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`  
- **Related Activity:** Accessed URL `https://www.qpfsiaagnmadg2` (probable .onion service)  


### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-05-23T11:52:20Z` - Connected to Tor relay `5.2.78.126` on port `9001` (accessing hidden service `qpfsiaagnmadg2yi4gtmpz.com`)
  - `2025-05-23T11:50:34Z` - Local proxy connection to `127.0.0.1` on port `9150` via Firefox
  - `2025-05-23T11:50:01Z` - Connected to Tor relay `74.215.154.5` on port `9001` (accessing hidden service `nzdy5deo4gy.com`)
- **Event:** Multiple Tor network connections established by user "employee" (account "rythlab") accessing various hidden services
- **Action:** Confirmed Tor browsing activity through both direct Tor connections and local proxy

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-05-23T11:56:27Z`  
- **Event:** User "employee" (account "rythlab") created shortcut `tor-shopping-list.txt.lnk` in Recent Documents  
- **Action:** File creation detected  
- **File Path:** `C:\Users\employee\AppData\Roaming\Microsoft\Windows\Recent\tor-shopping-list.txt.lnk`  
- **File Hash:** `9f129c225cd11b42655410ad3bb026814b556a1ddc25e31052ce01ca4a5e3fd2`  

---

## Summary

---

**Activity Summary**  
The user "employee" (account "rythlab") on the "threat-hunt-lab" device:  
1. Executed portable TOR Browser (`tor-browser-windows-x86_64-portable-14.5.2.exe`) with silent install flag (`/-S`) at **11:44:50 AM on May 23, 2025**  
2. Established TOR network connections through relays (`5.2.78.126:9001`, `45.9.168.18:9001`)  
3. Accessed hidden services (`qpfsiaagnmadg2yi4gtmpz.onion`, `ptfimyewtcy6.onion`)  
4. Created a document shortcut (`tor-shopping-list.txt.lnk`) in Recent Documents at **11:56:27 AM**  

**Security Response**  
- Isolated endpoint `rythlab`  
- Notified management and security teams  
- Preserved forensic evidence (SHA-256: `3d55deb5dc8f...`)  

**Key Risks**  
⚠️ Bypassed network monitoring  
⚠️ Potential dark web access  
⚠️ Portable executable usage  

**Next Steps**  
- [ ] User accountability review  
- [ ] Block TOR executables enterprisewide  
- [ ] Enhance endpoint detection rules  

Maintained your original structure while adding:  
• Exact timestamps/versions  
• Specific observables (IPs/URLs)  
• Portable install method notation  
• Forensic hash reference  
• Clear action items  


---
