# HTB: Nibbles

![Nibbles Header](./assets/nibbles_header.png)

**IP**: 10.129.240.183  
**OS**: Linux  
**Difficulty**: Easy

---

## Quick Summary
The attack path for this machine consists of three primary stages: discovering a hidden directory via source code comments, exploiting a vulnerability in Nibbleblog to gain an initial shell, and escalating privileges to root through a sudo misconfiguration.

* **Foothold**: Nibbleblog 4.0.3 Arbitrary File Upload (CVE-2015-6967)
* **Privilege Escalation**: Sudo NOPASSWD on `monitor.sh`

---

## Kill Chain

### 1. Enumeration
* **Ports**: 22 (SSH), 80 (HTTP).
* **Discovery**: A comment in the web page source code revealed the hidden directory `/nibbleblog/`.
* **Credentials**: The username `admin` was identified via `/content/private/users.xml`, and the password was successfully guessed as `nibbles`.

### 2. Exploitation (Foothold)
A PHP webshell was uploaded by exploiting a vulnerability in the "My Image" plugin:
* **Exploit**: CVE-2015-6967.
* **Payload**: Python3 reverse shell script.
* **Access**: Successfully obtained access as the `nibbler` user.

### 3. Privilege Escalation
* **Vulnerability**: Running `sudo -l` showed that the user `nibbler` could execute `/home/nibbler/personal/stuff/monitor.sh` with root privileges without a password.
* **Method**: The command `chmod 4777 /bin/bash` was written into the script. After executing the script with sudo, root access was obtained using `bash -p`.

---

## Final Result
![Nibbles Pwned](./assets/nibbles_pwned.png)

---

## Project Structure
* `walkthrough.md`: [Detailed step-by-step documentation](./walkthrough.md)
* `scans/`: Original Nmap scan files
* `scripts/`: Exploitation and privilege escalation scripts
* `loot/`: Retrieved files and flags