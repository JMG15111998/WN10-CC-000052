# WN10-CC-000052

# 🛡️ Vulnerability Management Lab – WN10-CC-000052

**Control Title:** Prioritize ECC Curves with Longer Key Lengths First  
**STIG ID:** WN10-CC-000052  
**Compliance Frameworks:** DISA STIG, NIST 800-53 (SC-12), FIPS 140-2  
**Lab Stack:** Azure + Windows 10 + Tenable.sc/Nessus + PowerShell  
**Category:** Cryptographic Protocol Hardening  
**Remediation Method:** SCHANNEL Cipher Suite Registry Configuration

---

## 🎯 Lab Objective

Demonstrate how to simulate, detect, and remediate a vulnerability where **cryptographic cipher suites** are not properly prioritized to favor modern ECC algorithms, specifically those with **longer key lengths** for improved security.

---

## 📑 Table of Contents

1. [Azure VM Setup](#azure-vm-setup)  
2. [Vulnerability Implementation](#vulnerability-implementation)  
3. [Tenable Scan Configuration](#tenable-scan-configuration)  
4. [Initial Scan Results](#initial-scan-results)  
5. [Remediation via PowerShell](#remediation-via-powershell)  
6. [Verification Steps](#verification-steps)  
7. [Security Rationale](#security-rationale)  
8. [Post-Lab Cleanup](#post-lab-cleanup)  
9. [Appendix: PowerShell Commands](#appendix-powershell-commands)

---

## ☁️ Azure VM Setup

### 🔸 Parameters

| Setting              | Value                         |
|----------------------|-------------------------------|
| OS Image             | Windows 10 Pro (x64, Gen2)    |
| VM Size              | Standard D2s v3               |
| Resource Group       | `vm-lab-eccpriority`          |
| Region               | Closest Azure region          |
| Admin Username       | Use strong password (avoid `labuser/Cyberlab123!`) |

### 🔸 Network Security Group (NSG)

- Allow **RDP (TCP 3389)** from your IP
- Optionally allow **WinRM (TCP 5985)** for Tenable scanning
- Block all other unnecessary inbound traffic

---

## 🔧 VM Configuration

### 🔹 Disable Windows Firewall

- Run `wf.msc` → Disable Domain, Private, and Public profiles

### 🔹 Enable Remote Access for Credentialed Scanning

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord -Force
```

📸 **Screenshot Placeholder:** `Screenshot_01_VM_Config_ECC.png`

---

## 💥 Vulnerability Implementation

### 🔸 Description

To simulate this vulnerability, you must remove or reorder ECC cipher suite priorities so that **less secure or legacy ciphers** are favored during TLS negotiation.

### 🔸 Simulate Non-Compliant State

```powershell
# Simulate vulnerable cipher suite order
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites" `
  -Name "Priority" `
  -Value "RC4-SHA:DES-CBC3-SHA:AES128-SHA"
```

📸 **Screenshot Placeholder:** `Screenshot_02_ECC_Vulnerable_Cipher_Suite.png`

---

## 🔍 Tenable Scan Configuration

### Template: **Advanced Network Scan**  
Audit File: **DISA Microsoft Windows 10 STIG**

### 🔹 Required Services

- Remote Registry
- Admin Shares (C$)
- Server Service

### 🔹 Discovery Settings

- Ping remote host
- TCP full port scan
- Windows authentication (local admin)

📸 **Screenshot Placeholder:** `Screenshot_03_Tenable_Scan_ECC.png`

---

## 🧪 Initial Scan Results

| STIG ID         | WN10-CC-000052 |
|------------------|----------------|
| Status           | ❌ Fail        |
| Plugin Output    | ECC cipher suite prioritization is incorrect |
| Detected Value   | RC4-SHA:DES-CBC3-SHA:AES128-SHA |
| Required Value   | `ECDHE-ECDSA-AES256-GCM-SHA384:...` |

📸 **Screenshot Placeholder:** `Screenshot_04_Scan_Results_ECC_FAIL.png`

---

## 🛠️ Remediation via PowerShell

### 🔸 Secure Cipher Suite Order

```powershell
# Enforce prioritized ECC cipher suite ordering
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites" `
  -Name "Priority" `
  -Value "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
```

📸 **Screenshot Placeholder:** `Screenshot_05_ECC_Remediation_Registry.png`

---

## ✅ Verification Steps

### 1. Check Registry Value

```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites" `
  -Name "Priority"
```

**Expected Output:**

```text
Priority : ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
```

📸 **Screenshot Placeholder:** `Screenshot_06_Verify_ECC_OK.png`

### 2. Restart System or Affected Services

```powershell
Restart-Computer
```

📌 You may also need to restart **Schannel-related services** or initiate a manual policy refresh.

### 3. Re-Run Tenable Scan

| STIG ID         | Result |
|------------------|--------|
| WN10-CC-000052   | ✅ Pass |

📸 **Screenshot Placeholder:** `Screenshot_07_Scan_Results_ECC_PASS.png`

---

## 🔐 Security Rationale

Modern ECC (Elliptic Curve Cryptography) cipher suites provide **higher levels of security** and **better performance** than legacy ciphers like RC4 or DES. Prioritizing longer ECC curves:

- Ensures **forward secrecy**
- Aligns with **TLS 1.2/1.3 best practices**
- Minimizes risk from known cryptographic attacks

### 🔒 Compliance Requirements

| Standard        | Control ID                   |
|-----------------|------------------------------|
| **DISA STIG**   | WN10-CC-000052               |
| **NIST 800-53** | SC-12, SC-13, SC-28          |
| **FIPS 140-2**  | Approved Cryptographic Methods |
| **PCI DSS**     | Req 4.1 (Strong Encryption)  |

---

## 🧼 Post-Lab Cleanup

1. Restart VM to apply cryptographic settings.
2. Document results in vulnerability management system.
3. Delete resource group for cleanup:

```bash
az group delete --name vm-lab-eccpriority --yes --no-wait
```

---

## 📎 Appendix: PowerShell Commands

| Task                  | Command |
|-----------------------|---------|
| Simulate Vulnerability| `Set-ItemProperty ... -Value "RC4-SHA:..."` |
| Remediate             | `Set-ItemProperty ... -Value "ECDHE-ECDSA-..."` |
| Verify                | `Get-ItemProperty ... CipherSuites` |
| Enable Remote Access  | `Set-ItemProperty ... LocalAccountTokenFilterPolicy -Value 1` |

---

✅ **Lab Complete**

You've now successfully simulated, detected, and remediated **improper ECC cipher suite ordering** in compliance with `WN10-CC-000052` using Azure-based infrastructure and Tenable authenticated scanning.

