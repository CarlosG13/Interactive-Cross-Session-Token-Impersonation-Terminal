# Interactive Cross-Session Token Impersonation Terminal

A proof of concept demonstrating a simpler and more evasive method to initiate an interactive terminal with the *Token* of a service account in another session, without being affected by the conditions of GUI interaction across **separate desktops**, or requiring elevated privileges such as **SeTCBPrivilege** or **Desktop APIs** calls to modify desktop *ACL*, which are considerably noisy and detectable.

# Motivation

When it comes to **Privilege Escalation** techniques, **Command and Control (C2) implants**, and **Defense Evasion**, one commonly employed method by adversaries is **Process Injection**, aiming to execute arbitrary code within the address space of a separate live process. Various sub-techniques of process injection, such as *Dynamic-link Library (DLL) Injection*, *Portable Executable Injection*, *Process Hollowing*, among others, are used. However, *EDRs* and *Anti-Malware products*, in general, have significantly evolved over time, making these techniques increasingly complex to deploy for evading detection and achieving our objectives.

##### [Process Injection (T1055)](https://attack.mitre.org/techniques/T1055/).

On the other hand, during an internal penetration test or adversary emulation, it's natural that if, for instance, we observe a process running within the context of a domain user different from ours, we may proceed to target the **LSASS.exe** process to steal their credentials and, consequently, achieve *Privilege Escalation*  and *lateral movement*.

For instance, in the following scenario/test lab, we find ourselves in a domain named **ZeroTrust-Sec.local** with a session initiated on machine *WKSTN-1* as the user *fcastle*. As observed, the domain administrator is running the **wsmprovhost.exe** process. This strongly suggests that we may find credentials of this user in **LSASS**. Why? Kerberos operates as a **Single-Sign-On (SSO)** protocol, caching user credentials in **LSASS** memory. This caching allows users a smoother experience, eliminating the need to provide credentials every time they access a particular resource within the domain.

![image](https://github.com/CarlosG13/Interactive-Cross-Session-Token-Impersonation-Terminal/assets/69405457/d185a37f-3248-45f1-8def-b6f7d9934952)

The issue lies in targeting **LSASS for credential theft**, which holds immense value for adversaries, yet this process is closely monitored and protected. We've witnessed the inception of **Protected Process Light (PPL)** to prevent credential theft from user mode. To circumvent this, a driver installation was introduced, albeit effective, it operates noisily. Additionally, within **Windows Defender Exploit Guard (WDEG)**, there exists **Attack Surface Reduction (ASR)**, which includes a rule that 'prevents' **LSASS** abuse by restricting untrusted processes from obtaining a handle to **LSASS** via the *Win32 OpenProcess* API. Furthermore, most EDR solutions commonly detect the majority of known techniques. Drawing from my experience in evading defenses across different scenarios and products, we'll explore a method to 'steal' a user's identity without the necessity of attacking **LSASS** or injecting into the target process in question.

##### [About Protected Process Light (PPL) technology for Windows](https://support.kaspersky.com/common/windows/13905).
##### [Attack surface reduction rules overview](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide).

We'll be *stealing a user's Token for this purpose*. However, we'll notice that this technique, depending on our scenario and desired execution, *has its limitations*. **We'll explore how to surpass these limitations to evade defenses.**

# What's an Access Token?

According to **Microsoft**: *"An access token is an object that defines the security context of a process or thread. It contains information about the identity and privileges of the user account linked to the process or thread. During user login, the system authenticates the user's password by comparing it with data stored in a security database. Upon successful authentication, the system generates an access token. Each process executed on behalf of this user possesses a copy of this access token."*

In essence, a **Token** is a *securable object* in Windows that encapsulates information regarding the privileges (the scope and/or capabilities a user has over the operating system and the *securable objects* therein), user permissions, and the user's associated groups. Additionally, every process created on behalf of the user will contain a copy of the access token. This aspect can be better understood and observed using the *SysInternals*' *Process Explorer* utility:

![image](https://github.com/CarlosG13/Interactive-Cross-Session-Token-Impersonation-Terminal/assets/69405457/58457117-22a5-407d-a81f-21494f3a8651)

Taking the **notepad.exe** process as an example, we can observe pertinent information contained within the *Token* assigned to this process: user SID, associated groups, Session ID, and its privileges.

Thus, from an offensive standpoint, what if an adversary manages to steal the **Access Token** of the user *'rtop1\cgarrido'*? They could potentially assume this user's identity and carry out subsequent actions on behalf of the compromised user!

##### [Microsoft Official Documentation: Access Tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens).

##### [Access Token Manipulation (T1134)](https://attack.mitre.org/techniques/T1134/).

# Access Token Manipulation

To execute this technique, we can leverage Windows APIs. Essentially, we'll need: **OpenProcess()** to obtain a handle to the target process, **OpenProcessToken()** to acquire a handle of the *primary access token*, followed by **DuplicateTokenEx()** to duplicate the target *Token*. Finally, **CreateProcessWithTokenW()** to create an arbitrary process, specifying the **Stolen Token** as a parameter.

### OpenProcess:

```cp
HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwProcessId
);
```

### OpenProcessToken:

```cp
BOOL OpenProcessToken(
  [in]  HANDLE  ProcessHandle,
  [in]  DWORD   DesiredAccess,
  [out] PHANDLE TokenHandle
);
```

### DuplicateTokenEx:

```cp
BOOL DuplicateTokenEx(
  [in]           HANDLE                       hExistingToken,
  [in]           DWORD                        dwDesiredAccess,
  [in, optional] LPSECURITY_ATTRIBUTES        lpTokenAttributes,
  [in]           SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
  [in]           TOKEN_TYPE                   TokenType,
  [out]          PHANDLE                      phNewToken
);
```

### CreateProcessWithTokenW:

```cp
BOOL CreateProcessWithTokenW(
  [in]                HANDLE                hToken,
  [in]                DWORD                 dwLogonFlags,
  [in, optional]      LPCWSTR               lpApplicationName,
  [in, out, optional] LPWSTR                lpCommandLine,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCWSTR               lpCurrentDirectory,
  [in]                LPSTARTUPINFOW        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
```

By launching our proof of concept (malicious artifact) against a user within the **same session as ours**, and **possessing local administrator privileges**, we can steal a user's *Token* and create a new process:

  - **Current User:** ZeroTrust-Sec.local\fcastle (Local Administrator)
  - **Target User:** TokenUser
  - **Target Process:** cmd.exe (PID: 6572)

As depicted in the following figure, we successfully acquired the identity of the user **TokenUser** by stealing the Command Prompt's **Access Token** and create a new instance of **cmd.exe** under that user's context:

![image](https://github.com/CarlosG13/Interactive-Cross-Session-Token-Impersonation-Terminal/assets/69405457/57cda6ef-e88c-4ee5-beb6-ec164dd53062)

##### **Although our technique worked seamlessly, there's a crucial question we must address: What happens if we attempt to steal the Token of a user in a different session than ours?**

# Addressing the Access Token Manipulation Across Session IDs Issue Pt.1

On the Windows OS, a session encompasses all system securable objects and processes linked to a user's logon session. When your computer boots up, the first session that launches is termed **session 0**, housing all initiated services . As additional users connect to the system, they obtain their unique sessions. The initial logged-in user is designated as **session number 1 (ZeroTrust-Sec.local\fcastle)**, the subsequent user becomes **session number 2**, and so forth.

What happens if we try to steal the *Token* of a process located in a session different from ours? For example, what if we attempt to steal the Token of the user **ZeroTrust-Sec.local\Administrator** (The process *wsmprovhost.exe* is in **session 0**)?

![image](https://github.com/CarlosG13/Interactive-Cross-Session-Token-Impersonation-Terminal/assets/69405457/d188b794-2bcf-4ec3-aab6-ce5750585e69)

 - **Current User:** ZeroTrust-Sec.local\fcastle
 - **Target User:** ZeroTrust-Sec.local\Administrator
 - **Target Process:** wsmprovhost.exe (PID: 6948)

As observed in the following illustration, the spawned **cmd.exe** process exhibits a *disrupted GUI*. Proper interaction with the handles *(StdIn, StdOut, and StdErr)* of the new process as **ZeroTrust-Sec.local\Administrator** is unattainable. This is due to the *Token* having a **Session ID** that differs from our current session.

![image](https://github.com/CarlosG13/Interactive-Cross-Session-Token-Impersonation-Terminal/assets/69405457/a19c4fd3-5393-420a-81ac-aba4db4e9fa3)

According to the following representation of an **Access Token** structure, *Tokens* contain a field known as the *TS Session ID*:

The *TS Session ID* is a value that indicates whether the **Access Token** is associated with the Terminal Services client session. This value is the root of our problem, as **CreateProcessWithTokenW** takes it into account when creating a graphical process.

![cc783557 4bbb6bff-2431-4d8a-b9f6-d03a28a0c615(ws 10)](https://github.com/CarlosG13/Interactive-Cross-Session-Token-Impersonation-Terminal/assets/69405457/2f424f19-7083-4d2a-a1e7-80f1e2c4f2e7)
##### [Image retrieved from How Access Tokens Work](https://learn.microsoft.com/pt-pt/previous-versions/windows/server/cc783557(v=ws.10)?redirectedfrom=MSDN)

# Addressing the Access Token Manipulation Across Session IDs Issue Pt.2

Based on my research and testing, I've identified two potential solutions to the previously explained issue: 

  1. Acquiring the **SeTCBPrivilege** privilege (exclusive to *NT Authority\System*) and invoking the **CreateProcessAsUser()** API. Therefore, executing this scenario requires first escalating to **NT Authority\System**.

     - References:
       
       [Microsoft Documentation: CreateProcessAsUser](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera).
       
       [Abusing Windows’ tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/).
  
 2. Altering the *ACL* of our Desktop **("winsta0\default")** by adding an *ACE* granting **'Full Control'** permissions to the **'Everyone'** group.

    - References:
      
      [PowerShell and Token Impersonation](https://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/).

Both approaches are viable, yet the issue with the *first solution* lies in the additional step required: escalating to **NT Authority\System**. Consequently, this could potentially raise alarms with an *EDR* system, leading to detection and thwarting of our operations. Essentially, when an untrusted process elevates to **NT Authority\System**, it raises suspicion and warrants investigation. In my experience, *EDRs* such as **CrowdStrike Falcon** and **Sentinel One** would likely trigger an alert in this scenario.

Regarding the *second approach*, modifying a system object, namely our desktop, could indeed raise suspicion and potentially lead to imminent detection by an *EDR*. Moreover, we would need to take additional steps, such as invoking the **AdjustTokenPrivileges()** Win32 API, as it's mandatory to enable the *SeSecurityPrivilege* privilege if we opt for this route. Consequently, this would raise the level of suspicion regarding our activities and the artifact itself.

Next, we'll explore a simpler alternative to continue leveraging the benefits of **CreateProcessWithTokenW()** for creating a graphical process by stealing the *Token* of a process from a different session, without the need to elevate to **NT Authority\System** or modify the *ACL* of the desktop associated with our current session.

# Addressing the Access Token Manipulation Across Session IDs Issue Pt.3

The proposed solution involves using **anonymous pipes** and creating a new console. Essentially, we can have a *console-less application (GUI App)* that, upon calling **AllocConsole()** Win32 API, creates a new console. Subsequently, we create the pipes using **CreatePipe()** Win32 API and use the handles *(StdIn, StdOut, StdErr)* as values for the *hStdInput, hStdOutput, hStdError* parameters in the **STARTUPINFO** structure of the spawned (Child) process and set the *CREATE_NO_WINDOW* flag in the *dwCreationFlags*  of **CreateProcessWithTokenW()**. Finally, we'll invoke **ReadFile()** and **CreateFile()** to *read* from and *write* to *StdIn* and *StdOut*, respectively.

 - **Note:** while *GUI* isn't mandatory for our technique, *GUI* applications can camouflage malicious activities, making it harder for security tools to differentiate between legitimate user interactions and malicious actions. Additionally, if we choose the approach of creating a console-based artifact, there's no need to call **AllocConsole()**, as we'll already have one in place.

* Testing Our Artifacts - (Console App):
  
![image](https://github.com/CarlosG13/Interactive-Cross-Session-Token-Impersonation-Terminal/assets/69405457/5287d136-5826-46ad-a486-cdd5a869edc7)


* Testing Our Artifacts - (GUI App):

  
   ![image](https://github.com/CarlosG13/Interactive-Cross-Session-Token-Impersonation-Terminal/assets/69405457/0b8e4a68-78b0-4836-a128-cfea25e62e9d)


This new approach in the **Access Token Manipulation** technique eliminates the need to escalate to **NT Authority\System** or modify our **desktop's ACL**, thereby reducing our chances of detection or raising suspicions.
This artifact underwent testing against one of the leading *EDR* solutions in the industry, successfully evading detection.
