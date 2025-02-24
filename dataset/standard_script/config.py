

MITRE_SIGNATURE_MAPPING = {
    "T1082": r".*Windows user enumeration.*",
    "T1016": r".*TLS Encrypted Client Hello.*",
    "T1018": r".*ddns:dyndns.org.*",
    "T1059.003": r".*PowerShell Script File.*|.*CMD Windows Script File.*",
    "T1218.011": r".*LNK File.*",
    "T1027.005": r".*VBScript Obfuscation.*",
    "T1078.002": r".*Microsoft Windows NTLMSSP Detection.*",
    "T1555": r".*Windows Local Security Architect lsardelete.*",
    "T1036.005": r".*Certificate Revocation List File.*",
    "T1140": r".*DER Encoded X509 Certificate.*",
    "T1071.001": r".*Suspicious HTTP Evasion.*",
    "T1572": r".*Suspicious TLS Evasion.*",
    "T1047": r".*Microsoft Windows user enumeration.*",
    "T1041": r".*Unknown Binary File.*|.*Microsoft PE File.*",
    "T1567": r".*Suspicious HTTP Evasion.*",
    "T1486": r".*Microsoft Cabinet \(CAB\).*",
}

MITRE_MAPPING = {
    "T1219": r"ScreenConnect\.exe|screenconnect\.com",
    "T1027.003": r"powershell.*-enc|base64",
    "T1059.003": r"powershell.*-nop|-exec bypass",
    "T1047": r"wmic.*process call create",
    "T1072": r"vnc|Invoke-Vnc",
    "T1036.005": r"\.scr|\.bat|\.ps1",
    "T1140": r"certutil.*decode|certutil.*encode",
    "T1027": r"powershell.*-encodedcommand",
    "T1082": r"whoami|hostname|systeminfo",
    "T1016": r"ipconfig|ifconfig|netstat",
    "T1018": r"Advanced IP Scanner|nmap|ping .* -t",
    "T1007": r"Get-WmiObject|wmic product get",
    "T1083": r"dir .*C:\\Users|dir .*home",
    "T1012": r"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Winlogon",
    "T1003.001": r"mimikatz|lsass.exe|sekurlsa",
    "T1555": r"vaultcmd|Credential Manager",
    "T1555.003": r"Windows Vault|Internet Explorer Saved Credentials",
    "T1078.003": r"add user.*Remote Desktop Users",
    "T1055.001": r"rundll32\.exe.*\.dll",
    "T1074.001": r"compress.*\.zip|zip .* -r",
    "T1041": r"Set-Cookie:.*[A-Za-z0-9+/=]{50,}",
    "T1048.002": r"psftp|putty|scp .* -P",
    "T1567": r"POST /upload.* HTTP",
    "T1132.001": r"Base64 encoded DNS queries",
    "T1105": r"Invoke-WebRequest|certutil.*http",
    "T1102": r"github.com/.* | pastebin.com/.*",
    "T1486": r"vssadmin delete shadows|cipher /w",
    "T1489": r"net stop .*|taskkill /F /IM",
}

# MITRE ATT&CK Mapping for Email Threats
MITRE_MAIL_MAPPING = {
    # **Credential Access**
    "T1003.001": r"NTLM|basic auth|credential theft|password dump",  # Windows Credential Editor: Dump Credentials
    "T1012": r"winlogon|registry|stored credentials|HKEY_LOCAL_MACHINE",  # Checking Credentials in Winlogon Registry Key
    "T1555": r"credential manager|vaultcmd|password|account compromised",  # Enumerating Credentials in Credential Manager
    "T1555.003": r"web credentials|vault|Internet Explorer",  # Web Credentials in Windows Vault

    # **Data Exfiltration**
    "T1041": r"exfiltration|data theft|leakage|Set-Cookie:.*[A-Za-z0-9+/=]{50,}|http.*cookie",  # HTTP Exfiltration via Cookie
    "T1048.002": r"psftp|putty|scp .* -P",  # Exfiltration Using PSFTP
    "T1567": r"threatUrl|url.*exe|url.*zip|POST /upload.* HTTP|POST.*HTTP|HTTP Data Exfiltration",  # HTTP Data Exfiltration from Email
    "T1567.001": r"git.*commit|git.*push",
    "T1074.001": r"compress.*zip|zip.*-r",

    # **Execution**
    "T1105": r"Invoke-WebRequest|certutil.*http|WMIC|malware download|file dropper",  # Downloader: Invoke-WebRequest
    "T1102": r"github|pastebin|anonymous upload|external tool",  # Remote Tool Usage (Web Service)
    "T1027.003": r"powershell.*-enc|base64|Steganography|encoded command",  # PowerShell Script Using Steganography
    "T1027": r"base64|encodedcommand|encrypted payload",  # Base64-Encoded Commands
    "T1140": r"certutil.*decode|encode|obfuscation|certutil.*encode",  # File Encoding and Decoding with CertUtil
    "T1036.005": r"\.scr|\.bat|\.ps1|fake attachment",  # Masquerading as Legitimate File
    
    # **Discovery & Lateral Movement**
    "T1082": r"hostname|systeminfo|system information|domain discovery",  # System Information Discovery
    "T1016": r"ipconfig|ifconfig|netstat|network configuration",  # System Network Configuration Discovery
    "T1018": r"Advanced IP Scanner|nmap|ping .* -t",  # Network Scanning (IP Discovery)
    "T1072": r"vnc|Invoke-Vnc|remote desktop",  # PowerShell VNC Injector
    "T1059.003": r"powershell|cmd|shell command",  # Invoking PowerShell Commands
    "T1047": r"wmic.*create|WMI execution",  # WMI Execution
    "T1055.001": r"rundll32\.exe.*\.dll|dll injection",  # DLL Injection for Process Injection
    "T1078.003": r"add user.*Remote Desktop Users|admin account created",  # Adding User to Remote Desktop Users Group
    "T1007": r"Get-WmiObject|wmic product get",

    # **Defense Evasion**
    "T1562.001": r"tls_verify.*FAIL|verify.*NONE|verify.*FAIL|tls encryption disabled",  # TLS Encryption Bypass
    "T1071.001": r"web beacon|hidden image|HTTP C2|relay|proxy|external relay",  # HTTP C2 Communication via Email
    "T1036.005": r"attachment.*js|attachment.*vbs|attachment.*cmd",  # Masquerading as Legitimate File (Email Attachment)
    "T1083": r"dir.*Users|dir.*home|file discovery|dir command|file and directory listing",  # File and Directory Discovery with `dir`
    "T1202": r"encrypted|cipher|base64|XOR",  # Obfuscation Using Encrypted Content

    # **Impact (Ransomware)**
    "T1486": r"vssadmin delete shadows|cipher /w|CymRansom|ransomware|encrypt|vssadmin delete shadows",  # Encrypting Files (Ransomware)
    "T1489": r"net stop.*|taskkill.*|Stop Service|service stop|disable security",  # Stopping Security Services
    "T1560": r"zip|archive|compress",

    # **Network-Based Indicators**
    "T1572": r"dns tunneling|dns over https|doh",  # DNS Tunneling
    "T1132.001": r"Base64 encoded DNS queries",  # DNS Exfiltration Using Base64

    # **Phishing & Social Engineering**
    "T1566.001": r"phish|phishing|spoof|deceptive",  # Spear Phishing Email
    "T1566.002": r"malicious attachment|attachment.*exe|attachment.*zip",  # Phishing via Malicious Attachment
    "T1204.002": r"link|threatUrl|url|click here|credential harvesting",  # Malicious Link in Email (URL Defense)
    "T1566": r"quarantineRule.*phish|quarantineFolder.*Phish",  # Generic Phishing Detection
    "T1567.002": r"attachment.*exe|attachment.*zip|attachment.*rar",  # Malware via Attachment

}

MITRE_PROXY_MAPPING = {
    #  Execution Techniques
    "T1219": r"ScreenConnect|remote access|screenconnect\.com",  # Remote Access Tool Detected
    "T1027.003": r"powershell.*-enc|base64|encoded|obfuscate",  # PowerShell Script Using Steganography
    "T1059.003": r"powershell|cmd|wscript",  # Raw Command Execution via Proxy

    #  Defense Evasion
    "T1036.005": r"\.exe|\.bat|\.cmd|\.scr|\.ps1|masquerade",  # Masquerading as Legitimate Files
    "T1140": r"certutil.*decode|certutil.*encode",  # CertUtil for File Encoding/Decoding
    "T1027": r"base64|encode|obfuscate",  # Encoding or Obfuscation

    #  Discovery Techniques
    "T1082": r"whoami|systeminfo|domain discovery",  # System Information Discovery
    "T1016": r"ipconfig|ifconfig|netstat|System Network Configuration Discovery",  # Network Configuration Discovery
    "T1018": r"Advanced IP Scanner|nmap|ping .* -t|scanner|network scan",  # IP Scanning Using Proxy

    #  Credential Access
    "T1012": r"winlogon|registry|Winlogon",  # Checking Credentials Stored in Registry
    "T1003.001": r"mimikatz|lsass\.exe|sekurlsa|Credential Dumping",  # Credential Dumping via Proxy
    "T1555": r"vaultcmd|Credential Manager",  # Extracting Credentials from Credential Manager
    "T1555.003": r"Windows Vault|Internet Explorer Saved Credentials|Web Credentials",  # Extracting Web Credentials

    #  Lateral Movement & Persistence
    "T1078.003": r"add user.*Remote Desktop Users|RDP|Remote Access",  # Adding User for Remote Access
    "T1055.001": r"rundll32\.exe.*\.dll|DLL Injection",  # DLL Injection via Proxy
    "T1072": r"vnc|Invoke-Vnc|remote control",  # PowerShell VNC Injector for Remote Access

    #  Exfiltration & Command-and-Control (C2)
    "T1041": r"\bSet-Cookie:.*[A-Za-z0-9+/=]{50,}|HTTP Data Exfiltration\b|exfiltration",  # HTTP Data Exfiltration
    "T1567": r"POST /upload.* HTTP|HTTP File Upload|upload",  # File Upload via HTTP
    "T1105": r"Invoke-WebRequest|certutil.*http|download",  # File Download Using Proxy
    "T1102": r"github\.com|pastebin\.com|anonymous|external tool",  # Use of External Services via Proxy
    "T1132.001": r"Base64 encoded DNS queries|DNS Exfiltration|dns tunneling",  # DNS Exfiltration Using Proxy
    "T1048.002": r"\bpsftp|scp|putty\b|Exfiltration Using PSFTP",  # Exfiltration Using PSFTP or SCP

    #  Ransomware & Impact Techniques
    "T1486": r"vssadmin delete shadows|cipher /w|ransomware|encrypt",  # File Encryption by Ransomware
    "T1489": r"\bnet stop|taskkill /F /IM\b|Stop Service",  # Service Termination or Disabling Security

    # Network Infrastructure & Proxy Behavior
    "T1071": r"network communication",  # Proxy Usage for Network Communication
    "T1572": r"doh|dns over https|DNS Tunneling|dns tunneling",  # DNS Tunneling via Proxy
}

MITRE_XDR_MAPPING = {
    "T1219": r"ScreenConnect|remote access",
    "T1027.003": r"powershell.*base64|encoded",
    "T1036.005": r"\.exe|\.bat|\.cmd|masquerade",
    "T1082": r"whoami|hostname|systeminfo",
    "T1016": r"ipconfig|netstat|ifconfig",
    "T1059.003": r"powershell|cmd",
    "T1055.001": r"rundll32|dll injection",
    "T1078.003": r"add user|remote desktop",
    "T1012": r"winlogon|registry",
    "T1555": r"credential manager|vaultcmd",
    "T1041": r"exfiltration|http|dns",
    "T1105": r"invoke-webrequest|download",
    "T1102": r"pastebin|github",
    "T1027": r"base64|encode",
    "T1140": r"certutil|decode",
    "T1018": r"scanner|nmap|ping",
    "T1047": r"wmic|process",
    "T1072": r"vnc|remote",
    "T1083": r"dir|file|explore",
    "T1003.001": r"mimikatz|dump",
    "T1555.003": r"vault|credentials",
    "T1486": r"ransomware|encrypt",
    "T1489": r"net stop|taskkill",
}


#  Standardized Column Names
STANDARD_COLUMNS = [
    "timestamp", "log_type", "source_ip", "destination_ip", "action",
    "user", "protocol", "port", "threat_name", "ttp_detected"
]
