

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


#  Standardized Column Names
STANDARD_COLUMNS = [
    "timestamp", "log_type", "source_ip", "destination_ip", "action",
    "user", "protocol", "port", "threat_name", "ttp_detected"
]
