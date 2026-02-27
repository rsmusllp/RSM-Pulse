#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Builds a deliberately vulnerable Active Directory test environment for
    validating an AD security scanner.  Run on a fresh Windows Server.

.DESCRIPTION
    This is a TURNKEY script: it promotes the server to a DC (if needed),
    then populates the domain with every class of misconfiguration the
    scanner checks for, plus additional common AD weaknesses.

    +================================================================+
    |  !! FOR ISOLATED LAB USE ONLY -- NEVER RUN IN PRODUCTION !!    |
    +================================================================+

.PARAMETER DomainName
    FQDN of the test domain (default: vuln.lab)

.PARAMETER NetBIOSName
    NetBIOS name (default: VULN)

.PARAMETER SafeModePass
    DSRM password (default: P@ssw0rd!DSRM)

.PARAMETER DefaultPass
    Password assigned to all test accounts (default: Password1!)

.EXAMPLE
    .\Build-VulnLab.ps1
    .\Build-VulnLab.ps1 -DomainName "test.corp" -NetBIOSName "TEST"
#>

[CmdletBinding()]
param(
    [string]$DomainName   = "vuln.lab",
    [string]$NetBIOSName  = "VULN",
    [string]$SafeModePass = "P@ssw0rd!DSRM",
    [string]$DefaultPass  = "Password1!"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

$transcriptPath = "$env:SystemDrive\VulnLab-Build-$(Get-Date -f 'yyyyMMdd-HHmmss').log"
Start-Transcript -Path $transcriptPath -Force

# --- Helpers -----------------------------------------------------------------

function Write-Banner ([string]$msg) {
    Write-Host ("`n" + ("=" * 70) + "`n  " + $msg + "`n" + ("=" * 70)) -ForegroundColor Cyan
}

function Write-Step ([string]$msg) {
    Write-Host "  [+] $msg" -ForegroundColor Green
}

function Write-Warn ([string]$msg) {
    Write-Host "  [!] $msg" -ForegroundColor Yellow
}

function Write-Section ([string]$msg) {
    Write-Host ("`n  -- " + $msg + " --") -ForegroundColor Magenta
}

function ConvertTo-Secure ([string]$plain) {
    ConvertTo-SecureString $plain -AsPlainText -Force
}

function New-LabUser {
    param(
        [string]$Name,
        [string]$SamAccountName = $Name,
        [string]$Path,
        [string]$Password = $DefaultPass,
        [string]$Description = "",
        [switch]$Enabled
    )
    $isEnabled = $true
    if ($PSBoundParameters.ContainsKey('Enabled')) {
        $isEnabled = $Enabled.IsPresent
    }
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $Name -SamAccountName $SamAccountName `
            -UserPrincipalName "$SamAccountName@$DomainName" `
            -Path $Path -AccountPassword (ConvertTo-Secure $Password) `
            -Description $Description -Enabled $isEnabled `
            -PasswordNeverExpires $true -CannotChangePassword $true
        Write-Step "Created user: $SamAccountName"
    }
}

function New-LabComputer {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Description = ""
    )
    if (-not (Get-ADComputer -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue)) {
        New-ADComputer -Name $Name -SamAccountName "$Name$" -Path $Path `
            -Description $Description -Enabled $true
        Write-Step "Created computer: $Name"
    }
}

$domainDN = ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','
$rebootMarker = "$env:SystemDrive\VulnLab-Phase1-Complete.flag"


# =============================================================================
#  PHASE 1 -- Install AD DS and promote to Domain Controller
# =============================================================================

if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
    Write-Banner "PHASE 1 -- Installing AD DS Role"
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature
    Write-Step "AD DS role installed"
}

$isDC = $false
try {
    $isDC = (Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue) -ne $null
}
catch {
    $isDC = $false
}

if (-not $isDC) {
    Write-Banner "PHASE 1 -- Promoting to Domain Controller"

    # Schedule this script to re-run after reboot
    $scriptPath = $MyInvocation.MyCommand.Path
    if ($scriptPath) {
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -DomainName `"$DomainName`" -NetBIOSName `"$NetBIOSName`" -SafeModePass `"$SafeModePass`" -DefaultPass `"$DefaultPass`""
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName "VulnLab-Phase2" -Trigger $trigger `
            -Action $action -Principal $principal -Force | Out-Null
        Write-Step "Scheduled Phase 2 task for post-reboot"
    }

    Import-Module ADDSDeployment
    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $NetBIOSName `
        -SafeModeAdministratorPassword (ConvertTo-Secure $SafeModePass) `
        -InstallDns:$true `
        -NoRebootOnCompletion:$false `
        -Force:$true

    # Server will reboot -- Phase 2 continues via scheduled task
    exit 0
}


# =============================================================================
#  PHASE 2 -- Post-promotion: populate vulnerable objects
# =============================================================================

# Remove the scheduled task if it exists
Unregister-ScheduledTask -TaskName "VulnLab-Phase2" -Confirm:$false -ErrorAction SilentlyContinue

# Wait for AD services to be fully available
Write-Banner "PHASE 2 -- Waiting for AD DS services"
$retries = 0
while ($retries -lt 30) {
    try {
        Get-ADDomain -ErrorAction Stop | Out-Null
        break
    }
    catch {
        $retries++
        Write-Warn "AD not ready yet -- waiting (attempt $retries/30)..."
        Start-Sleep -Seconds 10
    }
}
if ($retries -ge 30) {
    throw "AD DS did not become available in time."
}

Import-Module ActiveDirectory
Import-Module GroupPolicy

# Install ADCS role now (must be AFTER DC promotion, not before)
if (-not (Get-WindowsFeature ADCS-Cert-Authority).Installed) {
    Write-Step "Installing ADCS role (post-promotion)..."
    Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
    Write-Step "ADCS role installed"
}

$domainDN = (Get-ADDomain).DistinguishedName


# --- 1. Create OUs -----------------------------------------------------------

Write-Section "Organizational Units"

$OUs = @(
    "OU=Lab Users,$domainDN",
    "OU=Lab Admins,$domainDN",
    "OU=Lab Computers,$domainDN",
    "OU=Lab Servers,$domainDN",
    "OU=Service Accounts,$domainDN",
    "OU=Disabled,$domainDN",
    "OU=Staging,$domainDN"
)
foreach ($ou in $OUs) {
    $ouName = ($ou -split ',')[0] -replace 'OU=',''
    $ouParent = ($ou -split ',',2)[1]
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ou'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ouName -Path $ouParent -ProtectedFromAccidentalDeletion $false
        Write-Step "Created OU: $ouName"
    }
}


# --- 2. Weak Domain Password Policy ------------------------------------------

Write-Section "Weak Domain Password Policy"

Set-ADDefaultDomainPasswordPolicy -Identity $DomainName `
    -MinPasswordLength 4 `
    -PasswordHistoryCount 0 `
    -ComplexityEnabled $false `
    -MaxPasswordAge "365.00:00:00" `
    -MinPasswordAge "0.00:00:00" `
    -LockoutThreshold 0 `
    -ReversibleEncryptionEnabled $true
Write-Step "Domain password policy weakened (minLen=4, noComplexity, reversibleEncryption)"


# --- 3. Standard Users -------------------------------------------------------

Write-Section "Standard User Accounts"

$stdUsers = @(
    @{ Name = "Alice Johnson";  Sam = "alice.j"   },
    @{ Name = "Bob Smith";      Sam = "bob.s"     },
    @{ Name = "Charlie Brown";  Sam = "charlie.b" },
    @{ Name = "Diana Prince";   Sam = "diana.p"   },
    @{ Name = "Eve Torres";     Sam = "eve.t"     },
    @{ Name = "Frank Castle";   Sam = "frank.c"   },
    @{ Name = "Grace Hopper";   Sam = "grace.h"   },
    @{ Name = "Hank Pym";       Sam = "hank.p"    },
    @{ Name = "Ivy Green";      Sam = "ivy.g"     },
    @{ Name = "Jack Ryan";      Sam = "jack.r"    }
)
foreach ($u in $stdUsers) {
    New-LabUser -Name $u.Name -SamAccountName $u.Sam -Path "OU=Lab Users,$domainDN" -Enabled
}


# --- 4. Admin / Privileged Accounts -------------------------------------------

Write-Section "Admin and Privileged Accounts"

$adminUsers = @(
    @{ Name = "SVC-Backup";     Sam = "svc-backup";    Desc = "Backup service - see IT-wiki for creds" },
    @{ Name = "SVC-SQL";        Sam = "svc-sql";       Desc = "SQL service account" },
    @{ Name = "SVC-Exchange";   Sam = "svc-exchange";  Desc = "Exchange service" },
    @{ Name = "SVC-SCCM";      Sam = "svc-sccm";      Desc = "" },
    @{ Name = "Admin-Tier0";    Sam = "admin-tier0";   Desc = "" },
    @{ Name = "Admin-Tier1";    Sam = "admin-tier1";   Desc = "" },
    @{ Name = "Admin-HelpDesk"; Sam = "admin-helpdesk"; Desc = "" }
)
foreach ($u in $adminUsers) {
    New-LabUser -Name $u.Name -SamAccountName $u.Sam `
        -Path "OU=Lab Admins,$domainDN" -Description $u.Desc -Enabled
}

# Add to privileged groups
$privGroupMap = @{
    "Domain Admins"        = @("admin-tier0")
    "Enterprise Admins"    = @("admin-tier0")
    "Schema Admins"        = @("admin-tier0")
    "Account Operators"    = @("admin-tier1")
    "Server Operators"     = @("admin-tier1", "svc-backup")
    "Backup Operators"     = @("svc-backup")
    "Remote Desktop Users" = @("admin-helpdesk", "admin-tier1")
}
foreach ($group in $privGroupMap.Keys) {
    foreach ($sam in $privGroupMap[$group]) {
        try {
            Add-ADGroupMember -Identity $group -Members $sam -ErrorAction SilentlyContinue
            Write-Step "Added $sam -> $group"
        }
        catch {
            Write-Warn "Could not add $sam to $group"
        }
    }
}


# --- 5. Passwords in Descriptions (admins, users, computers) -----------------

Write-Section "Passwords in Descriptions"

Set-ADUser -Identity "svc-backup"  -Description "Backup svc - pw: B@ckup2024! (do not change)"
Set-ADUser -Identity "svc-sql"     -Description "SQL SA account password=SqlProd#99"
Set-ADUser -Identity "alice.j"     -Description "Temp password: Welcome1"
Set-ADUser -Identity "bob.s"       -Description "Reset pw to: Changeme123"
Write-Step "Set passwords in descriptions for 2 admins, 2 users"

New-LabComputer -Name "KIOSK-01" -Path "OU=Lab Computers,$domainDN" `
    -Description "Local admin pw: Kiosk#2024"
New-LabComputer -Name "KIOSK-02" -Path "OU=Lab Computers,$domainDN" `
    -Description "BIOS pw: bios1234 / local admin: Admin1!"
Write-Step "Set passwords in descriptions for 2 computers"


# --- 6. Kerberoastable Accounts (SPNs on user accounts) ----------------------

Write-Section "Kerberoastable SPNs"

$spnMap = @{
    "svc-sql"      = @("MSSQLSvc/sql01.$($DomainName):1433", "MSSQLSvc/sql01.$DomainName")
    "svc-exchange" = @("HTTP/mail.$DomainName")
    "svc-sccm"     = @("HTTP/sccm.$DomainName")
    "svc-backup"   = @("CIFS/backup01.$DomainName")
}
foreach ($sam in $spnMap.Keys) {
    foreach ($spn in $spnMap[$sam]) {
        Set-ADUser -Identity $sam -ServicePrincipalNames @{ Add = $spn }
    }
    Write-Step "SPN(s) set on $sam"
}


# --- 7. AS-REP Roastable Accounts (no pre-authentication) --------------------

Write-Section "AS-REP Roastable (no Kerberos pre-auth)"

$asrepUsers = @("eve.t", "frank.c", "svc-sccm")
foreach ($sam in $asrepUsers) {
    Set-ADAccountControl -Identity $sam -DoesNotRequirePreAuth $true
    Write-Step "Disabled pre-auth: $sam"
}


# --- 8. Unconstrained Delegation ---------------------------------------------

Write-Section "Unconstrained Delegation"

# Computers
foreach ($name in @("WEB-01", "APP-01")) {
    New-LabComputer -Name $name -Path "OU=Lab Servers,$domainDN"
    Set-ADComputer -Identity $name -TrustedForDelegation $true
    Write-Step "Unconstrained delegation (computer): $name"
}

# User account
Set-ADAccountControl -Identity "svc-exchange" -TrustedForDelegation $true
Write-Step "Unconstrained delegation (user): svc-exchange"


# --- 9. Constrained Delegation -----------------------------------------------

Write-Section "Constrained Delegation"

# Standard constrained delegation
New-LabComputer -Name "PROXY-01" -Path "OU=Lab Servers,$domainDN"
Set-ADComputer -Identity "PROXY-01" -Add @{
    'msDS-AllowedToDelegateTo' = @("HTTP/web-01.$DomainName", "HTTP/app-01.$DomainName")
}
Write-Step "Constrained delegation (standard): PROXY-01"

# Protocol transition (any-auth) -- the dangerous variant
New-LabComputer -Name "DVPN-01" -Path "OU=Lab Servers,$domainDN"
Set-ADAccountControl -Identity "DVPN-01$" -TrustedToAuthForDelegation $true
Set-ADComputer -Identity "DVPN-01" -Add @{
    'msDS-AllowedToDelegateTo' = @("CIFS/dc01.$DomainName", "LDAP/dc01.$DomainName")
}
Write-Step "Constrained delegation (protocol transition): DVPN-01 -> DC services"

Set-ADAccountControl -Identity "svc-sccm" -TrustedToAuthForDelegation $true
Set-ADUser -Identity "svc-sccm" -Add @{
    'msDS-AllowedToDelegateTo' = @("HTTP/sccm.$DomainName")
}
Write-Step "Constrained delegation (protocol transition): svc-sccm"


# --- 10. Deprecated / End-of-Life OS Computer Objects -------------------------

Write-Section "Deprecated OS Computer Objects"

$oldSystems = @(
    @{ Name = "XP-PC01";    OS = "Windows XP Professional";         Ver = "5.1 (2600)" },
    @{ Name = "WIN7-PC01";  OS = "Windows 7 Enterprise";            Ver = "6.1 (7601)" },
    @{ Name = "WIN7-PC02";  OS = "Windows 7 Professional";          Ver = "6.1 (7601)" },
    @{ Name = "SRV2003-01"; OS = "Windows Server 2003 Enterprise";  Ver = "5.2 (3790)" },
    @{ Name = "SRV2008-01"; OS = "Windows Server 2008 R2 Standard"; Ver = "6.1 (7601)" },
    @{ Name = "SRV2012-01"; OS = "Windows Server 2012 R2 Standard"; Ver = "6.3 (9600)" }
)
foreach ($sys in $oldSystems) {
    New-LabComputer -Name $sys.Name -Path "OU=Lab Computers,$domainDN"
    Set-ADComputer -Identity $sys.Name -OperatingSystem $sys.OS `
        -OperatingSystemVersion $sys.Ver
    Write-Step "Deprecated OS: $($sys.Name) ($($sys.OS))"
}


# --- 11. LAPS -- Deliberately missing coverage --------------------------------

Write-Section "LAPS -- partial / missing coverage"

# Create several computers that will never have LAPS passwords
$noLapsHosts = @("NOLAPS-PC01","NOLAPS-PC02","NOLAPS-PC03","NOLAPS-SRV01","NOLAPS-SRV02")
foreach ($name in $noLapsHosts) {
    New-LabComputer -Name $name -Path "OU=Lab Computers,$domainDN"
    Write-Step "Computer with no LAPS: $name"
}

# Try to install and configure LAPS schema if the module is available
try {
    # Attempt Windows LAPS schema extension (Server 2025 / patched 2019+)
    Update-LapsADSchema -ErrorAction Stop
    Write-Step "LAPS schema extended"

    # Set LAPS password on a couple of machines so coverage is partial
    $lapsHosts = @("KIOSK-01", "PROXY-01")
    foreach ($name in $lapsHosts) {
        try {
            Set-LapsADComputerAccount -Identity $name -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warn "Could not set LAPS for $name"
        }
    }
    Write-Step "LAPS password set on $($lapsHosts -join ', ') only -- others missing"
}
catch {
    Write-Warn "LAPS module not available -- creating attribute stubs for scanner testing"
    # Simulate partial coverage: set ms-Mcs-AdmPwd on only 2 of many computers
    # Legacy LAPS attribute - scanner checks for its presence
    try {
        foreach ($name in @("KIOSK-01","PROXY-01")) {
            Set-ADComputer -Identity $name -Add @{
                'ms-Mcs-AdmPwd' = 'FakeLAPSPw12345'
            } -ErrorAction SilentlyContinue
        }
        Write-Step "Simulated legacy LAPS attribute on 2 hosts"
    }
    catch {
        Write-Warn "Could not set legacy LAPS attribute (schema may not include it)"
    }
}


# --- 12. adminCount=1 -- orphaned, stale, disabled ----------------------------

Write-Section "adminCount=1 Objects"

# Create users, set adminCount manually, but do NOT put them in any privileged group
# These are orphaned adminCount objects
foreach ($sam in @("orphan-adm1", "orphan-adm2", "orphan-adm3")) {
    New-LabUser -Name $sam -SamAccountName $sam -Path "OU=Lab Users,$domainDN" -Enabled
    Set-ADUser -Identity $sam -Replace @{ adminCount = 1 }
    Write-Step "Orphaned adminCount=1: $sam"
}

# Disabled account with adminCount=1
New-LabUser -Name "disabled-adm1" -SamAccountName "disabled-adm1" `
    -Path "OU=Disabled,$domainDN"
Disable-ADAccount -Identity "disabled-adm1"
Set-ADUser -Identity "disabled-adm1" -Replace @{ adminCount = 1 }
Write-Step "Disabled adminCount=1: disabled-adm1"

# Stale account with adminCount=1 (set lastLogonTimestamp far in the past)
New-LabUser -Name "stale-adm1" -SamAccountName "stale-adm1" -Path "OU=Lab Users,$domainDN" -Enabled
Set-ADUser -Identity "stale-adm1" -Replace @{ adminCount = 1 }
# lastLogonTimestamp is SAM-owned so we must use ADSI to write it
try {
    $staleUser = Get-ADUser "stale-adm1"
    $adsiUser  = [ADSI]"LDAP://$($staleUser.DistinguishedName)"
    $staleTime = (Get-Date).AddDays(-400).ToFileTimeUtc()
    $adsiUser.Put("lastLogonTimestamp", $staleTime)
    $adsiUser.SetInfo()
    Write-Step "Stale adminCount=1: stale-adm1 (lastLogon 400 days ago)"
}
catch {
    Write-Warn "Could not set lastLogonTimestamp via ADSI: $_ (non-fatal)"
}


# --- 13. GPO Misconfigurations ------------------------------------------------

Write-Section "GPO Misconfigurations"

# Empty GPOs (created but never edited)
foreach ($gpoName in @("GPO-EmptyTest1", "GPO-EmptyTest2", "GPO-EmptyTest3")) {
    New-GPO -Name $gpoName -Comment "Deliberately empty GPO for scanner testing" | Out-Null
    Write-Step "Empty GPO: $gpoName"
}

# Unlinked GPOs (have settings but linked nowhere)
$unlinkedGPO = New-GPO -Name "GPO-Unlinked-Security"
$unlinkedGPO | Set-GPRegistryValue -Key "HKLM\Software\VulnLab" `
    -ValueName "TestSetting" -Type String -Value "test" | Out-Null
Write-Step "Unlinked GPO: GPO-Unlinked-Security"

$unlinkedGPO2 = New-GPO -Name "GPO-Unlinked-Legacy"
$unlinkedGPO2 | Set-GPRegistryValue -Key "HKLM\Software\VulnLab" `
    -ValueName "LegacySetting" -Type String -Value "old" | Out-Null
Write-Step "Unlinked GPO: GPO-Unlinked-Legacy"

# Disabled GPOs (all settings disabled)
$disabledGPO = New-GPO -Name "GPO-AllDisabled"
$disabledGPO | Set-GPRegistryValue -Key "HKLM\Software\VulnLab" `
    -ValueName "DisabledTest" -Type String -Value "x" | Out-Null
$disabledGPO.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::AllSettingsDisabled
Write-Step "Disabled GPO: GPO-AllDisabled (AllSettingsDisabled)"

# Linked GPO (legitimate -- for contrast)
$linkedGPO = New-GPO -Name "GPO-LabBaseline"
$linkedGPO | Set-GPRegistryValue -Key "HKLM\Software\VulnLab" `
    -ValueName "Baseline" -Type String -Value "1" | Out-Null
$linkedGPO | New-GPLink -Target $domainDN -LinkEnabled Yes | Out-Null
Write-Step "Linked GPO: GPO-LabBaseline (linked to domain root)"


# --- 14. Guest Account Enabled ------------------------------------------------

Write-Section "Guest Account"

Enable-ADAccount -Identity (Get-ADUser -Filter "SamAccountName -eq 'Guest'")
Set-ADUser -Identity "Guest" -PasswordNeverExpires $true
Write-Step "Guest account ENABLED"


# --- 15. Machine Account Quota (default 10 = allows any user to join) --------

Write-Section "Machine Account Quota"

Set-ADDomain -Identity $DomainName -Replace @{ 'ms-DS-MachineAccountQuota' = 10 }
Write-Step "ms-DS-MachineAccountQuota = 10 (any user can join machines)"


# --- 16. Anonymous / Null Session Access --------------------------------------

Write-Section "Anonymous LDAP and Null Session"

try {
    Set-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$domainDN" `
        -Replace @{ 'dSHeuristics' = '0000002' } -ErrorAction SilentlyContinue
    Write-Step "dSHeuristics set to allow anonymous LDAP access"
}
catch {
    Write-Warn "Could not set dSHeuristics (non-fatal)"
}

# Registry: allow null session shares and pipes
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RestrictNullSessAccess" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymous" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymousSAM" -Value 0 -Type DWord -Force
Write-Step "Null session access enabled via registry"


# --- 17. SMB Signing Not Required ---------------------------------------------

Write-Section "SMB Signing Disabled"

Set-SmbServerConfiguration -RequireSecuritySignature $false `
    -EnableSecuritySignature $false -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RequireSecuritySignature" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "RequireSecuritySignature" -Value 0 -Type DWord -Force
Write-Step "SMB signing not required (server and client)"


# --- 18. LDAP Signing Not Required --------------------------------------------

Write-Section "LDAP Signing Disabled"

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity" -Value 0 -Type DWord -Force
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ldap" `
        -Name "LDAPClientIntegrity" -Value 0 -Type DWord -Force
}
catch {
    Write-Warn "Could not set LDAP client integrity (non-fatal)"
}
Write-Step "LDAP signing not required"


# --- 19. LDAP Channel Binding Not Required ------------------------------------

Write-Section "LDAP Channel Binding Disabled"

$ntdsParams = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
Set-ItemProperty -Path $ntdsParams -Name "LdapEnforceChannelBinding" -Value 0 -Type DWord -Force
Write-Step "LDAP channel binding token requirement = Never"


# --- 20. Print Spooler Running on DC -----------------------------------------

Write-Section "Print Spooler on DC"

Set-Service -Name Spooler -StartupType Automatic
Start-Service -Name Spooler -ErrorAction SilentlyContinue
Write-Step "Print Spooler running on DC (PrintNightmare / SpoolSample attack surface)"


# --- 21. Cached Credentials ---------------------------------------------------

Write-Section "Excessive Cached Credentials"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -Name "CachedLogonsCount" -Value "50" -Type String -Force
Write-Step "CachedLogonsCount = 50 (default is 10, best practice is 2-4)"


# --- 22. WDigest Authentication (plaintext passwords in memory) ---------------

Write-Section "WDigest Authentication Enabled"

$wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $wdigestPath)) {
    New-Item -Path $wdigestPath -Force | Out-Null
}
Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Value 1 -Type DWord -Force
Write-Step "WDigest UseLogonCredential = 1 (plaintext creds in LSASS)"


# --- 23. Insecure DNS Zone Transfer -------------------------------------------

Write-Section "DNS Zone Transfer -- Any Server"

try {
    $zoneName = $DomainName
    dnscmd /Config $zoneName /AllowTransfer 0 2>$null   # 0 = to any server
    Write-Step "DNS zone transfer allowed to any server"
}
catch {
    Write-Warn "Could not configure DNS zone transfer (non-fatal)"
}


# --- 24. DCSync-capable Non-DC Account ----------------------------------------

Write-Section "DCSync-capable Account"

$dcSyncUser = "svc-replication"
New-LabUser -Name $dcSyncUser -SamAccountName $dcSyncUser `
    -Path "OU=Service Accounts,$domainDN" -Description "Replication service" -Enabled

# Grant Replicating Directory Changes + Replicating Directory Changes All
$acl = Get-Acl "AD:\$domainDN"

$replicateGuid    = [Guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"  # DS-Replication-Get-Changes
$replicateAllGuid = [Guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"  # DS-Replication-Get-Changes-All

$userSID = (Get-ADUser $dcSyncUser).SID

foreach ($guid in @($replicateGuid, $replicateAllGuid)) {
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $userSID,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $guid
    )
    $acl.AddAccessRule($ace)
}
Set-Acl "AD:\$domainDN" $acl
Write-Step "Granted DCSync rights to $dcSyncUser"


# --- 25. Weak ACLs -- GenericAll on Domain Admins -----------------------------

Write-Section "Weak ACLs"

$targetDN   = (Get-ADGroup "Domain Admins").DistinguishedName
$acl        = Get-Acl "AD:\$targetDN"
$lowPrivSID = (Get-ADUser "charlie.b").SID

$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $lowPrivSID,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($ace)
Set-Acl "AD:\$targetDN" $acl
Write-Step "charlie.b has GenericAll on Domain Admins"

# WriteDACL on domain root for another low-priv user
$domACL      = Get-Acl "AD:\$domainDN"
$writeDACSID = (Get-ADUser "diana.p").SID

$ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $writeDACSID,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$domACL.AddAccessRule($ace2)
Set-Acl "AD:\$domainDN" $domACL
Write-Step "diana.p has WriteDACL on domain root"


# --- 26. SID History Injection ------------------------------------------------

Write-Section "SID History"

try {
    $daGroup = Get-ADGroup "Domain Admins"
    Set-ADUser -Identity "hank.p" -Add @{
        'sIDHistory' = $daGroup.SID
    } -ErrorAction Stop
    Write-Step "Added DA SID to hank.p SID history"
}
catch {
    Write-Warn "SID history injection blocked (expected on single-domain -- logged for scanner reference)"
}


# --- 27. ADCS -- Vulnerable Certificate Templates -----------------------------

Write-Section "ADCS Vulnerable Certificate Templates"

try {
    # Configure Enterprise Root CA
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCA `
        -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
        -KeyLength 2048 -HashAlgorithmName SHA256 `
        -ValidityPeriod Years -ValidityPeriodUnits 10 `
        -Force -ErrorAction Stop | Out-Null
    Write-Step "Enterprise Root CA installed"

    Start-Sleep -Seconds 5

    $configDN   = (Get-ADRootDSE).configurationNamingContext
    $templateDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"

    # -- ESC1: Client Auth template that allows SAN + enrollee supplies subject
    $esc1Name = "VulnLab-ESC1"
    $baseDN   = "CN=User,$templateDN"

    if (-not (Get-ADObject -Filter "cn -eq '$esc1Name'" -SearchBase $templateDN -ErrorAction SilentlyContinue)) {
        $baseTemplate = Get-ADObject $baseDN -Properties *
        $oid = "1.3.6.1.4.1.311.21.8." + (Get-Random) + "." + (Get-Random) + "." + (Get-Random) + "." + (Get-Random) + "." + (Get-Random)

        New-ADObject -Name $esc1Name -Type "pKICertificateTemplate" -Path $templateDN -OtherAttributes @{
            'displayName'                  = $esc1Name
            'msPKI-Cert-Template-OID'      = $oid
            'flags'                        = 131680
            'msPKI-Certificate-Name-Flag'  = 1         # ENROLLEE_SUPPLIES_SUBJECT
            'msPKI-Enrollment-Flag'        = 0
            'msPKI-Private-Key-Flag'       = 16842752
            'msPKI-RA-Signature'           = 0
            'pKICriticalExtensions'        = @("2.5.29.15")
            'pKIDefaultCSPs'               = @("1,Microsoft RSA SChannel Cryptographic Provider")
            'pKIDefaultKeySpec'            = 1
            'pKIExpirationPeriod'          = $baseTemplate.'pKIExpirationPeriod'
            'pKIExtendedKeyUsage'          = @("1.3.6.1.5.5.7.3.2")   # Client Authentication
            'pKIMaxIssuingDepth'           = 0
            'pKIOverlapPeriod'             = $baseTemplate.'pKIOverlapPeriod'
            'revision'                     = 100
        }
        Write-Step "Created ESC1 template: $esc1Name (enrollee supplies subject + client auth)"

        # Grant Authenticated Users enroll
        $tmplObj  = Get-ADObject "CN=$esc1Name,$templateDN"
        $tmplACL  = Get-Acl "AD:\$($tmplObj.DistinguishedName)"
        $authUsers  = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
        $enrollGuid = [Guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55"  # Certificate-Enrollment

        $enrollACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $authUsers,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            $enrollGuid
        )
        $tmplACL.AddAccessRule($enrollACE)
        Set-Acl "AD:\$($tmplObj.DistinguishedName)" $tmplACL
        Write-Step "Granted Authenticated Users enroll on $esc1Name"
    }

    # -- ESC4: Low-priv user has full control over a template
    $esc4Name = "VulnLab-ESC4"
    if (-not (Get-ADObject -Filter "cn -eq '$esc4Name'" -SearchBase $templateDN -ErrorAction SilentlyContinue)) {
        $baseTemplate = Get-ADObject $baseDN -Properties *
        $oid4 = "1.3.6.1.4.1.311.21.8." + (Get-Random) + "." + (Get-Random) + "." + (Get-Random) + "." + (Get-Random) + "." + (Get-Random)

        New-ADObject -Name $esc4Name -Type "pKICertificateTemplate" -Path $templateDN -OtherAttributes @{
            'displayName'                  = $esc4Name
            'msPKI-Cert-Template-OID'      = $oid4
            'flags'                        = 131648
            'msPKI-Certificate-Name-Flag'  = 0
            'msPKI-Enrollment-Flag'        = 0
            'msPKI-Private-Key-Flag'       = 16842752
            'msPKI-RA-Signature'           = 0
            'pKICriticalExtensions'        = @("2.5.29.15")
            'pKIDefaultCSPs'               = @("1,Microsoft RSA SChannel Cryptographic Provider")
            'pKIDefaultKeySpec'            = 1
            'pKIExpirationPeriod'          = $baseTemplate.'pKIExpirationPeriod'
            'pKIExtendedKeyUsage'          = @("1.3.6.1.5.5.7.3.1")   # Server Authentication only
            'pKIMaxIssuingDepth'           = 0
            'pKIOverlapPeriod'             = $baseTemplate.'pKIOverlapPeriod'
            'revision'                     = 100
        }

        # Grant GenericAll to a regular user (ESC4 vector)
        $tmpl4    = Get-ADObject "CN=$esc4Name,$templateDN"
        $tmpl4ACL = Get-Acl "AD:\$($tmpl4.DistinguishedName)"
        $eveSID   = (Get-ADUser "eve.t").SID

        $gaACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $eveSID,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $tmpl4ACL.AddAccessRule($gaACE)
        Set-Acl "AD:\$($tmpl4.DistinguishedName)" $tmpl4ACL
        Write-Step "Created ESC4 template: $esc4Name (eve.t has GenericAll)"
    }
}
catch {
    Write-Warn "ADCS template creation failed: $_ (non-fatal -- CA may not be ready)"
}


# --- 28. Tombstone Lifetime Shortened -----------------------------------------

Write-Section "Tombstone Lifetime Shortened"

try {
    $configDN = (Get-ADRootDSE).configurationNamingContext
    Set-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$configDN" `
        -Replace @{ tombstoneLifetime = 30 }
    Write-Step "Tombstone lifetime set to 30 days (default 180)"
}
catch {
    Write-Warn "Could not set tombstone lifetime (non-fatal)"
}


# --- 29. Weak Kerberos Encryption (DES + RC4) ---------------------------------

Write-Section "Weak Kerberos Encryption"

Set-ADUser -Identity "svc-sql" -KerberosEncryptionType @("DES","RC4")
Set-ADUser -Identity "svc-backup" -KerberosEncryptionType @("DES","RC4")
Write-Step "DES + RC4 Kerberos encryption enabled for svc-sql, svc-backup"

# Domain-wide: allow RC4 in registry
$kerbPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
if (-not (Test-Path $kerbPath)) {
    New-Item -Path $kerbPath -Force | Out-Null
}
Set-ItemProperty -Path $kerbPath -Name "SupportedEncryptionTypes" -Value 0x7 -Type DWord -Force
Write-Step "Registry: SupportedEncryptionTypes allows DES+RC4"


# --- 30. Resource-Based Constrained Delegation (RBCD) on DC -------------------

Write-Section "Resource-Based Constrained Delegation (RBCD) on DC"

try {
    $dcComputer   = Get-ADComputer $env:COMPUTERNAME
    $attackerComp = Get-ADComputer "WEB-01"
    Set-ADComputer -Identity $dcComputer -PrincipalsAllowedToDelegateToAccount $attackerComp
    Write-Step "RBCD: WEB-01 can delegate to DC ($($dcComputer.Name))"
}
catch {
    Write-Warn "RBCD setup failed: $_"
}


# --- 31. Group Policy Preferences Password (simulated) ------------------------

Write-Section "GPP Password (simulated)"

$gppGPO = New-GPO -Name "GPO-GPP-Password"
$gppGPO | New-GPLink -Target "OU=Lab Computers,$domainDN" -LinkEnabled Yes | Out-Null

# Create a simulated Groups.xml with cpassword in SYSVOL
$gppPath = "\\$DomainName\SYSVOL\$DomainName\Policies\{$($gppGPO.Id)}\Machine\Preferences\Groups"
New-Item -Path $gppPath -ItemType Directory -Force | Out-Null

$gppXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="LocalAdmin"
        image="2" changed="2024-01-15 10:30:00" uid="{DEADBEEF-0000-0000-0000-000000000001}">
    <Properties action="U" newName="" fullName="" description=""
                cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" userName="LocalAdmin"/>
  </User>
</Groups>
"@
Set-Content -Path "$gppPath\Groups.xml" -Value $gppXml -Encoding UTF8
Write-Step "GPP cpassword planted in SYSVOL (GPO-GPP-Password)"


# --- 32. krbtgt Password Never Changed ----------------------------------------

Write-Section "krbtgt Information"

$krbtgt = Get-ADUser "krbtgt" -Properties PasswordLastSet
Write-Step "krbtgt password last set: $($krbtgt.PasswordLastSet) (newly created domain -- note for scanner)"


# --- 33. Pre-Windows 2000 Compatible Access Group -----------------------------

Write-Section "Pre-Windows 2000 Compatible Access"

try {
    Add-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" `
        -Members "S-1-5-11" -ErrorAction SilentlyContinue  # Authenticated Users
    Write-Step "Authenticated Users added to Pre-Windows 2000 Compatible Access"
}
catch {
    Write-Warn "Pre-Win2k group membership may already exist"
}


# --- 34. Audit Policy -- Insufficient Logging ---------------------------------

Write-Section "Audit Policy -- Minimal Logging"

auditpol /set /category:"Account Logon"              /success:disable /failure:disable
auditpol /set /category:"Logon/Logoff"               /success:enable  /failure:disable
auditpol /set /category:"Object Access"              /success:disable /failure:disable
auditpol /set /category:"Privilege Use"              /success:disable /failure:disable
auditpol /set /category:"Directory Service Access"   /success:disable /failure:disable
Write-Step "Audit policy set to minimal logging"


# =============================================================================
#  SUMMARY
# =============================================================================

Write-Banner "VULNERABLE LAB BUILD COMPLETE"

$summary = @"

  Domain           : $DomainName
  Domain DN        : $domainDN
  Default Password : $DefaultPass
  DSRM Password    : $SafeModePass

  Misconfigurations deployed:
   [1]  Weak domain password policy (minLen 4, no complexity, reversible enc.)
   [2]  Passwords in descriptions (2 admin, 2 user, 2 computer)
   [3]  Kerberoastable service accounts (4 SPNs)
   [4]  AS-REP roastable accounts (3 users)
   [5]  Unconstrained delegation (2 computers, 1 user)
   [6]  Constrained delegation -- standard (1) + protocol transition (2)
   [7]  Deprecated OS computer objects (6 -- XP through Server 2012 R2)
   [8]  LAPS coverage gaps (5+ computers with no LAPS)
   [9]  Orphaned adminCount=1 objects (3 orphaned, 1 disabled, 1 stale)
   [10] GPO hygiene issues (3 empty, 2 unlinked, 1 all-disabled)
   [11] Guest account enabled
   [12] MachineAccountQuota = 10
   [13] Anonymous LDAP / null session access
   [14] SMB signing not required
   [15] LDAP signing not required
   [16] LDAP channel binding disabled
   [17] Print Spooler running on DC
   [18] Excessive cached credentials (50)
   [19] WDigest authentication enabled (plaintext creds in LSASS)
   [20] DNS zone transfer to any server
   [21] DCSync-capable non-DC account
   [22] Dangerous ACLs (GenericAll on DA, WriteDACL on domain root)
   [23] ADCS vulnerable templates (ESC1, ESC4)
   [24] Tombstone lifetime shortened to 30 days
   [25] Weak Kerberos encryption (DES + RC4)
   [26] RBCD on DC from regular computer
   [27] GPP cpassword in SYSVOL
   [28] Pre-Windows 2000 Compatible Access misconfigured
   [29] Audit policy -- minimal logging

  Build log: $transcriptPath
"@
Write-Host $summary -ForegroundColor Yellow

Stop-Transcript