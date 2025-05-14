function Write-KvStatus {
    param(
        [ValidateSet('Ok', 'Warning', 'Error', 'Info')] [string] $Status,
        [Parameter(Mandatory)] [string] $Message
    )
    switch ($Status) {
        'Ok' { Write-Verbose   $Message }
        'Info' { Write-Information $Message }
        'Warning' { Write-Warning   $Message }
        'Error' { Write-Error     $Message }
    }
}

function Get-ProjectRoot {
    $d = Get-Location
    while ($d) {
        if (Test-Path "$($d.Path)\*.csproj") { return $d }
        $d = $d.Parent
    }
}

function Get-LevenshteinDistance {
    param([string]$A, [string]$B)
    $la, $lb = $A.Length, $B.Length
    if (!$la) { return $lb }; if (!$lb) { return $la }
    $prev = 0..$lb; $curr = New-Object int[] ($lb + 1)
    for ($i = 1; $i -le $la; $i++) {
        $curr[0] = $i
        for ($j = 1; $j -le $lb; $j++) {
            $cost = if ($A[$i - 1] -eq $B[$j - 1]) { 0 } else { 1 }
            $curr[$j] = [math]::Min([math]::Min($curr[$j - 1] + 1, $prev[$j] + 1), $prev[$j - 1] + $cost)
        }
        $prev, $curr = $curr, $prev
    }
    $prev[$lb]
}

function Test-IsPotentialSecretKey {
    param([string]$Key)
    $Key -imatch '(secret|password|token|key|certificate|connectionstring)$'
}

function Add-FlattenedJsonKeys {
    param(
        [object]$JsonObject,
        [string]$Prefix,
        [hashtable]$KeyBag,
        [hashtable]$Visited,
        [ref]$Counter,
        [int]$Depth = 0,
        [int]$MaxDepth = 25
    )
    if ($Depth -gt $MaxDepth) { return }
    if (-not ($JsonObject -is [pscustomobject])) { return }

    $id = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($JsonObject)
    if ($Visited.ContainsKey($id)) { return }
    $Visited[$id] = $true

    foreach ($p in $JsonObject.PSObject.Properties | Where-Object MemberType -EQ 'NoteProperty') {
        $key = if ($Prefix) { "$Prefix`:$($p.Name)" } else { $p.Name }
        $val = $p.Value
        switch ($val) {
            { $_ -is [pscustomobject] } {
                Add-FlattenedJsonKeys -JsonObject $val -Prefix $key -KeyBag $KeyBag -Visited $Visited `
                    -Counter $Counter -Depth ($Depth + 1) -MaxDepth $MaxDepth
            }
            { $_ -is [System.Collections.IEnumerable] -and -not ($_ -is [string]) } {
                $i = 0
                foreach ($item in $val) {
                    $indexed = "$key`[$i`]"
                    if ($item -is [pscustomobject]) {
                        Add-FlattenedJsonKeys -JsonObject $item -Prefix $indexed -KeyBag $KeyBag -Visited $Visited `
                            -Counter $Counter -Depth ($Depth + 1) -MaxDepth $MaxDepth
                    }
                    else { $KeyBag[$indexed] = $true }
                    $i++
                }
            }
            default { $KeyBag[$key] = $true }
        }
        $Counter.Value++
        if ($Counter.Value % 250 -eq 0) { Write-KvStatus Info "    …$($Counter.Value) keys processed" }
    }
}

function Show-Preview {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    if ($Text.Length -gt 8) { return $Text.Substring(0, 4) + '…' } else { return $Text.Substring(0, 1) + '…' }
}

function Select-ConfigurationKey {
    param(
        [string]$SecretName,
        [hashtable]$AvailableKeys,
        [int]$Threshold = 8
    )

    $suggestions = @(
        $AvailableKeys.Keys | ForEach-Object {
            [pscustomobject]@{
                Key      = $_
                Distance = Get-LevenshteinDistance $SecretName $_
            }
        } | Where-Object Distance -LE $Threshold |
        Sort-Object Distance, Key
    )

    if ($suggestions.Count -eq 0) {
        Write-Host "Could not find any existing appsettings entry matching '$SecretName'."
        return (Read-Host "Enter a config name to be used as a key for the local user secret (optionally: a comma-separated list of config names)")
    }

    if ($suggestions.Count -eq 1) {
        $suggested = $suggestions[0].Key
        Write-Host "A similar config key '$suggested' was found in appsettings for secret '$SecretName'."
        $confirm = Read-Host "Use suggested config key '$suggested' for '$SecretName'? [Y/n/custom key(s)]"
        switch ($confirm.ToLower()) {
            { $_ -eq '' -or $_ -eq 'y' -or $_ -eq 'yes' } { return $suggested }
            { $_ -eq 'n' -or $_ -eq 'no' } {
                return (Read-Host "Enter custom config name (or comma-separated list)")
            }
            default { return $confirm }
        }
    }

    Write-Host "`nSimilar config keys were found in appsettings for secret '$SecretName':" -ForegroundColor Cyan
    for ($i = 0; $i -lt $suggestions.Count; $i++) {
        Write-Host "$($i+1)) $($suggestions[$i].Key)"
    }

    Write-Host '[Enter a number from the suggestions above. Optionally: Enter a custom key or a comma-separated list]'
    $userInput = Read-Host 'Which key(s) do you want to use for local user secrets?'
    if ($userInput -match '^[0-9]+$' -and 1 -le $userInput -and $userInput -le $suggestions.Count) {
        return $suggestions[[int]$userInput - 1].Key
    }
    return $userInput
}

function Find-SubscriptionsWithVault {
    param(
        [string]$VaultName,
        [array]$Subscriptions
    )

    $matchingSubscriptionsAndRg = @()
    foreach ($sub in $Subscriptions) {
        try {
            $vault = Get-AzKeyVault -VaultName $VaultName -SubscriptionId $sub.Id -ErrorAction Stop
            $matchingSubscriptionsAndRg += [pscustomobject]@{
                Subscription  = $sub
                ResourceGroup = $vault.ResourceGroupName
            }
        }
        catch {}
    }
    return $matchingSubscriptionsAndRg
}

function Get-NetworkAclObject {
    param(
        [Parameter(Mandatory)][PSObject] $Vault
    )

    if ($Vault.PSObject.Properties.Match('NetworkAcls')) {
        return $Vault.NetworkAcls
    }

    # Otherwise, if it has a .Properties member (old SDK shape), drill into that
    if ($Vault.PSObject.Properties.Match('Properties')) {
        $inner = $Vault.Properties
        if ($inner.PSObject.Properties.Match('NetworkAcls')) {
            return $inner.NetworkAcls
        }
    }

    throw "Cannot find a NetworkAcls property on the vault object."
}

function Get-VaultIpRules {
    param(
        [Parameter(Mandatory)][PSObject] $Vault,
        [Parameter(Mandatory)][string]$ResourceGroupName
    )
    
    $networkAcls = if ($Vault.PSObject.Properties.Match('NetworkAcls')) {
        $Vault.NetworkAcls
    }
    elseif ($Vault.PSObject.Properties.Match('Properties') -and $Vault.Properties.PSObject.Properties.Match('NetworkAcls')) {
        $Vault.Properties.NetworkAcls
    }
    else {
        throw "Unable to locate NetworkAcls on vault object."
    }

    if (-not $networkAcls.PSObject.Properties.Match('IpRules')) {
        throw "No IpRules property found on NetworkAcls."
    }

    return $networkAcls.IpRules | ForEach-Object { $_.Value }
}

function Assert-KeyVaultNetworkAccess {
    param([string]$VaultName, [string]$ResourceGroupName, [ref]$AddedIp)
    
    try {
        $ip = Invoke-RestMethod -Uri 'https://api.ipify.org'
    }
    catch {
        Write-KvStatus Warning 'Could not detect your IP'
        return
    }

    $vault = Get-AzKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName -ErrorAction Stop
    $acl = Get-NetworkAclObject -Vault $vault
    $rules = Get-IpRuleValues -Acl $acl

    if ($rules -contains "$ip/32") {
        return # already allowed
    }

    Write-KvStatus Info "Adding IP $ip…"
    Update-AzKeyVaultNetworkRuleSet -VaultName $VaultName -ResourceGroupName $ResourceGroupName -IpAddress $ip
    $AddedIp.Value = $ip
    return $ip
}

function Remove-TemporaryNetworkAccess {
    param([string]$VaultName, [string]$ResourceGroupName, [string]$Ip)
    return unless $Ip
    Write-KvStatus Info "Removing IP $Ip"
    Remove-AzKeyVaultNetworkRule -Name $VaultName -ResourceGroupName $ResourceGroupName -IpAddress $Ip :contentReference[oaicite:6] { index=6 }
}

function Get-PlainSecret {
    param(
        [Parameter(Mandatory)] [string]$VaultName,
        [Parameter(Mandatory)] [string]$Name
    )

    # Prefer the modern switch if the cmdlet supports it
    if ((Get-Command Get-AzKeyVaultSecret).Parameters.ContainsKey('AsPlainText')) {
        return Get-AzKeyVaultSecret -VaultName $VaultName -Name $Name -AsPlainText
    }

    $obj = Get-AzKeyVaultSecret -VaultName $VaultName -Name $Name
    if ($obj.PSObject.Properties.Match('SecretValueText')) {
        return $obj.SecretValueText # Az.KeyVault < 5.x
    }

    # convert SecureString safely if it is the only way
    if ($obj.PSObject.Properties.Match('SecretValue') -and
        $obj.SecretValue -is [securestring]) {

        try {
            $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($obj.SecretValue)
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        }
        finally { if ($ptr) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) } }
    }

    throw "Get-AzKeyVaultSecret returned an unexpected object; can't find plain-text value."
}

# --- Main function ---

function Sync-AzKeyVaultWithUserSecrets {
    [CmdletBinding()] param([Parameter(Mandatory)] [string]$KeyVaultName)

    Set-StrictMode -Version Latest

    $root = Get-ProjectRoot
    if (-not $root) { Write-KvStatus Error 'No .csproj found.'; return }
    $csproj = (Get-ChildItem $root *.csproj | Select-Object -First 1).FullName
    Write-KvStatus Ok "Found project: $csproj"
    if (-not (Select-String -Path $csproj -Pattern '<UserSecretsId>' -Quiet)) {
        Write-KvStatus Info "Initializing dotnet user-secrets for project: $csproj"
        dotnet user-secrets init --project $csproj | Out-Null
    }

    $projectName = Split-Path $csproj -Leaf
    Write-KvStatus Ok "Current user-secrets for project $($projectName):"
    dotnet user-secrets list

    $ErrorActionPreference = 'Stop'
    if (-not (Get-Module -ListAvailable Az.Accounts, Az.KeyVault)) {
        Write-KvStatus Error 'Az modules are missing from your environment.'; return
    }
    Import-Module Az.Accounts, Az.KeyVault -ErrorAction Stop

    $subs = Get-AzSubscription | Sort-Object Name
    if (-not $subs) { Write-KvStatus Error 'Run Connect-AzAccount.'; return }

    $locations = Find-SubscriptionsWithVault -VaultName $KeyVaultName -Subscriptions $subs

    if (-not $locations) {
        Write-KvStatus Error "The Key Vault '$KeyVaultName' was not found in any subscription to which you have access."
        return
    }

    # if exactly one match, pick it automatically
    if ($locations.Count -eq 1) {
        $locationChoice = $locations[0]
    }
    else {
        Write-Host "`nKey Vault found in multiple subscriptions / resource-groups:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $locations.Count; $i++) {
            $sub = $locations[$i].Subscription
            $rg = $locations[$i].ResourceGroup
            Write-Host "$($i+1)) Subscription: $($sub.Name)   ResourceGroup: $rg"
        }
        do {
            $sel = Read-Host 'Choose a number'
        } until ($sel -match '^[0-9]+$' -and 1 -le $sel -and $sel -le $locations.Count)

        $locationChoice = $locations[[int]$sel - 1]
    }

    Set-AzContext -SubscriptionId $locationChoice.Subscription.Id | Out-Null
    Write-KvStatus Ok "Using subscription: $($locationChoice.Subscription.Name) / resource-group: $($locationChoice.ResourceGroup)"

    try {
        $vault = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction Stop
    }
    catch {
        Write-KvStatus Error "Key Vault '$KeyVaultName' not found or inaccessible."
        return
    }
    $rgName = $vault.ResourceGroupName
    Write-KvStatus Ok "Target Key Vault in resource group '$rgName'."

    $temporaryIp = $null
    try {
        $secrets = Get-AzKeyVaultSecret -VaultName $KeyVaultName -ErrorAction Stop
    }
    catch {
        $ex = $_.Exception

        $httpCode = $null
        if ($ex.PSObject.Properties['Response']) {
            $resp = $ex.Response
            if ($resp -and $resp.StatusCode) {
                $httpCode = [int]$resp.StatusCode.value__
            }
        }
        elseif ($ex.PSObject.Properties['ResponseMessage']) {
            $respMsg = $ex.ResponseMessage
            if ($respMsg -and $respMsg.StatusCode) {
                $httpCode = [int]$respMsg.StatusCode.value__
            }
        }

        $isForbidden = ($httpCode -eq 403) -or ($ex.Message -match 'Forbidden')

        if ($isForbidden -and $ex.Message -match 'Client address is not authorized') {
            Write-KvStatus Warning 'Firewall blocked your IP; adding temporary rule to accept your IP…'

            $ipRef = [ref]''
            Assert-KeyVaultNetworkAccess -VaultName $KeyVaultName -ResourceGroup $locationChoice.ResourceGroup -AddedIp $ipRef
            $temporaryIp = $ipRef.Value

            # now retry
            try {
                $secrets = Get-AzKeyVaultSecret -VaultName $KeyVaultName -ErrorAction Stop
            }
            catch {
                Write-KvStatus Error 'Still forbidden after adding your IP. Check your RBAC rights.'
                return
            }
        }
        elseif ($isForbidden) {
            Write-KvStatus Error 'Access denied—insufficient RBAC permissions.'
            return
        }
        else {
            throw # not a 403, re-throw
        }
    }
    finally {
        if ($temporaryIp) {
            Remove-TemporaryNetworkAccess -VaultName $KeyVaultName -ResourceGroupName $locationChoice.ResourceGroupName -Ip $temporaryIp
        }
    }

    if (-not $secrets) { Write-KvStatus Error 'Key Vault is empty.'; return }
    Write-KvStatus Ok "Found $($secrets.Count) secrets in selected Key Vault."

    $jsonFiles = Get-ChildItem $root -Recurse -Filter 'appsettings*.json' |
    Where-Object { $_.FullName -notmatch '\\(bin|obj|node_modules)\\' }
    if (-not $jsonFiles) { Write-KvStatus Warning 'No appsettings*.json in project.'; return }

    Write-Host "`nSelect appsettings file(s):" -ForegroundColor Cyan
    for ($i = 0; $i -lt $jsonFiles.Count; $i++) { Write-Host "$($i+1)) $($jsonFiles[$i].FullName)" }
    Write-Host 'a) All files'
    do { $sel = Read-Host 'Choose (single option or comma-separated list)' } until ($sel -match '^[0-9,]+$' -or $sel -eq 'a')
    $selected = if ($sel -eq 'a') { $jsonFiles } else { $idx = $sel -split ',' | ForEach-Object { [int]$_ - 1 }; $jsonFiles[$idx] }

    $keys = @{}; $visited = @{}; $counter = 0
    foreach ($f in $selected) {
        Add-FlattenedJsonKeys (Get-Content $f.FullName -Raw | ConvertFrom-Json) '' $keys $visited ([ref]$counter)
    }
    Write-KvStatus Ok "Found $($keys.Count) distinct config keys among the selected appsettings."

    $mappedKeys = @()
    foreach ($secret in $secrets) {
        Write-Host '─────────────────────────────────────────────────' -ForegroundColor DarkGray

        $keysCsv = Select-ConfigurationKey -SecretName $secret.Name -AvailableKeys $keys
        $localKeyValues = @(
            $keysCsv -split ',' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -ne '' }
        )

        if (-not $localKeyValues.Count) { continue } # user skipped it

        $plainTextSecretValue = Get-PlainSecret -VaultName $KeyVaultName -Name $secret.Name
        $preview = Show-Preview $plainTextSecretValue

        foreach ($cfg in $localKeyValues) {
            & dotnet user-secrets set $cfg $plainTextSecretValue --project $csproj | Out-Null
            Write-KvStatus Ok "Saved Key Vault secret '$($secret.Name)' → local '$cfg' (value: $preview)"
            $mappedKeys += $cfg
        }
    }

    $unmapped = $keys.Keys |
    ForEach-Object { $_.Trim() } |
    Where-Object { Test-IsPotentialSecretKey $_ } |
    Where-Object { $_ -notin $mappedKeys }

    if ($unmapped) {
        Write-KvStatus Warning 'There are some potential secrets in the appsettings which were not linked to any Key Vault entry:'
        $unmapped | Sort-Object | Get-Unique | ForEach-Object { "  $_" }
    }
    else {
        Write-KvStatus Ok 'All secrets described by appsettings have been mapped to user secrets.'
    }
}

Set-Alias -Name kv2local -Value Sync-AzKeyVaultWithUserSecrets -Scope Script
Export-ModuleMember -Function Sync-AzKeyVaultWithUserSecrets -Alias kv2local
