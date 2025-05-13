function Write-Status {
    [CmdletBinding()]
    param(
        [ValidateSet('Ok','Warning','Error','Info')] [string]$Status,
        [string]$Message
    )
    $Colors = @{ Ok = 'Green'; Warning = 'Yellow'; Error = 'Red'; Info = $null }
    $Symbols = @{ Ok = '✓'; Warning = '⚠'; Error = '✕'; Info = '•' }
    $c = $Colors[$Status]; $s = $Symbols[$Status]
    if ($c) { Write-Host "$s $Message" -ForegroundColor $c } else { Write-Host "$s $Message" }
}

function Get-ProjectRootDirectory {
    $d = Get-Location
    while ($d) {
        if (Test-Path "$($d.Path)\*.csproj") { return $d }
        $d = $d.Parent
    }
}

function Get-LevenshteinDistance {
    param([string]$A,[string]$B)
    $la,$lb = $A.Length,$B.Length
    if (!$la) { return $lb }; if (!$lb) { return $la }
    $prev = 0..$lb; $curr = New-Object int[] ($lb + 1)
    for ($i = 1; $i -le $la; $i++) {
        $curr[0] = $i
        for ($j = 1; $j -le $lb; $j++) {
            $cost = if ($A[$i - 1] -eq $B[$j - 1]) { 0 } else { 1 }
            $curr[$j] = [math]::Min([math]::Min($curr[$j - 1] + 1,$prev[$j] + 1),$prev[$j - 1] + $cost)
        }
        $prev,$curr = $curr,$prev
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
                    } else { $KeyBag[$indexed] = $true }
                    $i++
                }
            }
            default { $KeyBag[$key] = $true }
        }
        $Counter.Value++
        if ($Counter.Value % 250 -eq 0) { Write-Status Info "    …$($Counter.Value) keys processed" }
    }
}

function Select-ConfigurationKey {
    param(
        [string]$SecretName,
        [hashtable]$AvailableKeys,
        [int]$Threshold = 8
    )

    $suggestions = $AvailableKeys.Keys | ForEach-Object {
        [pscustomobject]@{ Key = $_; Distance = Get-LevenshteinDistance $SecretName $_ }
    } | Where-Object Distance -LE $Threshold | Sort-Object Distance,Key

    if ($suggestions.Count -eq 0) {
        Write-Host "Could not find any existing appsettings entry matching '$SecretName'."
        return (Read-Host "Enter a config name to be used as a key for the local user secret (optionally: a comma-separated list of config names)")
    }

    if ($suggestions.Count -eq 1) {
        $suggested = $suggestions[0].Key
        $confirm = Read-Host "Use suggested config key '$suggested' for '$SecretName'? [Y/n/custom key]"
        switch ($confirm.ToLower()) {
            { $_ -eq '' -or $_ -eq 'y' -or $_ -eq 'yes' } { return $suggested }
            { $_ -eq 'n' -or $_ -eq 'no' } {
                return (Read-Host "Enter custom config name (or comma-separated list)")
            }
            default { return $confirm }
        }
    }

    Write-Host "`nMap secret '$SecretName':" -ForegroundColor Cyan
    for ($i = 0; $i -lt $suggestions.Count; $i++) {
        Write-Host "$($i+1)) $($suggestions[$i].Key)"
    }

    Write-Host '[Enter a number from the suggestions above. Optionally: Enter a custom key or a comma-separated list]'
    $input = Read-Host 'Which key(s) do you want to use for local user secrets?'
    if ($input -match '^[0-9]+$' -and 1 -le $input -and $input -le $suggestions.Count) {
        return $suggestions[[int]$input - 1].Key
    }
    return $input
}

function Find-SubscriptionsWithVault {
    param([string]$VaultName,[array]$Subscriptions)
    $matches = @()
    foreach ($s in $Subscriptions) {
        try { $null = Get-AzKeyVault -VaultName $VaultName -SubscriptionId $s.Id -ErrorAction Stop; $matches += $s } catch {}
    }
    $matches
}

function Ensure-NetworkAccess {
    param([string]$VaultName,[string]$ResourceGroup,[ref]$AddedIp)

    try { $ip = (Invoke-RestMethod -Uri 'https://api.ipify.org') }
    catch { Write-Status Warning 'Could not determine your public IP.'; return $null }

    $vault = Get-AzKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroup -ErrorAction Stop
    $exists = $vault.NetworkAcls.IpRules | Where-Object { $_.Value -eq "$ip/32" }
    if ($exists) { return $ip } # already allowed

    Write-Status Warning "Temporarily adding your IP $ip to Key Vault firewall"
    Update-AzKeyVaultNetworkRuleSet -VaultName $VaultName -ResourceGroupName $ResourceGroup `
         -IpAddress $ip -ErrorAction Stop | Out-Null
    $AddedIp.Value = $ip
    return $ip
}

function Remove-TemporaryNetworkAccess {
    param(
        [string]$VaultName,
        [string]$ResourceGroup,
        [string]$Ip
    )
    if (-not $Ip) { return }

    Write-Status Info "Removing temporary IP rule $Ip"

    # Newer Az.KeyVault (≥ 5.x) ships Remove-AzKeyVaultNetworkRuleSet
    $removeCmd = Get-Command Remove-AzKeyVaultNetworkRuleSet -ErrorAction SilentlyContinue
    if ($removeCmd) {
        Remove-AzKeyVaultNetworkRuleSet -VaultName $VaultName `
             -ResourceGroupName $ResourceGroup `
             -IpAddress $Ip -ErrorAction SilentlyContinue
        return
    }

    # Fallback for older modules – use Update-AzKeyVaultNetworkRuleSet if it supports –IpAddressToRemove
    $updateCmd = Get-Command Update-AzKeyVaultNetworkRuleSet -ErrorAction SilentlyContinue
    if ($updateCmd -and $updateCmd.Parameters.ContainsKey('IpAddressToRemove')) {
        Update-AzKeyVaultNetworkRuleSet -VaultName $VaultName `
             -ResourceGroupName $ResourceGroup `
             -IpAddressToRemove $Ip -ErrorAction SilentlyContinue | Out-Null
        return
    }

    Write-Status Warning "Your Az.KeyVault version can't remove IP rules automatically. Delete '$Ip' manually in the portal."
}

function Sync-AzKeyVaultWithUserSecrets {
    [CmdletBinding()] param([Parameter(Mandatory)] [string]$KeyVaultName)

    $ErrorActionPreference = 'Stop'
    if (-not (Get-Module -ListAvailable Az.Accounts,Az.KeyVault)) {
        Write-Status Error 'Az modules are missing from your environment.'; return
    }
    Import-Module Az.Accounts,Az.KeyVault -ErrorAction Stop

    $subs = Get-AzSubscription | Sort-Object Name
    if (-not $subs) { Write-Status Error 'Run Connect-AzAccount.'; return }

    $candidateSubs = Find-SubscriptionsWithVault -VaultName $KeyVaultName -Subscriptions $subs
    if (-not $candidateSubs) {
        Write-Status Error "The Key Vault '$KeyVaultName' was not found in any subscription to which you have access."; return
    }
    $subscription = if ($candidateSubs.Count -eq 1) { $candidateSubs[0] } else {
        Write-Host "`nKey Vault found in multiple subscriptions:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $candidateSubs.Count; $i++) { Write-Host "$($i+1)) $($candidateSubs[$i].Name)" }
        do { $c = Read-Host 'Choose' } until ($c -match '^[0-9]+$' -and 1 -le $c -and $c -le $candidateSubs.Count)
        $candidateSubs[$c - 1]
    }
    Set-AzContext -SubscriptionId $subscription.Id | Out-Null
    Write-Status Ok "Using subscription: $($subscription.Name)"

    $root = Get-ProjectRootDirectory
    if (-not $root) { Write-Status Error 'No .csproj found.'; return }
    $csproj = (Get-ChildItem $root *.csproj | Select-Object -First 1).FullName
    Write-Status Ok "Found project: $csproj"
    if (-not (Select-String -Path $csproj -Pattern '<UserSecretsId>' -Quiet)) {
        Write-Status Info "Initializing dotnet user-secrets for project: $csproj"
        dotnet user-secrets init --project $csproj | Out-Null
    }

    $temporaryIp = $null
    try {
        $secrets = Get-AzKeyVaultSecret -VaultName $KeyVaultName -ErrorAction Stop
    }
    catch {
        $err = $_.Exception
        $statusCode = $null

        if ($err.PSObject.Properties['Response']) {
            $statusCode = $err.Response.StatusCode.value__
        }
        elseif ($err.PSObject.Properties['ResponseMessage']) {
            $statusCode = $err.ResponseMessage.StatusCode.value__
        }

        $forbidden = ($statusCode -eq 403) -or ($err.Message -match 'Forbidden')

        if ($forbidden -and $err.Message -match 'Client address is not authorized') {
            Write-Status Warning 'Key vault firewall blocked your current IP; trying to add a temporary rule …'
            $kv = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction Stop
            $ipRef = [ref]''
            Ensure-NetworkAccess -VaultName $KeyVaultName -ResourceGroup $kv.ResourceGroupName -AddedIp $ipRef | Out-Null
            $temporaryIp = $ipRef.Value
            try { $secrets = Get-AzKeyVaultSecret -VaultName $KeyVaultName -ErrorAction Stop }
            catch { Write-Status Error 'Still forbidden access after your IP address was added. Check RBAC permissions.'; return }
        }
        elseif ($forbidden) {
            Write-Status Error 'Access denied – it seems like you lack Key Vault RBAC permissions.'
            return
        }
        else {
            throw
        }
    }
    finally {
        if ($temporaryIp) {
            $kv = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction SilentlyContinue
            Remove-TemporaryNetworkAccess -VaultName $KeyVaultName -ResourceGroup $kv.ResourceGroupName -Ip $temporaryIp
        }
    }

    if (-not $secrets) { Write-Status Error 'Key Vault is empty.'; return }
    Write-Status Ok "Found $($secrets.Count) secrets in selected Key Vault."

    $jsonFiles = Get-ChildItem $root -Recurse -Filter 'appsettings*.json' |
    Where-Object { $_.FullName -notmatch '\\(bin|obj|node_modules)\\' }
    if (-not $jsonFiles) { Write-Status Warning 'No appsettings*.json in project.'; return }

    Write-Host "`nSelect appsettings file(s):" -ForegroundColor Cyan
    for ($i = 0; $i -lt $jsonFiles.Count; $i++) { Write-Host "$($i+1)) $($jsonFiles[$i].FullName)" }
    Write-Host 'a) All files'
    do { $sel = Read-Host 'Choose (single option or comma-separated list)' } until ($sel -match '^[0-9,]+$' -or $sel -eq 'a')
    $selected = if ($sel -eq 'a') { $jsonFiles } else { $idx = $sel -split ',' | ForEach-Object { [int]$_ - 1 }; $jsonFiles[$idx] }

    $keys = @{}; $visited = @{}; $counter = 0
    foreach ($f in $selected) {
        Add-FlattenedJsonKeys (Get-Content $f.FullName -Raw | ConvertFrom-Json) '' $keys $visited ([ref]$counter)
    }
    Write-Status Ok "Found $($keys.Count) distinct config keys among the selected appsettings."

    $mappedKeys = @()
    foreach ($secret in $secrets) {
        $keysCsv = Select-ConfigurationKey -SecretName $secret.Name -AvailableKeys $keys
        $localKeyValues = $keysCsv -split ',' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }

        $value = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secret.Name).SecretValueText

        foreach ($configName in $localKeyValues) {
            $value | & dotnet user-secrets set $configName --project $csproj -- | Out-Null
            Write-Status Ok "Saved key vault value '$($secret.Name)' as local secret '$configName'"
            $mappedKeys += $configName
        }
    }

    $unmapped = $keys.Keys |
    ForEach-Object { $_.Trim() } |
    Where-Object { Test-IsPotentialSecretKey $_ } |
    Where-Object { $_ -notin $mappedKeys }

    if ($unmapped) {
        Write-Status Warning 'There are some potential secrets in the appsettings which were not linked to any Key Vault entry:'
        $unmapped | Sort-Object | Get-Unique | ForEach-Object { "  $_" }
    } else {
        Write-Status Ok 'All secrets described by appsettings have been mapped to user secrets.'
    }
}

Export-ModuleMember -Function Sync-AzKeyVaultWithUserSecrets -Alias kv2local
Set-Alias kv2local Sync-AzKeyVaultWithUserSecrets -Option AllScope
