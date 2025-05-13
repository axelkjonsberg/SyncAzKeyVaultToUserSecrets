$ModulePath = "$PSScriptRoot\SyncAzKeyVaultWithUserSecrets"
Publish-Module -Path $ModulePath -NuGetApiKey $Env:PSGALLERY_API_KEY