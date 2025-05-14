$ErrorActionPreference = 'Stop'

$ModulePath = Join-Path $PSScriptRoot 'SyncAzKeyVaultWithUserSecrets'

Publish-Module `
     -Path $ModulePath `
     -Repository 'PSGallery' `
     -NuGetApiKey $Env:PSGALLERY_API_KEY `
     -AllowPrerelease `
     -SkipAutomaticDependencyCheck
