@{
    RootModule           = 'SyncAzKeyVaultWithUserSecrets.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = 'bc878d04-e435-44c4-acd4-60fb3550bd83'
    Author               = 'Axel M. Kjønsberg'
    Description          = 'Synchronise Azure Key Vault secrets into the local dotnet user-secrets store. Initializes an interactive process for mapping secrets found in the selected key vault.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport    = @('Sync-AzKeyVaultWithUserSecrets')
    CmdletsToExport      = @()
    AliasesToExport      = @('kv2local')

    RequiredModules = @(
        @{ ModuleName = 'Az.Accounts'; ModuleVersion = '2.13.0' },
        @{ ModuleName = 'Az.KeyVault';  ModuleVersion = '5.6.0'  }
    )

    PrivateData          = @{
        PSData = @{
            Tags         = @('Azure', 'KeyVault', 'Secrets', 'dotnet', 'UserSecrets')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/axelkjonsberg/SyncAzKeyVaultWithUserSecrets'
            ReleaseNotes = 'Initial (beta) release'
        }
    }
}
