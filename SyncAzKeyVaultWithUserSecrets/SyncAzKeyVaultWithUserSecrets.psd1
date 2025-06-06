@{
    RootModule           = 'SyncAzKeyVaultWithUserSecrets.psm1'
    ModuleVersion        = '0.1.1'
    GUID                 = 'bc878d04-e435-44c4-acd4-60fb3550bd83'
    Author               = 'Axel M. Kjønsberg'
    Description          = 'Synchronise Azure Key Vault secrets into the local dotnet user-secrets store. Initializes an interactive process for mapping secrets found in the selected key vault.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport    = @('Sync-AzKeyVaultWithUserSecrets')
    CmdletsToExport      = @()
    AliasesToExport      = @('kv2local')

    <#
    RequiredModules = @(
        'Az.Accounts',
        'Az.KeyVault'
    )
    #>

    PrivateData          = @{
        PSData = @{
            Prerelease   = 'beta'
            Tags         = @('Azure', 'KeyVault', 'Secrets', 'dotnet', 'UserSecrets')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/axelkjonsberg/SyncAzKeyVaultWithUserSecrets'
            ReleaseNotes = 'Initial (beta) release'
        }
    }
}
