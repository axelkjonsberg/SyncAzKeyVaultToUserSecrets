# SyncAzKeyVaultWithUserSecrets

`Sync-AzKeyVaultWithUserSecrets` is a PowerShell command that copies **all secrets from an Azure Key Vault** into the **local `dotnet user‑secrets` store** of the nearest .NET project.

---

## Requirements

* PowerShell **5.1** or newer (Windows) **or** PowerShell **7+** (cross‑platform).
* .NET SDK **5.0 or newer** installed (`dotnet` CLI).
* Azure PowerShell modules **Az.Accounts ≥ 2.12.0** and **Az.KeyVault ≥ 4.10.0**.
* Permissions to read secrets in the specified Key Vault.

---

## Installation

### Through PowerShell Gallery

```powershell
Install-Module SyncAzKeyVaultWithUserSecrets
```

*(or follow the instructions at [https://www.powershellgallery.com/packages/SyncAzKeyVaultWithUserSecrets](https://www.powershellgallery.com/packages/SyncAzKeyVaultWithUserSecrets))*

### Manual Installation

1. Copy **`SyncAzKeyVaultWithUserSecrets.psm1`** and **`SyncAzKeyVaultWithUserSecrets.psd1`** into
   a folder named **`SyncAzKeyVaultWithUserSecrets`** that sits in any path listed in `$env:PSModulePath`.
   Example:

   ```powershell
   $moduleRoot = "$HOME\Documents\PowerShell\Modules\SyncAzKeyVaultWithUserSecrets"
   New-Item -ItemType Directory -Path $moduleRoot -Force
   Copy-Item .\*.psm1,*.psd1 -Destination $moduleRoot
   ```

2. Import the module:

   ```powershell
   Import-Module SyncAzKeyVaultWithUserSecrets
   ```

---

## Usage

```powershell
Sync-AzKeyVaultWithUserSecrets -KeyVaultName "<vault-name>"
```

### Parameters

| Parameter           | Type     | Mandatory | Description                                                   |
| ------------------- | -------- | --------- | ------------------------------------------------------------- |
| **`-KeyVaultName`** | *String* | **Yes**   | Name of the Azure Key Vault whose secrets you want to use locally in your .NET project. |

---

## Examples

### Example 1: Basic synchronisation

```powershell
Sync-AzKeyVaultWithUserSecrets -KeyVaultName "my-kv-dev"
```

*Walks up to the first .csproj, prompts you to map each secret, stores them with `dotnet user‑secrets`.*

### Example 2: Run from a nested folder

```powershell
Set-Location src\Api
Sync-AzKeyVaultWithUserSecrets -KeyVaultName "my-kv-test"
```

---

## Contributing

Issues, ideas and pull requests are welcome!

1. Fork the repository: [https://github.com/axelkjonsberg/SyncAzKeyVaultToUserSecrets](https://github.com/axelkjonsberg/SyncAzKeyVaultToUserSecrets)
2. Create a feature branch (`git checkout -b feature/some-concisely-named-improvement`)
3. Commit your changes and open a PR.
