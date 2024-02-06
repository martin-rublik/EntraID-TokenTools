Add-Type -AssemblyName "System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"

$modulePath = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)

# Export functions
foreach($importScript in $(ls "$modulePath\public\*.ps1"))
{
    try
    {
        . $importScript.fullName
        Export-ModuleMember -Function $importScript.Name.Replace(".ps1","")
    }catch
    {
        Write-Error "Failed to import $($importScript.FullName): $_"
    }
}