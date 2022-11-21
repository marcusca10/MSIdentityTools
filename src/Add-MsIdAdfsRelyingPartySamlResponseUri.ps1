<#
.SYNOPSIS
        Imports a list availabe sample AD FS relyng party trust applications available in this module, the list is created by the Get-MsIdAdfsSampleApps cmdlet. These applications do NOT use real endpoints and are meant to be used as test applications.
.EXAMPLE
    PS >Add-MsIdAdfsRelyingPartySamlResponseUri

    Import the full list of sample AD FS apps to the local AD FS server.
#>
function Add-MsIdAdfsRelyingPartySamlResponseUri {
    [CmdletBinding()]
    param(
      # Name for the AD FS relying party
      [Parameter(Mandatory=$true,
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
      [string]$Name,
      # Additional SAML response URI to the AD FS relying party
      [Parameter(Mandatory=$true)]
      [string]$ResponseUri
    )

    if (Import-AdfsModule) {
        $index = 0

        $samlEndPoints =  Get-ADFSRelyingPartyTrust -Name $Name | select -ExpandProperty SamlEndpoint

        # Find next available index
        if ($samlEndPoints) {
            $index = 0
        }

        $newSamlEndPoint = New-ADFSSamlEndpoint -Binding 'POST' -Protocol 'SAMLAssertionConsumer' `
            -Uri $ResponseUri -Index $index

        $samlEndPoints += $newSamlEndPoint

        Set-ADFSRelyingPartyTrust -TargetName $Name -SamlEndpoint $samlEndPoints
    }
    else {
        Write-Error "The Add-MsIdAdfsRelyingPartySamlResponseUri cmdlet requires the ADFS module installed to work."
    }
}