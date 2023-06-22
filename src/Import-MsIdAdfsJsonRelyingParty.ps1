<#
.SYNOPSIS
    Imports a list availabe sample AD FS relyng party trust applications available in this module, the list is created by the Get-MsIdAdfsSampleApps cmdlet. These applications do NOT use real endpoints and are meant to be used as test applications.
.EXAMPLE
    PS >Get-ADFSRelyingPartyTrust -Name "App" | ConvertTo-Json | Import-MsIdAdfsJsonRelyingParty -Name "Test App"

    Import the full list of sample AD FS apps to the local AD FS server.

.EXAMPLE
    PS >Get-ADFSRelyingPartyTrust -Name "App" | ConvertTo-Json | Out-File .\app.json
    PS >Get-Content .\app.json | ConvertFrom-Json | Import-MsIdAdfsJsonRelyingParty –Name "Test App"

    Import the full list of sample AD FS apps to the local AD FS server.
#>
function Import-MsIdAdfsJsonRelyingParty {
    [CmdletBinding()]
    param(
      # Application identifier
      [Parameter(Mandatory=$true,
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
      [object]$RelyingParty,
      # Name for the AD FS relying party
      [Parameter(Mandatory=$true)]
      [string]$Name,
      # Include additional reply URI to the AD FS relying party
      [Parameter(Mandatory=$false)]
      [string]$ResponseUri = "",
      # Apply file parameters to existing apps
      [Parameter(Mandatory=$false)]
      [switch]$Force = $false
    )

    if (Import-AdfsModule) {
        Try {
            Write-Verbose "Processing app '$($RelyingParty.Name)' using the name '$($Name)'"

            $targetIdentifier = $RelyingParty.Identifier
        
            $adfsApp = Get-ADFSRelyingPartyTrust -Name $Name
            if ($null -eq $adfsApp) {
                Write-Verbose "Creating application '$($Name)'"
                $adfsApp = Add-ADFSRelyingPartyTrust -Identifier $targetIdentifier -Name $Name
            }            
            else {
                if (-not $Force) {
                    throw "The application '" + $Name + "' already exists, use -Force to ovewrite it."
                }
                Write-Verbose "Updating application '$($Name)'"
            }

            Set-ADFSRelyingPartyTrust -TargetName $Name -AutoUpdateEnabled $RelyingParty.AutoUpdateEnabled
            Set-ADFSRelyingPartyTrust -TargetName $Name -DelegationAuthorizationRules $RelyingParty.DelegationAuthorizationRules
            Set-ADFSRelyingPartyTrust -TargetName $Name -IssuanceAuthorizationRules $RelyingParty.IssuanceAuthorizationRules
            Set-ADFSRelyingPartyTrust -TargetName $Name -WSFedEndpoint $RelyingParty.WSFedEndpoint
            Set-ADFSRelyingPartyTrust -TargetName $Name -IssuanceTransformRules $RelyingParty.IssuanceTransformRules
            Set-ADFSRelyingPartyTrust -TargetName $Name -ClaimAccepted $RelyingParty.ClaimsAccepted
            Set-ADFSRelyingPartyTrust -TargetName $Name -EncryptClaims $RelyingParty.EncryptClaims
            Set-ADFSRelyingPartyTrust -TargetName $Name -EncryptionCertificate $RelyingParty.EncryptionCertificate
            Set-ADFSRelyingPartyTrust -TargetName $Name -MetadataUrl $RelyingParty.MetadataUrl
            Set-ADFSRelyingPartyTrust -TargetName $Name -MonitoringEnabled $RelyingParty.MonitoringEnabled
            Set-ADFSRelyingPartyTrust -TargetName $Name -NotBeforeSkew $RelyingParty.NotBeforeSkew
            Set-ADFSRelyingPartyTrust -TargetName $Name -ImpersonationAuthorizationRules $RelyingParty.ImpersonationAuthorizationRules
            Set-ADFSRelyingPartyTrust -TargetName $Name -ProtocolProfile $RelyingParty.ProtocolProfile
            Set-ADFSRelyingPartyTrust -TargetName $Name -RequestSigningCertificate $RelyingParty.RequestSigningCertificate
            Set-ADFSRelyingPartyTrust -TargetName $Name -EncryptedNameIdRequired $RelyingParty.EncryptedNameIdRequired
            Set-ADFSRelyingPartyTrust -TargetName $Name -SignedSamlRequestsRequired $RelyingParty.SignedSamlRequestsRequired  
        
            $newSamlEndPoints = @()
            foreach ($SamlEndpoint in $RelyingParty.SamlEndpoints) {
                # Is ResponseLocation defined?
                if ($SamlEndpoint.ResponseLocation) {
                    # ResponseLocation is not null or empty
                    $newSamlEndPoint = New-ADFSSamlEndpoint -Binding $SamlEndpoint.Binding `
                        -Protocol $SamlEndpoint.Protocol `
                        -Uri $SamlEndpoint.Location -Index $SamlEndpoint.Index `
                        -IsDefault $SamlEndpoint.IsDefault `
                        -ResponseUri $SamlEndpoint.ResponseLocation
                }
                else {
                    $newSamlEndPoint = New-ADFSSamlEndpoint -Binding $SamlEndpoint.Binding `
                        -Protocol $SamlEndpoint.Protocol `
                        -Uri $SamlEndpoint.Location -Index $SamlEndpoint.Index `
                        -IsDefault $SamlEndpoint.IsDefault
                }
                $newSamlEndPoints += $newSamlEndPoint
            }
            Set-ADFSRelyingPartyTrust -TargetName $Name -SamlEndpoint $newSamlEndPoints

            # Add another SAML redirect URI if provided
            if ($ResponseUri -ne "") { 
                Add-MsIdAdfsRelyingPartySamlResponseUri -Name $Name -ResponseUri $ResponseUri
            }

            Set-ADFSRelyingPartyTrust -TargetName $Name -SamlResponseSignature $RelyingParty.SamlResponseSignature
            Set-ADFSRelyingPartyTrust -TargetName $Name -SignatureAlgorithm $RelyingParty.SignatureAlgorithm
            Set-ADFSRelyingPartyTrust -TargetName $Name -TokenLifetime $RelyingParty.TokenLifetime

            # check if access control policy exists
            if ($RelyingParty.AccessControlPolicyName -ne $adfsApp.AccessControlPolicyName) {
                if (Get-AdfsAccessControlPolicy -Name $RelyingParty.AccessControlPolicyName) {
                    Set-AdfsRelyingPartyTrust -TargetName $Name -AccessControlPolicyName $RelyingParty.AccessControlPolicyName
                }
                else {
                    Write-Warning "The Access Control Policy '$($RelyingParty.AccessControlPolicyName)' is missing, run 'Import-MsIdAdfsJsonAccessPolicy' to import the policy."
                }
            }
        }            
        Catch {
            Write-Error $_
        }
    }
    else {
        Write-Error "The Import-MsIdAdfsJsonRelyingParty cmdlet requires the ADFS module installed to work."
    }
}