<#
.SYNOPSIS
    Imports the 'MsId Block Off Corp and VPN' sample AD FS access control policy. This policy is meant to be used as test policy.
.DESCRIPTION
    Imports the 'MsId Block Off Corp and VPN' sample AD FS access control policy. Pass locations in the format of range (205.143.204.1-205.143.205.250) or CIDR (12.159.168.1/24).

    This policy is meant to be used as test policy!
.EXAMPLE
    PS >Import-MsIdAdfsJsonAccessPolicy

    Create the policy to the local AD FS server.

#>
function Import-MsIdAdfsJsonAccessPolicy {
    [CmdletBinding()]
    param(
      # Access control policy name
      [Parameter(Mandatory=$true)]
      [string[]]$Name,
      # Network locations 
      [Parameter(Mandatory=$true)]
      [string[]]$MetadataPath,
      # Relying party names to apply the policy
      [Parameter(Mandatory=$false)]
      [string[]]$ApplyTo
    )

    if (Import-AdfsModule) {
        Try {
            # load and update metadata file
            $metadataStr = Get-Content $MetadataPath -Raw
            $metadata = New-Object -TypeName Microsoft.IdentityServer.PolicyModel.Configuration.PolicyTemplate.PolicyMetadata -ArgumentList $metadataStr

            $policy = Get-AdfsAccessControlPolicy -Name $Name
            if ($null -eq $policy) {
                Write-Verbose "Creating Access Control Policy $($Name)"
                $null = New-AdfsAccessControlPolicy -Name $Name -Identifier $Name.Replace(" ", "") -PolicyMetadata $metadata
            }
            else {
                throw "The policy '" + $Name + "' already exists."
            }

            if ($null -ne $ApplyTo) {
                foreach ($app in $ApplyTo) {
                    Set-AdfsRelyingPartyTrust -TargetName $app -AccessControlPolicyName $Name
                }
            }
        }            
        Catch {
            Write-Error $_
        }
    }
    else {
        Write-Error "The Import-MsIdAdfsJsonAccessPolicy cmdlet requires the ADFS module installed to work."
    }
}