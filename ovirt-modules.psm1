    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {
        $certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
        Add-Type $certCallback
        }
        [ServerCertificateValidationCallback]::Ignore()
    



function Get-oVirtAuthToken
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([string])]
    Param
    (
        #Address of oVirt server (must be FQDN)
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtServerName,

        #Username for oVirt (admin is default)
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtUsername = 'admin',

        #Password for the oVirt user to authenticate as
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtPassword,

        #domain the oVirt user belongs to (default is internal)
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtDomain = 'internal'
    )
        write-host ServerName: $oVirtServerName, password: $oVirtPassword username: $oVirtUsername Domain: $oVirtDomain
        if (Test-Connection -ComputerName $oVirtServerName -count 2) 
        {
            $AuthPayload = "grant_type=password&scope=ovirt-app-api&username=$oVirtUsername%40$oVirtDomain&password=$oVirtPassword"
            Write-Verbose "Auth Payload: $AuthPayload"
            $AuthHeaders = @{"Accept" = "application/json"}
            $URI = "https://$oVirtServerName/ovirt-engine/sso/oauth/token"
            Write-Verbose "Auth URI: $URI"
            $AuthResponse = Invoke-WebRequest -Uri $URI -Method Post -body $AuthPayload -Headers $AuthHeaders -ContentType 'application/x-www-form-urlencoded'
            Write-Verbose "Raw Response: $AuthResponse"
            $AuthToken = ((($AuthResponse.Content) -split '"')[3])
            $env:token = $AuthToken
            $env:oVirtServer = $oVirtServerName
            $env:tok_time = (get-date)
            return $AuthToken
        }
        else
        {
            $response = "404"
            Write-Verbose $reponse
            return $response
        }
   
}

function Get-oVirtClusterList
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([string])]
    Param
    (
        #Address of oVirt server (must be FQDN)
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtServerName = $env:oVirtServer,

        #AuthToken for oVirt server (use Get-oVirtAuthToken to obtain)
        [string][Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtAuthToken = $env:token
    )
    $Headers = @{'Authorization' = "Bearer $oVirtAuthToken"; "Accept" = "application/xml"}
    Write-Verbose $Headers
    $URI = "https://$oVirtServerName/ovirt-engine/api/clusters"
    Write-Verbose "URI: $URI"
    $Response = Invoke-WebRequest -Uri $URI -Method get -Headers $Headers -ContentType 'application/x-www-form-urlencoded' 
    Write-Verbose "Raw Response: $Response"
    $VerboseResponseContent = $Response.Content
    Write-Verbose "Response Content: $VerboseResponseContent"
    [xml]$ResponseContent = $Response.Content
    return $ResponseContent.clusters.cluster
}

function Get-oVirtvms
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([string])]
    Param
    (
        #Address of oVirt server (must be FQDN)
        [Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtServerName = $env:oVirtServer,

        #AuthToken for oVirt server (use Get-oVirtAuthToken to obtain)
        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtAuthToken = $env:token,

        #(To obtain the name of the vm)
        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $vmName
    )

    $Headers = @{'Authorization' = "Bearer $oVirtAuthToken"; "Accept" = "application/xml"}
    Write-Verbose $Headers
    $URI = "https://$oVirtServerName/ovirt-engine/api/vms"
    Write-Verbose "URI: $URI"
    $VMResponse = Invoke-WebRequest -Uri $URI -Method get -Headers $Headers
    Write-Verbose "Raw Response: $VMResponse"
    $VerboseResponseContent = $VMResponse.Content
    Write-Verbose "Response Content: $VerboseResponseContent"
    [xml]$VMResponseContent = $VMResponse.Content
    if ($name -eq $null)
    {
    return $VMResponseContent.vms.vm
    }
    else
    {
    return $VMResponseContent.vms.vm | where {$_.name -eq $vmName}
    }
}


function Get-StorageDomain
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([string])]
    Param
    (
        #Address of oVirt server (must be FQDN)
        [Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtServerName = $env:oVirtServer,

        #AuthToken for oVirt server (use Get-oVirtAuthToken to obtain)
        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtAuthToken = $env:token,

        #(To obtain the name of the StorageDomain)
        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $name
    )

    $Headers = @{'Authorization' = "Bearer $oVirtAuthToken"; "Accept" = "application/xml"}
    Write-output $name
    $URI = "https://$oVirtServerName/ovirt-engine/api/storagedomains/"
    Write-Verbose "URI: $URI"
    $sdResponse = Invoke-WebRequest -Uri $URI -Method get -Headers $Headers 
    Write-Verbose "Raw Response: $sdResponse"
    $VerboseResponseContent = $sdResponse.Content
    Write-Verbose "Response Content: $VerboseResponseContent"
    [xml]$sdResponseContent = $sdResponse.Content
#    if ($name -eq $null)
#    {
        return $sdResponseContent.storage_domains.storage_domain
#    }
#    else
#    {
#        return $sdResponseContent.storage_domains.storage_domain | where {$_.name -eq $name}
#    }
}

Function Get-DiskMoveData {

    [CmdletBinding()]
    [Alias()]
    [OutputType([string])]
    Param
    (
        #Target Storage ID
        [Parameter(Mandatory=$true,
                   Position=0)]
        $TargetSDID

        )

        $dt = '<action><storage_domain id="' + $TargetSDID + '" /></action>'
        return $dt

}

Function Move-DiskSD ($vmdiskid, $targetsdid) {
    $Headers = @{'Authorization' = "Bearer $env:token"; "Accept" = "application/xml"}
    Write-Verbose $Headers
    $dsURI = "https://$env:oVirtServer/ovirt-engine/api/disks/" + $vmdiskid + '/move'
    $dskResponse = Invoke-WebRequest -Uri $dsURI -Method Post -Headers $Headers -body (Get-DiskMoveData -TargetSDID $targetsdid) -ContentType 'application/xml'
    [xml]$mvresponse = $dskresponse.Content
    return $mvresponse.action.status
}

function Get-DisksFromSD
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([string])]
    Param
    (
        #Address of oVirt server (must be FQDN)
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtServerName = $env:oVirtServer,

        #AuthToken for oVirt server (use Get-oVirtAuthToken to obtain)
        [string][Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtAuthToken = $env:token,

        #(To obtain the name of the vm)
        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $dskName
    )

    $Headers = @{'Authorization' = "Bearer $oVirtAuthToken"; "Accept" = "application/xml"}
    Write-Verbose $Headers
    $URI = "https://$oVirtServerName/ovirt-engine/api/disks/"
    Write-output "URI: $URI"
    $sdResponse = Invoke-WebRequest -Uri $URI -Method get -Headers $Headers 
    Write-Verbose "Raw Response: $sdResponse"
    $VerboseResponseContent = $sdResponse
    Write-Verbose "Response Content: $VerboseResponseContent"
    [xml]$sdResponseContent = $sdResponse.Content
    if ($sdName -eq $null)
    {
        return $sdResponseContent.disks.disk
    }
    else
    {
        return $sdResponseContent.disks.disk | where {$_.name -eq $sdName}
    }
}


function Get-oVirtJob
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([string])]
    Param
    (
        #Address of oVirt server (must be FQDN)
        [Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtServerName = $env:oVirtServer,

        #AuthToken for oVirt server (use Get-oVirtAuthToken to obtain)
        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtAuthToken = $env:token
    )

    $Headers = @{'Authorization' = "Bearer $oVirtAuthToken"; "Accept" = "application/xml"}
    Write-Verbose $Headers
    $URI = "https://$oVirtServerName/ovirt-engine/api/jobs"
    Write-Verbose "URI: $URI"
    $JbResponse = Invoke-WebRequest -Uri $URI -Method get -Headers $Headers
    Write-Verbose "Raw Response: $JbResponse"
    [xml]$JbResponseContent = $JbResponse.Content
    return $JbResponseContent.jobs.job
}

function Get-oVirtVMDisk
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([string])]
    Param
    (
        #Address of oVirt server (must be FQDN)
        [Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtServerName = $env:oVirtServer,

        #AuthToken for oVirt server (use Get-oVirtAuthToken to obtain)
        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtAuthToken = $env:token,

        #(To obtain the name of the vm)
        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $id
    )

    $Headers = @{'Authorization' = "Bearer $oVirtAuthToken"; "Accept" = "application/xml"}
    Write-Verbose $Headers
    $URI = "https://$oVirtServerName/ovirt-engine/api/vms/$id/diskattachments"
    Write-Verbose "URI: $URI"
    $VMDskResponse = Invoke-WebRequest -Uri $URI -Method get -Headers $Headers
    Write-Verbose "Raw Response: $VMResponse"
    $VMDskResponseContent = $VMDskResponse.Content
    
    [xml]$VMDskResponseContent = $VMDskResponse.Content
    return $VMDskResponseContent.disk_attachments.disk_attachment
}

Function Get-oVirtVMSnap
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([string])]
    Param
    (
        #Address of oVirt server (must be FQDN)
        [Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtServerName = $env:oVirtServer,

        #AuthToken for oVirt server (use Get-oVirtAuthToken to obtain)
        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtAuthToken = $env:token,

        #(To obtain the name of the vm)
        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $id
    )

    $Headers = @{'Authorization' = "Bearer $oVirtAuthToken"; "Accept" = "application/xml"}
    Write-Verbose $Headers
    $URI = "https://$oVirtServerName/ovirt-engine/api/vms/$id/snapshots"
    Write-Verbose "URI: $URI"
    $snpResponse = Invoke-WebRequest -Uri $URI -Method get -Headers $Headers
    Write-Verbose "Raw Response: $snpResponse"
    [xml]$snpDskResponseContent = $snpResponse.Content
    return $snpDskResponseContent.snapshots.snapshot | where {$_.snapshot_type -eq "regular"}
}


Function Create-oVirtVMSnap {
    [CmdletBinding()]
    [Alias()]
    [OutputType([string])]
    Param
    (
        #Address of oVirt server (must be FQDN)
        [Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtServerName = $env:oVirtServer,

        #AuthToken for oVirt server (use Get-oVirtAuthToken to obtain)
        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtAuthToken = $env:token,

        #(To obtain the name of the vm)
        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $vmid, 

        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $description
    )
    $Headers = @{'Authorization' = "Bearer $env:token"; "Accept" = "application/xml"}
    Write-Verbose $Headers
    $description = $description + " - Created on " + ((get-date).ToShortDateString()).replace("/","-")
    $bdy = "<snapshot><description>" + $description + "</description></snapshot>"
    $newsnpURI = "https://$env:oVirtServer/ovirt-engine/api/vms/" + $vmid + '/snapshots'
    $newsnpResponse = Invoke-WebRequest -Uri $newsnpURI -Method Post -Headers $Headers -body $bdy -ContentType 'application/xml'
    [xml]$snpresponse = $newsnpResponse.Content
    return $snpresponse.snapshot.status
}

Function Remove-oVirtVMSnap {
    [CmdletBinding()]
    [Alias()]
    [OutputType([string])]
    Param
    (
        #Address of oVirt server (must be FQDN)
        [Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtServerName = $env:oVirtServer,

        #AuthToken for oVirt server (use Get-oVirtAuthToken to obtain)
        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $oVirtAuthToken = $env:token,

        #(To obtain the name of the vm)
        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $vmid, 

        [string][Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $snapid
    )
    $Headers = @{'Authorization' = "Bearer $env:token"; "Accept" = "application/xml"}
    Write-Verbose $Headers
    $delsnpURI = "https://$env:oVirtServer/ovirt-engine/api/vms/" + $vmid + '/snapshots/' + $snapid
    $delsnpResponse = Invoke-WebRequest -Uri $delsnpURI -Method Delete -Headers $Headers -ContentType 'application/xml'
    [xml]$delsnpresponsexml = $delsnpResponse.Content
    return $delsnpresponsexml.action.status
}

Function Disconnect-oVirt {
    Remove-Item env:\token
    Remove-Item env:\tok_time
}

Export-ModuleMember -Function 'Get-*'
Export-ModuleMember -Function 'Move-*'
Export-ModuleMember -Function 'Disconnect-*'
