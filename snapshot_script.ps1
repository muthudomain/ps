import-module C:\Users\muthu.krishnaraj\Documents\working\ps\ovirt_snap_mod.psm1
$pass = (New-Object System.Management.Automation.PSCredential 'N/A', (ConvertTo-SecureString -String (gc "d:\test\pass.txt"))).GetNetworkCredential().Password
Get-oVirtAuthToken -oVirtServerName $rhev_manager -oVirtPassword $pass

function Wait-oVirtTask($jbdescription, $vmname) 
{
    write-host "Waiting for job to complete.." -nonewline
    if ($jbdescription -eq "create") 
    {
    $jbdesc = "Creating VM Snapshot"
    }
    else { $jbdesc = "Removing Snapshot" }
    sleep 10
    do {
    sleep 10
    }while ((Get-oVirtJob | sort-object start_time | where {$_.description -match $jbdesc -and $_.status -ne "finished"}).status -eq "Started")
    $jbid = (Get-oVirtJob | sort-object start_time | where {$_.description -match $jbdesc -and $_.status -eq "started"}).id
    #write-host "Started" -ForegroundColor Green
    #write-host "waiting for job to complete.." -nonewline
    do {
    sleep 10
    } 
    while ((Get-oVirtJob | where {$_.id -eq $jbid}).status -eq "finished")
    write-host "Completed" -ForegroundColor Green
}

$vms = Get-oVirtvms
$mvmlist = (gc "D:\test\test_snap.csv" | convertfrom-csv)
$mvmlist | %{
    $vmname = $_.name
    $retention = $_.retention
    $vmid = ($vms |where {$_.name -eq $vmname}).id
    $vm_snaps = Get-oVirtVMSnap -id $vmid

    if ($vm_snaps.count -eq 0) 
    {
    write-host "No snap available for $vmname - Hence creating one..."
    $newsnap = New-oVirtVMSnap -vmid $vmid -description "New Snapshot"
    Wait-oVirtTask -vmname $vmname -jbdescription "create"
    write-host "Completed"
    }
    else
    {
        $ids = $vm_snaps.id
        $ids | %{
            write-host "Calculating snapshot retention.." -nonewline
            $timediff = (new-timespan -start $vm_snaps.date -End (get-date)).Days
            write-host "Completed" -ForegroundColor Green
            if ($timediff -ge $retention)
            {
               write-host "Removing exising snapshot with id - $_"
               Remove-oVirtVMSnap -vmid $vmid -snapid $_
               Wait-oVirtTask -vmname $vmname
               
               write-host "Creating New Snapshot.."
               New-oVirtVMSnap -vmid $vmid -description "New Snapshot"
               Wait-oVirtTask -vmname $vmname -jbdescription "create"
               write-host "Completed"
            }
            else { write-host "Snapshot Retention is within limit !" }
        }

    }
}

Disconnect-oVirt
