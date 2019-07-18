# totally ripped off and butchered (ahem, I mean carefully incised) from
# Jana Sattainathan [Twitter: @SQLJana] [Blog: sqljana.wordpress.com]
# https://sqljana.wordpress.com/2017/08/31/powershell-get-security-updates-list-from-microsoft-by-monthproductkbcve-with-api/
# all credit goes to Jana for saving me about a million hours


#region initialise

$DebugPreference = "Continue"

# environment variables
$currentuser = $env:USERNAME
$homepath = "C:\Users\$currentuser\documents"
$filename = "$homepath\MS_Monthly_CVE.csv"
$filename_raw = "$homepath\MS_Monthly_Raw.csv"
$APIKey = 'your_api_key_here'

# hardcoded month
$monthofInterest = '2019-Jul'

# import modules. Must be already saved in C:\Users\$env:USERNAME\Documents\Windows PowerShell\Modules
import-module MSrcSecurityUpdates

# send API key to enable functionality
Set-MSRCApiKey -ApiKey $APIKey

# unhide cursor to show activity
[Console]::CursorSize = 25

#endregion initialise


#region process

write-host "{*} Downloading monthly rollup data from Microsoft. Please wait..." -ForegroundColor Green

$reportdata = Get-MsrcCvrfDocument -ID  $MonthOfInterest | Get-MsrcCvrfAffectedSoftware

# Facts about raw data in $reportData
#
# 1) A single product can have multiple KB's associated with it
# 2) A single KB could be associated with multiple CVE's
# 3) A single raw row could have single or multiple KB's
# 4) A CVE could be associated with multiple products/KB's
# 5) For a single KB and product combination, "Severity, Impact, Restart required" could all be different. Eg: 3191828
# 6) Each raw row has
#       FullProductName - SingleValue
#       KBArticle       - Hashtable (EMPTY! in some cases)
#       CVE             - SingleValue
#       Severity        - SingleValue
#       Impact          - SingleValue
#       RestartRequired - Array (count matches Superdedence) but all values will be the same
#       Supercedence    - Array (count matches RestartRequired) but each array value is distinct
#       CvssScoreSet    - HashTable
# given the above,
# depending on the what you want to look at the data by,
# "Severity, Impact, RestartRequired" may be approximations (first or last occurance)


# these hashtables will hold specific associations as key and value as csv
[hashtable]$cveByProductHash = @{}
[hashtable]$kbByProductHash = @{}
[hashtable]$productByKBHash = @{}
[hashtable]$cveByKBHash = @{}
[hashtable]$kbByCVEHash = @{}
[hashtable]$productByCVEHash = @{}
 
# these hashtables will hold all data values as objects by the keys
[hashtable]$cveByProductHashData = @{}
[hashtable]$kbByProductHashData = @{}
[hashtable]$productByKBHashData = @{}
[hashtable]$cveByKBHashData = @{}
[hashtable]$kbByCVEHashData = @{}
[hashtable]$productByCVEHashData = @{}

foreach($row in $reportData) {
            
# there is only one CVE per raw row
    $cveByProductHash[$row.FullProductName] += ($row.CVE + ';')
 
# there are multiple KB's per raw row
    foreach($kb in $row.KBArticle) {
 
        # ----- By CVE --------
        $kbByCVEHashData[$row.CVE] = [pscustomobject]@{
            'CVE' = $row.CVE
            'Severity'= $row.severity
            'Impact'= $row.impact
            'CVSS_base' = $row.CvssScoreSet.base
            'CVSS_temporal' = $row.CvssScoreSet.temporal
            'CVSS_vector' = $row.CvssScoreSet.vector
        }
    }
}

<# This is a hangover from the old script, kept purely for reference if different results are required.

switch ($resultType)
        {
            'RAW'           {$reportData}
            'CVEByProduct'  {$cveByProductHashData.Values}
            'KBByProduct'   {$kbByProductHashData.Values}
            'ProductByKB'   {$productByKBHashData.Values}
            'CVEByKB'       {$cveByKBHashData.Values}
            'KBByCVE'       {$kbByCVEHashData.Values}
            'ProductByCVE'  {$productByCVEHashData.Values}
        }
#>


# unfiltered output file for data integrity checking
write-host "{*} Producing raw csv...(for sanity checking)" -ForegroundColor Green
$reportData | Export-Csv $filename_raw

# filtered on CVE
Write-Host "{*} Producing consolidated csv..." -ForegroundColor Green
$kbByCVEHashData.Values | Export-Csv $filename

#endregion process


#region finalise

# tidy up CSV file
(Get-Content $filename | Select-Object -Skip 1) | Set-Content $filename
(Get-Content $filename_raw | Select-Object -Skip 1) | Set-Content $filename_raw

# open files
.$filename
.$filename_raw

#endregion finalise
