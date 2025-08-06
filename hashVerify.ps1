#Blake Miller - 2025

#Check for/grab api key
$check = Read-Host -Prompt "Do you have an API Key for VirusTotal? (Y/N)"

if ($check -eq "Y") {
    $apipath = "$env:onedrive\Documents\vtapi.txt"
    if (Test-Path $apipath) {
        Write-Host "Grabbing api key from $apipath"
        $api = Get-Content $apipath
    }
    else {
        $api = Read-Host -Prompt "Please enter your api key here"
        $api | Out-File -FilePath "$apipath"
        Write-Host "I created the file for you here $apipath"
    }
}
else {
    Write-Host "Please create a VirusTotal Account and get an api key from here: https://www.virustotal.com/gui/join-us"
    $newUser = Read-Host -Prompt "Would you like to go there now? (Y/N)"
    if ($newUser -eq "Y") {
        Start-Process msedge "https://www.virustotal.com/gui/join-us"; exit(0)
    }
    else {
        Write-Host "Please re-run after you have an API key"; exit (0)
    }
}

$headers=@{
    "accept" = "application/json"
    "x-apikey" = "$api"
}

#Determine object to be analyzed
$type = Read-Host -Prompt "Do you have a File or a URL?"

if ($type -eq "File") {
    #Grab the file, then get the md5 hash
    $file = Read-Host -Prompt "Please enter the file path"
    while ($file.Substring($file.Length - 3) -notin "exe", ".7z", ".zip", "msi" ) {
        Write-Host "Please use an .exe, .7z, .zip, or .msi file"
        $file = Read-Host -Prompt "Please enter the file path"
    }
    $hash = certutil -hashfile $file md5 | findstr /v "CertUtil" | findstr /v "hash"
    Write-Host "Computing file hash..."
    $ext = "files/$hash"
    Write-Host "Uploading file hash to VirusTotal..."
}
elseif ($type -eq "URL") {
    #Send the URL
    $url = Read-Host -Prompt "Please enter the URL"
    $encodeUrl = [System.Text.Encoding]::UTF8.GetBytes($url)
    $finalEncode = [System.Convert]::ToBase64String($encodeUrl)
    $finalEncode = $finalEncode.Trim('=')
    $ext = "urls/$finalEncode"
    Write-Host "Uploading file url to VirusTotal..."
}
else {
    Write-Host "A valid option was not selected."; exit(0)
}

#Set URI for later
$uri = "https://www.virustotal.com/api/v3/$ext"

#VirusTotal api request using api key
$response = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers

#$content = ConvertTo-Json $response ####To view data to parse it only

$head = $response.data.attributes.last_analysis_stats

$count1 = ($head.malicious + $head.suspicious + $head.undetected + $head.harmless)
$count2 = $head.harmless
$badcount = ($head.malicious + $head.suspicious)
$stat1 = $head.undetected


#Reply to user, optionally offer to pull up the report in a web page
Write-Host "Out of $count1 total responses ($stat1 undetected), VirusTotal reports $count2 harmless responses and $badcount malicious/suspicious responses. This is an indication of how safe the file is."

if ($badcount -gt 5 ) {
    Write-Host "It appears that $badcount vendors reported this file as malicious, please investigate it further: https://www.virustotal.com/gui/$ext"
    $redirect = Read-Host -Prompt "Would you like to investigate now? (y/n)"
    if ($redirect -eq 'y') {
        Start-Process msedge "https://www.virustotal.com/gui/$ext"
        Write-Host "Redirecting!"
    }
}
else {
    Write-Host "Only $badcount response(s) out of $count1 are malicious/suspicious, this file appears to be safe"
}