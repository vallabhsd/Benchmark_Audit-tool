# Suppress background process output
$PSEmailServer = "localhost"  # Temporary workaround to hide background jobs

# Define the path to the Audits folder
$auditsPath = "./Audits"

# Loop through Audit_1.ps1 to Audit_12.ps1 and run them in sequence
for ($i = 1; $i -le 12; $i++) {
    $scriptPath = Join-Path -Path $auditsPath -ChildPath "Audit_$i.ps1"
    
    # Check if the script exists before running
    if (Test-Path $scriptPath) {
        Write-Host "Running $scriptPath..."
        # Run the script silently and hide background processes
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-ExecutionPolicy Bypass", "-File", $scriptPath -NoNewWindow -Wait | Out-Null
    } else {
        Write-Host "Script $scriptPath not found!"
    }
}
