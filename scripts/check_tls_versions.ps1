# MASTG-TEST-0217/0218 - Verificador de versiones TLS contra endpoints de Yoosee
$openssl = "C:\Program Files\Git\usr\bin\openssl.exe"
if (-not (Test-Path $openssl)) {
    $found = (Get-Command openssl -ErrorAction SilentlyContinue)
    if ($found) { $openssl = $found.Source } else { Write-Host "[!] openssl no encontrado"; exit 1 }
}

$endpoints = @(
    @{ H = "openapi-iot.cloudlinks.cn"; P = 443; C = "Cloudlinks core" },
    @{ H = "api1.cloudlinks.cn"; P = 443; C = "Cloudlinks API" },
    @{ H = "api2.cloudlinks.cn"; P = 443; C = "Cloudlinks API" },
    @{ H = "api3.cloud-links.net"; P = 443; C = "Cloudlinks DE" },
    @{ H = "api4.cloud-links.net"; P = 443; C = "Cloudlinks DE" },
    @{ H = "saas-playback.cloudlinks.cn"; P = 443; C = "Cloudlinks playback" },
    @{ H = "datasink.cloudlinks.cn"; P = 443; C = "Cloudlinks datasink" },
    @{ H = "customservicesystem.cloudlinks.cn"; P = 443; C = "Cloudlinks soporte" },
    @{ H = "android.bugly.qq.com"; P = 443; C = "Bugly Tencent" },
    @{ H = "share.yoosee.co"; P = 443; C = "Yoosee web" },
    @{ H = "www.yoosee.co"; P = 443; C = "Yoosee web" }
)

$versions = @(
    @{ Name = "TLS 1.0"; Flag = "-tls1" },
    @{ Name = "TLS 1.1"; Flag = "-tls1_1" },
    @{ Name = "TLS 1.2"; Flag = "-tls1_2" },
    @{ Name = "TLS 1.3"; Flag = "-tls1_3" }
)

Write-Host ""
Write-Host "[*] Probando negociacion TLS contra endpoints de Yoosee con openssl s_client"
Write-Host "[*] Openssl: $openssl"
Write-Host ""
Write-Host ("{0,-40} {1,-18} {2,-9} {3,-9} {4,-9} {5,-9}" -f "Endpoint", "Categoria", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3")
Write-Host ("-" * 100)

$insecureEndpoints = @()
$secureEndpoints = @()

foreach ($ep in $endpoints) {
    $target = $ep.H
    $portnum = $ep.P
    $catName = $ep.C
    $row = "{0,-40} {1,-18} " -f $target, $catName
    $accepts10 = $false
    $accepts11 = $false

    foreach ($v in $versions) {
        $flag = $v.Flag
        $verName = $v.Name
        # Ejecutar openssl con timeout corto; enviar Q al final y leer salida
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $openssl
        $psi.Arguments = "s_client -connect ${target}:${portnum} $flag -no_ign_eof"
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardInput = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true

        $proc = [System.Diagnostics.Process]::Start($psi)
        # Cerrar stdin para que openssl termine rapidamente
        $proc.StandardInput.Close()
        # Esperar max 6 segundos
        if (-not $proc.WaitForExit(6000)) {
            $proc.Kill()
        }
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $combined = $stdout + "`n" + $stderr
        $proc.Close()

        # Determinar si el handshake fue exitoso
        $hasProtocol = $combined -match "Protocol\s*:\s*TLS"
        $hasCipher   = $combined -match "Cipher\s*:"
        $hasAlert    = $combined -match "alert (handshake failure|protocol version)|wrong version number|handshake failure"

        if ($hasProtocol -or $hasCipher) {
            $cell = "OK"
            if ($verName -eq "TLS 1.0") { $accepts10 = $true }
            if ($verName -eq "TLS 1.1") { $accepts11 = $true }
        } elseif ($hasAlert) {
            $cell = "NO"
        } else {
            $cell = "ERR"
        }
        $row += ("{0,-9} " -f $cell)
    }
    Write-Host $row

    if ($accepts10 -or $accepts11) {
        $insecureEndpoints += $target
    } else {
        $secureEndpoints += $target
    }
}

Write-Host ""
Write-Host "[*] === RESUMEN DEL HALLAZGO (L10) ==="
Write-Host ""
if ($insecureEndpoints.Count -gt 0) {
    Write-Host "    [NO CUMPLE] $($insecureEndpoints.Count) endpoint(s) aceptan TLS 1.0 o TLS 1.1:"
    foreach ($h in $insecureEndpoints) { Write-Host "      - $h" }
} else {
    Write-Host "    [CUMPLE] Ningun endpoint acepta TLS 1.0 o TLS 1.1"
}
if ($secureEndpoints.Count -gt 0) {
    Write-Host ""
    Write-Host "    Endpoints que solo aceptan TLS 1.2+ (seguros):"
    foreach ($h in $secureEndpoints) { Write-Host "      - $h" }
}
Write-Host ""
Write-Host "[*] Leyenda: OK=acepta la version, NO=rechaza, ERR=error de red"
