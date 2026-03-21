# Test Windows binary on a native Windows host.
# Covers: smoke test, binary analysis, security hardening.
param(
    [Parameter(Mandatory)][string]$Binary
)

$ErrorActionPreference = "Continue"

# Resolve to absolute path so & can find it
$Binary = (Resolve-Path $Binary).Path
$Pass = 0
$Fail = 0

function Check($Desc, [scriptblock]$Test) {
    try {
        if (& $Test) {
            Write-Host "  PASS: $Desc"
            $script:Pass++
        } else {
            Write-Host "  FAIL: $Desc"
            $script:Fail++
        }
    } catch {
        Write-Host "  FAIL: $Desc ($_)"
        $script:Fail++
    }
}

# --- Smoke tests ---

Write-Host "=== Smoke tests ==="

Check "exists" { Test-Path $Binary }
Check "runs (prints usage with no args)" {
    $output = & $Binary 2>&1 | Out-String
    $LASTEXITCODE -eq 1 -and $output -match "listen"
}

# --- Binary analysis ---

Write-Host ""
Write-Host "=== Binary analysis ==="

$Bytes = [System.IO.File]::ReadAllBytes($Binary)
$BinaryText = [System.Text.Encoding]::ASCII.GetString($Bytes)

Check "is PE executable (MZ header)" {
    [char]$Bytes[0] -eq 'M' -and [char]$Bytes[1] -eq 'Z'
}

# PE32+ (64-bit) has magic 0x020B at the PE optional header
$PeOffset = [BitConverter]::ToInt32($Bytes, 0x3C)
Check "is PE32+ (64-bit)" {
    $Bytes[$PeOffset] -eq 0x50 -and $Bytes[$PeOffset+1] -eq 0x45 -and  # "PE"
    [BitConverter]::ToUInt16($Bytes, $PeOffset + 24) -eq 0x020B          # PE32+
}

# Machine type: detect from binary and validate
$MachineType = [BitConverter]::ToUInt16($Bytes, $PeOffset + 4)
if ($MachineType -eq 0xAA64) {
    Check "architecture is aarch64" { $true }
} elseif ($MachineType -eq 0x8664) {
    Check "architecture is x86_64" { $true }
} else {
    Check "architecture is known (got 0x$($MachineType.ToString('X4')))" { $false }
}

# NumberOfSymbols == 0 means symbols were stripped (by -s linker flag)
$NumSymbols = [BitConverter]::ToUInt32($Bytes, $PeOffset + 12)
Check "is stripped (no symbols)" {
    $NumSymbols -eq 0
}

# Check it's not importing DLLs it shouldn't (should be self-contained)
Check "no msvcrt dependency" {
    -not ($BinaryText -match "msvcrt\.dll")
}

$Size = (Get-Item $Binary).Length
Check "size < 256KB" { $Size -lt 262144 }

# --- Security hardening ---

Write-Host ""
Write-Host "=== Security hardening ==="

# ASLR: DllCharacteristics should have DYNAMIC_BASE (0x0040) and HIGH_ENTROPY_VA (0x0020)
$DllCharsOffset = $PeOffset + 24 + 70  # PE signature + optional header offset to DllCharacteristics
$DllChars = [BitConverter]::ToUInt16($Bytes, $DllCharsOffset)

Check "ASLR enabled (DYNAMIC_BASE)" {
    ($DllChars -band 0x0040) -ne 0
}
Check "high-entropy ASLR (HIGH_ENTROPY_VA)" {
    ($DllChars -band 0x0020) -ne 0
}

# DEP/NX: NX_COMPAT flag (0x0100) in DllCharacteristics
Check "DEP/NX enabled (NX_COMPAT)" {
    ($DllChars -band 0x0100) -ne 0
}

# Stack protector: the "stack smashing detected" error string survives stripping
Check "stack protector active (error string present)" {
    $BinaryText -match "stack smashing detected"
}

# No debug strings leaked into binary
Check "no 'SAS:' debug string" {
    -not ($BinaryText -match "SAS:")
}
Check "no 'handshake complete' debug string" {
    -not ($BinaryText -match "handshake complete.*SAS")
}

# Verify protocol strings are present (sanity check binary isn't corrupted)
Check "protocol string present ('cipher')" {
    $BinaryText -match "cipher"
}

Write-Host ""
Write-Host "=== Results: $Pass passed, $Fail failed ==="
exit $Fail
