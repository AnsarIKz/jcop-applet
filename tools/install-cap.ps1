param(
    [string]$GpJar = "./tools/gp.jar",
    [string]$CapPath = "",
    [string]$Key = "404142434445464748494A4B4C4D4E4F", # default test keys
    [string]$InstanceAID = "A00000006203010C06",           # applet AID
    [switch]$VerboseMode
)

function Find-Cap() {
    $cand = Get-ChildItem -Path ./build -Recurse -Filter *.cap -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $cand) { throw "CAP not found under ./build. Run 'ant convert' first." }
    return $cand.FullName
}

if (-not (Test-Path $GpJar)) {
    Write-Error "GlobalPlatformPro jar not found: $GpJar. Download from https://github.com/martinpaljak/GlobalPlatformPro/releases"
    exit 1
}

if ([string]::IsNullOrWhiteSpace($CapPath)) { $CapPath = Find-Cap }
if (-not (Test-Path $CapPath)) { throw "CAP not found: $CapPath" }

$args = @(
    "-jar", $GpJar,
    "-key", $Key,
    "-install", $CapPath,
    "-default",
    "-create", $InstanceAID
)
if ($VerboseMode) { $args += "-v" }

Write-Host "Installing CAP:" $CapPath "with AID" $InstanceAID
& java @args

if ($LASTEXITCODE -ne 0) { throw "gp install failed with code $LASTEXITCODE" }
Write-Host "Install completed"

