param(
    [Parameter(Mandatory=$true)]
    [string]$GameDir,
    [string]$ApkPath = "",
    [switch]$WatchLogcat
)

$ErrorActionPreference = "Stop"

# Clean-room BYOF staging script: pushes the user's own legally owned local PC files
# into Mobiro's Android app-scoped external storage for direct POSIX mmap access.
if (-not (Test-Path (Join-Path $GameDir "sekiro.exe"))) {
    throw "sekiro.exe not found in $GameDir"
}
for ($i = 1; $i -le 5; $i++) {
    foreach ($ext in @("bhd", "bdt")) {
        $f = Join-Path $GameDir ("Data{0}.{1}" -f $i, $ext)
        if (-not (Test-Path $f)) { throw "Missing required BYOF archive: $f" }
    }
}

$devices = (adb devices) | Select-String -Pattern "\tdevice$"
if (-not $devices) { throw "No authorized Android device detected via ADB (enable USB Debugging)." }

if ($ApkPath -ne "") {
    if (-not (Test-Path $ApkPath)) { throw "APK not found: $ApkPath" }
    Write-Host "[Mobiro] Installing APK: $ApkPath"
    adb install -r $ApkPath
}

$remoteDir = "/sdcard/Android/data/com.mobiro.runtime/files/game"
Write-Host "[Mobiro] Creating $remoteDir on device..."
adb shell "mkdir -p '$remoteDir'"

$items = @("sekiro.exe")
for ($i = 1; $i -le 5; $i++) { $items += "Data$i.bhd"; $items += "Data$i.bdt" }
Get-ChildItem -Path $GameDir -Filter "*.dll" | ForEach-Object { $items += $_.Name }
foreach ($sub in @("movie", "sound")) {
    if (Test-Path (Join-Path $GameDir $sub)) { $items += $sub }
}

foreach ($item in $items) {
    $local = Join-Path $GameDir $item
    if (Test-Path $local) {
        Write-Host "[Mobiro] Pushing $item ..."
        adb push $local "$remoteDir/$item"
    }
}

Write-Host "[Mobiro] Staging complete. Launching com.mobiro.runtime..."
adb shell monkey -p com.mobiro.runtime -c android.intent.category.LAUNCHER 1 | Out-Null

if ($WatchLogcat) {
    Write-Host "[Mobiro] Streaming logcat (Ctrl+C to stop)..."
    adb logcat -s Mobiro:V DXVK:I AndroidRuntime:E
}
