param(
    [string]$GameDir = "",
    [string]$ApkPath = "",
    [switch]$SelfTest,
    [switch]$Trace,
    [switch]$WatchLogcat
)

$ErrorActionPreference = "Stop"

$devices = (adb devices) | Select-String -Pattern "\tdevice$"
if (-not $devices) { throw "No authorized Android device detected via ADB (enable USB Debugging)." }

if ($ApkPath -ne "") {
    if (-not (Test-Path $ApkPath)) { throw "APK not found: $ApkPath" }
    Write-Host "[Mobiro] Installing APK: $ApkPath"
    adb install -r $ApkPath
}

if ($SelfTest) {
    $extras = "--ez selftest true"
    if ($Trace) { $extras += " --ez trace true" }
    Write-Host "[Mobiro] Launching built-in clean-room 60 FPS self-test ($extras)..."
    adb shell am force-stop com.mobiro.runtime
    adb shell "am start -n com.mobiro.runtime/.MainActivity $extras" | Out-Null
    if ($WatchLogcat) {
        Write-Host "[Mobiro] Streaming logcat (Ctrl+C to stop)..."
        adb logcat -s Mobiro:V DXVK:I AndroidRuntime:E
    }
    exit 0
}

# Clean-room BYOF staging: pushes the user's own legally owned local PC files
# into Mobiro's Android app-scoped external storage for direct POSIX mmap access.
if ($GameDir -eq "" -or -not (Test-Path (Join-Path $GameDir "sekiro.exe"))) {
    throw "Specify -SelfTest or a valid -GameDir containing sekiro.exe"
}
for ($i = 1; $i -le 5; $i++) {
    foreach ($ext in @("bhd", "bdt")) {
        $f = Join-Path $GameDir ("Data{0}.{1}" -f $i, $ext)
        if (-not (Test-Path $f)) { throw "Missing required BYOF archive: $f" }
    }
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
if ($Trace) {
    adb shell am start -n com.mobiro.runtime/.MainActivity --ez trace true | Out-Null
} else {
    adb shell monkey -p com.mobiro.runtime -c android.intent.category.LAUNCHER 1 | Out-Null
}

if ($WatchLogcat) {
    Write-Host "[Mobiro] Streaming logcat (Ctrl+C to stop)..."
    adb logcat -s Mobiro:V DXVK:I AndroidRuntime:E
}
