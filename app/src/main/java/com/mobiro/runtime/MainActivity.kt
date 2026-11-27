package com.mobiro.runtime

import android.app.AlertDialog
import android.content.ComponentCallbacks2
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.DocumentsContract
import android.util.Log
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import com.google.androidgamesdk.GameActivity
import java.io.File

class MainActivity : GameActivity() {

    private lateinit var thermalMonitor: ThermalMonitor
    private val uiHandler = Handler(Looper.getMainLooper())
    private var exitWatcher: Runnable? = null

    private val pickByofDirectory =
        registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri: Uri? ->
            if (uri == null) {
                Toast.makeText(this, "Select your local Sekiro PC directory (BYOF).", Toast.LENGTH_LONG).show()
                return@registerForActivityResult
            }
            contentResolver.takePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
            val resolved = resolveByofPath(uri)
            if (resolved != null) {
                prefs().edit().putString(KEY_BYOF_PATH, resolved).apply()
                startNativeContainer(resolved)
            } else {
                Toast.makeText(
                    this,
                    "Copy game files into ${defaultByofDir().absolutePath} for direct POSIX mmap access.",
                    Toast.LENGTH_LONG
                ).show()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        System.loadLibrary("sekiro_runtime")
        super.onCreate(savedInstanceState)

        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        hideSystemUi()

        thermalMonitor = ThermalMonitor(this) { headroom ->
            nativeOnThermalHeadroom(headroom)
        }
        thermalMonitor.start()

        val traceExtra = intent?.getBooleanExtra("trace", false) == true
        val traceMarker = File(getExternalFilesDir(null), "mobiro_trace.enable")
        if (traceExtra) {
            traceMarker.parentFile?.mkdirs()
            traceMarker.writeText("1")
        }

        applySavedOrIntentSettings()
        attachSettingsPill()

        val selfTestRequested = intent?.getBooleanExtra("selftest", false) == true
        val savedPath = prefs().getString(KEY_BYOF_PATH, null)
        val defaultDir = defaultByofDir().apply { mkdirs() }
        when {
            selfTestRequested -> startSelfTestContainer()
            savedPath != null && File(savedPath, "sekiro.exe").isFile -> startNativeContainer(savedPath, false)
            File(defaultDir, "sekiro.exe").isFile -> startNativeContainer(defaultDir.absolutePath, false)
            else -> {
                try {
                    pickByofDirectory.launch(null)
                } catch (_: android.content.ActivityNotFoundException) {
                    Log.w(TAG, "No SAF picker available; copy BYOF files to ${defaultDir.absolutePath}")
                    Toast.makeText(
                        this,
                        "Copy Sekiro PC files into ${defaultDir.absolutePath}",
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    override fun onDestroy() {
        exitWatcher?.let { uiHandler.removeCallbacks(it) }
        exitWatcher = null
        thermalMonitor.stop()
        super.onDestroy()
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= ComponentCallbacks2.TRIM_MEMORY_RUNNING_LOW) {
            nativeOnMemoryPressure(level)
        }
    }

    private fun startSelfTestContainer() {
        val dir = File(getExternalFilesDir(null), "selftest").apply { mkdirs() }
        val exe = File(dir, "sekiro.exe")
        try {
            assets.open("mobiro_selftest.exe").use { input ->
                exe.outputStream().use { output -> input.copyTo(output) }
            }
            startNativeContainer(dir.absolutePath, true)
        } catch (e: Exception) {
            Log.e(TAG, "Self-test payload unavailable in APK assets: ${e.message}")
            Toast.makeText(this, "Self-test payload not bundled in this build.", Toast.LENGTH_LONG).show()
        }
    }

    private fun startNativeContainer(gameDir: String, selfTest: Boolean = false) {
        val saveDir = File(filesDir, "saves_overlay").apply { mkdirs() }.absolutePath
        val cacheDir = File(cacheDir, "runtime_cache").apply { mkdirs() }.absolutePath
        val nativeLibDir = applicationInfo.nativeLibraryDir
        val err = nativeConfigureAndValidate(gameDir, saveDir, cacheDir, nativeLibDir, selfTest)
        if (err.isNotEmpty()) {
            Log.e(TAG, "BYOF validation failed: $err")
            Toast.makeText(this, "Validation failed: $err", Toast.LENGTH_LONG).show()
        } else {
            val diag = nativeGetDiagnosticsSummary()
            Log.i(TAG, "Mobiro ready: $diag")
            Toast.makeText(this, "Mobiro: $diag", Toast.LENGTH_SHORT).show()
            scheduleExitWatcher()
        }
    }

    private fun scheduleExitWatcher() {
        exitWatcher?.let { uiHandler.removeCallbacks(it) }
        val check = object : Runnable {
            override fun run() {
                val diag = nativeGetDiagnosticsSummary()
                if (diag.contains(" exit=")) {
                    val msg = if (diag.contains(" exit=0x35")) {
                        "Guest exited (0x35): retail Steam binary requires Steam client. [$diag]"
                    } else {
                        "Mobiro finished: $diag"
                    }
                    Log.i(TAG, msg)
                    Toast.makeText(this@MainActivity, msg, Toast.LENGTH_LONG).show()
                    exitWatcher = null
                } else {
                    uiHandler.postDelayed(this, 1000L)
                }
            }
        }
        exitWatcher = check
        uiHandler.postDelayed(check, 1000L)
    }

    private fun defaultByofDir(): File = File(getExternalFilesDir(null), "game")

    private fun resolveByofPath(treeUri: Uri): String? {
        // shortcut: Android SAF URIs don't expose direct POSIX paths for arbitrary volumes;
        // handles primary external storage directly and guides users to app-scoped external storage otherwise.
        val docId = DocumentsContract.getTreeDocumentId(treeUri)
        val parts = docId.split(":")
        if (parts.size == 2 && parts[0].equals("primary", ignoreCase = true)) {
            val candidate = File("/storage/emulated/0/${parts[1]}")
            if (candidate.isDirectory) return candidate.absolutePath
        }
        return null
    }

    private fun prefs() = getSharedPreferences("mobiro_runtime_prefs", MODE_PRIVATE)

    @Suppress("DEPRECATION")
    private fun hideSystemUi() {
        window.decorView.systemUiVisibility = (
            View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                or View.SYSTEM_UI_FLAG_FULLSCREEN
                or View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                or View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
        )
    }

    private fun applySavedOrIntentSettings() {
        val p = prefs()
        val fps = if (intent?.hasExtra("fps") == true) intent.getIntExtra("fps", 60) else p.getInt(KEY_TARGET_FPS, 60)
        val maxH = if (intent?.hasExtra("max_height") == true) intent.getIntExtra("max_height", 900) else p.getInt(KEY_MAX_HEIGHT, 900)
        val alpha = if (intent?.hasExtra("hud_alpha") == true) intent.getFloatExtra("hud_alpha", 1.0f) else p.getFloat(KEY_HUD_ALPHA, 1.0f)
        nativeApplyRuntimeSettings(fps, maxH, alpha)
    }

    private fun attachSettingsPill() {
        val density = resources.displayMetrics.density
        val sizePx = (38f * density).toInt()
        val marginPx = (8f * density).toInt()
        val pill = TextView(this).apply {
            text = "\u2699"
            textSize = 18f
            gravity = Gravity.CENTER
            setTextColor(Color.WHITE)
            setBackgroundColor(Color.argb(115, 20, 24, 32))
            setOnClickListener { showRuntimeSettingsDialog() }
        }
        val lp = FrameLayout.LayoutParams(sizePx, sizePx, Gravity.TOP or Gravity.START).apply {
            setMargins(marginPx, marginPx, 0, 0)
        }
        addContentView(pill, lp)
    }

    private fun showRuntimeSettingsDialog() {
        val p = prefs()
        val curFps = p.getInt(KEY_TARGET_FPS, 60)
        val curMaxH = p.getInt(KEY_MAX_HEIGHT, 900)
        val curAlpha = p.getFloat(KEY_HUD_ALPHA, 1.0f)
        val scaleLabel = when (curMaxH) {
            0 -> "Native"
            else -> "${curMaxH}p"
        }
        val hudLabel = when {
            curAlpha <= 0.05f -> "Hidden"
            curAlpha < 0.75f -> "50%"
            else -> "100%"
        }
        val items = arrayOf(
            "FPS Target: ${curFps} FPS (toggle 60 / 30)",
            "Render Scale: $scaleLabel (cycle 720p / 900p / Native, next launch)",
            "Touch HUD Opacity: $hudLabel (cycle 100% / 50% / Hidden)",
            "Run Clean-Room 3D 60 FPS Self-Test",
            "Select BYOF Game Directory"
        )
        AlertDialog.Builder(this)
            .setTitle("Mobiro — ${nativeGetDiagnosticsSummary()}")
            .setItems(items) { _, which ->
                when (which) {
                    0 -> {
                        val nextFps = if (curFps <= 30) 60 else 30
                        p.edit().putInt(KEY_TARGET_FPS, nextFps).apply()
                        nativeApplyRuntimeSettings(nextFps, curMaxH, curAlpha)
                    }
                    1 -> {
                        val nextH = when (curMaxH) { 720 -> 900; 900 -> 0; else -> 720 }
                        p.edit().putInt(KEY_MAX_HEIGHT, nextH).apply()
                        nativeApplyRuntimeSettings(curFps, nextH, curAlpha)
                        Toast.makeText(this, "Render scale set to ${if (nextH == 0) "Native" else "${nextH}p"} (applies on next launch).", Toast.LENGTH_SHORT).show()
                    }
                    2 -> {
                        val nextA = when { curAlpha >= 0.75f -> 0.5f; curAlpha > 0.05f -> 0.0f; else -> 1.0f }
                        p.edit().putFloat(KEY_HUD_ALPHA, nextA).apply()
                        nativeApplyRuntimeSettings(curFps, curMaxH, nextA)
                    }
                    3 -> startSelfTestContainer()
                    4 -> try { pickByofDirectory.launch(null) } catch (_: Exception) {}
                }
                hideSystemUi()
            }
            .setNegativeButton("Close") { _, _ -> hideSystemUi() }
            .show()
    }

    private external fun nativeConfigureAndValidate(
        gameDir: String,
        saveDir: String,
        cacheDir: String,
        nativeLibDir: String,
        selfTest: Boolean
    ): String

    private external fun nativeGetDiagnosticsSummary(): String
    private external fun nativeOnMemoryPressure(trimLevel: Int)
    private external fun nativeOnThermalHeadroom(headroom: Float)
    private external fun nativeApplyRuntimeSettings(targetFps: Int, maxRenderHeight: Int, hudOpacity: Float)

    companion object {
        private const val TAG = "Mobiro"
        private const val KEY_BYOF_PATH = "byof_game_dir"
        private const val KEY_TARGET_FPS = "target_fps"
        private const val KEY_MAX_HEIGHT = "max_render_height"
        private const val KEY_HUD_ALPHA = "hud_alpha"
    }
}
