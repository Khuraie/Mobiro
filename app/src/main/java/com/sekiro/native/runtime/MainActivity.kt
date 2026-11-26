package com.sekiro.native.runtime

import android.content.ComponentCallbacks2
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import com.google.androidgamesdk.GameActivity
import java.io.File

class MainActivity : GameActivity() {

    private lateinit var thermalMonitor: ThermalMonitor

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
            // Resolve to local app-scoped directory or SAF path hint
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

        val savedPath = prefs().getString(KEY_BYOF_PATH, null)
        val defaultDir = defaultByofDir().apply { mkdirs() }
        when {
            savedPath != null && File(savedPath, "sekiro.exe").isFile -> startNativeContainer(savedPath)
            File(defaultDir, "sekiro.exe").isFile -> startNativeContainer(defaultDir.absolutePath)
            else -> pickByofDirectory.launch(null)
        }
    }

    override fun onDestroy() {
        thermalMonitor.stop()
        super.onDestroy()
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= ComponentCallbacks2.TRIM_MEMORY_RUNNING_LOW) {
            nativeOnMemoryPressure(level)
        }
    }

    private fun startNativeContainer(gameDir: String) {
        val cacheDir = File(cacheDir, "runtime_cache").apply { mkdirs() }.absolutePath
        val nativeLibDir = applicationInfo.nativeLibraryDir
        val err = nativeConfigureAndValidate(gameDir, cacheDir, nativeLibDir)
        if (err.isNotEmpty()) {
            Log.e(TAG, "BYOF validation failed: $err")
            Toast.makeText(this, "Validation failed: $err", Toast.LENGTH_LONG).show()
        }
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

    private fun prefs() = getSharedPreferences("sekiro_runtime_prefs", MODE_PRIVATE)

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

    private external fun nativeConfigureAndValidate(
        gameDir: String,
        cacheDir: String,
        nativeLibDir: String
    ): String

    private external fun nativeOnMemoryPressure(trimLevel: Int)
    private external fun nativeOnThermalHeadroom(headroom: Float)

    companion object {
        private const val TAG = "SekiroRuntime"
        private const val KEY_BYOF_PATH = "byof_game_dir"
    }
}
