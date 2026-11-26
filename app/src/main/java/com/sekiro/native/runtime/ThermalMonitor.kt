package com.sekiro.native.runtime

import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PowerManager

class ThermalMonitor(
    context: Context,
    private val onHeadroom: (Float) -> Unit
) {
    private val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager
    private val handler = Handler(Looper.getMainLooper())
    private var running = false

    private val pollTask = object : Runnable {
        override fun run() {
            if (!running) return
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val headroom = powerManager.getThermalHeadroom(10)
                if (!headroom.isNaN()) {
                    onHeadroom(headroom)
                }
            }
            handler.postDelayed(this, 5000L)
        }
    }

    fun start() {
        if (running) return
        running = true
        handler.post(pollTask)
    }

    fun stop() {
        running = false
        handler.removeCallbacks(pollTask)
    }
}
