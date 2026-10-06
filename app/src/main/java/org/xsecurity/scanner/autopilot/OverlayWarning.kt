package org.xsecurity.scanner.autopilot

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import org.xsecurity.scanner.R
import org.xsecurity.scanner.quarantine.QuarantinePendingActionStore
import org.xsecurity.scanner.quarantine.QuarantineUserActions

/** SYSTEM_ALERT_WINDOW warning with the required user Allow/Uninstall actions. */
object OverlayWarning {
    const val EXTRA_PACKAGE = "warning_package"
    const val EXTRA_RECORD_ID = "warning_record_id"
    const val EXTRA_REASON = "warning_reason"

    fun show(context: Context, packageName: String?, recordId: String?, reasonCode: String) {
        val appContext = context.applicationContext
        val showOnMain = Runnable { showOnMainThread(appContext, packageName, recordId, reasonCode) }
        if (Looper.myLooper() == Looper.getMainLooper()) showOnMain.run()
        else Handler(Looper.getMainLooper()).post(showOnMain)
    }

    private fun showOnMainThread(context: Context, packageName: String?, recordId: String?, reasonCode: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && Settings.canDrawOverlays(context)) {
            if (showOverlay(context, packageName, recordId)) return
        }
        // Permission denied or OEM overlay failure: use a full-screen Activity instead.
        val intent = Intent(context, OverlayWarningActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            putExtra(EXTRA_PACKAGE, packageName)
            putExtra(EXTRA_RECORD_ID, recordId)
            putExtra(EXTRA_REASON, reasonCode)
        }
        runCatching { context.startActivity(intent) }
    }

    private fun showOverlay(context: Context, packageName: String?, recordId: String?): Boolean {
        val manager = context.getSystemService(Context.WINDOW_SERVICE) as? WindowManager ?: return false
        val card = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(context, 20), dp(context, 18), dp(context, 20), dp(context, 18))
            background = GradientDrawable().apply {
                setColor(Color.rgb(22, 29, 45))
                cornerRadius = dp(context, 18).toFloat()
                setStroke(dp(context, 1), Color.rgb(76, 106, 153))
            }
        }
        val target = packageName?.let { label(context, it) } ?: context.getString(R.string.autopilot_unknown_target)
        card.addView(TextView(context).apply {
            text = context.getString(R.string.autopilot_overlay_title)
            setTextColor(Color.WHITE)
            textSize = 18f
            typeface = Typeface.DEFAULT_BOLD
        })
        card.addView(TextView(context).apply {
            text = context.getString(R.string.autopilot_overlay_body, target)
            setTextColor(Color.LTGRAY)
            textSize = 14f
            setPadding(0, dp(context, 8), 0, dp(context, 14))
        })
        if (!packageName.isNullOrBlank()) {
            card.addView(Button(context).apply {
                text = context.getString(R.string.autopilot_allow_24h)
                setOnClickListener {
                    QuarantineUserActions.allowFor24Hours(context, packageName, recordId)
                    remove(manager, card)
                }
            })
            card.addView(Button(context).apply {
                text = context.getString(R.string.action_uninstall)
                setOnClickListener {
                    val intent = QuarantineUserActions.uninstallIntent(context, packageName, recordId)
                    if (intent != null) {
                        QuarantinePendingActionStore.setUninstall(context, packageName, recordId)
                        runCatching { context.startActivity(intent) }
                    }
                    remove(manager, card)
                }
            })
        }
        card.addView(Button(context).apply {
            text = context.getString(R.string.autopilot_dismiss)
            setOnClickListener { remove(manager, card) }
        })
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
            y = dp(context, 36)
        }
        return try {
            manager.addView(card, params)
            true
        } catch (_: SecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        }
    }

    private fun remove(manager: WindowManager, view: android.view.View) {
        runCatching { manager.removeView(view) }
    }

    private fun label(context: Context, packageName: String): String = try {
        val info = context.packageManager.getApplicationInfo(packageName, 0)
        context.packageManager.getApplicationLabel(info).toString().ifBlank { packageName }
    } catch (_: Exception) {
        packageName
    }

    private fun dp(context: Context, value: Int): Int =
        (value * context.resources.displayMetrics.density).toInt()
}
