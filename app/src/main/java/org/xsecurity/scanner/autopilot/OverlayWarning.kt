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

/** Warning surfaces: generic policy prompts plus opaque, list-only launch interception. */
object OverlayWarning {
    const val EXTRA_PACKAGE = "warning_package"
    const val EXTRA_RECORD_ID = "warning_record_id"
    const val EXTRA_REASON = "warning_reason"
    const val EXTRA_INTERCEPTION = "warning_interception"
    const val EXTRA_VERDICT = "warning_verdict"
    const val EXTRA_PROVIDER = "warning_provider"

    fun showInterception(context: Context, interception: ForegroundInterception) {
        val appContext = context.applicationContext
        val showOnMain = Runnable { showInterceptionOnMainThread(appContext, interception) }
        if (Looper.myLooper() == Looper.getMainLooper()) showOnMain.run()
        else Handler(Looper.getMainLooper()).post(showOnMain)
    }

    fun show(context: Context, packageName: String?, recordId: String?, reasonCode: String) {
        val appContext = context.applicationContext
        val showOnMain = Runnable { showOnMainThread(appContext, packageName, recordId, reasonCode) }
        if (Looper.myLooper() == Looper.getMainLooper()) showOnMain.run()
        else Handler(Looper.getMainLooper()).post(showOnMain)
    }

    private fun showInterceptionOnMainThread(context: Context, interception: ForegroundInterception) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && Settings.canDrawOverlays(context)) {
            if (showInterceptionOverlay(context, interception)) return
        }
        // Overlay denial/OEM failure falls back to an opaque, full-screen Activity.
        val intent = Intent(context, OverlayWarningActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            putExtra(EXTRA_PACKAGE, interception.packageName)
            putExtra(EXTRA_RECORD_ID, interception.recordId)
            putExtra(EXTRA_REASON, interception.reasonCode)
            putExtra(EXTRA_INTERCEPTION, true)
            putExtra(EXTRA_VERDICT, interception.verdict.name)
            putExtra(EXTRA_PROVIDER, interception.provider.name)
        }
        runCatching { context.startActivity(intent) }
    }

    private fun showInterceptionOverlay(context: Context, interception: ForegroundInterception): Boolean {
        val manager = context.getSystemService(Context.WINDOW_SERVICE) as? WindowManager ?: return false
        val root = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(context, 28), dp(context, 28), dp(context, 28), dp(context, 28))
            setBackgroundColor(Color.rgb(12, 18, 30))
        }
        val target = label(context, interception.packageName)
        root.addView(TextView(context).apply {
            text = context.getString(R.string.autopilot_interception_title)
            setTextColor(Color.WHITE)
            textSize = 23f
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
        }, centeredTextParams())
        root.addView(TextView(context).apply {
            text = context.getString(R.string.autopilot_interception_body, target)
            setTextColor(Color.WHITE)
            textSize = 18f
            gravity = Gravity.CENTER
            setPadding(0, dp(context, 18), 0, dp(context, 14))
        }, centeredTextParams())
        root.addView(TextView(context).apply {
            text = context.getString(
                R.string.autopilot_interception_details,
                ForegroundInterceptionLabels.verdict(context, interception.verdict),
                ForegroundInterceptionLabels.reason(context, interception.reasonCode)
            )
            setTextColor(Color.LTGRAY)
            textSize = 15f
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, dp(context, 22))
        }, centeredTextParams())
        root.addView(interceptionButton(context, R.string.autopilot_go_back) {
            if (ForegroundInterceptionCoordinator.goBack(context, interception)) remove(manager, root)
        })
        root.addView(interceptionButton(context, R.string.action_uninstall) {
            val intent = QuarantineUserActions.uninstallIntent(context, interception.packageName, interception.recordId)
            if (intent != null) {
                QuarantinePendingActionStore.setUninstall(context, interception.packageName, interception.recordId)
                if (runCatching { context.startActivity(intent) }.isSuccess) remove(manager, root)
            }
        })
        root.addView(interceptionButton(context, R.string.autopilot_open_anyway_24h) {
            if (QuarantineUserActions.allowFor24Hours(context, interception.packageName, interception.recordId)) {
                remove(manager, root)
            }
        })

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.OPAQUE
        ).apply { gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL }
        return try {
            manager.addView(root, params)
            true
        } catch (_: SecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        }
    }

    private fun interceptionButton(context: Context, labelRes: Int, action: () -> Unit): Button =
        Button(context).apply {
            text = context.getString(labelRes)
            isAllCaps = false
            setOnClickListener { action() }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(context, 10) }
        }

    private fun centeredTextParams() = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT
    )

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
