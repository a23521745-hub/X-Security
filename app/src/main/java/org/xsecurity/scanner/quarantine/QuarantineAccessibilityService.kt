package org.xsecurity.scanner.quarantine

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import org.xsecurity.scanner.edr.EdrStatus

/**
 * Narrow, user-enabled assist for the system app-details screen. It only looks for
 * Force stop controls while a time-limited request exists, never reads app content,
 * and never logs node text. OEMs that do not expose a recognized control stay in
 * PENDING/FAILED rather than being reported as quarantined.
 */
class QuarantineAccessibilityService : AccessibilityService() {
    override fun onServiceConnected() {
        serviceInfo = (serviceInfo ?: AccessibilityServiceInfo()).apply {
            eventTypes = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED or AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED
            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            flags = flags or AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
            notificationTimeout = 250
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return
        val request = QuarantineAssistStore.current(this) ?: return
        if (!isSettingsPackage(event.packageName?.toString())) return
        if (System.currentTimeMillis() - request.startedAtMillis > ASSIST_TIMEOUT_MILLIS) {
            failRequest(request.recordId)
            return
        }
        val root = rootInActiveWindow ?: return
        when (request.stage) {
            STAGE_FORCE_STOP -> {
                val button = findForceStopButton(root, allowTextFallback = true) ?: return
                if (button.isEnabled && button.performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
                    QuarantineAssistStore.updateStage(this, STAGE_CONFIRM)
                }
            }
            STAGE_CONFIRM -> {
                val confirm = findForceStopButton(root, allowTextFallback = true) ?: return
                if (confirm.isEnabled && confirm.performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
                    completeRequest(request.recordId)
                }
            }
        }
    }

    override fun onInterrupt() = Unit

    private fun completeRequest(recordId: String) {
        val result = QuarantineRepository.transition(
            context = this,
            id = recordId,
            state = QuarantineState.QUARANTINED,
            actor = QuarantineActor.AUTOMATION,
            nowMillis = System.currentTimeMillis()
        )
        if (result is QuarantineTransitionResult.Accepted) {
            QuarantineRepository.updateRestoreInfo(this, recordId, "accessibility_force_stop_confirmed")
        }
        QuarantineAssistStore.clear(this)
    }

    private fun failRequest(recordId: String) {
        QuarantineRepository.transition(
            context = this,
            id = recordId,
            state = QuarantineState.FAILED,
            actor = QuarantineActor.AUTOMATION,
            nowMillis = System.currentTimeMillis(),
            failureCode = "oem_accessibility_action_not_confirmed"
        )
        QuarantineAssistStore.clear(this)
    }

    private fun findForceStopButton(root: AccessibilityNodeInfo, allowTextFallback: Boolean): AccessibilityNodeInfo? {
        val stack = ArrayDeque<AccessibilityNodeInfo>()
        stack.add(root)
        while (stack.isNotEmpty()) {
            val node = stack.removeLast()
            val viewId = node.viewIdResourceName.orEmpty().lowercase()
            if (viewId.contains("force_stop") || viewId.contains("force-stop")) return node
            if (allowTextFallback && isExactForceStopLabel(node.text?.toString())) return node
            for (index in 0 until node.childCount) {
                node.getChild(index)?.let(stack::add)
            }
        }
        return null
    }

    /** Used only for a short-lived OEM fallback; the compared text is never retained or logged. */
    private fun isExactForceStopLabel(value: String?): Boolean = when (value?.trim()?.lowercase()) {
        "force stop", "zorla durdur", "uygulamayı durdur" -> true
        else -> false
    }

    private fun isSettingsPackage(packageName: String?): Boolean =
        packageName == "com.android.settings" ||
            packageName == "com.google.android.settings" ||
            packageName == "com.miui.securitycenter" ||
            packageName == "com.samsung.android.lool"

    companion object {
        private const val STAGE_FORCE_STOP = "force_stop"
        private const val STAGE_CONFIRM = "confirm"
        private const val ASSIST_TIMEOUT_MILLIS = 60_000L

        fun isEnabled(context: Context): Boolean = try {
            val enabled = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            )
            EdrStatus.isEnabledService(
                enabledServices = enabled,
                packageName = context.packageName,
                serviceClass = QuarantineAccessibilityService::class.java.name
            )
        } catch (_: Throwable) {
            false
        }

        /** Opens only the target app's system details page, after an explicit quarantine request. */
        fun requestForceStopAssist(context: Context, packageName: String, recordId: String): Boolean {
            if (!isEnabled(context)) return false
            QuarantineAssistStore.set(context, packageName, recordId, STAGE_FORCE_STOP)
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            return try {
                context.startActivity(intent)
                true
            } catch (_: RuntimeException) {
                QuarantineAssistStore.clear(context)
                false
            }
        }
    }
}
