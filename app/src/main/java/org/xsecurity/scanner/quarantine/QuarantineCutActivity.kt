package org.xsecurity.scanner.quarantine

import android.app.Activity
import android.app.DownloadManager
import android.content.Intent
import android.content.IntentSender
import android.graphics.drawable.ColorDrawable
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.R
import org.xsecurity.scanner.device.StorageAccess
import org.xsecurity.scanner.ui.MainActivity
import org.xsecurity.scanner.ui.theme.XSecurityTheme

/**
 * The ONE user tap that removes an original file after it was copied into the vault.
 *
 *  - With All Files Access the tap deletes directly (no system dialog).
 *  - Without it the same tap launches the platform confirmation (`MediaStore.createDeleteRequest`
 *    / RecoverableSecurityException prompt) and reports the answer back to [VaultDeleteFlow].
 *  - Denial or failure leaves the record ORIGINAL_PRESENT; the screen says so and offers Retry,
 *    the All Files Access setting, or the system Downloads app as fallbacks.
 *
 * Opened from the ongoing "Delete now" notification and from the Quarantine screen.
 */
class QuarantineCutActivity : ComponentActivity() {
    private sealed class Phase {
        object Confirm : Phase()
        object Working : Phase()
        object AwaitingSystem : Phase()
        data class Done(
            val message: String,
            val removed: Boolean,
            val canRetry: Boolean,
            val offerAllFilesAccess: Boolean,
            val offerDownloads: Boolean
        ) : Phase()
    }

    private var recordId: String = ""
    private var mode: String = MODE_CUT
    private var record by mutableStateOf<QuarantineRecord?>(null)
    private var phase by mutableStateOf<Phase>(Phase.Confirm)
    private var pendingRoute: VaultCutPolicy.Route? = null
    private var finishRecordDeleteAfterCut = false

    private val systemConfirmation = registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) { result ->
        val route = pendingRoute
        pendingRoute = null
        if (route == null) {
            phase = Phase.Confirm
            return@registerForActivityResult
        }
        val confirmed = result.resultCode == Activity.RESULT_OK
        phase = Phase.Working
        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                VaultDeleteFlow.completeUserConfirmation(this@QuarantineCutActivity, recordId, route, confirmed)
            }
            if (outcome is CutOutcome.Removed && finishRecordDeleteAfterCut) {
                finishRecordDeleteAfterCut = false
                val deleted = withContext(Dispatchers.IO) {
                    VaultDeleteFlow.deleteRecord(this@QuarantineCutActivity, recordId, alsoDeleteOriginal = false)
                }
                showDelete(deleted)
            } else {
                finishRecordDeleteAfterCut = false
                showCut(outcome)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        window?.setBackgroundDrawable(ColorDrawable(android.graphics.Color.rgb(12, 18, 30)))
        readArguments(intent)
        savedInstanceState?.getString(STATE_PENDING_ROUTE)?.let { saved ->
            pendingRoute = VaultCutPolicy.Route.values().firstOrNull { it.name == saved }
            if (pendingRoute != null) phase = Phase.AwaitingSystem
        }
        finishRecordDeleteAfterCut = savedInstanceState?.getBoolean(STATE_FINISH_DELETE, false) ?: false
        reloadRecord()
        setContent {
            XSecurityTheme {
                CutContent(
                    record = record,
                    mode = mode,
                    phase = phase,
                    onCut = { startCut() },
                    onDeleteRecord = { alsoOriginal -> startDeleteRecord(alsoOriginal) },
                    onOpenAllFilesAccess = { openAllFilesAccess() },
                    onOpenDownloads = { openDownloads() },
                    onOpenQuarantine = { openQuarantine() },
                    onClose = { finish() }
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        readArguments(intent)
        pendingRoute = null
        finishRecordDeleteAfterCut = false
        phase = Phase.Confirm
        reloadRecord()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        pendingRoute?.let { outState.putString(STATE_PENDING_ROUTE, it.name) }
        outState.putBoolean(STATE_FINISH_DELETE, finishRecordDeleteAfterCut)
    }

    override fun onResume() {
        super.onResume()
        if (phase is Phase.Confirm) reloadRecord()
    }

    private fun readArguments(intent: Intent?) {
        recordId = intent?.getStringExtra(EXTRA_RECORD_ID).orEmpty()
        mode = intent?.getStringExtra(EXTRA_MODE)?.takeIf { it == MODE_DELETE_RECORD } ?: MODE_CUT
    }

    private fun reloadRecord() {
        lifecycleScope.launch {
            record = withContext(Dispatchers.IO) { QuarantineRepository.record(this@QuarantineCutActivity, recordId) }
        }
    }

    private fun startCut() {
        phase = Phase.Working
        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) { VaultDeleteFlow.cut(this@QuarantineCutActivity, recordId) }
            showCut(outcome)
        }
    }

    private fun startDeleteRecord(alsoDeleteOriginal: Boolean) {
        phase = Phase.Working
        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                VaultDeleteFlow.deleteRecord(this@QuarantineCutActivity, recordId, alsoDeleteOriginal)
            }
            showDelete(outcome)
        }
    }

    private fun showCut(outcome: CutOutcome) {
        when (outcome) {
            is CutOutcome.NeedsUserConfirmation -> launchSystemConfirmation(outcome.token, outcome.route)
            is CutOutcome.Removed -> done(resolve(QuarantineWording.KEY_CUT_RESULT_REMOVED), removed = true)
            CutOutcome.Denied -> done(resolve(QuarantineWording.KEY_CUT_RESULT_DENIED), removed = false, canRetry = true)
            is CutOutcome.Failed -> failed(outcome.code)
        }
        reloadRecord()
    }

    private fun showDelete(outcome: DeleteOutcome) {
        when (outcome) {
            is DeleteOutcome.NeedsUserConfirmation -> {
                finishRecordDeleteAfterCut = true
                launchSystemConfirmation(outcome.token, outcome.route)
            }
            is DeleteOutcome.Deleted -> done(
                if (outcome.residue == OriginalResidue.ORIGINAL_REMOVED) getString(R.string.quarantine_delete_record_done_original_removed)
                else getString(R.string.quarantine_delete_record_done_original_present),
                removed = outcome.residue == OriginalResidue.ORIGINAL_REMOVED
            )
            DeleteOutcome.Denied -> done(resolve(QuarantineWording.KEY_CUT_RESULT_DENIED), removed = false, canRetry = true)
            is DeleteOutcome.Failed -> failed(outcome.code)
        }
        reloadRecord()
    }

    private fun failed(code: String) {
        val hint = QuarantineWording.hintKey(code)?.let { resolve(it) } ?: code
        done(
            message = resolve(QuarantineWording.KEY_CUT_RESULT_FAILED, hint),
            removed = false,
            canRetry = code != CutResultCodes.FAILED_NOT_FILE_RECORD && code != CutResultCodes.FAILED_RECORD_NOT_FOUND,
            offerAllFilesAccess = code == CutResultCodes.FAILED_PERMISSION &&
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !StorageAccess.hasDirectDeleteAccess(this),
            offerDownloads = code == CutResultCodes.FAILED_LOCATION_UNKNOWN || code == CutResultCodes.FAILED_PERMISSION ||
                code == CutResultCodes.FAILED_DELETE || code == CutResultCodes.FAILED_STILL_PRESENT
        )
    }

    private fun done(
        message: String,
        removed: Boolean,
        canRetry: Boolean = false,
        offerAllFilesAccess: Boolean = false,
        offerDownloads: Boolean = false
    ) {
        phase = Phase.Done(message, removed, canRetry, offerAllFilesAccess, offerDownloads)
    }

    private fun launchSystemConfirmation(token: Any, route: VaultCutPolicy.Route) {
        val sender = token as? IntentSender
        if (sender == null) {
            failed(CutResultCodes.FAILED_DELETE)
            return
        }
        pendingRoute = route
        phase = Phase.AwaitingSystem
        try {
            systemConfirmation.launch(IntentSenderRequest.Builder(sender).build())
        } catch (_: Exception) {
            pendingRoute = null
            lifecycleScope.launch {
                withContext(Dispatchers.IO) {
                    VaultDeleteFlow.completeUserConfirmation(this@QuarantineCutActivity, recordId, route, confirmed = false)
                }
                failed(CutResultCodes.FAILED_DELETE)
            }
        }
    }

    private fun openAllFilesAccess() {
        for (intent in StorageAccess.settingsIntents(this)) {
            if (runCatching { startActivity(intent) }.isSuccess) return
        }
    }

    private fun openDownloads() {
        val intent = Intent(DownloadManager.ACTION_VIEW_DOWNLOADS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { startActivity(intent) }
    }

    private fun openQuarantine() {
        startActivity(
            Intent(this, MainActivity::class.java)
                .putExtra(MainActivity.EXTRA_OPEN_QUARANTINE, true)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        )
        finish()
    }

    private fun resolve(key: String, vararg args: Any): String = QuarantineFileNotifications.resolve(this, key, *args)

    @Composable
    private fun CutContent(
        record: QuarantineRecord?,
        mode: String,
        phase: Phase,
        onCut: () -> Unit,
        onDeleteRecord: (Boolean) -> Unit,
        onOpenAllFilesAccess: () -> Unit,
        onOpenDownloads: () -> Unit,
        onOpenQuarantine: () -> Unit,
        onClose: () -> Unit
    ) {
        val label = record?.label ?: getString(R.string.autopilot_unknown_target)
        val pending = record != null && QuarantineHonesty.originalRemovalPending(record)
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background)
                .safeDrawingPadding()
                .padding(24.dp),
            verticalArrangement = Arrangement.Center
        ) {
            when (phase) {
                Phase.Confirm -> {
                    if (mode == MODE_DELETE_RECORD) {
                        Text(getString(R.string.quarantine_delete_record_title), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(12.dp))
                        Text(
                            if (pending) getString(R.string.quarantine_delete_record_body_original_present, label)
                            else getString(R.string.quarantine_delete_record_body, label)
                        )
                        Spacer(Modifier.height(20.dp))
                        if (pending) {
                            Button(onClick = { onDeleteRecord(true) }, modifier = Modifier.fillMaxWidth()) {
                                Text(getString(R.string.quarantine_delete_record_with_original))
                            }
                            Spacer(Modifier.height(8.dp))
                            OutlinedButton(onClick = { onDeleteRecord(false) }, modifier = Modifier.fillMaxWidth()) {
                                Text(getString(R.string.quarantine_delete_record_only))
                            }
                        } else {
                            Button(onClick = { onDeleteRecord(false) }, modifier = Modifier.fillMaxWidth()) {
                                Text(getString(R.string.quarantine_delete_record_only))
                            }
                        }
                    } else {
                        Text(getString(R.string.quarantine_cut_title), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(12.dp))
                        if (record == null) {
                            Text(getString(R.string.quarantine_cut_record_missing))
                        } else if (!pending) {
                            Text(
                                if (QuarantineHonesty.mayClaimFullQuarantine(record)) resolve(QuarantineWording.KEY_RESIDUE_REMOVED)
                                else getString(R.string.quarantine_cut_not_applicable)
                            )
                        } else {
                            Text(getString(R.string.quarantine_cut_body, label))
                            val hint = QuarantineWording.hintKey(record.cutResult)?.let { resolve(it) }
                            if (hint != null) {
                                Spacer(Modifier.height(8.dp))
                                Text(hint, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            if (!StorageAccess.hasDirectDeleteAccess(this@QuarantineCutActivity)) {
                                Spacer(Modifier.height(8.dp))
                                Text(getString(R.string.quarantine_cut_body_system_dialog), color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            Spacer(Modifier.height(20.dp))
                            Button(onClick = onCut, modifier = Modifier.fillMaxWidth()) {
                                Text(resolve(QuarantineWording.KEY_ACTION_DELETE_NOW))
                            }
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    TextButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text(getString(R.string.quarantine_cut_cancel)) }
                }
                Phase.Working, Phase.AwaitingSystem -> {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(16.dp))
                    Text(getString(R.string.quarantine_cut_working))
                }
                is Phase.Done -> {
                    Text(
                        if (phase.removed) getString(R.string.quarantine_cut_done_title) else getString(R.string.quarantine_cut_not_done_title),
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.height(12.dp))
                    Text(phase.message)
                    Spacer(Modifier.height(20.dp))
                    if (phase.canRetry) {
                        Button(onClick = onCut, modifier = Modifier.fillMaxWidth()) { Text(getString(R.string.quarantine_cut_retry)) }
                        Spacer(Modifier.height(8.dp))
                    }
                    if (phase.offerAllFilesAccess) {
                        OutlinedButton(onClick = onOpenAllFilesAccess, modifier = Modifier.fillMaxWidth()) {
                            Text(getString(R.string.quarantine_cut_grant_all_files))
                        }
                        Spacer(Modifier.height(8.dp))
                    }
                    if (phase.offerDownloads) {
                        OutlinedButton(onClick = onOpenDownloads, modifier = Modifier.fillMaxWidth()) {
                            Text(getString(R.string.quarantine_cut_open_downloads))
                        }
                        Spacer(Modifier.height(8.dp))
                    }
                    OutlinedButton(onClick = onOpenQuarantine, modifier = Modifier.fillMaxWidth()) {
                        Text(resolve(QuarantineWording.KEY_ACTION_OPEN_QUARANTINE))
                    }
                    Spacer(Modifier.height(8.dp))
                    TextButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text(getString(R.string.quarantine_cut_close)) }
                }
            }
        }
    }

    companion object {
        const val EXTRA_RECORD_ID = "quarantine_cut_record_id"
        const val EXTRA_MODE = "quarantine_cut_mode"
        const val MODE_CUT = "cut"
        const val MODE_DELETE_RECORD = "delete_record"
        private const val STATE_PENDING_ROUTE = "pending_route"
        private const val STATE_FINISH_DELETE = "finish_delete"

        fun intent(context: android.content.Context, recordId: String, mode: String = MODE_CUT): Intent =
            Intent(context, QuarantineCutActivity::class.java)
                .putExtra(EXTRA_RECORD_ID, recordId)
                .putExtra(EXTRA_MODE, mode)
    }
}
