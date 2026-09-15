package dev.okhsunrog.netdiag.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.okhsunrog.netdiag.proto.Check
import dev.okhsunrog.netdiag.proto.CheckStatus
import dev.okhsunrog.netdiag.proto.Finding
import dev.okhsunrog.netdiag.proto.FindingSeverity
import dev.okhsunrog.netdiag.ui.DiagnosisState
import dev.okhsunrog.netdiag.ui.EmptyState
import dev.okhsunrog.netdiag.ui.ExpandableRow
import dev.okhsunrog.netdiag.ui.KeyValueRow
import dev.okhsunrog.netdiag.ui.MonoText
import dev.okhsunrog.netdiag.ui.SectionCard
import dev.okhsunrog.netdiag.ui.StatusChip
import dev.okhsunrog.netdiag.ui.ThinDivider
import dev.okhsunrog.netdiag.ui.formatDuration
import dev.okhsunrog.netdiag.ui.label
import dev.okhsunrog.netdiag.ui.orderedEvidence
import dev.okhsunrog.netdiag.ui.severityColor
import dev.okhsunrog.netdiag.ui.statusColor

/**
 * The diagnosis screen.
 *
 * Findings come first and checks second, on purpose. The checks are the
 * evidence, but a person opening this screen wants the conclusion; the
 * evidence is there to be scrolled to when they want to verify it or when the
 * conclusion is wrong.
 */
@Composable
fun DiagnoseScreen(
    state: DiagnosisState,
    onDiagnose: () -> Unit,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 12.dp),
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Button(
                    onClick = onDiagnose,
                    enabled = !state.running,
                    modifier = Modifier.weight(1f),
                ) {
                    Text(if (state.running) "Diagnosing…" else "Diagnose connection")
                }
                if (state.running) {
                    OutlinedButton(onClick = onCancel) { Text("Cancel") }
                }
            }
        }

        if (state.running) {
            item {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
        }

        state.error?.let { error ->
            item {
                SectionCard(title = "Diagnosis failed") {
                    Text(error, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }

        state.response?.let { response ->
            item {
                SummaryCard(
                    summary = response.summary,
                    passed = response.passed,
                    failed = response.failed,
                    warned = response.warned,
                    skipped = response.skipped,
                    durationMs = response.totalDurationMs,
                    worst = response.worstSeverity,
                )
            }
        }

        if (state.response != null && state.response.findingsList.isNotEmpty()) {
            item {
                Text(
                    "Interpretation",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
            items(state.response.findingsList, key = { it.key }) { finding ->
                FindingCard(finding)
            }
        }

        if (state.checks.isNotEmpty()) {
            item {
                Text(
                    "Checks",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
            item {
                SectionCard(title = "", subtitle = null) {
                    state.checks.forEachIndexed { index, check ->
                        if (index > 0) ThinDivider()
                        CheckRow(check)
                    }
                }
            }
        }

        if (state.checks.isEmpty() && !state.running && state.response == null) {
            item {
                EmptyState(
                    message = "No diagnosis has been run yet.",
                    hint = "Runs about twenty checks across the framework, the kernel and " +
                        "the network, then explains what the combination means.",
                )
            }
        }
    }
}

@Composable
private fun SummaryCard(
    summary: String,
    passed: Int,
    failed: Int,
    warned: Int,
    skipped: Int,
    durationMs: Long,
    worst: FindingSeverity,
) {
    SectionCard(
        title = summary.ifEmpty { "Diagnosis complete" },
        subtitle = "took ${formatDuration(durationMs)}",
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatusChip("$passed pass", statusColor(CheckStatus.CHECK_STATUS_PASS))
            if (failed > 0) {
                StatusChip("$failed fail", statusColor(CheckStatus.CHECK_STATUS_FAIL))
            }
            if (warned > 0) {
                StatusChip("$warned warn", statusColor(CheckStatus.CHECK_STATUS_WARN))
            }
            if (skipped > 0) {
                StatusChip("$skipped skip", statusColor(CheckStatus.CHECK_STATUS_SKIP))
            }
        }
        if (worst != FindingSeverity.FINDING_SEVERITY_UNSPECIFIED) {
            Spacer(Modifier.height(8.dp))
            KeyValueRow(
                label = "Worst finding",
                value = worst.label(),
                valueColor = severityColor(worst),
                mono = false,
            )
        }
    }
}

@Composable
private fun FindingCard(finding: Finding) {
    val color = severityColor(finding.severity)
    SectionCard(
        title = finding.title,
        subtitle = "${finding.severity.label()} · ${finding.confidence}% confidence",
        trailing = { StatusChip(finding.severity.label().uppercase(), color) },
    ) {
        // The interpretation is written as prose with blank lines between
        // paragraphs; preserving them is what makes it readable.
        finding.interpretation.split("\n\n").forEach { paragraph ->
            Text(
                text = paragraph.replace("\n", " ").trim(),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(bottom = 8.dp),
            )
        }

        if (finding.suggestedActionsList.isNotEmpty()) {
            Spacer(Modifier.height(4.dp))
            Text(
                "What to try",
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
            )
            finding.suggestedActionsList.forEach { action ->
                Row(modifier = Modifier.padding(top = 4.dp)) {
                    Text("•  ", style = MaterialTheme.typography.bodyMedium)
                    Text(action, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }

        if (finding.supportingChecksList.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            MonoText(
                text = "based on: ${finding.supportingChecksList.joinToString(", ")}",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun CheckRow(check: Check) {
    val color = statusColor(check.status)
    ExpandableRow(
        summary = {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.Top,
            ) {
                StatusChip(check.status.label(), color, modifier = Modifier.width(56.dp))
                Spacer(Modifier.width(10.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = check.title.ifEmpty { check.key },
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                    )
                    Text(
                        text = check.detail,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        },
        detail = {
            MonoText(
                text = check.key,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (check.durationMs > 0) {
                MonoText(
                    text = "took ${check.durationMs} ms",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            check.orderedEvidence().forEach { (key, value) ->
                KeyValueRow(label = key, value = value)
            }
            if (check.dependsOnList.isNotEmpty()) {
                KeyValueRow(
                    label = "depends on",
                    value = check.dependsOnList.joinToString(", "),
                )
            }
            if (check.hasError() && check.error.detail.isNotEmpty()) {
                KeyValueRow(label = "error detail", value = check.error.detail)
            }
        },
    )
}

@Composable
fun DiagnosisRunningIndicator(modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.padding(16.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        CircularProgressIndicator(modifier = Modifier.width(20.dp).height(20.dp))
        Text("Running checks…", style = MaterialTheme.typography.bodyMedium)
    }
}
