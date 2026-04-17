/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

import com.intellij.ide.plugins.PluginManagerCore
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.application.PathManager
import com.intellij.openapi.extensions.PluginId
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.table.JBTable
import com.jakubjirak.vulnspeed.report.LastScanResultHolder
import java.awt.BorderLayout
import java.nio.file.Path
import java.nio.file.Paths
import javax.swing.Action
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.table.AbstractTableModel

/**
 * Tools → VulnSpeed → Enrich Vulnerabilities with CVE Metadata.
 *
 * Runs enrichment on the last scan's findings via [Task.Backgroundable], with
 * cancellation and progress reporting. The results are presented in a
 * [JBTable] showing CVE, package, CVSS, severity, fixed version, and CWEs.
 */
class EnrichVulnerabilitiesAction : AnAction() {

    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabled = e.project != null
    }

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val holder = LastScanResultHolder.getInstance(project)
        val scan = holder.get()
        if (scan == null) {
            notify(project, "No scan available", "Run a VulnSpeed scan first.", NotificationType.WARNING)
            return
        }
        val findings = scan.vulnerabilities
        if (findings.isEmpty()) {
            notify(project, "Nothing to enrich", "The most recent scan has no findings.", NotificationType.INFORMATION)
            return
        }

        ProgressManager.getInstance().run(object : Task.Backgroundable(
            project, "Enriching findings with CVE metadata…", true
        ) {
            override fun run(indicator: ProgressIndicator) {
                indicator.isIndeterminate = false
                val policy = EnrichmentPolicy(
                    userAgent = "VulnSpeed/${pluginVersion()} (+https://github.com/JirakJ/vulnspeed-plugin)",
                    nvdApiKey = System.getenv("NVD_API_KEY"),
                )
                val cacheDir = cacheDir()
                val enricher = CveEnricher(
                    CveMetadataCache(cacheDir),
                    OsvClient(policy = policy),
                    NvdClient(policy = policy),
                    policy,
                )
                val total = findings.size
                val enriched = ArrayList<EnrichedVulnerability>(total)
                for ((index, vuln) in findings.withIndex()) {
                    indicator.checkCanceled()
                    indicator.fraction = index.toDouble() / total.toDouble()
                    indicator.text = "Enriching ${index + 1} / $total"
                    enriched += enricher.enrich(vuln)
                }
                ApplicationManager.getApplication().invokeLater {
                    EnrichedDialog(project, enriched).show()
                }
            }
        })
    }

    private fun cacheDir(): Path {
        val config = runCatching { PathManager.getConfigPath() }.getOrNull()
        val base: Path = if (!config.isNullOrBlank()) {
            Paths.get(config, "vulnspeed", "cve-cache")
        } else {
            Paths.get(System.getProperty("user.home") ?: ".", ".vulnspeed", "cve-cache")
        }
        return base
    }

    private fun pluginVersion(): String {
        val id = PluginId.findId("com.jakubjirak.vulnspeed")
        return id?.let { PluginManagerCore.getPlugin(it) }?.version ?: "unknown"
    }

    private fun notify(project: Project, title: String, message: String, type: NotificationType) {
        NotificationGroupManager.getInstance()
            .getNotificationGroup("VulnSpeed Feedback")
            .createNotification(title, message, type)
            .notify(project)
    }

    private class EnrichedDialog(
        project: Project,
        private val enriched: List<EnrichedVulnerability>,
    ) : DialogWrapper(project, true) {

        init {
            title = "VulnSpeed — CVE Enrichment"
            setOKButtonText("Close")
            init()
        }

        override fun createActions(): Array<Action> = arrayOf(okAction)

        override fun createCenterPanel(): JComponent {
            val model = object : AbstractTableModel() {
                private val cols = arrayOf("CVE", "Package", "CVSS", "Severity", "Fixed In", "CWE")
                override fun getRowCount() = enriched.size
                override fun getColumnCount() = cols.size
                override fun getColumnName(i: Int) = cols[i]
                override fun getValueAt(r: Int, c: Int): Any {
                    val e = enriched[r]
                    val m = e.metadata
                    return when (c) {
                        0 -> e.cveId ?: "—"
                        1 -> "${e.vulnerability.filePath}:${e.vulnerability.line}"
                        2 -> if (m == null || m.cvssScore <= 0.0) "—" else "%.1f".format(m.cvssScore)
                        3 -> m?.severity ?: e.vulnerability.severity.name
                        4 -> m?.fixedVersions?.joinToString(", ")?.ifBlank { "—" } ?: "—"
                        else -> m?.cweIds?.joinToString(", ")?.ifBlank { "—" } ?: "—"
                    }
                }
            }
            val table = JBTable(model)
            val panel = JPanel(BorderLayout())
            panel.add(JBScrollPane(table), BorderLayout.CENTER)
            panel.preferredSize = java.awt.Dimension(900, 480)
            return panel
        }
    }
}
