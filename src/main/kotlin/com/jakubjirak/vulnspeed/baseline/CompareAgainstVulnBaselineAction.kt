/*
 * Copyright (c) 2026 Jakub Jirák. All rights reserved.
 * Licensed under the proprietary license. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.baseline

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.fileChooser.FileChooserFactory
import com.intellij.openapi.fileChooser.FileSaverDescriptor
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.vfs.VfsUtil
import com.intellij.ui.JBColor
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTabbedPane
import com.intellij.ui.table.JBTable
import com.jakubjirak.vulnspeed.core.VulnSpeedEngine
import com.jakubjirak.vulnspeed.model.ScanResult
import com.jakubjirak.vulnspeed.model.Vulnerability
import com.jakubjirak.vulnspeed.report.LastScanResultHolder
import java.awt.BorderLayout
import java.awt.datatransfer.StringSelection
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import javax.swing.Action
import javax.swing.BorderFactory
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.table.AbstractTableModel

/**
 * Runs the current scan against the stored security baseline and opens a
 * modal dialog summarising regressions, fixes, and persisted findings.
 *
 * Heavy work (reading the baseline, re-running a scan if necessary, computing
 * the diff) runs on a [Task.Backgroundable]; the dialog is only shown once
 * results are ready, keeping the EDT responsive.
 */
class CompareAgainstVulnBaselineAction : AnAction() {

    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabled = e.project != null
    }

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val basePath = project.basePath ?: System.getProperty("user.dir") ?: "."
        val root: Path = Paths.get(basePath)

        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Comparing against VulnSpeed baseline…", true) {
                override fun run(indicator: ProgressIndicator) {
                    indicator.isIndeterminate = true
                    try {
                        val baseline = VulnBaselineStore.load(VulnBaselineStore.defaultPath(root))
                        if (baseline == null) {
                            notify(
                                project,
                                "No baseline found",
                                "Create one via Tools → VulnSpeed → Create Security Baseline.",
                                NotificationType.WARNING,
                            )
                            return
                        }
                        val result = resolveOrScan(project, indicator)
                        val diff = VulnBaselineDiffService.diff(baseline, result.vulnerabilities, root)
                        ApplicationManager.getApplication().invokeLater {
                            DiffDialog(project, root, diff).show()
                        }
                    } catch (ex: VulnBaselineIoException) {
                        notify(project, "VulnSpeed baseline", "Failed to load baseline: ${ex.message}", NotificationType.ERROR)
                    } catch (ex: RuntimeException) {
                        notify(project, "VulnSpeed baseline", "Comparison failed: ${ex.message}", NotificationType.ERROR)
                    }
                }
            }
        )
    }

    private fun resolveOrScan(project: Project, indicator: ProgressIndicator): ScanResult {
        val holder = LastScanResultHolder.getInstance(project)
        val cached = holder.get()
        if (cached != null) return cached
        indicator.text = "No cached scan found — running project scan…"
        val engine = VulnSpeedEngine.getInstance(project)
        val result = engine.scanProject(project)
        holder.set(result)
        return result
    }

    private fun notify(project: Project, title: String, message: String, type: NotificationType) {
        NotificationGroupManager.getInstance()
            .getNotificationGroup("VulnSpeed Feedback")
            .createNotification(title, message, type)
            .notify(project)
    }

    private fun pluginVersion(): String {
        return com.intellij.ide.plugins.PluginManager.getPluginByClass(javaClass)?.version ?: "unknown"
    }

    /** Dialog rendering the three diff buckets with associated actions. */
    private inner class DiffDialog(
        private val project: Project,
        private val root: Path,
        private val diff: VulnBaselineDiff,
    ) : DialogWrapper(project, true) {

        init {
            title = if (diff.hasRegressions()) {
                "⚠ Regressions detected — VulnSpeed Baseline Diff"
            } else {
                "VulnSpeed Baseline Diff"
            }
            setOKButtonText("Close")
            init()
        }

        override fun createActions(): Array<Action> = arrayOf(okAction)

        override fun createCenterPanel(): JComponent {
            val tabs = JBTabbedPane()

            val newTable = vulnTable(diff.newFindings)
            val fixedTable = entryTable(diff.fixedEntries)
            val persistedTable = vulnTable(diff.persistedFindings)

            tabs.addTab("New Regressions (${diff.summary.totalNew})", JBScrollPane(newTable))
            tabs.addTab("Fixed (${diff.summary.totalFixed})", JBScrollPane(fixedTable))
            tabs.addTab("Persisted (${diff.summary.totalPersisted})", JBScrollPane(persistedTable))

            val summary = javax.swing.JLabel(summaryText()).apply {
                border = BorderFactory.createEmptyBorder(4, 8, 4, 8)
                foreground = if (diff.hasRegressions()) JBColor.RED else JBColor.foreground()
            }

            val buttons = JPanel()
            buttons.add(button("Copy Markdown Report") { copyMarkdown() })
            buttons.add(button("Update Baseline…") { updateBaseline() })
            buttons.add(button("Export Diff JSON…") { exportDiffJson() })
            buttons.add(button("Open in Problems View") { openFirstRegression() })

            val root = JPanel(BorderLayout())
            root.add(summary, BorderLayout.NORTH)
            root.add(tabs, BorderLayout.CENTER)
            root.add(buttons, BorderLayout.SOUTH)
            root.preferredSize = java.awt.Dimension(900, 520)
            return root
        }

        private fun summaryText(): String {
            val s = diff.summary
            return "New: ${s.totalNew}   Fixed: ${s.totalFixed}   Persisted: ${s.totalPersisted}"
        }

        private fun button(text: String, onClick: () -> Unit): javax.swing.JButton =
            javax.swing.JButton(text).also { it.addActionListener { onClick() } }

        private fun vulnTable(list: List<Vulnerability>): JBTable {
            val model = object : AbstractTableModel() {
                private val cols = arrayOf("Rule", "Severity", "CWE", "File", "Line", "Message")
                override fun getRowCount() = list.size
                override fun getColumnCount() = cols.size
                override fun getColumnName(i: Int) = cols[i]
                override fun getValueAt(r: Int, c: Int): Any {
                    val v = list[r]
                    return when (c) {
                        0 -> v.ruleId
                        1 -> v.severity.name
                        2 -> v.cwe
                        3 -> v.filePath
                        4 -> v.line
                        else -> v.message
                    }
                }
            }
            return JBTable(model)
        }

        private fun entryTable(list: List<VulnBaselineEntry>): JBTable {
            val model = object : AbstractTableModel() {
                private val cols = arrayOf("Rule", "Severity", "CWE", "File", "Line", "Accepted Reason")
                override fun getRowCount() = list.size
                override fun getColumnCount() = cols.size
                override fun getColumnName(i: Int) = cols[i]
                override fun getValueAt(r: Int, c: Int): Any {
                    val e = list[r]
                    return when (c) {
                        0 -> e.ruleId
                        1 -> e.severity
                        2 -> e.cwe
                        3 -> e.filePath
                        4 -> e.startLine
                        else -> (e.acceptedReason ?: "")
                    }
                }
            }
            return JBTable(model)
        }

        private fun copyMarkdown() {
            val md = VulnBaselineMarkdown.render(diff, pluginVersion())
            CopyPasteManager.getInstance().setContents(StringSelection(md))
            notify(project, "VulnSpeed baseline", "Markdown report copied to clipboard", NotificationType.INFORMATION)
        }

        private fun updateBaseline() {
            val confirm = Messages.showYesNoDialog(
                project,
                "Update the baseline to accept the current ${diff.summary.totalNew + diff.summary.totalPersisted} finding(s)?\n" +
                    "Fixed entries will be dropped.",
                "Update VulnSpeed Baseline",
                Messages.getWarningIcon()
            )
            if (confirm != Messages.YES) return
            ProgressManager.getInstance().run(object : Task.Backgroundable(project, "Updating VulnSpeed baseline…") {
                override fun run(indicator: ProgressIndicator) {
                    val result = LastScanResultHolder.getInstance(project).get() ?: return
                    val baseline = VulnBaseline.fromFindings(
                        findings = result.vulnerabilities,
                        projectRoot = root,
                        toolVersion = pluginVersion(),
                    )
                    val path = VulnBaselineStore.saveDefault(baseline, root)
                    VfsUtil.markDirtyAndRefresh(true, false, false, path.toFile())
                    notify(
                        project,
                        "VulnSpeed baseline updated",
                        "Wrote ${baseline.entries.size} entries to ${path.fileName}",
                        NotificationType.INFORMATION,
                    )
                }
            })
        }

        private fun exportDiffJson() {
            val descriptor = FileSaverDescriptor(
                "Export VulnSpeed Baseline Diff",
                "Choose a location to save the JSON diff",
                "json"
            )
            val dialog = FileChooserFactory.getInstance().createSaveFileDialog(descriptor, project)
            val baseVf = LocalFileSystem.getInstance().findFileByIoFile(File(root.toString()))
            val wrapper = dialog.save(baseVf, "vulnspeed-baseline-diff.json") ?: return
            val target: File = wrapper.file
            ProgressManager.getInstance().run(object : Task.Backgroundable(project, "Writing diff JSON…") {
                override fun run(indicator: ProgressIndicator) {
                    val gson = com.google.gson.GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create()
                    val payload = mapOf(
                        "summary" to diff.summary,
                        "newFindings" to diff.newFindings,
                        "fixedEntries" to diff.fixedEntries,
                        "persistedFindings" to diff.persistedFindings,
                    )
                    Files.write(target.toPath(), gson.toJson(payload).toByteArray(StandardCharsets.UTF_8))
                    VfsUtil.markDirtyAndRefresh(true, false, false, target)
                    notify(project, "VulnSpeed baseline", "Diff JSON written to ${target.name}", NotificationType.INFORMATION)
                }
            })
        }

        private fun openFirstRegression() {
            val first = diff.newFindings.firstOrNull() ?: run {
                Messages.showInfoMessage(project, "No regressions to open.", "VulnSpeed Baseline")
                return
            }
            val candidate = Paths.get(first.filePath).let {
                if (it.isAbsolute) it else root.resolve(it)
            }
            val vf = LocalFileSystem.getInstance().findFileByIoFile(candidate.toFile())
            if (vf == null) {
                Messages.showWarningDialog(project, "Cannot locate ${first.filePath} on disk.", "VulnSpeed Baseline")
                return
            }
            FileEditorManager.getInstance(project)
                .openTextEditor(OpenFileDescriptor(project, vf, (first.line - 1).coerceAtLeast(0), 0), true)
        }
    }
}
