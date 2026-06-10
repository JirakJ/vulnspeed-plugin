package com.jakubjirak.vulnspeed.editor

import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.Annotator
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.editor.colors.TextAttributesKey
import com.intellij.openapi.editor.markup.TextAttributes
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile
import com.intellij.ui.JBColor
import com.jakubjirak.vulnspeed.core.VulnSpeedEngine
import com.jakubjirak.vulnspeed.model.Severity
import com.jakubjirak.vulnspeed.quickfix.VulnSpeedQuickFix
import com.intellij.codeInsight.daemon.impl.HighlightInfo
import com.intellij.codeInsight.daemon.impl.HighlightInfoType
import java.awt.Color
import java.awt.Font

class VulnSpeedAnnotator : Annotator {
    override fun annotate(element: PsiElement, holder: AnnotationHolder) {
        // Annotate on the file node: its text range spans the whole document, so
        // findings anywhere in the file are valid annotation ranges. Gating on
        // firstChild instead made every finding outside the first token throw
        // "Range must be inside element being annotated".
        if (element !is PsiFile) return
        val psiFile = element
        val file = psiFile.virtualFile ?: return

        // AnnotationHolder is only valid inside this call — annotations must be
        // created synchronously, never from a pooled thread or invokeLater.
        try {
            val engine = VulnSpeedEngine.getInstance(element.project)
            val result = engine.scanFile(file, element.project)
            val document = com.intellij.openapi.fileEditor.FileDocumentManager.getInstance()
                .getDocument(file) ?: return

            result.vulnerabilities.forEach { vuln ->
                if (vuln.line < 1 || vuln.line > document.lineCount) return@forEach

                val lineStart = document.getLineStartOffset(vuln.line - 1)
                val lineEnd = document.getLineEndOffset(vuln.line - 1)
                val startOffset = (lineStart + vuln.column - 1).coerceIn(lineStart, lineEnd)
                val endOffset = minOf(startOffset + 50, lineEnd)

                if (endOffset > startOffset) {
                    holder.newAnnotation(
                        when (vuln.severity) {
                            Severity.CRITICAL -> com.intellij.lang.annotation.HighlightSeverity.ERROR
                            Severity.HIGH -> com.intellij.lang.annotation.HighlightSeverity.WARNING
                            Severity.MEDIUM -> com.intellij.lang.annotation.HighlightSeverity.WEAK_WARNING
                            else -> com.intellij.lang.annotation.HighlightSeverity.INFORMATION
                        },
                        buildMessage(vuln)
                    ).range(com.intellij.openapi.util.TextRange(startOffset, endOffset))
                        .create()
                }
            }
        } catch (e: Exception) {
            LOG.warn("VulnSpeed annotation failed for ${file.path}: ${e.message}")
        }
    }

    companion object {
        private val LOG = com.intellij.openapi.diagnostic.Logger.getInstance(VulnSpeedAnnotator::class.java)
    }
    
    private fun buildMessage(vuln: com.jakubjirak.vulnspeed.model.Vulnerability): String {
        return buildString {
            append("[VulnSpeed] ")
            append(vuln.ruleName)
            append(" (")
            append(vuln.severity.name)
            append(", CWE-")
            append(vuln.cwe)
            append(")")
            append("\n")
            append(vuln.message)
        }
    }
}

class DocumentEditorListener : com.intellij.openapi.editor.event.EditorFactoryListener {
    override fun editorCreated(event: com.intellij.openapi.editor.event.EditorFactoryEvent) {
        // Could be used for real-time scanning on editor open
    }
    
    override fun editorReleased(event: com.intellij.openapi.editor.event.EditorFactoryEvent) {
        // Cleanup if needed
    }
}
