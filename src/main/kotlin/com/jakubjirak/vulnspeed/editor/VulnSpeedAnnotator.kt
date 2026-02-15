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
        val file = element.containingFile?.virtualFile ?: return
        if (element != element.containingFile?.firstChild) return // Only annotate once per file
        
        ApplicationManager.getApplication().executeOnPooledThread {
            try {
                val engine = VulnSpeedEngine.getInstance(element.project)
                val result = engine.scanFile(file, element.project)
                
                ApplicationManager.getApplication().invokeLater {
                    result.vulnerabilities.forEach { vuln ->
                        // Create text range
                        val document = com.intellij.openapi.fileEditor.FileDocumentManager.getInstance()
                            .getDocument(file) ?: return@forEach
                        
                        val startOffset = document.getLineStartOffset(vuln.line - 1) + vuln.column - 1
                        val endOffset = minOf(startOffset + 50, document.textLength)
                        
                        if (startOffset < document.textLength && endOffset > startOffset) {
                            // Create annotation with appropriate severity
                            val annotation = holder.newAnnotation(
                                when (vuln.severity) {
                                    Severity.CRITICAL -> com.intellij.lang.annotation.HighlightSeverity.ERROR
                                    Severity.HIGH -> com.intellij.lang.annotation.HighlightSeverity.WARNING
                                    Severity.MEDIUM -> com.intellij.lang.annotation.HighlightSeverity.WEAK_WARNING
                                    else -> com.intellij.lang.annotation.HighlightSeverity.INFORMATION
                                },
                                buildMessage(vuln)
                            ).range(com.intellij.openapi.util.TextRange(startOffset, endOffset))
                            
                            annotation.create()
                        }
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
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
