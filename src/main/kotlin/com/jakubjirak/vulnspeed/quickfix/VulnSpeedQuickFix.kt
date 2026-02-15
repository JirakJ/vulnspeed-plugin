package com.jakubjirak.vulnspeed.quickfix

import com.intellij.codeInspection.LocalQuickFix
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.openapi.command.WriteCommandAction
import com.intellij.openapi.editor.Document
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiElement
import com.jakubjirak.vulnspeed.model.FixSuggestion
import com.jakubjirak.vulnspeed.model.Vulnerability

class VulnSpeedQuickFix(
    private val vulnerability: Vulnerability,
    private val fixSuggestion: FixSuggestion
) : LocalQuickFix {
    
    override fun getFamilyName(): String = "VulnSpeed Security Fix"
    
    override fun getName(): String = "Fix: ${fixSuggestion.title}"
    
    override fun applyFix(project: Project, descriptor: ProblemDescriptor) {
        WriteCommandAction.runWriteCommandAction(project) {
            try {
                val element = descriptor.psiElement
                val file = element.containingFile ?: return@runWriteCommandAction
                val document = PsiDocumentManager.getInstance(project).getDocument(file)
                    ?: return@runWriteCommandAction
                
                val startOffset = document.getLineStartOffset(vulnerability.line - 1) + vulnerability.column - 1
                val endOffset = minOf(startOffset + 100, document.textLength)
                
                if (startOffset >= 0 && endOffset > startOffset && endOffset <= document.textLength) {
                    // For demo purposes, replace entire line with suggested fix
                    val lineEndOffset = document.getLineEndOffset(vulnerability.line - 1)
                    document.replaceString(
                        document.getLineStartOffset(vulnerability.line - 1),
                        lineEndOffset,
                        fixSuggestion.code
                    )
                    
                    // Commit changes
                    PsiDocumentManager.getInstance(project).commitDocument(document)
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }
}
