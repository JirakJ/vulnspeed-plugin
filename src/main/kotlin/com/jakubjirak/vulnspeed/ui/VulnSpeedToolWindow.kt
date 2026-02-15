package com.jakubjirak.vulnspeed.ui

import com.intellij.openapi.project.Project
import com.intellij.ui.components.JBPanel
import com.jakubjirak.vulnspeed.model.ScanResult
import javax.swing.JLabel
import java.awt.BorderLayout

class VulnSpeedResultsPanel(private val project: Project) : JBPanel<VulnSpeedResultsPanel>() {
    
    init {
        layout = BorderLayout()
        add(JLabel("VulnSpeed Security Analysis Results"), BorderLayout.CENTER)
    }
    
    fun displayResult(result: ScanResult) {
        removeAll()
        
        val infoLabel = JLabel(
            "<html>Scan completed: ${result.vulnerabilities.size} vulnerabilities found<br/>" +
            "Critical: ${result.stats.criticalCount}, High: ${result.stats.highCount}, " +
            "Medium: ${result.stats.mediumCount}, Low: ${result.stats.lowCount}</html>"
        )
        add(infoLabel, BorderLayout.CENTER)
        
        revalidate()
        repaint()
    }
}
