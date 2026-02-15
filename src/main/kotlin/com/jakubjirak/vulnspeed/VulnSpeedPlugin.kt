package com.jakubjirak.vulnspeed

import com.intellij.openapi.components.Service
import com.intellij.openapi.project.Project

@Service(Service.Level.PROJECT)
class VulnSpeedPlugin(private val project: Project) {
    fun ping(): String = "VulnSpeed core initialized for ${project.name}"
}
