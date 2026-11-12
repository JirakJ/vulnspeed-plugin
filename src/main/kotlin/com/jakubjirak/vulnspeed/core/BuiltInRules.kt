/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.core

import com.jakubjirak.vulnspeed.model.Rule

/**
 * The built-in (non-secret) rules. Every rule is scoped to the languages where
 * its pattern means something, anchored on a concrete API or syntax, and — where
 * a single line cannot tell — gated on file context. Rules that could only be
 * expressed as "keyword X appears without Y somewhere" were removed in 2026.10.0
 * because a line regex cannot judge them.
 *
 * The rules live in [InjectionRules], [CryptoRules], [WebRules] and [InfrastructureRules];
 * each has positive and negative samples in the test resource `rule-samples.txt`.
 */
object BuiltInRules {

    val RULES: List<Rule> = InjectionRules.RULES + CryptoRules.RULES + WebRules.RULES + InfrastructureRules.RULES
}
