/*
 * Copyright (c) 2026 Jakub Jirák.
 * Licensed under the Apache License, Version 2.0. See LICENSE for details.
 */
package com.jakubjirak.vulnspeed.enrichment

/** Redacted, structurally faithful samples of real OSV and NVD responses. */
object FeedSamples {

    /** OSV response for CVE-2021-44228 (Log4Shell). Real structure, shortened. */
    const val OSV_LOG4SHELL: String = """
    {
      "id": "GHSA-jfh8-c2jp-5v3q",
      "aliases": ["CVE-2021-44228"],
      "summary": "Remote code execution in Apache Log4j",
      "details": "Apache Log4j2 <=2.14.1 JNDI features do not protect against attacker-controlled LDAP.",
      "published": "2021-12-10T00:00:00Z",
      "modified": "2023-06-12T08:20:10Z",
      "severity": [{"type": "CVSS_V3", "score": "9.8"}],
      "database_specific": {"cwe_ids": ["CWE-502", "CWE-917"]},
      "references": [
        {"type": "ADVISORY", "url": "https://logging.apache.org/log4j/2.x/security.html"},
        {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}
      ],
      "affected": [
        {
          "package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"},
          "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}
          ]
        }
      ]
    }
    """

    /** NVD response for the same CVE. Real structure, shortened. */
    const val NVD_LOG4SHELL: String = """
    {
      "vulnerabilities": [
        {
          "cve": {
            "id": "CVE-2021-44228",
            "published": "2021-12-10T10:15:09.143",
            "lastModified": "2023-04-03T20:15:08.070",
            "descriptions": [
              {"lang": "en", "value": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features..."},
              {"lang": "es", "value": "..."}
            ],
            "metrics": {
              "cvssMetricV31": [
                {
                  "cvssData": {
                    "baseScore": 10.0,
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "baseSeverity": "CRITICAL"
                  }
                }
              ]
            },
            "weaknesses": [
              {"description": [{"lang": "en", "value": "CWE-502"}]},
              {"description": [{"lang": "en", "value": "CWE-917"}]}
            ],
            "references": [
              {"url": "https://logging.apache.org/log4j/2.x/security.html"}
            ]
          }
        }
      ]
    }
    """

    /** Minimal OSV body used for cheap tests. */
    const val OSV_MINIMAL: String = """
    {
      "id": "CVE-2099-0001",
      "summary": "Test vulnerability",
      "published": "2099-01-01T00:00:00Z",
      "modified": "2099-01-02T00:00:00Z",
      "severity": [{"type": "CVSS_V3", "score": "5.5"}],
      "database_specific": {"cwe_ids": ["89"]},
      "references": [],
      "affected": []
    }
    """

    /** Minimal NVD body used for cheap tests. */
    const val NVD_MINIMAL: String = """
    {
      "vulnerabilities": [
        {
          "cve": {
            "id": "CVE-2099-0002",
            "published": "2099-02-01T00:00:00.000",
            "lastModified": "2099-02-02T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Test only"}],
            "metrics": {
              "cvssMetricV31": [
                {"cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N", "baseSeverity": "HIGH"}}
              ]
            },
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
            "references": [{"url": "https://example.com/cve"}]
          }
        }
      ]
    }
    """
}
