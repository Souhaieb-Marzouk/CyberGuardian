"""
CyberGuardian Threat Intelligence Package
=========================================
"""

from .intel import (
    get_threat_intel,
    ThreatIntelManager,
    HashLookupResult,
    IPReputationResult,
    DomainReputationResult,
)

from .virustotal_checker import (
    get_virustotal_checker,
    is_virustotal_available,
    VirusTotalChecker,
    VirusTotalCache,
    VTAnalysisDepth,
    VTHashResult,
    VTIPResult,
    VTDomainResult,
    VTURLResult,
    IOCResult,
)

__all__ = [
    'get_threat_intel',
    'ThreatIntelManager',
    'HashLookupResult',
    'IPReputationResult',
    'DomainReputationResult',
    # VirusTotal
    'get_virustotal_checker',
    'is_virustotal_available',
    'VirusTotalChecker',
    'VirusTotalCache',
    'VTAnalysisDepth',
    'VTHashResult',
    'VTIPResult',
    'VTDomainResult',
    'VTURLResult',
    'IOCResult',
]
