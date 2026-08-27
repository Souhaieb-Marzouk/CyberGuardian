"""
CyberGuardian AI Analyzer Module
================================
AI-powered analysis of security detections using multiple LLM providers.
Supports Deepseek, OpenAI, and Google Gemini.
"""

import os
import json
import logging
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger('cyberguardian.ai_analysis')

# Check if requests is available
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests module not available - AI analysis will not work")


class AIProvider(Enum):
    """Supported AI providers."""
    DEEPSEEK = "deepseek"
    OPENAI = "openai"
    GEMINI = "gemini"


class Verdict(Enum):
    """AI analysis verdict."""
    LEGITIMATE = "legitimate"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    NEEDS_INVESTIGATION = "needs_investigation"
    UNKNOWN = "unknown"


@dataclass
class AnalysisResult:
    """Result of AI analysis."""
    provider: AIProvider
    verdict: Verdict
    confidence: float
    summary: str
    detailed_analysis: str
    recommendations: List[str]
    indicators: List[str]
    risk_score: int  # 0-100
    threat_type: str = "unknown"
    mitre_techniques: List[str] = field(default_factory=list)
    severity_justification: str = ""
    analysis_time: datetime = field(default_factory=datetime.utcnow)
    raw_response: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'provider': self.provider.value,
            'verdict': self.verdict.value,
            'confidence': self.confidence,
            'summary': self.summary,
            'detailed_analysis': self.detailed_analysis,
            'recommendations': self.recommendations,
            'indicators': self.indicators,
            'risk_score': self.risk_score,
            'threat_type': self.threat_type,
            'mitre_techniques': self.mitre_techniques,
            'severity_justification': self.severity_justification,
            'analysis_time': self.analysis_time.isoformat(),
            'error': self.error
        }


class AIAnalyzer:
    """
    Multi-provider AI analyzer for security detections.
    Supports Deepseek, OpenAI, and Google Gemini.
    """
    
    # API endpoints
    API_ENDPOINTS = {
        AIProvider.DEEPSEEK: "https://api.deepseek.com/v1/chat/completions",
        AIProvider.OPENAI: "https://api.openai.com/v1/chat/completions",
        AIProvider.GEMINI: "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent",
    }
    
    # Model names
    MODEL_NAMES = {
        AIProvider.DEEPSEEK: "deepseek-chat",  # Using chat model for reliable JSON output
        AIProvider.OPENAI: "gpt-4o",
        AIProvider.GEMINI: "gemini-pro",
    }
    
    def __init__(self):
        self.api_keys: Dict[AIProvider, str] = {}
        self.enabled_providers: List[AIProvider] = []
        self._load_api_keys()
        self._executor = ThreadPoolExecutor(max_workers=3)
    
    def _load_api_keys(self):
        """Load API keys from secure storage, environment and config."""
        # First try secure storage
        try:
            from utils.secure_storage import load_all_api_keys
            saved_keys = load_all_api_keys()
            
            secure_keys = {
                AIProvider.DEEPSEEK: saved_keys.get('deepseek_api_key', ''),
                AIProvider.OPENAI: saved_keys.get('openai_api_key', ''),
                AIProvider.GEMINI: saved_keys.get('gemini_api_key', ''),
            }
            
            for provider, key in secure_keys.items():
                if key:
                    self.api_keys[provider] = key
                    if provider not in self.enabled_providers:
                        self.enabled_providers.append(provider)
        except Exception as e:
            logger.debug(f"Could not load API keys from secure storage: {e}")
        
        # Load from environment variables as fallback
        env_keys = {
            AIProvider.DEEPSEEK: os.environ.get('DEEPSEEK_API_KEY', ''),
            AIProvider.OPENAI: os.environ.get('OPENAI_API_KEY', ''),
            AIProvider.GEMINI: os.environ.get('GEMINI_API_KEY', ''),
        }
        
        for provider, key in env_keys.items():
            if key and provider not in self.api_keys:
                self.api_keys[provider] = key
                if provider not in self.enabled_providers:
                    self.enabled_providers.append(provider)
        
        # Load from config file as last resort (for backwards compatibility)
        try:
            from utils.config import get_config
            config = get_config()
            
            config_keys = {
                AIProvider.DEEPSEEK: getattr(config.config.api, 'deepseek_api_key', ''),
                AIProvider.OPENAI: getattr(config.config.api, 'openai_api_key', ''),
                AIProvider.GEMINI: getattr(config.config.api, 'gemini_api_key', ''),
            }
            
            for provider, key in config_keys.items():
                if key and provider not in self.api_keys:
                    self.api_keys[provider] = key
                    if provider not in self.enabled_providers:
                        self.enabled_providers.append(provider)
        except Exception as e:
            logger.debug(f"Could not load API keys from config: {e}")
    
    def set_api_key(self, provider: AIProvider, api_key: str):
        """Set API key for a provider."""
        if api_key:
            self.api_keys[provider] = api_key
            if provider not in self.enabled_providers:
                self.enabled_providers.append(provider)
        else:
            self.api_keys.pop(provider, None)
            if provider in self.enabled_providers:
                self.enabled_providers.remove(provider)
        
        # Save to secure storage
        self._save_api_key_secure(provider, api_key)
    
    def _save_api_key_secure(self, provider: AIProvider, api_key: str):
        """Save API key to secure storage."""
        try:
            from utils.secure_storage import get_secure_storage
            secure_storage = get_secure_storage()
            key_name = f'{provider.value}_api_key'
            secure_storage.save_api_key(key_name, api_key)
        except Exception as e:
            logger.error(f"Failed to save API key to secure storage: {e}")
        
        # Also save to config for backwards compatibility
        self._save_api_key_to_config(provider, api_key)
    
    def _save_api_key_to_config(self, provider: AIProvider, api_key: str):
        """Save API key to configuration file."""
        try:
            from utils.config import get_config
            config = get_config()
            
            attr_name = f'{provider.value}_api_key'
            if hasattr(config.config.api, attr_name):
                setattr(config.config.api, attr_name, api_key)
                config.save()
        except Exception as e:
            logger.error(f"Failed to save API key: {e}")
    
    def get_api_key(self, provider: AIProvider) -> Optional[str]:
        """Get API key for a provider."""
        return self.api_keys.get(provider)
    
    def is_provider_configured(self, provider: AIProvider) -> bool:
        """Check if a provider is configured with API key."""
        return bool(self.api_keys.get(provider))
    
    def get_configured_providers(self) -> List[AIProvider]:
        """Get list of configured providers."""
        return self.enabled_providers.copy()
    
    def analyze_detection(self, detection_data: Dict[str, Any], 
                         provider: Optional[AIProvider] = None) -> Optional[AnalysisResult]:
        """
        Analyze a detection using AI.
        
        Args:
            detection_data: Detection information dictionary
            provider: Specific provider to use (uses first available if None)
        
        Returns:
            AnalysisResult or None if no provider available
        """
        # Select provider
        if provider:
            if not self.is_provider_configured(provider):
                logger.warning(f"Provider {provider.value} is not configured")
                return None
            selected_provider = provider
        else:
            if not self.enabled_providers:
                logger.warning("No AI providers configured")
                return None
            selected_provider = self.enabled_providers[0]
        
        # Build prompt
        prompt = self._build_analysis_prompt(detection_data)
        
        # Call appropriate API
        try:
            if selected_provider == AIProvider.DEEPSEEK:
                return self._call_deepseek(prompt, detection_data)
            elif selected_provider == AIProvider.OPENAI:
                return self._call_openai(prompt, detection_data)
            elif selected_provider == AIProvider.GEMINI:
                return self._call_gemini(prompt, detection_data)
        except Exception as e:
            logger.error(f"AI analysis failed with {selected_provider.value}: {e}")
            return AnalysisResult(
                provider=selected_provider,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                summary="Analysis failed",
                detailed_analysis=f"Error: {str(e)}",
                recommendations=[],
                indicators=[],
                risk_score=0,
                error=str(e)
            )
        
        return None
    
    def analyze_detection_async(self, detection_data: Dict[str, Any],
                                callback: callable,
                                provider: Optional[AIProvider] = None):
        """
        Analyze detection asynchronously with callback.
        
        Args:
            detection_data: Detection information
            callback: Function to call with AnalysisResult
            provider: Specific provider to use
        """
        def _analyze():
            result = self.analyze_detection(detection_data, provider)
            if callback:
                callback(result)
        
        self._executor.submit(_analyze)
    
    def _build_analysis_prompt(self, detection_data: Dict[str, Any]) -> str:
        """Build analysis prompt from detection data including VirusTotal results."""
        detection_type = detection_data.get('detection_type', 'unknown')
        risk_level = detection_data.get('risk_level', 'unknown')
        indicator = detection_data.get('indicator', '')
        description = detection_data.get('description', '')
        evidence = detection_data.get('evidence', {})
        process_name = detection_data.get('process_name', '')
        process_id = detection_data.get('process_id', '')
        file_path = detection_data.get('file_path', '')
        command_line = detection_data.get('command_line', '')
        user = detection_data.get('user', '')
        
        # Build VirusTotal section if available
        vt_section = ""
        virustotal_result = detection_data.get('virustotal_result')
        if virustotal_result:
            # Build detailed VT information
            malicious_ip_details = []
            for ip_r in virustotal_result.get('ip_results', []):
                if ip_r.get('is_malicious'):
                    malicious_ip_details.append(
                        f"IP {ip_r.get('ip_address')}: {ip_r.get('detection_ratio')} ({ip_r.get('malicious_count')}/{ip_r.get('total_engines')} engines), "
                        f"Country: {ip_r.get('country', 'Unknown')}, AS: {ip_r.get('as_owner', 'Unknown')}, "
                        f"Threats: {', '.join(ip_r.get('threat_names', [])[:3])}"
                    )
            
            malicious_hash_details = []
            for h_r in virustotal_result.get('hash_results', []):
                if h_r.get('is_malicious'):
                    malicious_hash_details.append(
                        f"Hash {h_r.get('hash_value')}...: {h_r.get('detection_ratio')} "
                        f"({h_r.get('malicious_count')}/{h_r.get('total_engines')} engines), "
                        f"Type: {h_r.get('file_type', 'Unknown')}, "
                        f"Threats: {', '.join(h_r.get('threat_names', [])[:3])}"
                    )
            
            malicious_domain_details = []
            for d_r in virustotal_result.get('domain_results', []):
                if d_r.get('is_malicious'):
                    malicious_domain_details.append(
                        f"Domain {d_r.get('domain')}: {d_r.get('detection_ratio')}, "
                        f"Categories: {', '.join(d_r.get('categories', [])[:3])}"
                    )
            
            vt_section = f"""
=== CRITICAL: VIRUSTOTAL INTELLIGENCE RESULTS ===
The following Indicators of Compromise (IOCs) were checked against VirusTotal:

SUMMARY:
- Total IOCs Checked: {virustotal_result.get('iocs_checked', 0)}
- MALICIOUS IOCs Found: {virustotal_result.get('iocs_malicious', 0)}
- Clean IOCs: {virustotal_result.get('iocs_clean', 0)}
- Highest Risk Level from VT: {virustotal_result.get('highest_risk_level', 'unknown').upper()}
- Risk Adjustment Factor: {virustotal_result.get('overall_risk_adjustment', 0):.2f}

VT Summary: {virustotal_result.get('vt_summary', 'No summary available')}

ALL IOCs FOUND IN EVIDENCE:
{json.dumps(virustotal_result.get('all_iocs', {}), indent=2)}

MALICIOUS IP ADDRESSES:
{json.dumps(malicious_ip_details if malicious_ip_details else ['None found'], indent=2)}

MALICIOUS FILE HASHES:
{json.dumps(malicious_hash_details if malicious_hash_details else ['None found'], indent=2)}

MALICIOUS DOMAINS:
{json.dumps(malicious_domain_details if malicious_domain_details else ['None found'], indent=2)}

*** CRITICAL INSTRUCTION ***
You MUST consider these VirusTotal results in your analysis. 
- If VirusTotal shows {virustotal_result.get('iocs_malicious', 0)} malicious IOCs,  this significantly increases the confidence that the detection is a TRUE POSITIVE.
- Factor in the detection ratios and threat names from antivirus engines when making your assessment.
- Pay special attention to IPs/domains flagged as malicious - these are CONFIRMED threats.
- The risk level should be adjusted accordingly based on VT findings.
"""
        
        # Risk adjustment note if VT modified the risk level
        risk_adjusted_note = ""
        if detection_data.get('risk_adjusted_by_vt'):
            original_risk = detection_data.get('original_risk_level', risk_level)
            risk_adjusted_note = f"""
*** RISK LEVEL ADJUSTED ***
The original detection risk level was: {original_risk.upper()}
Based on VirusTotal findings, the risk level has been adjusted to: {risk_level.upper()}
This adjustment reflects the confirmed malicious nature of IOCs found in this detection.
"""
        
        prompt = f"""You are a senior cybersecurity threat analyst with expertise in malware analysis, incident response, and threat intelligence. Perform a comprehensive deep analysis of the following security detection.

=== DETECTION DETAILS ===
- Detection Type: {detection_type}
- Risk Level: {risk_level}
- Indicator: {indicator}
- Description: {description}
- Process Name: {process_name}
- Process ID: {process_id}
- File Path: {file_path}
- Command Line: {command_line}
- User: {user}
{risk_adjusted_note}
=== EVIDENCE ===
{json.dumps(evidence, indent=2)}
{vt_section}
=== ANALYSIS INSTRUCTIONS ===
Perform a thorough analysis considering:

1. THREAT CLASSIFICATION
   - Is this a known malware family, APT tool, or exploit?
   - What is the threat actor category (cybercrime, nation-state, hacktivist)?
   - MITRE ATT&CK techniques if applicable

2. TECHNICAL ANALYSIS
   - Analyze any command line arguments for malicious patterns
   - Evaluate file path legitimacy (system vs user locations)
   - Assess process relationships and parent processes
   - Check for evasion techniques, obfuscation, or anti-analysis

3. BEHAVIORAL INDICATORS
   - What malicious behaviors does this exhibit?
   - Is there evidence of persistence, lateral movement, data exfiltration?
   - Does it match known attack patterns or campaigns?

4. VIRUSTOTAL INTEGRATION
   - If VirusTotal results show malicious IOCs, incorporate this evidence strongly
   - Correlate VT threat names with known malware families
   - Use VT results to strengthen your confidence assessment
   - Adjust verdict and risk_score based on VT findings

5. RISK ASSESSMENT
   - Potential impact if executed (data theft, ransomware, backdoor)
   - Likelihood of false positive
   - Urgency level for remediation

6. REMEDIATION GUIDANCE
   - Specific steps to neutralize the threat (address it to beginners)
   - Containment recommendations (address it to beginners)
   - Verification steps to confirm removal (address it to beginners)

Provide your analysis in the following JSON format:
{{
    "verdict": "legitimate|suspicious|malicious|needs_investigation",
    "confidence": 0.0-1.0,
    "summary": "One paragraph executive summary of the threat including VirusTotal findings if applicable",
    "detailed_analysis": "Comprehensive technical analysis with sections for Threat Classification, Technical Analysis, Behavioral Indicators, VirusTotal Correlation (if applicable), and Risk Assessment. Be specific and detailed.",
    "recommendations": ["Priority-ordered list of specific actionable remediation steps"],
    "indicators": ["List of specific IOCs, suspicious behaviors, or malicious characteristics found - include VT-confirmed IOCs"],
    "risk_score": 0-100,
    "threat_type": "malware|apt|ransomware|trojan|backdoor|pua|false_positive|unknown",
    "mitre_techniques": ["Relevant MITRE ATT&CK technique IDs if applicable"],
    "severity_justification": "Explanation for the assigned risk score and verdict, including VirusTotal contribution if applicable"
}}

Respond ONLY with valid JSON. Be thorough and specific in your analysis."""

        return prompt
    
    def _parse_ai_response(self, response_text: str, provider: AIProvider,
                          detection_data: Dict[str, Any]) -> AnalysisResult:
        """Parse AI response into AnalysisResult with robust error handling."""
        try:
            # Clean response - remove markdown code blocks if present
            cleaned = response_text.strip()
            
            # Remove various markdown code block formats
            if cleaned.startswith('```json'):
                cleaned = cleaned[7:]
            elif cleaned.startswith('```'):
                cleaned = cleaned[3:]
            if cleaned.endswith('```'):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()
            
            # Try to find JSON object in the response
            # Look for the first { and last }
            json_start = cleaned.find('{')
            json_end = cleaned.rfind('}')
            
            if json_start != -1 and json_end != -1 and json_end > json_start:
                json_str = cleaned[json_start:json_end + 1]
            else:
                json_str = cleaned
            
            # Parse JSON
            try:
                data = json.loads(json_str)
            except json.JSONDecodeError:
                # Try to fix common JSON issues
                # Replace single quotes with double quotes (but not inside strings)
                import re
                # Fix unquoted keys
                json_str = re.sub(r'(\w+)(?=\s*:)', r'"\1"', json_str)
                # Fix single quotes
                json_str = json_str.replace("'", '"')
                # Try parsing again
                data = json.loads(json_str)
            
            # Map verdict string to enum
            verdict_map = {
                'legitimate': Verdict.LEGITIMATE,
                'suspicious': Verdict.SUSPICIOUS,
                'malicious': Verdict.MALICIOUS,
                'needs_investigation': Verdict.NEEDS_INVESTIGATION,
            }
            verdict_str = data.get('verdict', 'unknown').lower().replace(' ', '_').replace('-', '_')
            verdict = verdict_map.get(verdict_str, Verdict.UNKNOWN)
            
            # Ensure all required fields have safe defaults
            def safe_float(val, default=0.5):
                try:
                    return float(val)
                except (TypeError, ValueError):
                    return default
            
            def safe_int(val, default=50):
                try:
                    return int(float(val))
                except (TypeError, ValueError):
                    return default
            
            def safe_list(val):
                if isinstance(val, list):
                    return [str(x) for x in val if x is not None]
                elif isinstance(val, str):
                    return [val] if val else []
                return []
            
            def safe_str(val, default=''):
                if val is None:
                    return default
                return str(val)
            
            return AnalysisResult(
                provider=provider,
                verdict=verdict,
                confidence=safe_float(data.get('confidence'), 0.5),
                summary=safe_str(data.get('summary'), 'Analysis completed'),
                detailed_analysis=safe_str(data.get('detailed_analysis'), 'See raw response for details.'),
                recommendations=safe_list(data.get('recommendations')),
                indicators=safe_list(data.get('indicators')),
                risk_score=safe_int(data.get('risk_score'), 50),
                threat_type=safe_str(data.get('threat_type'), 'unknown'),
                mitre_techniques=safe_list(data.get('mitre_techniques')),
                severity_justification=safe_str(data.get('severity_justification'), ''),
                raw_response={'parsed': data, 'raw': response_text[:2000]}
            )
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            logger.debug(f"Response text (first 500 chars): {response_text[:500]}")
            # Try to extract useful information from non-JSON response
            return self._parse_text_fallback(response_text, provider, str(e))
        except Exception as e:
            logger.error(f"Unexpected error parsing AI response: {e}")
            return self._parse_text_fallback(response_text, provider, str(e))
    
    def _parse_text_fallback(self, response_text: str, provider: AIProvider, 
                            error_msg: str) -> AnalysisResult:
        """
        Fallback parser for non-JSON AI responses.
        Attempts to extract useful information from plain text responses.
        """
        text_lower = response_text.lower()
        
        # Try to detect verdict from text
        verdict = Verdict.NEEDS_INVESTIGATION
        confidence = 0.3
        
        if 'malicious' in text_lower or 'malware' in text_lower:
            verdict = Verdict.MALICIOUS
            confidence = 0.6
        elif 'suspicious' in text_lower:
            verdict = Verdict.SUSPICIOUS
            confidence = 0.5
        elif 'legitimate' in text_lower or 'safe' in text_lower or 'benign' in text_lower:
            verdict = Verdict.LEGITIMATE
            confidence = 0.5
        
        # Extract risk score if mentioned
        import re
        risk_score = 50
        risk_match = re.search(r'risk[_\s]*score[:\s]*(\d+)', text_lower)
        if risk_match:
            risk_score = min(100, max(0, int(risk_match.group(1))))
        
        return AnalysisResult(
            provider=provider,
            verdict=verdict,
            confidence=confidence,
            summary="AI analysis completed (text format - JSON parsing failed)",
            detailed_analysis=response_text[:1500] if response_text else "No response content available.",
            recommendations=["Manual review recommended", "Verify AI response format"],
            indicators=[],
            risk_score=risk_score,
            threat_type="unknown",
            mitre_techniques=[],
            severity_justification=f"Response was not in expected JSON format. Error: {error_msg}",
            raw_response={'raw': response_text[:2000], 'parse_error': error_msg},
            error=f"JSON parse error: {error_msg}"
        )
    
    def _call_deepseek(self, prompt: str, detection_data: Dict[str, Any]) -> AnalysisResult:
        """Call Deepseek API."""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests module not available")
        
        api_key = self.api_keys.get(AIProvider.DEEPSEEK)
        if not api_key:
            raise ValueError("Deepseek API key not configured")
        
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'model': self.MODEL_NAMES[AIProvider.DEEPSEEK],
            'messages': [
                {'role': 'system', 'content': 'You are a cybersecurity expert specializing in malware analysis and threat detection.'},
                {'role': 'user', 'content': prompt}
            ],
            'temperature': 0.3,
            'max_tokens': 2000
        }
        
        try:
            response = requests.post(
                self.API_ENDPOINTS[AIProvider.DEEPSEEK],
                headers=headers,
                json=payload,
                timeout=90  # Increased timeout
            )
            
            if response.status_code != 200:
                error_msg = f"API error: {response.status_code}"
                try:
                    error_data = response.json()
                    if 'error' in error_data:
                        error_msg = f"{error_msg} - {error_data['error'].get('message', response.text[:200])}"
                except:
                    error_msg = f"{error_msg} - {response.text[:200]}"
                raise Exception(error_msg)
            
            result = response.json()
            
            # Safely extract content
            if 'choices' not in result or len(result['choices']) == 0:
                raise ValueError("Empty response from API")
            
            content = result['choices'][0].get('message', {}).get('content', '')
            if not content:
                raise ValueError("No content in API response")
            
            return self._parse_ai_response(content, AIProvider.DEEPSEEK, detection_data)
            
        except requests.exceptions.Timeout:
            raise Exception("API request timed out after 90 seconds")
        except requests.exceptions.ConnectionError as e:
            raise Exception(f"Connection error: {str(e)}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request error: {str(e)}")
    
    def _call_openai(self, prompt: str, detection_data: Dict[str, Any]) -> AnalysisResult:
        """Call OpenAI API."""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests module not available")
        
        api_key = self.api_keys.get(AIProvider.OPENAI)
        if not api_key:
            raise ValueError("OpenAI API key not configured")
        
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'model': self.MODEL_NAMES[AIProvider.OPENAI],
            'messages': [
                {'role': 'system', 'content': 'You are a cybersecurity expert specializing in malware analysis and threat detection.'},
                {'role': 'user', 'content': prompt}
            ],
            'temperature': 0.3,
            'max_tokens': 2000
        }
        
        try:
            response = requests.post(
                self.API_ENDPOINTS[AIProvider.OPENAI],
                headers=headers,
                json=payload,
                timeout=90
            )
            
            if response.status_code != 200:
                error_msg = f"API error: {response.status_code}"
                try:
                    error_data = response.json()
                    if 'error' in error_data:
                        error_msg = f"{error_msg} - {error_data['error'].get('message', response.text[:200])}"
                except:
                    error_msg = f"{error_msg} - {response.text[:200]}"
                raise Exception(error_msg)
            
            result = response.json()
            
            if 'choices' not in result or len(result['choices']) == 0:
                raise ValueError("Empty response from API")
            
            content = result['choices'][0].get('message', {}).get('content', '')
            if not content:
                raise ValueError("No content in API response")
            
            return self._parse_ai_response(content, AIProvider.OPENAI, detection_data)
            
        except requests.exceptions.Timeout:
            raise Exception("API request timed out after 90 seconds")
        except requests.exceptions.ConnectionError as e:
            raise Exception(f"Connection error: {str(e)}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request error: {str(e)}")
    
    def _call_gemini(self, prompt: str, detection_data: Dict[str, Any]) -> AnalysisResult:
        """Call Google Gemini API."""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests module not available")
        
        api_key = self.api_keys.get(AIProvider.GEMINI)
        if not api_key:
            raise ValueError("Gemini API key not configured")
        
        url = f"{self.API_ENDPOINTS[AIProvider.GEMINI]}?key={api_key}"
        
        payload = {
            'contents': [
                {
                    'parts': [
                        {
                            'text': f"You are a cybersecurity expert specializing in malware analysis and threat detection.\n\n{prompt}"
                        }
                    ]
                }
            ],
            'generationConfig': {
                'temperature': 0.3,
                'maxOutputTokens': 2000
            }
        }
        
        headers = {
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=90
            )
            
            if response.status_code != 200:
                error_msg = f"API error: {response.status_code}"
                try:
                    error_data = response.json()
                    if 'error' in error_data:
                        error_msg = f"{error_msg} - {error_data['error'].get('message', response.text[:200])}"
                except:
                    error_msg = f"{error_msg} - {response.text[:200]}"
                raise Exception(error_msg)
            
            result = response.json()
            
            # Safely extract Gemini response
            if 'candidates' not in result or len(result['candidates']) == 0:
                raise ValueError("Empty response from API")
            
            candidate = result['candidates'][0]
            content = candidate.get('content', {}).get('parts', [{}])[0].get('text', '')
            if not content:
                raise ValueError("No content in API response")
            
            return self._parse_ai_response(content, AIProvider.GEMINI, detection_data)
            
        except requests.exceptions.Timeout:
            raise Exception("API request timed out after 90 seconds")
        except requests.exceptions.ConnectionError as e:
            raise Exception(f"Connection error: {str(e)}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request error: {str(e)}")
    
    def compare_providers(self, detection_data: Dict[str, Any]) -> Dict[AIProvider, AnalysisResult]:
        """
        Analyze detection with all configured providers for comparison.
        
        Returns:
            Dictionary mapping provider to analysis result
        """
        results = {}
        
        for provider in self.enabled_providers:
            try:
                result = self.analyze_detection(detection_data, provider)
                if result:
                    results[provider] = result
            except Exception as e:
                logger.error(f"Failed to analyze with {provider.value}: {e}")
        
        return results
    
    def get_consensus_verdict(self, results: Dict[AIProvider, AnalysisResult]) -> Verdict:
        """
        Get consensus verdict from multiple provider results.
        
        Args:
            results: Dictionary of provider results
        
        Returns:
            Consensus verdict
        """
        if not results:
            return Verdict.UNKNOWN
        
        # Weight by confidence
        verdict_scores = {
            Verdict.LEGITIMATE: 0.0,
            Verdict.SUSPICIOUS: 0.0,
            Verdict.MALICIOUS: 0.0,
            Verdict.NEEDS_INVESTIGATION: 0.0,
        }
        
        for result in results.values():
            if result.verdict in verdict_scores:
                verdict_scores[result.verdict] += result.confidence
        
        # Return highest scoring verdict
        return max(verdict_scores, key=verdict_scores.get)


# Global analyzer instance
_analyzer_instance: Optional[AIAnalyzer] = None


def get_ai_analyzer() -> AIAnalyzer:
    """Get the global AI analyzer instance."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = AIAnalyzer()
    return _analyzer_instance


def reset_analyzer():
    """Reset the global analyzer instance (useful after config changes)."""
    global _analyzer_instance
    _analyzer_instance = None
