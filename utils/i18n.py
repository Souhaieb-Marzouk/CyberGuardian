"""
Lightweight English/French localisation.

The catalog lives in Python (not Qt .qm files) so a one-file PyInstaller build
needs no extra data files.  ``tr()`` falls back to English, then to the key
itself, so a missing translation degrades gracefully instead of crashing.

Language is persisted in ``ui.language`` (``en`` or ``fr``) and applies to the
whole UI, the AI prompt (the model is told to answer in French) and generated
VirusTotal summaries.
"""

from __future__ import annotations

from typing import Any, Dict

from utils.config import get_config
from utils.logging_utils import get_logger

logger = get_logger("utils.i18n")

LANGUAGES: Dict[str, str] = {"en": "English", "fr": "Français"}
DEFAULT_LANGUAGE = "en"

CATALOG: Dict[str, Dict[str, str]] = {
    "en": {
        # navigation / shell
        "nav.overview": "Overview",
        "nav.scans": "Scans",
        "nav.findings": "Findings",
        "nav.canaries": "Canaries",
        "nav.tools": "Tools",
        "nav.logs": "Logs",
        "nav.settings": "Settings",
        "app.theme_dark": "Dark mode",
        "app.theme_light": "Light mode",
        "app.settings": "Settings",
        # scan page
        "scan.run": "Run scan",
        "scan.stop": "Stop",
        "scan.details": "View details",
        "scan.export": "Export results",
        "scan.ready": "Ready when you are.",
        "scan.scanning": "Scanning…",
        "scan.stopping": "Stopping…",
        "scan.stopped_forced": "Scan stopped (forced).",
        "scan.complete": "Complete · {items} items · {findings} findings",
        "scan.stopped": "Stopped · {items} items · {findings} findings",
        "scan.failed": "Scan failed: {message}",
        "scan.stopping_status": "Stopping…",
        "scan.no_findings": "Run a scan with findings first.",
        "scan.export_all_none": "No scan results to export yet.",
        "scan.export_saved": "Saved {count} finding(s) to:\n{path}",
        "scan.export_failed": "Export failed",
        "scan.export_title": "Export",
        "scan.target_prompt": "Choose a folder to scan",
        # columns
        "col.risk": "Risk",
        "col.process": "Process",
        "col.pid": "PID",
        "col.ppid": "PPID",
        "col.parent": "Parent",
        "col.user": "User",
        "col.finding": "Finding",
        "col.rule": "Rule",
        "col.confidence": "Confidence",
        "col.path": "Path",
        "col.local": "Local",
        "col.remote": "Remote",
        "col.protocol": "Protocol",
        "col.key": "Key",
        "col.value": "Value",
        "col.data": "Data",
        "col.event": "Event",
        "col.provider": "Provider",
        "col.channel": "Channel",
        "col.file": "File",
        "col.type": "Type",
        # overview
        "overview.session": "local session  ·  private by design",
        "overview.healthy": "Your PC looks healthy.",
        "overview.check": "A few things are worth checking.",
        "overview.attention": "This PC needs your attention.",
        "overview.quick": "Run a quick check",
        "overview.all_scans": "All scans",
        "overview.worth": "Worth a look",
        "overview.sorted": "sorted by risk",
        "overview.checked": "What we checked",
        "overview.nothing": "Nothing needs attention right now.",
        "overview.checked.process": "Running processes and signatures",
        "overview.checked.registry": "Startup programs and services",
        "overview.checked.eventlog": "Windows event logs",
        "overview.checked.file": "Files and downloads",
        "overview.checked.network": "Network connections",
        "stat.items": "items checked",
        "stat.findings": "findings",
        "stat.apps": "applications",
        "stat.events": "events",
        # scans page
        "scans.title": "Scans",
        "scans.subtitle": "Pick a scanner. Results stay on this machine.",
        # tools
        "tools.title": "Tools",
        "tools.subtitle": "Startup, software, reputation checks, canaries and quarantine.",
        "tools.open": "Open",
        # logs
        "logs.title": "Activity log",
        # settings
        "settings.title": "Settings",
        "settings.appearance": "Appearance",
        "settings.theme": "Theme",
        "settings.language": "Language",
        "settings.detection": "Detection",
        "settings.deep": "Enable deep analysis on supported scans",
        "settings.online": "Check hashes with VirusTotal (slower, needs API key)",
        "settings.advanced": "Open advanced settings (API keys, whitelist, YARA)",
        "settings.light": "Light",
        "settings.dark": "Dark",
        # findings
        "findings.title": "Findings",
        "findings.empty": "Nothing found yet. Run a scan to populate this page.",
        "findings.filter_all": "All risks",
        "findings.filter_critical": "Critical",
        "findings.filter_high": "High",
        "findings.filter_medium": "Medium",
        "findings.filter_low": "Low",
        "findings.count": "{count} finding(s)",
        "findings.view": "View details",
        "findings.export_all": "Export all results",
        "findings.export_title": "Export all results",
        # dialog
        "detail.tab.details": "Details",
        "detail.tab.remediation": "Remediation",
        "detail.tab.ai": "AI analysis",
        "detail.tab.vt": "VirusTotal Check",
        "detail.event_fields": "event fields",
        "detail.field": "Field",
        "detail.value": "Value",
        "detail.why": "why it was flagged",
        "detail.raw": "raw evidence (JSON)",
        "detail.reason_none": "No reason recorded.",
        "detail.remediation_none": "No specific remediation was recorded.",
        "detail.steps": "recommended steps",
        "detail.ai_intro": (
            "Send this finding and its evidence to your configured AI provider for a "
            "verdict, a step-by-step verification plan and remediation guidance."
        ),
        "detail.ai_run": "Analyze with AI",
        "detail.ai_busy": "Analyzing…",
        "detail.ai_contact": "Contacting provider…",
        "detail.ai_no_provider": "No provider configured.",
        "detail.ai_failed": "Analysis failed:\n\n{message}",
        "detail.ai_verdict": "VERDICT: {verdict}",
        "detail.ai_confidence": "Confidence: {confidence}    Risk score: {score}/100",
        "detail.ai_detailed": "DETAILED ANALYSIS",
        "detail.ai_verify": "STEP 1 — VERIFY BEFORE YOU ACT",
        "detail.ai_contain": "STEP 2 — CONTAIN / ISOLATE",
        "detail.ai_remediate": "STEP 3 — REMOVE AND RESTORE",
        "detail.ai_validate": "STEP 4 — CONFIRM IT IS GONE",
        "detail.ai_mitre": "MITRE ATT&CK:",
        "detail.whitelist": "Add to whitelist",
        "detail.locate": "Open file location",
        "detail.close": "Close",
        "detail.open_folder": "Open folder",
        "detail.copy": "Copy report",
        "detail.copied": "Incident summary copied to the clipboard.",
        "detail.copy_title": "Copied",
        # VT tab
        "detail.unknown_parent": "unknown parent",
        "detail.unknown_process": "unknown process",
        "detail.ai_api_key": "Add an API key in Settings → Advanced settings → AI Analysis.",
        "vt.intro": (
            "Checks every IoC in this finding (hashes, IPs, domains, URLs) against "
            "VirusTotal. Results are shown here and automatically included in the "
            "AI analysis. Free API keys are limited to 4 requests per minute."
        ),
        "vt.key_ok": "API key configured.",
        "vt.key_missing": (
            "No VirusTotal API key configured. Add one in Settings → Advanced settings "
            "(API keys) to enable this tab."
        ),
        "vt.run": "Check IoCs on VirusTotal",
        "vt.running": "Checking…",
        "vt.open": "Open selected on VirusTotal",
        "vt.ioc_count": "{count} IoC(s) detected in this finding.",
        "vt.no_iocs": "No IoC detected in this finding.",
        "vt.contacting": (
            "Contacting VirusTotal… this is rate-limited (free tier: 4 requests/minute), "
            "so a finding with several IoCs can take a minute."
        ),
        "vt.not_configured": "VirusTotal is not configured: add an API key in Settings → Advanced settings.",
        "vt.failed": "VirusTotal check failed: {message}",
        "vt.summary": "{summary}  ·  highest risk: {risk}  ·  these results are included in the AI analysis.",
        "vt.col_type": "Type",
        "vt.col_indicator": "Indicator",
        "vt.col_verdict": "Verdict",
        "vt.col_detections": "Detections",
        "vt.col_details": "Details",
        "vt.malicious": "MALICIOUS",
        "vt.clean": "no detections",
        "vt.unknown": "unknown",
        "vt.error": "error",
        "vt.hash": "File hash",
        "vt.ip": "IP address",
        "vt.domain": "Domain",
        "vt.url": "URL",
        # canaries
        "canary.banner": "POSSIBLE INTRUSION",
        "canary.timeline": "timeline",
        "canary.evidence": "technical evidence",
        "canary.action": "what to do now",
        "canary.detected": "detected {when} · {count} event(s) since {first}",
        "canary.kind.encrypted": "encrypted",
        "canary.kind.modified": "modified",
        "canary.kind.deleted": "deleted",
        "canary.kind.renamed": "renamed",
        "canary.kind.touched": "touched",
        "canary.kind.accessed": "accessed",
        "tools.tab.startup": "Startup",
        "tools.tab.software": "Software",
        "tools.tab.check": "Check a file or link",
        "tools.tab.canary": "Ransomware canaries",
        "tools.tab.quarantine": "Quarantine",
        "tools.refresh": "Refresh",
        "tools.disable": "Disable selected",
        "tools.enable": "Enable selected",
        "tools.check_updates": "Check for updates",
        "tools.browse": "Browse…",
        "tools.check": "Check",
        "tools.install": "Install canaries",
        "tools.check_now": "Check now",
        "tools.remove": "Remove",
        "tools.restore": "Restore selected",
        "tools.delete": "Delete permanently",
        "tools.update": "Update",
        "tools.col.name": "Name",
        "tools.col.impact": "Impact",
        "tools.col.source": "Source",
        "tools.col.state": "State",
        "tools.col.publisher": "Publisher",
        "tools.col.application": "Application",
        "tools.col.installed": "Installed",
        "tools.col.latest": "Latest",
        "tools.col.status": "Status",
        "tools.col.action": "Action",
        "tools.col.file": "File",
        "tools.col.original": "Original path",
        "tools.col.size": "Size",
        "tools.col.quarantined": "Quarantined",
        "gauge.excellent": "Excellent",
        "gauge.good": "Good",
        "gauge.fair": "Fair",
        "gauge.poor": "Poor",
        "gauge.no_data": "No scan yet",
        "overview.findings_count": "{count} findings",
        "overview.no_scan_detail": "Run a scan to get a score for this PC.",
        "detail.ai_export": "Export report (HTML)",
        "detail.ai_cached": "Cached result",
        "detail.vt_export": "Export report (HTML)",
        "export.saved": "Report saved to:\n{path}",
        "export.html": "HTML (*.html)",
        "about.about_short": "About",
        "about.byline": "by {author}",
        "about.settings_blurb": "Version, author, project links and legal notice.",
        "about.role": "Designed & architected by",
        "about.tagline": "Local-first malware detection and threat hunting for Windows.",
        "about.project": "Project",
        "about.github": "GitHub repository",
        "about.releases": "Releases",
        "about.issues": "Report an issue",
        "about.legal": "Legal",
        "about.license": "License",
        "about.rights": "All rights reserved.",
        "about.built": "Built with",
        "about.privacy": "Local-first by design",
        "about.close": "Close",
        "about.open_about": "About CyberGuardian",
        "about.about_app": "About this application",
        "about.version": "Version {version}",
        "about.third_party": "Third-party notices",
        "about.privacy_note": (
            "Scans and evidence stay on this machine. Only the AI analyses and "
            "VirusTotal checks you explicitly start send the selected finding."
        ),
        "canary.title": "Ransomware canaries",
        "canary.intro": (
            "Decoy documents are placed in the folders ransomware encrypts first. "
            "If one is changed, renamed or deleted, you get an immediate alert with "
            "a full incident report."
        ),
        "canary.arm": "Arm canaries",
        "canary.check": "Check now",
        "canary.disarm": "Disarm",
        "canary.armed": "{count} armed",
        "canary.not_armed": "Not armed",
        "canary.events": "{count} recorded event(s)",
        "canary.last": " · last {when}",
        "canary.col.detected": "Detected",
        "canary.col.canary": "Canary",
        "canary.col.event": "Event",
        "canary.col.location": "Location",
        "canary.open": "Open report",
        "canary.armed_title": "Canaries armed",
        "canary.armed_message": (
            "Created {count} decoy document(s) in Documents, Desktop, Downloads, "
            "OneDrive and Public Documents.\n\nLeave them alone; CyberGuardian checks "
            "them every few seconds."
        ),
        "canary.disarm_title": "Disarm canaries",
        "canary.disarm_question": "Remove the decoy files and clear the incident history?",
        "canary.disarmed": "Disarmed",
        "canary.disarmed_message": "Removed {count} canary file(s).",
        "canary.intact": "All canary files are intact.",
        "canary.alert_title": "Possible ransomware activity",
        "canary.alert_box": "Canary alert",
        "canary.alert_text": "<b>{name}</b> was {kind}.",
        "canary.alert_info": (
            "Location: {location}\nDetected: {when}\n\n{action}"
        ),
        "canary.dismiss": "Dismiss",
        "canary.report": "Open report",
        # misc
        "common.yes": "Yes",
        "common.no": "No",
        "common.cancel": "Cancel",
        "common.save": "Save",
        "common.close": "Close",
        "common.error": "Error",
        "common.warning": "Warning",
        "common.information": "Information",
        "overview.subline": (
            "Check what starts with Windows, what is running now, and the last "
            "24 hours of activity — all on this machine."
        ),
        "overview.no_findings": "No findings yet",
        "overview.realtime": "Real-time ready",
        "overview.health": "health score",
        "stat.objects": "objects checked",
        "stat.events_log": "log events",
        "scan.page.processes": "Processes",
        "scan.page.files": "Files",
        "scan.page.network": "Network",
        "scan.page.registry": "Registry",
        "scan.page.activity": "Activity",
        "scan.desc.processes": "What is running right now, and what looks wrong.",
        "scan.desc.files": "Static analysis of a folder: YARA, entropy, PE, Office, stego.",
        "scan.desc.network": "Live connections, listeners and C2-style patterns.",
        "scan.desc.registry": "Autoruns, services and persistence locations.",
        "scan.desc.activity": "Logons, services, tasks and tampering in Windows logs.",
        "tools.toolbox": "Toolbox",
        "tools.toolbox_body": "Startup impact, installed software, file/link checks, canaries, quarantine.",
        "tools.health": "PC health",
        "tools.health_body": "Score, recommendations and what changed since last time.",
    },
    "fr": {
        "nav.overview": "Vue d'ensemble",
        "nav.scans": "Analyses",
        "nav.findings": "Détections",
        "nav.canaries": "Canaris",
        "nav.tools": "Outils",
        "nav.logs": "Journaux",
        "nav.settings": "Paramètres",
        "app.theme_dark": "Mode sombre",
        "app.theme_light": "Mode clair",
        "app.settings": "Paramètres",
        "scan.run": "Lancer l'analyse",
        "scan.stop": "Arrêter",
        "scan.details": "Voir les détails",
        "scan.export": "Exporter les résultats",
        "scan.ready": "Prêt quand vous voulez.",
        "scan.scanning": "Analyse en cours…",
        "scan.stopping": "Arrêt…",
        "scan.stopped_forced": "Analyse arrêtée (forcée).",
        "scan.complete": "Terminé · {items} éléments · {findings} détections",
        "scan.stopped": "Arrêté · {items} éléments · {findings} détections",
        "scan.failed": "Échec de l'analyse : {message}",
        "scan.stopping_status": "Arrêt…",
        "scan.no_findings": "Lancez d'abord une analyse avec des détections.",
        "scan.export_all_none": "Aucun résultat d'analyse à exporter.",
        "scan.export_saved": "{count} détection(s) enregistrée(s) dans :\n{path}",
        "scan.export_failed": "Échec de l'export",
        "scan.export_title": "Exporter",
        "scan.target_prompt": "Choisissez un dossier à analyser",
        "col.risk": "Risque",
        "col.process": "Processus",
        "col.pid": "PID",
        "col.ppid": "PPID",
        "col.parent": "Parent",
        "col.user": "Utilisateur",
        "col.finding": "Détection",
        "col.rule": "Règle",
        "col.confidence": "Confiance",
        "col.path": "Chemin",
        "col.local": "Local",
        "col.remote": "Distant",
        "col.protocol": "Protocole",
        "col.key": "Clé",
        "col.value": "Valeur",
        "col.data": "Données",
        "col.event": "Événement",
        "col.provider": "Fournisseur",
        "col.channel": "Canal",
        "col.file": "Fichier",
        "col.type": "Type",
        "overview.session": "session locale  ·  privée par conception",
        "overview.healthy": "Votre PC semble sain.",
        "overview.check": "Quelques éléments méritent une vérification.",
        "overview.attention": "Ce PC nécessite votre attention.",
        "overview.quick": "Lancer une vérification rapide",
        "overview.all_scans": "Toutes les analyses",
        "overview.worth": "À examiner",
        "overview.sorted": "trié par risque",
        "overview.checked": "Ce que nous avons vérifié",
        "overview.nothing": "Rien ne nécessite d'attention pour le moment.",
        "overview.checked.process": "Processus en cours et signatures",
        "overview.checked.registry": "Programmes de démarrage et services",
        "overview.checked.eventlog": "Journaux d'événements Windows",
        "overview.checked.file": "Fichiers et téléchargements",
        "overview.checked.network": "Connexions réseau",
        "stat.items": "éléments vérifiés",
        "stat.findings": "détections",
        "stat.apps": "applications",
        "stat.events": "événements",
        "scans.title": "Analyses",
        "scans.subtitle": "Choisissez un analyseur. Les résultats restent sur cette machine.",
        "tools.title": "Outils",
        "tools.subtitle": "Démarrage, logiciels, réputation, canaris et quarantaine.",
        "tools.open": "Ouvrir",
        "logs.title": "Journal d'activité",
        "settings.title": "Paramètres",
        "settings.appearance": "Apparence",
        "settings.theme": "Thème",
        "settings.language": "Langue",
        "settings.detection": "Détection",
        "settings.deep": "Activer l'analyse approfondie sur les analyses compatibles",
        "settings.online": "Vérifier les hachages avec VirusTotal (plus lent, clé API requise)",
        "settings.advanced": "Ouvrir les paramètres avancés (clés API, liste blanche, YARA)",
        "settings.light": "Clair",
        "settings.dark": "Sombre",
        "findings.title": "Détections",
        "findings.empty": "Aucune détection pour le moment. Lancez une analyse pour remplir cette page.",
        "findings.filter_all": "Tous les risques",
        "findings.filter_critical": "Critique",
        "findings.filter_high": "Élevé",
        "findings.filter_medium": "Moyen",
        "findings.filter_low": "Faible",
        "findings.count": "{count} détection(s)",
        "findings.view": "Voir les détails",
        "findings.export_all": "Exporter tous les résultats",
        "findings.export_title": "Exporter tous les résultats",
        "detail.tab.details": "Détails",
        "detail.tab.remediation": "Remédiation",
        "detail.tab.ai": "Analyse IA",
        "detail.tab.vt": "Vérification VirusTotal",
        "detail.event_fields": "champs de l'événement",
        "detail.field": "Champ",
        "detail.value": "Valeur",
        "detail.why": "pourquoi cela a été signalé",
        "detail.raw": "preuves brutes (JSON)",
        "detail.reason_none": "Aucune raison enregistrée.",
        "detail.remediation_none": "Aucune remédiation spécifique enregistrée.",
        "detail.steps": "étapes recommandées",
        "detail.ai_intro": (
            "Envoyez cette détection et ses preuves au fournisseur IA configuré pour "
            "obtenir un verdict, un plan de vérification étape par étape et des conseils "
            "de remédiation."
        ),
        "detail.ai_run": "Analyser avec l'IA",
        "detail.ai_busy": "Analyse en cours…",
        "detail.ai_contact": "Contact du fournisseur…",
        "detail.ai_no_provider": "Aucun fournisseur configuré.",
        "detail.ai_failed": "Échec de l'analyse :\n\n{message}",
        "detail.ai_verdict": "VERDICT : {verdict}",
        "detail.ai_confidence": "Confiance : {confidence}    Score de risque : {score}/100",
        "detail.ai_detailed": "ANALYSE DÉTAILLÉE",
        "detail.ai_verify": "ÉTAPE 1 — VÉRIFIER AVANT D'AGIR",
        "detail.ai_contain": "ÉTAPE 2 — CONTENIR / ISOLER",
        "detail.ai_remediate": "ÉTAPE 3 — SUPPRIMER ET RESTAURER",
        "detail.ai_validate": "ÉTAPE 4 — CONFIRMER LA DISPARITION",
        "detail.ai_mitre": "MITRE ATT&CK :",
        "detail.whitelist": "Ajouter à la liste blanche",
        "detail.locate": "Ouvrir l'emplacement",
        "detail.close": "Fermer",
        "detail.open_folder": "Ouvrir le dossier",
        "detail.copy": "Copier le rapport",
        "detail.copied": "Résumé de l'incident copié dans le presse-papiers.",
        "detail.copy_title": "Copié",
        "detail.unknown_parent": "parent inconnu",
        "detail.unknown_process": "processus inconnu",
        "detail.ai_api_key": "Ajoutez une clé API dans Paramètres → Paramètres avancés → Analyse IA.",
        "vt.intro": (
            "Vérifie chaque IoC de cette détection (hachages, IP, domaines, URL) auprès "
            "de VirusTotal. Les résultats sont affichés ici et inclus automatiquement "
            "dans l'analyse IA. Les clés API gratuites sont limitées à 4 requêtes/minute."
        ),
        "vt.key_ok": "Clé API configurée.",
        "vt.key_missing": (
            "Aucune clé API VirusTotal configurée. Ajoutez-en une dans Paramètres → "
            "Paramètres avancés (clés API) pour activer cet onglet."
        ),
        "vt.run": "Vérifier les IoC sur VirusTotal",
        "vt.running": "Vérification…",
        "vt.open": "Ouvrir la sélection sur VirusTotal",
        "vt.ioc_count": "{count} IoC détecté(s) dans cette détection.",
        "vt.no_iocs": "Aucun IoC détecté dans cette détection.",
        "vt.contacting": (
            "Contact de VirusTotal… limité en débit (offre gratuite : 4 requêtes/minute), "
            "une détection avec plusieurs IoC peut prendre une minute."
        ),
        "vt.not_configured": "VirusTotal n'est pas configuré : ajoutez une clé API dans Paramètres → Paramètres avancés.",
        "vt.failed": "Échec de la vérification VirusTotal : {message}",
        "vt.summary": "{summary}  ·  risque le plus élevé : {risk}  ·  ces résultats sont inclus dans l'analyse IA.",
        "vt.col_type": "Type",
        "vt.col_indicator": "Indicateur",
        "vt.col_verdict": "Verdict",
        "vt.col_detections": "Détections",
        "vt.col_details": "Détails",
        "vt.malicious": "MALVEILLANT",
        "vt.clean": "aucune détection",
        "vt.unknown": "inconnu",
        "vt.error": "erreur",
        "vt.hash": "Hachage de fichier",
        "vt.ip": "Adresse IP",
        "vt.domain": "Domaine",
        "vt.url": "URL",
        "canary.banner": "INTRUSION POSSIBLE",
        "canary.timeline": "chronologie",
        "canary.evidence": "preuves techniques",
        "canary.action": "que faire maintenant",
        "canary.detected": "détecté le {when} · {count} événement(s) depuis le {first}",
        "canary.kind.encrypted": "chiffré",
        "canary.kind.modified": "modifié",
        "canary.kind.deleted": "supprimé",
        "canary.kind.renamed": "renommé",
        "canary.kind.touched": "touché",
        "canary.kind.accessed": "accédé",
        "tools.tab.startup": "Démarrage",
        "tools.tab.software": "Logiciels",
        "tools.tab.check": "Vérifier un fichier ou un lien",
        "tools.tab.canary": "Canaris anti-rançongiciel",
        "tools.tab.quarantine": "Quarantaine",
        "tools.refresh": "Actualiser",
        "tools.disable": "Désactiver la sélection",
        "tools.enable": "Activer la sélection",
        "tools.check_updates": "Rechercher des mises à jour",
        "tools.browse": "Parcourir…",
        "tools.check": "Vérifier",
        "tools.install": "Installer les canaris",
        "tools.check_now": "Vérifier maintenant",
        "tools.remove": "Supprimer",
        "tools.restore": "Restaurer la sélection",
        "tools.delete": "Supprimer définitivement",
        "tools.update": "Mettre à jour",
        "tools.col.name": "Nom",
        "tools.col.impact": "Impact",
        "tools.col.source": "Source",
        "tools.col.state": "État",
        "tools.col.publisher": "Éditeur",
        "tools.col.application": "Application",
        "tools.col.installed": "Installé",
        "tools.col.latest": "Dernière",
        "tools.col.status": "Statut",
        "tools.col.action": "Action",
        "tools.col.file": "Fichier",
        "tools.col.original": "Chemin d'origine",
        "tools.col.size": "Taille",
        "tools.col.quarantined": "Mis en quarantaine",
        "gauge.excellent": "Excellent",
        "gauge.good": "Bon",
        "gauge.fair": "Moyen",
        "gauge.poor": "Faible",
        "gauge.no_data": "Aucune analyse",
        "overview.findings_count": "{count} détections",
        "overview.no_scan_detail": "Lancez une analyse pour obtenir un score pour ce PC.",
        "detail.ai_export": "Exporter le rapport (HTML)",
        "detail.ai_cached": "Résultat en cache",
        "detail.vt_export": "Exporter le rapport (HTML)",
        "export.saved": "Rapport enregistré dans :\n{path}",
        "export.html": "HTML (*.html)",
        "about.about_short": "À propos",
        "about.byline": "par {author}",
        "about.settings_blurb": "Version, auteur, liens du projet et mentions légales.",
        "about.role": "Conçu et architecturé par",
        "about.tagline": "Détection de logiciels malveillants et chasse aux menaces, 100 % local sous Windows.",
        "about.project": "Projet",
        "about.github": "Dépôt GitHub",
        "about.releases": "Versions",
        "about.issues": "Signaler un problème",
        "about.legal": "Mentions légales",
        "about.license": "Licence",
        "about.rights": "Tous droits réservés.",
        "about.built": "Développé avec",
        "about.privacy": "Local par conception",
        "about.close": "Fermer",
        "about.open_about": "À propos de CyberGuardian",
        "about.about_app": "À propos de cette application",
        "about.version": "Version {version}",
        "about.third_party": "Mentions tierces",
        "about.privacy_note": (
            "Les analyses et les preuves restent sur cette machine. Seules les "
            "analyses IA et vérifications VirusTotal que vous lancez explicitement "
            "envoient la détection sélectionnée."
        ),
        "canary.title": "Canaris anti-rançongiciel",
        "canary.intro": (
            "Des documents leurres sont placés dans les dossiers que les rançongiciels "
            "chiffrent en premier. Si l'un est modifié, renommé ou supprimé, vous recevez "
            "une alerte immédiate avec un rapport d'incident complet."
        ),
        "canary.arm": "Armer les canaris",
        "canary.check": "Vérifier maintenant",
        "canary.disarm": "Désarmer",
        "canary.armed": "{count} armé(s)",
        "canary.not_armed": "Non armé",
        "canary.events": "{count} événement(s) enregistré(s)",
        "canary.last": " · dernier {when}",
        "canary.col.detected": "Détecté",
        "canary.col.canary": "Canari",
        "canary.col.event": "Événement",
        "canary.col.location": "Emplacement",
        "canary.open": "Ouvrir le rapport",
        "canary.armed_title": "Canaris armés",
        "canary.armed_message": (
            "{count} document(s) leurre(s) créé(s) dans Documents, Bureau, Téléchargements, "
            "OneDrive et Documents publics.\n\nNe les touchez pas ; CyberGuardian les vérifie "
            "toutes les quelques secondes."
        ),
        "canary.disarm_title": "Désarmer les canaris",
        "canary.disarm_question": "Supprimer les fichiers leurres et effacer l'historique des incidents ?",
        "canary.disarmed": "Désarmé",
        "canary.disarmed_message": "{count} fichier(s) canari supprimé(s).",
        "canary.intact": "Tous les fichiers canaris sont intacts.",
        "canary.alert_title": "Activité de rançongiciel possible",
        "canary.alert_box": "Alerte canari",
        "canary.alert_text": "<b>{name}</b> a été {kind}.",
        "canary.alert_info": "Emplacement : {location}\nDétecté : {when}\n\n{action}",
        "canary.dismiss": "Ignorer",
        "canary.report": "Ouvrir le rapport",
        "common.yes": "Oui",
        "common.no": "Non",
        "common.cancel": "Annuler",
        "common.save": "Enregistrer",
        "common.close": "Fermer",
        "common.error": "Erreur",
        "common.warning": "Avertissement",
        "common.information": "Information",
        "overview.subline": (
            "Vérifiez ce qui démarre avec Windows, ce qui s'exécute maintenant et "
            "les dernières 24 heures d'activité — le tout sur cette machine."
        ),
        "overview.no_findings": "Aucune détection",
        "overview.realtime": "Temps réel prêt",
        "overview.health": "score de santé",
        "stat.objects": "objets vérifiés",
        "stat.events_log": "événements journaux",
        "scan.page.processes": "Processus",
        "scan.page.files": "Fichiers",
        "scan.page.network": "Réseau",
        "scan.page.registry": "Registre",
        "scan.page.activity": "Activité",
        "scan.desc.processes": "Ce qui s'exécute actuellement, et ce qui semble anormal.",
        "scan.desc.files": "Analyse statique d'un dossier : YARA, entropie, PE, Office, stéganographie.",
        "scan.desc.network": "Connexions actives, écouteurs et schémas de type C2.",
        "scan.desc.registry": "Programmes au démarrage, services et emplacements de persistance.",
        "scan.desc.activity": "Connexions, services, tâches et altérations dans les journaux Windows.",
        "tools.toolbox": "Boîte à outils",
        "tools.toolbox_body": "Impact au démarrage, logiciels installés, vérification de fichiers/liens, canaris, quarantaine.",
        "tools.health": "Santé du PC",
        "tools.health_body": "Score, recommandations et changements depuis la dernière fois.",
    },
}

_current = DEFAULT_LANGUAGE


def available_languages() -> Dict[str, str]:
    return dict(LANGUAGES)


def current_language() -> str:
    return _current


def set_language(code: str) -> str:
    global _current
    code = (code or "").lower()
    if code not in CATALOG:
        code = DEFAULT_LANGUAGE
    _current = code
    try:
        config = get_config()
        if config.config.ui.language != code:
            config.set("ui.language", code)
            config.save()
    except Exception as exc:  # pragma: no cover - config is best effort
        logger.debug(f"Could not persist language: {exc}")
    return code


def tr(key: str, **kwargs: Any) -> str:
    """Translate ``key`` into the current language (English fallback)."""
    text = CATALOG.get(_current, {}).get(key)
    if text is None:
        text = CATALOG[DEFAULT_LANGUAGE].get(key, key)
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            return text
    return text


def load_language() -> str:
    """Apply the persisted language at startup."""
    code = DEFAULT_LANGUAGE
    try:
        code = str(get_config().config.ui.language or DEFAULT_LANGUAGE).lower()
    except Exception:
        code = DEFAULT_LANGUAGE
    return set_language(code)


FIELD_LABELS_FR = {
    "Risk": "Risque",
    "Finding": "Détection",
    "Confidence": "Confiance",
    "Indicator": "Indicateur",
    "Detected": "Détecté",
    "Process": "Processus",
    "Parent process": "Processus parent",
    "User": "Utilisateur",
    "Signed": "Signé",
    "Signer": "Signataire",
    "Image path": "Chemin de l'image",
    "Directory": "Dossier",
    "Command line": "Ligne de commande",
    "Started": "Démarré",
    "File": "Fichier",
    "Size": "Taille",
    "MIME type": "Type MIME",
    "Entropy": "Entropie",
    "Created": "Créé",
    "Modified": "Modifié",
    "Local endpoint": "Point local",
    "Remote endpoint": "Point distant",
    "Remote host": "Hôte distant",
    "Protocol": "Protocole",
    "State": "État",
    "Connection age (s)": "Âge de la connexion (s)",
    "Bytes sent / received": "Octets envoyés / reçus",
    "Hive": "Ruche",
    "Key": "Clé",
    "Value name": "Nom de la valeur",
    "Value type": "Type de valeur",
    "Value data": "Données de la valeur",
    "Channel": "Canal",
    "Event ID": "ID d'événement",
    "Provider": "Fournisseur",
    "Record ID": "ID d'enregistrement",
    "Event time": "Heure de l'événement",
    "Level": "Niveau",
    "YARA rules": "Règles YARA",
    "Matched strings": "Chaînes correspondantes",
    "TargetUserName": "Nom d'utilisateur cible",
    "SubjectUserName": "Nom d'utilisateur sujet",
    "ServiceName": "Nom du service",
    "TaskName": "Nom de la tâche",
    "IpAddress": "Adresse IP",
    "ProcessName": "Nom du processus",
}


def field_label(name: str) -> str:
    """Translate a known evidence field label; unknown labels stay verbatim."""
    if _current == "fr":
        return FIELD_LABELS_FR.get(name, name)
    return name
