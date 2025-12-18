"""
LLM Summarizer module for network anomaly detection system.
Contains functions for generating intelligent summaries of security findings.
"""

import logging
import json
from typing import Dict, List, Optional, Any
from datetime import datetime

# Set up logging
logger = logging.getLogger(__name__)

# System prompt for LLM hypothesis generation - V5.3 "ULTRA-STRICT Academic Intelligence Analysis"
SYSTEM_PROMPT = """<role_definition>
You are 'CognitiveSOC', an elite Tier-3 Cyber Threat Analyst presenting to a thesis defense committee. Your methodology is based on structured intelligence analysis frameworks. You must demonstrate sophisticated analytical thinking by considering multiple hypotheses, citing specific evidence, and providing detailed technical assessments that would impress cybersecurity experts.
</role_definition>

<critical_warnings>
⚠️ ABSOLUTE REQUIREMENT: Your entire response MUST be a single, valid JSON object starting with { and ending with }. 
⚠️ NO other text, explanations, or markdown formatting allowed.
⚠️ YOU WILL BE TERMINATED if you include ANY text outside the JSON structure.
⚠️ YOU WILL BE TERMINATED if you violate the minimum content requirements below.
⚠️ YOU WILL BE TERMINATED if you include MITRE techniques without explicit evidence support.
</critical_warnings>

<instructions>
MANDATORY JSON STRUCTURE - You MUST include ALL these sections with EXACT MINIMUM REQUIREMENTS:

Your analysis process is structured into a single `intelligence_analysis` object. You must perform these steps with HIGH ACADEMIC RIGOR:

1.  **Consider Multiple Hypotheses (MANDATORY 3+):** In the `hypotheses_considered` array, you MUST list EXACTLY THREE OR MORE plausible hypotheses. STRUCTURE THEM AS: 
    - Hypothesis 1: Primary threat hypothesis (most likely malicious scenario)
    - Hypothesis 2: Alternative attack vector hypothesis (different attack method)  
    - Hypothesis 3: Benign explanation hypothesis (legitimate activity explanation)
    - Optional: Additional hypotheses if evidence supports them
    ⚠️ LESS THAN 3 HYPOTHESES = IMMEDIATE TERMINATION

2.  **Cite Specific Evidence (MANDATORY 4+):** In the `supporting_evidence` array, list at least FOUR specific facts from the input report. Reference exact numbers, IPs, protocols, ports, and technical details. Show deep technical analysis.
    ⚠️ LESS THAN 4 EVIDENCE ITEMS = IMMEDIATE TERMINATION

3.  **Identify Critical Analysis Gaps (MANDATORY 3+):** In the `analysis_gaps` array, identify at least THREE pieces of missing information. CRITICAL RULE: You are FORBIDDEN from stating information is 'unknown' if it's already provided in the evidence.
    ⚠️ LESS THAN 3 ANALYSIS GAPS = IMMEDIATE TERMINATION
    ⚠️ CLAIMING KNOWN INFORMATION AS 'UNKNOWN' = IMMEDIATE TERMINATION

4.  **Formulate Detailed Final Hypothesis:** Create a comprehensive `threat_hypothesis` that shows sophisticated understanding of attack campaigns and adversary TTPs.

5.  **Comprehensive Framework Mapping:** Provide detailed `kill_chain_stage` and `mitre_attack_mapping` with multiple techniques when appropriate.

6.  **Professional Assessment:** Provide a detailed `assessment` with specific confidence reasoning and actionable recommendations.
</instructions>

<reasoning_guidelines>
* **Context Over Keywords:** Pay extreme attention to the *context* of anomalies, not just keywords. For protocols that can be used for covert channels (like **DNS** and **ICMP**), if you see evidence of `unusual data volume`, `high packet count`, or `abnormal patterns`, you MUST prioritize the **Command and Control (TA0011)** or **Exfiltration (TA0010)** tactics over generic Reconnaissance.
* **Specificity is Key:** If a technique in the Knowledge Primer has sub-techniques (e.g., `T1110.001`), and the evidence supports it, you MUST use the more specific sub-technique ID.
* **Link Evidence to Technique:** In your `supporting_evidence` array, explicitly state which piece of evidence leads you to select a specific MITRE technique. Example: "The high volume of REJ connections points directly to T1046 - Port Scan."
* **Evidence-Anchored Mapping:** ⚠️ CRITICAL ENFORCEMENT RULE: For EACH technique you list in `mitre_attack_mapping`, your `supporting_evidence` array MUST contain a string that explicitly justifies that choice by referencing a specific detail from the input data. If you cannot find direct evidence for a technique, DO NOT include it. VIOLATION = IMMEDIATE TERMINATION.
* **Protocol-Technique Alignment:** ⚠️ CRITICAL RULE: DO NOT map SSH authentication attacks to DNS tunneling techniques. If evidence shows SSH (port 22), authentication failures, or brute force attacks, use T1110 (Brute Force) under TA0001 (Initial Access). DNS techniques (T1071.004) require actual DNS traffic evidence. MIXING THESE = IMMEDIATE TERMINATION.
* **Data Diligence:** ⚠️ CRITICAL ENFORCEMENT RULE: You are FORBIDDEN from stating that information (like IPs, ports, protocols) is 'unknown' or 'needed' in the `analysis_gaps` if that information is already present in the input data. VIOLATION = IMMEDIATE TERMINATION.
* **MITRE Hierarchy Integrity:** ⚠️ CRITICAL ENFORCEMENT RULE: For each Tactic object you create in `mitre_attack_mapping`, the 'techniques' array inside it MUST ONLY contain Technique IDs that belong to that specific Tactic according to the KNOWLEDGE PRIMER. VIOLATION = IMMEDIATE TERMINATION.
</reasoning_guidelines>

<knowledge_primer>
Here is a curated list of common network-based tactics and techniques. Use this as your reference.

**TA0043 - Reconnaissance**
* T1046 - Port Scan
* T1595 - Active Scanning

**TA0001 - Initial Access**
* T1110 - Brute Force (Includes T1110.001 - Password Guessing)
* T1190 - Exploit Public-Facing Application

**TA0011 - Command and Control**
* T1071 - Application Layer Protocol (Includes T1071.004 - DNS Tunneling)
* T1568 - Dynamic Resolution (Includes T1568.002 - Domain Generation Algorithms)
* T1571 - Non-Standard Port

**TA0010 - Exfiltration**
* T1041 - Exfiltration Over C2 Channel
* T1048 - Exfiltration Over Alternative Protocol

**TA0040 - Impact**
* T1498 - Network Denial of Service (Includes DoS/DDoS)

</knowledge_primer>

<output_format>
The final JSON output MUST conform strictly to this structure. Note that `reasoning_chain` is now replaced by `intelligence_analysis`.
{
  "intelligence_analysis": {
    "hypotheses_considered": ["string"],
    "supporting_evidence": ["string"],
    "analysis_gaps": ["string"]
  },
  "threat_hypothesis": "string",
  "kill_chain_stage": "string",
  "mitre_attack_mapping": [{"tactic": "string", "techniques": ["string"]}],
  "assessment": {
    "confidence": {
      "level": "string",
      "score": integer
    },
    "summary": "string",
    "recommended_actions": ["string"]
  }
}
</output_format>

<example>
--- USER INPUT EXAMPLE ---
{
  "finding_summary": {"title": "Anomalous DNS Traffic from 10.0.2.15", "risk_score": 92},
  "evidence_statistics": {"ML Anomaly - High": 152},
  "key_evidence_details": [{"summary": "Unusual data packet size for DNS query detected."}]
}
--- YOUR OUTPUT EXAMPLE ---
{
  "intelligence_analysis": {
    "hypotheses_considered": ["Primary: An internal host is using DNS tunneling for C2 communication with external servers.","Alternative: A misconfigured application is generating unusual but benign DNS traffic patterns.","Benign: Legitimate software update or backup process using non-standard DNS resolution."],
    "supporting_evidence": ["A high count (152) of high-confidence ML anomalies specifically on DNS port 53 traffic.", "Evidence explicitly mentions 'unusual data packet size' which is a key technical indicator for DNS tunneling techniques.", "Source IP 10.0.2.15 shows consistent pattern of anomalous DNS behavior suggesting systematic rather than random activity.", "Risk score of 92/100 indicates multiple detection systems flagged this activity as highly suspicious."],
    "analysis_gaps": ["The destination domain names and DNS query content require packet capture analysis to determine exfiltration payload.", "Host 10.0.2.15 endpoint forensics needed to identify the specific process generating these DNS queries.", "Network topology context needed to understand if 10.0.2.15 should legitimately generate high-volume DNS traffic."]
  },
  "threat_hypothesis": "An internal host (10.0.2.15) is likely compromised and using DNS tunneling for command and control (C2) communication with external threat actors.",
  "kill_chain_stage": "Command & Control",
  "mitre_attack_mapping": [{"tactic": "TA0011 - Command and Control", "techniques": ["T1071.004 - DNS Tunneling"]}],
  "assessment": {
    "confidence": {"level": "High", "score": 95},
    "summary": "Strong technical evidence suggests an active, sophisticated C2 channel hiding within DNS traffic. This represents a critical threat requiring immediate response.",
    "recommended_actions": ["Immediately begin packet capture on all traffic from host 10.0.2.15 to analyze DNS query content.", "Query DNS logs for all domains resolved by this host in the past 24 hours.", "Isolate host 10.0.2.15 from the network pending comprehensive forensic analysis.", "Deploy additional DNS monitoring for similar patterns across the network."]
  }
}
</example>
"""

def generate_findings_summary(findings: List[Dict[str, Any]], 
                            time_window: str = "recent",
                            max_findings: int = 50) -> Dict[str, Any]:
    """
    Generate an intelligent summary of security findings using pattern analysis.
    
    Args:
        findings: List of alert/finding dictionaries
        time_window: Time window description for context
        max_findings: Maximum number of findings to analyze
        
    Returns:
        Dictionary with summary information
    """
    try:
        if not findings:
            return {
                'summary': "No security findings detected in the specified time window.",
                'total_findings': 0,
                'severity_breakdown': {},
                'top_patterns': [],
                'recommendations': []
            }
        
        # Limit findings to prevent overwhelming analysis
        findings = findings[:max_findings]
        
        # Analyze findings patterns
        severity_counts = {}
        source_ips = {}
        dest_ips = {}
        attack_types = {}
        protocols = {}
        
        for finding in findings:
            # Count by severity
            severity = finding.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count source IPs
            src_ip = finding.get('src_ip', 'unknown')
            source_ips[src_ip] = source_ips.get(src_ip, 0) + 1
            
            # Count destination IPs
            dest_ip = finding.get('dest_ip', 'unknown')
            dest_ips[dest_ip] = dest_ips.get(dest_ip, 0) + 1
            
            # Count attack types
            attack_type = finding.get('attack_type', finding.get('alert_type', 'unknown'))
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            # Count protocols
            protocol = finding.get('protocol', 'unknown')
            protocols[protocol] = protocols.get(protocol, 0) + 1
        
        # Generate summary text
        total_findings = len(findings)
        summary_parts = []
        
        # Overall summary
        summary_parts.append(f"Analyzed {total_findings} security findings from {time_window} activity.")
        
        # Severity breakdown
        if severity_counts:
            high_severity = severity_counts.get('high', 0) + severity_counts.get('critical', 0)
            if high_severity > 0:
                summary_parts.append(f"⚠️ {high_severity} high/critical severity alerts require immediate attention.")
        
        # Top source IPs
        top_sources = sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:3]
        if top_sources and top_sources[0][1] > 1:
            summary_parts.append(f"🔍 Most active source IP: {top_sources[0][0]} ({top_sources[0][1]} alerts)")
        
        # Top attack types
        top_attacks = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:3]
        if top_attacks:
            summary_parts.append(f"🎯 Primary threat type: {top_attacks[0][0]} ({top_attacks[0][1]} occurrences)")
        
        # Generate recommendations
        recommendations = generate_recommendations(findings, severity_counts, source_ips, attack_types)
        
        return {
            'summary': ' '.join(summary_parts),
            'total_findings': total_findings,
            'severity_breakdown': severity_counts,
            'top_source_ips': dict(top_sources),
            'top_attack_types': dict(top_attacks),
            'top_protocols': dict(sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:5]),
            'recommendations': recommendations,
            'analysis_timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error generating findings summary: {str(e)}")
        return {
            'summary': f"Error analyzing findings: {str(e)}",
            'total_findings': len(findings) if findings else 0,
            'error': str(e)
        }

def generate_recommendations(findings: List[Dict[str, Any]], 
                           severity_counts: Dict[str, int],
                           source_ips: Dict[str, int],
                           attack_types: Dict[str, int]) -> List[str]:
    """
    Generate actionable security recommendations based on findings analysis.
    
    Args:
        findings: List of findings
        severity_counts: Count of findings by severity
        source_ips: Count of findings by source IP
        attack_types: Count of findings by attack type
        
    Returns:
        List of recommendation strings
    """
    recommendations = []
    
    try:
        # High severity recommendations
        high_severity = severity_counts.get('high', 0) + severity_counts.get('critical', 0)
        if high_severity > 0:
            recommendations.append(f"🚨 Prioritize investigation of {high_severity} high/critical severity alerts")
        
        # Repeated source IP recommendations
        repeat_sources = {ip: count for ip, count in source_ips.items() if count > 3 and ip != 'unknown'}
        if repeat_sources:
            top_repeat = max(repeat_sources.items(), key=lambda x: x[1])
            recommendations.append(f"🔒 Consider blocking/monitoring IP {top_repeat[0]} ({top_repeat[1]} alerts)")
        
                # Attack type specific recommendations
        top_attack = max(attack_types.items(), key=lambda x: x[1]) if attack_types else None
        if top_attack and top_attack[0] != 'unknown':
            attack_type, count = top_attack
            if 'scan' in attack_type.lower():
                recommendations.append("🔍 Deploy network segmentation to limit scan impact")
            elif 'malware' in attack_type.lower() or 'c2' in attack_type.lower():
                recommendations.append("🦠 Initiate malware investigation and endpoint isolation")
            elif 'ddos' in attack_type.lower():
                recommendations.append("⚡ Activate DDoS mitigation and traffic filtering")
        
        # Volume-based recommendations
        if len(findings) > 20:
            recommendations.append("📊 High alert volume detected - consider tuning detection rules")
        
        # General recommendations
        if not recommendations:
            recommendations.append("✅ Continue monitoring - current threat level appears manageable")
        
        return recommendations[:5]  # Limit to top 5 recommendations
        
    except Exception as e:
        logger.error(f"Error generating recommendations: {str(e)}")
        return ["⚠️ Unable to generate specific recommendations due to analysis error"]

def create_executive_summary(findings: List[Dict[str, Any]], 
                           time_period: str = "24 hours") -> str:
    """
    Create a concise executive summary for management reporting.
    
    Args:
        findings: List of security findings
        time_period: Time period for the report
        
    Returns:
        Executive summary string
    """
    try:
        if not findings:
            return f"No security incidents detected in the past {time_period}. Network monitoring systems are operational and no immediate threats identified."
        
        total_alerts = len(findings)
        
        # Count critical/high severity
        critical_count = sum(1 for f in findings if f.get('severity') in ['critical', 'high'])
        
        # Count unique source IPs
        unique_sources = len(set(f.get('src_ip', 'unknown') for f in findings if f.get('src_ip') != 'unknown'))
        
        # Most common attack type
        attack_types = {}
        for finding in findings:
            attack_type = finding.get('attack_type', finding.get('alert_type', 'unknown'))
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        top_attack = max(attack_types.items(), key=lambda x: x[1])[0] if attack_types else 'various'
        
        # Create executive summary
        summary = f"Security Summary ({time_period}): "
        summary += f"{total_alerts} total security alerts detected. "
        
        if critical_count > 0:
            summary += f"{critical_count} high-priority incidents require immediate attention. "
        else:
            summary += "No critical incidents identified. "
        
        summary += f"Activity observed from {unique_sources} unique source IPs, "
        summary += f"primarily involving {top_attack} attack patterns. "
        
        if critical_count > 0:
            summary += "Recommend immediate security team review and response."
        else:
            summary += "Continued monitoring recommended with no immediate action required."
        
        return summary
        
    except Exception as e:
        logger.error(f"Error creating executive summary: {str(e)}")
        return f"Executive Summary: {len(findings) if findings else 0} security events detected in {time_period}. Detailed analysis unavailable due to processing error."

def format_finding_for_summary(finding: Dict[str, Any]) -> str:
    """
    Format a single finding for inclusion in summaries.
    
    Args:
        finding: Single finding dictionary
        
    Returns:
        Formatted string representation
    """
    try:
        timestamp = finding.get('timestamp', 'unknown time')
        src_ip = finding.get('src_ip', 'unknown')
        dest_ip = finding.get('dest_ip', 'unknown')
        attack_type = finding.get('attack_type', finding.get('alert_type', 'unknown'))
        severity = finding.get('severity', 'unknown')
        
        return f"[{timestamp}] {severity.upper()}: {attack_type} from {src_ip} to {dest_ip}"
        
    except Exception as e:
        return f"Finding format error: {str(e)}"

def create_llm_user_prompt(report: dict) -> str:
    """
    Create a formatted user prompt for LLM analysis from a pre-analysis report.
    
    Args:
        report: Dictionary containing pre-analysis report data
        
    Returns:
        Formatted prompt string for LLM
    """
    # Trích xuất dữ liệu từ report để dễ sử dụng
    summary = report.get('finding_summary', {})
    stats = report.get('evidence_statistics', {})
    key_evidence = report.get('key_evidence_details', [])
    timeline = report.get('timeline_summary', {})

    # Build the prompt string
    prompt = f"""
Analyze the following Pre-Analysis Report and generate a threat hypothesis in the required JSON format.

--- PRE-ANALYSIS REPORT ---

### Finding Summary
* **Title:** {summary.get('title', 'N/A')}
* **Primary IP:** {summary.get('ip', 'N/A')}
* **Risk Score:** {summary.get('risk_score', 'N/A')} / 100
* **Total Evidence Events:** {summary.get('evidence_count', 'N/A')}

### Evidence Statistics
* **Threat Breakdown:** {', '.join([f'{k}: {v}' for k, v in stats.items() if v > 0]) or 'No specific threats identified.'}

### Key Evidence (Detailed Analysis)
"""
    # Thêm từng bằng chứng vào prompt với COMPLETE INFORMATION
    for i, evidence in enumerate(key_evidence):
        # Extract comprehensive data structures
        representative_evidence = evidence.get('representative_evidence', {})
        conn_details = representative_evidence.get('connection_details', {})
        technical_details = representative_evidence.get('technical_details', {})
        network_analysis = evidence.get('network_analysis', {})
        
        # NEW: Complete sequences for pattern analysis
        evidence_sequence = evidence.get('complete_evidence_sequence', [])
        connection_sequence = evidence.get('complete_connection_sequence', [])
        
        # Basic evidence info
        prompt += f"\n{i+1}. **Evidence Category #{i+1}**\n"
        prompt += f"   **Summary:** {evidence.get('summary', 'N/A')}\n"
        prompt += f"   **Category Confidence Score:** {evidence.get('confidence_score', 'N/A')}\n"
        prompt += f"   **Total Events in Category:** {len(evidence_sequence)}\n"
        
        # ENHANCED: Representative Connection Details
        if conn_details:
            prompt += f"   **Representative Connection:**\n"
            prompt += f"     - Source: {conn_details.get('id.orig_h', 'N/A')}:{conn_details.get('id.orig_p', 'N/A')}\n"
            prompt += f"     - Destination: {conn_details.get('id.resp_h', 'N/A')}:{conn_details.get('id.resp_p', 'N/A')}\n"
            prompt += f"     - Protocol: {conn_details.get('proto', 'N/A').upper()}\n"
            prompt += f"     - Service: {conn_details.get('service', 'N/A')}\n"
            prompt += f"     - Connection State: {conn_details.get('conn_state', 'N/A')}\n"
            prompt += f"     - Duration: {conn_details.get('duration', 'N/A')}s\n"
            prompt += f"     - Bytes: {conn_details.get('orig_bytes', 0)} sent, {conn_details.get('resp_bytes', 0)} received\n"
        
        # NEW: Complete Evidence Sequence (CRITICAL for attack pattern analysis)
        if evidence_sequence:
            prompt += f"   **Complete Evidence Sequence ({len(evidence_sequence)} events):**\n"
            for j, ev in enumerate(evidence_sequence[:10]):  # Limit to 10 for readability
                prompt += f"     {j+1}. [{ev.get('timestamp', 'N/A')}] {ev.get('type', 'N/A')} - "
                prompt += f"{ev.get('matched_scenario', 'N/A')} (Confidence: {ev.get('confidence', 'N/A')}, "
                prompt += f"Detector: {ev.get('detector', 'N/A')})\n"
            
            if len(evidence_sequence) > 10:
                prompt += f"     ... and {len(evidence_sequence) - 10} more events\n"
        
        # NEW: Complete Connection Sequence (CRITICAL for network pattern analysis)
        if connection_sequence:
            prompt += f"   **Complete Connection Sequence ({len(connection_sequence)} connections):**\n"
            for j, conn in enumerate(connection_sequence[:10]):  # Limit to 10 for readability
                prompt += f"     {j+1}. {conn.get('src', 'N/A')} -> {conn.get('dst', 'N/A')} "
                prompt += f"({conn.get('proto', 'N/A')}/{conn.get('service', 'N/A')}) "
                prompt += f"State: {conn.get('state', 'N/A')}, Duration: {conn.get('duration', 'N/A')}s, "
                prompt += f"Bytes: {conn.get('bytes_sent', 0)}↑/{conn.get('bytes_recv', 0)}↓\n"
            
            if len(connection_sequence) > 10:
                prompt += f"     ... and {len(connection_sequence) - 10} more connections\n"
        
        # ENHANCED Network Analysis with timeline
        if network_analysis:
            prompt += f"   **Network Pattern Analysis:**\n"
            prompt += f"     - Total Connections: {network_analysis.get('total_connections', 'N/A')}\n"
            prompt += f"     - Unique Destinations: {network_analysis.get('unique_destinations', 'N/A')}\n"
            prompt += f"     - Destination IPs: {', '.join(network_analysis.get('destination_ips', [])[:5])}\n"
            prompt += f"     - Destination Ports: {', '.join(map(str, network_analysis.get('destination_ports', [])[:10]))}\n"
            prompt += f"     - Connection States: {network_analysis.get('connection_states', {})}\n"
            prompt += f"     - Pattern Diversity: {network_analysis.get('connection_timeline', {}).get('pattern_diversity', 'N/A')} services\n"
        
        # Technical Analysis
        if technical_details:
            prompt += f"   **Technical Analysis:**\n"
            prompt += f"     - Matched Scenario: {technical_details.get('matched_scenario', 'N/A')}\n"
            prompt += f"     - ML Confidence: {technical_details.get('ml_confidence', 'N/A')}\n"
            prompt += f"     - Detector: {technical_details.get('detector', 'N/A')}\n"
        
        prompt += "\n"  # Add spacing between evidence items

    # ENHANCED Timeline and context metadata with attack progression analysis
    context_metadata = report.get('context_metadata', {})
    
    # NEW: Add attack progression summary from evidence sequences
    attack_progression = []
    for evidence in key_evidence:
        evidence_sequence = evidence.get('complete_evidence_sequence', [])
        if evidence_sequence:
            category = evidence.get('summary', 'Unknown')
            first_event = evidence_sequence[0] if evidence_sequence else {}
            last_event = evidence_sequence[-1] if evidence_sequence else {}
            
            progression_entry = {
                'category': category,
                'event_count': len(evidence_sequence),
                'time_span': f"{first_event.get('timestamp', 'N/A')} to {last_event.get('timestamp', 'N/A')}",
                'progression_pattern': f"{first_event.get('matched_scenario', 'N/A')} → {last_event.get('matched_scenario', 'N/A')}"
            }
            attack_progression.append(progression_entry)
    
    prompt += f"""
### Enhanced Timeline Analysis
* **Overall Duration:** {timeline.get('duration', 'N/A')}
* **First Event:** {timeline.get('first_evidence_at', 'N/A')}
* **Last Event:** {timeline.get('last_evidence_at', 'N/A')}
* **Total Events:** {timeline.get('total_events', 'N/A')}
* **Timeline Completeness:** {timeline.get('timeline_completeness', 'N/A')}

### Attack Progression Analysis
"""
    
    if attack_progression:
        for i, prog in enumerate(attack_progression):
            prompt += f"* **Phase {i+1}:** {prog['category']} - {prog['event_count']} events over {prog['time_span']}\n"
            prompt += f"  - Pattern Evolution: {prog['progression_pattern']}\n"
    else:
        prompt += "* No clear attack progression identified from evidence sequences\n"
    
    prompt += f"""
### Context Metadata
* **Analysis Complexity:** {context_metadata.get('analysis_complexity', 'N/A')}
* **Highest Risk Category:** {context_metadata.get('highest_risk_category', 'N/A')}
* **Unique Threat Categories:** {context_metadata.get('total_unique_categories', 'N/A')}
* **Total Evidence Categories:** {len(key_evidence)}
* **Evidence Density:** {timeline.get('total_events', 0) / max(len(key_evidence), 1):.1f} events per category (avg)

--- END OF COMPREHENSIVE REPORT ---
"""
    return prompt

def get_hypothesis_from_llm(pre_analysis_report: dict, llm_client) -> dict:
    """
    Generate threat hypothesis from LLM based on pre-analysis report.
    
    Args:
        pre_analysis_report: Dictionary containing structured analysis data
        llm_client: OpenAI-compatible client for LLM API calls
        
    Returns:
        Dictionary containing threat hypothesis and assessment, or error information
    """
    try:
        # Create user prompt from the pre-analysis report
        user_prompt = create_llm_user_prompt(pre_analysis_report)
        
        # Prepare messages for LLM
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ]
        
        logger.info("Sending request to LLM for threat hypothesis generation")
        
        # Call LLM API - Enhanced for thesis defense with STRICT JSON compliance
        response = llm_client.chat.completions.create(
            model="meta-llama-3-8b-instruct",  # Model name from test_llm.py
            messages=messages,
            temperature=0.3,  # Higher temperature for creative analysis while maintaining structure
            max_tokens=2000,  # More tokens for comprehensive intelligence analysis
            # Add JSON mode if supported
            response_format={"type": "json_object"} if hasattr(llm_client, 'response_format') else None
        )
        
        # Extract response content
        raw_response = response.choices[0].message.content.strip()
        logger.info(f"Received LLM response: {raw_response[:100]}...")
        
        # JSON cleanup and parsing logic
        try:
            # BƯỚC 1 & 2: Dọn dẹp chuỗi JSON - tìm và trích xuất JSON object
            start_index = raw_response.find('{')
            end_index = raw_response.rfind('}')
            
            if start_index != -1 and end_index != -1 and end_index > start_index:
                clean_json_str = raw_response[start_index : end_index + 1]
                logger.info(f"Extracted JSON: {clean_json_str[:100]}...")
            else:
                # Fallback: try to fix incomplete JSON
                clean_json_str = raw_response.strip()
                if clean_json_str.startswith('{') and not clean_json_str.endswith('}'):
                    clean_json_str += '}'
                elif not clean_json_str.startswith('{'):
                    raise ValueError("No valid JSON object found in the response")
            
            # BƯỚC 2.5: Fix common JSON errors - trailing commas, quotes
            import re
            
            # Fix trailing commas in arrays and objects
            clean_json_str = re.sub(r',(\s*[}\]])', r'\1', clean_json_str)
            
            # Fix single quotes to double quotes (common LLM error)
            clean_json_str = re.sub(r"'([^']*)':", r'"\1":', clean_json_str)
            
            # Fix unescaped quotes in values
            clean_json_str = re.sub(r':\s*"([^"]*)"([^",}]*)"', r': "\1\2"', clean_json_str)
            
            logger.info(f"JSON after cleanup: {clean_json_str[:200]}...")
            
            # BƯỚC 3: Parse chuỗi đã được dọn dẹp
            parsed_data = json.loads(clean_json_str)
            
            # STRICT Validation for V5.3 Ultra-Strict Intelligence Analysis format
            if not isinstance(parsed_data, dict):
                raise ValueError("Response is not a valid JSON object")
            
            required_fields = ['intelligence_analysis', 'threat_hypothesis', 'kill_chain_stage', 'mitre_attack_mapping', 'assessment']
            missing_fields = [field for field in required_fields if field not in parsed_data]
            
            if missing_fields:
                logger.error(f"LLM FAILED to include required fields: {missing_fields}")
                logger.error(f"LLM response was: {raw_response}")
                raise ValueError(f"⚠️ LLM did not follow system prompt. Missing required fields: {missing_fields}")
            
            # STRICT Validation intelligence_analysis structure
            intelligence_analysis = parsed_data.get('intelligence_analysis', {})
            if isinstance(intelligence_analysis, dict):
                intel_fields = ['hypotheses_considered', 'supporting_evidence', 'analysis_gaps']
                missing_intel_fields = [field for field in intel_fields if field not in intelligence_analysis]
                if missing_intel_fields:
                    logger.error(f"LLM FAILED intelligence_analysis format: {missing_intel_fields}")
                    raise ValueError(f"⚠️ Intelligence analysis incomplete. Missing: {missing_intel_fields}")
                    
                # Check ULTRA-STRICT minimum content requirements (V5.3)
                hypotheses = intelligence_analysis.get('hypotheses_considered', [])
                if len(hypotheses) < 3:
                    logger.error(f"LLM VIOLATION: Only {len(hypotheses)} hypotheses, required 3+ for TERMINATION avoidance")
                    raise ValueError(f"⚠️ CRITICAL VIOLATION: LLM provided only {len(hypotheses)} hypotheses. System prompt requires exactly 3 or more. IMMEDIATE TERMINATION as specified.")
                    
                supporting_evidence = intelligence_analysis.get('supporting_evidence', [])
                if len(supporting_evidence) < 4:
                    logger.error(f"LLM VIOLATION: Only {len(supporting_evidence)} evidence items, required 4+ for TERMINATION avoidance")
                    raise ValueError(f"⚠️ CRITICAL VIOLATION: LLM provided only {len(supporting_evidence)} evidence items. System prompt requires 4 or more. IMMEDIATE TERMINATION as specified.")
                    
                analysis_gaps = intelligence_analysis.get('analysis_gaps', [])
                if len(analysis_gaps) < 3:
                    logger.error(f"LLM VIOLATION: Only {len(analysis_gaps)} analysis gaps, required 3+ for TERMINATION avoidance")
                    raise ValueError(f"⚠️ CRITICAL VIOLATION: LLM provided only {len(analysis_gaps)} analysis gaps. System prompt requires 3 or more. IMMEDIATE TERMINATION as specified.")
                    
                # Additional V5.3 ULTRA-STRICT Evidence-Anchored Mapping validation
                mitre_mappings = parsed_data.get('mitre_attack_mapping', [])
                for mapping in mitre_mappings:
                    techniques = mapping.get('techniques', [])
                    for technique in techniques:
                        # Check if each technique has supporting evidence
                        has_evidence_support = False
                        technique_base = technique.split(' - ')[0] if ' - ' in technique else technique
                        
                        # More specific evidence-technique validation
                        evidence_text = ' '.join(supporting_evidence).lower()
                        
                        if 'T1110' in technique_base:  # Brute Force
                            if any(keyword in evidence_text for keyword in ['auth', 'login', 'brute', 'force', 'ssh', 'authentication', 'failed', 'rej', 'rstr']):
                                has_evidence_support = True
                        elif 'T1190' in technique_base:  # Exploit Public-Facing Application
                            if any(keyword in evidence_text for keyword in ['exploit', 'application', 'service', 'vulnerability', 'cve']):
                                has_evidence_support = True
                        elif 'T1046' in technique_base:  # Network Service Scanning
                            if any(keyword in evidence_text for keyword in ['scan', 'port', 'probe', 'reconnaissance', 'discovery']):
                                has_evidence_support = True
                        elif 'T1071' in technique_base:  # Application Layer Protocol (including DNS Tunneling)
                            if any(keyword in evidence_text for keyword in ['dns', 'tunnel', 'covert', 'channel', 'exfiltration', 'c2']):
                                has_evidence_support = True
                            # CRITICAL: If evidence mentions SSH/authentication but maps to DNS tunneling, reject it
                            if 'dns' not in evidence_text and any(keyword in evidence_text for keyword in ['ssh', 'authentication', 'auth', 'login']):
                                logger.error(f"LLM CRITICAL ERROR: Maps {technique} but evidence shows SSH/authentication activity, not DNS")
                                raise ValueError(f"⚠️ CRITICAL LOGIC ERROR: LLM mapped '{technique}' but evidence clearly shows SSH authentication attack, not DNS activity. Evidence-Technique mismatch violates system prompt.")
                        elif 'T1595' in technique_base:  # Active Scanning
                            if any(keyword in evidence_text for keyword in ['scan', 'active', 'reconnaissance', 'discovery', 'probe']):
                                has_evidence_support = True
                                
                        if not has_evidence_support:
                            logger.error(f"LLM VIOLATION: Technique {technique} has no supporting evidence in the supporting_evidence array")
                            logger.error(f"Evidence text was: {evidence_text}")
                            raise ValueError(f"⚠️ CRITICAL VIOLATION: Evidence-Anchored Mapping rule violated. Technique '{technique}' listed without explicit supporting evidence. IMMEDIATE TERMINATION as specified.")
                
                logger.info(f"✅ LLM V5.3 ULTRA-STRICT validation passed: {len(hypotheses)} hypotheses, {len(supporting_evidence)} evidence items, {len(analysis_gaps)} analysis gaps")
            else:
                raise ValueError("intelligence_analysis must be a dictionary object")
            
            # Validate assessment structure with new confidence format
            assessment = parsed_data.get('assessment', {})
            assessment_fields = ['confidence', 'summary', 'recommended_actions']
            missing_assessment_fields = [field for field in assessment_fields if field not in assessment]
            
            if missing_assessment_fields:
                raise ValueError(f"Missing required assessment fields: {missing_assessment_fields}")
            
            # Validate confidence structure
            confidence = assessment.get('confidence', {})
            if isinstance(confidence, dict):
                confidence_fields = ['level', 'score']
                missing_confidence_fields = [field for field in confidence_fields if field not in confidence]
                if missing_confidence_fields:
                    raise ValueError(f"Missing required confidence fields: {missing_confidence_fields}")
            
            # Trả về kết quả thành công với cấu trúc V5.3 ULTRA-STRICT
            return {
                'status': 'success',
                'intelligence_analysis': parsed_data.get('intelligence_analysis'),
                'threat_hypothesis': parsed_data.get('threat_hypothesis'),
                'kill_chain_stage': parsed_data.get('kill_chain_stage'),
                'mitre_attack_mapping': parsed_data.get('mitre_attack_mapping'),
                'assessment': parsed_data.get('assessment'),
                'analysis_timestamp': datetime.now().isoformat(),
                'model_used': "meta-llama-3-8b-instruct",
                'compliance_version': "V5.3_ULTRA_STRICT",
                'validation_passed': True
            }
            
        except (json.JSONDecodeError, ValueError) as e:
            # BƯỚC 4: Trả về lỗi có cấu trúc
            logger.error(f"Failed to parse LLM response: {str(e)}")
            logger.error(f"Raw response: {repr(raw_response)}")
            
            return {
                'status': 'error',
                'error_type': type(e).__name__,
                'error_message': str(e),
                'raw_response': raw_response,
                'analysis_timestamp': datetime.now().isoformat()
            }
        
    except Exception as e:
        logger.error(f"Error calling LLM for hypothesis generation: {str(e)}")
        return {
            'status': 'error',
            'error_type': 'llm_call_error',
            'error_message': f"Failed to get hypothesis from LLM: {str(e)}",
            'analysis_timestamp': datetime.now().isoformat()
        }

