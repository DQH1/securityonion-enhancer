"""
UI Dashboard Module
Contains functions for rendering the main dashboard and findings display.
"""

import streamlit as st
from datetime import datetime
from typing import Dict, Any, List, Optional
from ui.sidebar import apply_simple_filter
import logging
import json
import os
import time
from typing import Tuple
from functools import lru_cache

logger = logging.getLogger(__name__)


MAX_FINDINGS_PER_PAGE = 10  # Show max 10 findings per page
MAX_EVENTS_PER_FINDING = 5  # Show max 5 events per finding

# PERFORMANCE OPTIMIZATION: Cache expensive explanation translations
@st.cache_data(show_spinner=False, max_entries=256)
def cached_translate_shap_to_human_readable(top_shap_features, conn_details):
    try:
        from components.xai import translate_shap_to_human_readable
        return translate_shap_to_human_readable(top_shap_features, conn_details)
    except Exception:
        return []

@st.cache_data(show_spinner=False, max_entries=256)
def cached_translate_ae_to_human_readable(top_ae_features):
    try:
        from components.xai import translate_ae_to_human_readable
        return translate_ae_to_human_readable(top_ae_features)
    except Exception:
        return []

def load_findings_incrementally(filepath: str = 'output/alerts.jsonl', 
                              last_position: int = 0,
                              max_lines_per_read: int = 100) -> Tuple[List[Dict], int]:
    """
    Load findings incrementally from JSONL file to improve performance.
    Only reads new lines since last position.
    
    Args:
        filepath: Path to alerts.jsonl file
        last_position: Last file position read (bytes)
        max_lines_per_read: Maximum lines to read per call
        
    Returns:
        Tuple of (new_findings, new_position)
    """
    try:
        if not os.path.exists(filepath):
            return [], 0
            
        file_size = os.path.getsize(filepath)
        if file_size == 0:
            return [], 0
            
        # If file is smaller than last position, it was truncated/rotated
        if file_size < last_position:
            last_position = 0
            
        new_findings = []
        new_position = last_position
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            # Seek to last position
            f.seek(last_position)
            
            lines_read = 0
            while lines_read < max_lines_per_read:
                line = f.readline()
                if not line:  # End of file
                    break
                    
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    finding = json.loads(line)
                    new_findings.append(finding)
                    lines_read += 1
                except json.JSONDecodeError:
                    continue
                    
            new_position = f.tell()
            
        return new_findings, new_position
        
    except Exception as e:
        logger.error(f"Error in incremental file reading: {e}")
        return [], last_position

def get_optimized_findings(session_state, filepath: str = 'output/alerts.jsonl') -> Dict[str, Any]:
    """
    Get findings with optimized loading strategy.
    Uses incremental reading and caching to improve performance.
    """
    try:
        # Initialize file position tracking
        if 'file_position' not in session_state:
            session_state.file_position = 0
            
        if 'findings_cache' not in session_state:
            session_state.findings_cache = {}
            
        if 'last_file_check' not in session_state:
            session_state.last_file_check = 0
            
        current_time = time.time()
        
        # Check file only every 2 seconds to avoid excessive I/O
        if current_time - session_state.last_file_check < 2:
            return session_state.findings_cache
            
        session_state.last_file_check = current_time
        
        # Load new findings incrementally
        new_findings, new_position = load_findings_incrementally(
            filepath, 
            session_state.file_position,
            max_lines_per_read=50  # Read max 50 lines per call
        )
        
        if new_findings:
            # Update cache with new findings
            for finding in new_findings:
                finding_id = finding.get('finding_id', '')
                if not finding_id:
                    finding_ip = finding.get('ip', 'unknown')
                    finding_created = finding.get('created_at', '')
                    finding_id = f"finding_{finding_ip}_{finding_created.replace(':', '').replace('-', '').replace('.', '')}"
                
                # Ensure last_updated is set
                if 'last_updated' not in finding:
                    finding['last_updated'] = finding.get('created_at', datetime.now().isoformat())
                
                session_state.findings_cache[finding_id] = finding
            
            # Update file position
            session_state.file_position = new_position
            
            logger.info(f"📊 Incremental load: {len(new_findings)} new findings, position: {new_position}")
        
        return session_state.findings_cache
        
    except Exception as e:
        logger.error(f"Error in optimized findings loading: {e}")
        return session_state.get('findings_cache', {})

def display_llm_preview_modal():
    """
    Display LLM preview in a full-width modal-like interface.
    """
    if hasattr(st.session_state, 'llm_preview_data') and st.session_state.llm_preview_data.get('show_modal', False):
        preview_data = st.session_state.llm_preview_data
        
        st.markdown("---")
        st.markdown("# 🔍 LLM Input Preview")
        st.markdown(f"**Finding ID:** `{preview_data['finding_id']}`")
        st.markdown("*Full preview of data that will be sent to CognitiveSOC AI for analysis*")
        
        # Close button
        col_close, col_spacer = st.columns([1, 4])
        with col_close:
            if st.button("❌ Close Preview", type="secondary"):
                st.session_state.llm_preview_data['show_modal'] = False
                st.rerun()
        
        # Main content in tabs for better organization
        tab1, tab2, tab3 = st.tabs([" Pre-Analysis Report", " Formatted Prompt", "📊 Summary"])
        
        with tab1:
            st.markdown("##  Pre-Analysis Report (JSON)")
            st.markdown("**Structured data prepared by correlation engine and sent to LLM:**")
            
            # Use full width for JSON display
            import json
            formatted_json = json.dumps(preview_data['pre_report'], indent=2, ensure_ascii=False)
            st.code(formatted_json, language='json', line_numbers=True)
            
            # Download JSON button
            st.download_button(
                label="💾 Download JSON",
                data=formatted_json,
                file_name=f"llm_input_{preview_data['finding_id']}.json",
                mime="application/json"
            )
        
        with tab2:
            st.markdown("##  Formatted Prompt")
            st.markdown("**Human-readable prompt sent to CognitiveSOC AI:**")
            
            # Display full prompt in a large text area for easy reading
            st.text_area(
                "Complete LLM Prompt",
                value=preview_data['user_prompt'],
                height=600,
                disabled=True,
                help="This is the exact prompt sent to the LLM"
            )
            
            # Download prompt button
            st.download_button(
                label="💾 Download Prompt",
                data=preview_data['user_prompt'],
                file_name=f"llm_prompt_{preview_data['finding_id']}.txt",
                mime="text/plain"
            )
        
        with tab3:
            st.markdown("## 📊 Analysis Summary")
            
            pre_report = preview_data['pre_report']
            
            # Key metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                evidence_count = pre_report.get('finding_summary', {}).get('evidence_count', 0)
                st.metric("📊 Evidence Count", evidence_count)
            
            with col2:
                risk_score = pre_report.get('finding_summary', {}).get('risk_score', 0)
                st.metric("⚠️ Risk Score", f"{risk_score}/100")
            
            with col3:
                key_evidence_count = len(pre_report.get('key_evidence_details', []))
                st.metric("🔑 Key Evidence", key_evidence_count)
            
            with col4:
                evidence_stats = pre_report.get('evidence_statistics', {})
                category_count = len(evidence_stats)
                st.metric("📂 Categories", category_count)
            
            # Evidence statistics breakdown
            st.markdown("### 📈 Evidence Breakdown")
            if evidence_stats:
                for category, count in evidence_stats.items():
                    st.markdown(f"• **{category}**: {count} events")
            else:
                st.info("No evidence statistics available")
            
            # Timeline information
            timeline = pre_report.get('timeline_summary', {})
            if timeline:
                st.markdown("### ⏰ Timeline Information")
                st.markdown(f"• **Duration**: {timeline.get('duration', 'N/A')}")
                st.markdown(f"• **First Event**: {timeline.get('first_evidence_at', 'N/A')}")
                st.markdown(f"• **Last Event**: {timeline.get('last_evidence_at', 'N/A')}")
            
            st.success("✅ Preview data ready for AI analysis")
        
        st.markdown("---")


def display_findings_board(session_state) -> None:
    """
    Display security findings in an organized dashboard with performance optimizations.
    Includes pagination and limiting to prevent UI lag with many logs.
    Uses incremental file reading for better performance.
    """
    
    # Check for LLM preview modal first (takes full width)
    display_llm_preview_modal()
    
    try:
        findings_dict = session_state.get('findings', {})
        
        if not findings_dict:
            st.info("🔍 No security findings detected yet. Start processing logs to see results.")
            return
        
        # Convert findings to list and sort by timestamp (newest first)
        findings_list = list(findings_dict.values())
    except Exception as e:
        logger.error(f"Error accessing session state findings: {e}")
        st.error("❌ Error accessing findings data. Please refresh the page.")
        return
    findings_list.sort(key=lambda x: x.get('last_updated', datetime.min), reverse=True)
    
    # PERFORMANCE OPTIMIZATION: Pagination
    total_findings = len(findings_list)
    
    # Initialize pagination state
    if 'findings_page' not in session_state:
        session_state.findings_page = 0
    
    # Calculate pagination
    max_page = (total_findings - 1) // MAX_FINDINGS_PER_PAGE if total_findings > 0 else 0
    current_page = min(session_state.findings_page, max_page)
    
    # Display page controls if needed
    if total_findings > MAX_FINDINGS_PER_PAGE:
        col1, col2, col3, col4 = st.columns([1, 1, 2, 1])
        
        with col1:
            if st.button("◀ Previous", disabled=(current_page == 0)):
                session_state.findings_page = max(0, current_page - 1)
                st.rerun()
        
        with col2:
            if st.button("Next ▶", disabled=(current_page == max_page)):
                session_state.findings_page = min(max_page, current_page + 1)
                st.rerun()
        
        with col3:
            st.write(f"Page {current_page + 1} of {max_page + 1} • Showing {total_findings} findings")
        
        with col4:
            if st.button("🔄 Reset"):
                session_state.findings_page = 0
                st.rerun()
    
    # Get findings for current page
    start_idx = current_page * MAX_FINDINGS_PER_PAGE
    end_idx = min(start_idx + MAX_FINDINGS_PER_PAGE, total_findings)
    page_findings = findings_list[start_idx:end_idx]
    
    # Display findings summary with performance info
    col1, col2 = st.columns([3, 1])
    with col1:
        st.subheader(f"🛡️ Security Findings Dashboard ({len(page_findings)} of {total_findings})")
    with col2:
        # Show performance indicator
        if 'file_position' in session_state and 'last_file_check' in session_state:
            last_check = session_state.get('last_file_check', 0)
            time_since_check = time.time() - last_check
            if time_since_check < 5:
                st.success("⚡ Optimized Loading")
            else:
                st.info("📊 Standard Loading")
    
    # Global fast/slow toggle for details rendering
    st.caption("Rendering mode:")
    fast_mode = st.toggle("⚡ Fast details (skip heavy analysis)", value=True, help="Turn off to include SHAP/AE explanations and large tables")
    st.session_state['fast_details_mode'] = fast_mode

    # Display each finding with optimized rendering
    for i, finding in enumerate(page_findings):
        try:
            _display_single_finding_optimized(finding, start_idx + i + 1)
        except Exception as e:
            logger.error(f"Error displaying finding: {e}")
            st.error(f"Error displaying finding {start_idx + i + 1}: {str(e)}")

def _display_single_finding_optimized(finding: Dict[str, Any], finding_number: int) -> None:
    """
    Display a single finding with performance optimizations.
    Limits the number of events shown and uses lazy loading.
    """
    try:
        # Extract basic info
        risk_score = finding.get('risk_score', 0)
        evidence_count = finding.get('evidence_count', 0) 
        ip = finding.get('ip', finding.get('primary_ip', 'Unknown'))
        title = finding.get('title', 'Security Finding')
        
        original_risk_score = risk_score
        
        # Risk level and color based on original risk score
        if original_risk_score >= 80:
            risk_level = "🔴 CRITICAL"
            risk_color = "red"
        elif original_risk_score >= 60:
            risk_level = "🟠 HIGH"
            risk_color = "orange"  
        elif original_risk_score >= 40:
            risk_level = "🟡 MEDIUM"
            risk_color = "blue"
        else:
            risk_level = "🟢 LOW"
            risk_color = "green"
            
        # Main finding container
        with st.container():
            # Header row
            col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
            
            with col1:
                st.markdown(f"**#{finding_number}** {title}")
                st.caption(f"IP: `{ip}` • Evidence: {evidence_count} events")
            
            with col2:
                st.markdown(f"**{risk_level}**")
            
            with col3:
                st.metric("Risk Score", f"{original_risk_score}/100")
                
                # ✅ DEBUG: Show risk score source
                if finding.get('rule_priority') is not None:
                    st.caption(f"Rule Priority: {finding.get('rule_priority')}")
                if finding.get('detector'):
                    st.caption(f"Detector: {finding.get('detector')}")
                elif finding.get('detection_method'):  # Fallback for old format
                    st.caption(f"Detector: {finding.get('detection_method')}")
                else:
                    # Fallback: derive detector from highest-threat evidence
                    highest_ev = _get_highest_threat_evidence(finding.get('evidence', [])) if finding.get('evidence') else {}
                    detector_name = highest_ev.get('detector')
                    if detector_name:
                        st.caption(f"Detector: {detector_name}")
            
            with col4:
                # Show details button
                details_key = f"show_details_{finding.get('finding_id', finding_number)}"
                if details_key not in st.session_state:
                    st.session_state[details_key] = False
                    
                if st.button(" Details", key=f"btn_{details_key}"):
                    st.session_state[details_key] = not st.session_state[details_key]
            
            # PERFORMANCE OPTIMIZATION: Only show details if requested
            if st.session_state.get(details_key, False):
                _display_finding_details_optimized(finding)
                
        st.markdown("---")  # Separator
        
    except Exception as e:
        logger.error(f"Error in _display_single_finding_optimized: {e}")
        st.error(f"Error displaying finding details: {str(e)}")

def _display_finding_details_optimized(finding: Dict[str, Any]) -> None:
    """
    Display detailed finding information with performance optimizations.
    """
    with st.expander("📊 Finding Details", expanded=True):
        # AI Analysis section - MOVED TO TOP for better visibility
        st.subheader("🤖 AI Analysis & Actions")
        
        col_ai1, col_ai2, col_ai3 = st.columns(3)
        
        with col_ai1:
            # CognitiveSOC AI Analysis button
            ai_status = finding.get('ai_analysis_status', 'not_started')
            finding_id = finding.get('finding_id', 'unknown')
            
            if ai_status == 'running':
                st.info("🤖 Running CognitiveSOC analysis...")
            elif ai_status == 'complete':
                st.success("✅ AI Analysis Complete")
            elif ai_status == 'error':
                st.error("❌ AI Analysis Failed")
            
            # Preview LLM Input button - Store data in session state for modal display
            if st.button("👀 Preview LLM Input", 
                        key=f"preview_llm_{finding_id}",
                        help="Preview the data that will be sent to LLM for analysis"):
                orchestrator = st.session_state.get('orchestrator')
                if orchestrator:
                    try:
                        # Generate the pre-analysis report that would be sent to LLM
                        pre_report = orchestrator.correlation_engine.summarize_finding_for_llm(finding)
                        
                        # Import the function to create user prompt
                        from components.llm_summarizer import create_llm_user_prompt
                        user_prompt = create_llm_user_prompt(pre_report)
                        
                        # Store in session state for modal display
                        st.session_state.llm_preview_data = {
                            'finding_id': finding_id,
                            'pre_report': pre_report,
                            'user_prompt': user_prompt,
                            'show_modal': True
                        }
                        # Avoid immediate rerun to prevent UI lag
                        st.experimental_rerun()
                    except Exception as e:
                        st.error(f"Error generating preview: {str(e)}")
                else:
                    st.error("Backend orchestrator not available")
            
            if st.button("🧠 Run AI Analysis", 
                        key=f"ai_analysis_{finding_id}",
                        disabled=(ai_status == 'running'),
                        help="Generate threat hypothesis using CognitiveSOC AI"):
                # Trigger AI analysis through backend orchestrator
                orchestrator = st.session_state.get('orchestrator')
                if orchestrator:
                    # Show immediate feedback
                    with st.spinner("🤖 Running CognitiveSOC analysis..."):
                        orchestrator.run_cognitive_soc_analysis(finding_id, st.session_state)
                    
                    # Force refresh to show results
                    st.experimental_rerun()
                else:
                    st.error("Backend orchestrator not available")
        
        with col_ai2:
            # RuleMaster generation button
            rule_status = finding.get('rule_generation_status', 'not_started')
            
            if rule_status == 'running':
                st.info(" Generating Suricata rule...")
            elif rule_status == 'complete':
                st.success("✅ Rule Generated")
            elif rule_status == 'error':
                st.error("❌ Rule Generation Failed")
            
            # Only enable if AI analysis is complete and high confidence
            ai_analysis = finding.get('ai_analysis', {})
            ai_confidence = ai_analysis.get('assessment', {}).get('confidence', {}).get('score', 0) if ai_analysis else 0
            rule_enabled = (ai_status == 'complete' and ai_confidence >= 85)
            
            if st.button(" Generate Rule", 
                        key=f"rule_gen_{finding_id}",
                        disabled=(not rule_enabled or rule_status == 'running'),
                        help="Generate Suricata detection rule (requires AI analysis with 85+ confidence)"):
                orchestrator = st.session_state.get('orchestrator')
                if orchestrator:
                    orchestrator.run_rulemaster_generation(finding_id, st.session_state)
                    st.experimental_rerun()
                else:
                    st.error("Backend orchestrator not available")
            
            if not rule_enabled and ai_status != 'running':
                st.caption("Requires AI analysis with 85+ confidence")
        
        with col_ai3:
            # Quick actions
            if st.button(" Export Finding", 
                        key=f"export_{finding_id}",
                        help="Export this finding to JSON"):
                # Create export data for single finding
                export_data = {
                    'export_timestamp': datetime.now().isoformat(),
                    'finding': finding
                }
                
                json_str = json.dumps(export_data, indent=2, default=str, ensure_ascii=False)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"finding_{finding_id}_{timestamp}.json"
                
                st.download_button(
                    label="💾 Download",
                    data=json_str,
                    file_name=filename,
                    mime="application/json",
                    key=f"download_{finding_id}"
                )
        
        # Display AI Analysis Results (if available) - ENHANCED TO SHOW COMPLETE ANALYSIS
        ai_analysis = finding.get('ai_analysis')
        if ai_analysis and ai_analysis.get('status') == 'success':
            st.markdown("---")
            st.subheader("🧠 CognitiveSOC Analysis Results")
            
            # CRITICAL: Show Intelligence Analysis section (often missing in display)
            intelligence_analysis = ai_analysis.get('intelligence_analysis', {})
            if intelligence_analysis:
                st.markdown("### 🎓 Intelligence Analysis")
                
                # Hypotheses Considered
                hypotheses = intelligence_analysis.get('hypotheses_considered', [])
                if hypotheses:
                    st.markdown("**🔬 Hypotheses Considered:**")
                    for i, hypothesis in enumerate(hypotheses, 1):
                        st.markdown(f"{i}. {hypothesis}")
                
                # Supporting Evidence
                supporting_evidence = intelligence_analysis.get('supporting_evidence', [])
                if supporting_evidence:
                    st.markdown("**📊 Supporting Evidence:**")
                    for i, evidence in enumerate(supporting_evidence, 1):
                        st.markdown(f"{i}. {evidence}")
                
                # Analysis Gaps
                analysis_gaps = intelligence_analysis.get('analysis_gaps', [])
                if analysis_gaps:
                    st.markdown("**❓ Analysis Gaps:**")
                    for i, gap in enumerate(analysis_gaps, 1):
                        st.markdown(f"{i}. {gap}")
            else:
                st.warning("⚠️ Intelligence Analysis section missing from AI response")
            
            # Threat hypothesis
            threat_hypothesis = ai_analysis.get('threat_hypothesis', 'No hypothesis available')
            st.markdown(f"** Threat Hypothesis:**")
            st.info(threat_hypothesis)
            
            # Kill Chain Stage (often missing)
            kill_chain_stage = ai_analysis.get('kill_chain_stage', 'Not specified')
            st.markdown(f"**⛓️ Kill Chain Stage:** {kill_chain_stage}")
            
            # Assessment
            assessment = ai_analysis.get('assessment', {})
            if assessment:
                confidence = assessment.get('confidence', {})
                if confidence:
                    conf_level = confidence.get('level', 'Unknown')
                    conf_score = confidence.get('score', 0)
                    
                    col_conf1, col_conf2 = st.columns(2)
                    with col_conf1:
                        st.metric("Confidence Level", conf_level)
                    with col_conf2:
                        st.metric("Confidence Score", f"{conf_score}%")
                
                # MITRE ATT&CK mapping
                mitre_mapping = ai_analysis.get('mitre_attack_mapping', [])
                if mitre_mapping:
                    st.markdown("** MITRE ATT&CK Mapping:**")
                    for tactic in mitre_mapping:
                        tactic_name = tactic.get('tactic', 'Unknown')
                        techniques = tactic.get('techniques', [])
                        st.markdown(f"• **{tactic_name}**: {', '.join(techniques)}")
                
                # Recommended actions
                recommended_actions = assessment.get('recommended_actions', [])
                if recommended_actions:
                    st.markdown("** Recommended Actions:**")
                    for action in recommended_actions:
                        st.markdown(f"• {action}")
            
                    # Show full AI response if requested
        if st.checkbox("🔧 Show Full AI Response", key=f"debug_ai_{finding_id}"):
                st.json(ai_analysis)
        
        # Display Suricata Rule (if generated)
        rule_generation = finding.get('suricata_rule_generation')
        if rule_generation and rule_generation.get('status') == 'success':
            st.markdown("---")
            st.subheader(" Generated Suricata Rule")
            
            rule = rule_generation.get('rule', '')
            if rule:
                st.code(rule, language='text')
                
                # Copy button
                if st.button(" Copy Rule", key=f"copy_rule_{finding_id}"):
                    st.code(rule)
                    st.success("Rule copied to clipboard area above!")
            
            reasoning = rule_generation.get('reasoning', 'No reasoning provided')
            # Use container instead of nested expander
            if st.checkbox(" Show Rule Generation Reasoning", key=f"show_reasoning_{finding_id}"):
                st.markdown("**Rule Generation Reasoning:**")
                st.markdown(reasoning)
        
        st.markdown("---")
        
        # Evidence section with limited display
        evidence = finding.get('evidence', [])
        
        if evidence:
            st.subheader(f"🔍 Evidence ({len(evidence)} events)")
            
            # PERFORMANCE OPTIMIZATION: Limit displayed events
            display_count = min(len(evidence), MAX_EVENTS_PER_FINDING)
            
            if len(evidence) > MAX_EVENTS_PER_FINDING:
                st.info(f"Showing first {display_count} of {len(evidence)} events for performance. Use filters to see more.")
            
            # Display limited events
            for i, event in enumerate(evidence[:display_count]):
                # Generate proper event summary from backend data
                event_type = event.get('type', 'Unknown')
                event_confidence = event.get('confidence', 'Unknown')
                
                # Create meaningful summary based on event type
                if event_type == 'ml_anomaly':
                    detector = event.get('detector', 'AI Classified: ML Model')
                    matched_scenario = event.get('matched_scenario', 'Anomalous behavior')
                    event_summary = f"{detector} detected {matched_scenario}"
                elif event_type == 'behavior_anomaly':
                    behavior_type = event.get('behavior_type', 'Unknown behavior')
                    event_summary = f"Behavioral anomaly: {behavior_type}"
                elif event_type == 'dns_tunneling':
                    matched_scenario = event.get('matched_scenario', 'DNS Tunneling')
                    event_summary = f"DNS anomaly: {matched_scenario}"
                else:
                    event_summary = f"Security event: {event_type}"
                
                with st.container():
                    st.markdown(f"**Event {i+1}:** {event_summary}")
                    st.caption(f"Confidence: {event_confidence}")
                    
                    # Show event details in collapsible section
                    if st.checkbox(f"Show details", key=f"event_details_{finding.get('finding_id', '')}_{i}"):
                        # Format event details nicely instead of raw JSON
                        _display_event_details_formatted(event)
        
        # REMOVED: Duplicate AI Analysis section - already displayed above


def display_findings_list(findings_to_display, tab_name):
    """Helper function to display a list of findings with summary metrics."""
    
    # Summary metrics for this tab
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        total_count = len(findings_to_display)
        if tab_name == "All":
            st.metric("Total Findings", f"{total_count}/{len(st.session_state.findings)}")
        else:
            st.metric(f"{tab_name} Findings", total_count)
    with col2:
        new_findings = sum(1 for f in findings_to_display if f['status'] == 'New')
        st.metric("New Findings", new_findings)
    with col3:
        high_risk = sum(1 for f in findings_to_display if f['risk_score'] >= 75)
        st.metric("High Risk", high_risk)
    with col4:
        total_evidence = sum(f['evidence_count'] for f in findings_to_display)
        st.metric("Total Evidence", total_evidence)
    
    st.markdown("---")
    
    # Initialize risk explanation visibility state if not exists
    if 'risk_explanation_visible' not in st.session_state:
        st.session_state.risk_explanation_visible = {}
    
    # Initialize reviewed findings set if not exists
    if 'reviewed_findings' not in st.session_state:
        st.session_state.reviewed_findings = set()
    
    # Display each finding as an expandable entry
    for finding in findings_to_display:
        # Risk score color coding
        risk_score = finding['risk_score']
        if risk_score >= 75:
            risk_color = "🔴"
        elif risk_score >= 50:
            risk_color = "🟠"
        elif risk_score >= 25:
            risk_color = "🟡"
        else:
            risk_color = "🟢"
        
        # Status indicator
        status_icon = "🆕" if finding['status'] == 'New' else "✅"
        
        # Time since last update
        time_diff = datetime.now() - finding['last_updated']
        if time_diff.total_seconds() < 60:
            time_str = "just now"
        elif time_diff.total_seconds() < 3600:
            time_str = f"{int(time_diff.total_seconds() / 60)}m ago"
        else:
            time_str = f"{int(time_diff.total_seconds() / 3600)}h ago"
        
        # Create expandable entry with summary info in title
        title = f"{status_icon} {risk_color} [SCORE: {risk_score}] {finding['title']} ({finding['evidence_count']} evidence) - {time_str}"
        
        with st.expander(title, expanded=False):
            # Finding details
            col_info, col_actions = st.columns([3, 1])
            
            with col_info:
                st.markdown(f"**Finding ID:** `{finding['finding_id']}`")
                st.markdown(f"**Type:** {finding['attack_type']}")
                st.markdown(f"**Primary IP:** `{finding['ip']}`")
                
                # Risk Score with Explanation Feature (MODULE 3)
                risk_col1, risk_col2 = st.columns([3, 1])
                with risk_col1:
                    st.markdown(f"**Risk Score:** {risk_score}/100")
                with risk_col2:
                    # Create unique key for this finding's explanation state
                    explanation_key = f"{tab_name}_{finding['finding_id']}_risk_explanation"
                    
                    # Toggle button for risk explanation
                    if st.button("Tại sao?", key=f"why_{explanation_key}", help="Giải thích điểm rủi ro"):
                        def toggle_explanation():
                            current_state = st.session_state.risk_explanation_visible.get(explanation_key, False)
                            st.session_state.risk_explanation_visible[explanation_key] = not current_state
                        
                        toggle_explanation()
                        st.rerun()
                
                # Show risk explanation if toggled on
                if st.session_state.risk_explanation_visible.get(explanation_key, False):
                    highest_evidence = _get_highest_threat_evidence(finding['evidence'])
                    if highest_evidence:
                        # Extract evidence description for explanation
                        evidence_type = highest_evidence.get('type', '')
                        if evidence_type == 'behavior_anomaly':
                            behavior_type = highest_evidence.get('behavior_type', 'unknown').replace('_', ' ').title()
                            evidence_description = f"{behavior_type}"
                        elif evidence_type == 'ml_anomaly':
                            confidence = highest_evidence.get('confidence', 'Unknown')
                            evidence_description = f"{confidence} Confidence ML Detection"
                        elif evidence_type == 'threat_intel_match':
                            evidence_description = "Threat Intelligence Match"
                        elif evidence_type == 'baseline_deviation':
                            evidence_description = "Communication Baseline Deviation"
                        elif evidence_type == 'log_flood':
                            evidence_description = "Log Flood Event"
                        elif evidence_type == 'suricata_alert':
                            evidence_description = "Suricata IDS Alert"
                        else:
                            evidence_description = evidence_type.replace('_', ' ').title()
                        
                        st.info(f" Điểm rủi ro được quyết định bởi bằng chứng: **'{evidence_description}'**")
                    else:
                        st.info(" Không có bằng chứng để giải thích điểm rủi ro.")
                
                # Get and display the highest threat evidence that determines the score (original caption)
                highest_evidence = _get_highest_threat_evidence(finding['evidence'])
                if highest_evidence:
                    # Extract evidence description for the caption
                    evidence_type = highest_evidence.get('type', '')
                    if evidence_type == 'behavior_anomaly':
                        behavior_type = highest_evidence.get('behavior_type', 'unknown').replace('_', ' ').title()
                        evidence_description = f"{behavior_type} Behavior"
                    elif evidence_type == 'ml_anomaly':
                        confidence = highest_evidence.get('confidence', 'Unknown')
                        matched_scenario = highest_evidence.get('matched_scenario', 'Unknown Pattern')
                        evidence_description = f"{confidence} Confidence ML Detection ({matched_scenario})"
                    elif evidence_type == 'threat_intel_match':
                        evidence_description = "Threat Intelligence Match"
                    elif evidence_type == 'baseline_deviation':
                        evidence_description = "Communication Baseline Deviation"
                    elif evidence_type == 'log_flood':
                        evidence_description = "Log Flood Event"
                    elif evidence_type == 'suricata_alert':
                        evidence_description = "Suricata IDS Alert"
                    else:
                        evidence_description = evidence_type.replace('_', ' ').title()
                    
                    st.caption(f" Score determined by: '{evidence_description}' evidence")
                
                st.markdown(f"**Status:** {finding['status']}")
                st.markdown(f"**Duration:** {finding['start_time'].strftime('%H:%M:%S')} - {finding['last_updated'].strftime('%H:%M:%S')}")
            
            with col_actions:
                # Status management
                if finding['status'] == 'New':
                    if st.button("🔍 Investigate", key=f"investigate_{tab_name}_{finding['finding_id']}"):
                        finding['status'] = 'Under Review'
                        st.rerun()
                elif finding['status'] == 'Under Review':
                    if st.button("✅ Close", key=f"close_{tab_name}_{finding['finding_id']}"):
                        finding['status'] = 'Closed'
                        st.rerun()
                
                # Details button
                if st.button("🔍 Details", key=f"details_{tab_name}_{finding['finding_id']}", help="View detailed analysis"):
                    st.session_state.selected_finding_id = finding['finding_id']
                    st.rerun()
                
                # IP investigation shortcut
                if st.button("📊 Profile", key=f"profile_{tab_name}_{finding['finding_id']}", help="View IP profile"):
                    st.session_state.investigated_ip = finding['ip']
                    st.rerun()
                
                # Human Feedback Section (TP/FP)
                st.markdown("**🤖 ML Feedback:**")
                
                # Check if finding has been reviewed
                finding_id = finding['finding_id']
                is_reviewed = finding_id in st.session_state.reviewed_findings
                
                # Create feedback buttons
                col_tp, col_fp = st.columns(2)
                
                with col_tp:
                    if st.button("👍 TP", 
                                key=f"tp_{tab_name}_{finding_id}", 
                                help="True Positive - Correct detection",
                                disabled=is_reviewed):
                        # Process TP feedback for all ML anomaly evidence
                        from utils.file_io import log_feedback
                        feedback_count = 0
                        
                        for evidence in finding['evidence']:
                            if evidence.get('type') == 'ml_anomaly':
                                alert_record = evidence.get('connection_details', {})
                                if alert_record:
                                    try:
                                        log_feedback(alert_record, 'TP')
                                        feedback_count += 1
                                    except Exception as e:
                                        st.error(f"Error logging TP feedback: {str(e)}")
                        
                        if feedback_count > 0:
                            st.session_state.reviewed_findings.add(finding_id)
                            st.toast(f"✅ Logged TP feedback for {feedback_count} ML detections", icon="👍")
                        else:
                            st.toast(" No ML anomaly evidence found in this finding", icon="")
                        st.rerun()
                
                with col_fp:
                    if st.button("👎 FP", 
                                key=f"fp_{tab_name}_{finding_id}", 
                                help="False Positive - Incorrect detection",
                                disabled=is_reviewed):
                        # Process FP feedback for all ML anomaly evidence
                        from utils.file_io import log_feedback
                        feedback_count = 0
                        
                        for evidence in finding['evidence']:
                            if evidence.get('type') == 'ml_anomaly':
                                alert_record = evidence.get('connection_details', {})
                                if alert_record:
                                    try:
                                        log_feedback(alert_record, 'FP')
                                        feedback_count += 1
                                    except Exception as e:
                                        st.error(f"Error logging FP feedback: {str(e)}")
                        
                        if feedback_count > 0:
                            st.session_state.reviewed_findings.add(finding_id)
                            st.toast(f"✅ Logged FP feedback for {feedback_count} ML detections", icon="👎")
                        else:
                            st.toast(" No ML anomaly evidence found in this finding", icon="")
                        st.rerun()
                
                # Show review status
                if is_reviewed:
                    st.caption("✅ Feedback submitted")
            
            st.markdown("####  Evidence Details")
            
            # DEBUG: Show evidence count info
            st.info(f"🔍 DEBUG: Finding has {len(finding['evidence'])} evidence items, evidence_count = {finding['evidence_count']}")
            
            # Display evidence in a structured way
            for idx, evidence in enumerate(finding['evidence'], 1):
                with st.container():
                    # Add source indicator
                    source = evidence.get('source', 'unknown')
                    source_icon = "🔍" if source == 'suricata' else "🤖" if source == 'anomaly_engine' else "❓"
                    source_label = "Suricata" if source == 'suricata' else "Anomaly Engine" if source == 'anomaly_engine' else "Unknown"
                    
                    st.markdown(f"**Evidence #{idx}** - {evidence.get('timestamp', 'Unknown time')} | {source_icon} {source_label}")
                    
                    # Evidence type specific display
                    evidence_type = evidence.get('type', '')
                    if evidence_type == 'ml_anomaly':
                        detector = evidence.get('detector', 'AI Classified: Unknown')
                        confidence = evidence.get('confidence', 'Unknown')
                        matched_scenario = evidence.get('matched_scenario', 'Unknown Pattern')
                        is_anomaly = evidence.get('is_anomaly', False)
                        
                        # Confidence-based icon selection
                        confidence_icon = {
                            'High': '🔴',
                            'Medium': '🟠',
                            'Low': '🟡'
                        }.get(confidence, '⚪')
                        anomaly_icon = "🚨" if is_anomaly else ""
                        
                        st.markdown(f"{anomaly_icon} **ML Anomaly Detection**")
                        st.markdown(f"- **Detector:** {detector}")
                        st.markdown(f"- **{confidence_icon} Confidence:** {confidence}")
                        st.markdown(f"- ** Scenario:** {matched_scenario}")
                        
                        # Display model details if available  
                        details = evidence.get('details', {})
                        if details:
                            # Isolation Forest details
                            if_details = details.get('isolation_forest', {})
                            if if_details.get('is_anomaly', False):
                                score = if_details.get('score', 0)
                                threshold = if_details.get('threshold', 0)
                                st.markdown(f"  - 🌲 **Isolation Forest:** {score:.4f} (threshold: {threshold:.4f})")
                            
                            # Autoencoder details
                            ae_details = details.get('autoencoder', {})
                            if ae_details.get('is_anomaly', False):
                                # Check for both 'error' and 'reconstruction_error' fields
                                error = ae_details.get('reconstruction_error') or ae_details.get('error', 0)
                                threshold = ae_details.get('threshold', 0)
                                st.markdown(f"  - 🧠 **Autoencoder:** {error:.6f} (threshold: {threshold:.6f})")
                        
                        # Show explanation if available - Updated for new structure
                        explanation = evidence.get('explanation', {})
                        if explanation:
                            # SHAP explanation (Isolation Forest) - only if IF detected anomaly
                            if_details = details.get('isolation_forest', {})
                            # ✅ FIX: Handle both boolean and string "True" values
                            if_anomaly = if_details.get('is_anomaly', False)
                            if if_anomaly == True or if_anomaly == "True" or str(if_anomaly).lower() == 'true':
                                shap_explanation = explanation.get('isolation_forest_shap')
                                
                                if shap_explanation and isinstance(shap_explanation, list):
                                    st.markdown("**📖 Diễn giải cho Analyst:**")
                                    
                                    # Use cached translation for performance
                                    top_shap_features = shap_explanation[:3]
                                    human_readable_reasons = cached_translate_shap_to_human_readable(top_shap_features, evidence.get('connection_details', {}))
                                    
                                    if human_readable_reasons:
                                        for reason in human_readable_reasons:
                                            st.info(f" {reason}")
                                    else:
                                        st.caption("Không có diễn giải tự động cho các đặc trưng này.")

                                    # Technical details section (no nested expander)
                                    st.markdown("---")
                                    st.markdown("**🔧 Chi tiết kỹ thuật (dành cho chuyên gia ML):**")
                                    with st.container():
                                        # Keep the original technical details here
                                        for exp_item in top_shap_features:  # Show top 3
                                            feature = exp_item.get('feature', 'Unknown')
                                            value = exp_item.get('value', 'N/A')
                                            direction = exp_item.get('direction', 'unknown')
                                            impact_icon = "🔴" if direction == 'anomaly' else "🟢"
                                            st.caption(f"  {impact_icon} **{feature}:** {value}")
                                # No SHAP data available
                            
                            # Autoencoder explanation - only if AE detected anomaly
                            ae_details = details.get('autoencoder', {})
                            # ✅ FIX: Handle both boolean and string "True" values
                            ae_anomaly = ae_details.get('is_anomaly', False)
                            if ae_anomaly == True or ae_anomaly == "True" or str(ae_anomaly).lower() == 'true':
                                ae_explanation = explanation.get('autoencoder_recon_error')
                                if ae_explanation and isinstance(ae_explanation, list):
                                    st.markdown("**📖 Diễn giải cho Analyst (Autoencoder):**")
                                    
                                    # Use cached translation for performance
                                    top_ae_features = ae_explanation[:3]
                                    human_readable_reasons = cached_translate_ae_to_human_readable(top_ae_features)
                                    
                                    if human_readable_reasons:
                                        for reason in human_readable_reasons:
                                            st.info(f" {reason}")
                                    else:
                                        st.caption("Không có diễn giải tự động cho các đặc trưng này.")

                                    # Technical details section (no nested expander)
                                    st.markdown("---")
                                    st.markdown("**🔧 Chi tiết kỹ thuật (dành cho chuyên gia ML):**")
                                    with st.container():
                                        st.markdown("**🔍 Top Error Contributors:**")
                                        for exp_item in top_ae_features:  # Show top 3
                                            feature = exp_item.get('feature', 'Unknown')
                                            contribution = exp_item.get('contribution_percent', 0)
                                            st.markdown(f"  🔴 **{feature}:** {contribution:.1f}%")
                                            
                                            # Show detailed difference information
                                            orig_val = exp_item.get('original_value', 0)
                                            recon_val = exp_item.get('reconstructed_value', 0)
                                            difference = exp_item.get('difference', 0)
                                            st.caption(f"    Difference: {difference:.4f} (Original: {orig_val:.2f}, Reconstructed: {recon_val:.2f})")
                    
                    elif evidence_type == 'behavior_anomaly':
                        behavior_type = evidence.get('behavior_type', 'unknown').replace('_', ' ').title()
                        st.markdown(f"🔍 **Behavioral Anomaly: {behavior_type}**")
                        st.markdown(f"- Details: {evidence.get('details', 'N/A')}")
                    
                    elif evidence_type == 'threat_intel_match':
                        st.markdown(f"⚠️ **Threat Intelligence Match**")
                        st.markdown(f"- IP: `{evidence.get('ip', 'N/A')}`")
                        st.markdown(f"- Source: {evidence.get('source_info', 'N/A')}")
                    
                    elif evidence_type == 'baseline_deviation':
                        st.markdown(f"📊 **Communication Baseline Deviation**")
                        st.markdown(f"- Details: {evidence.get('details', 'N/A')}")
                    
                    elif evidence_type == 'suricata_alert':
                        st.markdown(f"🔍 **Suricata IDS Alert**")
                        st.markdown(f"- Alert: {evidence.get('alert', {}).get('signature', 'N/A')}")
                        st.markdown(f"- Category: {evidence.get('alert', {}).get('category', 'N/A')}")
                        st.markdown(f"- Severity: {evidence.get('alert', {}).get('severity', 'N/A')}")
                        src_ip = evidence.get('src_ip', 'N/A')
                        dest_ip = evidence.get('dest_ip', 'N/A')
                        dest_port = evidence.get('dest_port', 'N/A')
                        st.markdown(f"- Flow: `{src_ip}` → `{dest_ip}:{dest_port}`")
                    
                    # Flood events removed in Redis-based pipeline; no rendering
                    
                    else:
                        # Default case for unknown evidence types
                        st.markdown(f"❓ **Unknown Evidence Type: {evidence_type}**")
                        st.markdown(f"- Details: {evidence.get('details', 'No details available')}")
                        if evidence.get('alert'):
                            st.markdown(f"- Alert: {evidence.get('alert', 'N/A')}")
                    
                    # Connection details (if available)
                    if 'connection_details' in evidence:
                        conn = evidence['connection_details']
                        st.markdown(f"- **Connection:** `{conn.get('id.orig_h', 'N/A')}:{conn.get('id.orig_p', 'N/A')}` → `{conn.get('id.resp_h', 'N/A')}:{conn.get('id.resp_p', 'N/A')}` ({conn.get('proto', 'N/A')})")
                        if conn.get('service'):
                            st.markdown(f"- **Service:** {conn.get('service')}")
                    
                    st.markdown("---")


def _get_highest_threat_evidence(evidence_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    ✅ FIXED: Get the evidence with the highest threat level to determine the finding's risk score.
    
    Args:
        evidence_list: List of evidence dictionaries
        
    Returns:
        The evidence with the highest threat level
    """
    # ✅ FIXED: Validate input
    if not evidence_list:
        logger.warning("Empty evidence list provided to _get_highest_threat_evidence")
        return {}
    
    # ✅ FIXED: Validate evidence_list[0] exists
    if len(evidence_list) == 0:
        logger.warning("Evidence list is empty")
        return {}
    
    # Define threat level priorities (higher number = higher threat)
    threat_priorities = {
        'threat_intel_match': 100,
        'behavior_anomaly': 80,
        'ml_anomaly': 60,
        'baseline_deviation': 40,
        'suricata_alert': 70,
        'log_flood': 50
    }
    
    # ✅ FIXED: Safe access to evidence_list[0]
    try:
        highest_evidence = evidence_list[0]
        if not highest_evidence:
            logger.warning("First evidence item is None or empty")
            return {}
            
        highest_priority = threat_priorities.get(highest_evidence.get('type', ''), 0)
        
        # ✅ FIXED: Safe iteration over evidence_list[1:]
        for evidence in evidence_list[1:]:
            if not evidence:
                continue  # Skip None/empty evidence
                
            evidence_type = evidence.get('type', '')
            priority = threat_priorities.get(evidence_type, 0)
            
            # For ML anomalies, also consider confidence level
            if evidence_type == 'ml_anomaly':
                confidence = evidence.get('confidence', 'Low')
                if confidence == 'High':
                    priority += 20
                elif confidence == 'Medium':
                    priority += 10
            
            if priority > highest_priority:
                highest_priority = priority
                highest_evidence = evidence
        
        return highest_evidence
        
    except (IndexError, TypeError, AttributeError) as e:
        logger.error(f"Error accessing evidence list: {str(e)}")
        return {} 


def _display_event_details_formatted(event: Dict[str, Any]) -> None:
    """
    Display event details in a nicely formatted way instead of raw JSON.
    """
    try:
        # Basic event info
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("** Event Information**")
            st.text(f"Type: {event.get('type', 'Unknown')}")
            st.text(f"Source: {event.get('source', 'Unknown')}")
            st.text(f"Timestamp: {event.get('timestamp', 'Unknown')}")
            
            if event.get('confidence'):
                st.text(f"Confidence: {event.get('confidence')}")
            if event.get('risk_score'):
                st.text(f"Risk Score: {event.get('risk_score')}")
            
            # Add matched scenario for better context
            if event.get('matched_scenario'):
                st.text(f"Scenario: {event.get('matched_scenario')}")
            if event.get('behavior_type'):
                st.text(f"Behavior: {event.get('behavior_type')}")
        
        with col2:
            st.markdown("**🌐 Network Details**")
            st.text(f"Source IP: {event.get('src_ip', event.get('ip', 'Unknown'))}")
            st.text(f"Dest IP: {event.get('dst_ip', event.get('dest_ip', 'Unknown'))}")
            st.text(f"Dest Port: {event.get('dst_port', 'Unknown')}")
            st.text(f"Protocol: {event.get('proto', 'Unknown')}")
            st.text(f"Service: {event.get('service', 'Unknown')}")
        
        # ML Detection Details
        if event.get('type') == 'ml_anomaly':
            st.markdown("**🤖 ML Detection Details**")
            st.text(f"Detector: {event.get('detector', 'Unknown')}")
            st.text(f"Scenario: {event.get('matched_scenario', 'Unknown')}")
            st.text(f"Is Anomaly: {event.get('is_anomaly', False)}")
            
            # Add rule priority for context
            if event.get('rule_priority'):
                st.text(f"Rule Priority: {event.get('rule_priority')}")
        
        # Behavioral Anomaly Details
        elif event.get('type') == 'behavior_anomaly':
            st.markdown("**🔍 Behavioral Anomaly Details**")
            st.text(f"Behavior Type: {event.get('behavior_type', 'Unknown')}")
            st.text(f"Confidence: {event.get('confidence', 'Unknown')}")
            
            # Add threshold info if available
            if event.get('threshold_exceeded'):
                st.text(f"Threshold Exceeded: {event.get('threshold_exceeded')}")
        
        # DNS Tunneling Details
        elif event.get('type') == 'dns_tunneling':
            st.markdown("**🌐 DNS Tunneling Details**")
            st.text(f"Query: {event.get('query', 'Unknown')}")
            st.text(f"Scenario: {event.get('matched_scenario', 'Unknown')}")
            st.text(f"Confidence: {event.get('confidence', 'Unknown')}")
            
            # Model scores
            details = event.get('details', {})
            if details:
                if_details = details.get('isolation_forest', {})
                ae_details = details.get('autoencoder', {})
                
                if if_details:
                    st.text(f"🌲 IF Score: {if_details.get('score', 'N/A')} (threshold: {if_details.get('threshold', 'N/A')})")
                if ae_details:
                    # Check for both 'error' and 'reconstruction_error' fields
                    ae_error = ae_details.get('reconstruction_error') or ae_details.get('error', 'N/A')
                    st.text(f"🧠 AE Error: {ae_error} (threshold: {ae_details.get('threshold', 'N/A')})")
                
                # SHAP Explanations Section
                explanation = event.get('explanation', {})
                if explanation:
                    st.markdown("---")
                    st.markdown("**🧠 AI Explanations**")
                    
                    # SHAP explanation (Isolation Forest) - only if IF detected anomaly
                    if if_details.get('is_anomaly', False):
                        shap_explanation = explanation.get('isolation_forest_shap')
                        
                        if shap_explanation and isinstance(shap_explanation, list):
                            st.markdown("**📖 AI Explanation (Human-Readable):**")
                            
                            # Force reload XAI module to get latest interpretations
                            import sys
                            if 'components.xai' in sys.modules:
                                del sys.modules['components.xai']
                            from components.xai import translate_shap_to_human_readable
                            
                            # Defer heavy table building behind a checkbox
                            if st.checkbox("Show SHAP table (slow)", key=f"dns_shap_table_{event.get('timestamp','unknown')}"):
                                top_shap_features = shap_explanation[:5]
                                human_readable_reasons = cached_translate_shap_to_human_readable(top_shap_features, event.get('connection_details', {}))
                            
                            if human_readable_reasons:
                                for reason in human_readable_reasons:
                                    st.info(f" {reason}")
                            else:
                                st.caption("No human-readable explanations available for these features.")

                            # Technical details section
                            if st.checkbox("🔧 Show Technical Details (for ML experts)", key=f"tech_details_if_{event.get('timestamp', 'unknown')}"):
                                st.markdown("**Technical SHAP Values:**")
                                for exp_item in top_shap_features:  # Show top 5
                                    feature = exp_item.get('feature', 'Unknown')
                                    value = exp_item.get('value', 'N/A')
                                    direction = exp_item.get('direction', 'unknown')
                                    impact_icon = "🔴" if direction == 'anomaly' else "🟢"
                                    st.caption(f"  {impact_icon} **{feature}:** {value}")
                        else:
                            st.info(" SHAP explanations not available for this detection.")
                    
                    # Autoencoder explanation - only if AE detected anomaly
                    if ae_details.get('is_anomaly', False):
                        ae_explanation = explanation.get('autoencoder_recon_error')
                        if ae_explanation and isinstance(ae_explanation, list):
                            st.markdown("**📖 AI Explanation (Autoencoder):**")
                            
                            from components.xai import translate_ae_to_human_readable
                            
                            # CRITICAL: Only process same number of features as technical details (top 3)
                            top_ae_features = ae_explanation[:3]
                            human_readable_reasons = translate_ae_to_human_readable(top_ae_features)
                            
                            if human_readable_reasons:
                                for reason in human_readable_reasons:
                                    st.info(f" {reason}")
                            else:
                                st.caption("No human-readable explanations available for these features.")

                            # Technical details section
                            if st.checkbox("🔧 Show AE Technical Details", key=f"tech_details_ae_{event.get('timestamp', 'unknown')}"):
                                st.markdown("**Technical AE Reconstruction Errors:**")
                                for exp_item in top_ae_features:  # Show top 3
                                    feature = exp_item.get('feature', 'Unknown')
                                    contribution = exp_item.get('contribution_percent', 0)
                                    orig_val = exp_item.get('original_value', 0)
                                    recon_val = exp_item.get('reconstructed_value', 0)
                                    difference = exp_item.get('difference', 0)
                                    st.caption(f"🔴 **{feature}:** {contribution:.1f}%")
                                    st.caption(f"   Difference: {difference:.4f} (Orig: {orig_val:.2f}, Recon: {recon_val:.2f})")

        
        # Connection Details
        conn_details = event.get('connection_details', {})
        if conn_details:
            st.markdown("**🔗 Connection Details**")
            st.text(f"Duration: {conn_details.get('duration', 'Unknown')} seconds")
            st.text(f"Orig Bytes: {conn_details.get('orig_bytes', 'Unknown')}")
            st.text(f"Resp Bytes: {conn_details.get('resp_bytes', 'Unknown')}")
            st.text(f"Connection State: {conn_details.get('conn_state', 'Unknown')}")
            
        # Show raw JSON in collapsible section (avoid nested expanders)
        st.markdown("---")
        if st.checkbox("🔧 Show Raw Technical Data", key=f"raw_data_{event.get('timestamp', 'unknown')}"):
            st.json(event, expanded=False)
            
    except Exception as e:
        st.error(f"Error formatting event details: {str(e)}")
        # Fallback to raw JSON if formatting fails
        st.json(event, expanded=False)

def display_dns_detection_summary(session_state):
    """Display DNS tunneling detection summary."""
    if hasattr(session_state, 'dns_analysis_results') and session_state.dns_analysis_results:
        results = session_state.dns_analysis_results
        
        st.subheader("🔍 DNS Tunneling Detection Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Files Analyzed",
                results.get('total_files_processed', 0),
                delta=None
            )
        
        with col2:
            st.metric(
                "Total Queries",
                f"{results.get('total_lines_processed', 0):,}",
                delta=None
            )
        
        with col3:
            tunneling_events = results.get('total_alerts_generated', 0)
            st.metric(
                "Tunneling Events",
                tunneling_events,
                delta=None
            )
        
        with col4:
            if results.get('total_lines_processed', 0) > 0:
                detection_rate = (tunneling_events / results.get('total_lines_processed', 1)) * 100
                st.metric(
                    "Detection Rate",
                    f"{detection_rate:.2f}%",
                    delta=None
                )
            else:
                st.metric("Detection Rate", "0%", delta=None)
        
        # File breakdown
        if results.get('file_results'):
            st.subheader("📁 File Analysis Breakdown")
            
            for file_result in results.get('file_results', []):
                file_path = file_result.get('file', 'Unknown')
                file_name = file_path.split('/')[-1] if '/' in file_path else file_path
                result = file_result.get('result', {})
                
                if result.get('success', False):
                    lines = result.get('lines_processed', 0)
                    alerts = result.get('alerts_generated', 0)
                    
                    with st.expander(f"📄 {file_name} - {alerts} events from {lines:,} queries"):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write(f"**File:** {file_path}")
                            st.write(f"**Queries Processed:** {lines:,}")
                        with col2:
                            st.write(f"**Tunneling Events:** {alerts}")
                            if lines > 0:
                                rate = (alerts / lines) * 100
                                st.write(f"**Detection Rate:** {rate:.2f}%")
                else:
                    st.error(f"❌ {file_name}: {result.get('error', 'Unknown error')}")

def display_dns_alerts_list(backend_orchestrator):
    """Display list of DNS tunneling alerts."""
    alerts = backend_orchestrator.get_active_alerts()
    
    # Filter for DNS alerts
    dns_alerts = [alert for alert in alerts if alert.get('type') == 'behavior_anomaly' and alert.get('behavior_type') == 'dns_tunneling']
    
    if dns_alerts:
        st.subheader(f"🚨 DNS Tunneling Alerts ({len(dns_alerts)})")
        
        for i, alert in enumerate(dns_alerts[-10:]):  # Show last 10 alerts
            with st.expander(f"🔍 DNS Alert {i+1}: {alert.get('dns_details', {}).get('query', 'Unknown Query')}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Basic Info:**")
                    st.write(f"- **Query:** {alert.get('dns_details', {}).get('query', 'N/A')}")
                    st.write(f"- **Source IP:** {alert.get('src_ip', 'N/A')}")
                    st.write(f"- **Query Type:** {alert.get('dns_details', {}).get('qtype', 'N/A')}")
                    st.write(f"- **Confidence:** {alert.get('confidence', 'N/A')}")
                    st.write(f"- **Detector:** {alert.get('detector', 'N/A')}")
                
                with col2:
                    st.write("**DNS Features:**")
                    features = alert.get('dns_details', {}).get('features', {})
                    st.write(f"- **Query Length:** {features.get('query_length', 'N/A')}")
                    st.write(f"- **Entropy:** {features.get('query_entropy', 'N/A'):.2f}" if features.get('query_entropy') else "- **Entropy:** N/A")
                    st.write(f"- **Subdomains:** {features.get('subdomain_count', 'N/A')}")
                    st.write(f"- **Suspicious Patterns:** {'Yes' if features.get('has_suspicious_patterns') else 'No'}")
                
                # ML Details
                ml_details = alert.get('dns_details', {}).get('ml_details', {})
                if ml_details:
                    st.write("**ML Model Results:**")
                    
                    iso_details = ml_details.get('isolation_forest', {})
                    ae_details = ml_details.get('autoencoder', {})
                    
                    col3, col4 = st.columns(2)
                    with col3:
                        st.write("*Isolation Forest:*")
                        st.write(f"Score: {iso_details.get('score', 'N/A'):.4f}" if iso_details.get('score') else "Score: N/A")
                        st.write(f"Anomaly: {'Yes' if iso_details.get('is_anomaly') else 'No'}")
                    
                    with col4:
                        st.write("*Autoencoder:*")
                        # Check for both 'error' and 'reconstruction_error' fields
                        ae_error = ae_details.get('reconstruction_error') or ae_details.get('error')
                        if ae_error is not None and isinstance(ae_error, (int, float)):
                            st.write(f"Error: {ae_error:.4f}")
                        else:
                            st.write("Error: N/A")
                        st.write(f"Anomaly: {'Yes' if ae_details.get('is_anomaly') else 'No'}")
                
                # Explanation
                explanation = alert.get('explanation', {})
                if explanation:
                    st.write("**Detection Explanation:**")
                    
                    primary = explanation.get('primary_indicators', [])
                    secondary = explanation.get('secondary_indicators', [])
                    risk_factors = explanation.get('risk_factors', [])
                    
                    if primary:
                        st.write("*Primary Indicators:*")
                        for indicator in primary:
                            st.write(f"- {indicator}")
                    
                    if secondary:
                        st.write("*Secondary Indicators:*")
                        for indicator in secondary:
                            st.write(f"- {indicator}")
                    
                    if risk_factors:
                        st.write("*Risk Factors:*")
                        for factor in risk_factors:
                            st.write(f"- {factor}")
                    
                    # ✅ BỔ SUNG DNS SHAP EXPLANATION
                    # Display DNS SHAP explanation if available
                    iso_shap = explanation.get('isolation_forest_shap', [])
                    iso_human = explanation.get('isolation_forest_human_readable', [])
                    
                    if iso_shap:
                        # Determine log type from SHAP data
                        log_type = iso_shap[0].get('log_type', 'unknown') if iso_shap else 'unknown'
                        log_title = "DNS Tunneling" if log_type == 'dns' else "Network Anomaly"
                        
                        st.write(f"**🔍 SHAP Explanation ({log_title}):**")
                        
                        # Create a DataFrame for better display
                        import pandas as pd
                        shap_data = []
                        for i, shap_item in enumerate(iso_shap[:5]):  # Show top 5
                            feature = shap_item.get('feature', f'Feature {i}')
                            value = shap_item.get('value', 0)
                            direction = shap_item.get('direction', 'normal')
                            
                            # Get human readable explanation
                            human_explanation = "N/A"
                            if i < len(iso_human):
                                human_explanation = iso_human[i].get('explanation', 'N/A')
                            
                            shap_data.append({
                                'Feature': feature,
                                'SHAP Value': f"{value:.4f}",
                                'Impact': f"{abs(value):.4f}",
                                'Direction': direction.title(),
                                'Explanation': human_explanation
                            })
                        
                        if shap_data:
                            df_shap = pd.DataFrame(shap_data)
                            st.dataframe(df_shap, use_container_width=True)
                            
                            # Color-coded explanation
                            st.write("**📊 Feature Impact Analysis:**")
                            for item in shap_data[:3]:  # Show top 3 with colors
                                feature = item['Feature']
                                impact = item['Impact']
                                direction = item['Direction']
                                explanation = item['Explanation']
                                
                                if direction in ['Tunneling', 'Anomaly']:
                                    st.error(f"🔴 **{feature}** (Impact: {impact}) - {explanation}")
                                else:
                                    st.success(f"🟢 **{feature}** (Impact: {impact}) - {explanation}")
                        else:
                            st.info("No SHAP explanation available for this query.")
                    
                    # Display Autoencoder explanation if available
                    ae_explanation = explanation.get('autoencoder', {})
                    if ae_explanation:
                        st.write("**🤖 Autoencoder Analysis:**")
                        ae_error = ae_explanation.get('error', 'N/A')
                        ae_threshold = ae_explanation.get('threshold', 'N/A')
                        ae_anomaly = ae_explanation.get('is_anomaly', False)
                        
                        col5, col6 = st.columns(2)
                        with col5:
                            st.write(f"**Reconstruction Error:** {ae_error:.4f}" if isinstance(ae_error, (int, float)) else f"**Reconstruction Error:** {ae_error}")
                            st.write(f"**Threshold:** {ae_threshold:.4f}" if isinstance(ae_threshold, (int, float)) else f"**Threshold:** {ae_threshold}")
                        with col6:
                            if ae_anomaly:
                                st.error("**Status:** Anomaly Detected")
                            else:
                                st.success("**Status:** Normal")
    else:
        st.info("No DNS tunneling alerts detected yet.") 