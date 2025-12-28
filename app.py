import streamlit as st
from config import APP_TITLE, APP_VERSION

from core.database import init_db, get_probes_for_user, get_probes_currently_held, get_user_role
from core.auth import authenticate_user, get_user_by_id, create_user_with_password
from core.custody import (
    add_probe,
    add_user,
    get_users,
    get_probes,
    add_transfer,
    verify_integrity,
    generate_report,
    generate_pdf_report_bytes,
    generate_probe_text_report_with_id,
    generate_probe_pdf_report_with_id,
    get_audit_log,
    get_current_custodian,
    can_download_evidence,
    can_download_reports
)

init_db()

if "user_id" not in st.session_state:
    st.set_page_config(page_title=APP_TITLE, layout="centered")
    st.title("🔐 Digital Chain of Custody")
    
    st.markdown("""
    ## Authenticate
    Access the chain of custody system
    """)
    
    tab_login, tab_register = st.tabs(["🔓 Login", "📝 Create Account"])
    
    with tab_login:
        st.subheader("Login")
        email = st.text_input("Email Address", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("🔓 Login", key="login_button"):
            result = authenticate_user(email, password)
            if result:
                user_id, user_name = result
                st.session_state.user_id = user_id
                st.session_state.username = user_name
                st.success(f"Welcome, {user_name}!")
                st.rerun()
            else:
                st.error("❌ Invalid credentials")
    
    with tab_register:
        st.subheader("Create New Account")
        st.write("Register as a new custodian or investigator")
        
        new_email = st.text_input("Email Address", key="register_email", help="Your email will be used to login")
        new_username = st.text_input("Display Name (Optional)", key="register_username", help="Leave blank to use part of your email")
        new_password = st.text_input("Password", type="password", key="register_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="register_confirm")
        
        user_role = st.selectbox(
            "User Role",
            options=["CUSTODIAN", "INVESTIGATOR"],
            help="CUSTODIAN: Holds evidence | INVESTIGATOR: Can analyze evidence",
            key="register_role"
        )
        
        if st.button("📝 Create Account", key="register_button"):
            if not new_email.strip():
                st.error("❌ Email cannot be empty")
            elif "@" not in new_email or "." not in new_email:
                st.error("❌ Please enter a valid email address")
            elif not new_password:
                st.error("❌ Password cannot be empty")
            elif len(new_password) < 6:
                st.error("❌ Password must be at least 6 characters")
            elif new_password != confirm_password:
                st.error("❌ Passwords do not match")
            else:
                try:
                    display_name = new_username.strip() if new_username.strip() else None
                    create_user_with_password(new_email.strip(), new_password, display_name, user_role)
                    st.success(f"✅ Account created successfully!")
                    st.info(f"Email: **{new_email.strip()}**\nRole: **{user_role}**\n\nYou can now login with your email.")
                except Exception as e:
                    if "UNIQUE constraint failed" in str(e):
                        st.error(f"❌ Email '{new_email.strip()}' already registered")
                    else:
                        st.error(f"❌ Error creating account: {str(e)}")
    
    st.stop()

st.set_page_config(
    page_title=APP_TITLE,
    layout="centered"
)

col1, col2 = st.columns([4, 1])
with col1:
    st.title("🔐 Digital Chain of Custody")
with col2:
    if st.button("🚪 Logout"):
        st.session_state.clear()
        st.rerun()

st.caption(f"Logged in as: **{st.session_state.username}**")

user_role = get_user_role(st.session_state.username)
role_emoji = {"ADMIN": "👑", "INVESTIGATOR": "🔬", "CUSTODIAN": "📦"}.get(user_role, "")
st.caption(f"Role: {role_emoji} **{user_role}**")
st.caption("Authentication and validation of digital evidence")

st.sidebar.markdown("---")
st.sidebar.markdown("### 📌 Navigation Menu")
st.sidebar.markdown("Select a module to access:")

current_module = st.sidebar.radio(
    "Choose Module:",
    options=[
        "1️⃣ Add Evidence",
        "2️⃣ Custody Transfer",
        "3️⃣ Integrity Check",
        "4️⃣ Report",
        "5️⃣ Audit Log",
        "6️⃣ Status & Checks",
        "7️⃣ Credential Analysis"
    ],
    label_visibility="collapsed"
)

st.sidebar.markdown("---")

if current_module == "1️⃣ Add Evidence":
    st.subheader("Add Digital Evidence")

    uploaded_file = st.file_uploader(
        "Upload digital evidence (text file, image, etc.)",
        type=None
    )

    if uploaded_file is not None:
        if "last_uploaded_file" not in st.session_state or st.session_state.last_uploaded_file != uploaded_file.name:
            file_bytes = uploaded_file.read()
            
            probe_id, sha256 = add_probe(uploaded_file.name, file_bytes, st.session_state.username)
            
            st.session_state.last_uploaded_file = uploaded_file.name
            st.session_state.last_probe_id = probe_id
            st.session_state.last_sha256 = sha256

            st.success("Evidence read successfully.")
            st.code(f"SHA-256: {sha256}")
            st.info(f"Evidence stored safely. Probe ID: {probe_id}")
            st.rerun()
        else:
            st.success("Evidence read successfully.")
            st.code(f"SHA-256: {st.session_state.last_sha256}")
            st.info(f"Evidence stored safely. Probe ID: {st.session_state.last_probe_id}")

if current_module == "2️⃣ Custody Transfer":
    st.subheader("Custody Transfer")

    from core.database import get_probes_currently_held
    user_probes = get_probes_currently_held(st.session_state.username)
    users = get_users()

    if not user_probes or not users:
        st.info("📦 No evidence to transfer. Upload evidence first.")
    else:
        user_names = [u[1] for u in users]
        probe_labels = {p[0]: p for p in user_probes}

        selected_probe_id = st.selectbox(
            "Select Evidence to Transfer",
            options=list(probe_labels.keys()),
            format_func=lambda pid: probe_labels[pid][1],
            key="transfer_probe_select"
        )

        from_user = st.session_state.username
        
        st.info(f"📦 From Custodian: **{from_user}** (you)")
        
        valid_recipients = [u for u in user_names if u != from_user]
        
        if not valid_recipients:
            st.warning("⚠️ No other custodians available for transfer")
        else:
            to_user = st.selectbox(
                "To Custodian",
                options=valid_recipients,
                key="transfer_to_user",
                help="Select who should receive the evidence"
            )
            
            transfer_reason = st.text_input(
                "Transfer Reason *",
                placeholder="e.g., For analysis, Evidence verification, Storage transfer...",
                help="Document why this evidence is being transferred (NIST compliance)"
            )
            
            transfer_notes = st.text_area(
                "Transfer Notes/Comments",
                placeholder="Add optional investigator notes, analysis findings, or chain integrity comments...",
                height=100,
                help="Document investigator observations and chain integrity information"
            )

            if st.button("Perform Transfer"):
                if not transfer_reason.strip():
                    st.error("❌ Transfer reason is required (NIST/Forensic standard)")
                else:
                    try:
                        transfer_status, integrity_status, original_hash, current_hash = add_transfer(
                            selected_probe_id,
                            from_user,
                            to_user,
                            transfer_reason.strip(),
                            transfer_notes.strip()
                        )
                        
                        if transfer_status == 'SUCCESS':
                            if integrity_status:
                                st.success("✅ Transfer recorded - Evidence integrity verified.")
                                st.info(f"Hash matches original: {current_hash[:16]}...")
                            else:
                                st.warning("⚠️ Transfer recorded - Evidence integrity ALTERED!")
                                st.warning("Note: Integrity compromise does NOT invalidate chain of custody.")
                                st.warning("Compromised evidence remains fully documented and traceable.")
                                st.code(f"Original Hash: {original_hash[:32]}...")
                                st.code(f"Current Hash:  {current_hash[:32]}...")
                            st.rerun()
                        else:
                            st.error(f"❌ Transfer failed: {transfer_status}")
                    except ValueError as e:
                        st.error(f"❌ Transfer validation failed:\n{str(e)}")
                    except Exception as e:
                        st.error(f"❌ Error during transfer:\n{str(e)}")

if current_module == "3️⃣ Integrity Check":
    st.subheader("Evidence Integrity Verification")

    user_probes = get_probes_for_user(st.session_state.username)

    if not user_probes:
        st.info("No evidence available. Upload evidence first.")
    else:
        probe_map = {p[0]: p for p in user_probes}

        selected_probe_id = st.selectbox(
            "Select Evidence",
            options=list(probe_map.keys()),
            format_func=lambda pid: probe_map[pid][1],
            key="verify_probe_select"
        )

        uploaded_file = st.file_uploader(
            "Upload file for verification",
            type=None,
            key="verify_upload"
        )

        if uploaded_file is not None:
            file_bytes = uploaded_file.read()

            if st.button("Check Integrity"):
                is_valid, current_hash = verify_integrity(
                    selected_probe_id,
                    file_bytes
                )

                if is_valid is None:
                    st.error("Evidence not found in database.")
                elif is_valid:
                    st.success("✅ Evidence is VALID.")
                    st.code(f"SHA-256: {current_hash}")
                else:
                    st.error("❌ Evidence was ALTERED.")
                    st.code(f"Current SHA-256: {current_hash}")

if current_module == "4️⃣ Report":
    st.subheader("Evidence Reports")

    user_probes = get_probes_for_user(st.session_state.username)
    
    if not user_probes:
        st.info("No evidence available to generate reports.")
    else:
        report_type = st.radio("Report Type", ["Per-Evidence", "Overall"])
        
        if report_type == "Per-Evidence":
            st.markdown("### Generate Report for Specific Evidence")
            
            probe_labels = {p[0]: p for p in user_probes}
            selected_probe_id = st.selectbox(
                "Select Evidence",
                options=list(probe_labels.keys()),
                format_func=lambda pid: probe_labels[pid][1],
                key="report_probe_select"
            )
            
            if st.button("Generate Evidence Report"):
                report_text = generate_probe_text_report_with_id(selected_probe_id)
                report_pdf = generate_probe_pdf_report_with_id(selected_probe_id)
                
                st.success("Report generated.")
                
                st.markdown("### Report Preview")
                st.text_area(
                    "Report Content",
                    report_text,
                    height=400,
                    disabled=True
                )
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.download_button(
                        label="📄 Download Report (.txt)",
                        data=report_text,
                        file_name=f"evidence_report_{selected_probe_id}.txt",
                        mime="text/plain"
                    )
                
                with col2:
                    if can_download_evidence(st.session_state.username, user_role):
                        st.download_button(
                            label="📑 Download Report (.pdf)",
                            data=report_pdf,
                            file_name=f"evidence_report_{selected_probe_id}.pdf",
                            mime="application/pdf"
                        )
                    else:
                        st.info("📑 PDF download restricted to INVESTIGATOR and ADMIN roles")
        
        else:
            st.markdown("### Generate Overall Chain of Custody Report")
            
            if st.button("Generate Overall Report"):
                report_text = generate_report()
                report_pdf = generate_pdf_report_bytes()
                
                st.success("Report generated.")
                
                st.markdown("### Report Preview")
                st.text_area(
                    "Report Content",
                    report_text,
                    height=400,
                    disabled=True
                )
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.download_button(
                        label="📄 Download Report (.txt)",
                        data=report_text,
                        file_name="chain_of_custody_report.txt",
                        mime="text/plain"
                    )
                
                with col2:
                    st.download_button(
                        label="📑 Download Report (.pdf)",
                        data=report_pdf,
                        file_name="chain_of_custody_report.pdf",
                        mime="application/pdf"
                    )

if current_module == "5️⃣ Audit Log":
    st.subheader("Audit Log - System Actions")
    
    col1, col2 = st.columns([3, 1])
    with col2:
        limit = st.selectbox("Show last", [10, 50, 100, 500], index=2)
    
    audit_entries = get_audit_log(limit)
    
    if not audit_entries:
        st.info("No audit log entries yet.")
    else:
        st.markdown("### Recent Activity")
        
        for entry in audit_entries:
            timestamp, action, details, status, error_msg = entry
            
            if status == "SUCCESS":
                icon = "✅"
            elif status == "WARNING":
                icon = "⚠️"
            else:
                icon = "❌"
            
            ts = timestamp.split('T')
            date_part = ts[0]
            time_part = ts[1][:8] if len(ts) > 1 else ""
            
            with st.expander(f"{icon} {action} - {date_part} {time_part}"):
                st.write(f"**Status:** {status}")
                st.write(f"**Details:** {details}")
                if error_msg:
                    st.error(f"**Error:** {error_msg}")

if current_module == "6️⃣ Status & Checks":
    st.subheader("Evidence Status & Integrity Verification")
    
    tab_status, tab_checks = st.tabs(["📋 Status Management", "🔍 Automated Checks"])
    
    with tab_status:
        st.markdown("### Update Evidence Status")
        st.write("Manage evidence lifecycle: RECEIVED → IN_ANALYSIS → VERIFIED → RELEASED/ARCHIVED")
        st.caption("⚠️ You can only update the status of evidence you currently hold")
        
        user_probes = get_probes_currently_held(st.session_state.username)
        
        if not user_probes:
            st.info("ℹ️ No evidence currently in your custody. You can only update status for evidence you hold.")
        else:
            probe_map = {p[0]: p for p in user_probes}
            selected_probe_id = st.selectbox(
                "Select Evidence",
                options=list(probe_map.keys()),
                format_func=lambda pid: probe_map[pid][1],
                key="status_probe_select"
            )
            
            from core.custody import get_probe_status, update_probe_status
            current_status = get_probe_status(selected_probe_id)
            
            st.info(f"Current Status: **{current_status if current_status else 'RECEIVED'}**")
            
            status_options = ['RECEIVED', 'IN_ANALYSIS', 'VERIFIED', 'RELEASED', 'ARCHIVED']
            new_status = st.selectbox(
                "Update Status To:",
                options=status_options,
                key="new_status_select"
            )
            
            if st.button("Update Status"):
                if update_probe_status(selected_probe_id, new_status):
                    st.success(f"✅ Status updated to {new_status}")
                    st.rerun()
                else:
                    st.error("❌ Failed to update status")
    
    with tab_checks:
        st.markdown("### Automated Integrity Verification")
        st.write("NIST Compliance: Verify all evidence hasn't been tampered with")
        
        if st.button("🔍 Run Full System Integrity Check"):
            from core.custody import run_integrity_check_all
            
            with st.spinner("Checking all probes..."):
                altered, summary = run_integrity_check_all()
            
            st.success("✅ Integrity check completed")
            
            st.markdown("#### Check Summary:")
            for msg in summary:
                st.write(f"• {msg}")
            
            if altered:
                st.warning(f"⚠️ **{len(altered)} Altered Probes Detected!**")
                st.markdown("#### Altered Evidence:")
                for probe_id, filename, status, hash_val in altered:
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.error(f"**ID {probe_id}:** {filename} - Status: {status}")
                    with col2:
                        st.code(hash_val[:16] + "...")
            else:
                st.success("✅ All probes verified - No alterations detected")

if current_module == "7️⃣ Credential Analysis":
    st.subheader("🔐 Credential Security Analysis")
    
    st.markdown("""
    **[OPTIONAL - DEMONSTRATIVE MODULE]**
    
    This module provides optional post-acquisition analysis of extracted credential hashes 
    using Hashcat for dictionary-based attack testing. This analysis:
    - ✅ Operates on **working copies** (never modifies original evidence)
    - ✅ Does **NOT affect** chain of custody or integrity verification
    - ✅ Stores only **statistics** (no plaintext passwords)
    - ✅ Is **completely optional** for forensic investigation
    """)
    
    st.divider()
    
    analysis_col1, analysis_col2 = st.columns([1, 1])
    
    with analysis_col1:
        st.markdown("### Upload Hash File")
        
        probes_list = get_probes_currently_held(st.session_state.username)
        if not probes_list:
            st.warning("No evidence currently in your custody for analysis")
            probes_list = []
        
        if probes_list:
            probe_options = {f"ID {p[0]}: {p[1]}": p[0] for p in probes_list}
            selected_probe_display = st.selectbox(
                "Select evidence to associate with analysis",
                options=probe_options.keys()
            )
            selected_probe_id = probe_options[selected_probe_display]
        else:
            selected_probe_id = None
        
        from core.analysis import HASHCAT_TYPES
        hash_type_options = list(HASHCAT_TYPES.keys())
        selected_hash_type = st.selectbox(
            "Select hash type",
            options=hash_type_options,
            help="Type of hashes in your file (MD5, SHA256, BCRYPT, NTLM, etc.)"
        )
        
        hash_file = st.file_uploader(
            "Upload text file containing hashes (one per line)",
            type=["txt"],
            help="Plain text file with one hash per line"
        )
        
        analysis_ready = hash_file is not None and selected_probe_id is not None
        
        if st.button("▶️ Run Credential Analysis", disabled=not analysis_ready, type="primary"):
            if not hash_file:
                st.error("Please upload a hash file")
            elif selected_probe_id is None:
                st.error("Please select evidence to analyze")
            else:
                st.info("⏳ Running analysis... This may take a moment depending on hash count and wordlist size.")
                
                try:
                    hash_content = hash_file.read().decode('utf-8')
                    
                    from core.analysis import perform_analysis
                    success, results = perform_analysis(hash_content, selected_hash_type)
                    
                    if success:
                        total_hashes = results.get('total_hashes', 0)
                        cracked_hashes = results.get('cracked_hashes', 0)
                        crack_rate = results.get('crack_rate_percent', 0)
                        findings = results.get('findings', '')
                        
                        from core.database import save_analysis_results
                        analysis_id = save_analysis_results(
                            selected_probe_id,
                            selected_hash_type,
                            total_hashes,
                            cracked_hashes,
                            crack_rate,
                            findings,
                            st.session_state.username
                        )
                        
                        from core.audit import log_credential_analysis
                        log_credential_analysis(
                            selected_probe_id,
                            selected_hash_type,
                            total_hashes,
                            cracked_hashes,
                            crack_rate
                        )
                        
                        st.success("✅ Analysis completed and saved")
                        st.rerun()
                    else:
                        error_msg = results.get('error', 'Unknown error during analysis')
                        st.error(f"❌ Analysis failed: {error_msg}")
                        
                except UnicodeDecodeError:
                    st.error("❌ Could not read file - ensure it's a valid text file")
                except Exception as e:
                    st.error(f"❌ Error during analysis: {str(e)}")
    
    with analysis_col2:
        st.markdown("### Analysis Results")
        
        if selected_probe_id is not None:
            from core.database import get_analysis_summary
            analysis = get_analysis_summary(selected_probe_id)
            
            if analysis:
                st.success("✅ Analysis found for this evidence")
                st.markdown(f"""
                **Analysis Details:**
                - **Hash Type:** {analysis['hash_type']}
                - **Timestamp:** {analysis['timestamp']}
                - **Analyst:** {analysis['analyzed_by']}
                
                **Results:**
                - **Total Hashes:** {analysis['total_hashes']}
                - **Cracked:** {analysis['cracked_hashes']}
                - **Crack Rate:** {analysis['crack_rate']:.1f}%
                
                **Findings:**
                {analysis['findings']}
                
                ---
                
                **Security Note:**
                No plaintext passwords are stored. This module operates on temporary working 
                copies and does not modify original evidence or affect the chain of custody.
                """)
            else:
                st.info("No credential analysis performed yet for this evidence")
                st.markdown("""
                To perform analysis:
                1. Upload a text file with extracted credential hashes
                2. Select the appropriate hash type
                3. Click "Run Credential Analysis"
                """)
        else:
            st.info("Select evidence from the left panel to view existing analysis")
    
    st.divider()
    st.markdown("""
    ### Module Documentation
    
    **Purpose:** Optional post-acquisition credential security assessment
    
    **Workflow:**
    1. Extract credential hashes from evidence (externally)
    2. Upload hashes to this module
    3. Select hash type and run dictionary attack
    4. Review cracking statistics
    5. Analysis is logged and included in evidence reports
    
    **Security Properties:**
    - ✅ Operates on working copies only
    - ✅ No plaintext passwords stored
    - ✅ Separate from chain of custody logic
    - ✅ Optional analysis only
    
    **Limitations:**
    - Dictionary attack only (not brute force)
    - Requires Hashcat to be installed on system
    - Analysis time depends on wordlist and hash count
    
    **For Production Use:**
    - Customize wordlist for your environment
    - Consider attack time vs. accuracy tradeoffs
    - Review and audit all analysis results
    - Integrate with your forensic workflow
    """)