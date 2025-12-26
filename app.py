import streamlit as st
from config import APP_TITLE, APP_VERSION

from core.database import init_db, get_probes_for_user, get_probes_currently_held
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
    get_current_custodian
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
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("🔓 Login", key="login_button"):
            result = authenticate_user(username, password)
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
        st.write("Register as a new custodian")
        
        new_username = st.text_input("Choose Username", key="register_username")
        new_password = st.text_input("Choose Password", type="password", key="register_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="register_confirm")
        
        if st.button("📝 Create Account", key="register_button"):
            if not new_username.strip():
                st.error("❌ Username cannot be empty")
            elif len(new_username) < 3:
                st.error("❌ Username must be at least 3 characters")
            elif not new_password:
                st.error("❌ Password cannot be empty")
            elif len(new_password) < 6:
                st.error("❌ Password must be at least 6 characters")
            elif new_password != confirm_password:
                st.error("❌ Passwords do not match")
            else:
                try:
                    create_user_with_password(new_username.strip(), new_password)
                    st.success(f"✅ Account created successfully!")
                    st.info(f"Username: **{new_username.strip()}**\n\nYou can now login.")
                except Exception as e:
                    if "UNIQUE constraint failed" in str(e):
                        st.error(f"❌ Username '{new_username.strip()}' already exists")
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
st.caption("Authentication and validation of digital evidence")

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "1️⃣ Add Evidence",
    "2️⃣ Custody Transfer",
    "3️⃣ Integrity Check",
    "4️⃣ Report",
    "5️⃣ Audit Log",
    "6️⃣ Status & Checks"
])

with tab1:
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

with tab2:
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
                "Transfer Reason",
                placeholder="e.g., For analysis, Evidence verification, Storage transfer...",
                help="Document why this evidence is being transferred (NIST compliance)"
            )

            if st.button("Perform Transfer"):
                if not transfer_reason.strip():
                    st.error("❌ Transfer reason is required (NIST/Forensic standard)")
                else:
                    try:
                        integrity_valid, original_hash, current_hash = add_transfer(
                            selected_probe_id,
                            from_user,
                            to_user,
                            transfer_reason.strip()
                        )
                        
                        if integrity_valid:
                            st.success("✅ Transfer recorded - Evidence integrity verified.")
                            st.info(f"Hash matches original: {current_hash[:16]}...")
                            st.rerun()
                        else:
                            st.warning("⚠️ Transfer recorded - Evidence integrity ALTERED!")
                            st.code(f"Original Hash: {original_hash[:32]}...")
                            st.code(f"Current Hash:  {current_hash[:32]}...")
                            st.rerun()
                    except ValueError as e:
                        st.error(f"❌ Transfer validation failed:\n{str(e)}")
                    except Exception as e:
                        st.error(f"❌ Error during transfer:\n{str(e)}")

with tab3:
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

with tab4:
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
                    st.download_button(
                        label="📑 Download Report (.pdf)",
                        data=report_pdf,
                        file_name=f"evidence_report_{selected_probe_id}.pdf",
                        mime="application/pdf"
                    )
        
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

with tab5:
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

with tab6:
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
