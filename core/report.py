from typing import List, Tuple
from datetime import datetime
from core.database import get_report_data, check_probe_integrity


def generate_text_report() -> str:
    """
    Generate a comprehensive custody chain text report.
    
    Returns:
        Formatted text report containing all probes and transfer history.
    """
    probes, transfers = get_report_data()
    
    lines = []
    lines.append("REPORT - DIGITAL CHAIN OF CUSTODY")
    lines.append("=" * 60)
    lines.append(f"Generation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    
    lines.append("DIGITAL EVIDENCE:")
    lines.append("-" * 60)
    if not probes:
        lines.append("No evidence recorded.")
    else:
        for p in probes:
            integrity_status = check_probe_integrity(p[0])
            status_display = get_integrity_display(integrity_status)
            evidence_status = p[4] if len(p) > 4 and p[4] else "RECEIVED"
            
            lines.append(f"\nEvidence ID: {p[0]}")
            lines.append(f"File: {p[1]}")
            lines.append(f"SHA-256: {p[2]}")
            lines.append(f"Date Added: {p[3]}")
            lines.append(f"Current Status: {evidence_status}")
            lines.append(f"Integrity Status: {status_display}")
    
    lines.append("\n")
    lines.append("TRANSFER HISTORY:")
    lines.append("-" * 60)
    if not transfers:
        lines.append("No transfers recorded.")
    else:
        for t in transfers:
            probe_id = t[0]
            from_user = t[1]
            to_user = t[2]
            transfer_hash = t[3]
            transfer_date = t[4]
            filename = t[5]
            original_hash = t[6]
            
            status = "✓ VALID" if transfer_hash == original_hash else "✗ ALTERED"
            
            lines.append(f"\nEvidence: {filename} (ID: {probe_id})")
            lines.append(f"  From: {from_user} → To: {to_user}")
            lines.append(f"  Status: {status}")
            lines.append(f"  Transfer Hash: {transfer_hash[:16]}...")
            lines.append(f"  Original Hash: {original_hash[:16]}...")
            lines.append(f"  Transfer Date: {transfer_date}")
    
    return "\n".join(lines)


def get_integrity_display(status: str) -> str:
    """Convert integrity status to display string."""
    status_map = {
        "VALID": "✅ UNMODIFIED",
        "ALTERED": "❌ MODIFIED",
        "NO_TRANSFERS": "⚠️ NO TRANSFERS",
        "NOT_FOUND": "❌ NOT FOUND"
    }
    return status_map.get(status, status)


def get_integrity_symbol(status: str) -> str:
    """Get integrity status symbol for PDF display."""
    status_map = {
        "VALID": "✓ Unmodified",
        "ALTERED": "✗ Modified",
        "NO_TRANSFERS": "◐ No Transfers",
        "NOT_FOUND": "✗ Not Found"
    }
    return status_map.get(status, status)


def generate_pdf_report() -> bytes:
    """
    Generate a professional PDF custody chain report.
    
    Returns:
        PDF file as bytes.
    """
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
        from reportlab.lib import colors
        from io import BytesIO
    except ImportError:
        raise ImportError("reportlab is required for PDF generation. Install it with: pip install reportlab")
    
    probes, transfers = get_report_data()
    
    pdf_buffer = BytesIO()
    doc = SimpleDocTemplate(pdf_buffer, pagesize=A4)
    story = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor('#1f4788'),
        spaceAfter=6,
        alignment=1
    )
    story.append(Paragraph("REPORT - DIGITAL CHAIN OF CUSTODY", title_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 0.3 * inch))
    
    story.append(Paragraph("DIGITAL EVIDENCE", styles['Heading2']))
    story.append(Spacer(1, 0.2 * inch))
    
    if probes:
        probe_data = [['ID', 'File', 'SHA-256 (first 16 chars)', 'Date Added', 'Status']]
        for p in probes:
            integrity_status = check_probe_integrity(p[0])
            status_symbol = get_integrity_symbol(integrity_status)
            probe_data.append([
                str(p[0]),
                p[1][:30] + '...' if len(p[1]) > 30 else p[1],
                p[2][:16] + '...',
                p[3][:10],
                status_symbol
            ])
        
        probe_table = Table(probe_data, colWidths=[0.5*inch, 1.8*inch, 2.2*inch, 1.2*inch, 1.3*inch])
        probe_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4788')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')])
        ]))
        story.append(probe_table)
    else:
        story.append(Paragraph("No evidence recorded.", styles['Normal']))
    
    story.append(Spacer(1, 0.3 * inch))
    
    story.append(Paragraph("TRANSFER HISTORY", styles['Heading2']))
    story.append(Spacer(1, 0.2 * inch))
    
    if transfers:
        transfer_data = [['Evidence', 'From', 'To', 'Status', 'Transfer Date']]
        for t in transfers:
            transfer_hash = t[3]
            original_hash = t[6]
            status = "✓ VALID" if transfer_hash == original_hash else "✗ ALTERED"
            
            transfer_data.append([
                t[5][:20] + '...' if len(t[5]) > 20 else t[5],
                t[1],
                t[2],
                status,
                t[4][:10]
            ])
        
        transfer_table = Table(transfer_data, colWidths=[1.2*inch, 1.2*inch, 1.2*inch, 1.2*inch, 1.2*inch])
        transfer_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d5aa6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#e8f0f8')])
        ]))
        story.append(transfer_table)
    else:
        story.append(Paragraph("No transfers recorded.", styles['Normal']))
    
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph("_" * 80, styles['Normal']))
    story.append(Paragraph(
        "Report automatically generated by the digital chain of custody system.",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey)
    ))
    
    doc.build(story)
    pdf_buffer.seek(0)
    return pdf_buffer.getvalue()


def generate_probe_text_report(probe_id: int) -> str:
    """
    Generate a text report for a single probe.
    
    Args:
        probe_id: The probe ID to generate report for
        
    Returns:
        Formatted text report for the probe
    """
    from core.database import get_probe_report_data, check_probe_integrity, get_probe_integrity_timeline, get_integrity_compromise_interval
    
    probe, transfers = get_probe_report_data(probe_id)
    
    if not probe:
        return f"Probe {probe_id} not found."
    
    lines = []
    lines.append("=" * 60)
    lines.append("EVIDENCE REPORT - CHAIN OF CUSTODY")
    lines.append("=" * 60)
    lines.append(f"Generation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    
    lines.append("EVIDENCE DETAILS:")
    lines.append("-" * 60)
    lines.append(f"ID: {probe[0]}")
    lines.append(f"Filename: {probe[1]}")
    lines.append(f"SHA-256: {probe[2]}")
    lines.append(f"Uploaded By: {probe[4]}")
    lines.append(f"Date Added: {probe[3]}")
    lines.append(f"File Size: {probe[5]} bytes" if probe[5] else "File Size: Unknown")
    
    evidence_status = probe[6] if len(probe) > 6 and probe[6] else "RECEIVED"
    lines.append(f"Current Status: {evidence_status}")
    
    from core.database import get_latest_integrity_verification
    latest_verification = get_latest_integrity_verification(probe_id)
    if latest_verification is not None:
        integrity_status = latest_verification
    else:
        integrity_status = check_probe_integrity(probe_id)
    
    lines.append(f"Integrity Status: {get_integrity_display(integrity_status)}")
    
    lines.append("")
    lines.append("TRANSFER HISTORY:")
    lines.append("-" * 60)
    
    if not transfers:
        lines.append("No transfers recorded. Evidence is with initial custodian.")
    else:
        for i, t in enumerate(transfers, 1):
            from_user = t[0]
            to_user = t[1]
            transfer_hash = t[2]
            transfer_date = t[3]
            transfer_reason = t[4] if len(t) > 4 else ""
            transfer_notes = t[5] if len(t) > 5 else ""
            
            status = "✓ VALID" if transfer_hash == probe[2] else "✗ ALTERED"
            
            lines.append(f"\nTransfer #{i}:")
            lines.append(f"  From: {from_user}")
            lines.append(f"  To: {to_user}")
            lines.append(f"  Date: {transfer_date}")
            lines.append(f"  Status: {status}")
            lines.append(f"  Hash at Transfer: {transfer_hash[:16]}...")
            
            if transfer_reason:
                lines.append(f"  Reason: {transfer_reason}")
            
            if transfer_notes:
                lines.append(f"  Notes: {transfer_notes}")
    
    lines.append("")
    lines.append("INTEGRITY VERIFICATION TIMELINE:")
    lines.append("-" * 60)
    
    timeline = get_probe_integrity_timeline(probe_id)
    
    if not timeline:
        lines.append("No integrity events recorded.")
    else:
        for event_type, description, timestamp, hash_value, integrity_result, transfer_status in timeline:
            if integrity_result == 'VALID':
                integrity_display = "✓ VALID"
            elif 'propagated' in integrity_result:
                integrity_display = "✗ ALTERED (propagated)"
            elif 'compromised' in integrity_result:
                integrity_display = "⚠ VALID (but evidence compromised)"
            else:
                integrity_display = "✗ ALTERED"
            lines.append(f"\n[{event_type}]")
            lines.append(f"  Timestamp: {timestamp}")
            lines.append(f"  Description: {description}")
            lines.append(f"  Hash: {hash_value[:16]}...")
            if transfer_status:
                lines.append(f"  Transfer Status: {transfer_status}")
            lines.append(f"  Integrity Result: {integrity_display}")
    
    lines.append("")
    lines.append("FORENSIC INTERPRETATION OF INTEGRITY COMPROMISE:")
    lines.append("-" * 60)
    lines.append("")
    lines.append("CRITICAL FORENSIC PRINCIPLE:")
    lines.append("Integrity failure (ALTERED evidence) does NOT invalidate chain of custody.")
    lines.append("All custody transfers succeed procedurally regardless of integrity status.")
    lines.append("Compromised evidence remains fully traceable and documented.")
    lines.append("")
    
    compromise_info = get_integrity_compromise_interval(probe_id)
    
    if compromise_info is None:
        lines.append("No integrity compromise detected. Evidence chain maintains integrity throughout")
        lines.append("all recorded custody transfers and verification checks.")
    else:
        last_valid_desc, first_altered_desc, interval_text = compromise_info
        lines.append("COMPROMISE INTERVAL IDENTIFIED:")
        lines.append("")
        lines.append(f"Last event with valid integrity:")
        lines.append(f"  {last_valid_desc}")
        lines.append("")
        lines.append(f"First event detecting integrity compromise:")
        lines.append(f"  {first_altered_desc}")
        lines.append("")
        lines.append(f"Time interval of compromise:")
        lines.append(f"  {interval_text}")
        lines.append("")
        lines.append("IMPORTANT: Evidence integrity compromise has been detected and documented.")
        lines.append("The chain of custody remains valid. All custodians who received ALTERED")
        lines.append("evidence have been documented and the integrity status was propagated through")
        lines.append("all subsequent transfers. This information is critical for investigation.")
        lines.append("FORENSIC FINDING:")
        lines.append("The digital evidence exhibits integrity divergence. The compromise occurred within")
        lines.append("the identified temporal interval. This finding is presented for forensic analysis")
        lines.append("purposes and does not attribute responsibility or causation to any custodian.")
    
    lines.append("")
    lines.append("CREDENTIAL SECURITY ANALYSIS:")
    lines.append("-" * 60)
    lines.append("[OPTIONAL - DEMONSTRATIVE ANALYSIS MODULE]")
    lines.append("")
    
    from core.database import get_analysis_summary
    analysis = get_analysis_summary(probe_id)
    
    if analysis is None:
        lines.append("No credential analysis has been performed on this evidence.")
        lines.append("Credential analysis is an optional post-acquisition analysis tool using")
        lines.append("Hashcat for dictionary-based password cracking assessment.")
    else:
        lines.append(f"Analysis Type: {analysis['hash_type']} Hash Dictionary Attack")
        lines.append(f"Analysis Timestamp: {analysis['timestamp']}")
        lines.append(f"Analyzed By: {analysis['analyzed_by']}")
        lines.append("")
        lines.append(f"Total Hashes Analyzed: {analysis['total_hashes']}")
        lines.append(f"Successfully Cracked: {analysis['cracked_hashes']}")
        lines.append(f"Crack Rate: {analysis['crack_rate']:.1f}%")
        lines.append("")
        lines.append("FINDINGS:")
        lines.append(f"  {analysis['findings']}")
        lines.append("")
        lines.append("NOTE: This analysis is demonstrative only. It operates on working copies")
        lines.append("of evidence and does not affect chain of custody or integrity verification.")
        lines.append("No plaintext passwords are stored in the system.")
    
    return "\n".join(lines)


def generate_probe_pdf_report(probe_id: int) -> bytes:
    """
    Generate a professional PDF report for a single probe.
    
    Args:
        probe_id: The probe ID to generate report for
        
    Returns:
        PDF file as bytes
    """
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from io import BytesIO
    from core.database import get_probe_report_data, check_probe_integrity, get_authoritative_integrity_status, get_probe_integrity_timeline, get_integrity_compromise_interval
    
    probe, transfers = get_probe_report_data(probe_id)
    
    if not probe:
        return b"Probe not found"
    
    pdf_buffer = BytesIO()
    doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, topMargin=0.5*inch)
    story = []
    styles = getSampleStyleSheet()
    
    story.append(Paragraph("EVIDENCE REPORT - CHAIN OF CUSTODY", styles['Title']))
    story.append(Spacer(1, 0.2*inch))
    
    story.append(Paragraph("Evidence Information", styles['Heading2']))
    
    latest_verification = get_authoritative_integrity_status(probe_id)
    if latest_verification is not None:
        integrity_status = latest_verification
    else:
        integrity_status = check_probe_integrity(probe_id)
    integrity_display = get_integrity_symbol(integrity_status)
    evidence_status = probe[6] if len(probe) > 6 and probe[6] else "RECEIVED"
    
    evidence_data = [
        ['Property', 'Value'],
        ['Evidence ID', str(probe[0])],
        ['Filename', probe[1]],
        ['SHA-256 Hash', probe[2][:32] + '...'],
        ['Uploaded By', probe[4]],
        ['Upload Date', probe[3]],
        ['File Size', f"{probe[5]} bytes" if probe[5] else "Unknown"],
        ['Current Status', evidence_status],
        ['Integrity Status', integrity_display]
    ]
    
    evidence_table = Table(evidence_data, colWidths=[2*inch, 4*inch])
    evidence_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#003366')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#e8f0f8')])
    ]))
    story.append(evidence_table)
    
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("Transfer History", styles['Heading2']))
    
    if not transfers:
        story.append(Paragraph("No transfers recorded. Evidence is with initial custodian.", styles['Normal']))
    else:
        transfer_data = [['#', 'From', 'To', 'Date', 'Reason', 'Status']]
        for i, t in enumerate(transfers, 1):
            from_user = t[0]
            to_user = t[1]
            transfer_hash = t[2]
            transfer_date = t[3]
            transfer_reason = t[4] if len(t) > 4 else ""
            
            status = "✓ VALID" if transfer_hash == probe[2] else "✗ ALTERED"
            transfer_data.append([str(i), from_user, to_user, transfer_date[:19], 
                                transfer_reason[:20], status])
        
        transfer_table = Table(transfer_data, colWidths=[0.4*inch, 1.2*inch, 1.2*inch, 1.4*inch, 1.3*inch, 0.8*inch])
        transfer_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#003366')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#e8f0f8')])
        ]))
        story.append(transfer_table)
    
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("Integrity Verification Timeline", styles['Heading2']))
    
    timeline = get_probe_integrity_timeline(probe_id)
    
    if not timeline:
        story.append(Paragraph("No integrity events recorded.", styles['Normal']))
    else:
        timeline_data = [['Type', 'Date & Time', 'Event Description', 'Status', 'Integrity']]
        for event_type, description, timestamp, hash_value, integrity_result, transfer_status in timeline:
            if integrity_result == 'VALID':
                integrity_display = "✓ VALID"
            elif 'propagated' in integrity_result:
                integrity_display = "✗ ALTERED (prop.)"
            elif 'compromised' in integrity_result:
                integrity_display = "⚠ VALID (comp.)"
            else:
                integrity_display = "✗ ALTERED"
            desc_short = description[:35] + "..." if len(description) > 35 else description
            status_display = transfer_status if transfer_status else '-'
            type_short = event_type[:12]
            timeline_data.append([
                type_short,
                timestamp[:16],
                desc_short,
                status_display,
                integrity_display
            ])
        
        timeline_table = Table(timeline_data, colWidths=[0.85*inch, 1.15*inch, 2.2*inch, 0.95*inch, 1.05*inch])
        timeline_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a3a5c')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('ALIGNMENT', (0, 0), (-1, 0), 'CENTER'),
            ('LEFTPADDING', (0, 0), (-1, 0), 5),
            ('RIGHTPADDING', (0, 0), (-1, 0), 5),
            ('TOPPADDING', (0, 0), (-1, 0), 7),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 7),
            
            ('ALIGN', (0, 1), (2, -1), 'LEFT'),
            ('ALIGNMENT', (3, 1), (4, -1), 'CENTER'),
            ('FONTSIZE', (0, 1), (-1, -1), 7.5),
            ('LEFTPADDING', (0, 1), (-1, -1), 5),
            ('RIGHTPADDING', (0, 1), (-1, -1), 5),
            ('TOPPADDING', (0, 1), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#666666')),
            ('LINEBELOW', (0, 0), (-1, 0), 1.5, colors.black),
            
            ('LINEAFTER', (3, 0), (3, -1), 1.5, colors.HexColor('#1a3a5c')),
            
            ('LINEAFTER', (0, 0), (0, -1), 0.5, colors.HexColor('#aaaaaa')),
            ('LINEAFTER', (1, 0), (1, -1), 0.5, colors.HexColor('#aaaaaa')),
            ('LINEAFTER', (2, 0), (2, -1), 0.5, colors.HexColor('#aaaaaa')),
            
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fbfd')]),
            
            ('BACKGROUND', (4, 1), (4, -1), colors.HexColor('#f0f8ff')),
        ]))
        story.append(timeline_table)
    
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("Forensic Interpretation of Integrity Compromise", styles['Heading2']))
    
    critical_principle = """
    <b>CRITICAL FORENSIC PRINCIPLE:</b><br/>
    Integrity failure (ALTERED evidence) does NOT invalidate the chain of custody.<br/>
    All custody transfers succeed procedurally regardless of integrity status.<br/>
    Compromised evidence remains fully traceable and documented.
    """
    story.append(Paragraph(critical_principle, styles['Normal']))
    story.append(Spacer(1, 0.1*inch))
    
    compromise_info = get_integrity_compromise_interval(probe_id)
    
    if compromise_info is None:
        story.append(Paragraph(
            "No integrity compromise detected. The evidence chain maintains integrity throughout "
            "all recorded custody transfers and verification checks.",
            styles['Normal']
        ))
    else:
        last_valid_desc, first_altered_desc, interval_text = compromise_info
        
        compromise_text = f"""
        <b>Compromise Interval Identified:</b><br/><br/>
        
        <b>Last event with valid integrity:</b><br/>
        {last_valid_desc}<br/><br/>
        
        <b>First event detecting integrity compromise:</b><br/>
        {first_altered_desc}<br/><br/>
        
        <b>Time interval of compromise:</b><br/>
        {interval_text}<br/><br/>
        
        <b>Chain of Custody Status:</b><br/>
        UNBROKEN - All custody transfers succeeded procedurally and are documented in this report.<br/>
        All custodians who received ALTERED evidence have been documented and the integrity status 
        was propagated through all subsequent transfers.<br/><br/>
        
        <b>Forensic Finding:</b><br/>
        The digital evidence exhibits integrity divergence. The compromise occurred within the 
        identified temporal interval. This finding is presented for forensic analysis purposes and 
        does not attribute responsibility or causation to any custodian. Further investigation into 
        the specific actions, system logs, and environmental conditions during the identified interval 
        may be warranted to determine the root cause of the integrity divergence.<br/><br/>
        
        <b>Investigative Significance:</b><br/>
        The documented integrity status change is critical evidence that the integrity of the 
        materials may have been compromised. All parties with access during the compromise interval 
        should be interviewed, and system logs should be reviewed for suspicious activities.
        """
        
        story.append(Paragraph(compromise_text, styles['Normal']))
    
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("Credential Security Analysis", styles['Heading2']))
    story.append(Paragraph("[OPTIONAL - DEMONSTRATIVE ANALYSIS MODULE]", 
                          ParagraphStyle('Note', parent=styles['Normal'], fontSize=9, textColor=colors.grey)))
    story.append(Spacer(1, 0.1*inch))
    
    from core.database import get_analysis_summary
    analysis = get_analysis_summary(probe_id)
    
    if analysis is None:
        analysis_text = """
        No credential analysis has been performed on this evidence.<br/><br/>
        Credential analysis is an optional post-acquisition analysis tool using Hashcat for 
        dictionary-based password cracking assessment. This module operates on working copies of 
        evidence and does not affect chain of custody or integrity verification.
        """
        story.append(Paragraph(analysis_text, styles['Normal']))
    else:
        analysis_data = [
            ['Metric', 'Value'],
            ['Analysis Type', f"{analysis['hash_type']} Hash Dictionary Attack"],
            ['Analysis Timestamp', analysis['timestamp']],
            ['Analyzed By', analysis['analyzed_by']],
            ['Total Hashes Analyzed', str(analysis['total_hashes'])],
            ['Successfully Cracked', str(analysis['cracked_hashes'])],
            ['Crack Rate', f"{analysis['crack_rate']:.1f}%"]
        ]
        
        analysis_table = Table(analysis_data, colWidths=[2.5*inch, 3.5*inch])
        analysis_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a5c2a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#e8f5e9')])
        ]))
        story.append(analysis_table)
        
        story.append(Spacer(1, 0.15*inch))
        findings_text = f"""
        <b>Findings:</b><br/>
        {analysis['findings']}<br/><br/>
        
        <b>Note:</b> This analysis is demonstrative only. It operates on working copies of evidence 
        and does not affect chain of custody or integrity verification. No plaintext passwords 
        are stored in the system.
        """
        story.append(Paragraph(findings_text, styles['Normal']))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("_" * 80, styles['Normal']))
    story.append(Paragraph(
        "Report generated by digital chain of custody system.",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey)
    ))
    
    doc.build(story)
    pdf_buffer.seek(0)
    return pdf_buffer.getvalue()
