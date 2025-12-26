"""
Report generation module for custody chain reports.
Supports both text and PDF formats.
"""

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
            
            lines.append(f"\nEvidence ID: {p[0]}")
            lines.append(f"File: {p[1]}")
            lines.append(f"SHA-256: {p[2]}")
            lines.append(f"Date Added: {p[3]}")
            lines.append(f"Status: {status_display}")
    
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
    from core.database import get_probe_report_data, check_probe_integrity
    
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
            
            status = "✓ VALID" if transfer_hash == probe[2] else "✗ ALTERED"
            
            lines.append(f"\nTransfer #{i}:")
            lines.append(f"  From: {from_user}")
            lines.append(f"  To: {to_user}")
            lines.append(f"  Date: {transfer_date}")
            lines.append(f"  Status: {status}")
            lines.append(f"  Hash at Transfer: {transfer_hash[:16]}...")
    
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
    from core.database import get_probe_report_data, check_probe_integrity
    
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
    
    integrity_status = check_probe_integrity(probe_id)
    integrity_display = get_integrity_symbol(integrity_status)
    
    evidence_data = [
        ['Property', 'Value'],
        ['Evidence ID', str(probe[0])],
        ['Filename', probe[1]],
        ['SHA-256 Hash', probe[2][:32] + '...'],
        ['Uploaded By', probe[4]],
        ['Upload Date', probe[3]],
        ['File Size', f"{probe[5]} bytes" if probe[5] else "Unknown"],
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
        transfer_data = [['#', 'From', 'To', 'Date', 'Status']]
        for i, t in enumerate(transfers, 1):
            from_user = t[0]
            to_user = t[1]
            transfer_hash = t[2]
            transfer_date = t[3]
            
            status = "✓ VALID" if transfer_hash == probe[2] else "✗ ALTERED"
            transfer_data.append([str(i), from_user, to_user, transfer_date[:19], status])
        
        transfer_table = Table(transfer_data, colWidths=[0.5*inch, 1.5*inch, 1.5*inch, 1.5*inch, 1*inch])
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
    story.append(Paragraph("_" * 80, styles['Normal']))
    story.append(Paragraph(
        "Report generated by digital chain of custody system.",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey)
    ))
    
    doc.build(story)
    pdf_buffer.seek(0)
    return pdf_buffer.getvalue()

