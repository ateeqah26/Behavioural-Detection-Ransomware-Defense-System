import os
import sqlite3
import database
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_pdf_report(filename="Monitor_Security_Report.pdf"):
    # 1. Sambung ke database asal anda (guna path yang sama seperti app.py / monitor.py)
    conn = database.get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            process_name TEXT,
            action_taken TEXT,
            threat_level TEXT
        )
    """)

    # Ambil data daripada kolom asal anda
    cursor.execute("SELECT id, timestamp, process_name, action_taken, threat_level FROM detection_logs ORDER BY id DESC LIMIT 15")
    logs = cursor.fetchall()
    conn.close()

    # 2. Tetapan Dokumen PDF
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    story = []
    styles = getSampleStyleSheet()

    # Style Font & Warna
    title_style = ParagraphStyle(
        'TitleStyle', parent=styles['Heading1'],
        fontName='Helvetica-Bold', fontSize=16, textColor=colors.white, spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'SubTitleStyle', parent=styles['Normal'],
        fontName='Helvetica', fontSize=9, textColor=colors.HexColor('#D0D8E8')
    )
    cell_header_style = ParagraphStyle(
        'CellHeader', fontName='Helvetica-Bold', fontSize=9, textColor=colors.white, alignment=1
    )
    cell_body_style = ParagraphStyle(
        'CellBody', fontName='Helvetica', fontSize=8, textColor=colors.HexColor('#1E293B'), alignment=1
    )

    # --- BANNER ATAS (Dark Blue) ---
    header_data = [
        [Paragraph("BEHAVIORAL DEFENSE SYSTEM", title_style)],
        [Paragraph("Automated Threat Detection & Security Summary Report", subtitle_style)]
    ]
    header_table = Table(header_data, colWidths=[540])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#0F172A')),
        ('TOPPADDING', (0,0), (-1,-1), 16),
        ('BOTTOMPADDING', (0,0), (-1,-1), 16),
        ('LEFTPADDING', (0,0), (-1,-1), 20),
        ('RIGHTPADDING', (0,0), (-1,-1), 20),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 15))

    # --- TARIKH DIJANAKAN ---
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    story.append(Paragraph(f"Generated On: {current_time}", ParagraphStyle('TimeStyle', fontName='Helvetica', fontSize=8, textColor=colors.HexColor('#64748B'))))
    story.append(Spacer(1, 12))

    # --- EXECUTIVE SUMMARY BOX ---
    summary_content = [
        [Paragraph("<b>EXECUTIVE SUMMARY</b>", ParagraphStyle('ExecTitle', fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor('#0F172A')))],
        [Spacer(1, 4)],
        [Paragraph("System Status: <b>PROTECTED</b> | Monitoring Engine: <b>ACTIVE</b> | Enforcement: <b>AUTOMATIC</b>", 
                   ParagraphStyle('ExecBody', fontName='Helvetica', fontSize=8, textColor=colors.HexColor('#334155')))]
    ]
    summary_table = Table(summary_content, colWidths=[540])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F1F5F9')),
        ('PADDING', (0,0), (-1,-1), 12),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 18))

    # --- TAJUK JADUAL ---
    story.append(Paragraph("Recent Incident Logs & Enforcement Actions", ParagraphStyle('SecTitle', fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor('#0F172A'))))
    story.append(Spacer(1, 8))

    # --- JADUAL DENGAN KOLOM ASAL ANDA ---
    table_data = [[
        Paragraph("ID", cell_header_style),
        Paragraph("Timestamp", cell_header_style),
        Paragraph("Process Name", cell_header_style),
        Paragraph("Action Taken", cell_header_style),
        Paragraph("Threat Level", cell_header_style)
    ]]

    for log in logs:
        table_data.append([
            Paragraph(str(log[0]), cell_body_style),
            Paragraph(str(log[1]), cell_body_style),
            Paragraph(str(log[2]), cell_body_style),
            Paragraph(str(log[3]), cell_body_style),
            Paragraph(str(log[4]), cell_body_style)
        ])

    log_table = Table(table_data, colWidths=[40, 130, 150, 120, 100])
    log_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    
    story.append(log_table)

    # 3. Bina Fail PDF
    doc.build(story)
    return filename

if __name__ == "__main__":
    generate_pdf_report()