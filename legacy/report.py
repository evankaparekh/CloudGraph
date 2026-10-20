"""Downloadable defensive assessment report; no cloud credentials required."""
from io import BytesIO
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from .engine import analyze, simulate


def risk_summary(result):
    """Transparent illustrative scoring; not CVSS or exploitability."""
    findings = result['findings']
    return {'highest_score': max((f['score'] for f in findings), default=0),
            'average_score': round(sum(f['score'] for f in findings) / len(findings), 1) if findings else 0,
            'critical': result['critical'], 'high': result['high'], 'total_paths': result['total_paths'],
            'method': 'Graph-derived illustrative severity, based on target impact, entry point, and path length; not CVSS.'}


def create_report(environment, disabled_edges=None):
    before = analyze(environment)
    after = simulate(environment, disabled_edges)['after'] if disabled_edges is not None else None
    stream = BytesIO()
    doc = SimpleDocTemplate(stream, pagesize=(595, 842), leftMargin=48, rightMargin=48, topMargin=48, bottomMargin=48)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CGTitle', parent=styles['Title'], fontSize=22, leading=27, textColor=colors.HexColor('#16365e'), spaceAfter=14))
    styles.add(ParagraphStyle(name='CGSmall', parent=styles['BodyText'], fontSize=9, leading=13, spaceAfter=8))
    story = [Paragraph('CloudGraph | Security Assessment', styles['CGTitle']),
             Paragraph('Environment: ' + escape(str(environment.get('name', 'Unnamed environment'))), styles['BodyText']), Spacer(1, 14)]
    summary = risk_summary(before)
    rows = [['Resources', str(before['resources'])], ['Relationships', str(before['relationships'])],
            ['Potential paths', str(before['total_paths'])], ['Critical / High', f"{before['critical']} / {before['high']}"],
            ['Highest illustrative score', str(summary['highest_score']) + ' / 100']]
    t = Table(rows, colWidths=[235, 235]);t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#edf4fc')),('BOTTOMPADDING',(0,0),(-1,-1),9),('TOPPADDING',(0,0),(-1,-1),9),('LINEBELOW',(0,0),(-1,-1),.3,colors.HexColor('#c9d5e3'))]));story.extend([t,Spacer(1,16)])
    story.append(Paragraph('Methodology & limitations', styles['Heading2']))
    story.append(Paragraph('Offline analysis of user-provided AWS-style synthetic relationships. Paths indicate modeled reachability, not confirmed effective AWS permissions, exploitability, or real-world compromise. Scores are illustrative and not CVSS. Results are capped at 100 displayed findings.', styles['CGSmall']))
    if after is not None:
        story.append(Paragraph('Remediation simulation', styles['Heading2']))
        story.append(Paragraph(f"Before: {before['total_paths']} paths | After: {after['total_paths']} paths | Disabled edge indices: {escape(str(disabled_edges))}. No live infrastructure was modified.", styles['CGSmall']))
    story.append(Paragraph('Exposure findings', styles['Heading2']))
    if not before['findings']:
        story.append(Paragraph('No modeled paths identified. This does not prove the environment is secure.', styles['CGSmall']))
    for index, finding in enumerate(before['findings'], 1):
        parts = [Paragraph(f"{index}. {escape(finding['severity'].upper())} | {escape(finding['source'])} → {escape(finding['target'])} | {finding['score']}/100", styles['Heading3']),
                 Paragraph('Path: ' + escape(' → '.join(finding['path'])), styles['CGSmall']),
                 Paragraph(escape(finding['reason']), styles['CGSmall']),
                 Paragraph('Suggested investigation: verify permissions and network reachability; apply least privilege and restrict unnecessary entry paths.', styles['CGSmall'])]
        story.append(KeepTogether(parts))
    doc.build(story)
    return stream.getvalue()
