"""Generate a downloadable PDF report from a synthetic environment."""
from io import BytesIO
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from .engine import analyze
from .linked import linked_analysis
from .scoring import enrich


def create_report(environment, policies=None, disabled_edges=None):
    if policies is not None:
        result = linked_analysis(environment, policies, disabled_edges or [])
    else:
        from .engine import simulate
        result = simulate(environment, disabled_edges)['after'] if disabled_edges else analyze(environment)
    enrich(result, environment)
    buf = BytesIO()
    doc = SimpleDocTemplate(buf,pagesize=letter,rightMargin=44,leftMargin=44,topMargin=45,bottomMargin=45)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='SubtleCG',parent=styles['Normal'],fontSize=9,textColor=colors.HexColor('#52647d'),leading=14))
    story=[Paragraph('CLOUDGRAPH | SECURITY ASSESSMENT',styles['Title']),Spacer(1,12),Paragraph('Offline modeled cloud exposure report',styles['Heading2']),Paragraph('Environment: '+escape(str(environment.get('name','Imported environment'))[:140]),styles['Normal']),Spacer(1,12)]
    metrics=[['Resources','Relationships','Modeled paths','Critical'],[str(result['resources']),str(result['relationships']),str(result['total_paths']),str(result['critical'])]]
    t=Table(metrics,colWidths=[125]*4);t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e7eef8')),('GRID',(0,0),(-1,-1),.5,colors.HexColor('#ccd7e4')),('BOTTOMPADDING',(0,0),(-1,-1),10),('TOPPADDING',(0,0),(-1,-1),10)]));story.extend([t,Spacer(1,15)])
    story.append(Paragraph('Scope and limitations',styles['Heading2']))
    story.append(Paragraph('This report analyzes a simplified offline resource graph. Paths are potential modeled relationships, not evidence of exploitation or effective AWS authorization. Scores are illustrative, not CVSS. Never treat an absence of findings as proof of safety.',styles['SubtleCG']))
    if policies is not None:
        story.append(Paragraph('IAM overlay: '+escape(result['scope']),styles['SubtleCG']))
    story.append(Spacer(1,12))
    story.append(Paragraph('Prioritized findings',styles['Heading2']))
    if not result['findings']:
        story.append(Paragraph('No paths found under this limited model.',styles['Normal']))
    for idx,f in enumerate(result['findings'][:50],1):
        details=f['risk_explanation']; factors=details['factors']
        elements=[Paragraph(f'{idx}. {escape(f["source"])} to {escape(f["target"])} | {escape(f["severity"].upper())} | {f["score"]}/100',styles['Heading3']),Paragraph('Path: '+escape(' -> '.join(f['path'])),styles['Normal']),Paragraph('Score factors: asset '+str(factors['sensitive_asset_impact'])+', source '+str(factors['source_exposure'])+', hop adjustment '+str(factors['intermediate_hop_adjustment']),styles['SubtleCG']),Paragraph('Suggested review: '+escape(' '.join(details['recommendations'])),styles['SubtleCG']),Spacer(1,9)]
        story.append(KeepTogether(elements))
    doc.build(story)
    return buf.getvalue()
