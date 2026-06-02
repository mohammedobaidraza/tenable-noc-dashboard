"""Generate project documentation Word file."""
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH

doc = Document()

style = doc.styles["Normal"]
style.font.name = "Calibri"
style.font.size = Pt(11)

# Title
title = doc.add_heading("Tenable NOC Dashboard - Project Documentation", level=0)
title.alignment = WD_ALIGN_PARAGRAPH.CENTER

doc.add_paragraph("")

# Overview
doc.add_heading("1. Project Overview", level=1)
doc.add_paragraph(
    "We transformed a basic Python script (tenable_tracker_reconstructed.py) that fetched "
    "only Critical and High severity vulnerabilities from Tenable.io and updated an Excel "
    "tracker, into a full interactive NOC-style dashboard generator that fetches all 4 "
    "severity levels and produces 7 standalone interactive HTML reports with a dark "
    "control room theme."
)

# Repository
doc.add_heading("2. Repository & File Locations", level=1)
table = doc.add_table(rows=7, cols=2, style="Light Grid Accent 1")
data = [
    ("GitHub Repo", "https://github.com/mohammedobaidraza/tenable-noc-dashboard"),
    ("Local Repo", r"C:\Users\Obaid Raza\Desktop\tenable-noc-dashboard"),
    ("Main Script", "tenable_noc_dashboard.py"),
    ("Excel Output", r"C:\tenable_tracker\Tenable_NOC_Tracker.xlsx"),
    ("HTML Reports", "C:\\tenable_tracker\\reports\\"),
    ("Original Script", r"C:\Users\Obaid Raza\Desktop\tenable_tracker_reconstructed.py"),
    ("Run Location", r"C:\tenable_tracker\ (on work machine)"),
]
for i, (k, v) in enumerate(data):
    table.rows[i].cells[0].text = k
    table.rows[i].cells[1].text = v

# What Changed
doc.add_heading("3. What Changed from Original", level=1)
changes = [
    "Fetches ALL 4 severity levels (Critical, High, Medium, Low) - original only did Critical + High",
    "Generates 7 standalone interactive HTML files (no server needed)",
    "Dark NOC/control room theme (deep navy background, cyan accents)",
    "Interactive Plotly charts with hover tooltips, zoom, pan, export",
    "Switchable chart types - toggle between Pie and Bar views via buttons",
    "Per-tower dashboard tabs (12 towers: Intel Server, Linux, Workstations, etc.)",
    "SLA aging analysis with configurable thresholds (Critical: 30d, High: 60d, Medium: 90d, Low: 180d)",
    "6-week trend tracking from Excel 'Host Total' columns",
    "Vulnerability treemap visualization (Tower > Severity > Plugin Family)",
    "Fluctuation heatmap showing week-over-week % change per tower",
    "Sortable and searchable data tables in every report",
    "Aging buckets breakdown (0-30, 31-60, 61-90, 91-120, 120+ days)",
    "Excel file renamed to Tenable_NOC_Tracker.xlsx",
]
for c in changes:
    doc.add_paragraph(c, style="List Bullet")

# HTML Output
doc.add_heading("4. HTML Reports Generated", level=1)
table2 = doc.add_table(rows=7, cols=2, style="Light Grid Accent 1")
table2.rows[0].cells[0].text = "File"
table2.rows[0].cells[1].text = "Description"
for cell in table2.rows[0].cells:
    cell.paragraphs[0].runs[0].bold = True
files = [
    ("dashboard.html", "Main NOC overview with per-tower tabs, treemap, heatmap"),
    ("critical.html", "Critical severity breakdown with charts and data table"),
    ("high.html", "High severity breakdown with charts and data table"),
    ("medium.html", "Medium severity breakdown with charts and data table"),
    ("low.html", "Low severity breakdown with charts and data table"),
    ("consolidated.html", "All severities combined with full cross-severity analysis"),
]
for i, (f, d) in enumerate(files, 1):
    table2.rows[i].cells[0].text = f
    table2.rows[i].cells[1].text = d

# Charts
doc.add_heading("5. Charts Included", level=1)

doc.add_heading("Dashboard Overview Tab:", level=2)
for item in [
    "KPI Cards - Total vulns, Critical, High, Medium, Low, Exploitable count",
    "Severity Distribution - Pie/Bar chart (switchable via toggle buttons)",
    "SLA Compliance per Tower - Bar chart with 80% target line",
    "Tower Comparison - Stacked bar chart by severity",
    "Vulnerability Treemap - Interactive map: Tower > Severity > Plugin Family",
    "Fluctuation Heatmap - Week-over-week % change across all towers",
    "Aging Buckets - Grouped bar chart by severity and age range",
]:
    doc.add_paragraph(item, style="List Bullet")

doc.add_heading("Per-Tower Tabs:", level=2)
for item in [
    "KPI Cards - Vulns, Hosts, Critical, High, Avg Age, SLA %",
    "Severity Distribution - Pie/Bar (switchable)",
    "SLA Compliance Donut with percentage overlay",
    "Age Histogram stacked by severity",
    "Exploit Availability Pie chart",
    "Top 10 Vulnerabilities horizontal bar chart",
    "Plugin Family Breakdown horizontal bar chart",
    "Weekly Trend Line chart (builds over time with each run)",
    "Aging Buckets grouped bar chart",
    "Full Interactive Data Table (sortable, searchable)",
]:
    doc.add_paragraph(item, style="List Bullet")

# API Keys
doc.add_heading("6. API Key Configuration", level=1)
doc.add_paragraph(
    "API keys are hardcoded at the top of tenable_noc_dashboard.py (lines 48-49), "
    "matching the original script style:"
)
doc.add_paragraph('accessKey = "YOUR_ACCESS_KEY"', style="No Spacing")
doc.add_paragraph('secretKey = "YOUR_SECRET_KEY"', style="No Spacing")
doc.add_paragraph("")
doc.add_paragraph(
    "Replace YOUR_ACCESS_KEY and YOUR_SECRET_KEY with your actual Tenable.io API keys. "
    "Keep the quotes around the values."
)

# SLA Rules
doc.add_heading("7. SLA Thresholds", level=1)
table3 = doc.add_table(rows=5, cols=3, style="Light Grid Accent 1")
table3.rows[0].cells[0].text = "Severity"
table3.rows[0].cells[1].text = "SLA Threshold"
table3.rows[0].cells[2].text = "Past SLA if age >"
for cell in table3.rows[0].cells:
    cell.paragraphs[0].runs[0].bold = True
sla_data = [("Critical", "30 days", "30"), ("High", "60 days", "60"),
            ("Medium", "90 days", "90"), ("Low", "180 days", "180")]
for i, (s, t, p) in enumerate(sla_data, 1):
    table3.rows[i].cells[0].text = s
    table3.rows[i].cells[1].text = t
    table3.rows[i].cells[2].text = p

# Dependencies
doc.add_heading("8. Dependencies & Setup", level=1)
doc.add_paragraph("Python 3.10+ required. Install dependencies:")
doc.add_paragraph("pip install plotly pandas openpyxl requests numpy", style="No Spacing")
doc.add_paragraph("")
doc.add_paragraph("To run:")
doc.add_paragraph("python tenable_noc_dashboard.py", style="No Spacing")

# New Device Setup
doc.add_heading("9. New Device Setup", level=1)
steps = [
    "Install Python 3.10+ from python.org (check 'Add to PATH')",
    "git clone https://github.com/mohammedobaidraza/tenable-noc-dashboard.git",
    "cd tenable-noc-dashboard",
    "pip install -r requirements.txt",
    "Edit tenable_noc_dashboard.py - paste your API keys at lines 48-49",
    "mkdir C:\\tenable_tracker\\reports",
    "python tenable_noc_dashboard.py",
    "Open C:\\tenable_tracker\\reports\\dashboard.html in your browser",
]
for i, s in enumerate(steps, 1):
    doc.add_paragraph(f"{i}. {s}")

# Bugs Fixed
doc.add_heading("10. Known Issues & Fixes Applied", level=1)

doc.add_heading("Pandas 3.0 .map() Error:", level=2)
doc.add_paragraph(
    "Error: TypeError: the first argument must be callable\n"
    "Cause: pandas 3.0 changed .map() behavior with dict arguments.\n"
    "Fix: Changed .map(SLA_THRESHOLDS) to .apply(lambda x: SLA_THRESHOLDS.get(str(x), 9999))\n"
    "Affects: load_excel_to_dataframes() and plugins_to_dataframe() functions."
)

doc.add_heading("API Key Variable Style:", level=2)
doc.add_paragraph(
    "User preference: hardcoded accessKey/secretKey at top of script, matching the original "
    "tenable_tracker_reconstructed.py style. Not env vars or runtime prompts."
)

# Git History
doc.add_heading("11. Git Commit History", level=1)
commits = [
    ("feat:", "Tenable vulnerability tracker with interactive NOC dashboard - initial build"),
    ("fix:", "Use hardcoded API key style matching original script"),
    ("fix:", "Use .apply() instead of .map() for pandas 3.0 compatibility"),
]
for tag, msg in commits:
    doc.add_paragraph(f"{tag} {msg}", style="List Number")

# Tower Tags
doc.add_heading("12. Configured Tower Tags", level=1)
towers = [
    "Intel Server", "Linux", "Workstations", "Network", "Database", "CVAN",
    "Exchange", "Middleware", "Internet(Perimeter) Exposed", "VMWare", "GCP", "EOL",
]
for t in towers:
    doc.add_paragraph(t, style="List Bullet")

# Save
output_path = r"C:\Users\Obaid Raza\Desktop\tenable-noc-dashboard\Tenable_NOC_Dashboard_Documentation.docx"
doc.save(output_path)
print(f"Word doc saved: {output_path}")
