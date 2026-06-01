# Tenable Vulnerability Tracker - NOC Dashboard

Interactive vulnerability operations center dashboard that fetches data from Tenable.io and generates standalone HTML reports with a dark NOC/control room theme.

## Features

- **NOC-Style Dark Theme** - Deep navy background, glowing cyan accents, monospace data displays
- **Interactive Charts** - Powered by Plotly.js with hover tooltips, zoom, pan, and export
- **Switchable Chart Types** - Toggle between Pie, Bar, and Histogram views
- **Per-Tower Dashboards** - Each tower/tag gets its own tab with full analytics
- **SLA Aging Analysis** - 6-week trend tracking with aging buckets (0-30, 31-60, 61-90, 91-120, 120+ days)
- **Vulnerability Treemap** - Interactive map: Tower > Severity > Plugin Family
- **Fluctuation Heatmap** - Week-over-week change % across all towers
- **Sortable & Searchable Tables** - Click column headers to sort, search box to filter
- **All 4 Severity Levels** - Critical, High, Medium, Low (fetched automatically)

## Output Files

| File | Description |
|------|-------------|
| `dashboard.html` | Main NOC overview with per-tower tabs |
| `critical.html` | Critical vulnerabilities breakdown |
| `high.html` | High vulnerabilities breakdown |
| `medium.html` | Medium vulnerabilities breakdown |
| `low.html` | Low vulnerabilities breakdown |
| `consolidated.html` | All severities combined |

## Requirements

```bash
pip install plotly pandas openpyxl requests
```

## Usage

### Option 1: Interactive (paste keys when prompted)
```bash
python tenable_noc_dashboard.py
```

### Option 2: Environment variables
```bash
set TENABLE_ACCESS_KEY=your_access_key
set TENABLE_SECRET_KEY=your_secret_key
python tenable_noc_dashboard.py
```

## Configuration

Edit the top of `tenable_noc_dashboard.py` to customize:

- `EXCEL_PATH` - Where the Excel tracker is saved (default: `C:\tenable_tracker\...`)
- `REPORT_DIR` - Where HTML reports are generated (default: `C:\tenable_tracker\reports\`)
- `TAGS` - Tower/tag list to fetch from Tenable
- `SLA_THRESHOLDS` - SLA days per severity (Critical: 30, High: 60, Medium: 90, Low: 180)
- `NUM_OF_DAYS` - Lookback window for API fetch (default: 7)

## SLA Rules

| Severity | SLA Threshold | Past SLA if age exceeds |
|----------|--------------|------------------------|
| Critical | 30 days | 30 |
| High | 60 days | 60 |
| Medium | 90 days | 90 |
| Low | 180 days | 180 |

## Weekly Trending

Run the script weekly. Each run adds a "Host Total MM/DD/YY" column to the Excel tracker. The dashboard reads the last 6 weeks of data to generate:

- Weekly trend line charts
- Fluctuation heatmaps (% change per tower per week)
- SLA compliance trends

## Screenshots

Open `dashboard.html` in any modern browser to see the full NOC dashboard with interactive charts, tower tabs, and vulnerability details.
