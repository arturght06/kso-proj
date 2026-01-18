import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import io
# import base64 <- Już niepotrzebny tutaj
import os
import tempfile
import numpy as np
from scipy.interpolate import make_interp_spline
from sqlalchemy import func
from models import db, LogEntry, Host
from fpdf import FPDF
from datetime import datetime

def generate_host_chart(host_id, start_date, end_date):
    """
    Generuje wykres i zwraca bufor pliku PNG (BytesIO).
    """
    img = io.BytesIO()
    
    # 1. Znajdź 10 najpopularniejszych kluczy
    top_keys_query = db.session.query(
        LogEntry.details['key_label'].astext, 
        func.count(LogEntry.id)
    ).filter(
        LogEntry.host_id == host_id,
        LogEntry.timestamp >= start_date,
        LogEntry.timestamp <= end_date
    ).group_by(
        LogEntry.details['key_label'].astext
    ).order_by(func.count(LogEntry.id).desc()).limit(10).all()
    
    if not top_keys_query:
        return None

    top_keys = [r[0] for r in top_keys_query]

    # 2. Dane minutowe
    raw_data = db.session.query(
        func.date_trunc('minute', LogEntry.timestamp),
        LogEntry.details['key_label'].astext,
        func.count(LogEntry.id)
    ).filter(
        LogEntry.host_id == host_id,
        LogEntry.details['key_label'].astext.in_(top_keys),
        LogEntry.timestamp >= start_date,
        LogEntry.timestamp <= end_date
    ).group_by(
        func.date_trunc('minute', LogEntry.timestamp),
        LogEntry.details['key_label'].astext
    ).order_by(func.date_trunc('minute', LogEntry.timestamp)).all()

    # 3. Przetwarzanie
    data_map = {key: {'x': [], 'y': []} for key in top_keys}
    for row in raw_data:
        timestamp, key, count = row
        if key in data_map:
            data_map[key]['x'].append(timestamp)
            data_map[key]['y'].append(count)

    # 4. Rysowanie
    plt.figure(figsize=(12, 4))
    
    for key in top_keys:
        x_dates = data_map[key]['x']
        y_vals = data_map[key]['y']

        if len(x_dates) > 3:
            try:
                x_nums = mdates.date2num(x_dates)
                x_np = np.array(x_nums)
                y_np = np.array(y_vals)
                x_new = np.linspace(x_np.min(), x_np.max(), 300) 
                spl = make_interp_spline(x_np, y_np, k=3)
                y_smooth = spl(x_new).clip(min=0)
                plt.plot(mdates.num2date(x_new), y_smooth, label=key, linewidth=2, alpha=0.8)
            except:
                plt.plot(x_dates, y_vals, label=key, marker='.', linestyle='-')
        elif len(x_dates) > 0:
            plt.plot(x_dates, y_vals, label=key, marker='o', linestyle='-')

    plt.title(f'Event Trend - {start_date.strftime("%Y-%m-%d %H:%M")} to {end_date.strftime("%Y-%m-%d %H:%M")}')
    plt.xlabel('Time')
    plt.ylabel('Events/Min')
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
    plt.gcf().autofmt_xdate()
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(bbox_to_anchor=(1.01, 1), loc='upper left', borderaxespad=0.)
    plt.tight_layout()
    
    plt.savefig(img, format='png', dpi=100)
    plt.close()
    img.seek(0)
    
    # ZMIANA: Zwracamy czysty obiekt BytesIO, a nie base64 string
    return img

def generate_pdf_report(host_id, date_from, date_to):
    host = Host.query.get(host_id)
    if not host:
        return None, None

    # Pobieramy bufor obrazka (teraz to BytesIO)
    chart_buffer = generate_host_chart(host_id, date_from, date_to)

    logs = LogEntry.query.filter_by(host_id=host_id)\
        .filter(LogEntry.timestamp >= date_from, LogEntry.timestamp <= date_to)\
        .order_by(LogEntry.timestamp.desc()).limit(100).all()

    pdf = FPDF()
    pdf.add_page()
    
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, f"Security Audit Report: {host.hostname}", ln=True, align='C')
    
    pdf.set_font("Arial", size=10)
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M')
    pdf.cell(0, 10, f"Host IP: {host.ip_address} | Generated: {now_str}", ln=True, align='C')
    pdf.cell(0, 10, f"Period: {date_from.strftime('%Y-%m-%d %H:%M')} to {date_to.strftime('%Y-%m-%d %H:%M')}", ln=True, align='C')
    pdf.ln(10)

    # ZMIANA: Zapisujemy bajty bezpośrednio z bufora
    if chart_buffer:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp_file:
            # chart_buffer to BytesIO, pobieramy jego zawartość getvalue()
            tmp_file.write(chart_buffer.getvalue())
            tmp_path = tmp_file.name
        
        try:
            pdf.image(tmp_path, x=10, w=190)
        finally:
            os.unlink(tmp_path)
        pdf.ln(10)

    # (Reszta kodu tabeli bez zmian)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "Event Log (Last 100 entries)", ln=True)
    
    pdf.set_font("Arial", 'B', 10)
    pdf.set_fill_color(220, 220, 220)
    pdf.cell(35, 7, "Time", 1, 0, 'C', True)
    pdf.cell(25, 7, "Severity", 1, 0, 'C', True)
    pdf.cell(35, 7, "Program", 1, 0, 'C', True)
    pdf.cell(95, 7, "Message Preview", 1, 1, 'C', True)

    pdf.set_font("Arial", size=8)
    for log in logs:
        safe_msg = log.message.encode('latin-1', 'replace').decode('latin-1')[:55] + "..."
        safe_prog = log.program.encode('latin-1', 'replace').decode('latin-1')
        
        if log.severity.value == 'critical':
            pdf.set_text_color(192, 57, 43)
        elif log.severity.value == 'warning':
            pdf.set_text_color(211, 84, 0)
        else:
            pdf.set_text_color(0, 0, 0)

        pdf.cell(35, 7, str(log.timestamp.strftime('%Y-%m-%d %H:%M')), 1)
        pdf.cell(25, 7, log.severity.value.upper(), 1, 0, 'C')
        pdf.cell(35, 7, safe_prog, 1)
        pdf.cell(95, 7, safe_msg, 1, 1)

    buffer = io.BytesIO()
    pdf_bytes = pdf.output(dest='S').encode('latin-1')
    buffer.write(pdf_bytes)
    buffer.seek(0)

    s_str = date_from.strftime('%m-%d')
    e_str = date_to.strftime('%m-%d')
    filename = f"report_{host.hostname}_{s_str}_{e_str}.pdf"

    return buffer, filename