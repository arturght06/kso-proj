import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import io
import base64
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

    data_map = {key: {'x': [], 'y': []} for key in top_keys}
    for row in raw_data:
        timestamp, key, count = row
        if key in data_map:
            data_map[key]['x'].append(timestamp)
            data_map[key]['y'].append(count)

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
    
    img.seek(0)
    plt.savefig(img, format='png', dpi=100)
    plt.close()
    img.seek(0)
    
    return img

def generate_pdf_report(host_id, date_from, date_to):
    host = Host.query.get(host_id)
    if not host:
        return None, None

    # 1. Wykres
    chart_buffer = generate_host_chart(host_id, date_from, date_to)

    # 2. Logi
    logs = LogEntry.query.filter_by(host_id=host_id)\
        .filter(LogEntry.timestamp >= date_from, LogEntry.timestamp <= date_to)\
        .order_by(LogEntry.timestamp.desc()).all()

    # 3. Inicjalizacja PDF
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Nagłówek
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, f"Security Audit Report: {host.hostname}", ln=True, align='C')
    
    pdf.set_font("Arial", size=10)
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M')
    pdf.cell(0, 10, f"Host IP: {host.ip_address} | Generated: {now_str}", ln=True, align='C')
    pdf.cell(0, 10, f"Period: {date_from.strftime('%Y-%m-%d %H:%M')} to {date_to.strftime('%Y-%m-%d %H:%M')}", ln=True, align='C')
    pdf.cell(0, 10, f"Total Events: {len(logs)}", ln=True, align='C')
    pdf.ln(5)

    # Wstawianie obrazka
    if chart_buffer:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp_file:
            tmp_file.write(chart_buffer.getvalue())
            tmp_path = tmp_file.name
        
        try:
            if pdf.get_y() + 60 > 270:
                pdf.add_page()
            pdf.image(tmp_path, x=10, w=190)
        finally:
            os.unlink(tmp_path)
        pdf.ln(5)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "Event Log Detail", ln=True)
    pdf.ln(2)

    # --- NOWY UKŁAD TABELI (Stacked Layout) ---
    
    # Szerokości kolumn dla nagłówka wpisu (Suma: 190)
    w_time = 35
    w_sev = 25
    w_key = 40
    w_user = 90  # Dużo miejsca na ścieżkę do pliku/usera

    for log in logs:
        # Przygotowanie danych
        timestamp = log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        details = log.details or {}
        key_label = details.get('key_label', '-')
        
        exe = details.get('executable', '')
        uid = details.get('uid', '')
        user_str = exe
        if uid:
            user_str += f" (UID: {uid})"
        if not user_str:
            user_str = "-"

        severity = log.severity.value.upper()
        
        # Wiadomość (Sanityzacja latin-1)
        raw_msg = log.message or ""
        safe_msg = raw_msg.encode('latin-1', 'replace').decode('latin-1')
        safe_user = user_str.encode('latin-1', 'replace').decode('latin-1')
        
        # Sprawdź miejsce na stronie (potrzebujemy ok 20mm na wpis)
        if pdf.get_y() > 260:
            pdf.add_page()

        # --- WIERSZ 1: METADANE (Szare tło) ---
        pdf.set_font("Arial", 'B', 8)
        pdf.set_fill_color(240, 240, 240) # Jasnoszary
        pdf.set_text_color(0, 0, 0)
        
        # Kolorowanie Severity (tylko tekst Severity)
        if severity == 'CRITICAL':
            pdf.set_text_color(192, 57, 43)
        elif severity == 'WARNING':
            pdf.set_text_color(211, 84, 0)

        # Rysujemy nagłówek wpisu
        # Save X,Y
        x_start = pdf.get_x()
        y_start = pdf.get_y()
        
        # Time
        pdf.set_text_color(0, 0, 0)
        pdf.cell(w_time, 6, timestamp, 1, 0, 'C', True)
        
        # Severity
        if severity == 'CRITICAL': pdf.set_text_color(192, 57, 43)
        elif severity == 'WARNING': pdf.set_text_color(211, 84, 0)
        pdf.cell(w_sev, 6, severity, 1, 0, 'C', True)
        pdf.set_text_color(0, 0, 0) # Reset
        
        # Key
        pdf.cell(w_key, 6, f"Key: {key_label}", 1, 0, 'L', True)
        
        # User/Exe (Przycinamy jeśli za długie w nagłówku)
        pdf.cell(w_user, 6, f"Exe: {safe_user[:60]}", 1, 1, 'L', True) # 1 na końcu = nowa linia

        # --- WIERSZ 2: PEŁNA WIADOMOŚĆ (Białe tło, Courier) ---
        pdf.set_font("Courier", '', 7) # Czcionka monospaced dla czytelności logów
        # MultiCell na całą szerokość (190)
        pdf.multi_cell(190, 4, safe_msg, border='LBR', align='L', fill=False)
        
        # Odstęp między wpisami
        pdf.ln(1)

    buffer = io.BytesIO()
    pdf_bytes = pdf.output(dest='S').encode('latin-1')
    buffer.write(pdf_bytes)
    buffer.seek(0)

    s_str = date_from.strftime('%m-%d')
    e_str = date_to.strftime('%m-%d')
    filename = f"full_report_{host.hostname}_{s_str}_{e_str}.pdf"

    return buffer, filename