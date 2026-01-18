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
    """
    Tworzy kompletny raport PDF (wykres + PEŁNA TABELA LOGÓW).
    """
    host = Host.query.get(host_id)
    if not host:
        return None, None

    # 1. Wykres
    chart_buffer = generate_host_chart(host_id, date_from, date_to)

    # 2. Logi - USUWAMY LIMIT(100)
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
            # Sprawdź czy obrazek zmieści się na stronie, jeśli nie - nowa strona
            if pdf.get_y() + 60 > 270:
                pdf.add_page()
            pdf.image(tmp_path, x=10, w=190)
        finally:
            os.unlink(tmp_path)
        pdf.ln(5)

    # Tytuł sekcji
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "Event Logs (Full Detail)", ln=True)
    
    # --- KONFIGURACJA TABELI ---
    # Szerokości kolumn (Suma: 190)
    # Time(30) | Key(30) | User(35) | Severity(20) | Message(75)
    w_time = 30
    w_key = 30
    w_user = 35
    w_sev = 20
    w_msg = 75
    line_height = 5

    # Nagłówki
    pdf.set_font("Arial", 'B', 9)
    pdf.set_fill_color(220, 220, 220)
    
    pdf.cell(w_time, 7, "Time", 1, 0, 'C', True)
    pdf.cell(w_key, 7, "Event Key", 1, 0, 'C', True)
    pdf.cell(w_user, 7, "Executable/User", 1, 0, 'C', True)
    pdf.cell(w_sev, 7, "Severity", 1, 0, 'C', True)
    pdf.cell(w_msg, 7, "Full Message", 1, 1, 'C', True)

    # Wiersze
    pdf.set_font("Arial", size=7) # Mniejsza czcionka, żeby więcej się zmieściło

    for log in logs:
        # Przygotowanie danych
        timestamp = log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        
        details = log.details or {}
        key_label = details.get('key_label', '-')
        
        # Formatowanie User/Exe
        exe = details.get('executable', '')
        uid = details.get('uid', '')
        user_str = exe
        if uid:
            user_str += f"\n(UID: {uid})"
        if not user_str:
            user_str = "-"

        severity = log.severity.value.upper()
        
        # Sanityzacja wiadomości (usuwanie polskich znaków/emoji bo FPDF ma z tym problem)
        # Wymuszamy zawijanie długich linii
        raw_msg = log.message or ""
        safe_msg = raw_msg.encode('latin-1', 'replace').decode('latin-1')
        safe_user = user_str.encode('latin-1', 'replace').decode('latin-1')
        
        # Kolory severity
        if severity == 'CRITICAL':
            pdf.set_text_color(192, 57, 43)
        elif severity == 'WARNING':
            pdf.set_text_color(211, 84, 0)
        else:
            pdf.set_text_color(0, 0, 0)

        # --- LOGIKA DYNAMICZNEJ WYSOKOŚCI WIERSZA ---
        # 1. Zapisz pozycję startową
        x_start = pdf.get_x()
        y_start = pdf.get_y()

        # 2. Symuluj wypisanie najdłuższej treści (Message) żeby poznać wysokość
        # FPDF MultiCell zwraca liczbę linii? Nie, przesuwa kursor.
        # Użyjemy sztuczki: Przesuwamy kursor w prawo, piszemy MultiCell, sprawdzamy nowe Y.
        
        # Sprawdź czy nie kończy się strona. Jeśli mało miejsca, dodaj nową.
        # Szacujemy, że jeden wpis to min. 10mm.
        if y_start > 270: 
            pdf.add_page()
            y_start = pdf.get_y() # Reset Y po nowej stronie
        
        # Ustaw X na kolumnę Message
        pdf.set_xy(x_start + w_time + w_key + w_user + w_sev, y_start)
        
        # Wypisz Message (MultiCell zrobi auto-wrap)
        pdf.multi_cell(w_msg, line_height, safe_msg, border=1, align='L')
        
        # Gdzie skończył się kursor?
        y_end = pdf.get_y()
        row_height = y_end - y_start
        
        # --- RYSOWANIE POZOSTAŁYCH KOLUMN O TEJ SAMEJ WYSOKOŚCI ---
        # Wracamy na początek wiersza
        pdf.set_xy(x_start, y_start)
        
        # Time
        pdf.cell(w_time, row_height, timestamp, 1, 0, 'C')
        
        # Key
        pdf.cell(w_key, row_height, key_label, 1, 0, 'C')
        
        # User (MultiCell bo może mieć dwie linie: exe + uid)
        # Zapisz X, Y przed userem
        curr_x = pdf.get_x()
        curr_y = pdf.get_y()
        pdf.multi_cell(w_user, line_height, safe_user, border=1, align='C')
        # Ponieważ użyliśmy MultiCell dla usera, kursor spadł w dół.
        # Musimy "cofnąć" Y do góry, ale ustawić X po prawej stronie usera dla następnej komórki
        pdf.set_xy(curr_x + w_user, curr_y) 
        
        # Severity
        pdf.cell(w_sev, row_height, severity, 1, 0, 'C')
        
        # Przesuwamy kursor na dół wiersza dla następnej iteracji
        pdf.set_y(y_end)
        
        # Reset koloru na czarny dla linii
        pdf.set_text_color(0, 0, 0)

    # Zapis
    buffer = io.BytesIO()
    pdf_bytes = pdf.output(dest='S').encode('latin-1')
    buffer.write(pdf_bytes)
    buffer.seek(0)

    s_str = date_from.strftime('%m-%d')
    e_str = date_to.strftime('%m-%d')
    filename = f"full_report_{host.hostname}_{s_str}_{e_str}.pdf"

    return buffer, filename