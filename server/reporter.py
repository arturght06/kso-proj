import matplotlib
matplotlib.use('Agg') # Backend bez GUI
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import io
import base64
import numpy as np
from scipy.interpolate import make_interp_spline
from sqlalchemy import func
from models import db, LogEntry
from datetime import datetime

def generate_host_chart(host_id, start_date, end_date):
    """
    Generuje wykres typu 'Spline' (gładka krzywa) w formacie Base64.
    Agregacja: Minutowa (dla większej dokładności).
    """
    img = io.BytesIO()
    
    # 1. Znajdź 10 najpopularniejszych kluczy (bez zmian)
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

    # 2. Pobierz dane agregowane co MINUTĘ (zwiększenie liczby punktów)
    # Zmieniono 'hour' na 'minute' w date_trunc
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

    # 3. Organizacja danych
    data_map = {key: {'x': [], 'y': []} for key in top_keys}
    
    for row in raw_data:
        timestamp, key, count = row
        if key in data_map:
            data_map[key]['x'].append(timestamp)
            data_map[key]['y'].append(count)

    # 4. Rysowanie (Stylizacja Curve)
    plt.figure(figsize=(12, 4)) # Nieco szerszy
    
    for key in top_keys:
        x_dates = data_map[key]['x']
        y_vals = data_map[key]['y']

        if len(x_dates) > 3:
            # --- ALGORYTM WYGŁADZANIA (CURVE) ---
            
            # 1. Konwersja dat na liczby (dla matematyki)
            x_nums = mdates.date2num(x_dates)
            x_np = np.array(x_nums)
            y_np = np.array(y_vals)

            # 2. Tworzenie gęstej siatki punktów (300 punktów dla gładkości)
            x_new = np.linspace(x_np.min(), x_np.max(), 300) 
            
            try:
                # 3. Interpolacja B-Spline (k=3 to sześcienna, gładka)
                spl = make_interp_spline(x_np, y_np, k=3)
                y_smooth = spl(x_new)

                # 4. Zapobieganie wartościom ujemnym (efekt uboczny spline'ów)
                y_smooth = y_smooth.clip(min=0)

                # Rysowanie gładkiej linii
                plt.plot(mdates.num2date(x_new), y_smooth, label=key, linewidth=2, alpha=0.8)
            except Exception as e:
                # Fallback: jeśli matematyka zawiedzie (np. zduplikowane x), rysuj zwykłą linię
                print(f"Spline error for {key}: {e}")
                plt.plot(x_dates, y_vals, label=key, marker='.', linestyle='-')
        
        elif len(x_dates) > 0:
            # Za mało punktów na krzywą -> rysuj prostą linię
            plt.plot(x_dates, y_vals, label=key, marker='o', linestyle='-')

    # Formatowanie wykresu
    title_date_fmt = "%Y-%m-%d %H:%M"
    plt.title(f'Event Trend (Minute Precision) - {start_date.strftime(title_date_fmt)} to {end_date.strftime(title_date_fmt)}')
    plt.xlabel('Time')
    plt.ylabel('Events per Minute')
    
    # Formatowanie osi X (żeby daty się nie nakładały)
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
    plt.gcf().autofmt_xdate()
    
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.legend(bbox_to_anchor=(1.01, 1), loc='upper left', borderaxespad=0.)
    plt.tight_layout()
    
    img = io.BytesIO()
    plt.savefig(img, format='png', dpi=100) # dpi=100 dla lepszej jakości
    plt.close()
    img.seek(0)
    
    return base64.b64encode(img.getvalue()).decode('utf8')