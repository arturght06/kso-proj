import matplotlib
matplotlib.use('Agg') # Backend bez GUI (wymagane dla serwera)
import matplotlib.pyplot as plt
import io
import base64
from sqlalchemy import func
from models import db, LogEntry

def generate_host_chart(host_id, start_date, end_date):
    """
    Generuje wykres liniowy logów w formacie Base64.
    Oś X: Czas (agregacja godzinowa), Oś Y: Liczba logów.
    Serie: Top 10 kluczy (reguł auditd).
    """
    img = io.BytesIO()
    
    # Ponieważ funkcja jest wywoływana wewnątrz route'a Flask,
    # mamy dostęp do aktywnego kontekstu aplikacji i bazy danych (db.session).
    
    # 1. Znajdź 10 najpopularniejszych kluczy w zadanym okresie
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

    # 2. Pobierz dane szeregów czasowych (agregacja co godzinę)
    raw_data = db.session.query(
        func.date_trunc('hour', LogEntry.timestamp),
        LogEntry.details['key_label'].astext,
        func.count(LogEntry.id)
    ).filter(
        LogEntry.host_id == host_id,
        LogEntry.details['key_label'].astext.in_(top_keys),
        LogEntry.timestamp >= start_date,
        LogEntry.timestamp <= end_date
    ).group_by(
        func.date_trunc('hour', LogEntry.timestamp),
        LogEntry.details['key_label'].astext
    ).order_by(func.date_trunc('hour', LogEntry.timestamp)).all()

    # 3. Przetwarzanie danych dla Matplotlib
    data_map = {key: {'x': [], 'y': []} for key in top_keys}
    
    for row in raw_data:
        timestamp, key, count = row
        if key in data_map:
            data_map[key]['x'].append(timestamp)
            data_map[key]['y'].append(count)

    # 4. Rysowanie Wykresu
    plt.figure(figsize=(10, 3)) # Szeroki, niski wykres
    
    for key in top_keys:
        if data_map[key]['x']:
            plt.plot(data_map[key]['x'], data_map[key]['y'], marker='.', label=key)

    # Formatowanie daty w tytule
    title_date_fmt = "%Y-%m-%d"
    plt.title(f'Log Trends (Top 10 Rules) - {start_date.strftime(title_date_fmt)} to {end_date.strftime(title_date_fmt)}')
    plt.xlabel('Time (Hourly aggregation)')
    plt.ylabel('Event Count')
    plt.grid(True, linestyle='--', alpha=0.5)
    
    # Legenda poza wykresem
    plt.legend(bbox_to_anchor=(1.01, 1), loc='upper left', borderaxespad=0.)
    plt.tight_layout()
    
    # Zapis do bufora pamięci
    plt.savefig(img, format='png')
    plt.close()
    img.seek(0)
    
    return base64.b64encode(img.getvalue()).decode('utf8')
