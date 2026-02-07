import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import re
from collections import Counter

# Загрузка данных из JSON файла
def load_json_data(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return pd.DataFrame(data['events'])

# Извлечение типа события из signature
def extract_event_type(signature):
    # Извлекаем первое слово до пробела как тип события
    # или используем регулярное выражение для более точного извлечения
    match = re.match(r'^([A-Z]+-?[A-Z]*)', signature)
    if match:
        return match.group(1)
    return "UNKNOWN"

# Основной анализ
def analyze_security_events(filename):
    # Загрузка данных
    df = load_json_data(filename)
    
    print("Первые 5 строк данных:")
    print(df.head())
    print("\n" + "="*50 + "\n")
    
    # Извлечение типов событий
    df['event_type'] = df['signature'].apply(extract_event_type)
    
    # Статистика по типам событий
    event_counts = df['event_type'].value_counts()
    
    print("Распределение типов событий:")
    print(event_counts)
    print("\n" + "="*50 + "\n")
    
    # Более детальный анализ signatures
    print("Примеры signature для каждого типа:")
    for event_type in event_counts.index:
        examples = df[df['event_type'] == event_type]['signature'].head(2).tolist()
        print(f"\n{event_type}:")
        for ex in examples:
            print(f"  - {ex}")
    
    return df, event_counts

# Построение графиков
def plot_event_distribution(event_counts, df):
    # Создаем фигуру с двумя графиками
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # 1. Столбчатая диаграмма
    colors = plt.cm.Set3(range(len(event_counts)))
    bars = ax1.bar(event_counts.index, event_counts.values, color=colors)
    ax1.set_title('Распределение типов событий безопасности', fontsize=14, fontweight='bold')
    ax1.set_xlabel('Тип события', fontsize=12)
    ax1.set_ylabel('Количество событий', fontsize=12)
    ax1.tick_params(axis='x', rotation=45)
    
    # Добавляем значения на столбцы
    for bar in bars:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}',
                ha='center', va='bottom')
    
    # 2. Круговая диаграмма
    wedges, texts, autotexts = ax2.pie(event_counts.values, labels=event_counts.index, autopct='%1.1f%%',
                                      colors=colors, startangle=90)
    ax2.set_title('Доля типов событий', fontsize=14, fontweight='bold')
    
    # Настройка отображения процентов
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontweight('bold')
    
    # 3. Дополнительный график: временная шкала событий (если нужно)
    fig2, ax3 = plt.subplots(figsize=(12, 6))
    
    # Конвертируем timestamp в datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    
    # Группируем по часу и типу события
    hourly_events = df.groupby(['hour', 'event_type']).size().unstack(fill_value=0)
    
    # Линейный график по часам
    hourly_events.plot(ax=ax3, marker='o', linewidth=2)
    ax3.set_title('Распределение событий по часам', fontsize=14, fontweight='bold')
    ax3.set_xlabel('Час дня', fontsize=12)
    ax3.set_ylabel('Количество событий', fontsize=12)
    ax3.grid(True, alpha=0.3)
    ax3.legend(title='Тип события')
    
    # Настройка внешнего вида
    plt.tight_layout()
    
    # Сохраняем графики
    fig.savefig('event_type_distribution.png', dpi=300, bbox_inches='tight')
    fig2.savefig('hourly_event_distribution.png', dpi=300, bbox_inches='tight')
    
    plt.show()
    
    return fig, fig2

# Дополнительный анализ с использованием Seaborn
def seaborn_visualization(df, event_counts):
    # График распределения событий по времени с разделением по типам
    plt.figure(figsize=(12, 6))
    
    # Конвертируем timestamp
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    
    # График распределения по часам
    plt.subplot(1, 2, 1)
    hourly_data = df.groupby(['hour', 'event_type']).size().reset_index(name='count')
    
    # Используем палитру Set2 для лучшей различимости
    palette = sns.color_palette("Set2", len(event_counts))
    
    for i, event_type in enumerate(event_counts.index):
        event_data = hourly_data[hourly_data['event_type'] == event_type]
        sns.lineplot(data=event_data, x='hour', y='count', 
                    label=event_type, marker='o', linewidth=2,
                    color=palette[i])
    
    plt.title('Распределение событий по часам', fontsize=14, fontweight='bold')
    plt.xlabel('Час дня')
    plt.ylabel('Количество событий')
    plt.grid(True, alpha=0.3)
    plt.legend(title='Тип события')
    
    # Boxplot для распределения по часам
    plt.subplot(1, 2, 2)
    sns.boxplot(data=df, x='event_type', y='hour', palette='Set2')
    plt.title('Распределение часов событий по типам', fontsize=14, fontweight='bold')
    plt.xlabel('Тип события')
    plt.ylabel('Час дня')
    plt.xticks(rotation=45)
    
    plt.tight_layout()
    plt.savefig('seaborn_event_analysis.png', dpi=300, bbox_inches='tight')
    plt.show()

# Основная функция
def main():
    # Имя файла
    filename = 'events.json'
    
    try:
        # Анализ данных
        df, event_counts = analyze_security_events(filename)
        
        # Построение графиков с matplotlib
        print("\nСтроим графики распределения...")
        fig1, fig2 = plot_event_distribution(event_counts, df)
        
        # Дополнительная визуализация с seaborn
        print("\nДополнительная визуализация с Seaborn...")
        seaborn_visualization(df, event_counts)
        
        # Сохранение обработанных данных
        df.to_csv('processed_security_events.csv', index=False)
        print("\nОбработанные данные сохранены в 'processed_security_events.csv'")
        
    except FileNotFoundError:
        print(f"Ошибка: Файл '{filename}' не найден!")
    except json.JSONDecodeError:
        print(f"Ошибка: Файл '{filename}' содержит некорректный JSON!")
    except KeyError as e:
        print(f"Ошибка: В данных отсутствует ключ {e}")
    except Exception as e:
        print(f"Произошла ошибка: {str(e)}")

if __name__ == "__main__":
    # Настройка стилей для графиков
    plt.style.use('seaborn-v0_8-darkgrid')
    sns.set_palette("husl")
    
    # Запуск анализа
    main()
