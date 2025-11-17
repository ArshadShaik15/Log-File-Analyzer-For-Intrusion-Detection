import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np


def create_dataframes():
    # Temporal data (Timestamp, requests_per_minute)
    # Data is pre-sorted chronologically to ensure X-axis displays times in order
    temporal_data = [
        ('2016-12-22 15:19:00', 2908), ('2016-12-22 15:20:00', 2659),
        ('2016-12-22 15:21:00', 1416), ('2016-12-22 16:18:00', 349),
        ('2016-12-22 16:20:00', 372),  ('2016-12-22 16:21:00', 363),
        ('2016-12-22 16:22:00', 363),  ('2016-12-22 16:26:00', 410),
        ('2016-12-22 16:27:00', 399),  ('2016-12-22 16:28:00', 414)

    ]

    df_temporal = pd.DataFrame(temporal_data, columns=['Timestamp', 'requests_per_minute'])
    # Parse 'Timestamp' as datetime
    df_temporal['Timestamp'] = pd.to_datetime(df_temporal['Timestamp'], format='%Y-%m-%d %H:%M:%S', errors='coerce')
    # Sort chronologically to ensure proper X-axis display
    df_temporal = df_temporal.sort_values('Timestamp').reset_index(drop=True)

    # Attribution (categorical) data
    # Column order: Threat_Type, IP_4_164_Count, IP_4_25_Count
    attribution_data = [
        ("Brute Force", 2620, 979),
        ("SQLi", 165, 44),
        ("XSS", 136, 29),
    ]

    df_attribution = pd.DataFrame(attribution_data, columns=['Threat_Type', 'IP_4_164_Count', 'IP_4_25_Count'])

    return df_temporal, df_attribution


def plot_threat_visualization(df_temporal, df_attribution, outfile='Threat_Visualization_Validated.png'):
    # Figure and two vertically stacked subplots
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10))

    # --- Subplot 1: Temporal Line Plot ---
    ax1.plot(
        df_temporal['Timestamp'],
        df_temporal['requests_per_minute'],
        marker='o',
        color='blue'
    )

    ax1.set_title('Temporal Analysis of DoS/DDoS Traffic (Requests Per Minute)')
    ax1.set_xlabel('Timestamp (HH:MM:SS)')
    ax1.set_ylabel('Requests Per Minute (RPM)')
    ax1.grid(True, linestyle='--', alpha=0.6)

    # Format x-axis tick labels to show only time
    h_fmt = mdates.DateFormatter('%H:%M:%S')
    ax1.xaxis.set_major_formatter(h_fmt)
    fig.autofmt_xdate(rotation=45)

    # --- Subplot 2: Grouped Bar Chart ---
    cats = df_attribution['Threat_Type'].tolist()
    x = np.arange(len(cats))
    w = 0.35

    bars_primary = ax2.bar(
        x - w/2,
        df_attribution['IP_4_164_Count'],
        width=w,
        label='192.168.4.164 (Primary Threat)',
        color='#DC143C'
    )

    bars_secondary = ax2.bar(
        x + w/2,
        df_attribution['IP_4_25_Count'],
        width=w,
        label='192.168.4.25 (Secondary Threat)',
        color='#FFA500'
    )

    ax2.set_title('Comparative Attacker Contribution by Threat Category')
    ax2.set_ylabel('Total Attack Count')
    ax2.set_xticks(x)
    ax2.set_xticklabels(cats)

    # Annotation: place the exact count above each bar
    for bar in list(bars_primary) + list(bars_secondary):
        height = bar.get_height()
        ax2.annotate(
            f'{int(height)}',
            xy=(bar.get_x() + bar.get_width() / 2, height),
            xytext=(0, 3),  # 3 points vertical offset
            textcoords='offset points',
            ha='center',
            va='bottom'
        )

    ax2.legend()

    plt.tight_layout()
    # Save high-resolution image
    plt.savefig(outfile, dpi=300)
    print(f"Saved figure to: {outfile}")
    plt.show()


def main():
    df_temporal, df_attribution = create_dataframes()
    plot_threat_visualization(df_temporal, df_attribution, outfile='Threat_Visualization_Validated.png')


if __name__ == '__main__':
    main()
