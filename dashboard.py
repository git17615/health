import pandas as pd
import matplotlib.pyplot as plt
import time
import os
from datetime import datetime

# File paths
HEALTH_LOG = 'health_log.csv'

def render_graphs():
    if not os.path.exists(HEALTH_LOG):
        print("Waiting for health_log.csv to populate...")
        return
        
    try:
        # Load health data dynamically using pandas mapping structures
        df = pd.read_csv(HEALTH_LOG, skipinitialspace=True)
        
        if df.empty or 'timestamp' not in df.columns or 'client_id' not in df.columns:
            return
            
        # Convert unix timestamp to datetime for cleanly tracked plotting points
        df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
        
        # 1. Generate CPU Usage Image
        plt.figure(figsize=(10, 6))
        for client in df['client_id'].unique():
            client_data = df[df['client_id'] == client].tail(50)
            plt.plot(client_data['datetime'], client_data['cpu_usage'], label=client, marker='o', markersize=3)
        plt.title('CPU Usage per Client')
        plt.ylabel('CPU (%)')
        plt.ylim(0, 100)
        plt.xticks(rotation=45)
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.legend(loc='upper right')
        plt.tight_layout()
        plt.savefig('cpu_usage.png', dpi=100)
        plt.close()
        
        # 2. Generate RAM Usage Image
        plt.figure(figsize=(10, 6))
        for client in df['client_id'].unique():
            client_data = df[df['client_id'] == client].tail(50)
            plt.plot(client_data['datetime'], client_data['ram_usage'], label=client, marker='o', markersize=3)
        plt.title('RAM Usage per Client')
        plt.ylabel('RAM (%)')
        plt.ylim(0, 100)
        plt.xticks(rotation=45)
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.legend(loc='upper right')
        plt.tight_layout()
        plt.savefig('ram_usage.png', dpi=100)
        plt.close()
        
        # 3. Generate Disk Usage Image
        if 'disk_usage' in df.columns:
            plt.figure(figsize=(10, 6))
            for client in df['client_id'].unique():
                client_data = df[df['client_id'] == client].tail(50)
                plt.plot(client_data['datetime'], client_data['disk_usage'], label=client, marker='o', markersize=3)
            plt.title('Disk Usage per Client')
            plt.ylabel('Disk (%)')
            plt.ylim(0, 100)
            plt.xticks(rotation=45)
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.legend(loc='upper right')
            plt.tight_layout()
            plt.savefig('disk_usage.png', dpi=100)
            plt.close()
            
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Saved updated cpu_usage.png, ram_usage.png, and disk_usage.png to disk")
            
    except pd.errors.EmptyDataError:
        pass
    except Exception as e:
        print(f"Error rendering graphs via Pandas: {e}")

if __name__ == "__main__":
    print("Starting Headless DTLS Dashboard Plotter...")
    
    # Use headless 'Agg' backend to avoid UI popup dependencies since we only export graphic files natively
    plt.switch_backend('Agg')
    
    while True:
        render_graphs()
        time.sleep(5)
