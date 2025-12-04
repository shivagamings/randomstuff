#!/usr/bin/env python3
import psutil
import time
import logging
from datetime import datetime
import sys
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/var/log/taskmonitord.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

REFRESH_INTERVAL = 10.0

def monitor_system():
    """Main monitoring loop"""
    high_cpu_threshold = 90.0
    
    while True:
        try:
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            
            logging.info(f"SYSTEM: CPU={cpu:.1f}% MEM={mem.percent:.1f}% "
                        f"({mem.used/(1024**3):.1f}/{mem.total/(1024**3):.1f}GiB)")
            
            procs = []
            for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                try:
                    procs.append(p)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            for p in procs:
                try:
                    p.cpu_percent(interval=None)
                except:
                    pass
            
            time.sleep(0.3)
            
            top_procs = []
            for p in procs:
                try:
                    cpu_p = p.cpu_percent(interval=None)
                    if cpu_p > 0:
                        top_procs.append((p.pid, p.name()[:30], cpu_p, p.memory_info().rss/(1024**2)))
                except:
                    continue
            
            top_procs.sort(key=lambda x: x[2], reverse=True)
            
            for pid, name, cpu, mem in top_procs[:5]:
                logging.info(f" TOP: PID={pid} {name:<30} CPU={cpu:.1f}% MEM={mem:.1f}MB")
                
                if cpu > high_cpu_threshold:
                    logging.warning(f"🚨 HIGH CPU ALERT: {name} (PID {pid}) using {cpu:.1f}% CPU!")
            
            logging.info(f"{'='*80}")
            
        except Exception as e:
            logging.error(f"Monitor error: {e}")
        
        time.sleep(REFRESH_INTERVAL)

if __name__ == "__main__":
    logging.info("🚀 Task Monitor Service Started")
    monitor_system()
