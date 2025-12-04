import psutil
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import datetime
import os
import signal
import csv
import platform
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

try:
    import notify2
    notify2.init("Python Task Manager")
    def notify(title, message):
        n = notify2.Notification(title, message)
        n.show()
except ImportError:
    def notify(title, message):
        print(f"NOTIFICATION: {title} - {message}")

try:
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False
    def notify_tray(title, message):
        pass

REFRESH_INTERVAL = 5

class TaskManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Task Manager Ultimate")
        self.root.geometry("1400x800")
        self.dark_mode = False
        
        # Style setup
        self.style = ttk.Style()
        self.setup_styles()
        
        # Data storage
        self.process_data = []
        self.net_connections = []
        self.cpu_history = np.zeros(60)
        self.mem_history = np.zeros(60)
        self.disk_history = np.zeros(60)
        self.net_sent_history = np.zeros(60)
        self.net_recv_history = np.zeros(60)
        self.history_index = 0
        
        self.sort_column = "cpu"
        self.sort_reverse = True
        self.alert_cpu_threshold = 90
        self.alert_mem_threshold = 80
        self.last_alert = {}
        self.logging_enabled = False
        self.scheduled_log_file = None
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.init_process_tab()
        self.init_perf_tab()
        self.init_network_tab()
        
        self.refresh_thread = threading.Thread(target=self.background_refresh, daemon=True)
        self.refresh_thread.start()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_styles(self):
        """Initialize base styles"""
        self.style.theme_use('clam')
    
    def init_process_tab(self):
        self.process_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.process_frame, text="Processes")
        
        frame = ttk.Frame(self.process_frame)
        frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.cpu_label = ttk.Label(frame, text="CPU: -- %")
        self.cpu_label.pack(side=tk.LEFT, padx=5)
        self.mem_label = ttk.Label(frame, text="Memory: -- %")
        self.mem_label.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(frame, text="Filter:").pack(side=tk.LEFT, padx=(10,0))
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(frame, textvariable=self.filter_var, width=20)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        self.filter_entry.bind("<KeyRelease>", lambda e: self.refresh_processes())
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Refresh Now", command=self.refresh_processes).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Import CSV", command=self.import_csv).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Toggle Dark Mode", command=self.toggle_dark_mode).pack(side=tk.LEFT, padx=2)
        
        # Process tree with all columns
        columns = ("pid","name","status","cpu","mem_mb","mem_pct","start","parent","threads","affinity")
        self.tree = ttk.Treeview(self.process_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        for col in columns:
            self.tree.heading(col, text=col.upper(), command=lambda c=col: self.change_sort(c))
            self.tree.column(col, width=90 if col not in ['name','status'] else 200,
                           anchor=tk.CENTER if col in ['pid','cpu','mem_mb','mem_pct','threads','affinity'] else tk.W)
        
        vsb = ttk.Scrollbar(self.process_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        action_frame = ttk.Frame(self.process_frame)
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(action_frame, text="Kill Selected", command=self.kill_selected_process).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="Lower Priority", command=self.lower_priority).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="Details", command=self.show_details).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="Show Tree View", command=self.show_process_tree).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="Start Logging", command=self.start_logging).pack(side=tk.LEFT, padx=2)
        ttk.Button(action_frame, text="Stop Logging", command=self.stop_logging).pack(side=tk.LEFT, padx=2)
        
        self.status_label = ttk.Label(self.process_frame, text="", foreground="gray")
        self.status_label.pack(side=tk.RIGHT, padx=10)
    
    def init_perf_tab(self):
        self.perf_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.perf_frame, text="Performance")
        
        self.fig = Figure(figsize=(12, 8), dpi=100, facecolor='white')
        self.ax1 = self.fig.add_subplot(221)
        self.ax1.set_title("CPU Usage (%)", fontsize=12, fontweight='bold')
        self.ax1.set_ylim(0, 100)
        self.ax1.set_xlim(0, 60)
        self.line_cpu, = self.ax1.plot([], [], 'r-', linewidth=2.5, label='CPU')
        self.ax1.grid(True, alpha=0.3)
        self.ax1.legend()
        
        self.ax2 = self.fig.add_subplot(222)
        self.ax2.set_title("Memory Usage (%)", fontsize=12, fontweight='bold')
        self.ax2.set_ylim(0, 100)
        self.ax2.set_xlim(0, 60)
        self.line_mem, = self.ax2.plot([], [], 'b-', linewidth=2.5, label='Memory')
        self.ax2.grid(True, alpha=0.3)
        self.ax2.legend()
        
        self.ax3 = self.fig.add_subplot(223)
        self.ax3.set_title("Disk Usage (%)", fontsize=12, fontweight='bold')
        self.ax3.set_ylim(0, 100)
        self.ax3.set_xlim(0, 60)
        self.line_disk, = self.ax3.plot([], [], 'g-', linewidth=2.5, label='Disk')
        self.ax3.grid(True, alpha=0.3)
        self.ax3.legend()
        
        self.ax4 = self.fig.add_subplot(224)
        self.ax4.set_title("Network (MiB)", fontsize=12, fontweight='bold')
        self.ax4.set_xlim(0, 60)
        self.line_net_sent, = self.ax4.plot([], [], 'orange', linewidth=2.5, label='Sent')
        self.line_net_recv, = self.ax4.plot([], [], 'purple', linewidth=2.5, label='Received')
        self.ax4.legend()
        self.ax4.grid(True, alpha=0.3)
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.perf_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.canvas.draw()
    
    def init_network_tab(self):
        self.net_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.net_frame, text="Network")
        columns = ("pid","laddr","raddr","status","type")
        self.net_tree = ttk.Treeview(self.net_frame, columns=columns, show="headings")
        self.net_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        for col in columns:
            self.net_tree.heading(col, text=col.upper())
            self.net_tree.column(col, width=200)
        
        ttk.Button(self.net_frame, text="Refresh Network", command=self.refresh_network).pack(pady=5)
    
    def background_refresh(self):
        while True:
            try:
                self.root.after(0, self.refresh_processes)
                self.root.after(0, self.refresh_network)
                self.root.after(0, self.refresh_performance)
                if self.logging_enabled and self.scheduled_log_file:
                    self.root.after(0, self.log_processes)
                time.sleep(REFRESH_INTERVAL)
            except Exception as e:
                print(f"Background refresh error: {e}")
    
    def refresh_processes(self):
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        self.cpu_label.config(text=f"CPU: {cpu:.1f}%")
        self.mem_label.config(text=f"Memory: {mem.percent:.1f}%")
        
        # Alerts
        if cpu > self.alert_cpu_threshold and 'cpu' not in self.last_alert:
            notify("High CPU Alert", f"CPU usage: {cpu:.1f}%")
            self.last_alert['cpu'] = time.time()
        elif cpu < self.alert_cpu_threshold - 10:
            self.last_alert.pop('cpu', None)
        
        procs = []
        for p in psutil.process_iter(["pid", "name", "status", "memory_info", "create_time", "num_threads", "cpu_affinity"]):
            try:
                p.cpu_percent(interval=None)
                procs.append(p)
            except:
                continue
        
        time.sleep(0.3)
        
        self.process_data = []
        for p in procs:
            try:
                with p.oneshot():
                    cpu_p = p.cpu_percent(interval=None)
                    mem_mb = p.memory_info().rss / (1024 ** 2)
                    mem_pct = p.memory_percent()
                    start_time = datetime.datetime.fromtimestamp(p.create_time()).strftime("%H:%M")
                    parent = p.parent().pid if p.parent() else 0
                    try:
                        parent_name = psutil.Process(parent).name()[:20] if parent else "init"
                    except:
                        parent_name = "N/A"
                    threads = p.num_threads()
                    affinity = len(p.cpu_affinity()) if hasattr(p, 'cpu_affinity') else 'N/A'
                    
                    self.process_data.append((p.pid, p.name()[:30], p.status(), cpu_p, mem_mb,
                                              mem_pct, start_time, parent_name, threads, affinity))
                    
                    if cpu_p > self.alert_cpu_threshold and p.pid not in self.last_alert:
                        notify("High CPU Process", f"{p.name()} using {cpu_p:.1f}% CPU")
                        self.last_alert[p.pid] = time.time()
            except:
                continue
        
        col_index = {"pid":0,"name":1,"status":2,"cpu":3,"mem_mb":4,"mem_pct":5,"start":6,"parent":7,"threads":8,"affinity":9}[self.sort_column]
        self.process_data.sort(key=lambda x: x[col_index], reverse=self.sort_reverse)
        
        self.update_process_tree()
    
    def update_process_tree(self):
        filter_text = self.filter_var.get().strip().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        count = 0
        for data in self.process_data:
            filter_check = filter_text in str(data).lower()
            if filter_text and not filter_check:
                continue
            self.tree.insert("", tk.END, values=data)
            count += 1
        
        self.status_label.config(text=f"Processes: {count} | Dark Mode: {'ON' if self.dark_mode else 'OFF'}")
    
    def refresh_network(self):
        for item in self.net_tree.get_children():
            self.net_tree.delete(item)
        
        connections = psutil.net_connections(kind='inet')
        for conn in connections[:100]:
            try:
                pid = conn.pid or 0
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                self.net_tree.insert("", tk.END, values=(pid, laddr, raddr, conn.status, conn.type))
            except:
                continue
    
    def refresh_performance(self):
        try:
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            net = psutil.net_io_counters()
            
            self.cpu_history[self.history_index] = cpu
            self.mem_history[self.history_index] = mem.percent
            self.disk_history[self.history_index] = disk.percent
            self.net_sent_history[self.history_index] = net.bytes_sent / (1024 ** 2)
            self.net_recv_history[self.history_index] = net.bytes_recv / (1024 ** 2)
            self.history_index = (self.history_index + 1) % 60
            
            x = np.arange(60)
            self.line_cpu.set_data(x, self.cpu_history)
            self.line_mem.set_data(x, self.mem_history)
            self.line_disk.set_data(x, self.disk_history)
            self.line_net_sent.set_data(x, self.net_sent_history)
            self.line_net_recv.set_data(x, self.net_recv_history)
            
            net_min = min(self.net_sent_history.min(), self.net_recv_history.min())
            net_max = max(self.net_sent_history.max(), self.net_recv_history.max())
            self.ax4.set_ylim(net_min * 0.9 if net_min > 0 else 0, net_max * 1.1)
            
            self.fig.tight_layout()
            self.canvas.draw_idle()
            self.canvas.flush_events()
        except Exception as e:
            print(f"Performance refresh error: {e}")
    
    def kill_selected_process(self):
        selected = self.tree.selection()
        if not selected:
            return messagebox.showinfo("Error", "Select a process first.")
        pid = int(self.tree.item(selected[0])["values"][0])
        if messagebox.askyesno("Confirm", f"Kill PID {pid}?"):
            try:
                p = psutil.Process(pid)
                p.terminate()
                self.status_label.config(text=f"Killed PID {pid}")
            except Exception as e:
                messagebox.showerror("Error", str(e))
            self.refresh_processes()
    
    def lower_priority(self):
        selected = self.tree.selection()
        if not selected:
            return messagebox.showinfo("Error", "Select a process first.")
        pid = int(self.tree.item(selected[0])["values"][0])
        try:
            p = psutil.Process(pid)
            current = p.nice()
            p.nice(min(current + 5, 19))
            self.status_label.config(text=f"Priority lowered for PID {pid}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def show_details(self):
        selected = self.tree.selection()
        if not selected:
            return messagebox.showinfo("Error", "Select a process first.")
        pid = int(self.tree.item(selected[0])["values"][0])
        try:
            p = psutil.Process(pid)
            io = p.io_counters()
            messagebox.showinfo("Details",
                                f"PID: {pid}\nName: {p.name()}\n"
                                f"IO Read: {io.read_bytes:,} bytes\nIO Write: {io.write_bytes:,} bytes\n"
                                f"Threads: {p.num_threads()}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def show_process_tree(self):
        tree_win = tk.Toplevel(self.root)
        tree_win.title("Process Tree")
        tree = ttk.Treeview(tree_win)
        tree.pack(fill=tk.BOTH, expand=True)
        
        tree["columns"] = ("pid", "cpu")
        tree.heading("#0", text="Name")
        tree.heading("pid", text="PID")
        tree.heading("cpu", text="CPU %")
        
        procs = {p.pid: p for p in psutil.process_iter()}
        children_map = {}
        for pid, proc in procs.items():
            ppid = proc.ppid()
            children_map.setdefault(ppid, []).append(pid)
        
        def insert_tree(parent, ppid):
            for child_pid in children_map.get(ppid, []):
                proc = procs.get(child_pid)
                if not proc:
                    continue
                try:
                    cpu = proc.cpu_percent(interval=None)
                except:
                    cpu = 0
                node = tree.insert(parent, tk.END, text=proc.name(), values=(child_pid, f"{cpu:.1f}"))
                insert_tree(node, child_pid)
        
        insert_tree("", 0)
    
    def start_logging(self):
        self.scheduled_log_file = filedialog.asksaveasfilename(defaultextension=".csv")
        if self.scheduled_log_file:
            self.logging_enabled = True
            messagebox.showinfo("Logging", f"Started logging to {self.scheduled_log_file}")
    
    def stop_logging(self):
        self.logging_enabled = False
        messagebox.showinfo("Logging", "Stopped logging")
    
    def log_processes(self):
        if not self.scheduled_log_file:
            return
        with open(self.scheduled_log_file, "a", newline="") as f:
            writer = csv.writer(f)
            if os.path.getsize(self.scheduled_log_file) == 0:
                writer.writerow(["timestamp"] + list(self.tree["columns"]))
            for item in self.tree.get_children():
                writer.writerow([datetime.datetime.now().isoformat()] + self.tree.item(item)["values"])
    
    def export_csv(self):
        fn = filedialog.asksaveasfilename(defaultextension=".csv")
        if fn:
            with open(fn, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(self.tree["columns"])
                for item in self.tree.get_children():
                    writer.writerow(self.tree.item(item)["values"])
            messagebox.showinfo("Export CSV", f"Exported view to {fn}")
    
    def import_csv(self):
        fn = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if fn:
            with open(fn, "r") as f:
                reader = csv.reader(f)
                headers = next(reader)
                for item in self.tree.get_children():
                    self.tree.delete(item)
                for row in reader:
                    self.tree.insert("", tk.END, values=row)
            messagebox.showinfo("Import CSV", f"Imported processes from {fn}")
    
    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        style = ttk.Style()
        
        if self.dark_mode:
            style.theme_use('clam')
            style.configure('TFrame', background='#2b2b2b')
            style.configure('TNotebook', background='#2b2b2b')
            style.configure('TNotebook.Tab', background='#3c3c3c', foreground='white')
            style.configure('TLabel', background='#2b2b2b', foreground='white', font=('Arial', 10))
            style.map('TLabel', background=[('active', '#3c3c3c')])
            style.configure('TButton', background='#404040', foreground='white', borderwidth=1)
            style.map('TButton', background=[('active', '#505050'), ('pressed', '#303030')],
                      foreground=[('active', 'white')])
            style.configure('TEntry', fieldbackground='#404040', foreground='white', borderwidth=1)
            style.map('TEntry', fieldbackground=[('focus', '#505050')])
            style.configure('Treeview', background='#2b2b2b', foreground='white', fieldbackground='#2b2b2b')
            style.configure('Treeview.Heading', background='#404040', foreground='white')
            style.map('Treeview', background=[('selected', '#505050')])
            style.map('Treeview.Heading', background=[('active', '#505050')])
            style.configure('Vertical.TScrollbar', background='#404040', troughcolor='#2b2b2b', borderwidth=0)
            style.map('Vertical.TScrollbar', background=[('active', '#505050')])
        else:
            style.theme_use('default')
            style.configure('TLabel', font=('Arial', 10))
        
        self.root.update_idletasks()
        self.status_label.config(text=f"Processes: {len(self.tree.get_children())} | Dark Mode: {'ON' if self.dark_mode else 'OFF'}")
    
    def change_sort(self, column):
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = (column == "cpu")
        self.refresh_processes()
    
    def on_close(self):
        self.logging_enabled = False
        plt.close('all')
        self.root.destroy()

def main():
    root = tk.Tk()
    app = TaskManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
