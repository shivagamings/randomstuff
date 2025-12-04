import psutil
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import os
import signal

REFRESH_INTERVAL = 10.0

class TaskManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Task Manager")
        self.root.geometry("900x500")

        summary_frame = ttk.Frame(root)
        summary_frame.pack(fill=tk.X, padx=10, pady=5)

        self.cpu_label = ttk.Label(summary_frame, text="CPU: -- %")
        self.cpu_label.pack(side=tk.LEFT, padx=5)

        self.mem_label = ttk.Label(summary_frame, text="Memory: -- %")
        self.mem_label.pack(side=tk.LEFT, padx=5)

        refresh_btn = ttk.Button(summary_frame, text="Refresh Now", command=self.refresh_processes)
        refresh_btn.pack(side=tk.RIGHT, padx=5)

        table_frame = ttk.Frame(root)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ("pid", "name", "status", "cpu", "mem")
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        self.tree.heading("pid", text="PID")
        self.tree.heading("name", text="Name")
        self.tree.heading("status", text="Status")
        self.tree.heading("cpu", text="CPU %")
        self.tree.heading("mem", text="Memory (MB)")

        self.tree.column("pid", width=80, anchor=tk.CENTER)
        self.tree.column("name", width=250, anchor=tk.W)
        self.tree.column("status", width=120, anchor=tk.CENTER)
        self.tree.column("cpu", width=80, anchor=tk.E)
        self.tree.column("mem", width=100, anchor=tk.E)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        action_frame = ttk.Frame(root)
        action_frame.pack(fill=tk.X, padx=10, pady=5)

        kill_btn = ttk.Button(action_frame, text="Kill Selected Process", command=self.kill_selected_process)
        kill_btn.pack(side=tk.LEFT, padx=5)

        self.status_label = ttk.Label(action_frame, text="", foreground="gray")
        self.status_label.pack(side=tk.RIGHT, padx=5)

        self._stop_event = threading.Event()
        self.refresh_thread = threading.Thread(target=self._auto_refresh_loop, daemon=True)
        self.refresh_thread.start()

        self.refresh_processes()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        self._stop_event.set()
        self.root.destroy()

    def _auto_refresh_loop(self):
        while not self._stop_event.is_set():
            self.refresh_processes()
            time.sleep(REFRESH_INTERVAL)

    def refresh_processes(self):
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        self.cpu_label.config(
            text=f"CPU: {cpu:.1f}%"
        )
        self.mem_label.config(
            text=f"Memory: {mem.percent:.1f}% ({mem.used / (1024**3):.2f}/{mem.total / (1024**3):.2f} GiB)"
        )

        procs = []
        for p in psutil.process_iter(["pid", "name", "status", "memory_info"]):
            try:
                p.cpu_percent(interval=None)
                procs.append(p)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(0.3)

        info_list = []
        for p in procs:
            try:
                with p.oneshot():
                    cpu_p = p.cpu_percent(interval=None)
                    mem_mb = p.memory_info().rss / (1024 ** 2)
                    info_list.append(
                        (
                            p.pid,
                            p.name()[:40],
                            p.status(),
                            cpu_p,
                            mem_mb,
                        )
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        info_list.sort(key=lambda x: x[3], reverse=True)

        for item in self.tree.get_children():
            self.tree.delete(item)

        for pid, name, status, cpu_p, mem_mb in info_list:
            self.tree.insert(
                "",
                tk.END,
                values=(pid, name, status, f"{cpu_p:.1f}", f"{mem_mb:.1f}")
            )

        self.status_label.config(text=f"Processes: {len(info_list)}")

    def kill_selected_process(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Kill Process", "Please select a process first.")
            return

        pid = int(self.tree.item(selected[0])["values"][0])

        if not messagebox.askyesno("Kill Process", f"Are you sure you want to terminate PID {pid}?"):
            return

        try:
            if os.name == "nt":
                p = psutil.Process(pid)
                p.terminate()
            else:
                os.kill(pid, signal.SIGTERM)
            self.status_label.config(text=f"Sent terminate signal to PID {pid}")
        except (psutil.NoSuchProcess, PermissionError, OSError) as e:
            messagebox.showerror("Error", f"Failed to kill PID {pid}: {e}")

        self.refresh_processes()

def main():
    root = tk.Tk()
    app = TaskManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()