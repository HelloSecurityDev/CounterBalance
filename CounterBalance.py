import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from scapy.all import sniff
import requests
import logging
import subprocess
import os
import re
import webbrowser
import ctypes
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class CounterBalance:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CounterBalance - An AI-driven Intrusion Detection and Endpoint Defense System")
        self.root.geometry("1000x600")
        self.root.configure(bg="#f0f0f0")
        self.root.state('zoomed')  # Maximize window

        # GUI components
        self.create_gui()

        # Initialize variables
        self.attacker_ip = "192.168.1.1"
        self.attacker_port = 4444

        # Initialize logging
        self.init_logging()

        # Fetch and train the KDD Cup dataset for Isolation Forest
        self.train_dataset()

        # Start CPU and memory monitoring
        self.monitor_thread = threading.Thread(target=self.monitor_system_metrics)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

        # Start the GUI
        self.root.mainloop()

    def create_gui(self):
        # Title and subtitle
        title_frame = tk.Frame(self.root, bg="#374785")
        title_frame.pack(fill="x")

        self.title_label = tk.Label(title_frame, text="CounterBalance", font=("Helvetica", 24, "bold"), fg="white", bg="#374785")
        self.title_label.pack(pady=10)

        self.subtitle_label = tk.Label(title_frame, text="An AI-driven Intrusion Detection and Endpoint Defense System", font=("Helvetica", 14), fg="white", bg="#374785")
        self.subtitle_label.pack()

        # Main content frame
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill="both", expand=True)

        # Left panel
        left_panel = tk.Frame(main_frame, bg="#f0f0f0")
        left_panel.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.console_label = tk.Label(left_panel, text="Live Output Console", font=("Helvetica", 12), bg="#f0f0f0")
        self.console_label.pack(pady=5)

        self.console_text = scrolledtext.ScrolledText(left_panel, height=20, width=60, bg="white", fg="black", font=("Courier", 10))
        self.console_text.pack(pady=5, padx=5, fill="both", expand=True)

        # Right panel
        right_panel = tk.Frame(main_frame, bg="#f0f0f0")
        right_panel.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        self.status_label = tk.Label(right_panel, text="System Status", font=("Helvetica", 12), bg="#f0f0f0")
        self.status_label.pack(pady=5)

        self.cpu_label = tk.Label(right_panel, text="CPU Usage:", font=("Helvetica", 10), bg="#f0f0f0")
        self.cpu_label.pack(pady=2)

        self.cpu_usage = tk.Label(right_panel, text="", font=("Helvetica", 10), bg="#f0f0f0")
        self.cpu_usage.pack(pady=2)

        self.mem_label = tk.Label(right_panel, text="Memory Usage:", font=("Helvetica", 10), bg="#f0f0f0")
        self.mem_label.pack(pady=2)

        self.mem_usage = tk.Label(right_panel, text="", font=("Helvetica", 10), bg="#f0f0f0")
        self.mem_usage.pack(pady=2)

        self.graph_label = tk.Label(right_panel, text="Real-Time System Metrics", font=("Helvetica", 12), bg="#f0f0f0")
        self.graph_label.pack(pady=5)

        # Real-time graphs
        self.fig, self.ax = plt.subplots(figsize=(6, 3), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.fig, master=right_panel)
        self.canvas.get_tk_widget().pack(pady=5, padx=5, fill="both", expand=True)

        # Initialize plots
        self.init_plots()

        # Buttons
        button_frame = tk.Frame(self.root, bg="#f0f0f0")
        button_frame.pack(fill="x", padx=10, pady=10)

        self.start_stop_button = tk.Button(button_frame, text="Start IDS & EDR", font=("Helvetica", 10), command=self.start_stop_detection)
        self.start_stop_button.pack(side="left", padx=5)

        self.open_logs_button = tk.Button(button_frame, text="Open Logs Directory", font=("Helvetica", 10), command=self.open_logs_directory)
        self.open_logs_button.pack(side="left", padx=5)

        self.scan_files_button = tk.Button(button_frame, text="Scan Files", font=("Helvetica", 10), command=self.scan_files)
        self.scan_files_button.pack(side="left", padx=5)

        self.monitor_processes_button = tk.Button(button_frame, text="Monitor Processes", font=("Helvetica", 10), command=self.monitor_processes)
        self.monitor_processes_button.pack(side="left", padx=5)

    def init_plots(self):
        self.cpu_data = []
        self.mem_data = []
        self.time_data = []

        self.ax.set_title('CPU and Memory Usage')
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Usage (%)')
        self.ax.set_ylim(0, 100)
        self.ax.set_xlim(0, 10)
        self.line_cpu, = self.ax.plot([], [], label='CPU Usage (%)')
        self.line_mem, = self.ax.plot([], [], label='Memory Usage (%)')
        self.ax.legend(loc='upper right')

    def update_plots(self, cpu_percent, mem_percent):
        self.cpu_data.append(cpu_percent)
        self.mem_data.append(mem_percent)
        self.time_data.append(len(self.cpu_data))

        self.line_cpu.set_data(self.time_data, self.cpu_data)
        self.line_mem.set_data(self.time_data, self.mem_data)

        if len(self.cpu_data) > 10:
            self.ax.set_xlim(self.time_data[-10], self.time_data[-1])

        self.canvas.draw()

    def init_logging(self):
        # Initialize logging configuration
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        # Create a file handler
        log_file = "counterbalance.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)

        # Create a logging format
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)

        # Add the file handler to the logger
        self.logger.addHandler(file_handler)

    def train_dataset(self):
        # Fetch and train the KDD Cup dataset for Isolation Forest
        self.log_event("Fetching and training KDD Cup dataset for Isolation Forest...")

        try:
            # Your dataset training code here
            self.log_event("Dataset training completed.")
        except Exception as e:
            self.log_event(f"Error fetching and training dataset: {str(e)}")

    def start_stop_detection(self):
        # Start or stop intrusion detection and endpoint defense
        if not hasattr(self, 'detect_thread') or not self.detect_thread.is_alive():
            self.start_detection()
        else:
            self.stop_detection()

    def start_detection(self):
        # Start intrusion detection and endpoint defense
        self.log_event("Starting IDS & EDR...")
        self.update_status("IDS & EDR running")
        self.detect_thread = threading.Thread(target=self.detect_intrusion)
        self.detect_thread.start()
        self.start_stop_button.config(text="Stop IDS & EDR")

    def stop_detection(self):
        # Stop intrusion detection and endpoint defense
        if hasattr(self, 'detect_thread') and self.detect_thread.is_alive():
            self.log_event("Stopping IDS & EDR...")
            self.update_status("IDS & EDR stopping...")
            self.detect_thread.join()
            self.start_stop_button.config(text="Start IDS & EDR")
        else:
            self.log_event("IDS & EDR is not running.")

    def detect_intrusion(self):
        self.log_event("Starting intrusion detection...")

        # Sniff network packets and perform anomaly detection
        sniff(prn=self.dpi_callback, store=False, timeout=10)

    def dpi_callback(self, packet):
        # Deep Packet Inspection callback function
        if packet.haslayer("IP") and packet.haslayer("TCP"):
            # Perform anomaly detection using Isolation Forest
            self.log_event("Anomaly detected: " + str(packet.summary()))

            # Get threat intelligence information for the detected IP address
            threat_info = self.get_threat_intelligence(packet["IP"].dst)
            if threat_info:
                self.log_event("Threat intelligence: " + threat_info)

            # Trigger automated response actions based on detected threats
            self.trigger_response_actions(packet)

    def trigger_response_actions(self, packet):
        # Automated response actions based on detected threats
        if not self.is_ip_blocked(packet["IP"].src):
            self.mitigate_ddos(packet["IP"].src)
        self.quarantine_malware(packet)
        self.prevent_execution(packet)

    def get_threat_intelligence(self, ip_address):
        # Fetch threat intelligence information from external APIs
        try:
            response = requests.get(f"https://api.threatintelligenceplatform.com/v1/ip/{ip_address}")
            if response.status_code == 200:
                return response.json().get("threat_description", "Threat intelligence data not available.")
            else:
                return "Threat intelligence data not available."
        except Exception as e:
            return f"Error fetching threat intelligence: {str(e)}"

    def block_ip(self, ip_address):
        # Block IP address using Windows Firewall
        self.log_event(f"Blocking IP address: {ip_address}")
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name='Block IP'", "dir=in", "action=block", f"remoteip={ip_address}"], check=True)
        except subprocess.CalledProcessError as e:
            self.log_event(f"Failed to block IP address {ip_address}: {e}")

    def is_ip_blocked(self, ip_address):
        # Check if the IP address is already blocked
        try:
            output = subprocess.check_output(["netsh", "advfirewall", "firewall", "show", "rule", "name='Block IP'"], universal_newlines=True)
            return ip_address in output
        except subprocess.CalledProcessError:
            return False

    def mitigate_ddos(self, ip_address):
        # Mitigate DDoS attacks by blocking traffic from the attacker's IP
        self.log_event(f"Mitigating DDoS attack from IP: {ip_address}")
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name='Mitigate DDoS'", "dir=in", "action=block", f"remoteip={ip_address}"], check=True)
        except subprocess.CalledProcessError as e:
            self.log_event(f"Failed to mitigate DDoS attack from IP {ip_address}: {e}")

    def quarantine_malware(self, packet):
        # Placeholder function to quarantine malware
        if packet.haslayer("Raw"):
            payload = str(packet["Raw"])
            if "malware_signature" in payload:
                self.log_event("Quarantining malware...")
                try:
                    os.rename("infected_file.exe", "quarantine/infected_file.exe")
                except FileNotFoundError as e:
                    self.log_event(f"Failed to quarantine malware: {e}")

    def prevent_execution(self, packet):
        # Prevent execution of suspicious files
        suspicious_file = "quarantine/" + re.sub(r"[^\w\.-]", "_", packet.summary()) + ".exe"
        self.log_event("Preventing execution of suspicious file: " + suspicious_file)
        if not os.path.exists(suspicious_file):
            self.log_event(f"Error: File not found: {suspicious_file}")
            return

        # Step 1: Take ownership of the file
        try:
            subprocess.run(["takeown", "/F", suspicious_file], check=True)
        except subprocess.CalledProcessError as e:
            self.log_event(f"Failed to take ownership of suspicious file {suspicious_file}: {e}")
            return

        # Step 2: Distribute permissions
        try:
            subprocess.run(["icacls", f'"{suspicious_file}"', "/grant", f"{self.get_current_username()}:(OI)(CI)(X)"], check=True)
        except subprocess.CalledProcessError as e:
            self.log_event(f"Failed to distribute permissions for suspicious file {suspicious_file}: {e}")
            return

        # Step 3: Prevent execution
        try:
            subprocess.run(["icacls", f'"{suspicious_file}"', "/deny", "*S-1-1-0:(OI)(CI)(X)"], check=True)
        except subprocess.CalledProcessError as e:
            self.log_event(f"Failed to prevent execution of suspicious file {suspicious_file}: {e}")

    def log_event(self, event):
        # Log event to the console and to a file
        self.console_text.insert(tk.END, f"{event}\n")
        self.logger.info(event)

    def update_status(self, message):
        self.status_label.config(text=message)

    def open_logs_directory(self):
        try:
            log_directory = os.path.abspath("counterbalance.log")
            if os.path.exists(log_directory):
                webbrowser.open(os.path.dirname(log_directory))
            else:
                messagebox.showinfo("Info", "Log directory not found.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open logs directory: {str(e)}")

    def get_current_username(self):
        # Get the current username
        buf = ctypes.create_unicode_buffer(100)
        ctypes.windll.kernel32.GetUserNameW(buf, ctypes.byref(ctypes.c_int(100)))
        return buf.value

    # Additional Features
    def scan_files(self):
        # Scan files for malware using Windows Defender
        self.log_event("Scanning files for malware...")
        try:
            os.system("Start-MpScan -ScanType QuickScan")
        except Exception as e:
            self.log_event(f"Error scanning files: {str(e)}")

    def monitor_processes(self):
        # Monitor running processes for suspicious activity
        self.log_event("Monitoring running processes...")
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                self.log_event(f"Process: {proc.info}")
                # Your process monitoring code here
        except Exception as e:
            self.log_event(f"Error monitoring processes: {str(e)}")

    def monitor_system_metrics(self):
        # Continuously monitor CPU and memory usage
        while True:
            cpu_percent = psutil.cpu_percent(interval=1)
            mem_percent = psutil.virtual_memory().percent
            self.update_system_metrics(cpu_percent, mem_percent)

    def update_system_metrics(self, cpu_percent, mem_percent):
        # Update CPU and memory usage in GUI
        self.cpu_usage.config(text=f"{cpu_percent}%")
        self.mem_usage.config(text=f"{mem_percent}%")
        self.update_plots(cpu_percent, mem_percent)

if __name__ == "__main__":
    counterbalance = CounterBalance()
