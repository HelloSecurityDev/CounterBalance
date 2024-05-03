import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff
import requests
import logging
import subprocess
import os
import re
import psutil
from datetime import datetime
import win32evtlog
import win32security
import pywintypes

class CounterBalance:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CounterBalance - An AI-driven Intrusion Detection and Endpoint Defense System")
        self.root.geometry("1000x600")
        self.root.configure(bg="#f0f0f0")
        self.root.state('zoomed')  # Maximize window

        # GUI components
        self.create_gui()

        # Initialize logging
        self.init_logging()

        # Start CPU and memory monitoring
        self.monitor_thread = threading.Thread(target=self.monitor_system_metrics)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

        # Check IDS & EDR status every 3 seconds
        self.check_edr_status()

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

        # Buttons
        button_frame = tk.Frame(self.root, bg="#f0f0f0")
        button_frame.pack(fill="x")

        self.start_stop_button = tk.Button(button_frame, text="Start IDS & EDR", font=("Helvetica", 10), command=self.start_stop_detection)
        self.start_stop_button.pack(side="left", padx=5)

        self.open_logs_button = tk.Button(button_frame, text="Open Logs Directory", font=("Helvetica", 10), command=self.open_logs_directory)
        self.open_logs_button.pack(side="left", padx=5)

        self.scan_files_button = tk.Button(button_frame, text="Scan Files", font=("Helvetica", 10), command=self.scan_files)
        self.scan_files_button.pack(side="left", padx=5)

        self.monitor_processes_button = tk.Button(button_frame, text="Monitor Processes", font=("Helvetica", 10), command=self.monitor_processes)
        self.monitor_processes_button.pack(side="left", padx=5)

        self.end_process_button = tk.Button(button_frame, text="End Process", font=("Helvetica", 10), command=self.end_selected_process)
        self.end_process_button.pack(side="left", padx=5)

        # Main content frame
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill="both", expand=True)

        # Divide the GUI into six equal parts
        part_width = self.root.winfo_screenwidth() // 6

        # Left panel
        left_panel = tk.Frame(main_frame, bg="#f0f0f0", width=part_width)
        left_panel.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.console1_label = tk.Label(left_panel, text="Live Network Traffic", font=("Helvetica", 12), bg="#f0f0f0")
        self.console1_label.pack(pady=5)

        self.console1_text = scrolledtext.ScrolledText(left_panel, height=10, width=60, bg="white", fg="black", font=("Courier", 10))
        self.console1_text.pack(pady=5, padx=5, fill="both", expand=True)

        self.console2_label = tk.Label(left_panel, text="IDS & EDR Information", font=("Helvetica", 12), bg="#f0f0f0")
        self.console2_label.pack(pady=5)

        self.console2_text = scrolledtext.ScrolledText(left_panel, height=10, width=60, bg="white", fg="black", font=("Courier", 10))
        self.console2_text.pack(pady=5, padx=5, fill="both", expand=True)

        # Middle panel
        middle_panel = tk.Frame(main_frame, bg="#f0f0f0", width=part_width)
        middle_panel.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.console3_label = tk.Label(middle_panel, text="Windows Event Log & Security Alerts", font=("Helvetica", 12), bg="#f0f0f0")
        self.console3_label.pack(pady=5)

        self.console3_text = scrolledtext.ScrolledText(middle_panel, height=10, width=60, bg="white", fg="black", font=("Courier", 10))
        self.console3_text.pack(pady=5, padx=5, fill="both", expand=True)

        # Right panel
        right_panel = tk.Frame(main_frame, bg="#f0f0f0", width=part_width)
        right_panel.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.console4_label = tk.Label(right_panel, text="Running Processes", font=("Helvetica", 12), bg="#f0f0f0")
        self.console4_label.pack(pady=5)

        self.console4_text = scrolledtext.ScrolledText(right_panel, height=10, width=60, bg="white", fg="black", font=("Courier", 10))
        self.console4_text.pack(pady=5, padx=5, fill="both", expand=True)

        self.console5_label = tk.Label(right_panel, text="System Metrics", font=("Helvetica", 12), bg="#f0f0f0")
        self.console5_label.pack(pady=5)

        self.console5_text = scrolledtext.ScrolledText(right_panel, height=10, width=60, bg="white", fg="black", font=("Courier", 10))
        self.console5_text.pack(pady=5, padx=5, fill="both", expand=True)

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
        self.detect_thread.daemon = True
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

        try:
            # Continuously sniff network packets and perform anomaly detection
            sniff(prn=self.dpi_callback, store=False)
        except Exception as e:
            self.log_event(f"Error during intrusion detection: {str(e)}")
        finally:
            self.log_event("Intrusion detection stopped.")

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

            # Update network monitoring
            self.update_network_monitoring(packet)

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
            subprocess.run(["icacls", f'"{suspicious_file}"', "/grant", f"{self.get_current_username()}:(F)"], check=True)
        except subprocess.CalledProcessError as e:
            self.log_event(f"Failed to distribute permissions for suspicious file {suspicious_file}: {e}")
            return

        # Step 3: Deny execution
        try:
            subprocess.run(["icacls", f'"{suspicious_file}"', "/deny", f"{self.get_current_username()}:(X)"], check=True)
        except subprocess.CalledProcessError as e:
            self.log_event(f"Failed to deny execution of suspicious file {suspicious_file}: {e}")
            return

        self.log_event("Execution prevention applied to suspicious file.")

    def get_current_username(self):
        # Get the current username
        return os.getlogin()

    def open_logs_directory(self):
        # Open logs directory in file explorer
        logs_dir = os.path.dirname(os.path.realpath(__file__))
        try:
            subprocess.Popen(f'explorer "{logs_dir}"')
        except Exception as e:
            self.log_event(f"Error opening logs directory: {str(e)}")

    def scan_files(self):
        # Placeholder function to scan files for malware
        self.log_event("Scanning files for malware...")

    def monitor_processes(self):
        # Monitor running processes and display in the GUI
        self.log_event("Monitoring running processes...")
        process_list = []
        for proc in psutil.process_iter(['pid', 'name']):
            process_list.append((proc.info['pid'], proc.info['name']))
        self.update_processes(process_list)

    def end_selected_process(self):
        # End the selected process
        self.log_event("Ending selected process...")
        selected_process = self.console4_text.get(tk.SEL_FIRST, tk.SEL_LAST)
        if selected_process:
            pid = int(selected_process.split()[0])
            try:
                process = psutil.Process(pid)
                process.terminate()
                self.log_event(f"Process {pid} terminated successfully.")
            except psutil.NoSuchProcess:
                self.log_event(f"Process {pid} does not exist.")
            except psutil.AccessDenied:
                self.log_event(f"Access denied: Unable to terminate process {pid}.")
        else:
            self.log_event("No process selected.")

    def check_edr_status(self):
        # Check IDS & EDR status every 3 seconds
        self.log_event("Checking IDS & EDR status...")
        if hasattr(self, 'detect_thread') and self.detect_thread.is_alive():
            self.update_status("IDS & EDR running")
        else:
            self.update_status("IDS & EDR not running")

        self.root.after(3000, self.check_edr_status)

    def monitor_system_metrics(self):
        # Continuously monitor system metrics
        while True:
            # CPU and memory usage
            cpu_percent = psutil.cpu_percent(interval=1)
            memory_stats = psutil.virtual_memory()
            memory_percent = memory_stats.percent
            memory_total = memory_stats.total
            memory_used = memory_stats.used
            memory_free = memory_stats.free

            # Disk usage
            disk_partitions = psutil.disk_partitions()
            disk_stats = {}
            for partition in disk_partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_stats[partition.device] = {
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": usage.percent
                    }
                except Exception as e:
                    disk_stats[partition.device] = {
                        "error": str(e)
                    }

            # Network usage
            network_stats = psutil.net_io_counters()
            bytes_sent = network_stats.bytes_sent
            bytes_received = network_stats.bytes_recv

            # Display system metrics in GUI
            self.update_system_metrics(cpu_percent, memory_percent, memory_total, memory_used, memory_free, disk_stats, bytes_sent, bytes_received)

    def update_status(self, status):
        # Update IDS & EDR status in GUI
        self.console2_text.delete('1.0', tk.END)
        self.console2_text.insert(tk.END, status)

    def update_network_monitoring(self, packet):
        # Update network monitoring in GUI
        self.console1_text.insert(tk.END, packet.summary() + "\n")

    def update_processes(self, process_list):
        # Update running processes in GUI
        self.console4_text.delete('1.0', tk.END)
        for pid, name in process_list:
            self.console4_text.insert(tk.END, f"{pid}\t{name}\n")

    def update_system_metrics(self, cpu_percent, memory_percent, memory_total, memory_used, memory_free, disk_stats, bytes_sent, bytes_received):
        # Update system metrics in GUI
        self.console5_text.delete('1.0', tk.END)
        self.console5_text.insert(tk.END, f"CPU Usage: {cpu_percent}%\n")
        self.console5_text.insert(tk.END, f"Memory Usage: {memory_percent}%\n")
        self.console5_text.insert(tk.END, f"Total Memory: {memory_total} bytes\n")
        self.console5_text.insert(tk.END, f"Used Memory: {memory_used} bytes\n")
        self.console5_text.insert(tk.END, f"Free Memory: {memory_free} bytes\n\n")
        self.console5_text.insert(tk.END, "Disk Usage:\n")
        for device, stats in disk_stats.items():
            self.console5_text.insert(tk.END, f"Device: {device}\n")
            if "error" in stats:
                self.console5_text.insert(tk.END, f"Error: {stats['error']}\n")
            else:
                self.console5_text.insert(tk.END, f"Total: {stats['total']} bytes\n")
                self.console5_text.insert(tk.END, f"Used: {stats['used']} bytes\n")
                self.console5_text.insert(tk.END, f"Free: {stats['free']} bytes\n")
                self.console5_text.insert(tk.END, f"Usage: {stats['percent']}%\n\n")
        self.console5_text.insert(tk.END, f"Network Traffic:\nBytes Sent: {bytes_sent}\nBytes Received: {bytes_received}\n")

    def log_event(self, event):
        # Log events to console and log file
        self.logger.info(event)
        self.console3_text.insert(tk.END, event + "\n")

if __name__ == "__main__":
    CounterBalance()
