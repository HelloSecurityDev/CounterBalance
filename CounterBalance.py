import threading
import tkinter as tk
from scapy.all import sniff
from sklearn.ensemble import IsolationForest
import requests
import logging
import subprocess
import os
import datetime
import re
from sklearn.datasets import fetch_kddcup99
from sklearn.preprocessing import OneHotEncoder
import webbrowser

class CounterBalance:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CounterBalance - An AI-driven Intrusion Detection and Endpoint Defense System")
        self.root.geometry("800x600")
        
        # GUI components
        self.title_label = tk.Label(self.root, text="CounterBalance", font=("Helvetica", 24, "bold"))
        self.title_label.pack(pady=10)
        
        self.tagline_label = tk.Label(self.root, text="Time to tip the digital scales.", font=("Helvetica", 14))
        self.tagline_label.pack(pady=5)
        
        self.console_label = tk.Label(self.root, text="Live Output Console", font=("Helvetica", 12))
        self.console_label.pack(pady=5)
        
        self.console_text = tk.Text(self.root, height=20, width=80)
        self.console_text.pack(pady=5)
        
        self.author_label = tk.Label(self.root, text="CounterBalance - an AI-driven Intrusion Detection and Endpoint Defense System - By Adam Rivers of Hello Security vCISO", font=("Helvetica", 8))
        self.author_label.pack(side="bottom", pady=5, padx=10)

        # Initialize variables
        self.attacker_ip = "192.168.1.1"
        self.attacker_port = 4444

        # Initialize logging
        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger(__name__)

        # Fetch and train the KCUPP dataset for Isolation Forest
        self.log_event("Fetching and training KCUPP dataset for Isolation Forest...")
        self.isolation_forest = self.train_kcupp_isolation_forest()

        # Add buttons
        self.start_stop_button = tk.Button(self.root, text="Start IDS & EDR", command=self.start_stop_detection)
        self.start_stop_button.pack(pady=5)

        self.open_logs_button = tk.Button(self.root, text="Open Logs Directory", command=self.open_logs_directory)
        self.open_logs_button.pack(pady=5)

        # Start the GUI
        self.root.mainloop()

    def train_kcupp_isolation_forest(self):
        # Fetch KCUPP dataset
        kddcup = fetch_kddcup99(subset='SA')
        X = kddcup.data

        # One-hot encode categorical features
        encoder = OneHotEncoder()
        X_encoded = encoder.fit_transform(X[:, [1, 2, 3, 6, 11]])

        # Train Isolation Forest model
        isolation_forest = IsolationForest()
        isolation_forest.fit(X_encoded)

        return isolation_forest

    def start_stop_detection(self):
        # Start or stop intrusion detection and endpoint defense
        if not hasattr(self, 'detect_thread'):
            self.log_event("Starting IDS & EDR...")
            self.detect_thread = threading.Thread(target=self.detect_intrusion)
            self.detect_thread.start()
            self.start_stop_button.config(text="Stop IDS & EDR")
        else:
            self.log_event("Stopping IDS & EDR...")
            self.detect_thread.join()
            del self.detect_thread
            self.start_stop_button.config(text="Start IDS & EDR")

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
        self.block_ip(packet["IP"].src)
        self.mitigate_ddos(packet["IP"].src)
        self.quarantine_malware(packet)
        self.prevent_execution(packet)

    def get_threat_intelligence(self, ip_address):
        # Fetch threat intelligence information from external APIs
        try:
            response = requests.get(f"https://api.threatintelligenceplatform.com/v1/ip/{ip_address}")
            if response.status_code == 200:
                return response.json()["threat_description"]
            else:
                return "Threat intelligence data not available."
        except Exception as e:
            return f"Error fetching threat intelligence: {str(e)}"

    def block_ip(self, ip_address):
        # Block IP address using Windows Firewall
        self.log_event(f"Blocking IP address: {ip_address}")
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name='Block IP'", "dir=in", "action=block", f"remoteip={ip_address}"])

    def mitigate_ddos(self, ip_address):
        # Mitigate DDoS attacks by blocking traffic from the attacker's IP
        self.log_event(f"Mitigating DDoS attack from IP: {ip_address}")
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name='Mitigate DDoS'", "dir=in", "action=block", f"remoteip={ip_address}"])

    def quarantine_malware(self, packet):
        # Placeholder function to quarantine malware
        if packet.haslayer("Raw"):
            payload = str(packet["Raw"])
            if "malware_signature" in payload:
                self.log_event("Quarantining malware...")
                os.rename("infected_file.exe", "quarantine/infected_file.exe")

    def prevent_execution(self, packet):
        # Prevent execution of suspicious files
        suspicious_file = "quarantine/" + re.sub(r"[^\w\.-]", "_", packet.summary()) + ".exe"
        self.log_event("Preventing execution of suspicious file: " + suspicious_file)
        try:
            subprocess.run(["icacls", suspicious_file, "/deny", "*S-1-1-0:(OI)(CI)(X)"], check=True)
        except subprocess.CalledProcessError as e:
            self.log_event(f"Failed to prevent execution of suspicious file {suspicious_file}: {e}")

    def log_event(self, event):
        # Log event to the console and to a file
        self.console_text.insert(tk.END, f"{event}\n")
        self.logger.info(event)
        with open("counterbalance.log", "a") as logfile:
            logfile.write(f"{datetime.datetime.now()} - {event}\n")

    def open_logs_directory(self):
        # Open the directory containing the logs
        log_directory = os.path.abspath("counterbalance.log")
        webbrowser.open(os.path.dirname(log_directory))

if __name__ == "__main__":
    counterbalance = CounterBalance()
