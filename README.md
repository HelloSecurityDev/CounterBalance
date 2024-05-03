# CounterBalance
AI driven windows IDS and EDR all in one

CounterBalance is an AI-driven Intrusion Detection and Endpoint Defense System designed to protect Windows machines from various cyber threats. It combines anomaly detection using machine learning with automated response actions to defend against potential attacks.


![CounterBalance Logo](https://github.com/HelloSecurityDev/CounterBalance/blob/main/CounterBalance%20Logo.png)

## Features

- **Real-time Intrusion Detection**: CounterBalance continuously monitors network traffic using deep packet inspection and anomaly detection techniques.
- **Automated Response Actions**: Upon detecting threats, CounterBalance triggers automated response actions such as blocking malicious IP addresses, mitigating DDoS attacks, quarantining malware, and preventing execution of suspicious files.
- **Live Output Console**: Provides a live output console for monitoring system events and alerts in real-time.
- **System Status Monitoring**: Displays real-time system metrics including CPU and memory usage.
- **Log Management**: Logs events to a file for historical analysis and auditing purposes.
- **User-friendly GUI**: Features a user-friendly graphical interface for easy interaction and control.

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/HelloSecurityDev/CounterBalance.git
   ```
2. Navigate to the project directory:

   ```bash
   cd CounterBalance
   ```
3. Install The Required Dependencies:

   ```bash
   pip install -r requirements.txt
   ```
4. Run the Program:

   ```bash
   python CounterBalance.py
   ```

## Requirements

Python 3.6+
Required Python packages are listed below.

```bash
- tkinter: Pythons de facto standard GUI (Graphical User Interface) package.
- scapy: For packet manipulation and sniffing.
- requests: For making HTTP requests to fetch threat intelligence.
- psutil: For retrieving system and process information.
- win32evtlog: Windows Event Log API for retrieving security alerts.
- pywintypes: Python for Windows extensions.
```
   
## V3 UPDATE

The Version 3 update that has been pushed provides the following additions, updates, and changes to the CounterBalance program.

*GUI Improvements:*
- Utilized tkinter's Label, Text, and Button widgets for the GUI.
- Defined the GUI layout using pack geometry manager.
- Added labels for the title, tagline, console, and author.
- Adjusted the window size to 800x600 pixels.
- Added 5 live output console windows.
- incorporated live system metrics output.
- incorporated live windows security event logs output.
- incorporated live running task monitoring and querying.
- Incorporated live network traffic monitoring output.
- incorporated the ability to end chosen tasks.

*Intrusion Detection and Endpoint Defense (IDS & EDR):*
- Integrated threading for handling concurrency in starting and stopping IDS & EDR.
- Incorporated packet sniffing using Scapy for intrusion detection.
- Implemented Deep Packet Inspection (DPI) callback function for analyzing network packets.
- Added functions for blocking IP addresses, mitigating DDoS attacks, quarantining malware, and preventing execution of suspicious files.
- Fetched threat intelligence information from an external API for detected IP addresses.
- Integrated Windows Firewall commands for IP address blocking and other security measures.
- Ensured logging of events to both the console and a log file for tracking system activity.

*Additional Features:*
- Included functionality for training an Isolation Forest model using the KDD Cup dataset.
- Added buttons for starting IDS & EDR and opening the logs directory.
- Provided methods for fetching threat intelligence and opening the logs directory in a web browser.

*There is currently no .exe executable download for V3 as of yet. I am working on producing it as quick as possible but as of now, downloading CounterBalance.exe from dropbox will only provide v1 not v2.*

## Contributing

Contributions are welcome! Please fork the repository, make changes, and submit a pull request.

## Created by

CounterBalance is created by [Hello Security LLC](https://www.hellosecurityllc.github.io) and [Adam Rivers](https://www.abtzpro.github.io).

## Disclaimer

CounterBalance is still a work in progress and may contain bugs and quirks. There are many additions planned for future development to make it a fully featured and robust security solution.
