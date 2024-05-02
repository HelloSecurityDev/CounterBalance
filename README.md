# CounterBalance
AI driven windows IDS and EDR all in one

CounterBalance is an AI-driven Intrusion Detection and Endpoint Defense System designed to protect Windows machines from various cyber threats. It combines anomaly detection using machine learning with automated response actions to defend against potential attacks.


![CounterBalance Logo](https://github.com/HelloSecurityDev/CounterBalance/blob/main/CounterBalance%20Logo.png)


## Features

- **Anomaly Detection**: Utilizes Isolation Forest, a machine learning algorithm, for anomaly detection in network traffic.
- **Threat Intelligence**: Fetches threat intelligence information from external APIs to enhance detection capabilities.
- **Automated Response**: Triggers automated response actions such as blocking malicious IPs, mitigating DDoS attacks, quarantining malware, and preventing the execution of suspicious files.
- **User Interface**: Provides a graphical user interface (GUI) for easy interaction and monitoring of system activities.
- **Logging**: Logs all system events to a file for audit and analysis purposes.

## Prerequisites

- Python 3.x
- Required Python packages (`pip install scapy scikit-learn requests`)
- Ensure you obtain and add your API key for the external security resources noted in the "config.ini" file. Not adding the API key will affect the external security resource functionality.  

## Usage

1. Clone the repository:

    ```bash
    git clone https://github.com/HelloSecurityDev/CounterBalance.git
    ```

2. Navigate to the CounterBalance directory:

    ```bash
    cd CounterBalance
    ```

3. Run the script:

    ```bash
    python CounterBalance.py
    ```

4. Use the GUI to start or stop the IDS & EDR functions, view live output, and open the logs directory.

## Configuration

- Modify the `config.ini` file to customize settings such as IP addresses, ports, and API keys.
- Adjust logging levels and formats in the `logging.basicConfig()` call within the script.

## Contributing

Contributions are welcome! Please fork the repository, make changes, and submit a pull request.

## Created by

CounterBalance is created by [Hello Security LLC](https://www.hellosecurityllc.github.io) and [Adam Rivers](https://www.abtzpro.github.io).

## Disclaimer

CounterBalance is still a work in progress and may contain bugs and quirks. There are many additions planned for future development to make it a fully featured and robust security solution.
