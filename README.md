# Network Intrusion Detection System with Security Onion & AI

##  Overview
This project focuses on enhancing network security monitoring by integrating **Security Onion** with **Unsupervised Machine Learning** techniques. Unlike traditional signature-based IDSs (like Snort/Suricata), this system is designed to detect **network anomalies** and potential **zero-day attacks** by analyzing traffic patterns.

##  Key Features
* **Data Collection:** Utilizes **Security Onion** to capture and manage network telemetry.
* **Log Analysis:** Specifically processes **Zeek logs** (`conn.log` and `dns.log`) to extract meaningful features (duration, orig_bytes, resp_bytes, service, etc.).
* **AI Detection Engine:** Implements two unsupervised learning models to identify outliers:
    * **Isolation Forest:** For efficient anomaly detection in high-dimensional datasets.
    * **Autoencoder:** For reconstructing normal traffic patterns and flagging high reconstruction errors as anomalies.
* **Zero-Day Detection:** Capable of detecting unknown attacks without prior knowledge or signatures.

##  Tech Stack
* **Infrastructure:** Security Onion (Linux).
* **Network Analysis:** Zeek (Bro).
* **Language:** Python 3.x.

##  Methodology
* **1. Ingestion:** Raw network traffic is processed by Zeek to generate log files.

* **2. Preprocessing:**
  * **Encoding categorical features:** (e.g., protocol, service).
  * **Normalizing numerical features:** (e.g., bytes, duration).

* **3. Training:** Models are trained on "normal" traffic baselines.

* **4. Detection:** The system evaluates new traffic; data points with high anomaly scores are flagged as potential intrusions.