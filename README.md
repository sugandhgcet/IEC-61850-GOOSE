# ⚡ IEC 61850 GOOSE Publisher/Decoder Tool
**Developed by [Sugandh Pratap](mailto:sugandh@iitk.ac.in)**

A graphical Python-based tool for **publishing, decoding, and analyzing IEC 61850 GOOSE (Generic Object Oriented Substation Event)** messages.  
This simulator is designed for **research, testing, and cybersecurity validation** in **digital substations**, enabling users to simulate protection events, trip signals, and cyber-attack scenarios.

---

## 🧠 Overview

The **GOOSE Publisher/Decoder Tool** provides a complete test environment for IEC 61850-8-1 GOOSE communication.  
It allows you to **publish**, **decode**, and **analyze** GOOSE frames exchanged between Intelligent Electronic Devices (IEDs) in a substation network.

The tool also supports **attack simulation** for research on **false data injection**, **spoofing**, and **packet manipulation** in GOOSE-based protection systems.

---

## 🧩 Features

### 🖥 GOOSE Publisher
- Publishes **IEC 61850 GOOSE messages** with configurable parameters:
  - Network Interface
  - Source & Destination MAC
  - gocbRef, datSet, and goID fields
- Send **Boolean status** data (e.g., trip, breaker open/close)
- Optionally include **RMS analog values** (IA, IB, IC, VA, VB, VC)
- Manual control of **stNum** and **sqNum** (sequence/state numbers) for testing retransmission or attack simulation
- Real-time log window for monitoring GOOSE frame publication

### 🔍 GOOSE Decoder
- Captures live GOOSE messages from the network interface
- Decodes and displays:
  - Ethernet header
  - APPID, gocbRef, datSet, goID
  - stNum, sqNum, Boolean and analog payloads
- Helps analyze IED communication and identify anomalies or attacks

### 🧠 Cyber-Attack Simulation
- Inject **malicious or falsified GOOSE events**
- Override **stNum/sqNum** for replay or flooding attack testing
- Simulate **unauthorized trip or block signals**
- Study the response of IEDs, controllers, or HIL-based protection systems

### 📈 Real-time Visualization
- Boolean and RMS analog data visualized live
- Log output for event tracking and debugging

---

## 🧰 Technology Stack

| Component | Technology |
|------------|-------------|
| Language | Python |
| GUI | PyQt5 / Tkinter |
| Packet Handling | Scapy |
| Plotting / Logs | Matplotlib / QTextEdit |
| Protocol | IEC 61850-8-1 (GOOSE) |

---

## 🚀 Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/<yourusername>/IEC61850-GOOSE-Tool.git
   cd IEC61850-GOOSE-Tool
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```
   *(Typical dependencies: `scapy`, `pyqt5`, `matplotlib`, `numpy`)*

3. **Run the Application**
   ```bash
   python GOOSE_Tool.py
   ```

---

## ⚙️ Usage

### 1. GOOSE Publisher
- Select your **network interface**
- Configure MAC addresses and GOOSE control block fields (gocbRef, datSet, goID)
- Choose Boolean or analog payloads
- Optionally enable RMS values
- Click **Publish GOOSE Event(s)**

### 2. GOOSE Decoder
- Switch to the **GOOSE Decoder** tab
- Select the network interface
- Click **Start Decoding**
- Observe real-time decoded data and analyze field values

### 3. Attack Simulation
- Enable **Manual stNum/sqNum Override**
- Modify values to simulate replay or spoofing attacks
- Publish altered GOOSE frames
- Observe how target IEDs respond under compromised conditions

---

## 📷 Screenshot

**GOOSE Publisher/Decoder Interface**
<img width="802" height="885" alt="image" src="https://github.com/user-attachments/assets/aa81b95d-6bef-4c2f-83a8-a0b972a0e181" />
<img width="803" height="884" alt="image" src="https://github.com/user-attachments/assets/3722be99-36a9-4e29-85e6-ae0024a610db" />


---

## 🧪 Research Applications

This tool is actively used for research on:
- Watermarking-based authentication of GOOSE messages  
- Cyber-attack detection using state-number tracking and timing features  
- IEC 61850-8-1 communication validation and protection scheme testing  
- Security analysis of **Digital Substation Automation Systems (DSAS)**  

If you use this tool for your research or publication, please cite or acknowledge the repository.

---

## 📜 Citation

If this simulator assists your research or project, please cite as:

> **Sugandh Pratap**, *"IEC 61850 GOOSE Publisher/Decoder Tool for Cybersecurity and Communication Testing"*, 2025.  
> GitHub Repository: [https://github.com/<yourusername>/IEC61850-GOOSE-Tool](https://github.com/<yourusername>/IEC61850-GOOSE-Tool)

---

## 🧑‍💻 Author
**Sugandh Pratap**  
Electrical Engineer & Researcher – Power System Cybersecurity  
Email: sugandh@iitk.ac.in 
LinkedIn: https://www.linkedin.com/in/sugandhp/

---

## 📄 License
This project is released under the **MIT License**.  
You are free to use, modify, and distribute it for research and educational purposes with proper credit.
