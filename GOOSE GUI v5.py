#!/usr/bin/env python3

import sys
import struct
import time
from datetime import datetime, timezone, timedelta

# --- PyQt6 Imports ---
# You must install PyQt6: pip install PyQt6
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QTabWidget, QPushButton, QLineEdit, QLabel, QTextEdit, QCheckBox, QGroupBox
)
from PyQt6.QtCore import QThread, QObject, pyqtSignal, pyqtSlot, Qt

# --- Scapy Import ---
# You must install scapy: pip install scapy
from scapy.all import sniff, Ether, Raw, sendp

# ==============================================================================
#  1. GOOSE PUBLISHER LOGIC
# ==============================================================================
class GoosePublisher:
    """Handles the creation and sending of GOOSE packets."""
    def __init__(self, iface, src_mac, dst_mac, gocbRef, datSet, goID, confRev=1):
        self.iface = iface
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.eth_type = 0x88b8
        self.gocbRef = gocbRef
        self.datSet = datSet
        self.goID = goID
        self.confRev = confRev
        self.timeAllowedtoLive = 2000
        # Internal state trackers
        self.stNum = 0
        self.sqNum = 0
        self.last_data_payload = None

    def _encode_integer_tlv(self, tag, value):
        """Encodes an integer value using ASN.1 INTEGER TLV format, handling
        variable length and leading zero for positive values with MSB set."""
        # Special case for 0
        if value == 0:
            val_bytes = b'\x00'
        else:
            # Determine minimal byte representation
            val_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
            # Check if a leading zero is needed for positive values to prevent
            # misinterpretation as a negative number by the ASN.1 parser.
            if val_bytes[0] & 0x80:
                val_bytes = b'\x00' + val_bytes
        
        length_bytes = len(val_bytes).to_bytes(1, 'big')
        return bytes([tag]) + length_bytes + val_bytes

    def _encode_asn1_payload(self, data_payload, stNum, sqNum):
        """Encodes the GOOSE APDU using ASN.1 TLV format. Handles bool and float types."""
        all_data_elements = b""
        for value in data_payload:
            if isinstance(value, bool):
                # ASN.1 Boolean: Tag 0x83, Length 1, Value 0x01 (True) or 0x00 (False)
                all_data_elements += b'\x83\x01' + (b'\x01' if value else b'\x00')
            elif isinstance(value, float):
                # ASN.1 FloatingPoint (32-bit): Tag 0x87, Length 4, Value (packed float)
                all_data_elements += b'\x87\x04' + struct.pack('!f', value)
        
        all_data_tlv = b'\xab' + bytes([len(all_data_elements)]) + all_data_elements

        now = datetime.now(timezone.utc)
        timestamp = int(now.timestamp())
        fractions = now.microsecond
        timestamp_bytes = struct.pack('!I', timestamp) + struct.pack('!I', fractions)

        gocbRef_tlv = b'\x80' + bytes([len(self.gocbRef)]) + self.gocbRef.encode('ascii')
        timeAllowedtoLive_tlv = b'\x81\x02' + struct.pack('!H', self.timeAllowedtoLive)
        datSet_tlv = b'\x82' + bytes([len(self.datSet)]) + self.datSet.encode('ascii')
        goID_tlv = b'\x83' + bytes([len(self.goID)]) + self.goID.encode('ascii')
        t_tlv = b'\x84\x08' + timestamp_bytes
        
        # FIX: Use the new robust integer encoding for stNum and sqNum
        stNum_tlv = self._encode_integer_tlv(0x85, stNum)
        sqNum_tlv = self._encode_integer_tlv(0x86, sqNum)

        test_tlv = b'\x87\x01\x00'
        confRev_tlv = b'\x88\x01' + bytes([self.confRev])
        ndsCom_tlv = b'\x89\x01\x00'
        numDatSetEntries_tlv = b'\x8a\x01' + bytes([len(data_payload)])

        apdu_content = (gocbRef_tlv + timeAllowedtoLive_tlv + datSet_tlv + goID_tlv +
                        t_tlv + stNum_tlv + sqNum_tlv + test_tlv + confRev_tlv +
                        ndsCom_tlv + numDatSetEntries_tlv + all_data_tlv)

        apdu_len = len(apdu_content)
        if apdu_len > 127:
            goose_pdu_tlv = b'\x61\x81' + bytes([apdu_len]) + apdu_content
        else:
            goose_pdu_tlv = b'\x61' + bytes([apdu_len]) + apdu_content

        appid = b'\x00\x01'
        length = struct.pack('!H', len(goose_pdu_tlv) + 4)
        reserved = b'\x00\x00\x00\x00'
        return appid + length + reserved + goose_pdu_tlv

    def _send_frame(self, goose_payload):
        """Constructs and sends an Ethernet frame."""
        ether_frame = Ether(src=self.src_mac, dst=self.dst_mac, type=self.eth_type) / Raw(load=goose_payload)
        try:
            sendp(ether_frame, iface=self.iface, verbose=False)
            return True, ""
        except Exception as e:
            return False, str(e)

    def publish_automatic(self, data_payload):
        """Publishes a single packet with automatic stNum/sqNum handling."""
        if data_payload != self.last_data_payload:
            self.stNum += 1
            self.sqNum = 0
            self.last_data_payload = data_payload
            status = f"State Change: stNum={self.stNum}, sqNum={self.sqNum}"
        else:
            self.sqNum += 1
            status = f"Heartbeat: stNum={self.stNum}, sqNum={self.sqNum}"

        goose_payload = self._encode_asn1_payload(data_payload, self.stNum, self.sqNum)
        success, err_msg = self._send_frame(goose_payload)
        
        if success:
            return f"Auto packet sent. {status}"
        else:
            return f"Error sending packet: {err_msg}"
            
    def set_manual_state(self, data_payload, stNum, sqNum):
        """Manually sets the publisher's internal state."""
        self.stNum = stNum
        self.sqNum = sqNum
        self.last_data_payload = data_payload
        return f"Publisher state manually set to: stNum={stNum}, sqNum={sqNum}"

    def publish_manual_increment(self, data_payload):
        """Publishes a packet using the current (manually set) state and increments sqNum."""
        goose_payload = self._encode_asn1_payload(data_payload, self.stNum, self.sqNum)
        success, err_msg = self._send_frame(goose_payload)
        
        if success:
            status = f"Manual packet sent: stNum={self.stNum}, sqNum={self.sqNum}"
            self.sqNum += 1 # Increment for the next packet in the burst
            return status
        else:
            return f"Error sending manual packet: {err_msg}"

# ==============================================================================
#  2. GOOSE DECODER LOGIC (Adapted for Threading)
# ==============================================================================
class SnifferWorker(QObject):
    """Worker object that runs scapy.sniff in a separate thread."""
    packet_decoded = pyqtSignal(str)
    def __init__(self, iface):
        super().__init__(); self.iface = iface; self.running = False
    def _parse_asn1_length(self, data):
        """Parses ASN.1 length field."""
        len_byte = data[0]
        if len_byte < 128: return (len_byte, 1)
        else:
            num_octets = len_byte & 0x7f
            length = int.from_bytes(data[1:1 + num_octets], 'big')
            return (length, 1 + num_octets)
    def _decode_goose_pdu(self, pdu_data):
        """Decodes the GOOSE PDU fields from raw bytes."""
        decoded_data = {}; i = 0
        while i < len(pdu_data):
            tag = pdu_data[i]; i += 1
            length, len_bytes_consumed = self._parse_asn1_length(pdu_data[i:]); i += len_bytes_consumed
            value_bytes = pdu_data[i:i + length]; i += length
            if tag == 0x80: decoded_data['gocbRef'] = value_bytes.decode('ascii', errors='ignore')
            elif tag == 0x81: decoded_data['timeAllowedtoLive'] = int.from_bytes(value_bytes, 'big')
            elif tag == 0x82: decoded_data['datSet'] = value_bytes.decode('ascii', errors='ignore')
            elif tag == 0x83: decoded_data['goID'] = value_bytes.decode('ascii', errors='ignore')
            elif tag == 0x84:
                seconds = int.from_bytes(value_bytes[:4], 'big'); fractions = int.from_bytes(value_bytes[4:8], 'big')
                dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds, microseconds=fractions)
                decoded_data['t'] = dt.isoformat()
            elif tag == 0x85: decoded_data['stNum'] = int.from_bytes(value_bytes, 'big')
            elif tag == 0x86: decoded_data['sqNum'] = int.from_bytes(value_bytes, 'big')
            elif tag == 0x87: decoded_data['test'] = bool(value_bytes[0])
            elif tag == 0x88: decoded_data['confRev'] = int.from_bytes(value_bytes, 'big')
            elif tag == 0x89: decoded_data['ndsCom'] = bool(value_bytes[0])
            elif tag == 0x8a: decoded_data['numDatSetEntries'] = int.from_bytes(value_bytes, 'big')
            elif tag == 0xab:
                decoded_data['allData'] = []
                j = 0
                while j < len(value_bytes):
                    data_tag = value_bytes[j]
                    data_len = value_bytes[j+1]
                    data_val = value_bytes[j+2:j+2+data_len]
                    if data_tag == 0x83: # Boolean
                        decoded_data['allData'].append(bool(data_val[0]))
                    elif data_tag == 0x87: # Floating Point
                        decoded_data['allData'].append(struct.unpack('!f', data_val)[0])
                    j += 2 + data_len
        return decoded_data
    def _process_packet(self, packet):
        """Callback function for each captured packet."""
        if Raw in packet:
            payload = packet[Raw].load; appid = int.from_bytes(payload[0:2], 'big'); apdu_data = payload[8:]
            if apdu_data[0] == 0x61:
                pdu_len, len_bytes = self._parse_asn1_length(apdu_data[1:])
                pdu_content = apdu_data[1 + len_bytes : 1 + len_bytes + pdu_len]
                decoded_pdu = self._decode_goose_pdu(pdu_content)
                output = f"-- GOOSE Packet --\n  Source MAC: {packet[Ether].src}\n  APPID:      {appid}\n" + "-"*20 + "\n"
                for key, value in decoded_pdu.items(): output += f"  {key:<18}: {value}\n"
                output += "\n"; self.packet_decoded.emit(output)

    @pyqtSlot()
    def run(self):
        """Starts the packet sniffer."""
        self.running = True
        try:
            # Loop with a timeout to prevent sniff from blocking indefinitely.
            # This allows the thread to check the 'self.running' flag periodically
            # and exit cleanly when stop() is called.
            while self.running:
                sniff(iface=self.iface, filter="ether proto 0x88b8", prn=self._process_packet, stop_filter=lambda p: not self.running, timeout=1)
        except Exception as e:
            # Log errors if necessary, e.g., if the interface goes down
            print(f"Sniffer error: {e}")
        finally:
            self.running = False
            
    def stop(self): 
        self.running = False

# ==============================================================================
#  3. MAIN GUI APPLICATION
# ==============================================================================
class MainWindow(QMainWindow):
    """Main application window."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GOOSE Publisher/Decoder Tool")
        self.setGeometry(100, 100, 800, 850) 
        self.publisher = None
        self.sniffer_thread = None
        self.sniffer_worker = None

        # --- THEME AND STYLING ---
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QGroupBox {
                background-color: #e0e8f0;
                border: 1px solid #c0c0c0;
                border-radius: 5px;
                margin-top: 1ex; 
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 3px;
                color: #000000; /* Ensure title font is black */
            }
            QLabel, QCheckBox {
                color: #000000; /* Ensure all labels and checkboxes have black font */
                font-weight: normal;
            }
            QLineEdit, QTextEdit {
                background-color: #ffffff;
                border: 1px solid #c0c0c0;
                border-radius: 4px;
                padding: 2px;
                color: #000000;
            }
            QPushButton {
                background-color: #0078d7;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #a0a0a0;
            }
            QTabWidget::pane {
                border-top: 1px solid #c0c0c0;
            }
            QTabBar::tab {
                background: #d0d0d0;
                border: 1px solid #c0c0c0;
                padding: 6px;
                border-bottom-left-radius: 4px;
                border-bottom-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #e0e8f0; /* Match group box color for selected tab */
                margin-bottom: -1px; 
            }
        """)

        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(10, 10, 10, 5) 
        main_layout.setSpacing(10)

        self.tabs = QTabWidget()
        self._create_publisher_tab()
        self._create_decoder_tab()
        
        main_layout.addWidget(self.tabs)

        credit_label = QLabel("<b>Developed by Sugandh Pratap</b>")
        credit_label.setStyleSheet("font-size: 12pt; color: #333333;") 
        credit_label.setAlignment(Qt.AlignmentFlag.AlignCenter) 
        main_layout.addWidget(credit_label)

        self.setCentralWidget(main_widget)

    def _create_publisher_tab(self):
        """Creates the UI for the GOOSE Publisher tab."""
        tab = QWidget(); layout = QVBoxLayout(tab)
        config_group = QGroupBox("Configuration"); config_layout = QGridLayout()
        self.iface_edit = QLineEdit("Ethernet"); self.src_mac_edit = QLineEdit("0c:c4:7a:52:15:2d"); self.dst_mac_edit = QLineEdit("01:0c:cd:01:28:50")
        self.gocb_ref_edit = QLineEdit("SERVER-GOOSELDevice1/LLN0$GO$CB_Goose_TRIP1"); self.dataset_edit = QLineEdit("SERVER-GOOSELDevice1/LLN0$Goose_TRIP1")
        self.goid_edit = QLineEdit("Goose_TRIP1")
        config_layout.addWidget(QLabel("Interface:"), 0, 0); config_layout.addWidget(self.iface_edit, 0, 1)
        config_layout.addWidget(QLabel("Source MAC:"), 1, 0); config_layout.addWidget(self.src_mac_edit, 1, 1)
        config_layout.addWidget(QLabel("Destination MAC:"), 2, 0); config_layout.addWidget(self.dst_mac_edit, 2, 1)
        config_layout.addWidget(QLabel("gocbRef:"), 3, 0); config_layout.addWidget(self.gocb_ref_edit, 3, 1)
        config_layout.addWidget(QLabel("datSet:"), 4, 0); config_layout.addWidget(self.dataset_edit, 4, 1)
        config_layout.addWidget(QLabel("goID:"), 5, 0); config_layout.addWidget(self.goid_edit, 5, 1)
        config_group.setLayout(config_layout)

        data_group = QGroupBox("Data Payload (Booleans)"); data_layout = QHBoxLayout()
        self.checkbox1 = QCheckBox("Boolean 1"); self.checkbox2 = QCheckBox("Boolean 2"); self.checkbox3 = QCheckBox("Boolean 3")
        data_layout.addWidget(self.checkbox1); data_layout.addWidget(self.checkbox2); data_layout.addWidget(self.checkbox3)
        data_group.setLayout(data_layout)

        # --- RMS Value Inclusion ---
        rms_group = QGroupBox("RMS Analog Values"); rms_layout = QGridLayout()
        self.include_rms_check = QCheckBox("Include RMS Values")
        self.ia_edit = QLineEdit("0.0"); self.ib_edit = QLineEdit("0.0"); self.ic_edit = QLineEdit("0.0")
        self.va_edit = QLineEdit("0.0"); self.vb_edit = QLineEdit("0.0"); self.vc_edit = QLineEdit("0.0")
        self.rms_edits = [self.ia_edit, self.ib_edit, self.ic_edit, self.va_edit, self.vb_edit, self.vc_edit]
        
        rms_layout.addWidget(self.include_rms_check, 0, 0, 1, 4)
        rms_layout.addWidget(QLabel("IA:"), 1, 0); rms_layout.addWidget(self.ia_edit, 1, 1)
        rms_layout.addWidget(QLabel("IB:"), 1, 2); rms_layout.addWidget(self.ib_edit, 1, 3)
        rms_layout.addWidget(QLabel("IC:"), 1, 4); rms_layout.addWidget(self.ic_edit, 1, 5)
        rms_layout.addWidget(QLabel("VA:"), 2, 0); rms_layout.addWidget(self.va_edit, 2, 1)
        rms_layout.addWidget(QLabel("VB:"), 2, 2); rms_layout.addWidget(self.vb_edit, 2, 3)
        rms_layout.addWidget(QLabel("VC:"), 2, 4); rms_layout.addWidget(self.vc_edit, 2, 5)
        rms_group.setLayout(rms_layout)
        self.include_rms_check.toggled.connect(self._toggle_rms_controls)
        self._toggle_rms_controls(False) # Initially disabled
        
        controls_group = QGroupBox("Publishing Controls"); controls_layout = QGridLayout()
        self.packet_count_edit = QLineEdit("1")
        self.manual_override_check = QCheckBox("Manual stNum/sqNum Override")
        self.manual_stnum_edit = QLineEdit("0"); self.manual_sqnum_edit = QLineEdit("0")
        self.manual_stnum_edit.setEnabled(False); self.manual_sqnum_edit.setEnabled(False)
        self.manual_override_check.toggled.connect(self._toggle_manual_controls)
        controls_layout.addWidget(QLabel("Packet Count:"), 0, 0); controls_layout.addWidget(self.packet_count_edit, 0, 1)
        controls_layout.addWidget(self.manual_override_check, 1, 0, 1, 2)
        controls_layout.addWidget(QLabel("Manual stNum:"), 2, 0); controls_layout.addWidget(self.manual_stnum_edit, 2, 1)
        controls_layout.addWidget(QLabel("Manual sqNum:"), 3, 0); controls_layout.addWidget(self.manual_sqnum_edit, 3, 1)
        controls_group.setLayout(controls_layout)

        self.publish_button = QPushButton("Publish GOOSE Event(s)"); self.publish_button.clicked.connect(self.publish_goose)
        self.publisher_log = QTextEdit(); self.publisher_log.setReadOnly(True)

        layout.addWidget(config_group); layout.addWidget(data_group); layout.addWidget(rms_group)
        layout.addWidget(controls_group); layout.addWidget(self.publish_button); 
        layout.addWidget(QLabel("Log:")); layout.addWidget(self.publisher_log)
        self.tabs.addTab(tab, "GOOSE Publisher")

    def _create_decoder_tab(self):
        """Creates the UI for the GOOSE Decoder tab."""
        tab = QWidget(); layout = QVBoxLayout(tab)
        self.decoder_iface_edit = QLineEdit("Ethernet"); button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Sniffing"); self.stop_button = QPushButton("Stop Sniffing")
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.start_button); button_layout.addWidget(self.stop_button)
        self.decoder_output = QTextEdit(); self.decoder_output.setReadOnly(True)
        self.decoder_output.setStyleSheet("font-family: 'Courier New', monospace; color: #000000;")
        layout.addWidget(QLabel("Interface:")); layout.addWidget(self.decoder_iface_edit)
        layout.addLayout(button_layout); layout.addWidget(self.decoder_output)
        self.start_button.clicked.connect(self.start_sniffing); self.stop_button.clicked.connect(self.stop_sniffing)
        self.tabs.addTab(tab, "GOOSE Decoder")
        
    def _toggle_manual_controls(self, checked):
        """Enables or disables the manual stNum/sqNum input fields."""
        self.manual_stnum_edit.setEnabled(checked); self.manual_sqnum_edit.setEnabled(checked)

    def _toggle_rms_controls(self, checked):
        """Enables or disables the RMS value input fields."""
        for edit in self.rms_edits:
            edit.setEnabled(checked)

    def publish_goose(self):
        """Handles the logic for the 'Publish' button click."""
        if not self.publisher or self.publisher.iface != self.iface_edit.text() or self.publisher.src_mac != self.src_mac_edit.text():
            try:
                self.publisher = GoosePublisher(
                    iface=self.iface_edit.text(), src_mac=self.src_mac_edit.text(), dst_mac=self.dst_mac_edit.text(),
                    gocbRef=self.gocb_ref_edit.text(), datSet=self.dataset_edit.text(), goID=self.goid_edit.text()
                )
                self.publisher_log.append("Publisher initialized/re-configured.")
            except Exception as e:
                self.publisher_log.append(f"Error initializing publisher: {e}")
                return

        # Build the data payload
        data_payload = [self.checkbox1.isChecked(), self.checkbox2.isChecked(), self.checkbox3.isChecked()]
        if self.include_rms_check.isChecked():
            try:
                rms_values = [float(edit.text()) for edit in self.rms_edits]
                data_payload.extend(rms_values)
            except ValueError:
                self.publisher_log.append("Error: All RMS values must be valid numbers (floats)."); return
        
        try: packet_count = int(self.packet_count_edit.text())
        except ValueError: self.publisher_log.append("Error: Packet count must be an integer."); return

        is_manual = self.manual_override_check.isChecked()

        if is_manual:
            try:
                stNum = int(self.manual_stnum_edit.text()); sqNum = int(self.manual_sqnum_edit.text())
            except ValueError: self.publisher_log.append("Error: Manual stNum/sqNum must be integers."); return
            status = self.publisher.set_manual_state(data_payload, stNum, sqNum)
            self.publisher_log.append(status)
        
        for i in range(packet_count):
            if is_manual:
                status = self.publisher.publish_manual_increment(data_payload)
            else:
                status = self.publisher.publish_automatic(data_payload)
            
            self.publisher_log.append(status)
            QApplication.processEvents() # Keep GUI responsive during burst

    def start_sniffing(self):
        """Starts the packet sniffing thread."""
        iface = self.decoder_iface_edit.text()
        self.decoder_output.clear(); self.decoder_output.append(f"Starting sniffer on interface '{iface}'...")
        self.sniffer_thread = QThread(); self.sniffer_worker = SnifferWorker(iface)
        self.sniffer_worker.moveToThread(self.sniffer_thread)
        self.sniffer_thread.started.connect(self.sniffer_worker.run)
        self.sniffer_worker.packet_decoded.connect(self.update_decoder_output)
        self.sniffer_thread.start()
        self.start_button.setEnabled(False); self.stop_button.setEnabled(True); self.decoder_iface_edit.setEnabled(False)

    def stop_sniffing(self):
        """Stops the packet sniffing thread."""
        if self.sniffer_worker: self.sniffer_worker.stop()
        if self.sniffer_thread: self.sniffer_thread.quit(); self.sniffer_thread.wait()
        self.decoder_output.append("\nSniffer stopped.")
        self.start_button.setEnabled(True); self.stop_button.setEnabled(False); self.decoder_iface_edit.setEnabled(True)

    @pyqtSlot(str)
    def update_decoder_output(self, text):
        """Appends decoded packet text to the output view."""
        self.decoder_output.append(text)
    def closeEvent(self, event):
        """Ensures the sniffer thread is stopped when closing the application."""
        self.stop_sniffing(); event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
