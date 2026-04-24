#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SV Scout - Sampled Values Visualization Tool
IEC 61850-9-2LE Sampled Values Analyzer

Features:
1. Simultaneous investigation of multiple SV streams (IEC 61850)
2. Support for 9-2LE with 80 and 256 samples per cycle
3. RMS and phase angle calculation (phasor diagram)
4. COMTRADE recording
5. Detailed stream information (zero crossings, individual values, etc.)
"""

import sys
import struct
import socket
import threading
import time
import math
from datetime import datetime
from collections import deque

import numpy as np
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTabWidget, QPushButton, QLabel, 
                             QTableWidget, QTableWidgetItem, QHeaderView,
                             QGroupBox, QSpinBox, QComboBox, QFileDialog,
                             QMessageBox, QTextEdit, QSplitter, QFrame,
                             QCheckBox, QLineEdit)
from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal, QDateTime
from PyQt5.QtGui import QFont, QColor, QPainter, QPen, QBrush

try:
    from scapy.all import sniff, Ether, IP, UDP, Raw, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# IEC 61850-9-2LE Constants
ETHER_TYPE_SV = 0x88BA
APPID_SV = 0x4A00  # Standard SV APPID range

# IEC 61850-9-2LE Ethernet Header (14 bytes) + VLAN (4 bytes) = 18 bytes
# Destination MAC: 01-0C-CD-04-xx-xx (multicast)
# Source MAC: 6 bytes
# VLAN Tag: 0x8100 (4 bytes) - optional
# EtherType: 0x88BA (2 bytes)

class SVStream:
    """Represents a single Sampled Values stream"""
    
    def __init__(self, stream_id):
        self.stream_id = stream_id
        self.mac_address = None
        self.appid = None
        self.sv_id = ""
        self.datset = ""
        self.conf_rev = 0
        self.nb_samples = 80  # 80 or 256 samples per cycle
        self.samples_per_cycle = 80
        self.smp_cnt = 0
        self.smp_synch = True
        self.data_quality = {}
        
        # Channel data
        self.channels = []  # List of channel names
        self.channel_data = {}  # Latest values for each channel
        self.sample_buffers = {}  # Buffer for RMS/phasor calculation
        
        # Timing
        self.last_sample_time = None
        self.sample_rate = 4000  # Default 80 samples * 50 Hz
        self.frequency = 50.0
        
        # Statistics
        self.packets_received = 0
        self.lost_packets = 0
        self.start_time = None
        
    def add_channel(self, name, ph_type="MV"):
        """Add a measurement channel"""
        self.channels.append(name)
        self.channel_data[name] = {
            'value': 0.0,
            'scale_factor': 1.0,
            'offset': 0.0,
            'unit': 'V' if 'U' in name.upper() else 'A',
            'samples': deque(maxlen=self.samples_per_cycle),
            'rms': 0.0,
            'phase': 0.0,
            'zero_crossings': []
        }
        self.sample_buffers[name] = deque(maxlen=self.samples_per_cycle)


class SVPacketParser:
    """Parser for IEC 61850-9-2LE packets"""
    
    @staticmethod
    def parse_ethernet_header(data):
        """Parse Ethernet header and return payload"""
        if len(data) < 14:
            return None, None, None
            
        dst_mac = data[0:6]
        src_mac = data[6:12]
        ether_type = struct.unpack('!H', data[12:14])[0]
        
        offset = 14
        
        # Check for VLAN tag
        if ether_type == 0x8100 and len(data) >= 18:
            vlan_tag = struct.unpack('!H', data[14:16])[0]
            ether_type = struct.unpack('!H', data[16:18])[0]
            offset = 18
        
        return dst_mac, src_mac, ether_type, offset
    
    @staticmethod
    def parse_asdu(data, offset):
        """Parse ASDU (Application Service Data Unit)"""
        if len(data) < offset + 12:
            return None
            
        # ASDU structure (IEC 61850-9-2):
        # svID (OctetString 65 bytes max, but typically shorter)
        # smpCnt (UINT16)
        # confRev (UINT32)
        # smpSynch (BOOLEAN + padding)
        # DataSets
        
        asdu_start = offset
        return data[asdu_start:]
    
    @staticmethod
    def parse_9_2le(data, offset):
        """
        Parse IEC 61850-9-2LE specific format
        Returns dictionary with parsed values
        """
        result = {
            'smp_cnt': 0,
            'conf_rev': 0,
            'smp_synch': True,
            'channels': []
        }
        
        if len(data) < offset + 8:
            return None
        
        # Skip to sample count (after svID which varies)
        # In 9-2LE implementation guide format:
        # The structure is more fixed than full 9-2
        
        try:
            # Find sample count - typically at fixed offset in 9-2LE
            # This is simplified - real parsing depends on exact configuration
            idx = offset
            
            # Look for typical 9-2LE structure
            # After Ethernet headers, we have ASN.1 BER encoded data
            
            # For 9-2LE UCA implementation guide:
            # Fixed structure with known channel order
            
            # Sample count is usually around byte 40-50
            # Let's search for it
            while idx < len(data) - 2:
                # Look for sample count pattern
                if data[idx:idx+2] == b'\x02\x02':  # INTEGER 2 bytes
                    result['smp_cnt'] = struct.unpack('!H', data[idx+2:idx+4])[0]
                    break
                idx += 1
            
            # Parse measured values (currents and voltages)
            # 9-2LE typically has: Ia, Ib, Ic, In, Ua, Ub, Uc, Un
            channels = ['Ia', 'Ib', 'Ic', 'In', 'Ua', 'Ub', 'Uc', 'Un']
            
            idx = offset
            value_idx = 0
            
            while idx < len(data) - 6 and value_idx < len(channels):
                # Look for INTEGER or FLOAT encoding
                if data[idx] == 0x02:  # INTEGER
                    if idx + 5 < len(data):
                        val_len = data[idx + 1]
                        if val_len == 4:
                            val = struct.unpack('!i', data[idx+2:idx+6])[0]
                            result['channels'].append({
                                'name': channels[value_idx] if value_idx < len(channels) else f'CH{value_idx}',
                                'value': val,
                                'type': 'INT32'
                            })
                            value_idx += 1
                            idx += 6
                            continue
                elif data[idx] == 0x09:  # FLOAT32
                    if idx + 5 < len(data):
                        val = struct.unpack('!f', data[idx+2:idx+6])[0]
                        result['channels'].append({
                            'name': channels[value_idx] if value_idx < len(channels) else f'CH{value_idx}',
                            'value': val,
                            'type': 'FLOAT32'
                        })
                        value_idx += 1
                        idx += 6
                        continue
                elif data[idx] == 0x0A:  # FLOAT64
                    if idx + 9 < len(data):
                        val = struct.unpack('!d', data[idx+2:idx+10])[0]
                        result['channels'].append({
                            'name': channels[value_idx] if value_idx < len(channels) else f'CH{value_idx}',
                            'value': val,
                            'type': 'FLOAT64'
                        })
                        value_idx += 1
                        idx += 10
                        continue
                
                idx += 1
            
        except Exception as e:
            print(f"Error parsing 9-2LE: {e}")
            return None
        
        return result


class SVReceiver(QThread):
    """Thread for receiving SV packets"""
    
    packet_received = pyqtSignal(dict, str)  # parsed_data, stream_id
    status_update = pyqtSignal(str)
    
    def __init__(self, interface=None, multicast_groups=None):
        super().__init__()
        self.interface = interface
        self.multicast_groups = multicast_groups or []
        self.running = False
        self.socket_fd = None
        self.packets_count = 0
        
    def run(self):
        """Main receiver loop"""
        self.running = True
        self.status_update.emit("Starting SV receiver...")
        
        if not SCAPY_AVAILABLE:
            self.status_update.emit("Scapy not available, using demo mode")
            self.run_demo_mode()
            return
        
        try:
            # Setup packet capture
            if self.multicast_groups:
                # Join multicast groups
                for group in self.multicast_groups:
                    self.join_multicast(group)
            
            # Use scapy for packet capture
            def packet_callback(pkt):
                if not self.running:
                    return
                    
                self.packets_count += 1
                try:
                    if pkt.haslayer(Raw):
                        raw_data = bytes(pkt[Raw].load)
                        parsed = self.parse_packet(raw_data)
                        if parsed:
                            stream_id = parsed.get('stream_id', 'unknown')
                            self.packet_received.emit(parsed, stream_id)
                except Exception as e:
                    print(f"Error processing packet: {e}")
            
            # Start sniffing
            filter_str = "ether proto 0x88ba"
            self.status_update.emit(f"Listening on {self.interface or 'all interfaces'}...")
            
            sniff(
                iface=self.interface,
                filter=filter_str,
                prn=packet_callback,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.status_update.emit(f"Error: {str(e)}")
            self.run_demo_mode()
    
    def join_multicast(self, group_ip):
        """Join a multicast group"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Join the group
            group = socket.inet_aton(group_ip)
            if self.interface:
                mreq = group + socket.inet_aton(self.interface)
            else:
                mreq = group + struct.pack('!I', socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            self.socket_fd = sock
        except Exception as e:
            print(f"Failed to join multicast {group_ip}: {e}")
    
    def parse_packet(self, data):
        """Parse SV packet"""
        parser = SVPacketParser()
        
        # Parse Ethernet header
        result = parser.parse_ethernet_header(data)
        if result is None or len(result) < 4:
            return None
            
        dst_mac, src_mac, ether_type, offset = result
        
        if ether_type != ETHER_TYPE_SV:
            return None
        
        # Create stream ID from source MAC
        stream_id = ':'.join(f'{b:02x}' for b in src_mac)
        
        # Parse 9-2LE data
        sv_data = parser.parse_9_2le(data, offset)
        if sv_data is None:
            return None
        
        sv_data['stream_id'] = stream_id
        sv_data['src_mac'] = stream_id
        sv_data['timestamp'] = time.time()
        
        return sv_data
    
    def run_demo_mode(self):
        """Run in demo mode generating synthetic data"""
        self.status_update.emit("Running in DEMO mode with synthetic data")
        
        # Generate synthetic SV data for demonstration
        frequency = 50.0
        samples_per_cycle = 80
        sample_rate = frequency * samples_per_cycle
        
        t = 0
        stream_id = "demo:stream:001"
        
        while self.running:
            # Generate synthetic currents and voltages
            timestamp = time.time()
            
            # Create synthetic measurements
            channels = []
            
            # Currents (with some harmonics for realism)
            for i, phase in enumerate(['Ia', 'Ib', 'Ic']):
                angle = 2 * math.pi * frequency * t + (i * 2 * math.pi / 3)
                value = int(1000 * math.sin(angle) + 50 * math.sin(3 * angle))
                channels.append({'name': phase, 'value': value, 'type': 'INT32'})
            
            # Neutral current
            channels.append({'name': 'In', 'value': 0, 'type': 'INT32'})
            
            # Voltages
            for i, phase in enumerate(['Ua', 'Ub', 'Uc']):
                angle = 2 * math.pi * frequency * t + (i * 2 * math.pi / 3)
                value = int(10000 * math.sin(angle))
                channels.append({'name': phase, 'value': value, 'type': 'INT32'})
            
            # Neutral voltage
            channels.append({'name': 'Un', 'value': 0, 'type': 'INT32'})
            
            parsed = {
                'stream_id': stream_id,
                'smp_cnt': int(t * sample_rate) % 65536,
                'conf_rev': 1,
                'smp_synch': True,
                'channels': channels,
                'timestamp': timestamp,
                'samples_per_cycle': samples_per_cycle
            }
            
            self.packet_received.emit(parsed, stream_id)
            
            t += 1.0 / sample_rate
            time.sleep(1.0 / sample_rate)
    
    def stop(self):
        """Stop the receiver"""
        self.running = False
        if self.socket_fd:
            try:
                self.socket_fd.close()
            except:
                pass
        self.wait(1000)


class PhasorWidget(QWidget):
    """Widget for displaying phasor diagram"""
    
    def __init__(self):
        super().__init__()
        self.setMinimumSize(300, 300)
        self.phasors = []  # List of (magnitude, phase, color, label)
        self.reference_phase = 0
        
    def set_phasors(self, phasors):
        """Set phasors to display: [(mag, phase, color, label), ...]"""
        self.phasors = phasors
        self.update()
    
    def paintEvent(self, event):
        """Paint the phasor diagram"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        width = self.width()
        height = self.height()
        center_x = width // 2
        center_y = height // 2
        radius = min(width, height) // 2 - 40
        
        # Draw background
        painter.fillRect(self.rect(), QColor(255, 255, 255))
        
        # Draw coordinate system
        pen = QPen(QColor(200, 200, 200))
        painter.setPen(pen)
        
        # Grid circles
        for i in range(1, 4):
            r = radius * i // 3
            painter.drawEllipse(center_x - r, center_y - r, 2*r, 2*r)
        
        # Axes
        pen = QPen(QColor(150, 150, 150))
        painter.setPen(pen)
        painter.drawLine(center_x - radius, center_y, center_x + radius, center_y)
        painter.drawLine(center_x, center_y - radius, center_x, center_y + radius)
        
        # Labels
        painter.setPen(QColor(100, 100, 100))
        painter.drawText(center_x + radius + 5, center_y + 5, "Re")
        painter.drawText(center_x + 5, center_y - radius - 5, "Im")
        
        # Draw phasors
        for mag, phase, color, label in self.phasors:
            # Adjust phase relative to reference
            adjusted_phase = phase - self.reference_phase
            
            # Calculate endpoint
            x = center_x + radius * (mag / 100.0) * math.cos(math.radians(adjusted_phase))
            y = center_y - radius * (mag / 100.0) * math.sin(math.radians(adjusted_phase))
            
            # Draw line
            pen = QPen(QColor(color), 2)
            painter.setPen(pen)
            painter.drawLine(center_x, center_y, int(x), int(y))
            
            # Draw arrowhead
            angle = math.radians(adjusted_phase)
            arrow_size = 10
            arrow_x1 = x - arrow_size * math.cos(angle - math.pi/6)
            arrow_y1 = y + arrow_size * math.sin(angle - math.pi/6)
            arrow_x2 = x - arrow_size * math.cos(angle + math.pi/6)
            arrow_y2 = y + arrow_size * math.sin(angle + math.pi/6)
            
            painter.drawLine(int(x), int(y), int(arrow_x1), int(arrow_y1))
            painter.drawLine(int(x), int(y), int(arrow_x2), int(arrow_y2))
            
            # Draw label
            painter.setPen(QColor(color))
            painter.drawText(int(x) + 10, int(y), label)
        
        # Draw title
        painter.setPen(QColor(0, 0, 0))
        painter.setFont(QFont("Arial", 10))
        painter.drawText(10, 20, "Phasor Diagram")


class WaveformWidget(QWidget):
    """Widget for displaying waveform"""
    
    def __init__(self):
        super().__init__()
        self.setMinimumSize(400, 200)
        self.samples = {}  # channel_name -> list of samples
        self.colors = {
            'Ia': '#FF0000', 'Ib': '#00FF00', 'Ic': '#0000FF',
            'Ua': '#FF8800', 'Ub': '#88FF00', 'Uc': '#0088FF',
            'default': '#000000'
        }
        
    def set_samples(self, channel_name, samples):
        """Set samples for a channel"""
        self.samples[channel_name] = samples
        self.update()
    
    def paintEvent(self, event):
        """Paint the waveform"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        width = self.width()
        height = self.height()
        margin = 40
        
        # Draw background
        painter.fillRect(self.rect(), QColor(250, 250, 250))
        
        if not self.samples:
            painter.setPen(QColor(100, 100, 100))
            painter.drawText(width//2 - 50, height//2, "No data")
            return
        
        # Draw grid
        painter.setPen(QPen(QColor(200, 200, 200), 1))
        for i in range(5):
            y = margin + (height - 2*margin) * i // 4
            painter.drawLine(margin, y, width - margin, y)
        
        # Draw waveforms
        plot_width = width - 2*margin
        plot_height = height - 2*margin
        center_y = height // 2
        
        for channel_name, samples in self.samples.items():
            if not samples:
                continue
                
            color = self.colors.get(channel_name, self.colors['default'])
            pen = QPen(QColor(color), 2)
            painter.setPen(pen)
            
            # Draw points
            num_samples = len(samples)
            if num_samples < 2:
                continue
            
            points = []
            for i, sample in enumerate(samples):
                x = margin + (i / (num_samples - 1)) * plot_width
                # Normalize sample value to plot area
                max_val = max(abs(s) for s in samples) or 1
                y = center_y - (sample / max_val) * (plot_height / 2)
                points.append((int(x), int(y)))
            
            # Draw lines between points
            for j in range(len(points) - 1):
                painter.drawLine(points[j][0], points[j][1], 
                               points[j+1][0], points[j+1][1])
        
        # Draw axes labels
        painter.setPen(QColor(0, 0, 0))
        painter.drawText(5, height//2, "Amplitude")
        painter.drawText(width//2, height - 5, "Sample Index")


class ComtradeWriter:
    """Writer for COMTRADE files (IEEE C37.111)"""
    
    @staticmethod
    def write_cfg(filename, streams, start_time, end_time, frequency=50):
        """Write COMTRADE configuration file"""
        cfg_content = f"""{filename.split('/')[-1].replace('.cfg', '')},P
1,{len(streams[0]['channels']) if streams else 0}
"""
        # Add channel definitions
        ch_num = 1
        for stream in streams:
            for ch in stream.get('channels', []):
                ch_name = ch.get('name', f'CH{ch_num}')
                ch_type = 'A' if 'I' in ch_name.upper() else 'V'
                cfg_content += f"{ch_num},{ch_name},{ch_type},R,{ch_num},1,1,1,1,1\n"
                ch_num += 1
        
        cfg_content += f"""{start_time.strftime('%d/%m/%Y,%H:%M:%S.%f')[:-3]}
{end_time.strftime('%d/%m/%Y,%H:%M:%S.%f')[:-3]}
F,{frequency}
L,L,{len(streams)},1
32-bit IEEE floating point
"""
        
        with open(filename, 'w') as f:
            f.write(cfg_content)
    
    @staticmethod
    def write_dat(filename, streams):
        """Write COMTRADE data file"""
        # Binary format with quality and timestamp
        with open(filename, 'wb') as f:
            for stream in streams:
                for ch in stream.get('channels', []):
                    val = float(ch.get('value', 0))
                    f.write(struct.pack('f', val))


class SVScoutWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SV Scout - Sampled Values Analyzer")
        self.setGeometry(100, 100, 1400, 900)
        
        # Data storage
        self.streams = {}  # stream_id -> SVStream
        self.recent_samples = deque(maxlen=1000)
        self.comtrade_data = []
        
        # Receiver thread
        self.receiver = None
        
        # UI setup
        self.init_ui()
        
        # Timer for UI updates
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_ui)
        self.update_timer.start(100)
        
    def init_ui(self):
        """Initialize user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        
        # Control panel
        control_group = QGroupBox("Control Panel")
        control_layout = QHBoxLayout()
        
        # Interface selection
        control_layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        if SCAPY_AVAILABLE:
            interfaces = get_if_list()
            self.interface_combo.addItems(interfaces)
        self.interface_combo.addItem("Demo Mode")
        control_layout.addWidget(self.interface_combo)
        
        # Multicast group
        control_layout.addWidget(QLabel("Multicast IP:"))
        self.multicast_edit = QLineEdit("01.0C.CD.04.00.01")
        self.multicast_edit.setMaximumWidth(150)
        control_layout.addWidget(self.multicast_edit)
        
        # Samples per cycle
        control_layout.addWidget(QLabel("Samples/Cycle:"))
        self.samples_combo = QComboBox()
        self.samples_combo.addItems(["80", "256"])
        control_layout.addWidget(self.samples_combo)
        
        # Start/Stop buttons
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.clicked.connect(self.start_capture)
        control_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Capture")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)
        
        control_group.setLayout(control_layout)
        main_layout.addWidget(control_group)
        
        # Tab widget for different views
        self.tabs = QTabWidget()
        
        # Waveform tab
        waveform_tab = QWidget()
        waveform_layout = QVBoxLayout(waveform_tab)
        self.waveform_widget = WaveformWidget()
        waveform_layout.addWidget(self.waveform_widget)
        self.tabs.addTab(waveform_tab, "Waveforms")
        
        # Phasor diagram tab
        phasor_tab = QWidget()
        phasor_layout = QVBoxLayout(phasor_tab)
        self.phasor_widget = PhasorWidget()
        phasor_layout.addWidget(self.phasor_widget)
        
        # Phasor table
        self.phasor_table = QTableWidget()
        self.phasor_table.setColumnCount(5)
        self.phasor_table.setHorizontalHeaderLabels(["Channel", "RMS", "Phase (°)", "Frequency", "Quality"])
        self.phasor_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        phasor_layout.addWidget(self.phasor_table)
        
        self.tabs.addTab(phasor_tab, "Phasors")
        
        # Detail view tab
        detail_tab = QWidget()
        detail_layout = QVBoxLayout(detail_tab)
        
        # Stream info
        self.stream_info = QTextEdit()
        self.stream_info.setReadOnly(True)
        self.stream_info.setMaximumHeight(150)
        detail_layout.addWidget(self.stream_info)
        
        # Sample details table
        self.sample_table = QTableWidget()
        self.sample_table.setColumnCount(4)
        self.sample_table.setHorizontalHeaderLabels(["Channel", "Value", "Type", "Zero Crossing"])
        self.sample_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        detail_layout.addWidget(self.sample_table)
        
        self.tabs.addTab(detail_tab, "Details")
        
        # Recording tab
        record_tab = QWidget()
        record_layout = QVBoxLayout(record_tab)
        
        self.record_info = QTextEdit()
        self.record_info.setReadOnly(True)
        self.record_info.setText("Recording Status: Idle\nFiles saved: 0")
        record_layout.addWidget(self.record_info)
        
        record_btn_layout = QHBoxLayout()
        
        self.record_comtrade_btn = QPushButton("Save to COMTRADE")
        self.record_comtrade_btn.clicked.connect(self.save_comtrade)
        record_btn_layout.addWidget(self.record_comtrade_btn)
        
        self.auto_record_check = QCheckBox("Auto-record")
        record_btn_layout.addWidget(self.auto_record_check)
        
        record_layout.addLayout(record_btn_layout)
        record_layout.addStretch()
        
        self.tabs.addTab(record_tab, "Recording")
        
        # Status log tab
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        self.tabs.addTab(log_tab, "Log")
        
        main_layout.addWidget(self.tabs)
        
        # Status bar
        self.statusBar().showMessage("Ready - Select interface and start capture")
        
    def log_message(self, message):
        """Add message to log"""
        timestamp = QDateTime.currentDateTime().toString("HH:mm:ss.zzz")
        self.log_text.append(f"[{timestamp}] {message}")
        
    def start_capture(self):
        """Start capturing SV packets"""
        interface = self.interface_combo.currentText()
        samples_per_cycle = int(self.samples_combo.currentText())
        
        if interface == "Demo Mode":
            interface = None
        
        self.receiver = SVReceiver(interface=interface if interface != "all" else None)
        self.receiver.packet_received.connect(self.on_packet_received)
        self.receiver.status_update.connect(self.log_message)
        self.receiver.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.interface_combo.setEnabled(False)
        
        self.log_message(f"Started capture on {interface or 'Demo Mode'}")
        self.statusBar().showMessage("Capturing...")
        
    def stop_capture(self):
        """Stop capturing"""
        if self.receiver:
            self.receiver.stop()
            self.receiver = None
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.interface_combo.setEnabled(True)
        
        self.log_message("Capture stopped")
        self.statusBar().showMessage("Stopped")
        
    def on_packet_received(self, parsed_data, stream_id):
        """Handle received SV packet"""
        # Store recent samples
        self.recent_samples.append(parsed_data)
        
        # Update or create stream
        if stream_id not in self.streams:
            self.streams[stream_id] = SVStream(stream_id)
            self.log_message(f"New stream detected: {stream_id}")
        
        stream = self.streams[stream_id]
        stream.packets_received += 1
        
        if stream.start_time is None:
            stream.start_time = datetime.now()
        
        # Update stream info
        stream.smp_cnt = parsed_data.get('smp_cnt', 0)
        stream.conf_rev = parsed_data.get('conf_rev', 0)
        stream.smp_synch = parsed_data.get('smp_synch', True)
        
        # Update channel data
        for ch in parsed_data.get('channels', []):
            ch_name = ch.get('name', 'Unknown')
            ch_value = ch.get('value', 0)
            
            if ch_name not in stream.channel_data:
                stream.add_channel(ch_name)
            
            stream.channel_data[ch_name]['value'] = ch_value
            stream.channel_data[ch_name]['samples'].append(ch_value)
            
            # Calculate zero crossings
            samples = list(stream.channel_data[ch_name]['samples'])
            if len(samples) > 1:
                if samples[-2] <= 0 < samples[-1]:
                    stream.channel_data[ch_name]['zero_crossings'].append(
                        len(samples) - 1
                    )
        
        # Store for COMTRADE
        self.comtrade_data.append({
            'timestamp': parsed_data.get('timestamp', time.time()),
            'stream_id': stream_id,
            'channels': parsed_data.get('channels', [])
        })
        
    def calculate_rms_and_phase(self, samples, frequency=50):
        """Calculate RMS and phase angle from samples"""
        if not samples or len(samples) < 2:
            return 0.0, 0.0
        
        samples_array = np.array(samples, dtype=float)
        
        # RMS calculation
        rms = np.sqrt(np.mean(samples_array ** 2))
        
        # Phase calculation using DFT at fundamental frequency
        n = len(samples_array)
        k = 1  # Fundamental frequency bin
        
        # Apply window function (Hanning)
        window = np.hanning(n)
        windowed = samples_array * window
        
        # DFT at fundamental
        real_sum = np.sum(windowed * np.cos(2 * np.pi * k * np.arange(n) / n))
        imag_sum = np.sum(windowed * np.sin(2 * np.pi * k * np.arange(n) / n))
        
        phase = -math.degrees(math.atan2(imag_sum, real_sum))
        
        return rms, phase
    
    def update_ui(self):
        """Update UI with latest data"""
        if not self.recent_samples:
            return
        
        # Get most recent sample
        latest = self.recent_samples[-1]
        
        # Update waveform
        for ch in latest.get('channels', []):
            ch_name = ch.get('name', '')
            # Collect last N samples for this channel
            samples = [s.get('value', 0) for s in self.recent_samples 
                      if any(c.get('name') == ch_name for c in s.get('channels', []))]
            if samples:
                self.waveform_widget.set_samples(ch_name, samples[-80:])
        
        # Update phasor table and diagram
        phasors = []
        colors = {'Ia': 'red', 'Ib': 'green', 'Ic': 'blue', 
                  'Ua': 'orange', 'Ub': 'lime', 'Uc': 'cyan'}
        
        self.phasor_table.setRowCount(0)
        
        for ch in latest.get('channels', []):
            ch_name = ch.get('name', '')
            stream_id = latest.get('stream_id', '')
            
            if stream_id in self.streams:
                stream = self.streams[stream_id]
                if ch_name in stream.channel_data:
                    samples = list(stream.channel_data[ch_name]['samples'])
                    
                    if len(samples) >= 10:
                        rms, phase = self.calculate_rms_and_phase(samples)
                        
                        # Scale RMS based on channel type
                        if 'I' in ch_name.upper():
                            rms_scaled = rms / 1000.0  # Assume 1000:1 CT ratio
                        else:
                            rms_scaled = rms / 100.0  # Assume 100:1 VT ratio
                        
                        # Add to phasor diagram
                        color = colors.get(ch_name, 'black')
                        phasors.append((min(rms_scaled, 100), phase, color, ch_name))
                        
                        # Add to table
                        row = self.phasor_table.rowCount()
                        self.phasor_table.insertRow(row)
                        self.phasor_table.setItem(row, 0, QTableWidgetItem(ch_name))
                        self.phasor_table.setItem(row, 1, QTableWidgetItem(f"{rms_scaled:.2f}"))
                        self.phasor_table.setItem(row, 2, QTableWidgetItem(f"{phase:.1f}"))
                        self.phasor_table.setItem(row, 3, QTableWidgetItem(f"{latest.get('frequency', 50):.1f}"))
                        self.phasor_table.setItem(row, 4, QTableWidgetItem("Good"))
        
        self.phasor_widget.set_phasors(phasors[:6])  # Show up to 6 phasors
        
        # Update detail view
        self.sample_table.setRowCount(0)
        for ch in latest.get('channels', []):
            ch_name = ch.get('name', '')
            ch_value = ch.get('value', 0)
            ch_type = ch.get('type', 'Unknown')
            
            row = self.sample_table.rowCount()
            self.sample_table.insertRow(row)
            self.sample_table.setItem(row, 0, QTableWidgetItem(ch_name))
            self.sample_table.setItem(row, 1, QTableWidgetItem(str(ch_value)))
            self.sample_table.setItem(row, 2, QTableWidgetItem(ch_type))
            
            # Check for zero crossing
            zero_crossing = "Yes" if any(
                abs(ch_value) < 100 for ch in latest.get('channels', [])
                if ch.get('name') == ch_name
            ) else "No"
            self.sample_table.setItem(row, 3, QTableWidgetItem(zero_crossing))
        
        # Update stream info
        info_text = f"Stream ID: {latest.get('stream_id', 'N/A')}\n"
        info_text += f"Sample Count: {latest.get('smp_cnt', 0)}\n"
        info_text += f"Config Revision: {latest.get('conf_rev', 0)}\n"
        info_text += f"Synchronized: {latest.get('smp_synch', False)}\n"
        info_text += f"Timestamp: {datetime.fromtimestamp(latest.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n"
        self.stream_info.setText(info_text)
        
        # Update status bar
        total_packets = sum(s.packets_received for s in self.streams.values())
        self.statusBar().showMessage(f"Packets: {total_packets} | Streams: {len(self.streams)}")
        
    def save_comtrade(self):
        """Save captured data to COMTRADE format"""
        if not self.comtrade_data:
            QMessageBox.warning(self, "No Data", "No data to save!")
            return
        
        # File dialog
        options = QFileDialog.Options()
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save COMTRADE", "", 
            "COMTRADE Files (*.cfg);;All Files (*)",
            options=options
        )
        
        if not filename:
            return
        
        try:
            # Write CFG file
            ComtradeWriter.write_cfg(
                filename,
                self.comtrade_data[-100:],  # Last 100 samples
                datetime.fromtimestamp(self.comtrade_data[0]['timestamp']),
                datetime.fromtimestamp(self.comtrade_data[-1]['timestamp'])
            )
            
            # Write DAT file
            dat_filename = filename.replace('.cfg', '.dat')
            ComtradeWriter.write_dat(dat_filename, self.comtrade_data[-100:])
            
            self.record_info.append(f"Saved: {filename}")
            self.record_info.append(f"Saved: {dat_filename}")
            self.log_message(f"COMTRADE files saved: {filename}")
            
            QMessageBox.information(self, "Success", f"COMTRADE files saved:\n{filename}\n{dat_filename}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save COMTRADE: {str(e)}")
            self.log_message(f"COMTRADE save error: {str(e)}")


def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = SVScoutWindow()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
