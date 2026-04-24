#!/usr/bin/env python3
"""
IEC 61850 Sampled Values Visualizer

A PyQt5-based application for visualizing IEC 61850 Sampled Values (SV) streams.
Features:
- Network interface selection
- SV stream discovery and selection
- Real-time data visualization
- Phasor diagram
- Detailed stream information
"""

import sys
import os
import json
import socket
import struct
from datetime import datetime
from collections import deque

import numpy as np
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QTabWidget, QTextEdit, QGroupBox,
    QGridLayout, QSplitter, QMessageBox, QFrame, QScrollArea
)
from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QPainter, QPen

# Try to import matplotlib for plotting
try:
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Warning: matplotlib not available, plots will be disabled")

# Try to import pyiec61850
try:
    import pyiec61850 as iec61850
    PYIEC61850_AVAILABLE = True
except ImportError:
    PYIEC61850_AVAILABLE = False
    print("Warning: pyiec61850 not available, using raw socket capture")


class SVStreamData:
    """Class to store SV stream data and metadata"""
    
    def __init__(self, stream_id, sv_id, app_id):
        self.stream_id = stream_id
        self.sv_id = sv_id
        self.app_id = app_id
        self.dat_set = ""
        self.smp_cnt = 0
        self.conf_rev = 0
        self.smp_mod = 0
        self.smp_rate = 0
        self.refr_tm = 0
        self.data_count = 0
        self.packet_count = 0
        self.data_values = []
        self.history = deque(maxlen=1000)  # Store historical data for plotting
        self.timestamps = deque(maxlen=1000)
        
    def update(self, data):
        """Update stream data from received packet"""
        self.sv_id = data.get('svId', self.sv_id)
        self.dat_set = data.get('datSet', self.dat_set)
        self.smp_cnt = data.get('smpCnt', self.smp_cnt)
        self.conf_rev = data.get('confRev', self.conf_rev)
        self.smp_mod = data.get('smpMod', self.smp_mod)
        self.smp_rate = data.get('smpRate', self.smp_rate)
        self.refr_tm = data.get('refrTm', self.refr_tm)
        self.data_count = data.get('dataCount', len(data.get('data', [])))
        self.packet_count = data.get('packets', self.packet_count + 1)
        self.data_values = data.get('data', [])
        
        # Store in history
        self.history.append(list(self.data_values))
        self.timestamps.append(datetime.now())


class SVCaptureThread(QThread):
    """Thread for capturing SV packets"""
    
    new_stream = pyqtSignal(dict)
    stream_update = pyqtSignal(int, dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, interface_name):
        super().__init__()
        self.interface_name = interface_name
        self.running = False
        self.streams = {}
        self.sock = None
        
    def run(self):
        """Main capture loop"""
        self.running = True
        
        if PYIEC61850_AVAILABLE:
            self._capture_with_libiec61850()
        else:
            self._capture_raw()
    
    def _capture_with_libiec61850(self):
        """Capture using libiec61850 library"""
        try:
            receiver = iec61850.SVReceiver_create()
            receiver.setInterfaceId(self.interface_name)
            
            # Create subscriber for all APPIDs
            subscriber = iec61850.SVSubscriber_create(None, 0)
            
            # We need a callback - use a simple approach
            def listener(sub, param, asdu):
                try:
                    sv_id = asdu.getSvId() if asdu.hasSvId() else "unknown"
                    app_id = sub.getAppID()
                    
                    stream_key = f"{sv_id}_{app_id}"
                    
                    if stream_key not in self.streams:
                        stream_data = {
                            'id': len(self.streams),
                            'svId': sv_id,
                            'appID': app_id,
                            'smpCnt': asdu.getSmpCnt(),
                            'confRev': asdu.getConfRev() if asdu.hasConfRev() else 0,
                            'smpMod': asdu.getSmpMod() if asdu.hasSmpMod() else 0,
                            'smpRate': asdu.getSmpRate() if asdu.hasSmpRate() else 0,
                            'refrTm': asdu.getRefrTmAsMs() if asdu.hasRefrTm() else 0,
                            'datSet': asdu.getDatSet() if asdu.hasDatSet() else "",
                            'dataCount': 0,
                            'packets': 1,
                            'data': []
                        }
                        
                        # Extract data values
                        data_size = asdu.getDataSize()
                        for i in range(min(data_size // 4, 32)):
                            try:
                                val = asdu.getFLOAT32(i * 4)
                                stream_data['data'].append(val)
                                stream_data['dataCount'] += 1
                            except:
                                break
                        
                        self.streams[stream_key] = stream_data
                        self.new_stream.emit(stream_data)
                    else:
                        # Update existing stream
                        stream_data = self.streams[stream_key]
                        stream_data['smpCnt'] = asdu.getSmpCnt()
                        stream_data['packets'] += 1
                        
                        # Update data values
                        data_size = asdu.getDataSize()
                        stream_data['data'] = []
                        for i in range(min(data_size // 4, 32)):
                            try:
                                val = asdu.getFLOAT32(i * 4)
                                stream_data['data'].append(val)
                            except:
                                break
                        stream_data['dataCount'] = len(stream_data['data'])
                        
                        self.stream_update.emit(stream_data['id'], stream_data)
                        
                except Exception as e:
                    self.error_occurred.emit(f"Error processing SV: {str(e)}")
            
            subscriber.setListener(listener, None)
            receiver.addSubscriber(subscriber)
            receiver.start()
            
            if receiver.isRunning():
                while self.running:
                    self.msleep(100)
                receiver.stop()
            
            receiver.destroy()
            
        except Exception as e:
            self.error_occurred.emit(f"libiec61850 error: {str(e)}")
    
    def _capture_raw(self):
        """Capture SV packets using raw sockets (fallback)"""
        try:
            # SV packets use Ethernet type 0x88CC
            ETH_P_SV = 0x88CC
            
            # Create raw socket
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_SV))
            self.sock.bind((self.interface_name, 0))
            self.sock.settimeout(1.0)
            
            stream_map = {}
            
            while self.running:
                try:
                    packet, addr = self.sock.recvfrom(65535)
                    
                    # Parse Ethernet header (14 bytes)
                    if len(packet) < 14:
                        continue
                    
                    dst_mac = packet[0:6]
                    src_mac = packet[6:12]
                    eth_type = struct.unpack('!H', packet[12:14])[0]
                    
                    # Check for SV ethertype (0x88CC)
                    if eth_type != 0x88CC:
                        continue
                    
                    # Parse SV APDU (simplified parsing)
                    payload = packet[14:]
                    if len(payload) < 20:
                        continue
                    
                    # Try to extract basic info
                    # In real implementation, proper ASN.1 BER decoding would be needed
                    sv_id = f"SV_{src_mac.hex()[:8]}"
                    app_id = 0x4000  # Default
                    
                    stream_key = f"{sv_id}_{app_id}"
                    
                    if stream_key not in stream_map:
                        stream_data = {
                            'id': len(stream_map),
                            'svId': sv_id,
                            'appID': app_id,
                            'smpCnt': 0,
                            'confRev': 0,
                            'smpMod': 0,
                            'smpRate': 0,
                            'refrTm': 0,
                            'datSet': '',
                            'dataCount': 0,
                            'packets': 1,
                            'data': [float(b) for b in payload[:32]]
                        }
                        stream_map[stream_key] = stream_data
                        self.new_stream.emit(stream_data)
                    else:
                        stream_data = stream_map[stream_key]
                        stream_data['packets'] += 1
                        self.stream_update.emit(stream_data['id'], stream_data)
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.error_occurred.emit(f"Socket error: {str(e)}")
                    break
                    
        except Exception as e:
            self.error_occurred.emit(f"Raw capture error: {str(e)}")
        finally:
            if self.sock:
                self.sock.close()
    
    def stop(self):
        """Stop the capture thread"""
        self.running = False
        self.wait(1000)


class PhasorPlot(QWidget):
    """Widget for displaying phasor diagram"""
    
    def __init__(self):
        super().__init__()
        self.setMinimumSize(300, 300)
        self.data_values = []
        self.setStyleSheet("background-color: white;")
        
    def set_data(self, values):
        """Set data values for phasor display"""
        self.data_values = values
        self.update()
    
    def paintEvent(self, event):
        """Draw phasor diagram"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        width = self.width()
        height = self.height()
        center_x = width // 2
        center_y = height // 2
        radius = min(width, height) // 2 - 20
        
        # Draw background circle
        painter.setPen(QPen(Qt.lightGray, 1))
        painter.drawEllipse(center_x - radius, center_y - radius, radius * 2, radius * 2)
        
        # Draw axes
        painter.setPen(QPen(Qt.black, 1))
        painter.drawLine(center_x - radius, center_y, center_x + radius, center_y)
        painter.drawLine(center_x, center_y - radius, center_x, center_y + radius)
        
        # Draw labels
        painter.drawText(center_x + radius + 5, center_y + 5, "Re")
        painter.drawText(center_x + 5, center_y - radius - 5, "Im")
        
        # Draw phasors (assume pairs of values represent magnitude/angle or complex)
        colors = [Qt.red, Qt.blue, Qt.green, Qt.magenta, Qt.cyan]
        
        for i, val in enumerate(self.data_values[:6]):  # Show max 6 phasors
            if isinstance(val, (int, float)):
                # Simple representation: value as magnitude, angle based on index
                magnitude = abs(val) / 100.0 * radius if abs(val) > 1 else abs(val) * radius
                angle = i * 60  # Distribute evenly
                
                # Convert polar to cartesian
                rad = np.radians(angle)
                x = center_x + magnitude * np.cos(rad)
                y = center_y - magnitude * np.sin(rad)
                
                painter.setPen(QPen(colors[i % len(colors)], 2))
                painter.drawLine(center_x, center_y, int(x), int(y))
                
                # Draw arrowhead
                arrow_size = 8
                painter.drawLine(
                    int(x), int(y),
                    int(x - arrow_size * np.cos(rad - np.pi/6)),
                    int(y + arrow_size * np.sin(rad - np.pi/6))
                )
                painter.drawLine(
                    int(x), int(y),
                    int(x - arrow_size * np.cos(rad + np.pi/6)),
                    int(y + arrow_size * np.sin(rad + np.pi/6))
                )


class SVVisualizerApp(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IEC 61850 Sampled Values Visualizer")
        self.setGeometry(100, 100, 1400, 900)
        
        self.selected_stream_id = None
        self.streams = {}
        self.capture_thread = None
        
        self.init_ui()
        self.detect_interfaces()
        
    def init_ui(self):
        """Initialize the user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Top control panel
        control_panel = QGroupBox("Control Panel")
        control_layout = QHBoxLayout(control_panel)
        
        # Interface selection
        control_layout.addWidget(QLabel("Network Interface:"))
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(200)
        control_layout.addWidget(self.interface_combo)
        
        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.toggle_capture)
        control_layout.addWidget(self.start_button)
        
        self.refresh_button = QPushButton("Refresh Interfaces")
        self.refresh_button.clicked.connect(self.detect_interfaces)
        control_layout.addWidget(self.refresh_button)
        
        control_layout.addStretch()
        
        main_layout.addWidget(control_panel)
        
        # Stream selection panel
        stream_panel = QGroupBox("Discovered SV Streams")
        stream_layout = QHBoxLayout(stream_panel)
        
        self.stream_combo = QComboBox()
        self.stream_combo.setMinimumWidth(300)
        self.stream_combo.currentIndexChanged.connect(self.on_stream_selected)
        stream_layout.addWidget(QLabel("Select Stream:"))
        stream_layout.addWidget(self.stream_combo)
        stream_layout.addStretch()
        
        main_layout.addWidget(stream_panel)
        
        # Main content with tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs, 1)
        
        # Tab 1: Visualization
        viz_widget = QWidget()
        viz_layout = QVBoxLayout(viz_widget)
        
        if MATPLOTLIB_AVAILABLE:
            # Create matplotlib figure for waveform
            self.waveform_fig = Figure(figsize=(8, 4))
            self.waveform_canvas = FigureCanvas(self.waveform_fig)
            viz_layout.addWidget(self.waveform_canvas)
            
            # Create phasor plot
            self.phasor_widget = PhasorPlot()
            self.phasor_widget.setMinimumHeight(250)
            viz_layout.addWidget(self.phasor_widget)
        else:
            viz_layout.addWidget(QLabel("Matplotlib not available - install with: pip install matplotlib"))
        
        self.tabs.addTab(viz_widget, "Visualization")
        
        # Tab 2: Characteristics
        char_widget = QWidget()
        char_layout = QVBoxLayout(char_widget)
        
        self.char_text = QTextEdit()
        self.char_text.setReadOnly(True)
        self.char_text.setFont(QFont("Courier", 10))
        char_layout.addWidget(self.char_text)
        
        self.tabs.addTab(char_widget, "Characteristics")
        
        # Tab 3: Detailed Information
        detail_widget = QWidget()
        detail_scroll = QScrollArea()
        detail_scroll.setWidgetResizable(True)
        detail_content = QWidget()
        detail_layout = QGridLayout(detail_content)
        
        row = 0
        self.detail_labels = {}
        
        fields = [
            ("Stream ID:", "stream_id"),
            ("SV ID:", "sv_id"),
            ("Dataset:", "dat_set"),
            ("APP ID:", "app_id"),
            ("Sample Count:", "smp_cnt"),
            ("Configuration Revision:", "conf_rev"),
            ("Sample Mode:", "smp_mod"),
            ("Sample Rate:", "smp_rate"),
            ("Reference Time:", "refr_tm"),
            ("Data Count:", "data_count"),
            ("Packet Count:", "packet_count"),
            ("Data Values:", "data_values"),
        ]
        
        for label_text, field_name in fields:
            label = QLabel(label_text)
            label.setFont(QFont("Arial", 10, QFont.Bold))
            value_label = QLabel("-")
            value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            detail_layout.addWidget(label, row, 0)
            detail_layout.addWidget(value_label, row, 1)
            self.detail_labels[field_name] = value_label
            row += 1
        
        detail_scroll.setWidget(detail_content)
        detail_layout_main = QVBoxLayout(detail_widget)
        detail_layout_main.addWidget(detail_scroll)
        
        self.tabs.addTab(detail_widget, "Detailed Info")
        
        # Status bar
        self.statusBar().showMessage("Ready - Select interface and start capture")
        
        # Timer for UI updates
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(100)  # Update every 100ms
    
    def detect_interfaces(self):
        """Detect available network interfaces"""
        self.interface_combo.clear()
        
        # Get list of network interfaces
        interfaces = []
        try:
            # Common Linux interfaces
            for iface in ['eth0', 'eth1', 'enp0s3', 'enp0s8', 'wlan0', 'lo']:
                if os.path.exists(f'/sys/class/net/{iface}'):
                    interfaces.append(iface)
            
            # Also try to get from socket
            import subprocess
            result = subprocess.run(['ip', '-o', 'link', 'show'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            iface_name = parts[1].strip()
                            if iface_name not in interfaces and '@' not in iface_name:
                                interfaces.append(iface_name)
        except:
            pass
        
        if not interfaces:
            interfaces = ['eth0', 'lo']
        
        for iface in sorted(set(interfaces)):
            self.interface_combo.addItem(iface)
        
        self.statusBar().showMessage(f"Found {len(interfaces)} network interface(s)")
    
    def toggle_capture(self):
        """Start or stop SV capture"""
        if self.capture_thread and self.capture_thread.isRunning():
            # Stop capture
            self.capture_thread.stop()
            self.capture_thread.wait(2000)
            self.capture_thread = None
            self.start_button.setText("Start Capture")
            self.statusBar().showMessage("Capture stopped")
        else:
            # Start capture
            interface = self.interface_combo.currentText()
            self.capture_thread = SVCaptureThread(interface)
            self.capture_thread.new_stream.connect(self.on_new_stream)
            self.capture_thread.stream_update.connect(self.on_stream_update)
            self.capture_thread.error_occurred.connect(self.on_capture_error)
            self.capture_thread.start()
            self.start_button.setText("Stop Capture")
            self.statusBar().showMessage(f"Capturing on {interface}...")
    
    def on_new_stream(self, stream_data):
        """Handle new stream discovery"""
        stream_id = stream_data['id']
        sv_id = stream_data.get('svId', 'unknown')
        app_id = stream_data.get('appID', 0)
        
        # Create stream object
        stream = SVStreamData(stream_id, sv_id, app_id)
        stream.update(stream_data)
        self.streams[stream_id] = stream
        
        # Add to combo box
        display_name = f"{sv_id} (APP ID: {app_id})"
        self.stream_combo.addItem(display_name, stream_id)
        
        self.statusBar().showMessage(f"New stream discovered: {sv_id}")
    
    def on_stream_update(self, stream_id, stream_data):
        """Handle stream data update"""
        if stream_id in self.streams:
            self.streams[stream_id].update(stream_data)
    
    def on_stream_selected(self, index):
        """Handle stream selection change"""
        if index < 0:
            return
        
        stream_id = self.stream_combo.itemData(index)
        self.selected_stream_id = stream_id
        
        if stream_id is not None and stream_id in self.streams:
            self.update_detail_view(self.streams[stream_id])
            self.statusBar().showMessage(f"Selected stream: {self.streams[stream_id].sv_id}")
    
    def on_capture_error(self, error_msg):
        """Handle capture errors"""
        self.statusBar().showMessage(f"Error: {error_msg}")
        QMessageBox.warning(self, "Capture Error", error_msg)
    
    def update_display(self):
        """Update all displays with current data"""
        if self.selected_stream_id is None or self.selected_stream_id not in self.streams:
            return
        
        stream = self.streams[self.selected_stream_id]
        
        # Update waveform plot
        if MATPLOTLIB_AVAILABLE and hasattr(self, 'waveform_fig'):
            self.waveform_fig.clear()
            
            if stream.data_values:
                ax = self.waveform_fig.add_subplot(111)
                
                # Plot data values
                x = range(len(stream.data_values))
                ax.plot(x, stream.data_values, 'b-o', linewidth=2, markersize=6)
                ax.set_xlabel('Sample Index')
                ax.set_ylabel('Value')
                ax.set_title(f'SV Data Values - {stream.sv_id}')
                ax.grid(True, alpha=0.3)
                ax.set_xticks(x)
                
                # Rotate x labels if many values
                if len(x) > 8:
                    plt = self.waveform_fig.canvas.figure
                    for label in ax.get_xticklabels():
                        label.set_rotation(45)
                
                self.waveform_canvas.draw()
            
            # Update phasor plot
            if hasattr(self, 'phasor_widget'):
                self.phasor_widget.set_data(stream.data_values)
        
        # Update characteristics
        self.update_characteristics(stream)
        
        # Update detailed view
        self.update_detail_view(stream)
    
    def update_characteristics(self, stream):
        """Update characteristics tab"""
        chars = []
        chars.append("=" * 60)
        chars.append("IEC 61850 Sampled Values - Stream Characteristics")
        chars.append("=" * 60)
        chars.append("")
        chars.append(f"Stream Identifier: {stream.sv_id}")
        chars.append(f"Dataset Reference: {stream.dat_set or 'N/A'}")
        chars.append(f"APP ID: 0x{stream.app_id:04X}")
        chars.append("")
        chars.append("Sampling Parameters:")
        chars.append(f"  - Sample Mode: {stream.smp_mod}")
        chars.append(f"  - Sample Rate: {stream.smp_rate} samples/cycle")
        chars.append(f"  - Sample Counter: {stream.smp_cnt}")
        chars.append(f"  - Config Revision: {stream.conf_rev}")
        chars.append("")
        chars.append("Data Information:")
        chars.append(f"  - Number of Data Values: {stream.data_count}")
        chars.append(f"  - Total Packets Received: {stream.packet_count}")
        chars.append("")
        
        if stream.data_values:
            chars.append("Current Data Values:")
            for i, val in enumerate(stream.data_values):
                chars.append(f"  [{i:2d}]: {val:12.6f}")
            
            # Calculate statistics
            if len(stream.data_values) >= 3:
                chars.append("")
                chars.append("Statistics (first 3 values):")
                for i in range(min(3, len(stream.data_values))):
                    vals = [h[i] for h in stream.history if len(h) > i]
                    if vals:
                        avg = sum(vals) / len(vals)
                        min_v = min(vals)
                        max_v = max(vals)
                        chars.append(f"  Value {i}: Avg={avg:.4f}, Min={min_v:.4f}, Max={max_v:.4f}")
        
        chars.append("")
        chars.append("=" * 60)
        
        self.char_text.setText("\n".join(chars))
    
    def update_detail_view(self, stream):
        """Update detailed information view"""
        self.detail_labels['stream_id'].setText(str(stream.stream_id))
        self.detail_labels['sv_id'].setText(stream.sv_id)
        self.detail_labels['dat_set'].setText(stream.dat_set or "N/A")
        self.detail_labels['app_id'].setText(f"0x{stream.app_id:04X} ({stream.app_id})")
        self.detail_labels['smp_cnt'].setText(str(stream.smp_cnt))
        self.detail_labels['conf_rev'].setText(str(stream.conf_rev))
        self.detail_labels['smp_mod'].setText(str(stream.smp_mod))
        self.detail_labels['smp_rate'].setText(str(stream.smp_rate))
        
        if stream.refr_tm:
            dt = datetime.fromtimestamp(stream.refr_tm / 1000.0)
            self.detail_labels['refr_tm'].setText(f"{stream.refr_tm} ms\n({dt.isoformat()})")
        else:
            self.detail_labels['refr_tm'].setText("N/A")
        
        self.detail_labels['data_count'].setText(str(stream.data_count))
        self.detail_labels['packet_count'].setText(str(stream.packet_count))
        
        # Format data values
        if stream.data_values:
            data_str = "\n".join([f"[{i}]: {v:.6f}" for i, v in enumerate(stream.data_values)])
            self.detail_labels['data_values'].setText(data_str)
        else:
            self.detail_labels['data_values'].setText("No data")
    
    def closeEvent(self, event):
        """Handle application close"""
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            self.capture_thread.wait(2000)
        event.accept()


def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = SVVisualizerApp()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
