import sys
import threading
import time
import socket
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Optional, Callable
from scapy.all import (
    sniff, Ether, IP, TCP, UDP, ICMP, sr1, conf, 
    IPv6, ARP, wrpcap, rdpcap
)
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLS
from PyQt5.QtCore import QObject, pyqtSignal, Qt, QThread
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QPushButton, QComboBox, QTreeWidget, QTreeWidgetItem, QTabWidget, 
    QGroupBox, QGridLayout, QMessageBox, QLineEdit, QFileDialog, QStatusBar,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtGui import QColor, QIcon

# Configure Scapy to suppress warnings
conf.verb = 0

class MainWindow(QMainWindow):
    """Main application window for network monitoring"""
    
    update_packet_table = pyqtSignal(dict)
    update_stats = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Monitoring Tool")
        self.setGeometry(100, 100, 1200, 800)
        
        # Setup UI
        self.setup_ui()
        
        # Initialize components
        self.packet_analyzer = PacketAnalyzer(self)
        self.packet_tracer = PacketTracer()
        
        # Connect signals
        self.packet_tracer.hop_detected.connect(self.update_trace_ui)
        self.packet_tracer.trace_completed.connect(self.finalize_trace)
        self.packet_tracer.error_occurred.connect(self.show_error)
        self.update_packet_table.connect(self.packet_analyzer.add_packet_to_table)
        self.update_stats.connect(self.packet_analyzer.update_statistics)
        
        # Add components to main window
        self.tab_widget.addTab(self.packet_analyzer, "Packet Analyzer")
        self.setup_packet_tracer_tab()
        self.setup_dashboard_tab()
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
    
    def setup_ui(self):
        """Initialize main window UI components"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Create dashboard tab
        self.dashboard = QWidget()
        self.tab_widget.addTab(self.dashboard, "Dashboard")

    def setup_packet_tracer_tab(self):
        """Setup packet tracer tab components"""
        tracer_tab = QWidget()
        layout = QVBoxLayout(tracer_tab)
        
        # Add tracer controls
        control_group = QGroupBox("Tracer Controls")
        control_layout = QHBoxLayout()
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP/hostname")
        control_layout.addWidget(QLabel("Target:"))
        control_layout.addWidget(self.target_input)
        
        self.start_trace_btn = QPushButton("Start Trace")
        self.start_trace_btn.clicked.connect(self.start_trace)
        control_layout.addWidget(self.start_trace_btn)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Results display
        results_group = QGroupBox("Trace Results")
        results_layout = QVBoxLayout()
        
        self.trace_results = QTreeWidget()
        self.trace_results.setHeaderLabels(["Hop", "IP Address", "Hostname", "RTT (ms)"])
        self.trace_results.setColumnWidth(0, 50)
        self.trace_results.setColumnWidth(1, 150)
        self.trace_results.setColumnWidth(2, 200)
        self.trace_results.setColumnWidth(3, 100)
        
        results_layout.addWidget(self.trace_results)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        tracer_tab.setLayout(layout)
        self.tab_widget.addTab(tracer_tab, "Packet Tracer")

    def start_trace(self):
        """Start a new trace operation"""
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target IP or hostname")
            return
        
        # Clear previous results
        self.trace_results.clear()
        
        # Start the trace
        trace_id = self.packet_tracer.start_trace(
            target=target,
            protocol="ICMP",
            max_hops=30,
            timeout=2
        )
        
        if not trace_id:
            self.show_error("Failed to start trace")
            return
        
        self.start_trace_btn.setEnabled(False)
        self.status_bar.showMessage(f"Tracing route to {target}...")
    
    def update_trace_ui(self, hop_data):
        """Update UI with new hop information"""
        trace_id = hop_data["trace_id"]
        hop = hop_data["hop"]
        
        item = QTreeWidgetItem(self.trace_results, [
            str(hop["hop_number"]),
            hop["ip"],
            hop["hostname"],
            str(hop["rtt"])
        ])
        
        self.trace_results.addTopLevelItem(item)
        self.trace_results.scrollToBottom()
    
    def finalize_trace(self, trace_data):
        """Handle trace completion"""
        self.start_trace_btn.setEnabled(True)
        self.status_bar.showMessage(f"Trace completed in {trace_data['end_time'] - trace_data['start_time']:.2f} seconds")
        
        # Add summary item
        summary = QTreeWidgetItem(self.trace_results, [
            "", 
            "Trace completed",
            f"{len(trace_data['hops'])} hops",
            f"{trace_data['end_time'] - trace_data['start_time']:.2f}s"
        ])
        summary.setBackground(0, QColor(200, 255, 200))
    
    def show_error(self, error_msg):
        """Show error message in status bar and dialog"""
        self.status_bar.showMessage(f"Error: {error_msg}", 5000)
        QMessageBox.critical(self, "Error", error_msg)
    
    def setup_dashboard_tab(self):
        """Setup dashboard statistics display"""
        layout = QGridLayout(self.dashboard)
        
        # Protocol statistics
        stats_group = QGroupBox("Protocol Statistics")
        stats_layout = QVBoxLayout()
        self.stats_labels = {
            'total': QLabel("Total Packets: 0"),
            'tcp': QLabel("TCP: 0"),
            'udp': QLabel("UDP: 0"),
            'icmp': QLabel("ICMP: 0"),
            'http': QLabel("HTTP: 0"),
            'tls': QLabel("TLS: 0"),
            'arp': QLabel("ARP: 0"),
            'ipv6': QLabel("IPv6: 0"),
            'unknown': QLabel("Unknown: 0")
        }
        
        # Style the labels
        for protocol, label in self.stats_labels.items():
            font = label.font()
            font.setBold(True)
            label.setFont(font)
            if protocol == 'total':
                label.setStyleSheet("font-size: 14px; color: #0066cc;")
            stats_layout.addWidget(label)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group, 0, 0)
        
        # Capture Status
        status_group = QGroupBox("Capture Status")
        status_layout = QVBoxLayout()
        
        self.capture_status_label = QLabel("Status: Idle")
        self.packets_per_second = QLabel("Packets/sec: 0")
        self.capture_time = QLabel("Capture Time: 00:00:00")
        
        status_layout.addWidget(self.capture_status_label)
        status_layout.addWidget(self.packets_per_second)
        status_layout.addWidget(self.capture_time)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group, 0, 1)
        
        # Network Traffic Summary
        traffic_group = QGroupBox("Network Traffic Summary")
        traffic_layout = QVBoxLayout()
        
        self.bytes_sent = QLabel("Bytes Sent: 0")
        self.bytes_received = QLabel("Bytes Received: 0")
        self.avg_packet_size = QLabel("Avg Packet Size: 0 bytes")
        
        traffic_layout.addWidget(self.bytes_sent)
        traffic_layout.addWidget(self.bytes_received)
        traffic_layout.addWidget(self.avg_packet_size)
        
        traffic_group.setLayout(traffic_layout)
        layout.addWidget(traffic_group, 1, 0)
        
        # Top Talkers
        talkers_group = QGroupBox("Top Talkers")
        talkers_layout = QVBoxLayout()
        
        self.top_sources = QLabel("Top Sources: None")
        self.top_destinations = QLabel("Top Destinations: None")
        self.top_protocols = QLabel("Top Protocols: None")
        
        talkers_layout.addWidget(self.top_sources)
        talkers_layout.addWidget(self.top_destinations)
        talkers_layout.addWidget(self.top_protocols)
        
        talkers_group.setLayout(talkers_layout)
        layout.addWidget(talkers_group, 1, 1)

class PacketAnalyzer(QWidget):
    """Packet analyzer component using Scapy"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.capture_thread = None
        self.stop_capture = False
        self.packets = []
        self.filter_expression = ""
        self.packet_counts = defaultdict(int)
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the packet analyzer UI"""
        layout = QVBoxLayout()
        
        # Control panel
        control_group = QGroupBox("Capture Controls")
        control_layout = QHBoxLayout()
        
        # Interface selection
        control_layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.get_network_interfaces())
        control_layout.addWidget(self.interface_combo)
        
        # Filter input
        control_layout.addWidget(QLabel("Filter:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("e.g., tcp port 80")
        control_layout.addWidget(self.filter_input)
        
        # Start/Stop buttons
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.clicked.connect(self.start_capture)
        control_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Capture")
        self.stop_btn.clicked.connect(self.stop_capture_thread)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Packet display area
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels([
            "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"
        ])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.packet_table.doubleClicked.connect(self.show_packet_details)
        layout.addWidget(self.packet_table)
        
        self.setLayout(layout)
    
    def get_network_interfaces(self):
        """Get available network interfaces"""
        try:
            return sorted(iface.name for iface in conf.ifaces.values() if iface.name != "lo")
        except Exception:
            return ["No interfaces found"]
    
    def start_capture(self):
        """Start packet capture"""
        if self.capture_thread and self.capture_thread.is_alive():
            return
        
        interface = self.interface_combo.currentText()
        if interface == "No interfaces found":
            QMessageBox.critical(self, "Error", "No network interfaces available")
            return
        
        self.stop_capture = False
        self.capture_thread = threading.Thread(
            target=self.capture_packets,
            args=(interface, self.filter_input.text()),
            daemon=True
        )
        self.capture_thread.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.parent.status_bar.showMessage(f"Capturing on {interface}...")
    
    def stop_capture_thread(self):
        """Stop packet capture"""
        if self.capture_thread and self.capture_thread.is_alive():
            self.stop_capture = True
            self.capture_thread.join(timeout=1)
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.parent.status_bar.showMessage("Capture stopped")
            
            # Update dashboard status
            if hasattr(self.parent, 'capture_status_label'):
                self.parent.capture_status_label.setText("Status: Stopped")
                
            # Save capture statistics for reference
            if hasattr(self, 'capture_start_time'):
                elapsed = int(time.time() - self.capture_start_time)
                hours, remainder = divmod(elapsed, 3600)
                minutes, seconds = divmod(remainder, 60)
                
                if hasattr(self.parent, 'capture_time'):
                    self.parent.capture_time.setText(f"Capture Time: {hours:02}:{minutes:02}:{seconds:02} (Stopped)")
                
                # Reset capture start time
                delattr(self, 'capture_start_time')
                
            # Reset PPS counter
            if hasattr(self.parent, 'packets_per_second'):
                self.parent.packets_per_second.setText("Packets/sec: 0")
                
            # Final update of top talkers
            self.update_top_talkers()
    
    def capture_packets(self, interface, filter_expr=""):
        """Capture packets using Scapy"""
        try:
            sniff(
                iface=interface,
                prn=self.process_packet,
                stop_filter=lambda p: self.stop_capture,
                filter=filter_expr,
                store=False
            )
        except Exception as e:
            self.parent.error_occurred.emit(f"Capture error: {str(e)}")
    
    def process_packet(self, packet):
        """Process captured packet"""
        packet_info = self.analyze_packet(packet)
        self.packets.append(packet_info)
        
        # Update statistics
        self.packet_counts['total'] += 1
        self.packet_counts[packet_info['protocol'].lower()] += 1
        
        # Track additional statistics for the dashboard
        # Update bytes sent/received
        if hasattr(self.parent, 'bytes_sent') and hasattr(self.parent, 'bytes_received'):
            packet_length = packet_info['length']
            
            # Simple heuristic: if source is a private IP and destination is not, it's outgoing
            src_ip = packet_info['source']
            dst_ip = packet_info['destination']
            
            if self.is_private_ip(src_ip) and not self.is_private_ip(dst_ip):
                self.update_dashboard_counter(self.parent.bytes_sent, packet_length)
            elif not self.is_private_ip(src_ip) and self.is_private_ip(dst_ip):
                self.update_dashboard_counter(self.parent.bytes_received, packet_length)
        
        # Update average packet size
        if hasattr(self.parent, 'avg_packet_size'):
            avg = sum(p['length'] for p in self.packets) / len(self.packets)
            self.parent.avg_packet_size.setText(f"Avg Packet Size: {int(avg)} bytes")
        
        # Update packets per second
        if hasattr(self.parent, 'packets_per_second'):
            current_time = time.time()
            if not hasattr(self, 'last_pps_update'):
                self.last_pps_update = current_time
                self.pps_count = 0
            
            self.pps_count += 1
            if current_time - self.last_pps_update >= 1.0:  # Update every second
                pps = self.pps_count / (current_time - self.last_pps_update)
                self.parent.packets_per_second.setText(f"Packets/sec: {int(pps)}")
                self.last_pps_update = current_time
                self.pps_count = 0
        
        # Update capture status
        if hasattr(self.parent, 'capture_status_label'):
            self.parent.capture_status_label.setText("Status: Capturing")
        
        # Update capture time
        if hasattr(self.parent, 'capture_time'):
            if not hasattr(self, 'capture_start_time'):
                self.capture_start_time = time.time()
            
            elapsed = int(time.time() - self.capture_start_time)
            hours, remainder = divmod(elapsed, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.parent.capture_time.setText(f"Capture Time: {hours:02}:{minutes:02}:{seconds:02}")
        
        # Update top talkers
        self.update_top_talkers()
        
        # Emit signals to update UI
        self.parent.update_packet_table.emit(packet_info)
        self.parent.update_stats.emit(dict(self.packet_counts))
    
    def analyze_packet(self, packet):
        """Analyze packet and extract information"""
        packet_info = {
            'number': len(self.packets) + 1,
            'time': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'source': '',
            'destination': '',
            'protocol': 'Unknown',
            'length': len(packet),
            'info': '',
            'raw': packet
        }
        
        # Extract protocol information
        if packet.haslayer(IPv6):
            packet_info['source'] = packet[IPv6].src
            packet_info['destination'] = packet[IPv6].dst
            packet_info['protocol'] = 'IPv6'
            
        elif packet.haslayer(IP):
            packet_info['source'] = packet[IP].src
            packet_info['destination'] = packet[IP].dst
            
            if packet.haslayer(TCP):
                packet_info['protocol'] = 'TCP'
                packet_info['info'] = f"Port {packet[TCP].sport} → {packet[TCP].dport}"
            elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
                packet_info['info'] = f"Port {packet[UDP].sport} → {packet[UDP].dport}"
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
                packet_info['info'] = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
        
        # ARP protocol detection
        elif packet.haslayer(ARP):
            packet_info['protocol'] = 'ARP'
            packet_info['source'] = packet[ARP].psrc
            packet_info['destination'] = packet[ARP].pdst
            packet_info['info'] = f"{'Request' if packet[ARP].op == 1 else 'Reply'} {packet[ARP].psrc} → {packet[ARP].pdst}"
        
        # Additional protocol detection
        if packet.haslayer(HTTPRequest):
            packet_info['protocol'] = 'HTTP'
            try:
                method = packet[HTTPRequest].Method.decode()
                host = packet[HTTPRequest].Host.decode()
                path = packet[HTTPRequest].Path.decode()
                packet_info['info'] = f"{method} {host}{path}"
            except:
                packet_info['info'] = "HTTP Request"
        
        elif packet.haslayer(HTTPResponse):
            packet_info['protocol'] = 'HTTP'
            try:
                status_code = packet[HTTPResponse].Status_Code.decode()
                reason = packet[HTTPResponse].Reason_Phrase.decode()
                packet_info['info'] = f"Response: {status_code} {reason}"
            except:
                packet_info['info'] = "HTTP Response"
        
        elif packet.haslayer(TLS):
            packet_info['protocol'] = 'TLS'
            packet_info['info'] = "TLS/SSL Encrypted Traffic"
        
        return packet_info
    
    def show_packet_details(self):
        selected_row = self.packet_table.currentRow()
        if selected_row >= 0 and selected_row < len(self.packets):
            packet_info = self.packets[selected_row]
            details = self.get_packet_details(packet_info['raw'])
            self.show_details_dialog(details)
    
    def get_packet_details(self, packet):
        details = []
        if packet.haslayer(IP):
            details.append(f"Source IP: {packet[IP].src}")
            details.append(f"Destination IP: {packet[IP].dst}")
        if packet.haslayer(TCP):
            details.append(f"TCP Source Port: {packet[TCP].sport}")
            details.append(f"TCP Dest Port: {packet[TCP].dport}")
        if packet.haslayer(HTTPRequest):
            details.append(f"HTTP Method: {packet[HTTPRequest].Method.decode()}")
            details.append(f"Host: {packet[HTTPRequest].Host.decode()}")
        return '\n'.join(details)
    
    def show_details_dialog(self, content):
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Packet Details")
        dialog.setText(content)
        dialog.exec_()
    
    def add_packet_to_table(self, packet_info):
        """Add packet to the table widget"""
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        
        self.packet_table.setItem(row, 0, QTableWidgetItem(str(packet_info['number'])))
        self.packet_table.setItem(row, 1, QTableWidgetItem(packet_info['time']))
        self.packet_table.setItem(row, 2, QTableWidgetItem(packet_info['source']))
        self.packet_table.setItem(row, 3, QTableWidgetItem(packet_info['destination']))
        self.packet_table.setItem(row, 4, QTableWidgetItem(packet_info['protocol']))
        self.packet_table.setItem(row, 5, QTableWidgetItem(str(packet_info['length'])))
        self.packet_table.setItem(row, 6, QTableWidgetItem(packet_info['info']))
        
        # Color-code by protocol
        protocol_colors = {
            'TCP': QColor(220, 240, 255),  # Light blue
            'UDP': QColor(255, 240, 220),  # Light orange
            'ICMP': QColor(255, 220, 220),  # Light red
            'HTTP': QColor(220, 255, 220),  # Light green
            'TLS': QColor(240, 220, 255),  # Light purple
            'ARP': QColor(255, 255, 220),  # Light yellow
            'IPv6': QColor(220, 220, 255)   # Light indigo
        }
        
        if packet_info['protocol'] in protocol_colors:
            color = protocol_colors[packet_info['protocol']]
            for col in range(self.packet_table.columnCount()):
                self.packet_table.item(row, col).setBackground(color)
        
        self.packet_table.scrollToBottom()
    
    def is_private_ip(self, ip):
        """Check if an IP address is private"""
        try:
            # Handle IPv6 addresses
            if ':' in ip:
                return False  # Simplified check for IPv6
            
            # Check for private IPv4 ranges
            octets = ip.split('.')
            if len(octets) != 4:
                return False
                
            # 10.0.0.0/8
            if octets[0] == '10':
                return True
                
            # 172.16.0.0/12
            if octets[0] == '172' and 16 <= int(octets[1]) <= 31:
                return True
                
            # 192.168.0.0/16
            if octets[0] == '192' and octets[1] == '168':
                return True
                
            # 127.0.0.0/8 (localhost)
            if octets[0] == '127':
                return True
                
            return False
        except:
            return False
    
    def update_dashboard_counter(self, label, value_to_add):
        """Update a dashboard counter label with an incremented value"""
        try:
            current_text = label.text()
            current_value = int(current_text.split(': ')[1].split(' ')[0])
            new_value = current_value + value_to_add
            
            # Format with commas for readability if large number
            if new_value > 1000:
                formatted_value = f"{new_value:,}"
            else:
                formatted_value = str(new_value)
                
            # Keep the same label format
            new_text = f"{current_text.split(': ')[0]}: {formatted_value}"
            if ' ' in current_text.split(': ')[1]:
                new_text += f" {current_text.split(': ')[1].split(' ')[1]}"
                
            label.setText(new_text)
        except Exception as e:
            print(f"Error updating dashboard counter: {e}")
    
    def update_top_talkers(self):
        """Update the top talkers statistics"""
        if not hasattr(self.parent, 'top_sources') or not self.packets:
            return
            
        # Count occurrences of sources, destinations, and protocols
        sources = {}
        destinations = {}
        protocols = {}
        
        for packet in self.packets[-100:]:  # Only consider last 100 packets for recent activity
            src = packet['source']
            dst = packet['destination']
            proto = packet['protocol']
            
            if src and src != '*':
                sources[src] = sources.get(src, 0) + 1
            if dst and dst != '*':
                destinations[dst] = destinations.get(dst, 0) + 1
            if proto and proto != 'Unknown':
                protocols[proto] = protocols.get(proto, 0) + 1
        
        # Get top 3 of each
        top_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:3]
        top_destinations = sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:3]
        top_protocols = sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:3]
        
        # Format and update labels
        if top_sources:
            sources_text = ", ".join([f"{ip} ({count})" for ip, count in top_sources])
            self.parent.top_sources.setText(f"Top Sources: {sources_text}")
        
        if top_destinations:
            destinations_text = ", ".join([f"{ip} ({count})" for ip, count in top_destinations])
            self.parent.top_destinations.setText(f"Top Destinations: {destinations_text}")
        
        if top_protocols:
            protocols_text = ", ".join([f"{proto} ({count})" for proto, count in top_protocols])
            self.parent.top_protocols.setText(f"Top Protocols: {protocols_text}")
    
    def update_statistics(self, stats):
        """Update statistics display"""
        # Update the dashboard statistics labels with current packet counts
        if self.parent and hasattr(self.parent, 'stats_labels'):
            for protocol, count in stats.items():
                if protocol in self.parent.stats_labels:
                    self.parent.stats_labels[protocol].setText(f"{protocol.upper()}: {count}")
            
            # Update total packets count
            if 'total' in self.parent.stats_labels and 'total' in stats:
                self.parent.stats_labels['total'].setText(f"Total Packets: {stats['total']}")
                
            # Force update of the dashboard UI
            self.parent.dashboard.update()
    
class PacketTracer(QObject):
    """Improved packet tracer with error handling"""
    
    hop_detected = pyqtSignal(dict)
    trace_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.active_traces = {}
        self.next_trace_id = 1
    
    def start_trace(self, target, protocol="ICMP", max_hops=30, timeout=2, port=None):
        """Start a new trace"""
        trace_id = str(self.next_trace_id)
        self.next_trace_id += 1
        
        thread = threading.Thread(
            target=self.run_trace,
            args=(trace_id, target, protocol, max_hops, timeout, port),
            daemon=True
        )
        
        self.active_traces[trace_id] = {
            'thread': thread,
            'target': target,
            'start_time': time.time()
        }
        
        thread.start()
        return trace_id
    
    def run_trace(self, trace_id, target, protocol, max_hops, timeout, port):
        """Execute the traceroute"""
        try:
            hops = []
            start_time = time.time()
            
            for ttl in range(1, max_hops + 1):
                if trace_id not in self.active_traces:
                    break
                
                probe = self.create_probe(protocol, target, ttl, port)
                reply = self.send_probe(probe, timeout)
                hop_info = self.process_reply(reply, ttl)
                
                hops.append(hop_info)
                self.hop_detected.emit({
                    'trace_id': trace_id,
                    'hop': hop_info
                })
                
                if hop_info['ip'] == target:
                    break
            
            self.trace_completed.emit({
                'trace_id': trace_id,
                'hops': hops,
                'start_time': start_time,
                'end_time': time.time()
            })
            
        except Exception as e:
            self.error_occurred.emit(f"Trace error: {str(e)}")
        finally:
            if trace_id in self.active_traces:
                del self.active_traces[trace_id]
    
    def create_probe(self, protocol, target, ttl, port):
        """Create probe packet"""
        if protocol == "ICMP":
            return IP(dst=target, ttl=ttl)/ICMP()
        elif protocol == "TCP":
            dport = port or 80
            return IP(dst=target, ttl=ttl)/TCP(dport=dport, flags="S")
        elif protocol == "UDP":
            dport = port or 33434
            return IP(dst=target, ttl=ttl)/UDP(dport=dport)
        raise ValueError(f"Unsupported protocol: {protocol}")
    
    def send_probe(self, probe, timeout):
        """Send probe and wait for reply"""
        try:
            return sr1(probe, timeout=timeout, verbose=0)
        except Exception as e:
            self.error_occurred.emit(f"Probe failed: {str(e)}")
            return None
    
    def process_reply(self, reply, ttl):
        """Process reply packet with proper error handling"""
        hop_info = {
            'hop_number': ttl,
            'ip': '*',
            'hostname': '*',
            'rtt': 'Timeout'
        }
        
        if reply is None:
            return hop_info
        
        # Get IP address
        if IP in reply:
            hop_info['ip'] = reply[IP].src
        elif IPv6 in reply:
            hop_info['ip'] = reply[IPv6].src
        
        # Resolve hostname
        try:
            if hop_info['ip'] != '*':
                hop_info['hostname'] = socket.gethostbyaddr(hop_info['ip'])[0]
        except (socket.herror, socket.gaierror):
            hop_info['hostname'] = hop_info['ip']
        
        # Calculate RTT safely
        if hasattr(reply, 'time') and hasattr(reply, 'sent_time'):
            if reply.time is not None and reply.sent_time is not None:
                hop_info['rtt'] = round((reply.time - reply.sent_time) * 1000, 2)
        
        return hop_info

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()