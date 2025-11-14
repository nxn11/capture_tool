import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                              QPushButton, QLabel, QListWidget, QTextBrowser, QLineEdit, 
                              QComboBox, QFrame, QFileDialog, QMessageBox, QMenu, QListWidgetItem)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCursor, QAction, QDesktopServices
from scapy.all import sniff, TCP, IP, Raw, wrpcap
import datetime
import webbrowser
import requests
from plyer import notification
import re

class PacketSnifferThread(QThread):
    packet_captured = pyqtSignal(object)
    error_occurred = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.is_running = False
        
    def run(self):
        self.is_running = True
        try:
            sniff(filter="tcp port 80 or tcp port 443", 
                  prn=self.packet_handler, 
                  store=False, 
                  stop_filter=lambda x: not self.is_running)
        except Exception as e:
            self.error_occurred.emit(f"ERREUR: {str(e)}\nAssurez-vous d'exécuter en tant qu'administrateur")
    
    def packet_handler(self, packet):
        if not self.is_running:
            return
        self.packet_captured.emit(packet)
    
    def stop(self):
        self.is_running = False

class HTTPCaptureApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Capture Tool NXN")
        self.setGeometry(100, 100, 1400, 800)
        
        self.capturing = False
        self.sniffer_thread = None
        self.packet_count = 0
        self.MAX_PACKETS = 10000
        self.colors = ["#00ff00", "#00ffff", "#ff00ff", "#ffff00", "#ff6600", "#00ff99", "#9900ff", "#ff0099"]
        self.auto_scroll = True
        self.packets_data = []
        self.raw_packets = []
        self.selected_packet = None
        self.selected_packet_id = None
        self.language = "en"
        self.vt_cache = {}
        self.vt_domain_cache = {}
        self.filter_protocol = "both"
        self.vt_analysis_queue = []
        self.vt_analyzing = False
        
        self.translations = {
            "fr": {
                "start": "DÉMARRER LA CAPTURE",
                "stop": "ARRÊTER LA CAPTURE",
                "clear": "EFFACER",
                "export_pcap": "EXPORTER PCAP",
                "packets": "Paquets",
                "requests_list": "LISTE DES REQUÊTES",
                "request_details": "DÉTAILS DE LA REQUÊTE",
                "general_info": "INFORMATIONS GÉNÉRALES",
                "network_info": "INFORMATIONS RÉSEAU",
                "http_request": "REQUÊTE HTTP",
                "http_response": "RÉPONSE HTTP",
                "raw_payload": "PAYLOAD BRUT (HEX)",
                "packet_id": "ID Paquet",
                "protocol": "Protocole",
                "domain": "Domaine",
                "url": "URL",
                "size": "Taille",
                "source": "Source",
                "destination": "Destination",
                "tcp_flags": "Flags TCP",
                "sequence": "Séquence",
                "acknowledgment": "Acknowledgment",
                "bytes": "bytes",
                "footer": "Nécessite des privilèges administrateur pour capturer le trafic réseau",
                "vt_link": "+VirusTotal",
                "copy_ip": "Copier l'adresse IP",
                "filter": "Filtre:",
                "auto_analysis": "Analyse automatique",
                "search_ip": "Rechercher IP:",
                "enter_ip": "Entrez une adresse IP...",
                "limit_reached": "Limite atteinte",
                "limit_message": "La capture a été arrêtée automatiquement après avoir atteint 10 000 paquets."
            },
            "en": {
                "start": "START CAPTURE",
                "stop": "STOP CAPTURE",
                "clear": "CLEAR",
                "export_pcap": "EXPORT PCAP",
                "packets": "Packets",
                "requests_list": "REQUESTS LIST",
                "request_details": "REQUEST DETAILS",
                "general_info": "GENERAL INFORMATION",
                "network_info": "NETWORK INFORMATION",
                "http_request": "HTTP REQUEST",
                "http_response": "RESPONSE HTTP",
                "raw_payload": "RAW PAYLOAD (HEX)",
                "packet_id": "Packet ID",
                "protocol": "Protocol",
                "domain": "Domain",
                "url": "URL",
                "size": "Size",
                "source": "Source",
                "destination": "Destination",
                "tcp_flags": "TCP Flags",
                "sequence": "Sequence",
                "acknowledgment": "Acknowledgment",
                "bytes": "bytes",
                "footer": "Requires administrator privileges to capture network traffic",
                "vt_link": "+VirusTotal",
                "copy_ip": "Copy IP Address",
                "filter": "Filter:",
                "auto_analysis": "Automatic analysis",
                "search_ip": "Search IP:",
                "enter_ip": "Enter an IP address...",
                "limit_reached": "Limit Reached",
                "limit_message": "Capture was automatically stopped after reaching 10,000 packets."
            }
        }
        
        self.init_ui()
        
        self.vt_timer = QTimer()
        self.vt_timer.timeout.connect(self.process_vt_queue)
        self.vt_timer.start(300)
        
    def t(self, key):
        return self.translations[self.language].get(key, key)
    
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        self.setStyleSheet("""
            QMainWindow { background-color: #1a1a1a; }
            QFrame#header { background-color: #0d0d0d; }
            QFrame#controlPanel { background-color: #1a1a1a; }
            QPushButton {
                background-color: #000000;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 11pt;
                font-weight: bold;
                padding: 10px;
            }
            QPushButton:hover { background-color: #333333; }
            QPushButton:pressed { background-color: #555555; }
            QPushButton#stopBtn { background-color: #ff0000; }
            QPushButton#stopBtn:hover { background-color: #cc0000; }
            QComboBox {
                background-color: #000000;
                color: white;
                border: 1px solid #333333;
                border-radius: 3px;
                padding: 5px;
                font-size: 10pt;
                font-weight: bold;
            }
            QComboBox::drop-down { border: none; padding-right: 5px; }
            QComboBox QAbstractItemView {
                background-color: #000000;
                color: white;
                selection-background-color: #333333;
                border: 1px solid #333333;
            }
            QListWidget {
                background-color: #0d0d0d;
                color: white;
                border: none;
                font-family: 'Arial', sans-serif;
                font-size: 14pt;
            }
            QListWidget::item:selected { background-color: #333333; }
            QTextBrowser {
                background-color: #0d0d0d;
                color: white;
                border: none;
                font-family: 'Segoe UI', 'San Francisco', 'Helvetica Neue', Arial, sans-serif;
                font-size: 14pt;
                padding: 15px;
            }
            QLineEdit {
                background-color: #0d0d0d;
                color: white;
                border: 1px solid #333333;
                border-radius: 3px;
                padding: 5px;
                font-size: 9pt;
            }
            QLineEdit:focus { border: 1px solid #555555; }
        """)
        
        # Header avec ASCII art NXN
        header_frame = QFrame()
        header_frame.setObjectName("header")
        header_frame.setFixedHeight(120)
        header_layout = QVBoxLayout(header_frame)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(0)
        
        # ASCII art NXN avec blocs
        ascii_art = """ ██████   █████ █████ █████ ██████   █████
▒▒██████ ▒▒███ ▒▒███ ▒▒███ ▒▒██████ ▒▒███ 
 ▒███▒███ ▒███  ▒▒███ ███   ▒███▒███ ▒███ 
 ▒███▒▒███▒███   ▒▒█████    ▒███▒▒███▒███ 
 ▒███ ▒▒██████    ███▒███   ▒███ ▒▒██████ 
 ▒███  ▒▒█████   ███ ▒▒███  ▒███  ▒▒█████ 
 █████  ▒▒█████ █████ █████ █████  ▒▒█████
▒▒▒▒▒    ▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒"""
        
        title_label = QLabel(ascii_art)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("""
            color: white;
            font-family: 'Courier New', 'Consolas', monospace;
            font-size: 9pt;
            font-weight: bold;
            padding: 5px;
            margin: 0;
        """)
        header_layout.addWidget(title_label)
        
        main_layout.addWidget(header_frame)
        
        # Control Panel
        control_frame = QFrame()
        control_frame.setObjectName("controlPanel")
        control_frame.setFixedHeight(80)
        control_layout = QHBoxLayout(control_frame)
        control_layout.setContentsMargins(20, 15, 20, 15)
        
        self.capture_btn = QPushButton(self.t("start"))
        self.capture_btn.setFixedSize(220, 45)
        self.capture_btn.clicked.connect(self.toggle_capture)
        
        self.clear_btn = QPushButton(self.t("clear"))
        self.clear_btn.setFixedSize(150, 45)
        self.clear_btn.clicked.connect(self.clear_output)
        
        self.export_btn = QPushButton(self.t("export_pcap"))
        self.export_btn.setFixedSize(180, 45)
        self.export_btn.clicked.connect(self.export_pcap)
        
        control_layout.addWidget(self.capture_btn)
        control_layout.addWidget(self.clear_btn)
        control_layout.addWidget(self.export_btn)
        
        control_layout.addSpacing(30)
        
        # Filtre
        self.filter_label = QLabel(self.t("filter"))
        self.filter_label.setStyleSheet("color: #888888; font-size: 10pt;")
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["HTTP/HTTPS", "HTTP", "HTTPS", "✕ Malicious"])
        self.filter_combo.setFixedSize(150, 35)
        self.filter_combo.currentTextChanged.connect(self.change_filter)
        
        control_layout.addWidget(self.filter_label)
        control_layout.addWidget(self.filter_combo)
        
        control_layout.addSpacing(20)
        
        # Language selector déplacé ici
        lang_label = QLabel("Language:")
        lang_label.setStyleSheet("color: #888888; font-size: 10pt;")
        self.lang_combo = QComboBox()
        self.lang_combo.addItems(["Français", "English"])
        self.lang_combo.setCurrentIndex(1)
        self.lang_combo.setFixedSize(120, 35)
        self.lang_combo.currentTextChanged.connect(self.change_language)
        
        control_layout.addWidget(lang_label)
        control_layout.addWidget(self.lang_combo)
        
        control_layout.addStretch()
        
        self.counter_label = QLabel(f"{self.t('packets')}: 0/{self.MAX_PACKETS}")
        self.counter_label.setStyleSheet("color: white; font-size: 11pt; font-weight: bold;")
        control_layout.addWidget(self.counter_label)
        
        main_layout.addWidget(control_frame)
        
        # Contenu principal
        content_layout = QHBoxLayout()
        content_layout.setContentsMargins(20, 0, 20, 20)
        content_layout.setSpacing(20)
        
        # Panneau gauche
        left_panel = QFrame()
        left_panel.setStyleSheet("background-color: #1a1a1a;")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        self.left_label = QLabel(self.t("requests_list"))
        self.left_label.setStyleSheet("color: #888888; font-size: 10pt; font-weight: bold; padding: 10px; font-family: 'Georgia', serif;")
        left_layout.addWidget(self.left_label)
        
        search_layout = QHBoxLayout()
        search_layout.setContentsMargins(10, 0, 10, 10)
        self.search_label = QLabel(self.t("search_ip"))
        self.search_label.setStyleSheet("color: #888888; font-size: 9pt;")
        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText(self.t("enter_ip"))
        self.search_entry.textChanged.connect(self.on_search)
        
        clear_search_btn = QPushButton("✕")
        clear_search_btn.setFixedSize(30, 30)
        clear_search_btn.clicked.connect(self.clear_search)
        
        search_layout.addWidget(self.search_label)
        search_layout.addWidget(self.search_entry)
        search_layout.addWidget(clear_search_btn)
        left_layout.addLayout(search_layout)
        
        self.packet_listbox = QListWidget()
        self.packet_listbox.itemClicked.connect(self.on_packet_select)
        self.packet_listbox.currentRowChanged.connect(self.on_packet_row_changed)
        self.packet_listbox.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.packet_listbox.customContextMenuRequested.connect(self.show_list_context_menu)
        left_layout.addWidget(self.packet_listbox)
        
        # Panneau droit
        right_panel = QFrame()
        right_panel.setStyleSheet("background-color: #1a1a1a;")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        self.right_label = QLabel(self.t("request_details"))
        self.right_label.setStyleSheet("color: #888888; font-size: 10pt; font-weight: bold; padding: 10px; font-family: 'Georgia', serif;")
        right_layout.addWidget(self.right_label)
        
        self.details_text = QTextBrowser()
        self.details_text.setOpenExternalLinks(True)
        self.details_text.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.details_text.customContextMenuRequested.connect(self.show_details_context_menu)
        right_layout.addWidget(self.details_text)
        
        content_layout.addWidget(left_panel, 6)
        content_layout.addWidget(right_panel, 14)
        
        main_layout.addLayout(content_layout)
        
        self.footer = QLabel(self.t("footer"))
        self.footer.setStyleSheet("color: #666666; font-size: 8pt; padding: 10px;")
        self.footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.footer)
    
    def get_status_badge(self, score):
        """Retourne un badge ROND moderne pour le statut de sécurité"""
        if score == 0:
            return f"""<span style='display: inline-flex; align-items: center; justify-content: center;
                      width: 28px; height: 28px; background: #00c853; 
                      color: white; border-radius: 50%; font-size: 16pt; font-weight: bold;
                      box-shadow: 0 2px 6px rgba(0,200,83,0.4); margin: 0 4px;'>o</span>
                      <span style='color: #888888; font-size: 13pt; font-weight: bold;'>{score}/95</span>"""
        else:
            return f"""<span style='display: inline-flex; align-items: center; justify-content: center;
                       width: 28px; height: 28px; background: #ff1744; 
                       color: white; border-radius: 50%; font-size: 16pt; font-weight: bold;
                       box-shadow: 0 2px 6px rgba(255,23,68,0.4); margin: 0 4px;'>✕</span>
                       <span style='color: #888888; font-size: 13pt; font-weight: bold;'>{score}/95</span>"""
    
    def get_threat_icon(self):
        """Retourne l'icône X RONDE surlignée en rouge pour la liste"""
        return """<span style='display: inline-flex; align-items: center; justify-content: center;
                  width: 20px; height: 20px; background: #ff1744; 
                  color: white; border-radius: 50%; font-size: 11pt; font-weight: bold;
                  box-shadow: 0 1px 3px rgba(255,23,68,0.4);'>✕</span>"""
    
    def change_language(self, lang):
        self.language = "fr" if lang == "Français" else "en"
        self.update_ui_language()
    
    def update_ui_language(self):
        if self.capturing:
            self.capture_btn.setText(self.t("stop"))
        else:
            self.capture_btn.setText(self.t("start"))
        
        self.clear_btn.setText(self.t("clear"))
        self.export_btn.setText(self.t("export_pcap"))
        self.counter_label.setText(f"{self.t('packets')}: {self.packet_count}/{self.MAX_PACKETS}")
        self.left_label.setText(self.t("requests_list"))
        self.right_label.setText(self.t("request_details"))
        self.footer.setText(self.t("footer"))
        self.filter_label.setText(self.t("filter"))
        self.search_label.setText(self.t("search_ip"))
        self.search_entry.setPlaceholderText(self.t("enter_ip"))
        
        current_index = self.filter_combo.currentIndex()
        if self.language == "en":
            self.filter_combo.clear()
            self.filter_combo.addItems(["HTTP/HTTPS", "HTTP", "HTTPS", "✕ Malicious"])
        else:
            self.filter_combo.clear()
            self.filter_combo.addItems(["HTTP/HTTPS", "HTTP", "HTTPS", "✕ Malveillants"])
        self.filter_combo.setCurrentIndex(current_index)
        
        if self.selected_packet:
            self.display_packet_details()
    
    def toggle_capture(self):
        if not self.capturing:
            self.start_capture()
        else:
            self.stop_capture()
    
    def start_capture(self):
        self.capturing = True
        self.capture_btn.setText(self.t("stop"))
        self.capture_btn.setObjectName("stopBtn")
        self.capture_btn.setStyleSheet("")
        self.packet_count = 0
        self.auto_scroll = True
        
        self.sniffer_thread = PacketSnifferThread()
        self.sniffer_thread.packet_captured.connect(self.process_packet)
        self.sniffer_thread.error_occurred.connect(self.show_error)
        self.sniffer_thread.start()
    
    def stop_capture(self):
        self.capturing = False
        if self.sniffer_thread:
            self.sniffer_thread.stop()
        self.capture_btn.setText(self.t("start"))
        self.capture_btn.setObjectName("")
        self.capture_btn.setStyleSheet("")
    
    def process_packet(self, packet):
        try:
            if self.packet_count >= self.MAX_PACKETS:
                if self.capturing:
                    self.stop_capture()
                    QMessageBox.information(self, self.t("limit_reached"), self.t("limit_message"))
                return
            
            if packet.haslayer(TCP) and packet.haslayer(IP):
                tcp_layer = packet[TCP]
                ip_layer = packet[IP]
                
                if tcp_layer.dport == 80 or tcp_layer.sport == 80 or tcp_layer.dport == 443 or tcp_layer.sport == 443:
                    self.packet_count += 1
                    self.counter_label.setText(f"{self.t('packets')}: {self.packet_count}/{self.MAX_PACKETS}")
                    self.raw_packets.append(packet)
                    
                    if len(self.raw_packets) > 10000:
                        self.raw_packets.pop(0)
                    if len(self.packets_data) > 10000:
                        self.packets_data.pop(0)
                    
                    protocol = "HTTPS" if (tcp_layer.dport == 443 or tcp_layer.sport == 443) else "HTTP"
                    domain = "N/A"
                    http_request = ""
                    http_response = ""
                    raw_payload = ""
                    
                    if packet.haslayer(Raw):
                        try:
                            payload = packet[Raw].load
                            raw_payload = payload.hex()[:500]
                            
                            try:
                                payload_str = payload.decode('utf-8', errors='ignore')
                                if 'Host: ' in payload_str:
                                    host_start = payload_str.find('Host: ') + 6
                                    host_end = payload_str.find('\r\n', host_start)
                                    if host_end != -1:
                                        domain = payload_str[host_start:host_end].strip()
                                
                                if any(method in payload_str for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ']):
                                    http_request = payload_str[:500]
                                
                                if payload_str.startswith('HTTP/'):
                                    http_response = payload_str[:500]
                            except:
                                pass
                            
                            if domain == "N/A" and protocol == "HTTPS":
                                try:
                                    if len(payload) > 43 and payload[0] == 0x16:
                                        i = 43
                                        while i < len(payload) - 4:
                                            if i < len(payload) - 9:
                                                ext_type = (payload[i] << 8) | payload[i + 1]
                                                ext_len = (payload[i] << 8) | payload[i + 3]
                                                
                                                if ext_type == 0:
                                                    sni_list_len = (payload[i + 4] << 8) | payload[i + 5]
                                                    sni_type = payload[i + 6]
                                                    sni_len = (payload[i + 7] << 8) | payload[i + 8]
                                                    
                                                    if sni_type == 0 and i + 9 + sni_len <= len(payload):
                                                        domain = payload[i + 9:i + 9 + sni_len].decode('utf-8', errors='ignore')
                                                        break
                                                
                                                i += 4 + ext_len
                                            else:
                                                break
                                except:
                                    pass
                        except:
                            pass
                    
                    packet_data = {
                        'id': self.packet_count,
                        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'protocol': protocol,
                        'domain': domain,
                        'src_ip': ip_layer.src,
                        'src_port': tcp_layer.sport,
                        'dst_ip': ip_layer.dst,
                        'dst_port': tcp_layer.dport,
                        'flags': str(tcp_layer.flags),
                        'seq': tcp_layer.seq,
                        'ack': tcp_layer.ack,
                        'size': len(packet),
                        'http_request': http_request,
                        'http_response': http_response,
                        'raw_payload': raw_payload,
                        'url': f"{'https' if protocol == 'HTTPS' else 'http'}://{domain}" if domain != "N/A" else "N/A",
                        'vt_checked': False,
                        'vt_score': None,
                        'as_info': None,
                        'dst_vt_checked': False,
                        'dst_vt_score': None,
                        'dst_as_info': None,
                        'domain_vt_checked': False,
                        'domain_vt_score': None,
                        'domain_categories': None
                    }
                    
                    self.packets_data.append(packet_data)
                    
                    should_add = False
                    if self.filter_protocol == "malicious":
                        pass
                    elif self.filter_protocol == "both" or \
                       (self.filter_protocol == "http" and protocol == "HTTP") or \
                       (self.filter_protocol == "https" and protocol == "HTTPS"):
                        should_add = True
                    
                    if should_add:
                        is_private = self.is_private_ip(ip_layer.src)
                        ip_color = "#ffffff" if is_private else "#ff69b4"
                        
                        display_text = f"{protocol:5} | {ip_layer.src}"
                        
                        item = QListWidgetItem(display_text)
                        item.setForeground(QColor(ip_color))
                        self.packet_listbox.addItem(item)
                        
                        if self.auto_scroll:
                            self.packet_listbox.scrollToBottom()
        except Exception as e:
            pass
    
    def is_private_ip(self, ip):
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first = int(parts[0])
            second = int(parts[1])
            
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
            if first == 169 and second == 254:
                return True
            
            return False
        except:
            return False
    
    def process_vt_queue(self):
        if self.vt_analyzing or not self.vt_analysis_queue:
            return
        
        self.vt_analyzing = True
        task = self.vt_analysis_queue.pop(0)
        
        if task['type'] == 'ip':
            self.auto_analyze_ip(task['ip'], task['is_source'])
        elif task['type'] == 'domain':
            self.auto_analyze_domain(task['domain'])
        
        self.vt_analyzing = False
    
    def update_selected_packet_data(self):
        if self.selected_packet_id:
            for packet in self.packets_data:
                if packet['id'] == self.selected_packet_id:
                    self.selected_packet = packet
                    break
    
    def auto_analyze_ip(self, ip, is_source):
        if self.is_private_ip(ip):
            return
        
        if ip in self.vt_cache:
            for packet in self.packets_data:
                if is_source and packet['src_ip'] == ip:
                    packet['vt_checked'] = True
                    packet['vt_score'] = self.vt_cache[ip]['score']
                    packet['as_info'] = self.vt_cache[ip]['as_info']
                elif not is_source and packet['dst_ip'] == ip:
                    packet['dst_vt_checked'] = True
                    packet['dst_vt_score'] = self.vt_cache[ip]['score']
                    packet['dst_as_info'] = self.vt_cache[ip]['as_info']
            
            self.update_selected_packet_data()
            self.display_packet_details()
            return
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": "8355be10b22191e7e352acc41b533750ccfd89fbdadd2454973ba978c5ad3cc6"}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                score = malicious + suspicious
                
                as_owner = data.get('data', {}).get('attributes', {}).get('as_owner', '')
                asn = data.get('data', {}).get('attributes', {}).get('asn', '')
                as_info = f"AS{asn} ({as_owner})" if asn else as_owner
                
                self.vt_cache[ip] = {'score': score, 'as_info': as_info}
                
                for packet in self.packets_data:
                    if packet['src_ip'] == ip:
                        packet['vt_checked'] = True
                        packet['vt_score'] = score
                        packet['as_info'] = as_info
                    if packet['dst_ip'] == ip:
                        packet['dst_vt_checked'] = True
                        packet['dst_vt_score'] = score
                        packet['dst_as_info'] = as_info
                
                if score >= 1:
                    try:
                        notification.notify(
                            title="⚠️ Menace détectée!",
                            message=f"IP: {ip}\nScore: {score}/95\nMenaces détectées par VirusTotal",
                            app_name="HTTP Capture NXN",
                            timeout=10
                        )
                    except:
                        pass
                
                self.update_selected_packet_data()
                self.refresh_listbox()
                self.display_packet_details()
        except:
            pass
    
    def auto_analyze_domain(self, domain):
        if domain == "N/A" or not domain:
            return
        
        if domain in self.vt_domain_cache:
            for packet in self.packets_data:
                if packet['domain'] == domain:
                    packet['domain_vt_checked'] = True
                    packet['domain_vt_score'] = self.vt_domain_cache[domain]['score']
                    packet['domain_categories'] = self.vt_domain_cache[domain]['categories']
            
            self.update_selected_packet_data()
            self.display_packet_details()
            return
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": "8355be10b22191e7e352acc41b533750ccfd89fbdadd2454973ba978c5ad3cc6"}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                score = malicious + suspicious
                
                categories = data.get('data', {}).get('attributes', {}).get('categories', {})
                category_list = list(categories.values())[:3]
                categories_str = ", ".join(category_list) if category_list else "N/A"
                
                self.vt_domain_cache[domain] = {'score': score, 'categories': categories_str}
                
                for packet in self.packets_data:
                    if packet['domain'] == domain:
                        packet['domain_vt_checked'] = True
                        packet['domain_vt_score'] = score
                        packet['domain_categories'] = categories_str
                
                if score >= 1:
                    try:
                        notification.notify(
                            title="⚠️ Domaine malveillant détecté!",
                            message=f"Domaine: {domain}\nScore: {score}/95\nMenaces détectées par VirusTotal",
                            app_name="HTTP Capture NXN",
                            timeout=10
                        )
                    except:
                        pass
                
                self.update_selected_packet_data()
                self.display_packet_details()
        except:
            pass
    
    def on_packet_row_changed(self, row):
        if row >= 0:
            self.auto_scroll = False
            
            visible_packets = []
            search_term = self.search_entry.text().strip()
            
            for idx, packet_data in enumerate(self.packets_data):
                protocol = packet_data['protocol']
                src_ip = packet_data['src_ip']
                dst_ip = packet_data['dst_ip']
                
                if self.filter_protocol == "malicious":
                    src_is_public = not self.is_private_ip(src_ip)
                    dst_is_public = not self.is_private_ip(dst_ip)
                    
                    src_is_malicious = src_is_public and packet_data.get('vt_checked') and packet_data.get('vt_score', 0) >= 1
                    dst_is_malicious = dst_is_public and packet_data.get('dst_vt_checked') and packet_data.get('dst_vt_score', 0) >= 1
                    
                    if not (src_is_malicious or dst_is_malicious):
                        continue
                else:
                    protocol_match = (self.filter_protocol == "both" or \
                                     (self.filter_protocol == "http" and protocol == "HTTP") or \
                                     (self.filter_protocol == "https" and protocol == "HTTPS"))
                    
                    if not protocol_match:
                        continue
                
                if search_term and src_ip != search_term:
                    continue
                
                visible_packets.append(idx)
            
            if row < len(visible_packets):
                real_index = visible_packets[row]
                self.selected_packet = self.packets_data[real_index]
                self.selected_packet_id = self.selected_packet['id']
                
                src_ip = self.selected_packet['src_ip']
                dst_ip = self.selected_packet['dst_ip']
                domain = self.selected_packet['domain']
                
                if not self.selected_packet['vt_checked'] and not self.is_private_ip(src_ip):
                    task = {'type': 'ip', 'ip': src_ip, 'is_source': True}
                    if task not in self.vt_analysis_queue:
                        self.vt_analysis_queue.append(task)
                
                if not self.selected_packet.get('dst_vt_checked') and not self.is_private_ip(dst_ip):
                    task = {'type': 'ip', 'ip': dst_ip, 'is_source': False}
                    if task not in self.vt_analysis_queue:
                        self.vt_analysis_queue.append(task)
                
                if not self.selected_packet.get('domain_vt_checked') and domain != "N/A":
                    task = {'type': 'domain', 'domain': domain}
                    if task not in self.vt_analysis_queue:
                        self.vt_analysis_queue.append(task)
                
                self.display_packet_details()
    
    def on_packet_select(self, item):
        self.auto_scroll = False
        
        index = self.packet_listbox.row(item)
        
        visible_packets = []
        search_term = self.search_entry.text().strip()
        
        for idx, packet_data in enumerate(self.packets_data):
            protocol = packet_data['protocol']
            src_ip = packet_data['src_ip']
            dst_ip = packet_data['dst_ip']
            
            if self.filter_protocol == "malicious":
                src_is_public = not self.is_private_ip(src_ip)
                dst_is_public = not self.is_private_ip(dst_ip)
                
                src_is_malicious = src_is_public and packet_data.get('vt_checked') and packet_data.get('vt_score', 0) >= 1
                dst_is_malicious = dst_is_public and packet_data.get('dst_vt_checked') and packet_data.get('dst_vt_score', 0) >= 1
                
                if not (src_is_malicious or dst_is_malicious):
                    continue
            else:
                protocol_match = (self.filter_protocol == "both" or \
                                 (self.filter_protocol == "http" and protocol == "HTTP") or \
                                 (self.filter_protocol == "https" and protocol == "HTTPS"))
                
                if not protocol_match:
                    continue
            
            if search_term and src_ip != search_term:
                continue
            
            visible_packets.append(idx)
        
        if index < len(visible_packets):
            real_index = visible_packets[index]
            self.selected_packet = self.packets_data[real_index]
            self.selected_packet_id = self.selected_packet['id']
            
            src_ip = self.selected_packet['src_ip']
            dst_ip = self.selected_packet['dst_ip']
            domain = self.selected_packet['domain']
            
            if not self.selected_packet['vt_checked'] and not self.is_private_ip(src_ip):
                task = {'type': 'ip', 'ip': src_ip, 'is_source': True}
                if task not in self.vt_analysis_queue:
                    self.vt_analysis_queue.append(task)
            
            if not self.selected_packet.get('dst_vt_checked') and not self.is_private_ip(dst_ip):
                task = {'type': 'ip', 'ip': dst_ip, 'is_source': False}
                if task not in self.vt_analysis_queue:
                    self.vt_analysis_queue.append(task)
            
            if not self.selected_packet.get('domain_vt_checked') and domain != "N/A":
                task = {'type': 'domain', 'domain': domain}
                if task not in self.vt_analysis_queue:
                    self.vt_analysis_queue.append(task)
            
            self.display_packet_details()
    
    def display_packet_details(self):
        if not self.selected_packet:
            return
        
        p = self.selected_packet
        
        src_ip_color = "#ffffff" if self.is_private_ip(p['src_ip']) else "#ff69b4"
        dst_ip_color = "#ffffff" if self.is_private_ip(p['dst_ip']) else "#ff69b4"
        
        thin_line = "<div style='border-top: 1px solid #444444; margin: 8px 0;'></div>"
        
        html = f"""
        {thin_line}
        <div style='color: #ffffff; font-weight: bold; font-size: 16pt; margin: 10px 0;'>▸ {self.t("general_info")}</div>
        {thin_line}
        <br>
        <span style='color: #ffffff;'>{self.t("packet_id")}       : </span><span style='color: #ffffff;'>#{p['id']}</span><br>
        <span style='color: #ffffff;'>{self.t("protocol")}       : </span><span style='color: #ffffff;'>{p['protocol']}</span><br>"""
        
        if p['domain'] != "N/A":
            html += f"""<span style='color: #ffffff;'>{self.t("domain")}         : </span><span style='color: #ffffff; font-weight: bold;'>{p['domain']}</span>"""
            
            if p.get('domain_vt_checked') and p.get('domain_vt_score') is not None:
                badge = self.get_status_badge(p['domain_vt_score'])
                html += f""" <span style='color: #ffffff;'>{self.t("auto_analysis")}</span> {badge}"""
                html += f""" <a href='https://www.virustotal.com/gui/domain/{p["domain"]}' style='color: #00aaff; text-decoration: none;'>{self.t("vt_link")}</a>"""
                
                if p.get('domain_categories') and p['domain_categories'] != "N/A":
                    html += f""" <span style='color: #ffffff;'>- {p['domain_categories']}</span>"""
            
            html += "<br>"
        
        if p['url'] != "N/A":
            html += f"""<span style='color: #ffffff;'>{self.t("url")}             : </span><a href='{p['url']}' style='color: #00aaff;'>{p['url']}</a><br>"""
        
        html += f"""<span style='color: #ffffff;'>{self.t("size")}          : </span><span style='color: #ffffff;'>{p['size']} {self.t("bytes")}</span><br><br>"""
        
        # Ligne blanche entre Information Générale et Information Réseau
        html += f"""<div style='border-top: 2px solid #ffffff; margin: 15px 0;'></div>"""
        
        html += f"""
        {thin_line}
        <div style='color: #ffffff; font-weight: bold; font-size: 16pt; margin: 10px 0;'>▸ {self.t("network_info")}</div>
        {thin_line}
        <br>
        <span style='color: #ffffff;'>{self.t("source")}          : </span><span style='color: {src_ip_color};' class='ip-address'>{p['src_ip']}</span>"""
        
        if not self.is_private_ip(p['src_ip']) and p['vt_checked'] and p['vt_score'] is not None:
            badge = self.get_status_badge(p['vt_score'])
            html += f""" <span style='color: #ffffff;'>{self.t("auto_analysis")}</span> {badge}"""
            html += f""" <a href='https://www.virustotal.com/gui/ip-address/{p['src_ip']}' style='color: #00aaff; text-decoration: none;'>{self.t("vt_link")}</a>"""
            
            if p.get('as_info'):
                as_name = p['as_info']
                if '(' in as_name and ')' in as_name:
                    as_name = as_name[as_name.find('(')+1:as_name.find(')')]
                html += f""" <span style='color: #ffffff;'>- {as_name}</span>"""
        
        html += "<br>"
        
        html += f"""<span style='color: #ffffff;'>{self.t("destination")}     : </span><span style='color: {dst_ip_color};' class='ip-address'>{p['dst_ip']}</span>"""
        
        if not self.is_private_ip(p['dst_ip']) and p.get('dst_vt_checked') and p.get('dst_vt_score') is not None:
            badge = self.get_status_badge(p['dst_vt_score'])
            html += f""" <span style='color: #ffffff;'>{self.t("auto_analysis")}</span> {badge}"""
            html += f""" <a href='https://www.virustotal.com/gui/ip-address/{p['dst_ip']}' style='color: #00aaff; text-decoration: none;'>{self.t("vt_link")}</a>"""
            
            if p.get('dst_as_info'):
                as_name = p['dst_as_info']
                if '(' in as_name and ')' in as_name:
                    as_name = as_name[as_name.find('(')+1:as_name.find(')')]
                html += f""" <span style='color: #ffffff;'>- {as_name}</span>"""
        
        html += f"""<br>
        <span style='color: #ffffff;'>{self.t("tcp_flags")}       : </span><span style='color: #ffffff;'>{p['flags']}</span><br>
        <span style='color: #ffffff;'>{self.t("sequence")}        : </span><span style='color: #ffffff;'>{p['seq']}</span><br>
        <span style='color: #ffffff;'>{self.t("acknowledgment")}  : </span><span style='color: #ffffff;'>{p['ack']}</span><br><br>"""
        
        if p['http_request']:
            html += f"""
            {thin_line}
            <div style='color: #ffffff; font-weight: bold; font-size: 16pt; margin: 10px 0;'>▸ {self.t("http_request")}</div>
            {thin_line}
            <div style='color: #ff00ff; background-color: #1a1a1a; padding: 10px; border-left: 3px solid #ff00ff; margin: 10px 0;'><pre style='margin: 0; white-space: pre-wrap; word-wrap: break-word; font-family: monospace;'>{p['http_request']}</pre></div><br>"""
        
        if p['http_response']:
            html += f"""
            {thin_line}
            <div style='color: #ffffff; font-weight: bold; font-size: 16pt; margin: 10px 0;'>▸ {self.t("http_response")}</div>
            {thin_line}
            <div style='color: #ff00ff; background-color: #1a1a1a; padding: 10px; border-left: 3px solid #ff00ff; margin: 10px 0;'><pre style='margin: 0; white-space: pre-wrap; word-wrap: break-word; font-family: monospace;'>{p['http_response']}</pre></div><br>"""
        
        if p['raw_payload']:
            html += f"""
            {thin_line}
            <div style='color: #ffffff; font-weight: bold; font-size: 16pt; margin: 10px 0;'>▸ {self.t("raw_payload")}</div>
            {thin_line}
            <div style='color: #ffffff; background-color: #1a1a1a; padding: 10px; border-left: 3px solid #00ff00; margin: 10px 0;'><pre style='margin: 0; white-space: pre-wrap; word-wrap: break-word; font-family: monospace;'>{p['raw_payload']}</pre></div>"""
        
        self.details_text.setHtml(html)
    
    def change_filter(self, filter_text):
        if filter_text == "HTTP":
            self.filter_protocol = "http"
        elif filter_text == "HTTPS":
            self.filter_protocol = "https"
        elif filter_text in ["✕ Malveillants", "✕ Malicious"]:
            self.filter_protocol = "malicious"
        else:
            self.filter_protocol = "both"
        self.refresh_listbox()
    
    def refresh_listbox(self):
        current_row = self.packet_listbox.currentRow()
        self.packet_listbox.clear()
        
        search_term = self.search_entry.text().strip()
        
        for idx, packet_data in enumerate(self.packets_data):
            protocol = packet_data['protocol']
            src_ip = packet_data['src_ip']
            dst_ip = packet_data['dst_ip']
            
            if self.filter_protocol == "malicious":
                src_is_public = not self.is_private_ip(src_ip)
                dst_is_public = not self.is_private_ip(dst_ip)
                
                src_is_malicious = src_is_public and packet_data.get('vt_checked') and packet_data.get('vt_score', 0) >= 1
                dst_is_malicious = dst_is_public and packet_data.get('dst_vt_checked') and packet_data.get('dst_vt_score', 0) >= 1
                
                if not (src_is_malicious or dst_is_malicious):
                    continue
            else:
                protocol_match = (self.filter_protocol == "both" or \
                                 (self.filter_protocol == "http" and protocol == "HTTP") or \
                                 (self.filter_protocol == "https" and protocol == "HTTPS"))
                
                if not protocol_match:
                    continue
            
            if search_term and src_ip != search_term:
                continue
            
            src_is_public = not self.is_private_ip(src_ip)
            src_malicious = src_is_public and packet_data.get('vt_checked') and packet_data.get('vt_score', 0) >= 1
            
            dst_is_public = not self.is_private_ip(dst_ip)
            dst_malicious = dst_is_public and packet_data.get('dst_vt_checked') and packet_data.get('dst_vt_score', 0) >= 1
            
            show_threat = src_malicious or dst_malicious
            
            org_name = ""
            if src_is_public and packet_data.get('vt_checked'):
                as_info = packet_data.get('as_info', '')
                if as_info and '(' in as_info and ')' in as_info:
                    org_name = as_info[as_info.find('(')+1:as_info.find(')')]
                    org_name = f"({org_name[:20]}) "
            
            threat_marker = "✕ " if show_threat else ""
            
            is_private = self.is_private_ip(src_ip)
            ip_color = "#ffffff" if is_private else "#ff69b4"
            
            display_text = f"{protocol:5} | {threat_marker}{org_name}{src_ip}"
            
            item = QListWidgetItem(display_text)
            item.setForeground(QColor(ip_color))
            self.packet_listbox.addItem(item)
        
        if current_row >= 0 and current_row < self.packet_listbox.count():
            self.packet_listbox.setCurrentRow(current_row)
    
    def on_search(self):
        self.refresh_listbox()
    
    def clear_search(self):
        self.search_entry.clear()
        self.refresh_listbox()
    
    def clear_output(self):
        self.packet_listbox.clear()
        self.details_text.clear()
        self.packets_data = []
        self.raw_packets = []
        self.selected_packet = None
        self.selected_packet_id = None
        self.packet_count = 0
        self.vt_cache = {}
        self.vt_domain_cache = {}
        self.vt_analysis_queue = []
        self.counter_label.setText(f"{self.t('packets')}: 0/{self.MAX_PACKETS}")
        self.auto_scroll = True
    
    def export_pcap(self):
        if not self.raw_packets:
            QMessageBox.warning(self, "Attention", "Aucun paquet à exporter")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Exporter PCAP",
            f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap",
            "PCAP files (*.pcap);;All files (*.*)"
        )
        
        if filename:
            try:
                wrpcap(filename, self.raw_packets)
                QMessageBox.information(self, "Succès", f"Export réussi: {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de l'export: {str(e)}")
    
    def show_error(self, message):
        QMessageBox.critical(self, "Erreur", message)
    
    def show_list_context_menu(self, position):
        menu = QMenu()
        copy_action = QAction("Copier", self)
        copy_action.triggered.connect(self.copy_selected)
        menu.addAction(copy_action)
        menu.exec(self.packet_listbox.mapToGlobal(position))
    
    def show_details_context_menu(self, position):
        menu = QMenu()
        
        cursor = self.details_text.cursorForPosition(position)
        cursor.select(QTextCursor.SelectionType.LineUnderCursor)
        line_text = cursor.selectedText()
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_match = re.search(ip_pattern, line_text)
        
        if ip_match:
            ip_address = ip_match.group()
            copy_ip_action = QAction(f"{self.t('copy_ip')}: {ip_address}", self)
            copy_ip_action.triggered.connect(lambda: QApplication.clipboard().setText(ip_address))
            menu.addAction(copy_ip_action)
            menu.addSeparator()
        
        copy_action = QAction("Copier", self)
        copy_action.triggered.connect(self.copy_details)
        select_all_action = QAction("Tout sélectionner", self)
        select_all_action.triggered.connect(self.select_all_details)
        
        menu.addAction(copy_action)
        menu.addAction(select_all_action)
        menu.exec(self.details_text.mapToGlobal(position))
    
    def copy_selected(self):
        current_item = self.packet_listbox.currentItem()
        if current_item:
            QApplication.clipboard().setText(current_item.text())
    
    def copy_details(self):
        cursor = self.details_text.textCursor()
        if cursor.hasSelection():
            QApplication.clipboard().setText(cursor.selectedText())
    
    def select_all_details(self):
        self.details_text.selectAll()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HTTPCaptureApp()
    window.show()
    sys.exit(app.exec())