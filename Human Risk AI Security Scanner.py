# professional_device_scanner.py - Professional Security Scanner with Report Generation
import os
import sys
import json
import time
import hashlib
import threading
import requests
import psutil
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import ctypes
import glob
import base64
from io import BytesIO

# ============ CONFIGURATION ============
VT_API_KEY = ""  # Add your VirusTotal API key here (optional)

# File extensions to scan
SCAN_EXTENSIONS = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.apk', '.msi', '.com', '.zip', '.rar', '.docm', '.xlsm', '.pptm']

# Author Info
AUTHOR_NAME = "Abhishek Rampariya"
AUTHOR_EMAIL = "rampariyaabhishek@gmail.com"
AUTHOR_GITHUB = "github.com/abhishekrampariya"

# ============ COMPLETE DEVICE SCANNER ============
class CompleteDeviceScanner:
    def __init__(self):
        self.scan_results = {
            'total_files': 0,
            'scanned_files': 0,
            'suspicious_files': [],
            'infected_files': [],
            'large_files': [],
            'hidden_files': [],
            'scan_log': [],
            'scan_complete': False,
            'scan_start_time': None,
            'scan_end_time': None,
            'scan_duration_seconds': 0
        }
        self.scanning = False
        self.current_scan_progress = 0
        self.current_file = ""
        self.system_info = {}
        self.processes = []
        self.network_connections = []
        self.recent_files = []
        self.suspicious_activities = []
        
    def get_system_info(self):
        """Get complete system information"""
        try:
            self.system_info = {
                'os': platform.system(),
                'os_version': platform.version(),
                'os_release': platform.release(),
                'hostname': socket.gethostname(),
                'cpu_count': psutil.cpu_count(),
                'cpu_percent': psutil.cpu_percent(interval=0.5),
                'memory_percent': psutil.virtual_memory().percent,
                'memory_available': round(psutil.virtual_memory().available / (1024**3), 2),
                'memory_total': round(psutil.virtual_memory().total / (1024**3), 2),
                'disk_usage': {},
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
            }
            
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    self.system_info['disk_usage'][partition.mountpoint] = {
                        'total': round(usage.total / (1024**3), 2),
                        'used': round(usage.used / (1024**3), 2),
                        'free': round(usage.free / (1024**3), 2),
                        'percent': usage.percent
                    }
                except:
                    pass
        except Exception as e:
            print(f"System info error: {e}")
        
        return self.system_info
    
    def get_running_processes(self):
        """Get all running processes with details"""
        self.processes = []
        suspicious_keywords = ['meterpreter', 'mimikatz', 'nc.exe', 'netcat', 'nmap', 'wireshark', 
                               'hydra', 'john', 'hashcat', 'sqlmap', 'burp', 'metasploit', 
                               'cobalt', 'beacon', 'powershell -enc', 'cmd /c']
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    pinfo = proc.info
                    proc_name = pinfo['name'].lower() if pinfo['name'] else ''
                    proc_exe = pinfo['exe'].lower() if pinfo['exe'] else ''
                    
                    is_suspicious = False
                    reason = None
                    
                    for keyword in suspicious_keywords:
                        if keyword in proc_name or keyword in proc_exe:
                            is_suspicious = True
                            reason = f"Known tool: {keyword}"
                            break
                    
                    cpu = pinfo['cpu_percent'] or 0
                    memory = pinfo['memory_percent'] or 0
                    
                    if cpu > 80:
                        is_suspicious = True
                        reason = f"High CPU usage: {cpu}%"
                    
                    self.processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'exe': pinfo['exe'],
                        'cpu': round(cpu, 1),
                        'memory': round(memory, 1),
                        'suspicious': is_suspicious,
                        'reason': reason
                    })
                except:
                    pass
        except Exception as e:
            print(f"Process error: {e}")
        
        return self.processes[:100]
    
    def get_network_connections(self):
        """Get active network connections"""
        self.network_connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    is_suspicious = False
                    
                    if not (remote_ip.startswith('192.168.') or remote_ip.startswith('10.') or 
                           remote_ip.startswith('172.') or remote_ip == '127.0.0.1'):
                        is_suspicious = True
                    
                    self.network_connections.append({
                        'local_ip': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'N/A',
                        'remote_ip': f"{remote_ip}:{conn.raddr.port}",
                        'pid': conn.pid,
                        'status': conn.status,
                        'suspicious': is_suspicious
                    })
        except:
            pass
        
        return self.network_connections[:50]
    
    def get_recent_files(self):
        """Get recently downloaded/modified files"""
        self.recent_files = []
        try:
            if platform.system() == 'Windows':
                paths = [
                    os.path.expanduser("~\\Downloads"),
                    os.path.expanduser("~\\Desktop"),
                    os.path.expanduser("~\\Documents")
                ]
            else:
                paths = [
                    os.path.expanduser("~/Downloads"),
                    os.path.expanduser("~/Desktop"),
                    os.path.expanduser("~/Documents")
                ]
            
            for search_path in paths:
                if os.path.exists(search_path):
                    for file in os.listdir(search_path)[:50]:
                        file_path = os.path.join(search_path, file)
                        if os.path.isfile(file_path):
                            mod_time = os.path.getmtime(file_path)
                            if time.time() - mod_time < 86400:
                                ext = os.path.splitext(file)[1].lower()
                                self.recent_files.append({
                                    'name': file,
                                    'path': file_path,
                                    'extension': ext,
                                    'size_mb': round(os.path.getsize(file_path) / (1024**2), 2),
                                    'modified': datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
                                })
        except Exception as e:
            print(f"Recent files error: {e}")
        
        return self.recent_files[:30]
    
    def check_suspicious_activities(self):
        """Detect suspicious activities on device"""
        self.suspicious_activities = []
        
        cpu_percent = psutil.cpu_percent(interval=0.5)
        if cpu_percent > 80:
            self.suspicious_activities.append({
                'type': 'High CPU Usage',
                'detail': f'CPU usage is at {cpu_percent}%',
                'risk': 'Medium',
                'recommendation': 'Check running processes for unusual activity'
            })
        
        memory_percent = psutil.virtual_memory().percent
        if memory_percent > 90:
            self.suspicious_activities.append({
                'type': 'High Memory Usage',
                'detail': f'Memory usage at {memory_percent}%',
                'risk': 'Medium',
                'recommendation': 'Close unnecessary applications'
            })
        
        suspicious_procs = [p for p in self.processes if p.get('suspicious')]
        if suspicious_procs:
            for proc in suspicious_procs[:5]:
                self.suspicious_activities.append({
                    'type': 'Suspicious Process',
                    'detail': f'Process "{proc["name"]}" (PID: {proc["pid"]}) - {proc.get("reason", "Unknown")}',
                    'risk': 'High',
                    'recommendation': 'Investigate this process immediately'
                })
        
        suspicious_conns = [c for c in self.network_connections if c.get('suspicious')]
        if suspicious_conns:
            for conn in suspicious_conns[:5]:
                self.suspicious_activities.append({
                    'type': 'Suspicious Network Connection',
                    'detail': f'Connection to {conn["remote_ip"]}',
                    'risk': 'High',
                    'recommendation': 'Unknown external connection detected'
                })
        
        suspicious_files = [f for f in self.recent_files if f['extension'] in ['.exe', '.dll', '.scr', '.apk', '.msi']]
        if suspicious_files:
            for file in suspicious_files[:5]:
                self.suspicious_activities.append({
                    'type': 'Recent Executable Download',
                    'detail': f'File "{file["name"]}" downloaded recently ({file["size_mb"]} MB)',
                    'risk': 'Medium',
                    'recommendation': 'Scan this file before opening'
                })
        
        return self.suspicious_activities
    
    def calculate_file_hash(self, filepath):
        """Calculate SHA256 hash of file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return None
    
    def scan_single_file(self, filepath):
        """Scan a single file"""
        try:
            if not os.path.exists(filepath):
                return None
                
            file_size = os.path.getsize(filepath)
            file_hash = self.calculate_file_hash(filepath)
            ext = os.path.splitext(filepath)[1].lower()
            
            file_info = {
                'path': filepath,
                'name': os.path.basename(filepath),
                'size_mb': round(file_size / (1024 * 1024), 2),
                'extension': ext,
                'hash': file_hash,
                'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat(),
                'is_suspicious': False,
                'risk_score': 0,
                'reason': []
            }
            
            if file_size > 100 * 1024 * 1024:
                file_info['is_suspicious'] = True
                file_info['risk_score'] += 20
                file_info['reason'].append('Large file size')
            
            if platform.system() == 'Windows':
                try:
                    if ctypes.windll.kernel32.GetFileAttributesW(filepath) & 2:
                        file_info['is_suspicious'] = True
                        file_info['risk_score'] += 30
                        file_info['reason'].append('Hidden file')
                except:
                    pass
            
            suspicious_names = ['setup', 'installer', 'crack', 'keygen', 'patch', 'activator', 'hack', 'exploit']
            name_lower = file_info['name'].lower()
            for sus in suspicious_names:
                if sus in name_lower:
                    file_info['is_suspicious'] = True
                    file_info['risk_score'] += 15
                    file_info['reason'].append(f'Contains "{sus}" in name')
                    break
            
            if ext in ['.exe', '.scr', '.bat', '.ps1']:
                file_info['risk_score'] += 10
                if file_info['risk_score'] > 30:
                    file_info['is_suspicious'] = True
            
            return file_info
            
        except Exception as e:
            return None
    
    def scan_directory(self, directory, callback=None):
        """Scan directory recursively"""
        self.scanning = True
        self.scan_results = {
            'total_files': 0,
            'scanned_files': 0,
            'suspicious_files': [],
            'infected_files': [],
            'large_files': [],
            'hidden_files': [],
            'scan_log': [],
            'scan_complete': False,
            'scan_start_time': datetime.now().isoformat(),
            'scan_end_time': None,
            'scan_duration_seconds': 0
        }
        
        files_to_scan = []
        
        if platform.system() == 'Windows':
            scan_paths = ['C:\\Users', 'C:\\Program Files', 'C:\\Program Files (x86)']
        else:
            scan_paths = ['/home', '/usr/local/bin', '/opt']
        
        for scan_path in scan_paths:
            if os.path.exists(scan_path):
                for root, dirs, files in os.walk(scan_path):
                    skip_dirs = ['System32', 'Windows', '$Recycle.Bin', 'AppData\\Local\\Temp']
                    if any(skip in root for skip in skip_dirs):
                        continue
                    
                    for file in files:
                        ext = os.path.splitext(file)[1].lower()
                        if ext in SCAN_EXTENSIONS:
                            files_to_scan.append(os.path.join(root, file))
        
        self.scan_results['total_files'] = len(files_to_scan)
        
        for idx, filepath in enumerate(files_to_scan):
            if not self.scanning:
                break
            
            self.current_scan_progress = (idx + 1) / len(files_to_scan) * 100 if files_to_scan else 0
            self.current_file = filepath
            
            if callback:
                callback(self.current_scan_progress, filepath)
            
            file_info = self.scan_single_file(filepath)
            if file_info and file_info.get('is_suspicious'):
                self.scan_results['suspicious_files'].append(file_info)
            
            self.scan_results['scanned_files'] = idx + 1
            
            if idx % 100 == 0:
                self.scan_results['scan_log'].append({
                    'time': datetime.now().isoformat(),
                    'scanned': idx + 1,
                    'total': len(files_to_scan),
                    'suspicious': len(self.scan_results['suspicious_files'])
                })
        
        self.scanning = False
        self.scan_results['scan_complete'] = True
        self.scan_results['scan_end_time'] = datetime.now().isoformat()
        
        # Calculate duration
        start = datetime.fromisoformat(self.scan_results['scan_start_time'])
        end = datetime.fromisoformat(self.scan_results['scan_end_time'])
        self.scan_results['scan_duration_seconds'] = int((end - start).total_seconds())
        
        return self.scan_results

# ============ REPORT GENERATOR ============
class ReportGenerator:
    @staticmethod
    def generate_json_report(scan_results, system_info, suspicious_activities):
        """Generate JSON report"""
        report = {
            'report_info': {
                'generated_at': datetime.now().isoformat(),
                'tool_name': 'Human Risk AI - Device Security Scanner',
                'author': AUTHOR_NAME,
                'version': '2.0'
            },
            'scan_summary': {
                'total_files_scanned': scan_results['scanned_files'],
                'suspicious_files_found': len(scan_results['suspicious_files']),
                'scan_duration_seconds': scan_results.get('scan_duration_seconds', 0),
                'scan_start_time': scan_results.get('scan_start_time'),
                'scan_end_time': scan_results.get('scan_end_time')
            },
            'system_information': system_info,
            'suspicious_activities': suspicious_activities,
            'suspicious_files': scan_results['suspicious_files']
        }
        return json.dumps(report, indent=2, default=str)
    
    @staticmethod
    def generate_txt_report(scan_results, system_info, suspicious_activities):
        """Generate TXT report"""
        report = []
        report.append("="*80)
        report.append("HUMAN RISK AI - DEVICE SECURITY SCAN REPORT")
        report.append("="*80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Author: {AUTHOR_NAME}")
        report.append("")
        
        report.append("-"*80)
        report.append("SCAN SUMMARY")
        report.append("-"*80)
        report.append(f"Total Files Scanned: {scan_results['scanned_files']}")
        report.append(f"Suspicious Files Found: {len(scan_results['suspicious_files'])}")
        report.append(f"Scan Duration: {scan_results.get('scan_duration_seconds', 0)} seconds")
        report.append(f"Scan Start: {scan_results.get('scan_start_time')}")
        report.append(f"Scan End: {scan_results.get('scan_end_time')}")
        report.append("")
        
        report.append("-"*80)
        report.append("SYSTEM INFORMATION")
        report.append("-"*80)
        report.append(f"OS: {system_info.get('os')} {system_info.get('os_release')}")
        report.append(f"Hostname: {system_info.get('hostname')}")
        report.append(f"CPU Usage: {system_info.get('cpu_percent')}%")
        report.append(f"Memory Usage: {system_info.get('memory_percent')}%")
        report.append("")
        
        if suspicious_activities:
            report.append("-"*80)
            report.append("SUSPICIOUS ACTIVITIES DETECTED")
            report.append("-"*80)
            for act in suspicious_activities:
                report.append(f"[{act['risk']}] {act['type']}")
                report.append(f"    Details: {act['detail']}")
                report.append(f"    Recommendation: {act['recommendation']}")
                report.append("")
        
        if scan_results['suspicious_files']:
            report.append("-"*80)
            report.append("SUSPICIOUS FILES FOUND")
            report.append("-"*80)
            for idx, file in enumerate(scan_results['suspicious_files'][:50], 1):
                report.append(f"{idx}. {file['name']}")
                report.append(f"   Path: {file['path']}")
                report.append(f"   Size: {file['size_mb']} MB")
                report.append(f"   Risk Score: {file['risk_score']}")
                report.append(f"   Reasons: {', '.join(file['reason'])}")
                report.append("")
        else:
            report.append("-"*80)
            report.append("NO SUSPICIOUS FILES FOUND")
            report.append("-"*80)
            report.append("Your system appears to be clean!")
        
        report.append("")
        report.append("="*80)
        report.append("END OF REPORT - Human Risk AI")
        report.append("="*80)
        
        return "\n".join(report)
    
    @staticmethod
    def generate_html_report(scan_results, system_info, suspicious_activities):
        """Generate HTML report"""
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Human Risk AI - Security Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            padding: 40px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .content {{ padding: 30px; }}
        .section {{
            margin-bottom: 30px;
            border-bottom: 2px solid #eee;
            padding-bottom: 20px;
        }}
        .section h2 {{
            color: #302b63;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
            padding-left: 15px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 15px;
        }}
        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        .suspicious-file {{
            background: #fff3e0;
            border-left: 4px solid #ff9800;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
        }}
        .malicious-file {{
            background: #ffebee;
            border-left: 4px solid #f44336;
        }}
        .activity {{
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #eee;
        }}
        .risk-high {{ color: #f44336; }}
        .risk-medium {{ color: #ff9800; }}
        .risk-low {{ color: #4caf50; }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: bold;
        }}
        .badge-high {{ background: #f44336; color: white; }}
        .badge-medium {{ background: #ff9800; color: white; }}
        .badge-low {{ background: #4caf50; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Human Risk AI</h1>
            <p>Device Security Scan Report</p>
            <small>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Scan Summary</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{scan_results['scanned_files']:,}</div>
                        <div class="stat-label">Total Files Scanned</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{len(scan_results['suspicious_files'])}</div>
                        <div class="stat-label">Suspicious Files Found</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{scan_results.get('scan_duration_seconds', 0)}</div>
                        <div class="stat-label">Scan Duration (sec)</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>💻 System Information</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{system_info.get('os', 'Unknown')}</div>
                        <div class="stat-label">Operating System</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{system_info.get('hostname', 'Unknown')}</div>
                        <div class="stat-label">Hostname</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{system_info.get('cpu_percent', 0)}%</div>
                        <div class="stat-label">CPU Usage</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{system_info.get('memory_percent', 0)}%</div>
                        <div class="stat-label">Memory Usage</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>⚠️ Suspicious Activities Detected</h2>
                {''.join([f'''<div class="activity">
                    <strong>{act['type']}</strong>
                    <span class="badge badge-{act['risk'].lower()}">{act['risk']} Risk</span>
                    <p style="margin-top: 8px;">{act['detail']}</p>
                    <small style="color: #666;">💡 {act['recommendation']}</small>
                </div>''' for act in suspicious_activities]) if suspicious_activities else '<p>✅ No suspicious activities detected</p>'}
            </div>
            
            <div class="section">
                <h2>🔴 Suspicious Files Found</h2>
                {''.join([f'''<div class="suspicious-file">
                    <strong>{file['name']}</strong>
                    <span class="badge badge-{'high' if file['risk_score'] > 50 else 'medium'}">Risk Score: {file['risk_score']}</span>
                    <p style="margin-top: 8px;"><strong>Path:</strong> {file['path']}</p>
                    <p><strong>Size:</strong> {file['size_mb']} MB | <strong>Modified:</strong> {file['modified']}</p>
                    <p><strong>Reasons:</strong> {', '.join(file['reason'])}</p>
                </div>''' for file in scan_results['suspicious_files'][:30]]) if scan_results['suspicious_files'] else '<p>✅ No suspicious files found! Your system appears clean.</p>'}
            </div>
        </div>
        
        <div class="footer">
            <p>Human Risk AI - Real-Time Human Behavior Cybersecurity Engine</p>
            <p>Made by <strong>{AUTHOR_NAME}</strong> | Report Generated on {datetime.now().strftime('%Y-%m-%d')}</p>
        </div>
    </div>
</body>
</html>'''
        return html

# ============ HTTP SERVER ============
scanner = CompleteDeviceScanner()
scan_thread = None

class DeviceScannerHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode('utf-8'))
            
        elif self.path == '/api/system_info':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            data = {'success': True, 'system': scanner.get_system_info()}
            self.wfile.write(json.dumps(data, default=str).encode('utf-8'))
            
        elif self.path == '/api/processes':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            data = {'success': True, 'processes': scanner.get_running_processes()}
            self.wfile.write(json.dumps(data, default=str).encode('utf-8'))
            
        elif self.path == '/api/connections':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            data = {'success': True, 'connections': scanner.get_network_connections()}
            self.wfile.write(json.dumps(data, default=str).encode('utf-8'))
            
        elif self.path == '/api/recent_files':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            data = {'success': True, 'files': scanner.get_recent_files()}
            self.wfile.write(json.dumps(data, default=str).encode('utf-8'))
            
        elif self.path == '/api/suspicious_activities':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            scanner.get_running_processes()
            scanner.get_network_connections()
            scanner.get_recent_files()
            data = {'success': True, 'activities': scanner.check_suspicious_activities()}
            self.wfile.write(json.dumps(data, default=str).encode('utf-8'))
            
        elif self.path == '/api/scan_progress':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            data = {
                'success': True,
                'scanning': scanner.scanning,
                'progress': scanner.current_scan_progress,
                'current_file': scanner.current_file,
                'scanned_files': scanner.scan_results['scanned_files'],
                'total_files': scanner.scan_results['total_files'],
                'suspicious_found': len(scanner.scan_results['suspicious_files']),
                'scan_complete': scanner.scan_results.get('scan_complete', False)
            }
            self.wfile.write(json.dumps(data).encode('utf-8'))
            
        elif self.path == '/api/scan_results':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            results = {
                'total_files': scanner.scan_results['total_files'],
                'scanned_files': scanner.scan_results['scanned_files'],
                'suspicious_files': scanner.scan_results['suspicious_files'],
                'scan_log': scanner.scan_results['scan_log'][-20:],
                'scan_complete': scanner.scan_results.get('scan_complete', False),
                'scan_start_time': scanner.scan_results.get('scan_start_time'),
                'scan_end_time': scanner.scan_results.get('scan_end_time'),
                'scan_duration_seconds': scanner.scan_results.get('scan_duration_seconds', 0)
            }
            self.wfile.write(json.dumps({'success': True, 'results': results}, default=str).encode('utf-8'))
            
        elif self.path.startswith('/api/download_report'):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            format_type = params.get('format', ['json'])[0]
            
            # Get latest data
            system_info = scanner.get_system_info()
            suspicious_activities = scanner.check_suspicious_activities()
            scan_results = scanner.scan_results
            
            if format_type == 'json':
                report = ReportGenerator.generate_json_report(scan_results, system_info, suspicious_activities)
                content_type = 'application/json'
                filename = f'security_scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            elif format_type == 'txt':
                report = ReportGenerator.generate_txt_report(scan_results, system_info, suspicious_activities)
                content_type = 'text/plain'
                filename = f'security_scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
            elif format_type == 'html':
                report = ReportGenerator.generate_html_report(scan_results, system_info, suspicious_activities)
                content_type = 'text/html'
                filename = f'security_scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
            else:
                report = ReportGenerator.generate_json_report(scan_results, system_info, suspicious_activities)
                content_type = 'application/json'
                filename = f'security_scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            
            self.send_response(200)
            self.send_header('Content-type', content_type)
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.end_headers()
            self.wfile.write(report.encode('utf-8'))
            
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        global scan_thread
        
        if self.path == '/api/start_scan':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            def scan_wrapper():
                scanner.scan_directory('', lambda p, f: None)
            
            if not scanner.scanning:
                scan_thread = threading.Thread(target=scan_wrapper)
                scan_thread.start()
            
            self.wfile.write(json.dumps({'success': True}).encode('utf-8'))
            
        elif self.path == '/api/stop_scan':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            scanner.scanning = False
            self.wfile.write(json.dumps({'success': True}).encode('utf-8'))
            
        else:
            self.send_response(404)
            self.end_headers()

# ============ PROFESSIONAL HTML TEMPLATE ============
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Human Risk AI - Professional Security Scanner</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            min-height: 100vh;
        }
        
        /* Author Corner */
        .author-corner {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 1000;
        }
        .author-card {
            background: rgba(255,255,255,0.95);
            backdrop-filter: blur(10px);
            padding: 12px 20px;
            border-radius: 50px;
            display: flex;
            align-items: center;
            gap: 12px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
            cursor: pointer;
            transition: all 0.3s ease;
            border: 1px solid rgba(102,126,234,0.3);
        }
        .author-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            background: white;
        }
        .author-avatar {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 18px;
        }
        .author-info {
            display: flex;
            flex-direction: column;
        }
        .author-name {
            font-weight: 700;
            color: #302b63;
            font-size: 14px;
        }
        .author-title {
            font-size: 10px;
            color: #666;
        }
        
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        
        /* Header */
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        .header h1 {
            font-size: 2.5em;
            background: linear-gradient(135deg, #fff 0%, #a8c0ff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .header p { font-size: 1.1em; opacity: 0.9; margin-top: 10px; }
        
        /* Tabs */
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 25px;
            flex-wrap: wrap;
            justify-content: center;
        }
        .tab-btn {
            background: rgba(255,255,255,0.1);
            color: white;
            border: none;
            padding: 12px 28px;
            border-radius: 50px;
            cursor: pointer;
            font-size: 15px;
            font-weight: 500;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .tab-btn i { font-size: 16px; }
        .tab-btn.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            box-shadow: 0 5px 15px rgba(102,126,234,0.4);
        }
        .tab-btn:hover:not(.active) { background: rgba(255,255,255,0.2); }
        .tab-content { display: none; }
        .tab-content.active { display: block; animation: fadeIn 0.4s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        
        /* Cards */
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
            gap: 25px;
            margin-bottom: 25px;
        }
        .card {
            background: rgba(255,255,255,0.95);
            border-radius: 20px;
            padding: 25px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .card:hover { transform: translateY(-3px); box-shadow: 0 25px 50px rgba(0,0,0,0.15); }
        .card h2 {
            color: #302b63;
            margin-bottom: 20px;
            font-size: 1.3em;
            display: flex;
            align-items: center;
            gap: 10px;
            border-left: 4px solid #667eea;
            padding-left: 15px;
        }
        .card h2 i { color: #667eea; }
        
        /* Risk Meter */
        .risk-meter {
            text-align: center;
            padding: 25px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 20px;
            color: white;
        }
        .risk-score { font-size: 4.5em; font-weight: 800; }
        .scan-progress {
            width: 100%;
            height: 8px;
            background: rgba(0,0,0,0.2);
            border-radius: 10px;
            overflow: hidden;
            margin: 20px 0;
        }
        .scan-progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #00ff88, #00c6fb);
            transition: width 0.3s;
            border-radius: 10px;
        }
        
        /* Buttons */
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 12px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102,126,234,0.4); }
        .btn-danger { background: #f44336; color: white; }
        .btn-danger:hover { background: #d32f2f; }
        .btn-success { background: #4caf50; color: white; }
        .btn-success:hover { background: #45a049; }
        .btn-warning { background: #ff9800; color: white; }
        
        .report-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 15px;
        }
        
        /* Lists */
        .data-list {
            max-height: 320px;
            overflow-y: auto;
        }
        .data-item {
            padding: 12px;
            border-bottom: 1px solid #eee;
            font-size: 13px;
            transition: background 0.2s;
        }
        .data-item:hover { background: #f8f9fa; }
        .suspicious { background: #fff3e0; border-left: 3px solid #ff9800; }
        .malicious { background: #ffebee; border-left: 3px solid #f44336; }
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 10px;
            font-weight: 600;
            margin-left: 8px;
        }
        .badge-high { background: #f44336; color: white; }
        .badge-medium { background: #ff9800; color: white; }
        .badge-low { background: #4caf50; color: white; }
        .badge-success { background: #4caf50; color: white; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-top: 15px;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 15px;
            text-align: center;
            transition: all 0.3s;
        }
        .stat-card:hover { transform: translateY(-2px); background: #f0f0f0; }
        .stat-value { font-size: 1.8em; font-weight: 800; color: #302b63; }
        .stat-label { font-size: 0.75em; color: #666; margin-top: 5px; }
        
        .live-badge {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: #00ff88;
            border-radius: 50%;
            animation: pulse 1.5s infinite;
            margin-right: 8px;
        }
        @keyframes pulse {
            0% { opacity: 1; transform: scale(1); }
            100% { opacity: 0; transform: scale(2); }
        }
        
        .footer-note {
            text-align: center;
            margin-top: 30px;
            color: rgba(255,255,255,0.6);
            font-size: 12px;
        }
        
        @media (max-width: 768px) {
            .grid { grid-template-columns: 1fr; }
            .tabs { flex-direction: column; align-items: stretch; }
            .tab-btn { justify-content: center; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> Human Risk AI</h1>
            <p>Real-Time Human Behavior Cybersecurity | Advanced Device Security Scanner</p>
        </div>
        
        <!-- Tabs -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('live')"><i class="fas fa-chart-line"></i> Live Monitoring</button>
            <button class="tab-btn" onclick="switchTab('results')"><i class="fas fa-file-alt"></i> Scan Results</button>
            <button class="tab-btn" onclick="switchTab('reports')"><i class="fas fa-download"></i> Reports</button>
        </div>
        
        <!-- Live Monitoring Tab -->
        <div id="liveTab" class="tab-content active">
            <div class="grid">
                <div class="card">
                    <h2><i class="fas fa-microchip"></i> <span class="live-badge"></span> System Statistics</h2>
                    <div id="systemInfo">Loading...</div>
                </div>
                <div class="card">
                    <h2><i class="fas fa-chart-pie"></i> Risk Assessment</h2>
                    <div class="risk-meter">
                        <div>DEVICE RISK SCORE</div>
                        <div class="risk-score" id="riskScore">0</div>
                        <div id="riskLevel">Analyzing...</div>
                    </div>
                    <div class="scan-progress" id="scanProgress" style="display:none">
                        <div class="scan-progress-bar" id="progressBar" style="width:0%"></div>
                    </div>
                    <div id="scanStatus" style="margin: 10px 0; font-size: 12px; color: #666;"></div>
                    <div style="display: flex; gap: 10px; margin-top: 15px;">
                        <button class="btn btn-primary" id="startScanBtn" onclick="startFullScan()"><i class="fas fa-play"></i> Start Full Scan</button>
                        <button class="btn btn-danger" id="stopScanBtn" onclick="stopScan()" style="display:none"><i class="fas fa-stop"></i> Stop Scan</button>
                    </div>
                </div>
            </div>
            
            <div class="grid">
                <div class="card">
                    <h2><i class="fas fa-exclamation-triangle"></i> Suspicious Activities</h2>
                    <div class="data-list" id="suspiciousList">Loading...</div>
                </div>
                <div class="card">
                    <h2><i class="fas fa-tasks"></i> Running Processes</h2>
                    <div class="data-list" id="processList">Loading...</div>
                </div>
            </div>
            
            <div class="grid">
                <div class="card">
                    <h2><i class="fas fa-download"></i> Recent Files</h2>
                    <div class="data-list" id="fileList">Loading...</div>
                </div>
                <div class="card">
                    <h2><i class="fas fa-network-wired"></i> Network Connections</h2>
                    <div class="data-list" id="connectionList">Loading...</div>
                </div>
            </div>
        </div>
        
        <!-- Scan Results Tab -->
        <div id="resultsTab" class="tab-content">
            <div class="card">
                <h2><i class="fas fa-chart-bar"></i> Scan Results Summary</h2>
                <div id="scanSummary" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 15px; color: white; margin-bottom: 20px;">
                    <div class="stats-grid">
                        <div class="stat-card" style="background:rgba(255,255,255,0.15)">
                            <div class="stat-value" id="resultTotalFiles">0</div>
                            <div class="stat-label">Files Scanned</div>
                        </div>
                        <div class="stat-card" style="background:rgba(255,255,255,0.15)">
                            <div class="stat-value" id="resultSuspiciousFiles">0</div>
                            <div class="stat-label">Suspicious Files</div>
                        </div>
                        <div class="stat-card" style="background:rgba(255,255,255,0.15)">
                            <div class="stat-value" id="resultScanTime">0</div>
                            <div class="stat-label">Duration (sec)</div>
                        </div>
                    </div>
                    <div id="scanTimeInfo" style="text-align:center; margin-top: 10px;"></div>
                </div>
                
                <h3><i class="fas fa-bug"></i> Suspicious Files Detected</h3>
                <div class="data-list" id="suspiciousFilesList" style="max-height: 400px;">No scan performed yet</div>
                
                <h3 style="margin-top: 20px;"><i class="fas fa-history"></i> Scan Log</h3>
                <div class="data-list" id="scanLogList" style="max-height: 200px; font-family: monospace;">No logs available</div>
            </div>
        </div>
        
        <!-- Reports Tab -->
        <div id="reportsTab" class="tab-content">
            <div class="card">
                <h2><i class="fas fa-download"></i> Generate Security Report</h2>
                <p style="margin-bottom: 20px; color: #666;">Download your scan report in multiple formats. Reports include all suspicious files, system information, and detected activities.</p>
                
                <div class="report-buttons">
                    <button class="btn btn-primary" onclick="downloadReport('json')"><i class="fab fa-js"></i> Download JSON Report</button>
                    <button class="btn btn-primary" onclick="downloadReport('txt')"><i class="fas fa-file-alt"></i> Download TXT Report</button>
                    <button class="btn btn-primary" onclick="downloadReport('html')"><i class="fab fa-html5"></i> Download HTML Report</button>
                </div>
                
                <div style="margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 15px;">
                    <h3><i class="fas fa-info-circle"></i> Report Information</h3>
                    <ul style="margin-top: 10px; margin-left: 20px; color: #666;">
                        <li>JSON Format: Machine-readable, ideal for integration</li>
                        <li>TXT Format: Human-readable text report</li>
                        <li>HTML Format: Professional web-based report with styling</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="footer-note">
            <i class="fas fa-shield-alt"></i> Real-time monitoring | Auto-refreshes every 5 seconds
        </div>
    </div>
    
    <!-- Author Corner -->
    <div class="author-corner">
        <div class="author-card" onclick="window.open('https://github.com/abhishekrampariya', '_blank')">
            <div class="author-avatar">
                <i class="fas fa-code"></i>
            </div>
            <div class="author-info">
                <span class="author-name"><i class="fas fa-crown"></i> Abhishek Rampariya</span>
                <span class="author-title">Security Researcher & Developer</span>
            </div>
        </div>
    </div>
    
    <script>
        let scanInterval = null;
        
        function switchTab(tabName) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById('liveTab').classList.remove('active');
            document.getElementById('resultsTab').classList.remove('active');
            document.getElementById('reportsTab').classList.remove('active');
            
            if (tabName === 'live') {
                document.getElementById('liveTab').classList.add('active');
            } else if (tabName === 'results') {
                document.getElementById('resultsTab').classList.add('active');
                loadScanResultsDisplay();
            } else {
                document.getElementById('reportsTab').classList.add('active');
            }
        }
        
        async function loadSystemInfo() {
            try {
                const response = await fetch('/api/system_info');
                const data = await response.json();
                if (data.success) {
                    const sys = data.system;
                    let diskHtml = '';
                    for (const [drive, info] of Object.entries(sys.disk_usage || {})) {
                        diskHtml += `<div>${drive}: ${info.used}GB / ${info.total}GB (${info.percent}%)</div>`;
                    }
                    document.getElementById('systemInfo').innerHTML = `
                        <div class="stats-grid">
                            <div class="stat-card"><div class="stat-value">${sys.cpu_percent}%</div><div class="stat-label">CPU</div></div>
                            <div class="stat-card"><div class="stat-value">${sys.memory_percent}%</div><div class="stat-label">RAM</div></div>
                            <div class="stat-card"><div class="stat-value">${sys.hostname}</div><div class="stat-label">Device</div></div>
                            <div class="stat-card"><div class="stat-value">${sys.os}</div><div class="stat-label">OS</div></div>
                        </div>
                        <div style="margin-top: 10px;"><strong>Disk:</strong> ${diskHtml || 'Loading...'}</div>
                    `;
                }
            } catch(e) { console.error(e); }
        }
        
        async function loadProcesses() {
            try {
                const response = await fetch('/api/processes');
                const data = await response.json();
                if (data.success) {
                    document.getElementById('processList').innerHTML = data.processes.slice(0,25).map(p => `
                        <div class="data-item ${p.suspicious ? 'suspicious' : ''}">
                            <strong>${p.name}</strong> (PID: ${p.pid})
                            <small style="float:right">CPU: ${p.cpu}% | MEM: ${p.memory}%</small>
                            ${p.reason ? `<br><span class="badge badge-high">${p.reason}</span>` : ''}
                        </div>
                    `).join('');
                }
            } catch(e) { console.error(e); }
        }
        
        async function loadConnections() {
            try {
                const response = await fetch('/api/connections');
                const data = await response.json();
                if (data.success && data.connections.length) {
                    document.getElementById('connectionList').innerHTML = data.connections.slice(0,20).map(c => `
                        <div class="data-item ${c.suspicious ? 'suspicious' : ''}">
                            <strong>${c.remote_ip}</strong>
                            <small style="float:right">${c.local_ip}</small>
                            ${c.suspicious ? '<br><span class="badge badge-medium">External Connection</span>' : ''}
                        </div>
                    `).join('');
                } else {
                    document.getElementById('connectionList').innerHTML = '<div class="data-item">No active connections</div>';
                }
            } catch(e) { console.error(e); }
        }
        
        async function loadRecentFiles() {
            try {
                const response = await fetch('/api/recent_files');
                const data = await response.json();
                if (data.success && data.files.length) {
                    document.getElementById('fileList').innerHTML = data.files.slice(0,20).map(f => `
                        <div class="data-item">
                            <strong>${f.name}</strong>
                            <small style="float:right">${f.size_mb} MB</small>
                            <br><small>Modified: ${f.modified}</small>
                            ${f.extension === '.exe' ? '<span class="badge badge-medium">EXE</span>' : ''}
                        </div>
                    `).join('');
                } else {
                    document.getElementById('fileList').innerHTML = '<div class="data-item">No recent files</div>';
                }
            } catch(e) { console.error(e); }
        }
        
        async function loadSuspiciousActivities() {
            try {
                const response = await fetch('/api/suspicious_activities');
                const data = await response.json();
                if (data.success) {
                    let riskScore = 0;
                    if (data.activities.length) {
                        document.getElementById('suspiciousList').innerHTML = data.activities.map(a => `
                            <div class="data-item ${a.risk === 'High' ? 'malicious' : 'suspicious'}">
                                <strong>${a.type}</strong>
                                <span class="badge badge-${a.risk.toLowerCase()}">${a.risk}</span>
                                <p><small>${a.detail}</small></p>
                                <small style="color:#666">💡 ${a.recommendation}</small>
                            </div>
                        `).join('');
                        for (const act of data.activities) {
                            if (act.risk === 'High') riskScore += 25;
                            else if (act.risk === 'Medium') riskScore += 15;
                            else riskScore += 5;
                        }
                    } else {
                        document.getElementById('suspiciousList').innerHTML = '<div class="data-item">✅ No suspicious activities</div>';
                    }
                    riskScore = Math.min(100, riskScore);
                    document.getElementById('riskScore').innerHTML = riskScore;
                    let riskLevel = riskScore < 30 ? 'Low Risk - System appears safe' : (riskScore < 60 ? 'Medium Risk - Some concerns' : (riskScore < 85 ? 'High Risk - Attention needed' : 'Critical Risk - Security breach possible'));
                    document.getElementById('riskLevel').innerHTML = riskLevel;
                }
            } catch(e) { console.error(e); }
        }
        
        async function checkScanProgress() {
            try {
                const response = await fetch('/api/scan_progress');
                const data = await response.json();
                if (data.success && data.scanning) {
                    document.getElementById('scanProgress').style.display = 'block';
                    document.getElementById('progressBar').style.width = data.progress + '%';
                    document.getElementById('scanStatus').innerHTML = `<i class="fas fa-spinner fa-pulse"></i> Scanning: ${data.current_file.substring(0, 70)}...`;
                    document.getElementById('startScanBtn').disabled = true;
                    document.getElementById('stopScanBtn').style.display = 'inline-flex';
                } else if (data.success && !data.scanning && document.getElementById('startScanBtn').disabled) {
                    document.getElementById('startScanBtn').disabled = false;
                    document.getElementById('stopScanBtn').style.display = 'none';
                    setTimeout(() => {
                        document.getElementById('scanProgress').style.display = 'none';
                        document.getElementById('scanStatus').innerHTML = '';
                    }, 2000);
                    if (data.scan_complete) {
                        loadScanResultsDisplay();
                        alert('Scan completed successfully! Check the "Scan Results" tab.');
                    }
                }
            } catch(e) { console.error(e); }
        }
        
        async function loadScanResultsDisplay() {
            try {
                const response = await fetch('/api/scan_results');
                const data = await response.json();
                if (data.success) {
                    const results = data.results;
                    document.getElementById('resultTotalFiles').innerHTML = results.scanned_files || 0;
                    document.getElementById('resultSuspiciousFiles').innerHTML = results.suspicious_files?.length || 0;
                    document.getElementById('resultScanTime').innerHTML = results.scan_duration_seconds || 0;
                    if (results.scan_start_time) {
                        document.getElementById('scanTimeInfo').innerHTML = `Started: ${new Date(results.scan_start_time).toLocaleString()}`;
                    }
                    if (results.suspicious_files?.length) {
                        document.getElementById('suspiciousFilesList').innerHTML = results.suspicious_files.map(f => `
                            <div class="data-item malicious">
                                <strong>⚠️ ${f.name}</strong>
                                <span class="badge badge-high">Risk: ${f.risk_score}</span>
                                <br><small>📁 ${f.path}</small>
                                <br><small>📦 ${f.size_mb} MB | ${f.modified}</small>
                                <br><small>⚠️ ${f.reason.join(', ')}</small>
                            </div>
                        `).join('');
                    } else if (results.scanned_files > 0) {
                        document.getElementById('suspiciousFilesList').innerHTML = '<div class="data-item" style="background:#e8f5e9">✅ No suspicious files found! Your system is clean.</div>';
                    }
                }
            } catch(e) { console.error(e); }
        }
        
        function downloadReport(format) {
            window.location.href = `/api/download_report?format=${format}`;
        }
        
        function startFullScan() {
            fetch('/api/start_scan', { method: 'POST' }).then(() => {
                if (scanInterval) clearInterval(scanInterval);
                scanInterval = setInterval(checkScanProgress, 1000);
            });
        }
        
        function stopScan() {
            fetch('/api/stop_scan', { method: 'POST' });
            if (scanInterval) clearInterval(scanInterval);
        }
        
        setInterval(loadSystemInfo, 10000);
        setInterval(loadProcesses, 5000);
        setInterval(loadConnections, 5000);
        setInterval(loadRecentFiles, 10000);
        setInterval(loadSuspiciousActivities, 5000);
        setInterval(checkScanProgress, 2000);
        
        loadSystemInfo();
        loadProcesses();
        loadConnections();
        loadRecentFiles();
        loadSuspiciousActivities();
    </script>
</body>
</html>
'''

# ============ MAIN ============
import socket

def run_server(port=5000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, DeviceScannerHandler)
    
    print("\n" + "="*70)
    print(" HUMAN RISK AI - PROFESSIONAL SECURITY SCANNER")
    print("="*70)
    print(f" Server: http://localhost:{port}")
    print(f" Author: {AUTHOR_NAME}")
    print("")
    print(" FEATURES:")
    print("   ✅ Professional UI with modern design")
    print("   ✅ Real-time device monitoring")
    print("   ✅ Full device file scanning")
    print("   ✅ Multi-format report generation (JSON/TXT/HTML)")
    print("   ✅ Export and download reports")
    print("   ✅ Author credit in corner")
    print("")
    print(" HOW TO USE:")
    print("   1. Click 'Start Full Scan' to scan your device")
    print("   2. Check 'Scan Results' tab after completion")
    print("   3. Go to 'Reports' tab to download reports")
    print("   4. Choose JSON, TXT, or HTML format")
    print("="*70 + "\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n Shutting down...")
        httpd.shutdown()

if __name__ == '__main__':
    run_server()