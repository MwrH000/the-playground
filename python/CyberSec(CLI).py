import hashlib
import socket
import os
import re
import json
import base64
from datetime import datetime
import subprocess
import sys
import platform
from typing import Dict, List, Tuple, Optional

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def set_console_title(title):
    if os.name == 'nt':
        os.system(f'title {title}')
    else:
        sys.stdout.write(f"\x1b]2;{title}\x07")

class CybersecurityToolkit:
    
    def __init__(self):
        self.common_passwords = self._load_common_passwords()
    
    def _load_common_passwords(self) -> List[str]:
        common = [
            'password', '123456', '123456789', 'qwerty', 'admin',
            'letmein', 'welcome', 'monkey', 'password1', 'abc123',
            '12345678', '1234567', '12345', '1234', '111111', '123abc',
            '123123', 'abc123'
        ]
        return common
    
    def check_password_strength(self, password: str) -> Dict:
        score = 0
        feedback = []
        
        if len(password) >= 12:
            score += 25
        elif len(password) >= 8:
            score += 15
        else:
            feedback.append("Password should be at least 8 characters long")
        
        if re.search(r'[A-Z]', password):
            score += 15
        else:
            feedback.append("Add uppercase letters")
            
        if re.search(r'[a-z]', password):
            score += 15
        else:
            feedback.append("Add lowercase letters")
            
        if re.search(r'[0-9]', password):
            score += 15
        else:
            feedback.append("Add numbers")
            
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password):
            score += 15
        else:
            feedback.append("Add special characters")
        
        if password.lower() in self.common_passwords:
            score -= 30
            feedback.append("This is a commonly used password - choose something more unique")
        
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|123|234|345|456|567|678|789)', password.lower()):
            score -= 10
            feedback.append("Avoid sequential characters")
        
        if score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Moderate"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        return {
            'score': min(max(score, 0), 100),
            'strength': strength,
            'feedback': feedback,
            'length': len(password)
        }
    
    def caesar_cipher(self, text: str, shift: int, encrypt: bool = True) -> str:
        if not encrypt:
            shift = -shift
        
        result = ""
        for char in text:
            if char.isalpha():
                shift_base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
            else:
                result += char
        return result
    
    def calculate_hash(self, data: str, algorithm: str = 'sha256') -> str:
        algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        
        if algorithm not in algorithms:
            raise ValueError(f"Unsupported algorithm. Choose from: {list(algorithms.keys())}")
        
        return algorithms[algorithm](data.encode()).hexdigest()
    
    def check_file_integrity(self, filepath: str, expected_hash: str, algorithm: str = 'sha256') -> Dict:
        if not os.path.exists(filepath):
            return {'verified': False, 'error': 'File not found'}
        
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            if algorithm == 'md5':
                actual_hash = hashlib.md5(file_data).hexdigest()
            elif algorithm == 'sha1':
                actual_hash = hashlib.sha1(file_data).hexdigest()
            elif algorithm == 'sha256':
                actual_hash = hashlib.sha256(file_data).hexdigest()
            elif algorithm == 'sha512':
                actual_hash = hashlib.sha512(file_data).hexdigest()
            else:
                return {'verified': False, 'error': 'Unsupported algorithm'}
            
            verified = actual_hash == expected_hash.lower()
            
            return {
                'verified': verified,
                'actual_hash': actual_hash,
                'expected_hash': expected_hash,
                'algorithm': algorithm,
                'file': filepath,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {'verified': False, 'error': str(e)}
    
    def simple_port_scanner(self, target: str, ports: List[int] = None, timeout: float = 1.0) -> Dict:
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]
        
        open_ports = []
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'open_ports': open_ports,
            'total_scanned': len(ports)
        }
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    service_name = self._get_service_name(port)
                    open_ports.append({
                        'port': port,
                        'service': service_name,
                        'status': 'open'
                    })
                sock.close()
                
            except socket.error:
                pass
            except Exception as e:
                print(f"Error scanning port {port}: {e}")
        
        results['open_ports'] = open_ports
        return results
    
    def _get_service_name(self, port: int) -> str:
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3389: 'RDP'
        }
        return common_services.get(port, 'Unknown')
    
    def generate_secure_password(self, length: int = 16) -> str:
        import random
        import string
        
        if length < 8:
            length = 8
        
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(symbols)
        ]
        
        all_chars = lowercase + uppercase + digits + symbols
        password.extend(random.choice(all_chars) for _ in range(length - 4))
        
        random.shuffle(password)
        
        return ''.join(password)
    
    def detect_suspicious_strings(self, text: str) -> List[Dict]:
        patterns = {
            'SQL Injection': [
                r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE)\b.*\b(FROM|INTO|SET|TABLE)\b",
                r"\b(OR|AND)\b.*\d+.*=.*\d+"
            ],
            'XSS Attempt': [
                r"<script.*?>.*?</script>",
                r"javascript:",
                r"onerror=|onload=|onclick="
            ],
            'Path Traversal': [
                r"\.\./",
                r"\.\.\\",
                r"etc/passwd",
                r"win.ini"
            ],
            'Command Injection': [
                r";\s*\b(ls|dir|cat|type|rm|del|mkdir)\b",
                r"`.*`",
                r"\$\(",
                r"\|\s*\b(ls|dir|cat|type)\b"
            ]
        }
        
        findings = []
        
        for category, regex_list in patterns.items():
            for pattern in regex_list:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        'category': category,
                        'pattern': pattern,
                        'matched_text': match.group(),
                        'position': match.start()
                    })
        
        return findings
    
    def base64_encode_decode(self, data: str, encode: bool = True) -> str:
        try:
            if encode:
                return base64.b64encode(data.encode()).decode()
            else:
                return base64.b64decode(data.encode()).decode()
        except Exception as e:
            return f"Error: {str(e)}"

def main_menu():
    toolkit = CybersecurityToolkit()
    
    while True:
        clear_screen()
        set_console_title("CyberSecurity by @MwrH000")
        
        print("\n" + "="*60)
        print("CYBERSECURITY TOOLKIT")
        print("="*60)
        print("1. Check Password Strength")
        print("2. Generate Secure Password")
        print("3. Caesar Cipher Encryption/Decryption")
        print("4. Calculate Hash")
        print("5. File Integrity Check")
        print("6. Simple Port Scanner")
        print("7. Detect Suspicious Strings")
        print("8. Base64 Encode/Decode")
        print("9. Exit")
        print("="*60)
        
        choice = input("\nSelect an option (1-9): ").strip()
        
        if choice == '1':
            clear_screen()
            set_console_title("Cyber Security by @MwrH000 - Password Check")
            password = input("Enter password to check: ")
            result = toolkit.check_password_strength(password)
            
            print(f"\nPassword Analysis Results:")
            print(f"  Length: {result['length']} characters")
            print(f"  Score: {result['score']}/100")
            print(f"  Strength: {result['strength']}")
            
            if result['feedback']:
                print("  Suggestions:")
                for feedback in result['feedback']:
                    print(f"    - {feedback}")
            else:
                print("  Great! No suggestions for improvement.")
        
        elif choice == '2':
            clear_screen()
            set_console_title("Cyber Security by @MwrH000 - Password Generator")
            try:
                length = int(input("Enter password length (default 16): ") or "16")
                password = toolkit.generate_secure_password(length)
                print(f"\nGenerated Password: {password}")
                
                strength = toolkit.check_password_strength(password)
                print(f"Strength: {strength['strength']} ({strength['score']}/100)")
                
            except ValueError:
                print("Invalid length. Using default length 16.")
                password = toolkit.generate_secure_password()
                print(f"\nGenerated Password: {password}")
        
        elif choice == '3':
            clear_screen()
            set_console_title("Cyber Security by @MwrH000 - Caesar Cipher")
            text = input("Enter text: ")
            try:
                shift = int(input("Enter shift value (1-25): "))
                if not 1 <= shift <= 25:
                    raise ValueError
                
                action = input("Encrypt or Decrypt? (E/D): ").upper()
                if action == 'E':
                    result = toolkit.caesar_cipher(text, shift, encrypt=True)
                    print(f"\nEncrypted text: {result}")
                elif action == 'D':
                    result = toolkit.caesar_cipher(text, shift, encrypt=False)
                    print(f"\nDecrypted text: {result}")
                else:
                    print("Invalid choice. Please enter E or D.")
                    
            except ValueError:
                print("Invalid shift value. Please enter a number between 1 and 25.")
        
        elif choice == '4':
            clear_screen()
            set_console_title("Cyber Security by @MwrH000 - Hash Calculator")
            data = input("Enter data to hash: ")
            print("\nAvailable algorithms: md5, sha1, sha256, sha512")
            algorithm = input("Select algorithm (default sha256): ") or "sha256"
            
            try:
                hash_value = toolkit.calculate_hash(data, algorithm)
                print(f"\n{algorithm.upper()} Hash: {hash_value}")
            except ValueError as e:
                print(f"Error: {e}")
        
        elif choice == '5':
            clear_screen()
            set_console_title("Cyber Security by @MwrH000 - File Integrity")
            filepath = input("Enter file path: ")
            expected_hash = input("Enter expected hash: ")
            algorithm = input("Enter hash algorithm (default sha256): ") or "sha256"
            
            result = toolkit.check_file_integrity(filepath, expected_hash, algorithm)
            
            if result.get('error'):
                print(f"Error: {result['error']}")
            else:
                print(f"\nFile Integrity Check:")
                print(f"  File: {result['file']}")
                print(f"  Algorithm: {result['algorithm']}")
                print(f"  Expected: {result['expected_hash']}")
                print(f"  Actual: {result['actual_hash']}")
                print(f"  Verified: {'✓ PASS' if result['verified'] else '✗ FAIL'}")
        
        elif choice == '6':
            clear_screen()
            set_console_title("Cyber Security by @MwrH000 - Port Scanner")
            target = input("Enter target IP or hostname: ")
            ports_input = input("Enter ports to scan (comma-separated, default common ports): ")
            
            if ports_input.strip():
                try:
                    ports = [int(p.strip()) for p in ports_input.split(',')]
                except ValueError:
                    print("Invalid port list. Using common ports.")
                    ports = None
            else:
                ports = None
            
            print(f"\nScanning {target}...")
            results = toolkit.simple_port_scanner(target, ports)
            
            print(f"\nScan Results for {results['target']}:")
            print(f"Time: {results['timestamp']}")
            print(f"Ports scanned: {results['total_scanned']}")
            
            if results['open_ports']:
                print("\nOpen ports found:")
                for port_info in results['open_ports']:
                    print(f"  Port {port_info['port']}: {port_info['service']}")
            else:
                print("\nNo open ports found in the scanned range.")
        
        elif choice == '7':
            clear_screen()
            set_console_title("Cyber Security by @MwrH000 - Threat Detection")
            text = input("Enter text to analyze: ")
            findings = toolkit.detect_suspicious_strings(text)
            
            if findings:
                print(f"\nFound {len(findings)} suspicious pattern(s):")
                for i, finding in enumerate(findings, 1):
                    print(f"\n{i}. Category: {finding['category']}")
                    print(f"   Pattern: {finding['pattern']}")
                    print(f"   Matched: '{finding['matched_text']}'")
                    print(f"   Position: {finding['position']}")
            else:
                print("\nNo suspicious patterns detected.")
        
        elif choice == '8':
            clear_screen()
            set_console_title("Cyber Security by @MwrH000 - Base64 Tool")
            data = input("Enter data: ")
            action = input("Encode or Decode? (E/D): ").upper()
            
            if action == 'E':
                result = toolkit.base64_encode_decode(data, encode=True)
                print(f"\nBase64 Encoded: {result}")
            elif action == 'D':
                result = toolkit.base64_encode_decode(data, encode=False)
                print(f"\nBase64 Decoded: {result}")
            else:
                print("Invalid choice. Please enter E or D.")
        
        elif choice == '9':
            clear_screen()
            print("\nThank you for using the Cybersecurity Toolkit!")
            print("Created by @MwrH000")
            break
        
        else:
            clear_screen()
            print("Invalid choice. Please select a valid option.")
        
        if choice != '9':
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    set_console_title("Cyber Security by @MwrH000")
    
    if os.name == 'nt':
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            is_admin = False
    else:
        is_admin = os.getuid() == 0
    
    if not is_admin:
        clear_screen()
        print("="*60)
        print("CYBERSECURITY TOOLKIT by @MwrH000")
        print("="*60)
        print("Note: Some features may require administrative privileges.")
        print("For best results, run this program as administrator/root when needed.")
        print("="*60)
        input("\nPress Enter to continue...")
    
    try:
        main_menu()
    except KeyboardInterrupt:
        clear_screen()
        print("\n\nProgram interrupted by user.")
        sys.exit(0)
    except Exception as e:
        clear_screen()
        print(f"\nAn error occurred: {e}")
        sys.exit(1)