"""
SALT SIEM v3.0 - Zone Sandbox Module
Advanced Malware Analysis Engine
"""

import os
import hashlib
import datetime

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


class ZoneSandbox:
    """
    Malware analysis engine with YARA rule matching,
    hash calculation, and PE file analysis
    """
    
    def __init__(self, filepath, yara_rules=None):
        """
        Initialize Zone Sandbox
        
        Args:
            filepath (str): Path to file to analyze
            yara_rules: Compiled YARA rules object
        """
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.yara_rules = yara_rules
        self.results = []
        self.threat_score = 0
        self.sha256 = None
        self.md5 = None
        self.sha1 = None
        self.file_size = 0
        
    def log(self, text):
        """Add entry to results log"""
        self.results.append(text)
        
    def calculate_hashes(self):
        """
        Calculate file hashes (SHA256, MD5, SHA1)
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read()
            
            self.file_size = len(data)
            self.sha256 = hashlib.sha256(data).hexdigest()
            self.md5 = hashlib.md5(data).hexdigest()
            self.sha1 = hashlib.sha1(data).hexdigest()
            
            self.log(f"File Size: {self.file_size:,} bytes")
            self.log(f"SHA256: {self.sha256}")
            self.log(f"MD5: {self.md5}")
            self.log(f"SHA1: {self.sha1}")
            
            return True
            
        except Exception as e:
            self.log(f"Error calculating hashes: {e}")
            return False
            
    def analyze_pe(self):
        """
        Analyze PE (Portable Executable) file structure
        
        Checks:
        - Entry point
        - Image base
        - Section entropy (high entropy = packed/encrypted)
        - Suspicious section names
        """
        if not PEFILE_AVAILABLE:
            self.log("PE analysis unavailable (pefile not installed)")
            return
            
        try:
            # Only analyze PE files
            if not self.filepath.lower().endswith(('.exe', '.dll', '.sys', '.scr')):
                return
                
            pe = pefile.PE(self.filepath)
            
            self.log("\n=== PE FILE ANALYSIS ===")
            self.log(f"Entry Point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}")
            self.log(f"Image Base: 0x{pe.OPTIONAL_HEADER.ImageBase:08x}")
            self.log(f"Compile Time: {datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)}")
            
            self.log("\nSections:")
            for section in pe.sections:
                name = section.Name.decode(errors='ignore').strip('\x00')
                entropy = section.get_entropy()
                size = section.SizeOfRawData
                virtual_size = section.Misc_VirtualSize
                
                # Flags
                suspicious = ""
                if entropy > 7.0:
                    suspicious = " [HIGH ENTROPY - PACKED/ENCRYPTED]"
                    self.threat_score += 2
                    
                # Suspicious section names
                if name.lower() in ['.upx', '.aspack', '.petite', '.mpress']:
                    suspicious += " [KNOWN PACKER]"
                    self.threat_score += 2
                    
                # Executable and writable (dangerous combo)
                if section.Characteristics & 0x20000000 and section.Characteristics & 0x80000000:
                    suspicious += " [WRITE+EXECUTE]"
                    self.threat_score += 1
                    
                self.log(f"  {name:10} Size: {size:8,} VSize: {virtual_size:8,} Entropy: {entropy:.2f}{suspicious}")
                
            # Check imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                self.log("\nImported DLLs:")
                for entry in pe.DIRECTORY_ENTRY_IMPORT[:10]:  # First 10
                    self.log(f"  {entry.dll.decode()}")
                    
        except Exception as e:
            self.log(f"PE analysis error: {e}")
            
    def yara_scan(self):
        """
        Run YARA rules against the file
        
        Returns:
            int: Number of YARA matches
        """
        if not self.yara_rules:
            self.log("YARA rules not loaded")
            return 0
            
        try:
            matches = self.yara_rules.match(self.filepath)
            
            if matches:
                self.log("\n=== YARA RULE MATCHES ===")
                for match in matches:
                    severity = match.meta.get('severity', 'unknown')
                    description = match.meta.get('description', 'No description')
                    
                    self.log(f"\n[{match.rule}]")
                    self.log(f"  Severity: {severity.upper()}")
                    self.log(f"  Description: {description}")
                    
                    # Add to threat score based on severity
                    severity_scores = {
                        'critical': 5,
                        'high': 3,
                        'medium': 2,
                        'low': 1
                    }
                    self.threat_score += severity_scores.get(severity.lower(), 1)
                    
                return len(matches)
            else:
                self.log("\n=== YARA SCAN ===")
                self.log("No YARA rule matches")
                return 0
                
        except Exception as e:
            self.log(f"YARA scan error: {e}")
            return 0
            
    def get_threat_level(self):
        """
        Calculate overall threat level based on score
        
        Returns:
            str: 'Low', 'Medium', 'High', or 'Critical'
        """
        if self.threat_score >= 10:
            return "Critical"
        elif self.threat_score >= 6:
            return "High"
        elif self.threat_score >= 3:
            return "Medium"
        else:
            return "Low"
            
    def get_recommendation(self):
        """Get security recommendation based on threat level"""
        threat_level = self.get_threat_level()
        
        recommendations = {
            'Critical': 'IMMEDIATE ACTION REQUIRED: Quarantine file, isolate system, initiate incident response',
            'High': 'QUARANTINE: Do not execute. Investigate source and indicators of compromise',
            'Medium': 'CAUTION: Further analysis recommended. Check with antivirus and threat intelligence',
            'Low': 'File appears safe. No significant threats detected'
        }
        
        return recommendations.get(threat_level, 'Unknown threat level')
        
    def analyze(self):
        """
        Perform complete file analysis
        
        Returns:
            dict: Analysis results including report, threat level, hashes, etc.
        """
        self.log("=" * 70)
        self.log("ZONE SANDBOX - MALWARE ANALYSIS REPORT")
        self.log(f"File: {self.filename}")
        self.log(f"Analysis Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log("=" * 70)
        self.log("")
        
        # Run analyses
        self.calculate_hashes()
        self.log("")
        self.analyze_pe()
        yara_matches = self.yara_scan()
        
        # Calculate final assessment
        threat_level = self.get_threat_level()
        recommendation = self.get_recommendation()
        
        self.log("")
        self.log("=" * 70)
        self.log("THREAT ASSESSMENT")
        self.log("=" * 70)
        self.log(f"Threat Level: {threat_level}")
        self.log(f"Threat Score: {self.threat_score}/15")
        self.log(f"YARA Matches: {yara_matches}")
        self.log("")
        self.log("RECOMMENDATION:")
        self.log(f"  {recommendation}")
        self.log("=" * 70)
        
        # Return structured results
        return {
            'report': "\n".join(self.results),
            'threat_level': threat_level,
            'threat_score': self.threat_score,
            'sha256': self.sha256 or 'N/A',
            'md5': self.md5 or 'N/A',
            'sha1': self.sha1 or 'N/A',
            'file_size': self.file_size,
            'yara_matches': yara_matches,
            'recommendation': recommendation,
            'timestamp': datetime.datetime.now().isoformat()
        }