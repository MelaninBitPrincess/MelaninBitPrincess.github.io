import re
import hashlib

class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
    
    def load_common_passwords(self):
        """Load common passwords from file"""
        try:
            with open('common_passwords.txt', 'r') as f:
                return set(line.strip().lower() for line in f)
        except FileNotFoundError:
            return set(['password', '123456', 'admin', 'welcome'])
    
    def check_length(self, password):
        """Check if password meets minimum length requirement"""
        return len(password) >= 8
    
    def check_complexity(self, password):
        """Check password complexity requirements"""
        checks = {
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'digits': bool(re.search(r'\d', password)),
            'special_chars': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }
        return checks
    
    def check_common_patterns(self, password):
        """Check for common weak patterns"""
        patterns = {
            'sequential_numbers': bool(re.search(r'123|234|345|456|567|678|789', password)),
            'keyboard_patterns': bool(re.search(r'qwerty|asdf|zxcv', password.lower())),
            'repeated_chars': bool(re.search(r'(.)\1{2,}', password))
        }
        return patterns
    
    def check_against_common_list(self, password):
        """Check if password is in common passwords list"""
        return password.lower() in self.common_passwords
    
    def calculate_entropy(self, password):
        """Calculate password entropy (simplified)"""
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        import math
        return len(password) * math.log2(charset_size)
    
    def hash_password(self, password):
        """Demonstrate password hashing"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def analyze_password(self, password):
        """Comprehensive password analysis"""
        results = {
            'password': password,
            'length_ok': self.check_length(password),
            'complexity': self.check_complexity(password),
            'weak_patterns': self.check_common_patterns(password),
            'is_common': self.check_against_common_list(password),
            'entropy': self.calculate_entropy(password),
            'hash': self.hash_password(password)
        }
        
        # Calculate overall score
        score = 0
        if results['length_ok']:
            score += 20
        score += sum(results['complexity'].values()) * 15
        if not any(results['weak_patterns'].values()):
            score += 20
        if not results['is_common']:
            score += 20
        
        results['score'] = min(score, 100)
        results['strength'] = self.get_strength_rating(results['score'])
        
        return results
    
    def get_strength_rating(self, score):
        """Convert score to strength rating"""
        if score < 30:
            return "Very Weak"
        elif score < 50:
            return "Weak"
        elif score < 70:
            return "Fair"
        elif score < 90:
            return "Good"
        else:
            return "Strong"