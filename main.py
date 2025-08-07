from password_checker import PasswordAnalyzer
import getpass

def display_results(results):
    """Display analysis results in a user-friendly format"""
    print("\n" + "="*50)
    print("PASSWORD SECURITY ANALYSIS REPORT")
    print("="*50)
    
    print(f"Password Strength: {results['strength']} ({results['score']}/100)")
    print(f"Entropy: {results['entropy']:.2f} bits")
    
    print("\nSECURITY CHECKS:")
    print(f"✓ Length (8+ chars): {'PASS' if results['length_ok'] else 'FAIL'}")
    
    complexity = results['complexity']
    print(f"✓ Uppercase letters: {'PASS' if complexity['uppercase'] else 'FAIL'}")
    print(f"✓ Lowercase letters: {'PASS' if complexity['lowercase'] else 'FAIL'}")
    print(f"✓ Numbers: {'PASS' if complexity['digits'] else 'FAIL'}")
    print(f"✓ Special characters: {'PASS' if complexity['special_chars'] else 'FAIL'}")
    
    patterns = results['weak_patterns']
    print(f"✓ No sequential numbers: {'PASS' if not patterns['sequential_numbers'] else 'FAIL'}")
    print(f"✓ No keyboard patterns: {'PASS' if not patterns['keyboard_patterns'] else 'FAIL'}")
    print(f"✓ No repeated characters: {'PASS' if not patterns['repeated_chars'] else 'FAIL'}")
    print(f"✓ Not common password: {'PASS' if not results['is_common'] else 'FAIL'}")
    
    print(f"\nPassword Hash (SHA-256): {results['hash'][:32]}...")
    
    # Provide recommendations
    print("\nRECOMMENDATIONS:")
    if results['score'] < 70:
        if not results['length_ok']:
            print("• Use at least 8 characters")
        if not complexity['uppercase']:
            print("• Add uppercase letters")
        if not complexity['lowercase']:
            print("• Add lowercase letters")
        if not complexity['digits']:
            print("• Add numbers")
        if not complexity['special_chars']:
            print("• Add special characters (!@#$%^&*)")
        if patterns['sequential_numbers']:
            print("• Avoid sequential numbers (123, 456, etc.)")
        if patterns['keyboard_patterns']:
            print("• Avoid keyboard patterns (qwerty, asdf, etc.)")
        if results['is_common']:
            print("• Avoid common passwords")
    else:
        print("• Great job! Your password meets security standards.")
    
    print("="*50)

def main():
    analyzer = PasswordAnalyzer()
    
    print("Password Security Analyzer")
    print("This tool will analyze your password strength securely.")
    print("Note: Your password will not be stored or transmitted.\n")
    
    while True:
        print("\nOptions:")
        print("1. Analyze a password")
        print("2. Learn about password security")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            # Use getpass to hide password input
            password = getpass.getpass("Enter password to analyze (hidden): ")
            if password:
                results = analyzer.analyze_password(password)
                display_results(results)
            else:
                print("Please enter a password.")
        
        elif choice == '2':
            show_security_tips()
        
        elif choice == '3':
            print("Thanks for using Password Security Analyzer!")
            break
        
        else:
            print("Invalid choice. Please try again.")

def show_security_tips():
    """Display password security education"""
    tips = """
    PASSWORD SECURITY BEST PRACTICES:
    
    1. Length Matters: Use at least 12-16 characters
    2. Complexity: Mix uppercase, lowercase, numbers, and symbols
    3. Uniqueness: Use different passwords for each account
    4. Avoid Patterns: No keyboard walks, sequences, or personal info
    5. Use Passphrases: "Coffee$Morning#Walk2024" is stronger than "C@ff33"
    6. Enable 2FA: Add two-factor authentication when available
    7. Use Password Managers: Let tools generate and store strong passwords
    8. Regular Updates: Change passwords if there's a security breach
    
    COMMON ATTACK METHODS:
    • Dictionary attacks: Using common passwords
    • Brute force: Trying all possible combinations
    • Rainbow tables: Precomputed hash lookups
    • Social engineering: Guessing based on personal information
    
    Remember: A strong password is your first line of defense!
    """
    print(tips)

if __name__ == "__main__":
    main()
