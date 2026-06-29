import string
import secrets
import re

# Simulated database of previously used passwords (to demonstrate the feature)
OLD_PASSWORDS_DB = ["Password123!", "Admin@2025", "Welcome2026!", "Letmein!!!"]

# Top common/weak passwords to check against
COMMON_PASSWORDS = ["123456", "password", "qwerty", "111111", "iloveyou"]

def analyze_password(password):
    """
    Evaluates the password strength based on length, complexity, and uniqueness.
    Returns a score, a strength rating, and a list of feedback feedback.
    """
    score = 0
    feedback = []
    
    # 1. Check Uniqueness & Re-use
    if password in OLD_PASSWORDS_DB:
        return 0, "CRITICAL WEAKNESS", ["This password matches a previously used password in our database. Reuse is strictly prohibited."]
    
    if password.lower() in COMMON_PASSWORDS:
        return 0, "VERY WEAK", ["This is a highly common password that can be easily guessed by attackers."]

    # 2. Length Check
    length = len(password)
    if length < 8:
        feedback.append("Password is too short (minimum 8 characters required).")
    elif length >= 12:
        score += 2
        feedback.append("Excellent length (12+ characters).")
    else:
        score += 1
        feedback.append("Acceptable length (8-11 characters), but longer is better.")

    # 3. Complexity Checks
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters (a-z).")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters (A-Z).")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add at least one number (0-9).")

    if re.search(r"[{}]".format(re.escape(string.punctuation)), password):
        score += 1
    else:
        feedback.append("Add at least one special character (e.g., !, @, #, $, %).")

    # Determine Rating based on score (Max score possible = 6)
    if score <= 2:
        rating = "WEAK"
    elif score <= 4:
        rating = "MEDIUM"
    else:
        rating = "STRONG"

    return score, rating, feedback

def generate_strong_alternative(length=14):
    """
    Generates a cryptographically secure random password using Python's 'secrets' module.
    """
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        # Ensure it actually meets security criteria
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in "!@#$%^&*()" for c in password)):
            return password

def main():
    print("=========================================")
    print("       PASSWORD STRENGTH ANALYZER        ")
    print("=========================================\n")
    
    user_password = input("Enter a password to test: ").strip()
    
    if not user_password:
        print("Password cannot be empty.")
        return

    score, rating, feedback = analyze_password(user_password)
    
    print("\n--- RESULTS ---")
    print(f"Strength Rating: **{rating}** (Score: {score}/6)")
    
    print("\nFeedback/Suggestions:")
    if rating == "STRONG" and not feedback:
        print(" - Great job! Your password meets all security criteria.")
    else:
        for item in feedback:
            print(f" • {item}")
            
    # Suggest an alternative if it isn't strong
    if rating != "STRONG":
        print("\n--- SUGGESTED ALTERNATIVE ---")
        suggested = generate_strong_alternative()
        print(f"Try a cryptographically secure password like: `{suggested}`")
        print("*(Note: This was generated using Python's `secrets` module, which is safe for cryptography)*")
    print("=========================================")

if __name__ == "__main__":
    main()