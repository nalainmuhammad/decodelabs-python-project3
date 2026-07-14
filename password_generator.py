"""
             CRYPTOGRAPHIC RANDOM PASSWORD GENERATOR                  
          Enterprise-Grade CLI Security Tool  .  v1.0.0                
+======================================================================+

Architecture : IPO (Input -> Process -> Output) with strict decoupling
Security     : secrets.choice() -- CSPRNG backed by OS entropy pool
Compliance   : NIST SP 800-63B (2024) -- minimum 15-character passwords
Efficiency   : O(N) string assembly via ''.join() on generator expression
Dependencies : Standard library only (secrets, string, math, os, sys)
"""

import secrets   
import string    
import math      
import os       
import sys      

    
# Windows consoles default to cp1252/cp437 which cannot render Unicode
# box-drawing characters. We force UTF-8 on both the Python I/O layer

if os.name == "nt":
    os.system("chcp 65001 >nul 2>&1")  # Set Windows console to UTF-8 silently

# Reconfigure stdout to UTF-8 with error replacement as a safety net
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------
# ANSI ESCAPE SEQUENCES -- zero-dependency terminal styling
# ---------------------------------------------------------------------
class Style:
    """Centralised ANSI codes -- avoids magic strings scattered in logic."""
    RESET     = "\033[0m"
    BOLD      = "\033[1m"
    DIM       = "\033[2m"
    UNDERLINE = "\033[4m"

    # Foreground colours
    RED       = "\033[91m"
    GREEN     = "\033[92m"
    YELLOW    = "\033[93m"
    CYAN      = "\033[96m"
    WHITE     = "\033[97m"
    MAGENTA   = "\033[95m"

    # Compound styles (pre-composed for readability)
    HEADER    = f"{BOLD}{CYAN}"
    SUCCESS   = f"{BOLD}{GREEN}"
    ERROR     = f"{BOLD}{RED}"
    METRIC    = f"{BOLD}{YELLOW}"
    ACCENT    = f"{BOLD}{MAGENTA}"
    SUBTLE    = f"{DIM}{WHITE}"


# ---------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------

# NIST SP 800-63B (2024) recommends >=15 chars for high-entropy passwords
MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 128  # Sane upper bound to prevent abuse

# Full character pool: 26 lower + 26 upper + 10 digits + 32 punctuation = 94
CHARACTER_POOL = string.ascii_letters + string.digits + string.punctuation
POOL_SIZE = len(CHARACTER_POOL)  # 94 -- used in entropy calculation

# UI dividers (pure ASCII for maximum terminal compatibility)
DIVIDER_HEAVY = "=" * 62
DIVIDER_LIGHT = "-" * 62
DIVIDER_DOT   = "." * 62


    # UTILITY FUNCTIONS


def clear_screen():
    """
    Wipes the terminal buffer for a clean UI state transition.
    Uses 'cls' on Windows (NT kernel) and 'clear' on POSIX systems.
    """
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    """Renders the application header -- sets the professional tone."""
    print(f"""
{Style.HEADER}+{DIVIDER_HEAVY}+{Style.RESET}
{Style.HEADER}|{Style.RESET}{Style.ACCENT}       [*]  CRYPTOGRAPHIC RANDOM PASSWORD GENERATOR       {Style.RESET}{Style.HEADER}|{Style.RESET}
{Style.HEADER}|{Style.RESET}{Style.SUBTLE}            Enterprise Security Tool  .  v1.0.0            {Style.RESET}{Style.HEADER}|{Style.RESET}
{Style.HEADER}+{DIVIDER_HEAVY}+{Style.RESET}
{Style.SUBTLE}  Engine  : secrets.choice() -- OS-level CSPRNG (urandom){Style.RESET}
{Style.SUBTLE}  Pool    : {POOL_SIZE} characters (A-Z, a-z, 0-9, symbols){Style.RESET}
{Style.SUBTLE}  Standard: NIST SP 800-63B (2024) compliant{Style.RESET}
""")


def print_section_header(title):
    """Renders a styled section divider with a title."""
    print(f"\n{Style.HEADER}  +{DIVIDER_LIGHT}+{Style.RESET}")
    print(f"{Style.HEADER}  |{Style.RESET}  {Style.BOLD}{Style.WHITE}{title}{Style.RESET}")
    print(f"{Style.HEADER}  +{DIVIDER_LIGHT}+{Style.RESET}")


# =====================================================================
# INPUT -- Get and rigorously validate the desired password length
# =====================================================================


def get_password_length():
    """
        Prompts the user for a password length and validates it.
    """
    print_section_header("INPUT  .  Password Configuration")
    print(f"\n{Style.SUBTLE}  Minimum length: {MIN_PASSWORD_LENGTH} characters (NIST 2024 standard){Style.RESET}")
    print(f"{Style.SUBTLE}  Maximum length: {MAX_PASSWORD_LENGTH} characters{Style.RESET}\n")

    while True:
        try:
            raw_input = input(
                f"  {Style.CYAN}>{Style.RESET} Enter desired password length: "
            )

            # Strip whitespace and reject empty strings early
            raw_input = raw_input.strip()
            if not raw_input:
                print(f"  {Style.ERROR}[X] Error:{Style.RESET} Input cannot be empty. "
                      f"Please enter a number.\n")
                continue

            # Attempt integer conversion -- catches floats, letters, symbols
            length = int(raw_input)

            # Enforce NIST-aligned minimum
            if length < MIN_PASSWORD_LENGTH:
                print(f"  {Style.ERROR}[X] Error:{Style.RESET} Length {length} is below the "
                      f"minimum of {Style.BOLD}{MIN_PASSWORD_LENGTH}{Style.RESET} characters.")
                print(f"  {Style.SUBTLE}  NIST SP 800-63B (2024) requires >={MIN_PASSWORD_LENGTH} "
                      f"for adequate entropy.{Style.RESET}\n")
                continue

            # Enforce sane upper bound
            if length > MAX_PASSWORD_LENGTH:
                print(f"  {Style.ERROR}[X] Error:{Style.RESET} Length {length} exceeds the "
                      f"maximum of {Style.BOLD}{MAX_PASSWORD_LENGTH}{Style.RESET} characters.\n")
                continue

            return length  # All validations passed

        except ValueError:
            # Handles non-integer input (floats like "3.14", words, symbols)
            print(f"  {Style.ERROR}[X] Error:{Style.RESET} '{raw_input}' is not a valid integer. "
                  f"Please enter a whole number.\n")

        except (EOFError, KeyboardInterrupt):
            # Graceful exit on Ctrl+D (Unix) / Ctrl+Z (Windows) / Ctrl+C
            print(f"\n\n  {Style.YELLOW}[!] Session terminated by user.{Style.RESET}\n")
            raise SystemExit(0)


# =====================================================================
# PROCESS -- Generate the password and calculate entropy
# =====================================================================


def generate_password(length):
    """
    Generates a cryptographically secure random password.

    Uses secrets.choice() which draws from the OS CSPRNG (/dev/urandom
    on Linux, CryptGenRandom on Windows) -- immune to Mersenne Twister
    state-recovery attacks that plague the `random` module.

    String is assembled via ''.join() on a generator expression for
    O(N) time complexity, avoiding the O(N^2) cost of += accumulation
    (which creates a new string object on every iteration).

    Args:
        length (int): The desired password length (pre-validated).

    Returns:
        str: The generated password.
    """
    # Generator expression + join = O(N) -- no intermediate string copies
    password = ''.join(secrets.choice(CHARACTER_POOL) for _ in range(length))
    return password


def calculate_entropy(length, pool_size):
    """
    Calculates the Shannon information entropy of the password.

    Formula: E = L * log2(R)
      where L = password length, R = character pool size

    This measures the theoretical key-space in bits. A higher entropy
    means exponentially more brute-force attempts are required.

    Reference thresholds (approximate):
      < 60 bits   -> Weak      (vulnerable to offline attacks)
      60-80 bits  -> Fair      (adequate for most online services)
      80-100 bits -> Strong    (resistant to sustained attacks)
      > 100 bits  -> Excellent (exceeds most threat models)

    Args:
        length (int): Password length.
        pool_size (int): Number of unique characters in the pool.

    Returns:
        float: Entropy in bits, rounded to 2 decimal places.
    """
    # math.log2(94) ~ 6.5546 bits per character
    entropy = length * math.log2(pool_size)
    return round(entropy, 2)


def classify_entropy(entropy_bits):
    """
    Maps raw entropy bits to a human-readable security classification.

    Returns:
        tuple: (label, colour_code) for styled terminal output.
    """
    if entropy_bits >= 100:
        return "EXCELLENT", Style.SUCCESS
    elif entropy_bits >= 80:
        return "STRONG", Style.SUCCESS
    elif entropy_bits >= 60:
        return "FAIR", Style.YELLOW
    else:
        return "WEAK", Style.ERROR


# =====================================================================
# OUTPUT -- Display the generated password and entropy metrics
# =====================================================================


def display_results(password, length, entropy):
    """
    Renders the password and security metrics in a polished CLI layout.

    Output includes:
      - The generated password (highlighted in green)
      - Password length confirmation
      - Character pool size
      - Entropy in bits with colour-coded security classification
      - Brute-force difficulty estimate (2^entropy)

    Args:
        password (str): The generated password.
        length (int): Password length.
        entropy (float): Calculated entropy in bits.
    """
    classification, colour = classify_entropy(entropy)

    # -- Password Display --
    print_section_header("OUTPUT  .  Generated Password")

    print(f"""
  {Style.SUBTLE}+{'-' * 60}+{Style.RESET}
  {Style.SUBTLE}|{Style.RESET} {Style.SUCCESS} {password} {Style.RESET}
  {Style.SUBTLE}+{'-' * 60}+{Style.RESET}
""")

    # -- Security Metrics Panel --
    print_section_header("METRICS  .  Security Analysis")

    # Password length
    print(f"\n  {Style.CYAN}>{Style.RESET} Password Length      : "
          f"{Style.BOLD}{Style.WHITE}{length} characters{Style.RESET}")

    # Character pool size
    print(f"  {Style.CYAN}>{Style.RESET} Character Pool (R)   : "
          f"{Style.BOLD}{Style.WHITE}{POOL_SIZE} unique characters{Style.RESET}")
    print(f"    {Style.SUBTLE}[a-z] [A-Z] [0-9] [!@#$%^&*...]{Style.RESET}")

    # Entropy with formula display
    print(f"  {Style.CYAN}>{Style.RESET} Entropy (E = L*log2R): "
          f"{Style.METRIC}{entropy} bits{Style.RESET}")

    # Security classification
    print(f"  {Style.CYAN}>{Style.RESET} Security Rating      : "
          f"{colour}[{classification}]{Style.RESET}")

    # Brute-force difficulty
    brute_force_combinations = 2 ** entropy
    print(f"  {Style.CYAN}>{Style.RESET} Brute-Force Space    : "
          f"{Style.BOLD}{Style.WHITE}2^{entropy} = {brute_force_combinations:.2e} combinations{Style.RESET}")

    # Entropy reference scale (ASCII block bars for compatibility)
    print(f"""
  {Style.SUBTLE}{DIVIDER_DOT}{Style.RESET}
  {Style.SUBTLE}  Entropy Reference Scale:{Style.RESET}
  {Style.ERROR}  {'#' * 4}{Style.SUBTLE}{'.' * 16}{Style.RESET}  {Style.SUBTLE}< 60 bits  -> Weak{Style.RESET}
  {Style.YELLOW}  {'#' * 8}{Style.SUBTLE}{'.' * 12}{Style.RESET}  {Style.SUBTLE}60-80 bits -> Fair{Style.RESET}
  {Style.SUCCESS}  {'#' * 12}{Style.SUBTLE}{'.' * 8}{Style.RESET}  {Style.SUBTLE}80-100 bits -> Strong{Style.RESET}
  {Style.SUCCESS}  {'#' * 20}{Style.RESET}  {Style.SUBTLE}> 100 bits -> Excellent{Style.RESET}
  {Style.SUBTLE}{DIVIDER_DOT}{Style.RESET}
""")


def display_footer():
    """Renders the session footer with security reminders."""
    print(f"{Style.HEADER}+{DIVIDER_HEAVY}+{Style.RESET}")
    print(f"{Style.HEADER}|{Style.RESET}{Style.SUBTLE}  [!] Store this password in a trusted password manager.      {Style.RESET}{Style.HEADER}|{Style.RESET}")
    print(f"{Style.HEADER}|{Style.RESET}{Style.SUBTLE}  [!] Never reuse passwords across multiple services.         {Style.RESET}{Style.HEADER}|{Style.RESET}")
    print(f"{Style.HEADER}|{Style.RESET}{Style.SUBTLE}  [!] Clipboard will NOT be modified -- copy manually.        {Style.RESET}{Style.HEADER}|{Style.RESET}")
    print(f"{Style.HEADER}+{DIVIDER_HEAVY}+{Style.RESET}")
    print()


# =====================================================================
# MAIN EXECUTION -- Orchestrates the IPO pipeline
# =====================================================================


def main():
    """
    Application entry point -- orchestrates the IPO pipeline:

      1. INPUT   -> get_password_length()   -- validate user input
      2. PROCESS -> generate_password()     -- CSPRNG password generation
                 -> calculate_entropy()     -- Shannon entropy calculation
      3. OUTPUT  -> display_results()       -- render styled terminal output
    """
    clear_screen()
    print_banner()

    # -- INPUT ------------------------------------------------------
    length = get_password_length()

    # -- PROCESS ----------------------------------------------------
    password = generate_password(length)
    entropy = calculate_entropy(length, POOL_SIZE)

    # -- OUTPUT -----------------------------------------------------
    display_results(password, length, entropy)
    display_footer()


# Guard clause -- prevents execution on import, enables testability
if __name__ == "__main__":
    main()
