import sys
import os
import time
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from binascii import unhexlify, a2b_base64

# --- IMPORTANT SECURITY CONSIDERATIONS ---
# 1. Hardcoded Keys/IVs:
#    - For real-world applications, NEVER hardcode keys and IVs directly in your code.
#    - Keys should be securely generated and stored in appropriate key management systems.
#    - IVs should be randomly generated for EACH encryption operation and transmitted/stored alongside the ciphertext.
#
# 2. Key Length Discrepancy (OpenSSL Compatibility):
#    - The `openssl` command specified `-aes-256-cbc` but used a 128-bit key.
#    - OpenSSL implicitly zero-pads keys to match the cipher's requirement.
#    - This script replicates that zero-padding for the provided key to enable decryption.
#    - **This is NOT a secure practice for key generation or encryption.** A true AES-256 key
#      must be a full 256 bits (32 bytes) of high-entropy random data.
# ---

# ANSI escape codes for terminal colors
COLOR_GREEN = '\033[92m'
COLOR_YELLOW = '\033[93m'
COLOR_RED = '\033[91m'
COLOR_BLUE = '\033[94m'
COLOR_CYAN = '\033[96m'
COLOR_RESET = '\033[0m'
COLOR_BOLD = '\033[1m'
COLOR_WHITE_BG = '\033[47m' # White background
COLOR_BLACK_TEXT = '\033[30m' # Black text
COLOR_GREEN_BG = '\033[42m' # Green background
COLOR_BLACK_BG = '\033[40m' # Black background

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def type_text(message, speed=0.03, color=COLOR_CYAN, delay_after=0.5):
    """Simulates typing text to the console."""
    sys.stdout.write(color)
    for char in message:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    sys.stdout.write(COLOR_RESET)
    sys.stdout.write('\n')
    time.sleep(delay_after)

def show_progress_bar(duration=2, steps=20, char='█', empty_char=' '):
    """Displays a simple progress bar animation."""
    for i in range(steps + 1):
        progress = i / steps
        filled_length = int(steps * progress)
        bar = char * filled_length + empty_char * (steps - filled_length)
        sys.stdout.write(f"\r[{COLOR_GREEN}{bar}{COLOR_RESET}] {int(progress * 100)}%")
        sys.stdout.flush()
        time.sleep(duration / steps)
    sys.stdout.write('\n')

def hacking_animation():
    """Plays a hacking-like terminal animation."""
    clear_screen()
    type_text(f"{COLOR_BOLD}Initializing decryption sequence...{COLOR_RESET}", speed=0.04, delay_after=0.8)
    time.sleep(0.5)

    messages = [
        "Establishing secure connection to target data stream...",
        "Authenticating decryption key...",
        "Analyzing ciphertext block structure...",
        "Performing iterative key-scheduling expansion...",
        "Calculating optimal decryption path...",
        "Reversing substitution and permutation networks...",
        "Synchronizing Initialization Vector...",
        "Verifying padding integrity...",
        "Cracking entropy layers...",
        "Reconstructing original plaintext data..."
    ]

    for msg in messages:
        type_text(f"{COLOR_YELLOW}>> {msg}{COLOR_RESET}", speed=0.02, delay_after=0.2)
        if random.random() < 0.7: # Randomly show a short progress bar
            show_progress_bar(duration=random.uniform(0.5, 1.5), steps=random.randint(10, 20))
        time.sleep(random.uniform(0.1, 0.5))

    type_text(f"{COLOR_GREEN}{COLOR_BOLD}Decryption protocols engaged.{COLOR_RESET}", speed=0.05, delay_after=1.0)
    clear_screen()

def print_boxed_message(title, message, box_color=COLOR_GREEN, text_color=COLOR_BOLD, padding_char='═', width=80):
    """
    Prints a message inside a colored box with a title.
    """
    lines = message.split('\n')
    max_line_len = max([len(line) for line in lines] + [len(title)])
    content_width = min(width - 4, max_line_len)

    print(f"{box_color}╔{padding_char * content_width}╗{COLOR_RESET}")
    print(f"{box_color}║{text_color}{title.center(content_width)}{COLOR_RESET}{box_color}║{COLOR_RESET}")
    print(f"{box_color}╠{padding_char * content_width}╣{COLOR_RESET}")

    for line in lines:
        print(f"{box_color}║{text_color}{line.ljust(content_width)}{COLOR_RESET}{box_color}║{COLOR_RESET}")

    print(f"{box_color}╚{padding_char * content_width}╝{COLOR_RESET}")


def decrypt_aes_cbc_openssl_padded(ciphertext_b64, hex_key_provided, hex_iv):
    """
    Decrypts a base64-encoded ciphertext using AES-256 in CBC mode,
    replicating OpenSSL's implicit zero-padding for keys shorter than 256-bit
    when -aes-256-cbc is specified.

    Args:
        ciphertext_b64 (str): The base64-encoded ciphertext string.
        hex_key_provided (str): The encryption key in hexadecimal format,
                                 which might be shorter than 256-bit.
        hex_iv (str): The Initialization Vector (IV) in hexadecimal format.

    Returns:
        str: The decrypted plaintext, or None if decryption fails.
    """
    try:
        # Convert hex IV to bytes
        iv = unhexlify(hex_iv)

        # Replicate OpenSSL's key padding behavior:
        # Pad the provided key with zeros to 256 bits (32 bytes)
        # to match the -aes-256-cbc cipher's expectation.
        key_bytes_provided = unhexlify(hex_key_provided)
        if len(key_bytes_provided) < 32:
            key = key_bytes_provided + b'\x00' * (32 - len(key_bytes_provided))
        else:
            # If the provided key is already 32 bytes or longer, use it directly (or truncate if too long,
            # but OpenSSL would typically error or truncate. For this specific case, we assume padding for shorter).
            # For strict OpenSSL -K compatibility, it would use the first 32 bytes if longer.
            key = key_bytes_provided[:32]

        # Validate IV length
        if len(iv) != algorithms.AES.block_size // 8: # AES block size is 128 bits / 16 bytes
            raise ValueError(
                f"Invalid IV length. Expected {algorithms.AES.block_size // 8} bytes (32 hex chars), got {len(iv)} bytes."
            )

        # Decode the base64 ciphertext to bytes
        ciphertext = a2b_base64(ciphertext_b64)

        # Create AES cipher object in CBC mode with AES-256 and the padded key
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode('utf-8')

    except Exception as e:
        print(f"Decryption error: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python decryptor.py <encrypted_file_path>")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)

    # Key and IV from the provided openssl command
    # Note: The key is 128-bit, but openssl -aes-256-cbc will zero-pad it to 256 bits.
    AES_KEY_HEX_PROVIDED = "99d46109ec24b5a996dbae8e106cd13a"
    AES_IV_HEX = "cac14868a4435c009b6bbe0169af34aa"

    print(f"{COLOR_BOLD}Initiating secure decryption process...{COLOR_RESET}")
    time.sleep(1)

    hacking_animation() # Play the animation before decryption

    # These lines are now inside the animation, but kept here for clarity of original print.
    # print(f"Key provided (will be zero-padded to AES-256): {AES_KEY_HEX_PROVIDED}")
    # print(f"Using IV: {AES_IV_HEX}")
    # time.sleep(0.5)

    try:
        with open(file_path, 'r') as f:
            encrypted_content_b64 = f.read().strip()

        decrypted_text = decrypt_aes_cbc_openssl_padded(encrypted_content_b64, AES_KEY_HEX_PROVIDED, AES_IV_HEX)

        if decrypted_text:
            clear_screen()
            # New boxed output for success message and decrypted text
            print_boxed_message("Decryption Successful!", "Status: OK", box_color=COLOR_GREEN, text_color=COLOR_BOLD)
            print("\n") # Add a blank line for spacing
            print_boxed_message("Decrypted Text", decrypted_text, box_color=COLOR_BLUE, text_color=COLOR_CYAN)
            print("\n")
        else:
            clear_screen()
            type_text(f"{COLOR_RED}{COLOR_BOLD}Decryption failed.{COLOR_RESET}", speed=0.07, delay_after=1.0)
            print("Please check the key, IV, and ciphertext.")

    except Exception as e:
        clear_screen()
        type_text(f"{COLOR_RED}{COLOR_BOLD}An unexpected error occurred: {e}{COLOR_RESET}", speed=0.05, delay_after=1.0)
