# 🔒 AES-256 Decryptor with Terminal Animation (OpenSSL Compatible)

This Python script is a command-line tool designed to decrypt the flag for the **HackTheBox ENCwhale challenge**. It handles files encrypted using the AES-256-CBC algorithm with `openssl` and features a "hacking-like" terminal animation to enhance the user experience during flag retrieval.


## 🛠️ Prerequisites
* Python 3.6+

* **Virtual Environment (Recommended):**
    It's highly recommended to use a Python virtual environment to manage dependencies.

    ```bash
    # Create a virtual environment
    python3 -m venv venv

    # Activate the virtual environment
    source venv/bin/activate
    ```

* `cryptography` library:

    ```bash
    pip install cryptography
    ```

## 🚀 How to Use

### 1. 💾 Save the Script

Save the provided Python code into a file named `decryptor.py`.

### 1. 💾 Save the Encrypted Flag

Save the provided encrypted flag into a file named `encrypted.txt`.

### 2. 🖥️ Run the Decryptor Script

Execute the Python script from your terminal, providing the path to your `encrypted.txt` file as an argument:

```bash
python decryptor.py encrypted.txt
```

## Finally

Happy Decoding 👌
