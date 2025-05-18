# 🔐 Cryptfile – A Command Line Encryption Tool

Cryptfile is a Python-based command-line tool for **encrypting and decrypting files and directories** using AES and chaos-based techniques. It's designed to secure sensitive documents (text, PDF, Word, and images) with additional support for compression during encryption.

---

## ⚙️ Features

- 🔒 AES + Chaos-based encryption (e.g., Logistic Map, Arnold Cat Map)
- 🗃️ Support for:
  - `.txt`
  - `.docx`
  - `.pdf`
  - `.jpg`, `.jpeg`, `.png`
- 🗂️ Directory encryption/decryption
- 📦 Optional directory compression before encryption
- 🔐 Secure key management

---

## 🧠 Requirements

- Python 3.7+
- Required Python packages:
  ```bash
  pip install cryptography numpy pillow python-docx PyMuPDF
🚀 How to Use
1. Clone the Repository
   ```bash
   git clone https://github.com/your-username/Cryptfile.git
   cd Cryptfile
2. Run the Script
Edit and run your main script (main.py or equivalent):
  ```bash
  python cryptfile.py
  ```
---

##🛠️ TODO (Optional Enhancements)
- Add GUI with Tkinter or Gradio
- Password-based access control
- Logging and progress tracking
- Evaluate encryption strength (Entropy, Avalanche, etc.)

---

##Author
Disha Kumar Arora
JK Lakshmipat University

---
##📃 License
MIT License. Free to use, distribute, and modify for educational purposes.
