Gnoppix GPG Key Generator
=========================

**A modern, automated GPG key management tool designed for Gnoppix 25/26.**

This application simplifies the process of creating secure GPG identities. It offers a graphical interface to generate keys with "Military Grade" encryption, automatically handles strong passphrase generation, and manages existing keys safely.

🚀 Features
-----------

*   **Automated Generation:** No more complex terminal commands.
    
*   **Encryption Options:** Choose between **Quick (ECC/Ed25519)** or **Military Grade (RSA 4096-bit)**.
    
*   **Smart Conflict Resolution:** Automatically detects existing keys and offers a "Delete All" option to ensure a clean identity.
    
*   **Strong Security:** Automatically generates a 32-character (16-byte) Hex passphrase.
    
*   **Passphrase Management:** Includes an option to rotate/edit your passphrase securely.
    
*   **Clipboard Support:** Easily copy all key details (Fingerprint, ID, Passphrase) at the end of the process.
    

📋 Prerequisites
----------------

To run this application on Gnoppix 26 (it may work on Debian 13/14 based system), you need Python 3 and the Qt6 library. Since I work on with Debian Systens only I can't support other Distributions.  

### 1\. Install Dependencies

Open a terminal and run:


   sudo apt update  sudo apt install python3 python3-pyqt6 gnupg2  

_Note: If gpg2 is not available, the application will automatically fall back to gpg._

🛠️ How to Use
--------------

1.  **Download the Script:**Save the application file as gnoppix\_gpggen

2.  run a chmod +x gnoppix\_gpggen 
    
2.  run ./gnoppix\_gpggen   
    
3.  **Follow the Wizard:**
    
    *   **Step 1:** Select your encryption strength.
        
    *   **Step 2:** Enter your Name, Email, and Key Validity period.
        
    *   **Step 3:** Click **Create GPG Key Now**.
        
4.  **Save Your Credentials:**Once finished, a dialog will appear with your new Key ID, Fingerprint, and the **auto-generated secure passphrase**. Click "Copy All Information" and store this safely (e.g., in a password manager like KeePassXC).

5.  WARNING **IN CASE YOU HAVE EXISTING KEY, THOSE WILL BE REPLACED EXISTING KEYS BUT, YOU WILL BE ASKED IF YOU AGREE TO DELETE THEM**


    

☕ Support Us
------------

We work hard to make Gnoppix secure and easy to use. If you find this tool useful or would like to sponsor the development of new features, feel free to support us!

[https://ko-fi.com/gnoppix](https://ko-fi.com/gnoppix)_(Feel free to buy us a coffee if you like to add new features!)_

**Feel free to clone and send me your pull-requests.**

📄 License & Copyright
----------------------

**(c) Gnoppix Linux - Andreas Mueller 2002-2025**

This software is provided "as is", without warranty of any kind. Permission is granted to use, copy, modify, and distribute this software for Gnoppix Linux and related Debian-based systems.
