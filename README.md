# 🔒 Secure File Hider with OTP Authentication 📧

## Overview

The Secure File Hider is a Java Swing desktop application designed to provide a layer of security for personal files. It allows users to "hide" files by encrypting them and making them inaccessible without proper authentication. The application implements strong cryptographic practices, master password protection, and a two-factor authentication (2FA) mechanism using One-Time Passwords (OTPs) sent via email.

## Features ✨

* **File Encryption (AES):** Encrypts files using the Advanced Encryption Standard (AES) to ensure data confidentiality.
* **Secure Key Derivation (PBKDF2):** Derives robust encryption keys from the user's passphrase using PBKDF2-HMAC-SHA256, protecting against brute-force attacks on the passphrase.
* **Master Password Protection:** Secures access to the application and its features with a master password, which is stored securely using hashing and salting.
* **One-Time Password (OTP) Authentication:** Implements a critical second factor for decryption. OTPs are generated dynamically and sent to the user's registered email address, expiring after a set time.
* **Email Integration:** Utilizes the Jakarta Mail API to send OTPs, enhancing the security and usability of the 2FA process.
* **File Management:**
    * **Hide Function:** Encrypts the original file and then securely deletes the unencrypted original. The encrypted file (e.g., `filename.encrypted`) remains at the original location.
    * **Unhide Function:** Decrypts the `.encrypted` file back to its original name and then securely deletes the encrypted version.
* **Persistence:** Saves the master password hash, salt, and registered email (for OTP recovery) locally, so users don't have to set them up every time they run the application.
    * **❗ SECURITY NOTE:** For this demonstration, these sensitive credentials are saved in a plain text properties file. **This is NOT secure for production use.** In a real application, this configuration file itself would be encrypted, or platform-specific secure storage (e.g., Java KeyStore for keys, OS credential stores) would be utilized.
* **"Forgot Password" Flow:** A secure recovery mechanism that allows users to reset their master password by verifying identity via OTP sent to their registered email.
* **"Reset App" Option:** Provides a way for users to clear all stored application data (master password, email) and start fresh.
* **Interactive GUI (Java Swing):** A user-friendly graphical interface with clear logging and status updates.

## Technologies Used 💻

* **Java (JDK 8+):** Core programming language. ☕
* **Java Swing:** For building the desktop GUI. 🎨
* **Java Cryptography Architecture (JCA/JCE):** For cryptographic operations (AES, PBKDF2, hashing, secure random). 🔐
* **Jakarta Mail API (v2.0.1):** For sending emails (OTPs). ✉️
* **Jakarta Activation API (v2.1.3):** A dependency required by Jakarta Mail. 🔗

## Project Structure 🏗️

The project uses a standard Java package structure. You should execute commands from the project's root directory (`SecureFileHider`).

```python
SecureFileHider/
├── bin/                     # Compiled .class files will be stored here
├── lib/                     # External JAR libraries go here
│   ├── jakarta.activation-api-2.1.3.jar   # Jakarta Activation API
│   └── jakarta.mail-2.0.1.jar             # Jakarta Mail API
└── src/                     # Java source code root
└── com/                 # Base package folder
└── security/
└── filehider/
├── AuthManager.java     # Handles master password hashing and OTP management
├── CryptoUtils.java     # Handles AES encryption/decryption, PBKDF2 key derivation, salts/IVs
├── EmailSender.java     # Sends emails (e.g., OTPs)
└── MainApp.java         # Main application class, GUI, and orchestrates operations
```

## Setup Instructions 🛠️

To set up and run this project locally, please follow these detailed steps:

### 1. Prerequisites ✅

* **Java Development Kit (JDK) 8 or higher:** [Download and Install JDK](https://www.oracle.com/java/technologies/downloads/) ☕
* **External Libraries (JAR Files):**
    * **Jakarta Mail API (v2.0.1):**
        * Place `jakarta.mail-2.0.1.jar` into your `lib/` folder.
        * [Download from Maven Central](https://search.maven.org/artifact/com.sun.mail/jakarta.mail) (Look for version `2.0.1` and download `jakarta.mail-2.0.1.jar`)
    * **Jakarta Activation API (v2.1.3):**
        * Place `jakarta.activation-api-2.1.3.jar` into your `lib/` folder.
        * [Download from Maven Central](https://search.maven.org/artifact/jakarta.activation/jakarta.activation-api) (Look for version `2.1.3` and download `jakarta.activation-api-2.1.3.jar`)

### 2. Email Sender Configuration 📧

The application is configured to send OTP emails from a specific Gmail account.

1.  **Open `SecureFileHider/src/com/security/filehider/EmailSender.java`**.
2.  **Update Sender Credentials:**
    * **`SENDER_EMAIL`**: Set this to your actual Gmail address (e.g., `your_email@gmail.com`).
    * **`SENDER_PASSWORD`**: This **MUST be an App Password** generated from your Google Account. Your regular Gmail password will not work.
        * **How to get an App Password (for Gmail):**
            1.  Ensure 2-Step Verification is enabled on your Google Account.
            2.  Go to [Google Account Security](https://myaccount.google.com/security) -> "App passwords".
            3.  Select "Mail" as the app and "Other (Custom name)" for the device (e.g., "Secure File Hider App").
            4.  Generate the 16-character password and **copy it immediately** (it's shown only once).
            5.  Use this copied password for `SENDER_PASSWORD` in your `EmailSender.java` file.
    ```java
    // In EmailSender.java:
    private static final String SENDER_EMAIL = "your_gmail_address@gmail.com"; // REPLACE THIS!
    private static final String SENDER_PASSWORD = "YOUR_16_CHARACTER_APP_PASSWORD_HERE"; // REPLACE THIS!
    ```

### 3. Compile and Run the Application 🚀

1.  **Navigate to Project Root:** Open your terminal (e.g., VS Code Terminal, Command Prompt, PowerShell) and navigate to the `SecureFileHider` directory (e.g., `C:\SecureFileHider`).

2.  **Compile Java Code:** This compiles all `.java` files in the `src/com/security/filehider/` package and places the `.class` files into the `bin` directory, correctly referencing all libraries.

    ```bash
    javac -cp "lib\jakarta.mail-2.0.1.jar;lib\jakarta.activation-api-2.1.3.jar" -d bin src\com\security\filehider\*.java
    ```
    * **Windows users:** Ensure you use backslashes (`\`) for paths.

3.  **Run the Application:** After successful compilation, execute the application:

    ```bash
    java -cp "bin;lib\jakarta.mail-2.0.1.jar;lib\jakarta.activation-api-2.1.3.jar" com.security.filehider.MainApp
    ```

The GUI application should now launch! On the first run, you will be prompted to set up your master password and registered email. For subsequent runs, you'll enter your master password to log in.

---

## Contributing 🤝

Feel free to fork this repository, contribute, and suggest improvements! Pull requests are welcome.

## License 📄

This project is open-source and available under the [MIT License](LICENSE).
