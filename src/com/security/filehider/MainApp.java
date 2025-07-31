package com.security.filehider;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

public class MainApp extends JFrame {

    // --- UI Components ---
    private JTextArea logArea;
    private JTextField filePathField;
    private JButton selectFileButton;
    private JButton hideButton;
    private JButton unhideButton;
    private JButton newUserButton;

    // --- Stored User/Session Data (Will be loaded from/saved to config file) ---
    private String storedHashedMasterPassword = null;
    private byte[] storedMasterSalt = null;
    private String registeredEmail = null;
    private String currentOtp = null;
    private ScheduledExecutorService otpScheduler;

    // --- Configuration File ---
    private static final String CONFIG_FILE_NAME = ".secure_hider_config.properties";
    private static final Path CONFIG_FILE_PATH = Paths.get(System.getProperty("user.home"), CONFIG_FILE_NAME);

    public MainApp() {
        setTitle("Secure File Hider");
        setSize(800, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null); // Center the window

        // --- UI Setup ---
        JPanel mainPanel = new JPanel(new BorderLayout(15, 15)); // Increased spacing
        mainPanel.setBorder(new EmptyBorder(15, 15, 15, 15)); // Increased padding
        mainPanel.setBackground(new Color(235, 245, 255)); // Lighter AliceBlue

        // Header
        JLabel headerLabel = new JLabel("Secure File Hider 🔒", SwingConstants.CENTER); // Added emoji
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 28)); // Larger font
        headerLabel.setForeground(new Color(25, 100, 150)); // Darker blue
        mainPanel.add(headerLabel, BorderLayout.NORTH);

        // File Selection Panel
        JPanel filePanel = new JPanel(new BorderLayout(10, 0)); // More horizontal spacing
        filePathField = new JTextField("No file selected.");
        filePathField.setEditable(false);
        filePathField.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        selectFileButton = new JButton("Select File 📁"); // Added emoji
        selectFileButton.addActionListener(this::selectFile);
        selectFileButton.setFont(new Font("Segoe UI", Font.BOLD, 15)); // Increased font size
        selectFileButton.setBackground(new Color(190, 220, 255)); // Light blue
        selectFileButton.setForeground(Color.BLACK);
        filePanel.add(filePathField, BorderLayout.CENTER);
        filePanel.add(selectFileButton, BorderLayout.EAST);
        filePanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(new Color(150, 180, 220)), "File Operations", TitledBorder.LEFT, TitledBorder.TOP, new Font("Segoe UI", Font.BOLD, 14), new Color(50, 100, 150)));
        filePanel.setBackground(new Color(245, 250, 255)); // Slightly different background

        // Action Buttons Panel
        JPanel actionPanel = new JPanel(new GridLayout(1, 2, 20, 0)); // More spacing between buttons
        hideButton = new JButton("Hide File (Encrypt) 🔒"); // Added emoji
        unhideButton = new JButton("Unhide File (Decrypt) 🔓"); // Added emoji
        hideButton.addActionListener(this::hideFile);
        unhideButton.addActionListener(this::unhideFile);

        Font actionButtonFont = new Font("Segoe UI", Font.BOLD, 18); // Increased font size for action buttons

        hideButton.setFont(actionButtonFont);
        hideButton.setBackground(new Color(150, 255, 150)); // Lighter Green background
        hideButton.setForeground(Color.BLACK); // Black text for better contrast
        hideButton.setFocusPainted(false);
        hideButton.setBorder(BorderFactory.createLineBorder(new Color(70, 150, 70), 2)); // Green border

        unhideButton.setFont(actionButtonFont);
        unhideButton.setBackground(new Color(255, 220, 150)); // Lighter Orange background
        unhideButton.setForeground(Color.BLACK); // Black text for better contrast
        unhideButton.setFocusPainted(false);
        unhideButton.setBorder(BorderFactory.createLineBorder(new Color(200, 120, 70), 2)); // Orange border

        actionPanel.add(hideButton);
        actionPanel.add(unhideButton);

        // NEW: New User / Reset App Button
        newUserButton = new JButton("Reset App / New User Setup 🔄"); // Added new button
        newUserButton.setFont(new Font("Segoe UI", Font.BOLD, 15)); // Increased font size
        newUserButton.setBackground(new Color(220, 220, 220)); // Light Gray
        newUserButton.setForeground(Color.BLACK);
        newUserButton.setFocusPainted(false);
        newUserButton.setBorder(BorderFactory.createLineBorder(new Color(180, 180, 180), 1));
        newUserButton.addActionListener(this::resetApp); // Add action listener for reset

        JPanel controlsAndResetPanel = new JPanel(new BorderLayout(15, 15));
        controlsAndResetPanel.add(actionPanel, BorderLayout.NORTH); // Main actions at the top
        controlsAndResetPanel.add(newUserButton, BorderLayout.SOUTH); // New user button at the bottom

        JPanel controlsPanel = new JPanel(new BorderLayout(15, 15)); // Increased spacing
        controlsPanel.add(filePanel, BorderLayout.NORTH);
        controlsPanel.add(controlsAndResetPanel, BorderLayout.CENTER); // Embed the new panel here
        controlsPanel.setBackground(new Color(235, 245, 255)); // Match main panel background
        mainPanel.add(controlsPanel, BorderLayout.CENTER);

        // Log Area
        logArea = new JTextArea(10, 50);
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logArea.setBackground(new Color(255, 255, 240)); // Light Yellow
        logArea.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY, 1));
        JScrollPane logScrollPane = new JScrollPane(logArea);
        logScrollPane.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(new Color(150, 180, 220)), "Activity Log", TitledBorder.LEFT, TitledBorder.TOP, new Font("Segoe UI", Font.BOLD, 14), new Color(50, 100, 150)));
        mainPanel.add(logScrollPane, BorderLayout.SOUTH);

        add(mainPanel);

        // --- Initial Setup/Login Flow ---
        SwingUtilities.invokeLater(this::initialSetupOrLogin);
    }

    private void initialSetupOrLogin() {
        // Attempt to load existing master password/email from config file
        loadConfig();

        if (storedHashedMasterPassword == null) {
            updateLog("No existing configuration found. Proceeding to first-time setup.");
            showSetupDialog(); // First time run: set master password and email
        } else {
            updateLog("Configuration loaded. Please log in.");
            showLoginDialog(); // Subsequent runs: login with master password
        }
    }

    private void loadConfig() {
        if (Files.exists(CONFIG_FILE_PATH)) {
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(CONFIG_FILE_PATH.toFile())) {
                props.load(fis);
                String hashedPassBase64 = props.getProperty("master.password.hash");
                String saltBase64 = props.getProperty("master.salt");
                String email = props.getProperty("registered.email");

                if (hashedPassBase64 != null && saltBase64 != null && email != null) {
                    storedHashedMasterPassword = hashedPassBase64;
                    storedMasterSalt = AuthManager.base64ToBytes(saltBase64); // Use AuthManager's utility
                    registeredEmail = email;
                    updateLog("Configuration loaded from " + CONFIG_FILE_PATH.getFileName());
                } else {
                    updateLog("Config file found but incomplete. Starting fresh setup.");
                }
            } catch (IOException e) {
                updateLog("Error loading config file: " + e.getMessage());
                // Config file might be corrupted, treat as no config
                storedHashedMasterPassword = null;
                storedMasterSalt = null;
                registeredEmail = null;
            }
        } else {
            updateLog("Config file not found.");
        }
    }

    private void saveConfig() {
        Properties props = new Properties();
        props.setProperty("master.password.hash", storedHashedMasterPassword);
        props.setProperty("master.salt", AuthManager.bytesToBase64(storedMasterSalt)); // Use AuthManager's utility
        props.setProperty("registered.email", registeredEmail);

        try (FileOutputStream fos = new FileOutputStream(CONFIG_FILE_PATH.toFile())) {
            props.store(fos, "Secure File Hider Configuration");
            updateLog("Configuration saved to " + CONFIG_FILE_PATH.getFileName());
        } catch (IOException e) {
            showError("Error saving config file: " + e.getMessage());
        }
        // ❗ SECURITY WARNING: Storing hashed password and salt in plain file is NOT secure for production.
        // For production, this file should be encrypted, or platform-specific secure storage should be used.
    }

    // NEW: resetApp method
    private void resetApp(ActionEvent e) {
        int confirm = JOptionPane.showConfirmDialog(this,
                "This will delete your current master password and registered email.\n"
                + "You will need to set up a new one. Are you sure?",
                "Reset Application Data",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);

        if (confirm == JOptionPane.YES_OPTION) {
            try {
                Files.deleteIfExists(CONFIG_FILE_PATH);
                storedHashedMasterPassword = null;
                storedMasterSalt = null;
                registeredEmail = null;
                updateLog("Application configuration reset successfully. Restarting setup.");
                showSetupDialog(); // Show setup dialog again
            } catch (IOException ex) {
                showError("Failed to delete config file: " + ex.getMessage());
            }
        }
    }

    private void showSetupDialog() {
        JPasswordField masterPassField = new JPasswordField(20);
        JPasswordField confirmPassField = new JPasswordField(20);
        JTextField emailField = new JTextField(20);

        JPanel panel = new JPanel(new GridLayout(0, 2, 5, 5));
        panel.add(new JLabel("Set Master Password:"));
        panel.add(masterPassField);
        panel.add(new JLabel("Confirm Password:"));
        panel.add(confirmPassField);
        panel.add(new JLabel("Registered Email (for OTP):"));
        panel.add(emailField);

        int result = JOptionPane.showConfirmDialog(this, panel, "First Time Setup", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            String masterPass = masterPassField.getText();
            String confirmPass = confirmPassField.getText();
            String email = emailField.getText().trim();

            if (masterPass.isEmpty() || email.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Password and Email cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
                showSetupDialog(); // Retry setup
                return;
            }
            if (!masterPass.equals(confirmPass)) {
                JOptionPane.showMessageDialog(this, "Passwords do not match.", "Error", JOptionPane.ERROR_MESSAGE);
                showSetupDialog(); // Retry setup
                return;
            }
            if (!email.matches("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$")) {
                JOptionPane.showMessageDialog(this, "Please enter a valid email address.", "Error", JOptionPane.ERROR_MESSAGE);
                showSetupDialog(); // Retry setup
                return;
            }

            try {
                storedMasterSalt = AuthManager.generateSalt();
                storedHashedMasterPassword = AuthManager.hashPassword(masterPass, storedMasterSalt);
                registeredEmail = email;
                saveConfig(); // Save configuration after successful setup
                updateLog("Setup successful! Master password and email registered. Please log in.");
                showLoginDialog();
            } catch (NoSuchAlgorithmException e) {
                showError("Error during password hashing: " + e.getMessage());
            }
        } else {
            System.exit(0); // Exit if setup is cancelled
        }
    }

    private void showLoginDialog() {
        JPasswordField masterPassField = new JPasswordField(20);
        JButton forgotPasswordButton = new JButton("Forgot Password?");

        JPanel panel = new JPanel(new BorderLayout(10, 10));
        JPanel inputPanel = new JPanel(new GridLayout(0, 2, 5, 5));
        inputPanel.add(new JLabel("Enter Master Password:"));
        inputPanel.add(masterPassField);
        panel.add(inputPanel, BorderLayout.CENTER);

        // Create custom buttons
        JButton okButton = new JButton("OK");
        JButton cancelButton = new JButton("Cancel");

        // Add buttons to a panel to control their layout
        JPanel customButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        customButtonPanel.add(okButton);
        customButtonPanel.add(cancelButton);
        customButtonPanel.add(forgotPasswordButton);

        // Add custom button panel to the JOptionPane's content
        // IMPORTANT: The JOptionPane constructor takes an array of options. These are the *objects* that will be used.
        // We set the initial value to okButton so it has initial focus.
        JOptionPane loginPane = new JOptionPane(panel, JOptionPane.PLAIN_MESSAGE, JOptionPane.DEFAULT_OPTION, null, new Object[]{okButton, cancelButton, forgotPasswordButton}, okButton);

        // Create the dialog from the JOptionPane
        JDialog loginDialog = loginPane.createDialog(this, "Login");

        // Attach listeners to custom buttons to set the JOptionPane's value when clicked
        okButton.addActionListener(e -> loginPane.setValue(okButton));
        cancelButton.addActionListener(e -> loginPane.setValue(cancelButton));
        forgotPasswordButton.addActionListener(e -> loginPane.setValue(forgotPasswordButton));

        // Show the dialog and block until a button is pressed or dialog is closed
        loginDialog.setVisible(true);

        // Get the selected option (which will be one of our button objects)
        Object selectedValue = loginPane.getValue();

        if (selectedValue == okButton) { // OK button was pressed
            String enteredPass = masterPassField.getText();
            try {
                if (storedHashedMasterPassword == null || !AuthManager.verifyPassword(enteredPass, storedHashedMasterPassword, storedMasterSalt)) {
                    JOptionPane.showMessageDialog(this, "Invalid Master Password.", "Login Failed", JOptionPane.ERROR_MESSAGE);
                    showLoginDialog(); // Retry login
                } else {
                    updateLog("Login successful! Proceeding to operations.");
                }
            } catch (NoSuchAlgorithmException e) {
                showError("Error during password verification: " + e.getMessage());
            }
        } else if (selectedValue == forgotPasswordButton) { // Forgot Password button was pressed
            showForgotPasswordFlow(); // Start forgot password flow
        } else { // Cancel button was pressed or dialog closed
            System.exit(0); // Exit
        }
    }

    // NEW: showForgotPasswordFlow method
    private void showForgotPasswordFlow() {
        if (registeredEmail == null || registeredEmail.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No registered email found for password recovery. Please use 'Reset App' to set up new credentials.", "Recovery Not Available", JOptionPane.WARNING_MESSAGE);
            showLoginDialog();
            return;
        }

        // Step 1: Confirm Registered Email
        JTextField emailConfirmField = new JTextField(registeredEmail); // Pre-fill with known registered email
        emailConfirmField.setEditable(false); // Make it read-only

        JPanel emailPanel = new JPanel(new GridLayout(0, 2, 5, 5));
        emailPanel.add(new JLabel("Confirm Registered Email:"));
        emailPanel.add(emailConfirmField);

        int confirmEmailResult = JOptionPane.showConfirmDialog(this, emailPanel, "Forgot Password - Step 1", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (confirmEmailResult != JOptionPane.OK_OPTION) {
            updateLog("Forgot Password flow cancelled by user.");
            showLoginDialog(); // Go back to login
            return;
        }

        // Step 2: Send OTP
        currentOtp = AuthManager.generateOtp();
        String emailSubject = "Secure File Hider Password Reset OTP";
        String emailBody = "Your One-Time Password (OTP) for password reset is: " + currentOtp + "\n\n"
                + "This OTP is valid for 5 minutes.";

        EmailSender.sendEmail(registeredEmail, emailSubject, emailBody);
        updateLog("OTP sent to your registered email for password reset: " + registeredEmail);

        // Start OTP expiration timer
        startOtpExpirationTimer();

        // Step 3: Enter OTP
        JTextField otpField = new JTextField(6);
        JPanel otpPanel = new JPanel(new GridLayout(0, 2, 5, 5));
        otpPanel.add(new JLabel("Enter OTP received via email:"));
        otpPanel.add(otpField);

        int otpResult = JOptionPane.showConfirmDialog(this, otpPanel, "Forgot Password - Step 2", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (otpResult == JOptionPane.OK_OPTION) {
            String enteredOtp = otpField.getText().trim();
            if (currentOtp == null || !currentOtp.equals(enteredOtp)) {
                JOptionPane.showMessageDialog(this, "Invalid or expired OTP. Password reset aborted.", "OTP Failed", JOptionPane.ERROR_MESSAGE);
                updateLog("OTP verification failed during password reset.");
                showLoginDialog(); // Go back to login
                return;
            }
            stopOtpExpirationTimer(); // OTP verified, stop timer
            currentOtp = null; // Clear OTP

            // Step 4: Set New Master Password
            JPasswordField newMasterPassField = new JPasswordField(20);
            JPasswordField confirmNewPassField = new JPasswordField(20);

            JPanel newPassPanel = new JPanel(new GridLayout(0, 2, 5, 5));
            newPassPanel.add(new JLabel("Set NEW Master Password:"));
            newPassPanel.add(newMasterPassField);
            newPassPanel.add(new JLabel("Confirm NEW Password:"));
            newPassPanel.add(confirmNewPassField);

            int newPassResult = JOptionPane.showConfirmDialog(this, newPassPanel, "Forgot Password - Step 3", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

            if (newPassResult == JOptionPane.OK_OPTION) {
                String newMasterPass = newMasterPassField.getText();
                String confirmNewPass = confirmNewPassField.getText();

                if (newMasterPass.isEmpty()) {
                    JOptionPane.showMessageDialog(this, "New Master Password cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
                    showLoginDialog(); // Go back to login
                    return;
                }
                if (!newMasterPass.equals(confirmNewPass)) {
                    JOptionPane.showMessageDialog(this, "New Passwords do not match.", "Error", JOptionPane.ERROR_MESSAGE);
                    showLoginDialog(); // Go back to login
                    return;
                }

                try {
                    storedMasterSalt = AuthManager.generateSalt(); // Generate new salt for new password
                    storedHashedMasterPassword = AuthManager.hashPassword(newMasterPass, storedMasterSalt);
                    saveConfig(); // Save the new password hash and salt
                    JOptionPane.showMessageDialog(this, "Master Password reset successfully! Please log in with your new password.", "Password Reset", JOptionPane.INFORMATION_MESSAGE);
                    updateLog("Master password reset successfully.");
                    showLoginDialog(); // Go back to login
                } catch (NoSuchAlgorithmException ex) {
                    showError("Error during new password hashing: " + ex.getMessage());
                    showLoginDialog(); // Go back to login
                }
            } else {
                updateLog("New password setup cancelled. Password not reset.");
                showLoginDialog(); // Go back to login
            }
        } else {
            updateLog("OTP verification cancelled. Password not reset.");
            showLoginDialog(); // Go back to login
        }
    }

    private void selectFile(ActionEvent e) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            filePathField.setText(selectedFile.getAbsolutePath());
            updateLog("File selected: " + selectedFile.getName());
        }
    }

    private void hideFile(ActionEvent e) {
        String originalFilePath = filePathField.getText(); // This is the path to the original file
        if (originalFilePath.isEmpty() || originalFilePath.equals("No file selected.")) {
            showError("Please select a file first.");
            return;
        }

        Path originalPath = Paths.get(originalFilePath);
        if (!Files.exists(originalPath)) {
            showError("Original file does not exist: " + originalFilePath);
            return;
        }
        if (Files.isDirectory(originalPath)) {
            showError("Cannot hide a directory. Please select a file.");
            return;
        }

        // Authenticate with master password before hiding
        JPasswordField masterPassField = new JPasswordField(20);
        JPanel panel = new JPanel(new GridLayout(0, 2, 5, 5));
        panel.add(new JLabel("Confirm Master Password:"));
        panel.add(masterPassField);

        int result = JOptionPane.showConfirmDialog(this, panel, "Confirm to Hide File", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            String enteredPass = masterPassField.getText();
            try {
                if (storedHashedMasterPassword == null || !AuthManager.verifyPassword(enteredPass, storedHashedMasterPassword, storedMasterSalt)) {
                    JOptionPane.showMessageDialog(this, "Incorrect Master Password. File hiding aborted.", "Authentication Failed", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // --- Hiding Process ---
                // 1. Define encrypted file path (at original location)
                String encryptedFilePathAtOriginalLocation = originalFilePath + ".encrypted";
                Path encryptedPath = Paths.get(encryptedFilePathAtOriginalLocation);

                // 2. Generate encryption salt and IV (unique for THIS file encryption)
                byte[] encryptionSalt = CryptoUtils.generateSalt();
                byte[] encryptionIv = CryptoUtils.generateIv();

                // 3. Derive key using the MASTER PASSWORD and the FILE-SPECIFIC ENCRYPTION SALT
                SecretKey fileEncryptionKey = CryptoUtils.deriveKey(enteredPass, encryptionSalt);

                // 4. Encrypt the original file, including writing salt/IV as header
                Files.deleteIfExists(encryptedPath); // Ensure clean overwrite
                CryptoUtils.encryptFile(originalFilePath, encryptedFilePathAtOriginalLocation, fileEncryptionKey, encryptionSalt, encryptionIv);

                // 5. Delete the ORIGINAL file
                Files.delete(originalPath);
                updateLog("Original file deleted: " + originalPath.getFileName());

                // Removed setting hidden attribute on the .encrypted file (as per user's last request for visibility)
                // try {
                //     Files.setAttribute(encryptedPath, "dos:hidden", true);
                //     updateLog("Encrypted file marked as hidden (Windows attribute).");
                // } catch (UnsupportedOperationException | IOException ex) {
                //     updateLog("Warning: Could not set encrypted file as hidden (not supported on this OS or file system).");
                // }
                updateLog("File '" + originalPath.getFileName() + "' hidden successfully!");
                filePathField.setText(encryptedFilePathAtOriginalLocation); // Show the .encrypted file in the field
            } catch (Exception ex) {
                showError("Failed to hide file: " + ex.getMessage());
                ex.printStackTrace();
            }
        }
    }

    private void unhideFile(ActionEvent e) {
        String encryptedFilePath = filePathField.getText(); // This is the path to the encrypted file
        if (encryptedFilePath.isEmpty() || encryptedFilePath.equals("No file selected.") || !encryptedFilePath.endsWith(".encrypted")) {
            showError("Please select an encrypted file (ending with .encrypted) to unhide.");
            return;
        }

        Path encryptedPath = Paths.get(encryptedFilePath);
        if (!Files.exists(encryptedPath)) {
            showError("Encrypted file does not exist: " + encryptedFilePath);
            return;
        }

        // --- Step 1: Master Password Authentication ---
        JPasswordField masterPassField = new JPasswordField(20);
        JPanel passPanel = new JPanel(new GridLayout(0, 2, 5, 5));
        passPanel.add(new JLabel("Enter Master Password:"));
        passPanel.add(masterPassField);

        int passResult = JOptionPane.showConfirmDialog(this, passPanel, "Authenticate to Unhide", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (passResult == JOptionPane.OK_OPTION) {
            String enteredPass = masterPassField.getText();
            try {
                if (storedHashedMasterPassword == null || !AuthManager.verifyPassword(enteredPass, storedHashedMasterPassword, storedMasterSalt)) {
                    JOptionPane.showMessageDialog(this, "Invalid Master Password.", "Authentication Failed", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // --- Step 2: Send OTP to Registered Email ---
                currentOtp = AuthManager.generateOtp();
                String emailSubject = "Secure File Hider OTP";
                String emailBody = "Your One-Time Password (OTP) for Secure File Hider is: " + currentOtp + "\n\n"
                        + "This OTP is valid for 5 minutes.";

                EmailSender.sendEmail(registeredEmail, emailSubject, emailBody);
                updateLog("OTP sent to your registered email: " + registeredEmail);

                // --- Step 3: OTP Verification ---
                JTextField otpField = new JTextField(6);
                JPanel otpPanel = new JPanel(new GridLayout(0, 2, 5, 5));
                otpPanel.add(new JLabel("Enter OTP received via email:"));
                otpPanel.add(otpField);

                // Start OTP expiration timer
                startOtpExpirationTimer();

                int otpResult = JOptionPane.showConfirmDialog(this, otpPanel, "OTP Verification", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
                if (otpResult == JOptionPane.OK_OPTION) {
                    String enteredOtp = otpField.getText().trim();
                    if (currentOtp == null || !currentOtp.equals(enteredOtp)) {
                        JOptionPane.showMessageDialog(this, "Invalid or expired OTP. Unhiding aborted.", "OTP Failed", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    // OTP is valid, proceed with decryption

                    // Corrected key derivation: CryptoUtils.decryptFile will now derive the key internally
                    // using the master password AND the file-specific salt read from the encrypted file's header.
                    // Define decrypted file path (original name without .encrypted extension)
                    String originalFileName = encryptedPath.getFileName().toString().replace(".encrypted", "");
                    Path originalRestoredPath = encryptedPath.getParent().resolve(originalFileName);

                    // 1. Decrypt the .encrypted file to its original name
                    // Pass the master password to CryptoUtils.decryptFile so it can derive the key with the file's salt
                    CryptoUtils.decryptFile(encryptedFilePath, originalRestoredPath.toString(), enteredPass);

                    // 2. Delete the .encrypted file
                    Files.deleteIfExists(encryptedPath);
                    updateLog("Encrypted file deleted: " + encryptedPath.getFileName());

                    // Removed unhiding attribute from the original restored file
                    // try {
                    //     Files.setAttribute(originalRestoredPath, "dos:hidden", false);
                    //     updateLog("Original restored file marked as visible (Windows attribute).");
                    // } catch (UnsupportedOperationException | IOException ex) {
                    //     updateLog("Warning: Could not remove hidden attribute from original file (OS-specific issue or not set).");
                    // }
                    updateLog("File '" + originalFileName + "' unhidden successfully!");
                    filePathField.setText(originalRestoredPath.toString()); // Show original file path in field
                } else {
                    updateLog("OTP verification cancelled. Unhiding aborted.");
                }
            } catch (Exception ex) {
                showError("Failed to unhide file: " + ex.getMessage());
                ex.printStackTrace();
            } finally {
                stopOtpExpirationTimer(); // Always stop timer
                currentOtp = null; // Clear OTP
            }
        }
    }

    private void startOtpExpirationTimer() {
        if (otpScheduler != null && !otpScheduler.isShutdown()) {
            otpScheduler.shutdownNow();
        }
        otpScheduler = Executors.newSingleThreadScheduledExecutor();
        otpScheduler.schedule(() -> {
            currentOtp = null; // Invalidate OTP after 5 minutes
            updateLog("OTP has expired.");
        }, 5, TimeUnit.MINUTES);
    }

    private void stopOtpExpirationTimer() {
        if (otpScheduler != null && !otpScheduler.isShutdown()) {
            otpScheduler.shutdownNow();
        }
    }

    private void updateLog(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength()); // Scroll to bottom
        });
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
        updateLog("ERROR: " + message);
    }

    public static void main(String[] args) {
        // Set System Look and Feel
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }

        SwingUtilities.invokeLater(() -> new MainApp().setVisible(true));
    }
}
