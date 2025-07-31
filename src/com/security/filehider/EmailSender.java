package com.security.filehider; // Package name changed to match current project structure

import jakarta.mail.*;
import jakarta.mail.internet.*;
import java.util.Properties;

public class EmailSender {

    // This will be the email address from which OTPs are sent.
    private static final String SENDER_EMAIL = "amansrivastava1511@gmail.com";
    // For Gmail, this must be an App Password, not your regular account password.
    // Make sure you replace "YOUR_APP_PASSWORD_HERE" with the actual App Password.
    private static final String SENDER_PASSWORD = "jjol agmb lywn eurn";
    private static final String SMTP_HOST = "smtp.gmail.com"; // Gmail's SMTP host
    private static final String SMTP_PORT = "587"; // Standard SMTP port for TLS

    /**
     * Sends an email to a specified recipient.
     *
     * @param recipientEmail The email address of the recipient (to whom the OTP
     * will be sent).
     * @param subject The subject line of the email.
     * @param body The main content of the email (e.g., the OTP).
     */
    public static void sendEmail(String recipientEmail, String subject, String body) {
        Properties properties = new Properties();
        // Enable SMTP authentication and STARTTLS for secure connection
        properties.put("mail.smtp.auth", "true");
        properties.put("mail.smtp.starttls.enable", "true");
        properties.put("mail.smtp.host", SMTP_HOST);
        properties.put("mail.smtp.port", SMTP_PORT);

        // Create a Session object with the Authenticator for sender's credentials
        Session session = Session.getInstance(properties, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(SENDER_EMAIL, SENDER_PASSWORD);
            }
        });

        try {
            // Create a new email message
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(SENDER_EMAIL)); // Set the sender
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipientEmail)); // Set the recipient
            message.setSubject(subject); // Set the subject
            message.setText(body); // Set the email body (plain text)

            // Send the email
            Transport.send(message);
            System.out.println("Email sent successfully to " + recipientEmail + "!");

        } catch (MessagingException e) {
            e.printStackTrace();
            System.err.println("Failed to send email. Error: " + e.getMessage());
        }
    }
}
