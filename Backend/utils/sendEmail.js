const nodemailer = require("nodemailer");

/**
 * Send email using nodemailer
 * @param {string} to - Recipient email address
 * @param {string} subject - Email subject
 * @param {string} text - Email body (plain text)
 * @param {string} html - Email body (HTML, optional)
 * @returns {Promise<void>}
 */
const sendEmail = async (to, subject, text, html = null) => {
  try {
    // Validate inputs
    if (!to || !subject || !text) {
      throw new Error("To, subject, and text are required");
    }

    // Create transporter
    const transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE || "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // Verify transporter configuration
    await transporter.verify();

    // Email options
    const mailOptions = {
      from: `"${process.env.EMAIL_FROM_NAME || "Email Verifier"}" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      text,
      html: html || text.replace(/\n/g, "<br>"), // Convert plain text to HTML if no HTML provided
    };

    // Send email
    const info = await transporter.sendMail(mailOptions);
    console.log(`Email sent successfully to ${to}: ${info.messageId}`);
    return info;
  } catch (error) {
    console.error("Error sending email:", error.message);
    throw new Error(`Failed to send email: ${error.message}`);
  }
};

module.exports = sendEmail;
