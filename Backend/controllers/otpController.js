const Otp = require("../models/Otp");
const sendEmail = require("../utils/sendEmail");

// ----------------------
// Generate OTP Code
// ----------------------
const generateOTP = () => {
  return Math.floor(1000 + Math.random() * 9000).toString();
};

// ----------------------
// Send OTP
// ----------------------
exports.sendOtp = async (req, res) => {
  try {
    const { email } = req.body;

    // Validation
    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    // Basic email format validation
    const emailRegex = /^\S+@\S+\.\S+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid email address",
      });
    }

    // Generate OTP
    const otpCode = generateOTP();

    // Set expiration (5 minutes from now)
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    // Delete any existing OTP for this email
    await Otp.deleteMany({ email });

    // Save new OTP in database
    await Otp.create({
      email: email.toLowerCase().trim(),
      code: otpCode,
      expiresAt,
    });

    // Send email with OTP
    try {
      await sendEmail(
        email,
        `Your OTP Code`,
        `Your OTP code is: ${otpCode}\n\nThis code will expire in 5 minutes.\n\nIf you didn't request this code, please ignore this email.`
      );
    } catch (emailError) {
      // If email fails, still return success but log the error
      console.error("Email sending failed:", emailError.message);
      // Optionally, you can return an error here if email is critical
    }

    res.status(200).json({
      success: true,
      message: "OTP sent successfully to your email",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error sending OTP",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

// ----------------------
// Verify OTP
// ----------------------
exports.verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    // Validation
    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Email and OTP are required",
      });
    }

    // Find OTP record
    const otpRecord = await Otp.findOne({
      email: email.toLowerCase().trim(),
      code: otp,
    });

    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP code",
      });
    }

    // Check if OTP is expired
    if (new Date() > otpRecord.expiresAt) {
      // Delete expired OTP
      await Otp.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({
        success: false,
        message: "OTP has expired. Please request a new one.",
      });
    }

    // OTP is valid - delete it (one-time use)
    await Otp.deleteOne({ _id: otpRecord._id });

    res.status(200).json({
      success: true,
      message: "OTP verified successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error verifying OTP",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};
