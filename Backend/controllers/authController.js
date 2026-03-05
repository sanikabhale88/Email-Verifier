const User = require("../models/User");
const Otp = require("../models/Otp");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const sendEmail = require("../utils/sendEmail");

// Generate JWT Token
const generateToken = (userId) => {
  const secret = process.env.JWT_SECRET || "dev_jwt_secret_change_me";
  return jwt.sign({ id: userId }, secret, {
    expiresIn: process.env.JWT_EXPIRE || "7d",
  });
};

/* ------------------------------------------
   1️⃣ REGISTER REQUEST — SEND OTP
-------------------------------------------*/
exports.registerRequest = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Please provide name, email, and password",
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists",
      });
    }

    const otp = Math.floor(1000 + Math.random() * 9000);

    await Otp.deleteMany({ email });
    await Otp.create({
      email,
      code: otp,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    // send email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP is ${otp}`,
    });

    res.status(200).json({
      success: true,
      message: "OTP sent to your email",
      data: { name, email, password },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/* ------------------------------------------
   2️⃣ VERIFY OTP — CREATE USER
-------------------------------------------*/
exports.verifyOtpAndCreateUser = async (req, res) => {
  try {
    const { name, email, password, otp } = req.body;

    // Find OTP record
    const otpRecord = await Otp.findOne({ email, code: otp });
    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    // Check expiration
    if (otpRecord.expiresAt < Date.now()) {
      return res.status(400).json({
        success: false,
        message: "OTP expired",
      });
    }

    // ⭐ Create user after OTP is verified
    const user = await User.create({
      name,
      email,
      password,
      credits: 100,
      isVerified: true,   // ⭐ IMPORTANT — this fixes login issue
    });

    // Delete OTP after success
    await Otp.deleteMany({ email });

    // Generate JWT
    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      message: "Account verified and created successfully",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        credits: user.credits,
        isVerified: user.isVerified,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error verifying OTP",
      error: error.message,
    });
  }
};

/* ------------------------------------------
   3️⃣ LOGIN
-------------------------------------------*/
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    if (!user.isVerified) {
      return res.status(400).json({
        success: false,
        message: "Please verify your email",
      });
    }

    const token = generateToken(user._id);

    res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      user,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, message: "User not found" });

    const otp = Math.floor(1000 + Math.random() * 9000);

    await Otp.deleteMany({ email });
    await Otp.create({
      email,
      code: otp,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    await sendEmail(
      email,
      "Your Password Reset OTP",
      `Your OTP for resetting password is: ${otp}`
    );

    return res.json({
      success: true,
      message: "OTP sent to email",
    });

  } catch (err) {
    return res.json({ success: false, message: err.message });
  }
};

exports.verifyForgotOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const record = await Otp.findOne({ email, code: otp });
    if (!record) return res.json({ success: false, message: "Invalid OTP" });

    if (record.expiresAt < Date.now()) {
      return res.json({ success: false, message: "OTP expired" });
    }

    await Otp.deleteMany({ email });

    return res.json({ success: true, message: "OTP verified" });

  } catch (err) {
    return res.json({ success: false, message: err.message });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    // update password (pre-save hook will hash it)
    user.password = password;
    await user.save();

    return res.json({
      success: true,
      message: "Password updated successfully",
    });

  } catch (err) {
    return res.json({
      success: false,
      message: err.message,
    });
  }
};

exports.changePassword = async (req, res) => {
  try {
    const userId = req.user.id; // from authMiddleware
    const { oldPassword, newPassword } = req.body;

    const user = await User.findById(userId).select("+password");

    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    // Check old password
    const isMatch = await user.comparePassword(oldPassword);
    if (!isMatch) {
      return res.json({ success: false, message: "Old password is incorrect" });
    }

    // Update the new password
    user.password = newPassword;
    await user.save();

    return res.json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (err) {
    return res.json({
      success: false,
      message: err.message,
    });
  }
};