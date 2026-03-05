const express = require("express");
const auth = require("../controllers/authController");
const authMiddleware = require("../middleware/authMiddleware");

const {
  registerRequest,
  verifyOtpAndCreateUser,
  login,
  forgotPassword,
  verifyForgotOtp,
  resetPassword,
  changePassword
} = auth;

const router = express.Router();

// Step 1: Send OTP for registration
router.post("/register-request", registerRequest);

// Step 2: Verify OTP & create user
router.post("/verify-otp", verifyOtpAndCreateUser);

// Login
router.post("/login", login);

// Forgot password (send OTP)
router.post("/forgot-password", forgotPassword);

// Verify OTP for forgot password
router.post("/verify-forgot-otp", verifyForgotOtp);

// Reset password (after OTP)
router.post("/reset-password", resetPassword);

// Change password (requires JWT auth)
router.post("/change-password", authMiddleware, changePassword);

module.exports = router;