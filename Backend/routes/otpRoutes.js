const express = require("express");
const { sendOtp, verifyOtp } = require("../controllers/otpController");

const router = express.Router();

// @route   POST /api/otp/send
// @desc    Send OTP to email
// @access  Public
router.post("/send", sendOtp);

// @route   POST /api/otp/verify
// @desc    Verify OTP code
// @access  Public
router.post("/verify", verifyOtp);

module.exports = router;
