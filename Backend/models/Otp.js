const mongoose = require("mongoose");

const OtpSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, "Email is required"],
      trim: true,
      lowercase: true,
    },
    code: {
      type: String,
      required: [true, "OTP code is required"],
      length: [4, "OTP must be 4 digits"],
    },
    expiresAt: {
      type: Date,
      required: [true, "Expiration date is required"],
      index: { expireAfterSeconds: 0 }, // Auto-delete expired documents
    },
  },
  {
    timestamps: true,
  }
);

// Index for faster lookups
OtpSchema.index({ email: 1, code: 1 });

module.exports = mongoose.model("Otp", OtpSchema);
