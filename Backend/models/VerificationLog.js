const mongoose = require("mongoose");

const VerificationLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "User ID is required"],
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      trim: true,
      lowercase: true,
    },
    result: {
      type: mongoose.Schema.Types.Mixed,
      required: [true, "Result object is required"],
    },
  },
  {
    timestamps: true, // Automatically adds createdAt and updatedAt
  }
);

// Index for faster queries
VerificationLogSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model("VerificationLog", VerificationLogSchema);
