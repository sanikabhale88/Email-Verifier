const VerificationLog = require("../models/VerificationLog");
const User = require("../models/User");

// ------------------------
// Get User Verification History
// ------------------------
exports.getLogs = async (req, res) => {
  try {
    const userId = req.userId; // Set by authMiddleware

    const logs = await VerificationLog.find({ userId })
      .sort({ createdAt: -1 })
      .select("-__v");

    res.status(200).json({
      success: true,
      count: logs.length,
      logs,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching verification logs",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

// ------------------------
// Get User Credits
// ------------------------
exports.getCredits = async (req, res) => {
  try {
    const userId = req.userId; // Set by authMiddleware

    const user = await User.findById(userId).select("credits name email");
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    res.status(200).json({
      success: true,
      credits: user.credits,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching credits",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};
