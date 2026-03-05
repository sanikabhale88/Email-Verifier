const jwt = require("jsonwebtoken");
const User = require("../models/User");

// -------------------------
// Authentication Middleware
// -------------------------
const authMiddleware = async (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message: "No token provided. Access denied.",
      });
    }

    // Extract token (handle "Bearer <token>" format)
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7)
      : authHeader;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "No token provided. Access denied.",
      });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (jwtError) {
      if (jwtError.name === "TokenExpiredError") {
        return res.status(401).json({
          success: false,
          message: "Token has expired. Please login again.",
        });
      }
      if (jwtError.name === "JsonWebTokenError") {
        return res.status(401).json({
          success: false,
          message: "Invalid token. Access denied.",
        });
      }
      throw jwtError;
    }

    // Check if user still exists
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User no longer exists. Access denied.",
      });
    }

    // Attach user ID to request
    req.userId = decoded.id;
    req.user = user;

    next();
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Authentication error",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

module.exports = authMiddleware;
