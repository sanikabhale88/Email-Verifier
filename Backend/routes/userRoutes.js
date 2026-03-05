const express = require("express");
const { getLogs, getCredits } = require("../controllers/userController");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

// All routes require authentication
router.use(authMiddleware);

// @route   GET /api/user/logs
// @desc    Get user's verification logs
// @access  Private
router.get("/logs", getLogs);

// @route   GET /api/user/credits
// @desc    Get user's remaining credits
// @access  Private
router.get("/credits", getCredits);

module.exports = router;
