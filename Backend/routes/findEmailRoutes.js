const express = require("express");
const router = express.Router();
const authMiddleware = require("../middleware/authMiddleware");
const { findEmail } = require("../controllers/findEmailController");

router.post("/find-email", authMiddleware, findEmail);

module.exports = router;