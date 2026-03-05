const verifyEmail = require("../utils/verifyEmail");  // you will create this
const User = require("../models/User");

exports.findEmail = async (req, res) => {
  try {
    const userId = req.user.id;
    const { firstName, lastName, domain } = req.body;

    if (!firstName || !lastName || !domain) {
      return res.json({ success: false, message: "All fields required" });
    }

    // Deduct 1 credit
    const user = await User.findById(userId);
    if (user.credits <= 0) {
      return res.json({ success: false, message: "Not enough credits" });
    }
    user.credits -= 1;
    await user.save();

    // Common corporate email patterns
    const patterns = [
      `${firstName}.${lastName}@${domain}`,
      `${firstName}${lastName}@${domain}`,
      `${firstName}_${lastName}@${domain}`,
      `${firstName[0]}${lastName}@${domain}`,
      `${firstName}${lastName[0]}@${domain}`,
      `${firstName}@${domain}`,
      `${lastName}@${domain}`,
      `${lastName}.${firstName}@${domain}`,
      `${firstName}-${lastName}@${domain}`,
      `${firstName[0]}.${lastName}@${domain}`,
      `${firstName}.${lastName[0]}@${domain}`,
      `${firstName[0]}${lastName[0]}@${domain}`,
    ];

    let results = [];

    for (let email of patterns) {
      const status = await verifyEmail(email); // valid, risky, invalid
      results.push({ email, status });
    }

    // Pick best email (valid > risky > invalid)
    const best = 
      results.find(r => r.status === "valid") ||
      results.find(r => r.status === "risky") ||
      results[0];

    res.json({
      success: true,
      bestEmail: best,
      allResults: results,
      creditsLeft: user.credits
    });

  } catch (err) {
    res.json({ success: false, message: err.message });
  }
};