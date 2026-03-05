module.exports = async function verifyEmail(email) {
  // MOCK VERSION → Works without buying any API
  // You can integrate real API later (Hunter.io or Zerobounce)
  
  if (email.includes("test")) return "invalid";

  const random = Math.random();

  if (random > 0.7) return "valid";
  if (random > 0.4) return "risky";
  return "invalid";
};