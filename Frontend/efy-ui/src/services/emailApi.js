const BASE_URL = "http://localhost:5000/api";

export const validateSingleEmail = async (email) => {
  const res = await fetch(`${BASE_URL}/validate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });

  return res.json();
};

export const validateMultipleEmails = async (emails) => {
  const res = await fetch(`${BASE_URL}/validate/multiple`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ emails }),
  });

  return res.json();
};