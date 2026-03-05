import React, { useState, useRef } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import "./Login.css";

const API_BASE_URL = "http://localhost:5000/api";

function Verification() {
  const navigate = useNavigate();
  const location = useLocation();
  const inputs = useRef([]);

  // Get the data passed from CreateAccount page
  const { name, email, password } = location.state || {};

  const [otp, setOtp] = useState(["", "", "", ""]);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  // Handle each OTP box input
  const handleChange = (value, index) => {
    if (!/^[0-9]?$/.test(value)) return;

    const newOtp = [...otp];
    newOtp[index] = value;
    setOtp(newOtp);

    if (value && index < 3) {
      inputs.current[index + 1].focus();
    }
  };

  // Confirm Button → Call backend verify API
  const handleConfirm = async () => {
    const code = otp.join("");

    if (code.length !== 4) {
      setError("Please enter all 4 digits");
      return;
    }

    setLoading(true);
    setError("");
    setSuccess("");

    try {
      const res = await fetch(`${API_BASE_URL}/auth/verify-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          email,
          password,
          otp: code,
        }),
      });

      const data = await res.json();

      if (!data.success) {
        throw new Error(data.message);
      }

      setSuccess("OTP Verified! Account created successfully.");

      setTimeout(() => {
        navigate("/login");
      }, 1500);

    } catch (err) {
      setError(err.message || "OTP verification failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <div className="card">

        {/* LEFT SIDE */}
        <div className="left">
          <h1>Verification</h1>
          <p style={{ marginTop: "20px" }}>
            Enter the 4-digit code sent to <strong>{email}</strong>.
          </p>

          <p style={{ marginTop: "60px" }}>
            Didn’t receive a code?{" "}
            <span style={{ color: "#fff", cursor: "pointer" }}>
              Resend
            </span>
          </p>
        </div>

        {/* RIGHT SIDE */}
        <div
          className="right"
          style={{
            display: "flex",
            flexDirection: "column",
            justifyContent: "center",
          }}
        >

          {/* OTP BOXES */}
          <div
            style={{
              display: "flex",
              gap: "20px",
              justifyContent: "center",
              marginBottom: "20px",
            }}
          >
            {otp.map((digit, index) => (
              <input
                key={index}
                type="text"
                maxLength="1"
                value={digit}
                ref={(el) => (inputs.current[index] = el)}
                onChange={(e) => handleChange(e.target.value, index)}
                style={{
                  width: "60px",
                  height: "60px",
                  textAlign: "center",
                  fontSize: "24px",
                  borderRadius: "10px",
                  border: "1px solid #ccc",
                }}
              />
            ))}
          </div>

          {/* ERROR / SUCCESS */}
          {error && <p className="error-text">{error}</p>}
          {success && <p className="success-text">{success}</p>}

          {/* CONFIRM BUTTON */}
          <button className="login-btn" onClick={handleConfirm} disabled={loading}>
            {loading ? "Verifying..." : "Confirm"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default Verification;