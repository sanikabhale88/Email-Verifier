import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./ForgotPassword.css";
import { FcGoogle } from "react-icons/fc";
import { FaEnvelope } from "react-icons/fa";

// Backend API base URL
const API_BASE_URL = "http://localhost:5000/api";

export default function ForgotPassword() {
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [otpDigits, setOtpDigits] = useState(["", "", "", ""]);
  const [step, setStep] = useState("request"); // request = send OTP, verify = enter OTP
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // SEND OTP FUNCTION
  const handleSendOtp = async () => {
    setError("");
    setSuccess("");

    if (!email) {
      setError("Please enter your email.");
      return;
    }

    try {
      setLoading(true);

      const res = await fetch(`${API_BASE_URL}/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      const data = await res.json();

      if (!data.success) throw new Error(data.message);

      setSuccess("OTP sent to your email.");
      setStep("verify");

    } catch (err) {
      setError(err.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  };

  // VERIFY OTP FUNCTION
  const handleVerifyOtp = async () => {
    setError("");
    setSuccess("");

    const otp = otpDigits.join("");

    if (otp.length !== 4) {
      setError("Please enter the 4-digit OTP.");
      return;
    }

    try {
      setLoading(true);

      const res = await fetch(`${API_BASE_URL}/auth/verify-forgot-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, otp }),
      });

      const data = await res.json();

      if (!data.success) throw new Error(data.message);

      setSuccess("OTP verified!");

      // Redirect to Reset Password page
      setTimeout(() => {
        navigate("/reset-password", { state: { email } });
      }, 1000);

    } catch (err) {
      setError(err.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  };

  // HANDLE OTP DIGIT CHANGE
  const handleChangeOtpDigit = (index, value) => {
    if (value.length > 1) return;

    const updated = [...otpDigits];
    updated[index] = value.replace(/\D/g, "");
    setOtpDigits(updated);
  };

  return (
    <div className="fp-container">
      <div className="fp-card">

        {/* LEFT SIDE */}
        <div className="fp-left">
          <h1>Hello,Welcome Back</h1>
          <h2>E-fy</h2>
          <p>Already have an Account?</p>

          <button
            className="login-btn-outline"
            onClick={() => navigate("/login")}
          >
            Login
          </button>

          <div className="envelope-shape"></div>
        </div>

        {/* RIGHT SIDE */}
        <div className="fp-right">

          <h2>Forgot Password</h2>

          <button className="google-btn">
            <FcGoogle /> Sign in With Google
          </button>

          {/* EMAIL INPUT */}
          <div className="input-box">
            <FaEnvelope />
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          {/* OTP TEXT + RESEND */}
          <div className="otp-row">
            <span>Enter OTP.</span>
            <span className="resend" onClick={handleSendOtp}>
              {loading && step === "request" ? "Sending..." : "Resend OTP"}
            </span>
          </div>

          {/* OTP INPUT BOXES */}
          <div className="otp-boxes">
            {otpDigits.map((digit, idx) => (
              <input
                key={idx}
                maxLength="1"
                value={digit}
                onChange={(e) => handleChangeOtpDigit(idx, e.target.value)}
              />
            ))}
          </div>

          {error && <p className="error-text">{error}</p>}
          {success && <p className="success-text">{success}</p>}

          {/* ACTION BUTTON */}
          <button
            className="main-btn"
            onClick={step === "request" ? handleSendOtp : handleVerifyOtp}
            disabled={loading}
          >
            {step === "request"
              ? loading
                ? "Sending..."
                : "Send OTP"
              : loading
              ? "Verifying..."
              : "Verify OTP"}
          </button>

        </div>
      </div>
    </div>
  );
}