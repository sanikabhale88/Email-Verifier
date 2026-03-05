import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
// import "./ResetPassword.css";
import { FcGoogle } from "react-icons/fc";
import { FaLock } from "react-icons/fa";

const API_BASE_URL = "http://localhost:5000/api";

export default function ResetPassword() {
  const navigate = useNavigate();
  const location = useLocation();

  // Email passed from ForgotPassword page
  const email = location.state?.email;

  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleReset = async () => {
    setError("");
    setSuccess("");

    if (!newPassword || !confirmPassword) {
      setError("Please fill all fields.");
      return;
    }

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    try {
      setLoading(true);

      const res = await fetch(`${API_BASE_URL}/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password: newPassword }),
      });

      const data = await res.json();

      if (!data.success) throw new Error(data.message);

      setSuccess("Password changed successfully!");

      setTimeout(() => {
        navigate("/login");
      }, 1500);

    } catch (err) {
      setError(err.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fp-container">
      <div className="fp-card">

        {/* LEFT SIDE */}
        <div className="fp-left">
          <h1>Hello,Welcome to</h1>
          <h2>E-fy</h2>
          <p>Don’t have an Account?</p>

          <button
            className="login-btn-outline"
            onClick={() => navigate("/signup")}
          >
            Create Account
          </button>

          <div className="envelope-shape"></div>
        </div>

        {/* RIGHT SIDE */}
        <div className="fp-right">

          <h2>Reset Password</h2>

          <button className="google-btn">
            <FcGoogle /> Sign in With Google
          </button>

          {/* NEW Password */}
          <div className="input-box">
            <FaLock />
            <input
              type="password"
              placeholder="New Password"
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </div>

          {/* CONFIRM Password */}
          <div className="input-box">
            <FaLock />
            <input
              type="password"
              placeholder="Confirm Password"
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>

          {error && <p className="error-text">{error}</p>}
          {success && <p className="success-text">{success}</p>}

          <button className="main-btn" onClick={handleReset} disabled={loading}>
            {loading ? "Updating..." : "Login"}
          </button>

        </div>
      </div>
    </div>
  );
}