import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./ChangePassword.css";
import { FaLock } from "react-icons/fa";
import { FcGoogle } from "react-icons/fc";

const API_BASE_URL = "http://localhost:5000/api";

export default function ChangePassword() {
  const navigate = useNavigate();

  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // token from login
  const token = localStorage.getItem("efy_token");

  const handleChangePassword = async () => {
    setError("");
    setSuccess("");

    if (!oldPassword || !newPassword || !confirmPassword) {
      setError("Please fill all fields.");
      return;
    }

    if (newPassword !== confirmPassword) {
      setError("New passwords do not match.");
      return;
    }

    try {
      setLoading(true);

      const res = await fetch(`${API_BASE_URL}/auth/change-password`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ oldPassword, newPassword }),
      });

      const data = await res.json();

      if (!data.success) throw new Error(data.message);

      setSuccess("Password changed successfully!");

      setTimeout(() => {
        navigate("/dashboard");
      }, 1500);

    } catch (err) {
      setError(err.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="cp-container">
      <div className="cp-card">

        <h2>Change Password</h2>

        <div className="input-box">
          <FaLock />
          <input
            type="password"
            placeholder="Old Password"
            onChange={(e) => setOldPassword(e.target.value)}
          />
        </div>

        <div className="input-box">
          <FaLock />
          <input
            type="password"
            placeholder="New Password"
            onChange={(e) => setNewPassword(e.target.value)}
          />
        </div>

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

        <button className="main-btn" onClick={handleChangePassword}>
          {loading ? "Updating..." : "Confirm"}
        </button>

        <button className="google-btn">
          <FcGoogle /> Sign in With Google
        </button>

      </div>
    </div>
  );
}