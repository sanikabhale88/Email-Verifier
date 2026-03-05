import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./Login.css";
import { FcGoogle } from "react-icons/fc";
import { FaEnvelope, FaLock, FaUser } from "react-icons/fa";

// Backend API base URL
const API_BASE_URL = "http://localhost:5000/api";

function CreateAccount() {
  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();

    setError("");
    setSuccess("");

    if (!name || !email || !password) {
      setError("Please fill all fields.");
      return;
    }

    try {
      setLoading(true);

      const res = await fetch(`${API_BASE_URL}/auth/register-request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ name, email, password }),
      });

      const data = await res.json();

      if (!data.success) {
        throw new Error(data.message || "Registration failed");
      }

      setSuccess("OTP sent to your email. Redirecting...");

      // Redirect to OTP verification page with user data
      setTimeout(() => {
        navigate("/verify-otp", {
          state: { name, email, password },
        });
      }, 1500);

    } catch (err) {
      setError(err.message || "Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <div className="card">

        {/* LEFT SIDE */}
        <div className="left">
          <h1>Hello, Welcome to</h1>
          <h2>E-fy</h2>
          <p>Already have an Account?</p>
          <button
            className="create-btn"
            onClick={() => navigate("/login")}
          >
            Login
          </button>
          <p className="option">Other Option</p>
        </div>

        {/* RIGHT SIDE */}
        <div className="right">
          <h2>Create Account</h2>

          <button className="google-btn">
            <FcGoogle /> Sign in With Google
          </button>

          <form onSubmit={handleSubmit}>

            <div className="input-box">
              <FaUser />
              <input
                type="text"
                placeholder="Name"
                onChange={(e) => setName(e.target.value)}
              />
            </div>

            <div className="input-box">
              <FaEnvelope />
              <input
                type="email"
                placeholder="Email"
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>

            <div className="input-box">
              <FaLock />
              <input
                type="password"
                placeholder="Password"
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            {error && <p className="error-text">{error}</p>}
            {success && <p className="success-text">{success}</p>}

            <button className="login-btn" disabled={loading}>
              {loading ? "Sending OTP..." : "Sign Up"}
            </button>

          </form>
        </div>

      </div>
    </div>
  );
}

export default CreateAccount;