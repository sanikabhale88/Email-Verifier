import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./Login.css";
import { FcGoogle } from "react-icons/fc";
import { FaEnvelope, FaLock } from "react-icons/fa";

const API_BASE_URL = "http://localhost:5000/api";

function Login() {
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [keepLoggedIn, setKeepLoggedIn] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();

    setError("");

    if (!email || !password) {
      setError("Please enter email and password.");
      return;
    }

    try {
      setLoading(true);

      const res = await fetch(`${API_BASE_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (!data.success) {
        throw new Error(data.message || "Login failed");
      }

      // Save JWT
      if (data.token) {
        if (keepLoggedIn) {
          localStorage.setItem("efy_token", data.token); // Stay logged in
        } else {
          sessionStorage.setItem("efy_token", data.token); // Clear on tab close
        }
      }

      // Save user info
      if (data.user) {
        localStorage.setItem("efy_user", JSON.stringify(data.user));
      }

      navigate("/dashboard?welcome=true");

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
          <h1>Hello, Welcome Back</h1>
          <h2>E-fy</h2>
          <p>Don’t have an Account?</p>

          <button className="create-btn" onClick={() => navigate("/signup")}>
            Create Account
          </button>

          <p className="option">Other Option</p>
        </div>

        {/* RIGHT SIDE */}
        <div className="right">
          <h2>Login</h2>

          <button className="google-btn">
            <FcGoogle /> Sign in With Google
          </button>

          <form onSubmit={handleSubmit}>
            
            {/* Email */}
            <div className="input-box">
              <FaEnvelope />
              <input
                type="email"
                placeholder="Email"
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>

            {/* Password */}
            <div className="input-box">
              <FaLock />
              <input
                type="password"
                placeholder="Password"
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            {error && <p className="error-text">{error}</p>}

            <button className="login-btn" disabled={loading}>
              {loading ? "Logging in..." : "Login"}
            </button>

            {/* KEEP LOGIN + FORGOT PASSWORD */}
            <div className="login-bottom-row">
              <label className="keep-login">
                <input
                  type="checkbox"
                  checked={keepLoggedIn}
                  onChange={(e) => setKeepLoggedIn(e.target.checked)}
                />
                Keep Log In
              </label>

              <span
                className="forgot-password-link"
                onClick={() => navigate("/forgot-password")}
              >
                Forgot Password?
              </span>
            </div>

          </form>
        </div>
      </div>
    </div>
  );
}

export default Login;