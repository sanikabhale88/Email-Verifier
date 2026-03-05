import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import "./WelcomeModal.css";

function WelcomeModal({ name }) {
  const [visible, setVisible] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    setTimeout(() => setVisible(true), 10);
  }, []);

  const handleClose = () => {
    setVisible(false);

    setTimeout(() => {
      navigate("/dashboard");  // ⭐ Go to dashboard
    }, 300); // match fade-out duration
  };

  return (
    <div className={`modal-overlay ${visible ? "show" : ""}`} onClick={handleClose}>
      <div
        className={`modal-card ${visible ? "show" : ""}`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-gift">
          🎁
          <div className="sparkle s1">·</div>
          <div className="sparkle s2">·</div>
          <div className="sparkle s3">·</div>
        </div>

        <div className="modal-line"></div>

        <h2 className="modal-welcome">Welcome, {name}</h2>

        <div className="modal-credits">
          <span className="credits-get">Get </span>
          <span className="credits-number">100</span>
          <span className="credits-free">Free</span>
          <span className="credits-label"> Credits</span>
        </div>

        <p className="modal-subtitle">and Start Verifying Emails Right Now</p>

        <button className="modal-btn" onClick={handleClose}>
          Get Started
        </button>
      </div>
    </div>
  );
}

export default WelcomeModal;