import React, { useState } from "react";
import "./FindEmail.css";
import { FaSearch, FaEnvelope, FaUndo } from "react-icons/fa";

export default function FindEmail() {
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [companyDomain, setCompanyDomain] = useState("");

  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleFindEmail = async () => {
    if (!firstName || !lastName || !companyDomain) {
      setError("Please fill all fields");
      return;
    }

    setError("");
    setLoading(true);

    try {
      const token = localStorage.getItem("efy_token");

      const res = await fetch("http://localhost:5000/api/find-email", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          firstName,
          lastName,
          domain: companyDomain,
        }),
      });

      const data = await res.json();

      if (!data.success) throw new Error(data.message);

      setResult(data);
    } catch (err) {
      setError(err.message || "Something went wrong");
    }

    setLoading(false);
  };

  return (
    <div className="fe-container">
      {/* SIDEBAR */}
      <div className="fe-sidebar">
        <div className="fe-logo">E-fy ✉️</div>

        <button className="fe-menu-btn active">
          <FaSearch /> Find Email
        </button>

        <button className="fe-menu-btn">
          <FaEnvelope /> Email Verification
        </button>

        <button className="fe-menu-btn">
          <FaUndo /> Credit Balance
        </button>

        <div className="fe-credits-box">
          <div className="fe-credit-label">Credits</div>
          <div className="fe-credit-value">100</div>
        </div>

        <button className="fe-buy-btn">₹ Buy Credits</button>
      </div>

      {/* MAIN SECTION */}
      <div className="fe-main">
        {/* Top profile */}
        <div className="fe-profile">
          <img src="https://i.pravatar.cc/40" alt="profile" className="fe-avatar" />
          <span className="fe-username">Shravani Achari</span>
          <span className="fe-dropdown">▼</span>
        </div>

        <h1 className="fe-title">Find Email</h1>

        {/* INPUT ROW */}
        <div className="fe-input-row">
          <input
            type="text"
            placeholder="Kamlesh"
            className="fe-input"
            onChange={(e) => setFirstName(e.target.value)}
          />

          <input
            type="text"
            placeholder="Surana"
            className="fe-input"
            onChange={(e) => setLastName(e.target.value)}
          />

          <input
            type="text"
            placeholder="Enter Company Domain"
            className="fe-input"
            onChange={(e) => setCompanyDomain(e.target.value)}
          />

          <button className="fe-find-btn" onClick={handleFindEmail}>
            {loading ? "Finding..." : "Find Email"}
          </button>
        </div>

        {/* ERROR */}
        {error && <p className="fe-error">{error}</p>}

        {/* RESULT SECTION */}
        {result && (
          <div className="fe-result-box">
            <h2>Best Match</h2>
            <p className="fe-best-email">
              {result.bestEmail.email} ({result.bestEmail.status})
            </p>

            <h3>All Tried Patterns:</h3>
            <div className="fe-all-patterns">
              {result.allResults.map((r, i) => (
                <p key={i}>
                  {r.email} — <b>{r.status}</b>
                </p>
              ))}
            </div>

            <h3>Credits Left: {result.creditsLeft}</h3>
          </div>
        )}

        {/* Floating Help Button */}
        <button className="fe-help-btn">🛈</button>
      </div>
    </div>
  );
}