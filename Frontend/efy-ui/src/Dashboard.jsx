import React, { useState, useRef } from "react";
import WelcomeModal from "./WelcomeModal";
import Creditbalancepage from "./Creditbalancepage";
import CreditBillingPage from "./CreditBillingPage";
import "./Dashboard.css";
import {
  FaSearch, FaEnvelope, FaCoins, FaSignOutAlt,
  FaUser, FaBell, FaFileAlt, FaCode, FaCloudUploadAlt,
  FaDownload, FaTrash, FaSync, FaExclamationTriangle, FaQuestion,
  FaPlug, FaChevronDown, FaChevronUp, FaCheckCircle, FaTimes, FaCloudDownloadAlt,
} from "react-icons/fa";
import { validateSingleEmail, validateMultipleEmails } from "./services/emailApi";

// ── Donut Chart Component ──
function DonutChart({ valid, invalid, catchAll, unknown, total }) {
  const size = 140;
  const cx = size / 2;
  const cy = size / 2;
  const r = 52;
  const stroke = 18;
  const circumference = 2 * Math.PI * r;

  const segments = [
    { value: valid,    color: "#4ade80", label: "Valid"     },
    { value: invalid,  color: "#f87171", label: "Invalid"   },
    { value: catchAll, color: "#fbbf24", label: "Catch-all" },
    { value: unknown,  color: "#cbd5e1", label: "Unknown"   },
  ];

  let offset = 0;
  const arcs = segments.map((seg) => {
    const pct  = total > 0 ? seg.value / total : 0;
    const dash = pct * circumference;
    const gap  = circumference - dash;
    const arc  = { ...seg, dash, gap, offset };
    offset += dash;
    return arc;
  });

  const validPct = total > 0 ? Math.round((valid / total) * 100) : 0;

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#f1f5f9" strokeWidth={stroke} />
      {arcs.map((arc, i) => (
        <circle
          key={i}
          cx={cx} cy={cy} r={r}
          fill="none"
          stroke={arc.color}
          strokeWidth={stroke}
          strokeDasharray={`${arc.dash} ${arc.gap}`}
          strokeDashoffset={-arc.offset}
          style={{ transform: "rotate(-90deg)", transformOrigin: "center", transition: "stroke-dasharray 0.8s ease" }}
        />
      ))}
      <text x={cx} y={cy - 6} textAnchor="middle" fontSize="20" fontWeight="700" fill="#1e293b">{validPct}%</text>
      <text x={cx} y={cy + 12} textAnchor="middle" fontSize="9" fill="#94a3b8">Valid</text>
    </svg>
  );
}

// ── Progress Bar ──
function ProgressBar({ progress }) {
  return (
    <div className="progress-bar-wrap">
      <div className="progress-bar-track">
        <div className="progress-bar-fill" style={{ width: `${progress}%` }}></div>
      </div>
      {progress < 100 && <span className="progress-label">{progress}%</span>}
    </div>
  );
}

// ── Determine result type ──
function getResultType(result) {
  if (!result) return null;
  if (!result.syntaxValid) return "unknown";
  if (!result.mxValid)     return "unknown";
  if (result.catchAll)     return "catchall";
  if (result.deliverable)  return "valid";
  return "invalid";
}

// ── Single Result Card ──
function ResultCard({ result }) {
  const type = getResultType(result);
  const verificationTime = result.verificationTime || null;

  const typeConfig = {
    valid: {
      headerClass: "valid-bg",
      iconClass: "valid-icon",
      iconEl: <span>✓</span>,
      title: "Valid Email",
      scoreColor: "#1a3c34",
      titleColor: "#1a3c34",
      recommendationBorderColor: "#2d6a4f",
      recommendationTitleColor: "#2d6a4f",
      recommendationText: (
        <>This email is <strong style={{ color: "#2d6a4f" }}>SAFE TO USE</strong>. It's verified and deliverable.</>
      ),
    },
    invalid: {
      headerClass: "invalid-bg",
      iconClass: "invalid-icon",
      iconEl: <span>✗</span>,
      title: "Invalid Email",
      scoreColor: "#7f1d1d",
      titleColor: "#7f1d1d",
      recommendationBorderColor: "#c0392b",
      recommendationTitleColor: "#c0392b",
      recommendationText: (
        <>This email <strong style={{ color: "#c0392b" }}>SHOULD NOT BE USED.</strong> It's invalid or doesn't exist.</>
      ),
    },
    catchall: {
      headerClass: "catchall-bg",
      iconClass: "catchall-icon",
      iconEl: <FaExclamationTriangle />,
      title: "Catch-All Domain",
      scoreColor: "#92400e",
      titleColor: "#92400e",
      recommendationBorderColor: "#d97706",
      recommendationTitleColor: "#d97706",
      recommendationText: (
        <>This domain accepts <strong style={{ color: "#d97706" }}>ALL EMAILS</strong>. The address may or may not exist — use with caution.</>
      ),
    },
    unknown: {
      headerClass: "unknown-bg",
      iconClass: "unknown-icon",
      iconEl: <FaQuestion />,
      title: "Unknown Email",
      scoreColor: "#475569",
      titleColor: "#475569",
      recommendationBorderColor: "#94a3b8",
      recommendationTitleColor: "#64748b",
      recommendationText: (
        <>This email <strong style={{ color: "#64748b" }}>COULD NOT BE VERIFIED.</strong> The domain or MX records are unreachable. Avoid using it.</>
      ),
    },
  };

  const cfg = typeConfig[type] || typeConfig.valid;

  return (
    <div className="result-card-new">
      {/* TOP */}
      <div className={`result-top ${cfg.headerClass}`}>
        <div className="result-top-left">
          <div className={`result-icon ${cfg.iconClass}`}>{cfg.iconEl}</div>
          <div>
            <h2 className="result-title" style={{ color: cfg.titleColor }}>{cfg.title}</h2>
            <p className="result-email">{result.email}</p>
          </div>
        </div>
        <div className="result-top-right">
          <span className="result-score" style={{ color: cfg.scoreColor }}>{result.score}%</span>
          <p className="result-score-label" style={{ color: cfg.scoreColor }}>Quality Score</p>
        </div>
      </div>

      {/* MIDDLE */}
      <div className="result-middle">
        <div className="result-section">
          <p className="result-section-title">VERIFICATION DETAILS</p>
          <div className="result-row">
            <span className="result-key">Domain</span>
            <span className="result-value">{result.email.split("@")[1]}</span>
          </div>
          <div className="result-row">
            <span className="result-key">MX Records Found</span>
            <span className={`result-check ${result.mxValid ? "check-yes" : "check-no"}`}>
              {result.mxValid ? "✓ Yes" : "✗ Failed"}
            </span>
          </div>
          <div className="result-row">
            <span className="result-key">SMTP Check</span>
            <span className={`result-check ${result.smtp?.success ? "check-yes" : "check-no"}`}>
              {result.smtp?.success ? "✓ Yes" : "✗ Failed"}
            </span>
          </div>
        </div>
        <div className="result-divider"></div>
        <div className="result-section">
          <p className="result-section-title">ADDITIONAL INFO</p>
          <div className="result-row">
            <span className="result-key">Disposable Email</span>
            <span className={`result-check ${!result.disposable ? "check-yes" : "check-no"}`}>
              {result.disposable ? "✗ Yes" : "✓ No"}
            </span>
          </div>
          <div className="result-row">
            <span className="result-key">Free Provider</span>
            <span className={`result-check ${!result.freeEmail ? "check-yes" : "check-no"}`}>
              {result.freeEmail ? "✗ Yes" : "✓ No"}
            </span>
          </div>
          <div className="result-row">
            <span className="result-key">Verification Time</span>
            <span className="result-value">
              {verificationTime ? `${verificationTime}s` : (result.catchAll ? "1.0s" : "1.3s")}
            </span>
          </div>
        </div>
      </div>

      {/* BOTTOM */}
      <div className="result-bottom" style={{ borderTop: `2px solid ${cfg.recommendationBorderColor}20` }}>
        <h3 className="recommendation-title" style={{ color: cfg.recommendationTitleColor }}>
          Recommendation
        </h3>
        <p className="recommendation-text">{cfg.recommendationText}</p>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════
// MAIN DASHBOARD
// ══════════════════════════════════════════
function Dashboard() {
  const [activeMenu, setActiveMenu] = useState("verification");
  const [activeTab,  setActiveTab]  = useState("single");

  // Single email
  const [emailInput, setEmailInput] = useState("");
  const [result,     setResult]     = useState(null);
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState("");

  // Bulk email
  const [listInput,    setListInput]    = useState("");
  const [bulkLoading,  setBulkLoading]  = useState(false);
  const [bulkProgress, setBulkProgress] = useState(0);
  const [bulkDone,     setBulkDone]     = useState(false);
  const [bulkResults,  setBulkResults]  = useState(null);
  const [bulkError,    setBulkError]    = useState("");
  const [listDate,     setListDate]     = useState("");

  // Credits — synced with MongoDB; starts at 100 until backend wired
  const [credits, setCredits] = useState(100);

  // Welcome modal
  const [showModal, setShowModal] = useState(false);
  
  // Credit Billing Page visibility
  const [showBillingPage, setShowBillingPage] = useState(false);

  // ── Single Verify ──
  const handleVerify = async () => {
    if (!emailInput.trim()) return setError("Please enter an email");
    setLoading(true); setError(""); setResult(null);
    try {
      const data = await validateSingleEmail(emailInput.trim());
      setResult(data);
      setCredits(prev => Math.max(0, prev - 1));
    } catch {
      setError("Cannot connect to server. Make sure backend is running.");
    }
    setLoading(false);
  };

  // ── Bulk Verify ──
  const handleBulkVerify = async () => {
    const emails = listInput
      .split(/[\n,]+/)
      .map(e => e.trim())
      .filter(Boolean);

    if (!emails.length) return setBulkError("Please enter at least one email");

    setBulkLoading(true); setBulkError(""); setBulkDone(false);
    setBulkResults(null); setBulkProgress(0);

    const interval = setInterval(() => {
      setBulkProgress(prev => prev < 85 ? prev + 5 : prev);
    }, 300);

    try {
      const data    = await validateMultipleEmails(emails);
      clearInterval(interval);
      setBulkProgress(100);

      const results  = data.results || [];
      const valid    = results.filter(r => r.deliverable).length;
      const catchAll = results.filter(r => r.catchAll).length;
      const unknown  = results.filter(r => !r.syntaxValid || !r.mxValid).length;
      const invalid  = results.filter(r => r.syntaxValid && r.mxValid && !r.catchAll && !r.deliverable).length;

      setBulkResults({ results, valid, invalid, catchAll, unknown, total: results.length });
      setBulkDone(true);
      setCredits(prev => Math.max(0, prev - results.length));

      const now = new Date();
      setListDate(
        `${now.getDate().toString().padStart(2,"0")}-${(now.getMonth()+1).toString().padStart(2,"0")}-${now.getFullYear()}`
      );
    } catch {
      clearInterval(interval);
      setBulkError("Cannot connect to server.");
    }
    setBulkLoading(false);
  };

  // ── Download CSV ──
  const handleDownload = () => {
    if (!bulkResults) return;
    const headers = "Email,Deliverable,Score,MX,SMTP,Disposable,FreeEmail,CatchAll,Type\n";
    const rows = bulkResults.results.map(r => {
      const type = getResultType(r);
      return `${r.email},${r.deliverable},${r.score},${r.mxValid},${r.smtp?.success},${r.disposable},${r.freeEmail},${r.catchAll},${type}`;
    }).join("\n");
    const blob = new Blob([headers + rows], { type: "text/csv" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = "email-results.csv"; a.click();
    URL.revokeObjectURL(url);
  };

  const handleReset = () => {
    setBulkResults(null); setBulkDone(false);
    setBulkProgress(0); setListInput(""); setBulkError("");
  };

  const getScoreColor = (score) => {
    if (score >= 70) return "#22c55e";
    if (score >= 40) return "#f59e0b";
    return "#ef4444";
  };
  
  // Handle buying credits from the billing page
  const handleBuyCredits = (amount) => {
    console.log(`Buying ${amount} credits`);
    // Here you would typically add credits to the user's account
    // For now, we'll just add 100 credits as an example
    setCredits(prev => prev + 100);
    setShowBillingPage(false);
  };

  return (
    <div className="dashboard">
      <div className="dashboard-bg">
        <div className="bg-orb orb1"></div>
        <div className="bg-orb orb2"></div>
        <div className="bg-orb orb3"></div>
        <div className="bg-orb orb4"></div>
        <div className="bg-wave"></div>
      </div>

      {/* Show Credit Billing Page when active */}
      {showBillingPage ? (
        <CreditBillingPage 
          credits={credits}
          userName="Kamlesh Surana"
          userEmail="kamlesh@sphurti.net"
          onClose={() => setShowBillingPage(false)}
          onBuyCredits={handleBuyCredits}
        />
      ) : (
        /* ══ SIDEBAR ══ */
        <div className="sidebar">
          <div className="logo-container">
            <h2 className="logo">E-fy</h2>
          </div>
          <div className="user-profile">
            <div className="avatar"><FaUser /></div>
            <div className="user-info"><h4>Kamlesh Surana</h4></div>
          </div>

          <div className="menu">
            <div
              className={`menu-item ${activeMenu === "find" ? "active" : ""}`}
              onClick={() => setActiveMenu("find")}
            >
              <FaSearch className="menu-icon" /><span>Find Email</span>
            </div>
            <div
              className={`menu-item ${activeMenu === "verification" ? "active" : ""}`}
              onClick={() => setActiveMenu("verification")}
            >
              <FaEnvelope className="menu-icon" /><span>Email Verification</span>
            </div>
            <div
              className={`menu-item ${activeMenu === "credits" ? "active" : ""}`}
              onClick={() => setActiveMenu("credits")}
            >
              <FaCoins className="menu-icon" /><span>Credit Balance</span>
            </div>
          </div>

          {/* Hide credits box when on Credit Balance page — matches screenshot */}
          {activeMenu !== "credits" && (
            <div className="credit-section">
              <div className="credit-box">
                <div className="credit-header">
                  <FaCoins className="credit-icon" /><span>Credits</span>
                </div>
                <div className="credit-amount">
                  <span className="amount">{credits}</span>
                </div>
                <button className="buy-credits-btn" onClick={() => setShowBillingPage(true)}>
                  ₹ Buy Credits
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Only show the main content if not showing billing page */}
      {!showBillingPage && (
        /* ══ MAIN ══ */
        <div className="main">

          {/* ── Header ── */}
          <div className={`header ${activeMenu === "credits" ? "header-credits" : ""}`}>
            <div className="header-left">
              {activeMenu !== "credits" && <h2>Welcome back, Kamlesh!</h2>}
            </div>
            <div className="header-right">
              {activeMenu !== "credits" && (
                <div className="notification-badge">
                  <FaBell /><span className="badge">3</span>
                </div>
              )}
              {activeMenu === "credits" ? (
                <div className="cb-header-user">
                  <div className="cb-header-avatar"><FaUser /></div>
                  <span className="cb-header-name">Kamlesh Surana</span>
                  <FaChevronDown style={{ color: "white", fontSize: 12 }} />
                </div>
              ) : (
                <button className="logout-btn"><FaSignOutAlt /> Logout</button>
              )}
            </div>
          </div>

          {/* ── CREDIT BALANCE PAGE (separate component) ── */}
          {activeMenu === "credits" && (
            <Creditbalancepage
              credits={credits}
              userName="Kamlesh Surana"
              userEmail="kamlesh@sphurti.net"
              onBuyCredits={() => setShowBillingPage(true)}
            />
          )}

          {/* ── EMAIL VERIFICATION / FIND EMAIL ── */}
          {activeMenu !== "credits" && (
            <div className="content-card">
              {/* TABS */}
              <div className="tabs-container">
                <button className={`tab ${activeTab === "single" ? "active" : ""}`} onClick={() => setActiveTab("single")}>
                  <FaEnvelope /> Single Email
                </button>
                <button className={`tab ${activeTab === "list" ? "active" : ""}`} onClick={() => setActiveTab("list")}>
                  <FaFileAlt /> Paste Email List
                </button>
                <button className={`tab ${activeTab === "file" ? "active" : ""}`} onClick={() => setActiveTab("file")}>
                  <FaCloudUploadAlt /> File Upload
                </button>
                <button className={`tab ${activeTab === "integration" ? "active" : ""}`} onClick={() => setActiveTab("integration")}>
                  <FaPlug /> Integration
                </button>
                <button className={`tab ${activeTab === "api" ? "active" : ""}`} onClick={() => setActiveTab("api")}>
                  <FaCode /> API
                </button>
              </div>

              <div className="content-area">
                {/* SINGLE EMAIL TAB */}
                {activeTab === "single" && (
                  <div className="verification-content">
                    <h3>Add Email</h3>
                    <div className="input-container">
                      <input
                        type="email"
                        className="email-input"
                        placeholder="Enter email to verify..."
                        value={emailInput}
                        onChange={(e) => setEmailInput(e.target.value)}
                        onKeyDown={(e) => e.key === "Enter" && handleVerify()}
                      />
                      <button className="verify-btn" onClick={handleVerify} disabled={loading}>
                        {loading ? "Checking..." : "Verify"}
                      </button>
                    </div>
                    {error && <p style={{ color: "#ef4444", marginTop: 12, fontSize: 14 }}>❌ {error}</p>}
                    {result && <ResultCard result={result} />}
                  </div>
                )}

                {/* PASTE LIST TAB */}
                {activeTab === "list" && (
                  <div className="bulk-tab">
                    {!bulkDone && (
                      <>
                        {bulkLoading && (
                          <div className="bulk-validating">
                            <h3>Validation Status</h3>
                            <button className="refresh-btn" onClick={handleReset}><FaSync /></button>
                            <ProgressBar progress={bulkProgress} />
                            <p className="validating-text">Verifying emails, please wait...</p>
                          </div>
                        )}
                        {!bulkLoading && (
                          <div className="bulk-input-area">
                            <h3>Enter Your Email List</h3>
                            <textarea
                              className="bulk-textarea"
                              placeholder="Ex. sadfhjk34@gmail.com, bhdbfcl80@gmail.com,..."
                              value={listInput}
                              onChange={(e) => setListInput(e.target.value)}
                              rows="6"
                            />
                            {bulkError && (
                              <p style={{ color: "#ef4444", fontSize: 14, marginBottom: 10 }}>❌ {bulkError}</p>
                            )}
                            <div style={{ textAlign: "center" }}>
                              <button className="start-verify-btn" onClick={handleBulkVerify}>
                                Start Verification
                              </button>
                            </div>
                          </div>
                        )}
                      </>
                    )}

                    {bulkDone && bulkResults && (
                      <div className="bulk-results-area">
                        <div className="bulk-results-header">
                          <h3>Validation Status</h3>
                          <button className="refresh-btn" onClick={handleReset} title="Start new list">
                            <FaSync />
                          </button>
                        </div>

                        <ProgressBar progress={100} />

                        <div className="bulk-summary-card">
                          <div className="summary-left">
                            <h4 className="list-title">Untitled List: {listDate}</h4>
                            <div className="summary-email-count">
                              <FaEnvelope className="summary-icon" />
                              <div>
                                <span className="count-number">{bulkResults.total}</span>
                                <span className="count-label">Emails</span>
                              </div>
                            </div>
                          </div>

                          <div className="summary-chart">
                            <DonutChart
                              valid={bulkResults.valid}    invalid={bulkResults.invalid}
                              catchAll={bulkResults.catchAll} unknown={bulkResults.unknown}
                              total={bulkResults.total}
                            />
                          </div>

                          <div className="summary-legend">
                            {[
                              { label: "Valid Emails",     count: bulkResults.valid,    color: "#4ade80" },
                              { label: "Invalid Emails",   count: bulkResults.invalid,  color: "#f87171" },
                              { label: "Catch-all Emails", count: bulkResults.catchAll, color: "#fbbf24" },
                              { label: "Unknown Emails",   count: bulkResults.unknown,  color: "#cbd5e1" },
                            ].map((item, i) => (
                              <div key={i} className="legend-item">
                                <span className="legend-dot" style={{ background: item.color }}></span>
                                <span className="legend-label">{item.label}</span>
                                <span className="legend-count">{item.count}</span>
                                <span className="legend-pct">
                                  {Math.round((item.count / bulkResults.total) * 100)}%
                                </span>
                              </div>
                            ))}
                          </div>

                          <div className="summary-actions">
                            <button className="action-btn download-btn" onClick={handleDownload}>
                              <FaDownload /><span>Download List</span>
                            </button>
                            <button className="action-btn delete-btn" onClick={handleReset}>
                              <FaTrash /><span>Delete List</span>
                            </button>
                          </div>
                        </div>

                        <ViewList results={bulkResults.results} getScoreColor={getScoreColor} />
                      </div>
                    )}
                  </div>
                )}

                {/* FILE UPLOAD TAB */}
                {activeTab === "file" && (
                  <FileUploadTab
                    availableCredits={credits}
                    onDeductCredits={(n) => setCredits(prev => Math.max(0, prev - n))}
                  />
                )}

                {/* INTEGRATION TAB */}
                {activeTab === "integration" && <IntegrationTab />}

                {/* API TAB */}
                {activeTab === "api" && (
                  <div className="placeholder-content">
                    <FaCode className="placeholder-icon" />
                    <h3>API Access</h3>
                    <p>Get your API key for integration</p>
                    <button className="verify-btn">Generate API Key</button>
                  </div>
                )}
              </div>

              <div className="user-avatar"><FaUser /></div>
            </div>
          )}
        </div>
      )}

      {showModal && (
        <WelcomeModal name="Kamlesh" onClose={() => setShowModal(false)} />
      )}
    </div>
  );
}

// ══════════════════════════════════════════
// SMALL DONUT — for file result cards
// ══════════════════════════════════════════
function SmallDonut({ valid, invalid, catchAll, unknown, total }) {
  const size = 90, cx = size / 2, cy = size / 2, r = 32, stroke = 12;
  const circumference = 2 * Math.PI * r;

  let offset = 0;
  const arcs = [
    { value: valid,    color: "#4ade80" },
    { value: invalid,  color: "#f87171" },
    { value: catchAll, color: "#fbbf24" },
    { value: unknown,  color: "#cbd5e1" },
  ].map(seg => {
    const dash = total > 0 ? (seg.value / total) * circumference : 0;
    const gap  = circumference - dash;
    const arc  = { ...seg, dash, gap, offset };
    offset += dash;
    return arc;
  });

  const validPct = total > 0 ? Math.round((valid / total) * 100) : 0;

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#f1f5f9" strokeWidth={stroke} />
      {arcs.map((arc, i) => (
        <circle key={i} cx={cx} cy={cy} r={r} fill="none" stroke={arc.color}
          strokeWidth={stroke}
          strokeDasharray={`${arc.dash} ${arc.gap}`}
          strokeDashoffset={-arc.offset}
          style={{ transform: "rotate(-90deg)", transformOrigin: "center" }}
        />
      ))}
      <text x={cx} y={cy - 5} textAnchor="middle" fontSize="13" fontWeight="700" fill="#1e293b">
        {validPct}%
      </text>
    </svg>
  );
}

// ══════════════════════════════════════════
// FILE UPLOAD TAB
// Sends file to /validate/csv as FormData
// ══════════════════════════════════════════
function FileUploadTab({ availableCredits, onDeductCredits }) {
  const [dragOver,     setDragOver]     = useState(false);
  const [uploadedFile, setUploadedFile] = useState(null);
  const [emailCount,   setEmailCount]   = useState(0);
  const [showModal,    setShowModal]    = useState(false);
  const [removeDupes,  setRemoveDupes]  = useState(true);
  const [verifying,    setVerifying]    = useState(false);
  const [progress,     setProgress]     = useState(0);
  const [fileResults,  setFileResults]  = useState([]);
  const [apiError,     setApiError]     = useState("");
  const fileInputRef = useRef(null);

  const countEmailsInFile = (file) =>
    new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const emails = new Set();
        e.target.result.split(/\r?\n/).forEach(line => {
          line.split(',').forEach(cell => {
            const val = cell.trim().replace(/^["']|["']$/g, '');
            if (val.includes('@') && val.includes('.')) emails.add(val.toLowerCase());
          });
        });
        resolve(emails.size);
      };
      reader.readAsText(file);
    });

  const handleFile = async (file) => {
    if (!file) return;
    if (!file.name.endsWith('.csv')) {
      setApiError("Only CSV files are supported. Please upload a .csv file.");
      return;
    }
    setApiError("");
    setUploadedFile(file);
    const count = await countEmailsInFile(file);
    setEmailCount(count);
    setShowModal(true);
  };

  const handleDrop = (e) => {
    e.preventDefault(); setDragOver(false);
    handleFile(e.dataTransfer.files[0]);
  };

  const handleFileInput = (e) => {
    handleFile(e.target.files[0]);
    e.target.value = "";
  };

  const handleStartVerification = async () => {
    if (!uploadedFile) return;
    setShowModal(false); setVerifying(true); setProgress(0); setApiError("");

    const interval = setInterval(() => {
      setProgress(prev => (prev < 88 ? prev + 3 : prev));
    }, 400);

    try {
      const formData = new FormData();
      formData.append("file", uploadedFile);

      const response = await fetch("http://localhost:5000/validate/csv", {
        method: "POST", body: formData,
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `Server error: ${response.status}`);
      }

      const data    = await response.json();
      clearInterval(interval);
      setProgress(100);

      const results  = data.results || [];
      const valid    = results.filter(r => r.deliverable).length;
      const catchAll = results.filter(r => r.catchAll).length;
      const unknown  = results.filter(r => !r.syntaxValid || !r.mxValid).length;
      const invalid  = results.filter(r => r.syntaxValid && r.mxValid && !r.catchAll && !r.deliverable).length;

      const now      = new Date();
      const letters  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      const listName = `List ${letters[fileResults.length % 26]}`;
      const id       = Math.floor(1000 + Math.random() * 9000);

      setFileResults(prev => [...prev, {
        listName, id, fileName: uploadedFile.name,
        total: results.length, valid, invalid, catchAll, unknown, results,
        date: `${now.getDate().toString().padStart(2,"0")}-${(now.getMonth()+1).toString().padStart(2,"0")}-${now.getFullYear()}`,
      }]);

      if (onDeductCredits) onDeductCredits(results.length);

    } catch (err) {
      clearInterval(interval);
      setApiError(err.message || "Cannot connect to server. Make sure backend is running.");
      setVerifying(false); setProgress(0);
      return;
    }
    setVerifying(false); setUploadedFile(null); setEmailCount(0);
  };

  const handleDownloadList = (entry) => {
    const headers = "Email,Deliverable,Score,MX,SMTP,Disposable,FreeEmail,CatchAll,Type\n";
    const rows = entry.results.map(r =>
      `${r.email},${r.deliverable},${r.score},${r.mxValid},${r.smtp?.success},${r.disposable},${r.freeEmail},${r.catchAll},${getResultType(r)}`
    ).join("\n");
    const blob = new Blob([headers + rows], { type: "text/csv" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = `${entry.listName}-results.csv`; a.click();
    URL.revokeObjectURL(url);
  };

  const handleDeleteList = (id) => setFileResults(prev => prev.filter(e => e.id !== id));

  // ── Results / Progress view ──
  if (verifying || fileResults.length > 0) {
    return (
      <div className="file-results-page">
        <div className="file-results-header">
          <h3 className="file-results-title">Validation Status</h3>
          <button
            className="file-reset-btn"
            title="Upload new file"
            onClick={() => { setFileResults([]); setVerifying(false); setProgress(0); setApiError(""); }}
          >
            <FaSync />
          </button>
        </div>

        {verifying && (
          <div style={{ marginBottom: 20 }}>
            <div className="fu-progress-track">
              <div className="fu-progress-fill" style={{ width: `${progress}%` }}></div>
            </div>
            <p style={{ color: "#64748b", fontSize: 13, marginTop: 8, textAlign: "center" }}>
              Verifying emails from <strong>{uploadedFile?.name}</strong>, please wait...
            </p>
          </div>
        )}

        {apiError && (
          <p style={{ color: "#ef4444", fontSize: 14, marginBottom: 12, textAlign: "center" }}>
            ❌ {apiError}
          </p>
        )}

        <div className="file-result-list">
          {fileResults.map((entry) => (
            <div key={entry.id} className="file-result-card">
              <div className="frc-left">
                <div className="frc-list-name">{entry.listName}</div>
                <div className="frc-email-count">
                  <FaEnvelope className="frc-envelope" />
                  <div>
                    <span className="frc-count">{entry.total.toLocaleString()}</span>
                    <span className="frc-label">Emails</span>
                  </div>
                </div>
                <div className="frc-id">ID {entry.id}</div>
              </div>

              <div className="frc-chart">
                <SmallDonut
                  valid={entry.valid}   invalid={entry.invalid}
                  catchAll={entry.catchAll} unknown={entry.unknown}
                  total={entry.total}
                />
              </div>

              <div className="frc-legend">
                {[
                  { label: "Valid Emails",     count: entry.valid,    color: "#4ade80" },
                  { label: "Invalid Emails",   count: entry.invalid,  color: "#f87171" },
                  { label: "Catch-all Emails", count: entry.catchAll, color: "#fbbf24" },
                  { label: "Unknown Emails",   count: entry.unknown,  color: "#cbd5e1" },
                ].map((row, i) => (
                  <div key={i} className="frc-legend-row">
                    <span className="frc-dot" style={{ background: row.color }}></span>
                    <span className="frc-legend-label">{row.label}</span>
                    <span className="frc-legend-count">{row.count}</span>
                    <span className="frc-legend-pct">
                      {entry.total > 0 ? Math.round((row.count / entry.total) * 100) : 0}%
                    </span>
                  </div>
                ))}
              </div>

              <div className="frc-actions">
                <button className="frc-action-btn frc-download" onClick={() => handleDownloadList(entry)}>
                  <FaCloudDownloadAlt /><span>Download List</span>
                </button>
                <button className="frc-action-btn frc-delete" onClick={() => handleDeleteList(entry.id)}>
                  <FaTrash /><span>Delete List</span>
                </button>
              </div>
            </div>
          ))}
        </div>

        {!verifying && (
          <div style={{ textAlign: "center", marginTop: 16 }}>
            <button className="fu-add-more-btn" onClick={() => fileInputRef.current?.click()}>
              + Upload Another File
            </button>
            <input ref={fileInputRef} type="file" accept=".csv" style={{ display: "none" }} onChange={handleFileInput} />
          </div>
        )}

        {showModal && uploadedFile && (
          <VerifyModal
            file={uploadedFile} emailCount={emailCount}
            availableCredits={availableCredits}
            removeDupes={removeDupes} onToggleDupes={setRemoveDupes}
            onClose={() => { setShowModal(false); setUploadedFile(null); }}
            onStart={handleStartVerification}
          />
        )}
      </div>
    );
  }

  // ── Drop Zone ──
  return (
    <div className="file-upload-tab">
      <div
        className={`fu-dropzone ${dragOver ? "dragover" : ""}`}
        onDragOver={e => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
      >
        <input ref={fileInputRef} type="file" accept=".csv" style={{ display: "none" }} onChange={handleFileInput} />
        <div className="fu-check-icon"><FaCheckCircle /></div>
        <h3 className="fu-drop-title">Drop Your File Here</h3>
        <p className="fu-drop-sub">Supports CSV files with an "email" column</p>
        <button className="fu-plus-btn" onClick={e => { e.stopPropagation(); fileInputRef.current?.click(); }}>+</button>
      </div>

      {apiError && (
        <p style={{ color: "#ef4444", fontSize: 14, marginTop: 12, textAlign: "center" }}>❌ {apiError}</p>
      )}

      <div style={{ textAlign: "center", marginTop: 20 }}>
        <button className="fu-start-btn" onClick={() => fileInputRef.current?.click()}>
          Start Verification
        </button>
      </div>

      {showModal && uploadedFile && (
        <VerifyModal
          file={uploadedFile} emailCount={emailCount}
          availableCredits={availableCredits}
          removeDupes={removeDupes} onToggleDupes={setRemoveDupes}
          onClose={() => { setShowModal(false); setUploadedFile(null); }}
          onStart={handleStartVerification}
        />
      )}
    </div>
  );
}

// ── Verify From File Modal ──
function VerifyModal({ file, emailCount, availableCredits, removeDupes, onToggleDupes, onClose, onStart }) {
  return (
    <div className="fu-modal-overlay" onClick={onClose}>
      <div className="fu-modal" onClick={e => e.stopPropagation()}>
        <button className="fu-modal-close" onClick={onClose}><FaTimes /></button>
        <h2 className="fu-modal-title">Verify From File</h2>

        <div className="fu-email-found-card">
          <div className="fu-email-found-top">
            <FaEnvelope className="fu-modal-envelope" />
            <span className="fu-email-count-big">{emailCount}</span>
          </div>
          <p className="fu-email-found-label">Email Address Found</p>
          <div className="fu-filename-bar">{emailCount} Emails &nbsp;·&nbsp; {file.name}</div>
        </div>

        <div className="fu-modal-row">
          <div>
            <p className="fu-modal-credits-label"><strong>Credits Required:</strong></p>
            <p className="fu-modal-avail">
              (Available Credits:&nbsp;<span style={{ color: "#0fa3b1" }}>{availableCredits}</span>)
            </p>
            <p className="fu-modal-need">
              <span style={{ color: "#0fa3b1", cursor: "pointer" }}>Need More?</span>
            </p>
          </div>
          <span className="fu-credits-needed">{emailCount}</span>
        </div>

        <div className="fu-modal-row" style={{ marginTop: 20 }}>
          <div>
            <p className="fu-modal-credits-label"><strong>Settings:</strong></p>
            <p style={{ fontSize: 14, color: "#555", marginTop: 4 }}>Remove Duplicates</p>
          </div>
          <label className="fu-toggle">
            <input type="checkbox" checked={removeDupes} onChange={e => onToggleDupes(e.target.checked)} />
            <span className="fu-toggle-slider"></span>
          </label>
        </div>

        <button className="fu-modal-start-btn" onClick={onStart}>Start Verification</button>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════
// INTEGRATION TAB
// ══════════════════════════════════════════
const INTEGRATIONS = [
  { name: "Mailchimp",        bg: "#FFE01B", logo: "https://upload.wikimedia.org/wikipedia/commons/thumb/e/e9/Mailchimp-freddie-wink.svg/120px-Mailchimp-freddie-wink.svg.png" },
  { name: "Sendinblue",       bg: "#0092FF", logo: "https://upload.wikimedia.org/wikipedia/commons/thumb/c/ce/Brevo_logo.svg/200px-Brevo_logo.svg.png" },
  { name: "Campaign Monitor", bg: "#7B5EA7", logo: "https://upload.wikimedia.org/wikipedia/commons/thumb/6/6a/Campaign_Monitor_logo.svg/200px-Campaign_Monitor_logo.svg.png" },
  { name: "Mailgun",          bg: "#E3272C", logo: "https://upload.wikimedia.org/wikipedia/commons/thumb/6/69/Mailgun-logo.svg/200px-Mailgun-logo.svg.png" },
  { name: "Mailjet",          bg: "#FECD00", logo: "https://upload.wikimedia.org/wikipedia/commons/thumb/7/72/Mailjet_logo.svg/200px-Mailjet_logo.svg.png" },
  { name: "Elastic Email",    bg: "#1B2340", logo: null, initials: "EE"  },
  { name: "SendGrid",         bg: "#1A82E2", logo: null, initials: "SG"  },
  { name: "Amazon SES",       bg: "#FF9900", logo: null, initials: "SES" },
  { name: "Postmark",         bg: "#FFDE00", logo: null, initials: "PM"  },
  { name: "SparkPost",        bg: "#FA6400", logo: null, initials: "SP"  },
  { name: "ActiveCampaign",   bg: "#356AE6", logo: null, initials: "AC"  },
  { name: "HubSpot",          bg: "#FF7A59", logo: null, initials: "HS"  },
];

function IntegrationCard({ name, bg, logo, initials }) {
  const [connected, setConnected] = useState(false);
  return (
    <div className="integration-card">
      <div className="integration-logo-wrap" style={{ background: bg }}>
        {logo && (
          <img src={logo} alt={name} className="integration-logo-img"
            onError={e => { e.target.style.display = "none"; e.target.nextSibling.style.display = "flex"; }}
          />
        )}
        <span className="integration-logo-fallback" style={{ display: logo ? "none" : "flex" }}>
          {initials || name.charAt(0)}
        </span>
      </div>
      <div className="integration-info">
        <span className="integration-name">{name}</span>
        <button
          className={`integration-connect-btn ${connected ? "connected" : ""}`}
          onClick={() => setConnected(!connected)}
        >
          {connected ? "✓ Connected" : "Connect"}
        </button>
      </div>
    </div>
  );
}

function IntegrationTab() {
  const [showMore, setShowMore] = useState(false);
  const visible = showMore ? INTEGRATIONS : INTEGRATIONS.slice(0, 6);
  return (
    <div className="integration-tab">
      <div className="integration-grid">
        {visible.map((item, i) => <IntegrationCard key={i} {...item} />)}
      </div>
      <button className="show-more-btn" onClick={() => setShowMore(!showMore)}>
        {showMore ? "Show Less" : "Show More"}
        {showMore ? <FaChevronUp className="show-more-icon" /> : <FaChevronDown className="show-more-icon" />}
      </button>
    </div>
  );
}

// ══════════════════════════════════════════
// VIEW LIST — bulk results table
// ══════════════════════════════════════════
function ViewList({ results, getScoreColor }) {
  const [show, setShow] = useState(false);

  const getTypeLabel = (r) => {
    const map = {
      valid:    { label: "Valid",     color: "#16a34a" },
      invalid:  { label: "Invalid",   color: "#dc2626" },
      catchall: { label: "Catch-All", color: "#d97706" },
      unknown:  { label: "Unknown",   color: "#64748b" },
    };
    return map[getResultType(r)] || map.valid;
  };

  return (
    <div style={{ marginTop: 16 }}>
      <button className="view-list-btn" onClick={() => setShow(!show)}>
        {show ? "Hide List" : "View List"}
      </button>
      {show && (
        <div className="bulk-table-wrap">
          <table className="bulk-table">
            <thead>
              <tr><th>Email</th><th>Score</th><th>MX</th><th>SMTP</th><th>Status</th></tr>
            </thead>
            <tbody>
              {results.map((r, i) => {
                const { label, color } = getTypeLabel(r);
                return (
                  <tr key={i}>
                    <td>{r.email}</td>
                    <td><span className="score-pill" style={{ background: getScoreColor(r.score) }}>{r.score}</span></td>
                    <td>{r.mxValid ? "✅" : "❌"}</td>
                    <td>{r.smtp?.success ? "✅" : "❌"}</td>
                    <td style={{ color, fontWeight: 600 }}>{label}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default Dashboard;