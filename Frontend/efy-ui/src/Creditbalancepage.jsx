import React, { useEffect, useState } from "react";
import {
  FaUser, FaEnvelope, FaShieldAlt,
  FaTimes, FaKey, FaBell, FaCog,
  FaCheckCircle, FaCopy, FaLock,
  FaCoins, FaClock, FaSignOutAlt,
  FaIdBadge,
} from "react-icons/fa";
import "./Creditbalancepage.css";

// ══════════════════════════════════════════════════
// Creditbalancepage.jsx
// Buy Credits box → lives in Dashboard.js sidebar
// This file: login banner + tabs only
// ══════════════════════════════════════════════════

const TABS = [
  { id: "account",       label: "Account",       icon: <FaUser />  },
  { id: "apikeys",       label: "API Keys",       icon: <FaKey />   },
  { id: "twofactor",     label: "2FA Auth",       icon: <FaLock />  },
  { id: "notifications", label: "Notifications",  icon: <FaBell />  },
  { id: "others",        label: "Others",         icon: <FaCog />   },
];

// ── Avatar initials circle ─────────────────────────
function Avatar({ name, size = 52, fontSize = 18 }) {
  const initials = name
    .split(" ")
    .map(w => w[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
  return (
    <div className="cb-avatar-circle" style={{ width: size, height: size, fontSize }}>
      {initials}
    </div>
  );
}

// ── Shared white card ──────────────────────────────
function Card({ children, className = "" }) {
  return <div className={`cb-card ${className}`}>{children}</div>;
}

// ══════════════════════════════════════════════════
// LOGGED-IN USER BANNER
// ══════════════════════════════════════════════════
function LoggedInBanner({ name, email }) {
  return (
    <div className="cb-login-banner">
      <div className="cb-login-left">
        <div className="cb-login-avatar-wrap">
          <Avatar name={name} size={60} fontSize={22} />
          <span className="cb-online-dot" />
        </div>
        <div className="cb-login-info">
          <div className="cb-login-name">{name}</div>
          <div className="cb-login-email">{email}</div>
          <div className="cb-login-status">
            <span className="cb-status-dot" />
            Logged in
          </div>
        </div>
      </div>
      <div className="cb-login-right">
        <span className="cb-admin-chip">
          <FaIdBadge /> Admin
        </span>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════
// ACCOUNT TAB
// ══════════════════════════════════════════════════
function AccountTab({ savedName, savedEmail, onEdit, users, onAddUserClick }) {
  const displayUsers = users.length
    ? users
    : [{ id: 0, name: savedName, email: savedEmail, role: "Admin" }];

  return (
    <div className="cb-tab-panel">
      <div className="cb-panel-header">
        <div>
          <h2 className="cb-panel-title">Account</h2>
          <p className="cb-panel-sub">Manage your account details and sub-users</p>
        </div>
        <button className="cb-action-btn cb-action-primary" onClick={onAddUserClick}>
          + Add New User
        </button>
      </div>

      <div className="cb-user-list">
        {displayUsers.map((u, idx) => (
          <Card key={u.id ?? idx} className="cb-user-card">
            <div className="cb-user-card-left">
              <Avatar name={u.name} size={52} fontSize={18} />
              <div className="cb-user-text">
                <div className="cb-user-name">{u.name}</div>
                <div className="cb-user-email">{u.email}</div>
                {u.role && <span className="cb-role-badge">{u.role}</span>}
              </div>
            </div>
            <button className="cb-link-btn" onClick={onEdit}>
              Edit Account
            </button>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════
// API KEYS TAB
// ══════════════════════════════════════════════════
function ApiKeysTab({ copied, onCopy }) {
  const keys = [
    { label: "Live API Key", key: "live", val: "efy_live_xk29mAbcDeFgHiJkLmNoPqRsTu" },
    { label: "Test API Key", key: "test", val: "efy_test_xk29mAbcDeFgHiJkLmNoPqRsTu" },
  ];
  return (
    <div className="cb-tab-panel">
      <div className="cb-panel-header">
        <div>
          <h2 className="cb-panel-title">API Keys</h2>
          <p className="cb-panel-sub">Use these keys to authenticate API requests</p>
        </div>
        <button className="cb-action-btn cb-action-primary">+ Generate New Key</button>
      </div>

      <div className="cb-api-keys-stack">
        {keys.map(item => (
          <Card key={item.key} className="cb-api-key-card">
            <div className="cb-api-key-meta">
              <span className="cb-api-key-label">{item.label}</span>
              <span className="cb-api-key-masked">
                {"efy_" + item.key + "_" + "•".repeat(24)}
              </span>
            </div>
            <button
              className={`cb-copy-btn ${copied === item.key ? "cb-copied" : ""}`}
              onClick={() => onCopy(item.key, item.val)}
            >
              {copied === item.key ? <><FaCheckCircle /> Copied</> : <><FaCopy /> Copy</>}
            </button>
          </Card>
        ))}
      </div>

      <div className="cb-info-banner">
        <FaShieldAlt className="cb-info-banner-icon" />
        <div>
          <strong>Keep your API keys secure</strong>
          <p>Never share your API keys or expose them in client-side code.</p>
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════
// STORE ICONS (inline SVG — no extra deps)
// ══════════════════════════════════════════════════
function MicrosoftIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 21 21">
      <rect x="1"  y="1"  width="9" height="9" fill="#F25022"/>
      <rect x="11" y="1"  width="9" height="9" fill="#7FBA00"/>
      <rect x="1"  y="11" width="9" height="9" fill="#00A4EF"/>
      <rect x="11" y="11" width="9" height="9" fill="#FFB900"/>
    </svg>
  );
}

function GooglePlayIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24">
      <path d="M3.18 23.76c.37.21.8.23 1.2.07l11.4-6.58-2.57-2.57L3.18 23.76z" fill="#EA4335"/>
      <path d="M21.54 10.31 18.3 8.46l-2.88 2.88 2.88 2.88 3.27-1.88c.93-.54.93-1.49-.03-2.03z" fill="#FBBC04"/>
      <path d="M3.18.24C2.74.47 2.44.93 2.44 1.55v20.9c0 .62.3 1.08.74 1.31l11.06-11.06L3.18.24z" fill="#4285F4"/>
      <path d="M4.38.31l11.04 6.37-2.57 2.57L1.42.17C1.82.02 2.24.04 2.61.25z" fill="#34A853"/>
    </svg>
  );
}

function AppStoreIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24">
      <defs>
        <linearGradient id="as-g" x1="0" y1="0" x2="24" y2="24" gradientUnits="userSpaceOnUse">
          <stop stopColor="#1AC9FF"/><stop offset="1" stopColor="#0070C9"/>
        </linearGradient>
      </defs>
      <rect width="24" height="24" rx="5.5" fill="url(#as-g)"/>
      <path d="M12 5.5l-1.7 3h1.1l1.1-1.9 1.1 1.9h1.1L13 5.5h-1zm-5.2 2l1.7 3h-1.1l-1.6-2.2L4.2 12.5H3.1l2.2-4-.5-.1V7h1.8v.5h-.8zm10.4 0h1.8v.5h-.8l2.2 4h-1.1l-1.6-2.2-1.6 2.2h-1.1l2.2-4zM6.8 13l1.7 3h-1.1l-1.6-2.2L4.2 16H3.1l1.7-3h-.9v-1.5h3.8V13H6.8zm10.4 0h-1.5l1.7 3H16.3l-1.7-3h-.9v-1.5h3.8V13h-.3z" fill="white"/>
    </svg>
  );
}

// ══════════════════════════════════════════════════
// REAL QR CODE (via public qrserver.com API)
// Encodes standard OTP-Auth URI for Google Authenticator
// ══════════════════════════════════════════════════
const SECRET   = "LGJIRKYPJIZLGB3";
const OTP_URI  = `otpauth://totp/E-fy:kamlesh%40sphurti.net?secret=${SECRET}&issuer=E-fy`;
const QR_URL   = `https://api.qrserver.com/v1/create-qr-code/?size=140x140&margin=8&data=${encodeURIComponent(OTP_URI)}`;

// ══════════════════════════════════════════════════
// 2FA TAB
// ══════════════════════════════════════════════════
function TwoFactorTab() {
  const [showCode, setShowCode] = useState(true);
  const [enabled,  setEnabled]  = useState(true);

  const stores = [
    { label: "Microsoft Store", icon: <MicrosoftIcon /> },
    { label: "Google Play",     icon: <GooglePlayIcon /> },
    { label: "App Store",       icon: <AppStoreIcon /> },
  ];

  return (
    <div className="cb-tab-panel">
      <div className="cb-panel-header">
        <div className="cb-2fa-head-left">
          <div className="cb-google-badge">G</div>
          <div>
            <h2 className="cb-panel-title">Two-Factor Authentication</h2>
            <p className="cb-panel-sub">Secure your account with Google Authenticator</p>
          </div>
        </div>
        <div className="cb-2fa-toggle-wrap">
          <span className="cb-2fa-toggle-label">{enabled ? "Enabled" : "Disabled"}</span>
          <Toggle checked={enabled} onChange={() => setEnabled(p => !p)} />
        </div>
      </div>

      <div className="cb-2fa-steps">

        {/* Step 1 */}
        <Card className="cb-2fa-step-card">
          <div className="cb-step-num">1</div>
          <div className="cb-step-body">
            <h4>Install Authenticator App</h4>
            <p>Download Google Authenticator from your device's store.</p>
            <div className="cb-store-links">
              {stores.map(s => (
                <button key={s.label} className="cb-store-btn">
                  {s.icon}
                  <span>{s.label}</span>
                </button>
              ))}
            </div>
          </div>
        </Card>

        {/* Step 2 */}
        <Card className="cb-2fa-step-card">
          <div className="cb-step-num">2</div>
          <div className="cb-step-body">
            <h4>Scan the QR Code</h4>
            <p>Open the app, tap <strong>+</strong>, then scan the code below.</p>
            <div className="cb-qr-box">
              <img
                src={QR_URL}
                alt="OTP QR Code"
                className="cb-qr-img"
                onError={e => { e.target.style.display = "none"; e.target.nextSibling.style.display = "flex"; }}
              />
              <div className="cb-qr-fallback" style={{ display: "none" }}>
                📷 Scan manually
              </div>
            </div>
            <p className="cb-qr-hint">Account: <strong>kamlesh@sphurti.net</strong></p>
          </div>
        </Card>

        {/* Step 3 */}
        <Card className="cb-2fa-step-card">
          <div className="cb-step-num">3</div>
          <div className="cb-step-body">
            <h4>Or Enter Code Manually</h4>
            <p>Can't scan? Paste this secret key into your authenticator app.</p>
            <div className="cb-secret-box">
              <span className="cb-secret-code">
                {showCode ? SECRET : "•".repeat(SECRET.length)}
              </span>
            </div>
            <div className="cb-secret-actions">
              <button className="cb-action-btn cb-action-ghost" onClick={() => setShowCode(s => !s)}>
                {showCode ? "Hide" : "Show"}
              </button>
              <button className="cb-action-btn cb-action-ghost" onClick={() => navigator.clipboard.writeText(SECRET)}>
                <FaCopy /> Copy
              </button>
            </div>
          </div>
        </Card>

      </div>
    </div>
  );
}

// ── Toggle ─────────────────────────────────────────
function Toggle({ checked, onChange, className = "" }) {
  return (
    <label className={`cb-toggle ${className}`}>
      <input type="checkbox" checked={checked} onChange={onChange} />
      <span className="cb-toggle-track" />
    </label>
  );
}

// ══════════════════════════════════════════════════
// NOTIFICATIONS TAB
// ══════════════════════════════════════════════════
function NotificationsTab() {
  const [prefs, setPrefs] = useState({
    noCreditWebhook: true, lowCreditWebhook: true,
    fileReadyWebhook: true, fileDeleteWebhook: true,
  });
  const [webhookUrl,      setWebhookUrl]      = useState("");
  const [lowCreditAmount, setLowCreditAmount] = useState("");
  const toggle = key => setPrefs(p => ({ ...p, [key]: !p[key] }));

  const rows = [
    { key: "noCreditWebhook",   label: "No Credit Notification",   desc: "Alert when credits reach zero" },
    { key: "lowCreditWebhook",  label: "Low Credit Notification",  desc: "Alert when balance is running low" },
    { key: "fileReadyWebhook",  label: "File Ready Notification",  desc: "Alert when file validation completes" },
    { key: "fileDeleteWebhook", label: "File Delete Notification", desc: "Alert when a file is deleted" },
  ];

  return (
    <div className="cb-tab-panel">
      <div className="cb-panel-header">
        <div>
          <h2 className="cb-panel-title">Notifications</h2>
          <p className="cb-panel-sub">Configure webhook alerts for your account events</p>
        </div>
      </div>
      <Card className="cb-notif-card">
        <div className="cb-field-group">
          <label className="cb-field-label">Webhook URL</label>
          <input className="cb-input" type="text" placeholder="https://mydomain.com/webhook"
            value={webhookUrl} onChange={e => setWebhookUrl(e.target.value)} />
        </div>
        <div className="cb-notif-rows">
          {rows.map(row => (
            <div key={row.key} className="cb-notif-row">
              <div className="cb-notif-info">
                <span className="cb-notif-label">{row.label}</span>
                <span className="cb-notif-desc">{row.desc}</span>
              </div>
              <Toggle checked={prefs[row.key]} onChange={() => toggle(row.key)} />
            </div>
          ))}
        </div>
        {prefs.lowCreditWebhook && (
          <div className="cb-field-group" style={{ marginTop: 12 }}>
            <label className="cb-field-label">Low credit threshold amount</label>
            <input className="cb-input cb-input-sm" type="number" placeholder="e.g. 10"
              value={lowCreditAmount} onChange={e => setLowCreditAmount(e.target.value)} />
          </div>
        )}
        <div className="cb-card-footer">
          <button className="cb-action-btn cb-action-primary">Save Settings</button>
        </div>
      </Card>
    </div>
  );
}

// ══════════════════════════════════════════════════
// OTHERS TAB
// ══════════════════════════════════════════════════
function OthersTab() {
  const [timezone, setTimezone] = useState("");
  const [utcNow,   setUtcNow]   = useState(() => new Date());
  useEffect(() => {
    const t = setInterval(() => setUtcNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  const pad = n => String(n).padStart(2, "0");
  const dateTime = `${utcNow.getUTCFullYear()}-${pad(utcNow.getUTCMonth()+1)}-${pad(utcNow.getUTCDate())} ${pad(utcNow.getUTCHours())}:${pad(utcNow.getUTCMinutes())}:${pad(utcNow.getUTCSeconds())} UTC`;
  const timezones = [
    { value: "Asia/Kolkata",        label: "India Standard Time (IST)"     },
    { value: "America/New_York",    label: "Eastern Time (ET)"             },
    { value: "America/Chicago",     label: "Central Time (CT)"             },
    { value: "America/Los_Angeles", label: "Pacific Time (PT)"             },
    { value: "Europe/London",       label: "Greenwich Mean Time (GMT)"     },
    { value: "Europe/Paris",        label: "Central European Time (CET)"   },
    { value: "Asia/Dubai",          label: "Gulf Standard Time (GST)"      },
    { value: "Asia/Singapore",      label: "Singapore Time (SGT)"          },
    { value: "Australia/Sydney",    label: "Australian Eastern Time (AET)" },
  ];
  return (
    <div className="cb-tab-panel">
      <div className="cb-panel-header">
        <div>
          <h2 className="cb-panel-title">Time Zone Settings</h2>
          <p className="cb-panel-sub">Configure your local timezone preference</p>
        </div>
      </div>
      <Card className="cb-tz-card">
        <div className="cb-tz-clock-row">
          <div className="cb-tz-clock-icon"><FaClock /></div>
          <div>
            <div className="cb-tz-time">{dateTime}</div>
            <div className="cb-tz-sublabel">Current UTC time</div>
          </div>
        </div>
        <div className="cb-field-group">
          <label className="cb-field-label">Your Timezone</label>
          <select className="cb-select" value={timezone} onChange={e => setTimezone(e.target.value)}>
            <option value="" disabled>Select timezone…</option>
            {timezones.map(tz => <option key={tz.value} value={tz.value}>{tz.label}</option>)}
          </select>
        </div>
        <div className="cb-card-footer">
          <button className="cb-action-btn cb-action-primary">Save Changes</button>
        </div>
      </Card>
    </div>
  );
}

// ══════════════════════════════════════════════════
// EDIT ACCOUNT MODAL
// ══════════════════════════════════════════════════
function EditModal({ name, email, onSave, onClose }) {
  const [n, setN] = useState(name);
  const [e, setE] = useState(email);
  return (
    <div className="cb-overlay" onClick={onClose}>
      <div className="cb-modal" onClick={ev => ev.stopPropagation()}>
        <button className="cb-modal-close" onClick={onClose}><FaTimes /></button>
        <div className="cb-modal-avatar-wrap">
          <Avatar name={n || "?"} size={64} fontSize={22} />
        </div>
        <h2 className="cb-modal-title">Edit Account</h2>
        <div className="cb-field-group">
          <label className="cb-field-label">Full Name</label>
          <div className="cb-input-icon-wrap">
            <FaUser className="cb-input-icon" />
            <input className="cb-input cb-input-icon-pad" value={n} onChange={ev => setN(ev.target.value)} placeholder="Full name" />
          </div>
        </div>
        <div className="cb-field-group">
          <label className="cb-field-label">Email Address</label>
          <div className="cb-input-icon-wrap">
            <FaEnvelope className="cb-input-icon" />
            <input className="cb-input cb-input-icon-pad" value={e} onChange={ev => setE(ev.target.value)} placeholder="Email address" />
          </div>
        </div>
        <button className="cb-action-btn cb-action-primary cb-action-full" onClick={() => onSave(n, e)}>
          Save Changes
        </button>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════
// ADD USER MODAL
// ══════════════════════════════════════════════════
function AddUserModal({ onSave, onClose }) {
  const [firstName,   setFirstName]   = useState("");
  const [lastName,    setLastName]    = useState("");
  const [email,       setEmail]       = useState("");
  const [accountType, setAccountType] = useState("shared");
  const handleAdd = () => {
    if (!firstName.trim() || !lastName.trim() || !email.trim()) return;
    onSave({ id: Date.now(), name: `${firstName.trim()} ${lastName.trim()}`, email: email.trim(), role: accountType === "shared" ? "Shared" : "Isolated" });
  };
  return (
    <div className="cb-overlay" onClick={onClose}>
      <div className="cb-modal" onClick={ev => ev.stopPropagation()}>
        <button className="cb-modal-close" onClick={onClose}><FaTimes /></button>
        <h2 className="cb-modal-title">Add Subuser</h2>
        {[
          { label: "First Name", val: firstName, set: setFirstName, ph: "First name" },
          { label: "Last Name",  val: lastName,  set: setLastName,  ph: "Last name"  },
          { label: "Email",      val: email,     set: setEmail,     ph: "name@example.com" },
        ].map(f => (
          <div key={f.label} className="cb-field-group">
            <label className="cb-field-label">{f.label}</label>
            <input className="cb-input" value={f.val} onChange={ev => f.set(ev.target.value)}
              placeholder={f.ph} type={f.label === "Email" ? "email" : "text"} />
          </div>
        ))}
        <div className="cb-field-group">
          <label className="cb-field-label">Account Type</label>
          <div className="cb-radio-group">
            {["isolated", "shared"].map(t => (
              <label key={t} className="cb-radio-label">
                <input type="radio" name="accountType" value={t} checked={accountType === t}
                  onChange={ev => setAccountType(ev.target.value)} />
                <span>{t.charAt(0).toUpperCase() + t.slice(1)}</span>
              </label>
            ))}
          </div>
        </div>
        <button className="cb-action-btn cb-action-primary cb-action-full" onClick={handleAdd}>
          Add New User
        </button>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════
// MAIN EXPORT
// ══════════════════════════════════════════════════
export default function CreditBalancePage({
  credits   = 100,
  userName  = "Kamlesh Surana",
  userEmail = "kamlesh@sphurti.net",
  onBuyCredits,
  onTabChange,
}) {
  const [activeTab,   setActiveTab]   = useState("account");
  const [showEdit,    setShowEdit]    = useState(false);
  const [showAddUser, setShowAddUser] = useState(false);
  const [savedName,   setSavedName]   = useState(userName);
  const [savedEmail,  setSavedEmail]  = useState(userEmail);
  const [copied,      setCopied]      = useState("");
  const [users,       setUsers]       = useState([
    { id: 1, name: userName, email: userEmail, role: "Admin" },
  ]);

  const handleSave = (name, email) => { setSavedName(name); setSavedEmail(email); setShowEdit(false); };
  const handleCopy = (key, val) => {
    navigator.clipboard.writeText(val).catch(() => {});
    setCopied(key);
    setTimeout(() => setCopied(""), 2000);
  };
  const handleAddUser = user => { setUsers(prev => [...prev, user]); setShowAddUser(false); };

  useEffect(() => { if (onTabChange) onTabChange(activeTab); }, [activeTab, onTabChange]);

  return (
    <div className="cb-root">

      {/* ── Logged-in user banner ── */}
      <LoggedInBanner name={savedName} email={savedEmail} />

      {/* ── Tab bar ── */}
      <div className="cb-tabbar">
        {TABS.map(t => (
          <button
            key={t.id}
            className={`cb-tab-btn ${activeTab === t.id ? "active" : ""}`}
            onClick={() => setActiveTab(t.id)}
          >
            <span className="cb-tab-icon">{t.icon}</span>
            <span>{t.label}</span>
          </button>
        ))}
      </div>

      {/* ── Tab content ── */}
      <div className="cb-content">
        {activeTab === "account"       && <AccountTab savedName={savedName} savedEmail={savedEmail} onEdit={() => setShowEdit(true)} users={users} onAddUserClick={() => setShowAddUser(true)} />}
        {activeTab === "apikeys"       && <ApiKeysTab copied={copied} onCopy={handleCopy} />}
        {activeTab === "twofactor"     && <TwoFactorTab />}
        {activeTab === "notifications" && <NotificationsTab />}
        {activeTab === "others"        && <OthersTab />}
      </div>

      {showEdit    && <EditModal    name={savedName} email={savedEmail} onSave={handleSave} onClose={() => setShowEdit(false)} />}
      {showAddUser && <AddUserModal onSave={handleAddUser} onClose={() => setShowAddUser(false)} />}
    </div>
  );
}