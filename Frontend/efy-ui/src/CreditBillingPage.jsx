
import React, { useState } from "react";
import {
  FaUser, FaEnvelope, FaTimes, FaDownload, FaChevronDown,
  FaCoins, FaCreditCard, FaGooglePay, FaApplePay, FaPaypal,
  FaRupeeSign, FaFileInvoice, FaWallet, FaBolt, FaBuilding,
  FaMapMarker, FaGlobeAsia, FaPercentage, FaPlus, FaMinus,
  FaCcVisa, FaCcMastercard, FaCcAmex, FaCcPaypal, FaCheckCircle,
  FaArrowLeft, FaHistory, FaCalendarAlt, FaDollarSign, FaCopy,
  FaTrashAlt, FaShieldAlt, FaQrcode, FaLock, FaBell, FaCog,
  FaSearch, FaUndo
} from "react-icons/fa";
import "./CreditBillingPage.css";

// ══════════════════════════════════════════════════
// CreditBillingPage.jsx - Complete Billing UI
// ══════════════════════════════════════════════════

const BILLING_TABS = [
  { id: "billing",      label: "Billing Details",   icon: <FaBuilding /> },
  { id: "invoices",     label: "Invoices",          icon: <FaFileInvoice /> },
  { id: "cards",        label: "Saved Cards",       icon: <FaCreditCard /> },
  { id: "autotopup",    label: "Auto Topup",        icon: <FaBolt /> },
];

// ── Billing Details Tab ──
function BillingDetailsTab() {
  return (
    <div className="billing-details-tab-container">
      <h3>Billing Details</h3>
      <div className="billing-info-card">
        <div className="billing-details-grid">

  <div className="info-item">
    <span className="info-label">Name</span>
    <span className="info-value">Kamlesh Surana</span>
  </div>

  <div className="info-item">
    <span className="info-label">Address</span>
    <span className="info-value">Abc Chh Sambhajinagar</span>
  </div>

  <div className="info-item">
    <span className="info-label">Currency</span>
    <span className="info-value">USD - US Dollar</span>
  </div>

  <div className="info-item center-item">
    <button className="individual-btn">Individual</button>
  </div>

  <div className="info-item right-item">
    <button className="change-btn">Change</button>
  </div>
</div>
</div>
</div>
);
}

// ── Invoices Tab ──
function InvoicesTab() {
  const [emailInvoices, setEmailInvoices] = useState(false);

  return (
    <div className="invoices-tab-container">
      <h3>Invoices</h3>
      <div className="email-invoices-section">
        <div className="email-invoices-header">
          <h4>Email Invoices</h4>
          <p>Would you like to email your invoices in the future? Turn on and enter email address to receive invoices via email.</p>
        </div>
        <label className="toggle-switch">
          <input 
            type="checkbox" 
            checked={emailInvoices}
            onChange={() => setEmailInvoices(!emailInvoices)}
          />
          <span className="slider round"></span>
        </label>
      </div>
    </div>
  );
}

// ── Add Card Modal ──
function AddCardModal({ onClose, onAdd }) {
  const [cardNumber, setCardNumber] = useState("");
  const [expiry, setExpiry] = useState("");
  const [cvc, setCvc] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    if (onAdd) {
      onAdd({ cardNumber, expiry, cvc });
    }
    onClose();
  };

  return (
    <div className="cb-modal-overlay" onClick={onClose}>
      <div className="cb-modal cb-modal-small" onClick={e => e.stopPropagation()}>
        <button className="cb-modal-close" onClick={onClose}>
          <FaTimes />
        </button>
        
        <h2 className="cb-modal-title">Add Card Details</h2>
        
        <form onSubmit={handleSubmit}>
          <div className="cb-card-input-group">
            <label>Enter Card Number</label>
            <input 
              type="text"
              placeholder="1234 5678 9012 3456"
              value={cardNumber}
              onChange={(e) => setCardNumber(e.target.value)}
              maxLength="19"
            />
          </div>

          <div className="cb-card-row">
            <div className="cb-card-input-group">
              <label>MM / YY</label>
              <input 
                type="text"
                placeholder="MM/YY"
                value={expiry}
                onChange={(e) => setExpiry(e.target.value)}
                maxLength="5"
              />
            </div>
            <div className="cb-card-input-group">
              <label>CVC</label>
              <input 
                type="text"
                placeholder="123"
                value={cvc}
                onChange={(e) => setCvc(e.target.value)}
                maxLength="3"
              />
            </div>
          </div>

          <button type="submit" className="cb-confirm-card-btn">
            Confirm
          </button>
        </form>
      </div>
    </div>
  );
}

// ── Saved Cards Tab ──
function SavedCardsTab() {
  const [showAddCard, setShowAddCard] = useState(false);

  return (
    <div className="saved-cards-tab-container">
      <h3>Bank Cards</h3>
      <div className="add-card-box" onClick={() => setShowAddCard(true)}>
        <FaPlus />
      </div>
      {showAddCard && (
        <AddCardModal 
          onClose={() => setShowAddCard(false)}
          onAdd={(newCard) => {
            console.log("New card added:", newCard);
          }}
        />
      )}
    </div>
  );
}

// ── Auto Topup Tab ──
function AutoTopupTab() {
  const [autoTopup, setAutoTopup] = useState(false);
  const [cardNumber, setCardNumber] = useState('');
  const [expiry, setExpiry] = useState('');
  const [cvc, setCvc] = useState('');

  return (
    <div className="auto-topup-tab-container">
      <h3>Topup Settings</h3>
      <div className="auto-topup-card">
        <div className="auto-topup-header">
          <h4>Activate Auto Topup</h4>
          <p>Activate and set your automatic payments</p>
        </div>
        <div className="auto-topup-toggle">
          <label className="toggle-switch">
            <input 
              type="checkbox" 
              checked={autoTopup}
              onChange={() => setAutoTopup(!autoTopup)}
            />
            <span className="slider round"></span>
          </label>
        </div>
        <div className="auto-topup-form">
          <div className="card-input-row">
            <input 
              type="text" 
              placeholder="Card Number" 
              value={cardNumber}
              onChange={(e) => setCardNumber(e.target.value)}
            />
            <input 
              type="text" 
              placeholder="MM / YY" 
              value={expiry}
              onChange={(e) => setExpiry(e.target.value)}
              className="expiry-input"
            />
            <input 
              type="text" 
              placeholder="CVC" 
              value={cvc}
              onChange={(e) => setCvc(e.target.value)}
              className="cvc-input"
            />
          </div>
          <button className="save-changes-btn">Save Changes</button>
        </div>
      </div>
    </div>
  );
}

// ── Buy Credits Modal with Plan Selection ──
function BuyCreditsModal({ onClose, onBuy, userName }) {
  const [selectedAmount, setSelectedAmount] = useState("2.0M");
  const [customAmount, setCustomAmount] = useState("");
  const [planType, setPlanType] = useState("payg");
  const [showCalculator, setShowCalculator] = useState(false);

  const popularAmounts = ["5k", "50k", "100k", "250k", "500k", "1M", "2M", "5M"];

  const handleAmountSelect = (amount) => {
    setSelectedAmount(amount);
    setCustomAmount("");
  };

  const calculatePrice = (amount) => {
    const numAmount = parseFloat(amount.replace('k', '000').replace('M', '000000'));
    return (numAmount * 0.0004).toFixed(2);
  };

  const price = selectedAmount ? calculatePrice(selectedAmount) : "0.00";

  return (
    <div className="cb-modal-overlay" onClick={onClose}>
      <div className="cb-modal cb-modal-buy" onClick={e => e.stopPropagation()}>
        <button className="cb-modal-close" onClick={onClose}>
          <FaTimes />
        </button>

        {/* Modal Sidebar */}
        <div className="cb-modal-sidebar">
          <div className="sidebar-header">
            <span className="logo">E-fy</span>
          </div>
          <div className="modal-user-info">
            <FaUser className="user-avatar" />
            <span>{userName}</span>
          </div>
          <nav className="sidebar-nav">
            <ul>
              <li><FaSearch /> Find Email</li>
              <li><FaEnvelope /> Email Verification</li>
              <li className="active"><FaUndo /> Credit Balance</li>
            </ul>
          </nav>
          <div className="sidebar-footer">
            <div className="credits-box-simple">
              <div className="credits-header">
                <FaCoins className="credits-icon" />
                <span className="credits-text">Credits</span>
              </div>
              <div className="credits-value">100</div>
            </div>
          </div>
        </div>

        {/* Modal Main Content */}
        <div className="cb-modal-main-content">
          <div className="cb-buy-header">
            <h2>How many emails do you have?</h2>
            <div className="cb-email-count-display">
              <span className="cb-count-value">2,000,000</span>
            </div>
          </div>

          <div className="cb-plan-toggle">
            <button 
              className={`cb-plan-btn ${planType === 'payg' ? 'active' : ''}`}
              onClick={() => setPlanType('payg')}
            >
              Pay-As-You-Go
            </button>
            <button 
              className={`cb-plan-btn ${planType === 'monthly' ? 'active' : ''}`}
              onClick={() => setPlanType('monthly')}
            >
              Monthly
            </button>
          </div>

          <div className="cb-credit-calculator" onClick={() => setShowCalculator(!showCalculator)}>
            <span>or, select an amount...</span>
            <FaChevronDown className={`cb-calculator-icon ${showCalculator ? 'rotated' : ''}`} />
          </div>

          {showCalculator && (
            <div className="cb-credit-options">
              {popularAmounts.map(amount => (
                <button
                  key={amount}
                  className={`cb-credit-option-btn ${selectedAmount === amount ? 'selected' : ''}`}
                  onClick={() => handleAmountSelect(amount)}
                >
                  {amount}
                </button>
              ))}
            </div>
          )}

          <div className="cb-selected-amount">
            <span className="cb-amount-label">Selected:</span>
            <span className="cb-amount-value">{selectedAmount || '0'}</span>
          </div>

          <div className="cb-pricing-details">
            <div className="cb-pricing-row">
              <span>Credit Cost per credit</span>
              <span className="cb-pricing-value">$0.0004</span>
            </div>
            <div className="cb-pricing-row total">
              <span>Total</span>
              <span className="cb-total-value">${price}</span>
            </div>
          </div>

          <div className="cb-features-list">
            <div className="cb-feature-item">
              <FaCheckCircle className="cb-feature-icon" />
              <span>No Monthly Payments</span>
            </div>
            <div className="cb-feature-item">
              <FaCheckCircle className="cb-feature-icon" />
              <span>Credits Never Expire</span>
            </div>
            <div className="cb-feature-item">
              <FaCheckCircle className="cb-feature-icon" />
              <span>No Upfront Fee</span>
            </div>
            <div className="cb-feature-item">
              <FaCheckCircle className="cb-feature-icon" />
              <span>All Prices Include Taxes And Fees.</span>
            </div>
          </div>

          <div className="cb-payment-methods-supported">
            <p>We support</p>
            <div className="cb-supported-icons">
              <FaPaypal />
              <FaCcVisa />
              <FaCcMastercard />
              <FaCcAmex />
            </div>
          </div>

          <button className="cb-get-started-btn" onClick={() => onBuy(selectedAmount)}>
            Get Started Free! <span className="cb-free-credits">Includes 100 free credits</span>
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Billing Details Modal ──
function BillingDetailsModal({ onClose, onConfirm }) {
  const [formType, setFormType] = useState("business"); // 'business' or 'individual'

  return (
    <div className="cb-modal-overlay" onClick={onClose}>
      <div className="cb-modal cb-modal-billing" onClick={e => e.stopPropagation()}>
        <button className="cb-modal-close" onClick={onClose}>
          <FaTimes />
        </button>
        
        <h2 className="cb-modal-title">Billing Details</h2>

        <div className="cb-form-toggle">
          <button 
            className={`cb-form-toggle-btn ${formType === 'business' ? 'active' : ''}`}
            onClick={() => setFormType('business')}
          >
            Business
          </button>
          <button 
            className={`cb-form-toggle-btn ${formType === 'individual' ? 'active' : ''}`}
            onClick={() => setFormType('individual')}
          >
            Individual
          </button>
        </div>

        <form className="billing-details-form">
          <div className="form-row">
            <div className="form-group">
              <label>First Name</label>
              <input type="text" placeholder="First Name" />
            </div>
            <div className="form-group">
              <label>Last Name</label>
              <input type="text" placeholder="Last Name" />
            </div>
          </div>
          <div className="form-group">
            <label>Business Name</label>
            <input type="text" placeholder="Business Name" />
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>City</label>
              <input type="text" placeholder="City" />
            </div>
            <div className="form-group">
              <label>Post Code</label>
              <input type="text" placeholder="Post Code" />
            </div>
          </div>
          <div className="form-group">
            <label>Address</label>
            <input type="text" placeholder="Address" />
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Country</label>
              <select>
                <option>Country</option>
              </select>
            </div>
            <div className="form-group">
              <label>Currency</label>
              <select>
                <option>Currency</option>
              </select>
            </div>
          </div>
          <div className="form-group">
            <label>Tax Number</label>
            <input type="text" placeholder="Tax Number" />
          </div>
          <button type="button" className="cb-confirm-btn" onClick={onConfirm}>
            Confirm
          </button>
        </form>
      </div>
    </div>
  );
}

// ── Main CreditBillingPage Component ──
export default function CreditBillingPage({
  credits = 100,
  userName = "Shravani Achari",
  onBuyCredits,
  onClose,
}) {
  const [activeTab, setActiveTab] = useState("billing");
  const [showBuyCredits, setShowBuyCredits] = useState(false);
  const [showBillingDetails, setShowBillingDetails] = useState(false);
  const [activeNavItem, setActiveNavItem] = useState("credit-balance");

  const renderTabContent = () => {
    switch (activeTab) {
      case "billing":
        return <BillingDetailsTab />;
      case "invoices":
        return <InvoicesTab />;
      case "cards":
        return <SavedCardsTab />;
      case "autotopup":
        return <AutoTopupTab />;
      default:
        return <BillingDetailsTab />;
    }
  };

  return (
    <div className="billing-page-container">
      {/* Left Sidebar */}
      <div className="billing-sidebar">
        <div className="sidebar-header">
          <span className="logo">E-fy</span>
        </div>
        <nav className="sidebar-nav">
          <ul>
            <li 
              className={activeNavItem === "find-email" ? "active" : ""}
              onClick={() => setActiveNavItem("find-email")}
            >
              <FaSearch /> Find Email
            </li>
            <li
              className={activeNavItem === "email-verification" ? "active" : ""}
              onClick={() => setActiveNavItem("email-verification")}
            >
              <FaEnvelope /> Email Verification
            </li>
            <li
              className={activeNavItem === "credit-balance" ? "active" : ""}
              onClick={() => setActiveNavItem("credit-balance")}
            >
              <FaUndo /> Credit Balance
            </li>
          </ul>
        </nav>
        <div className="sidebar-footer">
        <div className="credits-box-simple">
          <div className="credits-value">100</div>
          <button className="buy-credits-btn-simple" onClick={() => setShowBillingDetails(true)}>
            <FaRupeeSign /> Buy Credits
          </button>
        </div>
      </div>
      </div>

      {/* Right Main Content */}
      <div className="billing-main-content">
        <header className="main-header">
          <div className="user-menu">
            <FaUser className="user-avatar" />
            <span>{userName}</span>
            <FaChevronDown />
          </div>
        </header>
        
        {/* Horizontal Tabs Navigation */}
        <div className="billing-tabs-wrapper">
          <div className="billing-tabs-container">
            {BILLING_TABS.map(tab => (
              <button
                key={tab.id}
                className={`billing-tab-btn ${activeTab === tab.id ? 'active' : ''}`}
                onClick={() => setActiveTab(tab.id)}
              >
                <span className="tab-icon">{tab.icon}</span>
                <span className="tab-label">{tab.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Tab Content */}
        <div className="billing-tab-content-wrapper">
          <div className="billing-tab-content">
            {renderTabContent()}
          </div>
        </div>
      </div>

      {showBuyCredits && (
        <BuyCreditsModal 
          userName={userName}
          onClose={() => setShowBuyCredits(false)}
          onBuy={() => {
            setShowBuyCredits(false);
            setShowBillingDetails(true);
          }}
        />
      )}

      {showBillingDetails && (
        <BillingDetailsModal
          onClose={() => setShowBillingDetails(false)}
          onConfirm={() => {
            setShowBillingDetails(false);
            // Handle confirmation logic
          }}
        />
      )}
    </div>
  );
}