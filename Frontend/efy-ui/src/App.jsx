import { Routes, Route } from "react-router-dom";
import Landing from "./Landing";      
import CreateAccount from "./CreateAccount";
import Login from "./Login";
import Verification from "./Verification";
import ForgotPassword from "./ForgotPassword";
import Dashboard from "./Dashboard";
import ResetPassword from "./ResetPassword";
import ChangePassword from "./ChangePassword"; 
import FindEmail from "./FindEmail";
import WelcomeModal from "./WelcomeModal";
import CreditBalancePage from "./Creditbalancepage";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/signup" element={<CreateAccount />} />
      <Route path="/login" element={<Login />} />
      <Route path="/verify-otp" element={<Verification />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/dashboard" element={<Dashboard />} />
      <Route path="/reset-password" element={<ResetPassword/>} />
      <Route path="/change-password" element={<ChangePassword />} />
      <Route path="/find-email" element={<FindEmail />} />
      <Route path="/welcome-modal" element={<WelcomeModal name="Sanika" />} />
      <Route path="/creditBalance" element={<CreditBalancePage/>}/>
    </Routes>
  );
}



