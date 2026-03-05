import { useState, useEffect, useRef } from "react";
import { motion, useScroll, useTransform, useSpring, AnimatePresence } from "framer-motion";
import topSection from "./assets/top-verification.png";
import trustedSection from "./assets/trusted-section.png";
import CreateAccount from "./CreateAccount";
import { useNavigate } from "react-router-dom";


const logos = [
  // "/logos/apollo.png",
  "/logos/cargoAi.png",
  "/logos/clay.png",
  "/logos/pipedream.png",
  "/logos/hunter-logo.png",
  "logos/Zapier-logo.png"
  
];

// Advanced Reveal Component with Parallax and Stagger Effects
function Reveal({ children, className = "", delay = 0, direction = "up", duration = 0.6 }) {
  const ref = useRef(null);
  const [isVisible, setIsVisible] = useState(false);

  const directions = {
    up: { y: 50, opacity: 0 },
    down: { y: -50, opacity: 0 },
    left: { x: 50, opacity: 0 },
    right: { x: -50, opacity: 0 },
    scale: { scale: 0.8, opacity: 0 },
    rotate: { rotate: -10, opacity: 0, scale: 0.9 }
  };

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
          observer.unobserve(entry.target);
        }
      },
      { threshold: 0.1, rootMargin: "0px 0px -50px 0px" }
    );

    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);

  return (
    <motion.div
      ref={ref}
      initial={directions[direction] || directions.up}
      animate={isVisible ? { x: 0, y: 0, scale: 1, rotate: 0, opacity: 1 } : directions[direction] || directions.up}
      transition={{ duration, delay, type: "spring", stiffness: 100 }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

// Magnetic Button Effect
function MagneticButton({ children, onClick, className = "" }) {
  const buttonRef = useRef(null);
  const [position, setPosition] = useState({ x: 0, y: 0 });

  const handleMouseMove = (e) => {
    const { clientX, clientY } = e;
    const { left, top, width, height } = buttonRef.current.getBoundingClientRect();
    const x = (clientX - (left + width / 2)) * 0.3;
    const y = (clientY - (top + height / 2)) * 0.3;
    setPosition({ x, y });
  };

  const handleMouseLeave = () => {
    setPosition({ x: 0, y: 0 });
  };

  return (
    <motion.button
      ref={buttonRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      animate={{ x: position.x, y: position.y }}
      transition={{ type: "spring", stiffness: 150, damping: 15 }}
      onClick={onClick}
      className={className}
    >
      {children}
    </motion.button>
  );
}

// Parallax Background Effect
function ParallaxBackground({ children }) {
  const { scrollY } = useScroll();
  const y = useTransform(scrollY, [0, 500], [0, -150]);
  const opacity = useTransform(scrollY, [0, 300], [0.3, 0.1]);
  const scale = useTransform(scrollY, [0, 500], [1, 1.2]);

  return (
    <motion.div
      style={{ y, opacity, scale }}
      className="absolute -bottom-40 -right-40 w-[600px] h-[600px] bg-teal-400 rounded-full blur-3xl pointer-events-none"
    >
      {children}
    </motion.div>
  );
}

// Animated Counter
function AnimatedCounter({ from = 0, to, duration = 2 }) {
  const [count, setCount] = useState(from);
  const ref = useRef(null);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
          observer.unobserve(entry.target);
        }
      },
      { threshold: 0.5 }
    );

    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!isVisible) return;

    let startTime;
    const animate = (timestamp) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / (duration * 1000), 1);
      setCount(Math.floor(from + (to - from) * progress));
      if (progress < 1) requestAnimationFrame(animate);
    };
    requestAnimationFrame(animate);
  }, [isVisible, from, to, duration]);

  return <span ref={ref}>{count.toLocaleString()}</span>;
}

// Floating Elements
function FloatingElement({ children, delay = 0, amplitude = 10, duration = 3 }) {
  return (
    <motion.div
      animate={{
        y: [0, -amplitude, 0],
      }}
      transition={{
        duration,
        repeat: Infinity,
        delay,
        ease: "easeInOut"
      }}
    >
      {children}
    </motion.div>
  );
}

// Typewriter Effect
function TypewriterText({ text, delay = 0 }) {
  const [displayText, setDisplayText] = useState("");
  const [isVisible, setIsVisible] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
          observer.unobserve(entry.target);
        }
      },
      { threshold: 0.5 }
    );

    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!isVisible) return;

    let index = 0;
    const timer = setInterval(() => {
      if (index < text.length) {
        setDisplayText(prev => prev + text.charAt(index));
        index++;
      } else {
        clearInterval(timer);
      }
    }, 50);

    return () => clearInterval(timer);
  }, [isVisible, text]);

  return <span ref={ref}>{displayText}</span>;
}

// Staggered Children Animation
function StaggerContainer({ children, className = "", staggerDelay = 0.1 }) {
  return (
    <motion.div
      variants={{
        hidden: { opacity: 0 },
        visible: {
          opacity: 1,
          transition: {
            staggerChildren: staggerDelay
          }
        }
      }}
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true, margin: "-50px" }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

function StaggerItem({ children }) {
  return (
    <motion.div
      variants={{
        hidden: { y: 20, opacity: 0 },
        visible: { y: 0, opacity: 1 }
      }}
      transition={{ type: "spring", stiffness: 100 }}
    >
      {children}
    </motion.div>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState("findEmail");
  const navigate = useNavigate();
  const orbRef = useRef(null);
  const heroRef = useRef(null);
  const { scrollYProgress } = useScroll();
  const heroScale = useTransform(scrollYProgress, [0, 0.2], [1, 0.95]);
  const heroOpacity = useTransform(scrollYProgress, [0, 0.2], [1, 0.8]);

  useEffect(() => {
    const onMove = (e) => {
      const x = (e.clientX / window.innerWidth - 0.5) * 30;
      const y = (e.clientY / window.innerHeight - 0.5) * 30;
      if (orbRef.current) {
        orbRef.current.style.transform = `translate3d(${x * 2}px, ${y * 2}px, 0)`;
      }
    };
    window.addEventListener("mousemove", onMove, { passive: true });
    return () => window.removeEventListener("mousemove", onMove);
  }, []);

  const onHeroMove = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = (e.clientX - rect.left) / rect.width - 0.5;
    const py = (e.clientY - rect.top) / rect.height - 0.5;
    const rx = py * -8;
    const ry = px * 8;
    if (heroRef.current) {
      heroRef.current.style.transform = `perspective(1200px) rotateX(${rx}deg) rotateY(${ry}deg) translateZ(20px)`;
    }
  };
  const onHeroLeave = () => {
    if (heroRef.current) {
      heroRef.current.style.transform = "perspective(1200px) rotateX(0deg) rotateY(0deg) translateZ(0)";
    }
  };

  const tabs = [
    { id: "findEmail", label: "Find Email" },
    { id: "findDomain", label: "Find by Domain" },
    { id: "lookup", label: "Email Lookup" },
    { id: "verifier", label: "Email Verifier" },
  ];

  const getHeading = () => {
    switch (activeTab) {
      case "findDomain":
        return (
          <>
            Get{" "}
            <motion.span
              className="text-[#6ad8df] inline-block font-semibold"
              animate={{ scale: [1, 1.02, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              Decision-maker and Employee Emails
            </motion.span>{" "}
            by entering a company domain.
          </>
        );
      case "lookup":
        return (
          <>
            Easily{" "}
            <motion.span
              className="text-[#6ad8df] inline-block font-semibold"
              animate={{ scale: [1, 1.02, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              Find Lead Data by Email
            </motion.span>{" "}
            to reach out, personalize, and improve conversions.
          </>
        );
      case "verifier":
        return (
          <>
            Verify any{" "}
            <motion.span
              className="text-[#6ad8df] inline-block font-semibold"
              animate={{ scale: [1, 1.02, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              email address
            </motion.span>{" "}
            with reliable email checker.
          </>
        );
      default:
        return (
          <>
            Get the{" "}
            <motion.span
              className="text-[#6ad8df] inline-block font-semibold"
              animate={{ scale: [1, 1.02, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              Email of a Professional
            </motion.span>{" "}
            with a simple search.
          </>
        );
    }
  };

  const getInputFields = () => {
    const inputVariants = {
      hidden: { scale: 0.8, opacity: 0 },
      visible: { scale: 1, opacity: 1, transition: { type: "spring", stiffness: 200 } }
    };

    if (activeTab === "findDomain") {
      return (
        <motion.div
          variants={inputVariants}
          initial="hidden"
          animate="visible"
          className="mt-12 flex items-center overflow-hidden rounded-bl-[3rem] rounded-br-[3rem] bg-white/90 shadow-xl"
        >
          <input
            type="text"
            placeholder="Enter Company Domain"
            className="flex-1 px-6 py-4 text-gray-700 outline-none"
          />
          <MagneticButton className="bg-[#2CA1AE] px-8 py-4 font-medium text-white transition hover:bg-[#238A95]">
            Find Email
          </MagneticButton>
        </motion.div>
      );
    }

    if (activeTab === "lookup") {
      return (
        <motion.div
          variants={inputVariants}
          initial="hidden"
          animate="visible"
          className="mt-12 flex items-center overflow-hidden rounded-bl-[3rem] rounded-br-[3rem] bg-white/90 shadow-xl"
        >
          <input
            type="email"
            placeholder="Enter Email Address"
            className="flex-1 px-6 py-4 text-gray-700 outline-none"
          />
          <MagneticButton className="bg-[#2CA1AE] px-8 py-4 font-medium text-white transition hover:bg-[#238A95]">
            Find Contact
          </MagneticButton>
        </motion.div>
      );
    }

    if (activeTab === "verifier") {
      return (
        <motion.div
          variants={inputVariants}
          initial="hidden"
          animate="visible"
          className="mt-12 flex items-center overflow-hidden rounded-bl-[3rem] rounded-br-[3rem] bg-white/90 shadow-xl"
        >
          <input
            type="email"
            placeholder="Enter Email Address"
            className="flex-1 px-6 py-4 text-gray-700 outline-none"
          />
          <MagneticButton className="bg-[#2CA1AE] px-8 py-4 font-medium text-white transition hover:bg-[#238A95]">
            Verify Email
          </MagneticButton>
        </motion.div>
      );
    }

    return (
      <motion.div
        variants={inputVariants}
        initial="hidden"
        animate="visible"
        className="mt-12 flex items-center overflow-hidden rounded-bl-[3rem] rounded-br-[3rem] bg-white/90 shadow-xl"
      >
        <input
          type="text"
          placeholder="Full Name"
          className="flex-1 px-6 py-4 text-gray-700 outline-none"
        />
        <input
          type="text"
          placeholder="Domain"
          className="flex-1 px-6 py-4 text-gray-700 outline-none"
        />
        <MagneticButton className="bg-[#2CA1AE] px-8 py-4 font-medium text-white transition hover:bg-[#238A95]">
          Find Email
        </MagneticButton>
      </motion.div>
    );
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
        delayChildren: 0.3
      }
    }
  };

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
      transition: { type: "spring", stiffness: 100 }
    }
  };

  return (
    <motion.div
      initial="hidden"
      animate="visible"
      variants={containerVariants}
      className="relative min-h-screen bg-[#023e56] text-white"
    >
      {/* Animated Background Elements */}
      <ParallaxBackground />

      {/* Navbar */}
      <motion.nav
        variants={itemVariants}
        className="flex justify-between items-center px-12 py-6 relative z-10"
      >
        <motion.h1
          className="text-2xl font-bold tracking-wide"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          E-fy
        </motion.h1>

        <StaggerContainer className="flex gap-8 text-gray-300 font-medium" staggerDelay={0.05}>
          {[
            { name: "Home", href: "#home" },
            { name: "Pricing", href: "#pricing" },
            { name: "Integration", href: "#" },
            { name: "API", href: "#" }
          ].map((item) => (
            <StaggerItem key={item.name}>
              <motion.a
                href={item.href}
                className="hover:text-teal-300 transition"
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.95 }}
              >
                {item.name}
              </motion.a>
            </StaggerItem>
          ))}
        </StaggerContainer>

        <div className="flex gap-4 items-center">
          <MagneticButton
            onClick={() => navigate("/login")}
            className="text-gray-300 hover:text-teal-300 transition"
          >
            Login
          </MagneticButton>

          <MagneticButton
            onClick={() => navigate("/signup")}
            className="bg-white text-[#0f4c5c] px-5 py-2 rounded-xl font-medium shadow-md"
          >
            Create Account
          </MagneticButton>
        </div>
      </motion.nav>

      {/* Hero Section */}
      <motion.div
        id="home"
        style={{ scale: heroScale, opacity: heroOpacity }}
        className="flex justify-center mt-10 relative w-full pt-12 pb-40 overflow-hidden"
      >
        {/* Background Shapes confined to Hero */}
        <motion.div
          initial={{ opacity: 0, scale: 0.8, x: 100, y: 100, rotate: 35 }}
          animate={{ opacity: 1, scale: 1, x: 600, y: -100, rotate: 35 }}
          transition={{ duration: 1.5, ease: "easeOut" }}
          className="absolute -right-[10%] -bottom-[40%] w-[1200px] h-[450px] bg-[#1b7c8d] rounded-full pointer-events-none z-0"
        />
        <motion.div
          initial={{ opacity: 0, scale: 0.8, x: 100, y: 100, rotate: 35 }}
          animate={{ opacity: 1, scale: 1, x: 600, y: -100, rotate: 40 }}
          transition={{ duration: 1.5, delay: 0.2, ease: "easeOut" }}
          className="absolute right-[5%] -bottom-[50%] w-[1200px] h-[450px] bg-[#2ca1ae] rounded-full pointer-events-none z-0"
        />

        <motion.div
          ref={heroRef}
          onMouseMove={onHeroMove}
          onMouseLeave={onHeroLeave}
          variants={itemVariants}
          whileHover={{ boxShadow: "0 0 100px rgba(0,255,200,0.3)" }}
          className="w-[950px] rounded-3xl border-t-[3px] border-t-[#1b7c8d] backdrop-blur-[64px] py-24 px-16 shadow-[0_8px_32px_rgba(0,0,0,0.2)] transition-transform duration-300 will-change-transform z-10"
        >
          <motion.h2
            variants={itemVariants}
            className="text-4xl font-semibold text-center leading-snug"
          >
            {getHeading()}
          </motion.h2>

          {/* Tabs */}
          <StaggerContainer className="flex justify-center gap-10 mt-10 text-gray-300 font-medium">
            {tabs.map((tab) => (
              <StaggerItem key={tab.id}>
                <motion.span
                  onClick={() => setActiveTab(tab.id)}
                  className={`cursor-pointer transition pb-1 ${activeTab === tab.id
                    ? "text-[#6ad8df] border-b-2 border-[#6ad8df]"
                    : "hover:text-[#6ad8df]"
                    }`}
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.95 }}
                >
                  {tab.label}
                </motion.span>
              </StaggerItem>
            ))}
          </StaggerContainer>

          {/* Dynamic Inputs */}
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3 }}
            >
              {getInputFields()}
            </motion.div>
          </AnimatePresence>
        </motion.div>
      </motion.div>

      {/* Trusted Section */}
      {/* Trusted By Section */}
<motion.section
  initial={{ opacity: 0 }}
  whileInView={{ opacity: 1 }}
  viewport={{ once: true }}
  className="w-full bg-gradient-to-br from-slate-50 via-white to-blue-50 py-16"
>
  <div className="text-center mb-10">
    <p className="text-blue-600 tracking-[0.3em] text-sm font-medium uppercase">
      TRUSTED BY TEAMS FROM AROUND THE WORLD
    </p>
  </div>

  {/* Infinite Carousel (no boxes) */}
  <div className="overflow-hidden w-full">
    <motion.div
      className="flex whitespace-nowrap"
      animate={{ x: ["0%", "-50%"] }}
      transition={{
        duration: 20,
        repeat: Infinity,
        ease: "linear",
      }}
    >
      {/* Row 1 */}
      <div className="flex gap-16 flex-none px-16">
        {logos.map((logo, i) => (
          <img
            key={i}
            src={logo}
            alt={`Logo ${i + 1}`}
            className="h-14 w-32 object-contain opacity-80 hover:opacity-100 transform hover:scale-105 transition-all duration-300"
            draggable={false}
          />
        ))}
      </div>

      {/* Row 2 (duplicate) */}
      <div className="flex gap-16 flex-none px-16">
        {logos.map((logo, i) => (
          <img
            key={`dupA-${i}`}
            src={logo}
            alt={`Logo ${i + 1}`}
            className="h-14 w-32 object-contain opacity-80 hover:opacity-100 transform hover:scale-105 transition-all duration-300"
            draggable={false}
          />
        ))}
      </div>

      {/* Row 3 (extra to avoid empty space) */}
      <div className="flex gap-16 flex-none px-16">
        {logos.map((logo, i) => (
          <img
            key={`dupB-${i}`}
            src={logo}
            alt={`Logo ${i + 1}`}
            className="h-14 w-32 object-contain opacity-80 hover:opacity-100 transform hover:scale-105 transition-all duration-300"
            draggable={false}
          />
        ))}
      </div>
    </motion.div>
  </div>
</motion.section>


  <motion.section
    initial={{ opacity: 0, y: 40 }}
    whileInView={{ opacity: 1, y: 0 }}
    viewport={{ once: true }}
    className="relative py-32 bg-gradient-to-br from-blue-50/90 via-cyan-50 to-blue-50/80 overflow-hidden"
  >
    {/* Enhanced Background Effects - Light Blue Theme */}
    <div className="absolute inset-0 pointer-events-none">
      <div className="absolute top-1/4 left-0 w-[600px] h-[600px] bg-gradient-to-br from-blue-300/20 via-cyan-300/20 to-blue-400/20 rounded-full blur-3xl animate-blob" />
      <div className="absolute bottom-1/4 right-0 w-[500px] h-[500px] bg-gradient-to-br from-blue-400/15 via-indigo-400/15 to-cyan-400/15 rounded-full blur-3xl animate-blob animation-delay-2000" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-gradient-to-r from-blue-200/20 to-cyan-200/20 rounded-full blur-2xl animate-pulse" />
    </div>

    {/* Content */}
    <div className="relative z-10 max-w-7xl mx-auto px-6">
      {/* Premium Badge */}
      <motion.div
        initial={{ opacity: 0, scale: 0.8, y: 20 }}
        whileInView={{ opacity: 1, scale: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.6, type: "spring" }}
        className="text-center mb-12"
      >
        <div className="inline-flex items-center gap-3 px-6 py-3 bg-white/90 backdrop-blur-xl shadow-xl border border-blue-100/80 rounded-2xl hover:shadow-2xl transition-all duration-300">
          <div className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 bg-gradient-to-r from-emerald-400 to-green-500 rounded-full shadow-lg animate-ping" />
            <div className="w-1.5 h-1.5 bg-gradient-to-r from-emerald-400 to-green-500 rounded-full shadow-lg animate-pulse" />
          </div>
          <span className="text-lg font-bold bg-gradient-to-r from-slate-800 to-slate-900 bg-clip-text text-transparent">
            #1 Trusted by 50K+ Businesses
          </span>
        </div>
      </motion.div>

      {/* Hero Content */}
      <div className="grid lg:grid-cols-2 gap-16 items-center mb-20">
        {/* Left Text Content - Smaller Text */}
        <motion.div
          initial={{ opacity: 0, x: -50 }}
          whileInView={{ opacity: 1, x: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8 }}
          className="text-center lg:text-left lg:max-w-lg"
        >
          <motion.h2
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8, delay: 0.2 }}
            className="text-4xl md:text-5xl lg:text-6xl font-black tracking-tight leading-tight mb-8"
          >
            <span className="block text-slate-900 drop-shadow-lg">Ultimate</span>
            <span className="block bg-gradient-to-r from-blue-600 via-cyan-600 to-blue-700 bg-clip-text text-transparent drop-shadow-2xl">
              Email Verification
            </span>
            {/* Smaller cleaner text matching your image */}
            <span className="block text-xl md:text-2xl lg:text-2xl font-bold text-slate-700 mt-4 tracking-tight leading-tight">
              Lightning Fast • 99.9% Accurate
            </span>
          </motion.h2>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8, delay: 0.4 }}
            className="text-lg md:text-xl text-slate-600 leading-relaxed mb-8 max-w-lg mx-auto lg:mx-0"
          >
            Clean your email lists instantly. Remove bounces, catch typos, 
            and validate domains with enterprise-grade precision.
          </motion.p>
        </motion.div>

        {/* Right Image Hero -  */}
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8, delay: 0.3 }}
          className="relative"
        >
          <div className="relative group">
            {/* Top-right badge - */}
            <motion.div
              className="absolute -top-4 -right-4 bg-gradient-to-r from-emerald-500 to-green-600 text-white px-4 py-2 rounded-xl shadow-2xl text-xs font-bold border border-white/50 backdrop-blur-md z-20"
              initial={{ opacity: 0, y: -20, rotate: -10 }}
              whileInView={{ opacity: 1, y: 0, rotate: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.6, type: "spring", stiffness: 300 }}
              whileHover={{ scale: 1.05 }}
            >
              🚀 10x Faster
            </motion.div>

            {/* Bottom-left badge -*/}
            <motion.div
              className="absolute -bottom-4 -left-4 bg-gradient-to-r from-blue-600 to-cyan-700 text-white px-4 py-2 rounded-xl shadow-2xl text-xs font-bold border border-white/50 backdrop-blur-md rotate-[-6deg] z-20"
              initial={{ opacity: 0, y: 20, rotate: 10 }}
              whileInView={{ opacity: 1, y: 0, rotate: -6 }}
              viewport={{ once: true }}
              transition={{ delay: 0.7, type: "spring", stiffness: 300 }}
              whileHover={{ scale: 1.05 }}
            >
              ✅ 99.9% Accuracy
            </motion.div>

            {/* Main Glass Card - Perfect fit for your image */}
            <div className="relative bg-white/95 backdrop-blur-3xl rounded-3xl p-6 shadow-2xl border border-blue-100/70 hover:shadow-3xl hover:shadow-blue-400/30 transition-all duration-500 group-hover:-translate-y-2 z-10">
              {/* Subtle blue glow */}
              <div className="absolute inset-0 bg-gradient-to-r from-blue-400/10 via-transparent to-cyan-400/10 rounded-3xl blur-xl opacity-0 group-hover:opacity-100 transition-all duration-700" />
              
              {/* Image container - */}
              <div className="relative overflow-hidden rounded-2xl shadow-xl">
  <motion.img
    src={topSection}
    alt="Email Verification Dashboard"
    className="w-full max-h-[450px] object-contain rounded-2xl mx-auto"
    whileHover={{
      scale: 1.02,
      y: -6,
    }}
    transition={{
      duration: 0.4,
      ease: "easeOut",
    }}
  />
</div>
            </div>
          </div>
        </motion.div>
      </div>
    </div>

    <style jsx>{`
      @keyframes blob {
        0%, 100% { transform: translate(0px, 0px) scale(1); }
        33% { transform: translate(30px, -50px) scale(1.1); }
        66% { transform: translate(-20px, 20px) scale(0.9); }
      }
      @keyframes shimmer {
        0% { transform: translateX(-100%); }
        100% { transform: translateX(100%); }
      }
      .animate-blob {
        animation: blob 7s infinite;
      }
      .animation-delay-2000 {
        animation-delay: 2s;
      }
      .animate-shimmer {
        animation: shimmer 3s infinite;
      }
    `}</style>
  </motion.section>


      {/* Bulk Email Verification Section */}
      
{/* ========== ATTRACTIVE FEATURES SECTION ========== */}

{/* ========== ATTRACTIVE FEATURES SECTION ========== */}
{/* ========== ATTRACTIVE FEATURES SECTION - GRADIENT CARDS MATCHING BUTTON ========== */}
<motion.section
  initial={{ opacity: 0 }}
  whileInView={{ opacity: 1 }}
  viewport={{ once: true }}
  className="relative py-32 overflow-hidden bg-gradient-to-br from-blue-50/90 via-white to-blue-50/80"
>
  {/* Animated background orbs - soft light colors */}
  <motion.div
    className="absolute -top-40 -right-40 w-[600px] h-[600px] rounded-full bg-gradient-to-br from-[#2CA1AE]/10 to-[#6ad8df]/10 blur-3xl"
    animate={{
      scale: [1, 1.2, 1],
      rotate: [0, 45, 0],
      opacity: [0.2, 0.4, 0.2],
    }}
    transition={{ duration: 10, repeat: Infinity }}
  />
  <motion.div
    className="absolute -bottom-40 -left-40 w-[600px] h-[600px] rounded-full bg-gradient-to-tr from-[#1b7c8d]/10 to-[#2CA1AE]/10 blur-3xl"
    animate={{
      scale: [1, 1.3, 1],
      rotate: [0, -45, 0],
      opacity: [0.1, 0.3, 0.1],
    }}
    transition={{ duration: 12, repeat: Infinity }}
  />

  {/* Light grid overlay */}
  <div 
    className="absolute inset-0"
    style={{
      backgroundImage: `
        linear-gradient(rgba(44, 161, 174, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(44, 161, 174, 0.03) 1px, transparent 1px)
      `,
      backgroundSize: '50px 50px',
    }}
  />

  {/* Floating particles - subtle light */}
  <div className="absolute inset-0 overflow-hidden">
    {[...Array(15)].map((_, i) => (
      <motion.div
        key={i}
        className="absolute w-1 h-1 rounded-full bg-[#2CA1AE]/20"
        initial={{
          x: Math.random() * 100 + "%",
          y: Math.random() * 100 + "%",
        }}
        animate={{
          y: [null, "-30%"],
          x: [null, (Math.random() - 0.5) * 50 + "%"],
          opacity: [0, 0.3, 0],
        }}
        transition={{
          duration: 5 + Math.random() * 5,
          repeat: Infinity,
          delay: Math.random() * 5,
          ease: "linear",
        }}
      />
    ))}
  </div>

  <div className="relative z-10 max-w-7xl mx-auto px-6">
    {/* Section Header */}
    <motion.div
      initial={{ opacity: 0, y: 30 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.6 }}
      className="text-center mb-16"
    >
      {/* Eyebrow text */}
      <motion.span
        initial={{ opacity: 0, scale: 0.8 }}
        whileInView={{ opacity: 1, scale: 1 }}
        viewport={{ once: true }}
        transition={{ duration: 0.4, delay: 0.2 }}
        className="inline-block px-4 py-1.5 mb-4 text-sm font-semibold text-[#2CA1AE] bg-[#2CA1AE]/10 rounded-full border border-[#2CA1AE]/20"
      >
        ✦ Why Choose E-fy ✦
      </motion.span>

      {/* Main Title */}
      <motion.h2
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.5, delay: 0.3 }}
        className="text-4xl md:text-5xl font-bold text-gray-900 mb-4"
      >
        Powerful{' '}
        <motion.span
          className="inline-block bg-gradient-to-r from-[#2CA1AE] to-[#1b7c8d] bg-clip-text text-transparent"
          animate={{
            backgroundPosition: ['0%', '100%', '0%'],
          }}
          transition={{ duration: 5, repeat: Infinity }}
          style={{ backgroundSize: '200% auto' }}
        >
          Features
        </motion.span>
      </motion.h2>

      {/* Animated underline */}
      <motion.div
        initial={{ width: 0 }}
        whileInView={{ width: '96px' }}
        viewport={{ once: true }}
        transition={{ duration: 0.8, delay: 0.4 }}
        className="h-1 bg-gradient-to-r from-[#2CA1AE] to-[#1b7c8d] mx-auto rounded-full"
      />

      {/* Subtitle */}
      <motion.p
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.5, delay: 0.5 }}
        className="text-gray-600 text-lg mt-6 max-w-2xl mx-auto"
      >
        Everything you need to verify, validate, and enrich your email lists with enterprise-grade accuracy
      </motion.p>
    </motion.div>

    {/* Features Grid */}
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
      {/* Feature Card 1 - Bulk Verification */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ delay: 0.1 }}
        whileHover={{ y: -10 }}
        className="group relative"
      >
        {/* Animated gradient border - matches button gradient */}
        <motion.div
          className="absolute -inset-0.5 bg-gradient-to-r from-[#2CA1AE] via-[#6ad8df] to-[#1b7c8d] rounded-2xl opacity-0 group-hover:opacity-30 blur transition-all duration-500"
          animate={{
            background: [
              "linear-gradient(90deg, #2CA1AE, #6ad8df, #1b7c8d)",
              "linear-gradient(180deg, #2CA1AE, #6ad8df, #1b7c8d)",
              "linear-gradient(270deg, #2CA1AE, #6ad8df, #1b7c8d)",
            ],
          }}
          transition={{ duration: 4, repeat: Infinity }}
        />

        {/* Card - Gradient matching "Explore All Features" button */}
        <div className="relative bg-gradient-to-r from-[#2CA1AE] to-[#1b7c8d] rounded-2xl p-8 shadow-xl overflow-hidden">
          {/* Inner glow */}
          <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

          {/* Icon container */}
          <div className="relative mb-6">
            <motion.div
              className="w-20 h-20 mx-auto bg-white/20 rounded-2xl flex items-center justify-center border border-white/30 backdrop-blur-sm"
              whileHover={{ rotate: 5, scale: 1.05 }}
              transition={{ type: "spring", stiffness: 300 }}
            >
              <motion.span
                className="text-4xl"
                animate={{
                  y: [0, -5, 0],
                }}
                transition={{ duration: 3, repeat: Infinity }}
              >
                🔍
              </motion.span>
            </motion.div>

            {/* Pulse ring */}
            <motion.div
              className="absolute inset-0 rounded-2xl border-2 border-white/0"
              animate={{
                scale: [1, 1.2, 1],
                opacity: [0, 0.5, 0],
                borderColor: ["#ffffff00", "#ffffff", "#ffffff00"],
              }}
              transition={{ duration: 2, repeat: Infinity }}
            />
          </div>

          {/* Title */}
          <h3 className="text-xl font-bold text-white text-center mb-4">
            Bulk Verification
          </h3>

          {/* Stats */}
          <div className="border-t border-white/20 pt-4">
            <div className="flex justify-between items-center text-sm mb-3">
              <span className="text-white/80">Processing Speed</span>
              <motion.span
                className="text-white font-semibold"
                animate={{ opacity: [0.7, 1, 0.7] }}
                transition={{ duration: 2, repeat: Infinity }}
              >
                10K/sec
              </motion.span>
            </div>
            <div className="flex justify-between items-center text-sm">
              <span className="text-white/80">Accuracy Rate</span>
              <motion.span
                className="text-white font-semibold"
                animate={{ opacity: [0.7, 1, 0.7] }}
                transition={{ duration: 2, delay: 0.5, repeat: Infinity }}
              >
                99.9%
              </motion.span>
            </div>
          </div>

          {/* Hover line */}
          <motion.div
            className="absolute bottom-0 left-0 h-0.5 bg-white"
            initial={{ width: 0 }}
            whileHover={{ width: "100%" }}
            transition={{ duration: 0.3 }}
          />
        </div>
      </motion.div>

      {/* Feature Card 2 - Catch-all Detection */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ delay: 0.2 }}
        whileHover={{ y: -10 }}
        className="group relative"
      >
        <motion.div
          className="absolute -inset-0.5 bg-gradient-to-r from-[#2CA1AE] via-[#6ad8df] to-[#1b7c8d] rounded-2xl opacity-0 group-hover:opacity-30 blur transition-all duration-500"
          animate={{
            background: [
              "linear-gradient(90deg, #2CA1AE, #6ad8df, #1b7c8d)",
              "linear-gradient(180deg, #2CA1AE, #6ad8df, #1b7c8d)",
              "linear-gradient(270deg, #2CA1AE, #6ad8df, #1b7c8d)",
            ],
          }}
          transition={{ duration: 4, repeat: Infinity }}
        />

        <div className="relative bg-gradient-to-r from-[#2CA1AE] to-[#1b7c8d] rounded-2xl p-8 shadow-xl overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

          <div className="relative mb-6">
            <motion.div
              className="w-20 h-20 mx-auto bg-white/20 rounded-2xl flex items-center justify-center border border-white/30 backdrop-blur-sm"
              whileHover={{ rotate: 5, scale: 1.05 }}
              transition={{ type: "spring", stiffness: 300 }}
            >
              <motion.span
                className="text-4xl"
                animate={{
                  y: [0, -5, 0],
                }}
                transition={{ duration: 3, delay: 0.2, repeat: Infinity }}
              >
                🛡️
              </motion.span>
            </motion.div>
            <motion.div
              className="absolute inset-0 rounded-2xl border-2 border-white/0"
              animate={{
                scale: [1, 1.2, 1],
                opacity: [0, 0.5, 0],
                borderColor: ["#ffffff00", "#ffffff", "#ffffff00"],
              }}
              transition={{ duration: 2, delay: 0.3, repeat: Infinity }}
            />
          </div>

          <h3 className="text-xl font-bold text-white text-center mb-4">
            Catch-all Detection
          </h3>

          <div className="border-t border-white/20 pt-4">
            <div className="flex justify-between items-center text-sm mb-3">
              <span className="text-white/80">Detected</span>
              <motion.span
                className="text-white font-semibold"
                animate={{ opacity: [0.7, 1, 0.7] }}
                transition={{ duration: 2, delay: 0.2, repeat: Infinity }}
              >
                +2,250
              </motion.span>
            </div>
            <div className="flex justify-between items-center text-sm">
              <span className="text-white/80">Recovery Rate</span>
              <motion.span
                className="text-white font-semibold"
                animate={{ opacity: [0.7, 1, 0.7] }}
                transition={{ duration: 2, delay: 0.7, repeat: Infinity }}
              >
                27%
              </motion.span>
            </div>
          </div>

          <motion.div
            className="absolute bottom-0 left-0 h-0.5 bg-white"
            initial={{ width: 0 }}
            whileHover={{ width: "100%" }}
            transition={{ duration: 0.3 }}
          />
        </div>
      </motion.div>

      {/* Feature Card 3 - Real-time API */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ delay: 0.3 }}
        whileHover={{ y: -10 }}
        className="group relative"
      >
        <motion.div
          className="absolute -inset-0.5 bg-gradient-to-r from-[#2CA1AE] via-[#6ad8df] to-[#1b7c8d] rounded-2xl opacity-0 group-hover:opacity-30 blur transition-all duration-500"
          animate={{
            background: [
              "linear-gradient(90deg, #2CA1AE, #6ad8df, #1b7c8d)",
              "linear-gradient(180deg, #2CA1AE, #6ad8df, #1b7c8d)",
              "linear-gradient(270deg, #2CA1AE, #6ad8df, #1b7c8d)",
            ],
          }}
          transition={{ duration: 4, repeat: Infinity }}
        />

        <div className="relative bg-gradient-to-r from-[#2CA1AE] to-[#1b7c8d] rounded-2xl p-8 shadow-xl overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

          <div className="relative mb-6">
            <motion.div
              className="w-20 h-20 mx-auto bg-white/20 rounded-2xl flex items-center justify-center border border-white/30 backdrop-blur-sm"
              whileHover={{ rotate: 5, scale: 1.05 }}
              transition={{ type: "spring", stiffness: 300 }}
            >
              <motion.span
                className="text-4xl"
                animate={{
                  y: [0, -5, 0],
                }}
                transition={{ duration: 3, delay: 0.4, repeat: Infinity }}
              >
                ⚡
              </motion.span>
            </motion.div>
            <motion.div
              className="absolute inset-0 rounded-2xl border-2 border-white/0"
              animate={{
                scale: [1, 1.2, 1],
                opacity: [0, 0.5, 0],
                borderColor: ["#ffffff00", "#ffffff", "#ffffff00"],
              }}
              transition={{ duration: 2, delay: 0.6, repeat: Infinity }}
            />
          </div>

          <h3 className="text-xl font-bold text-white text-center mb-4">
            Real-time API
          </h3>

          <div className="border-t border-white/20 pt-4">
            <div className="flex justify-between items-center text-sm mb-3">
              <span className="text-white/80">Response Time</span>
              <motion.span
                className="text-white font-semibold"
                animate={{ opacity: [0.7, 1, 0.7] }}
                transition={{ duration: 2, delay: 0.4, repeat: Infinity }}
              >
                &lt;100ms
              </motion.span>
            </div>
            <div className="flex justify-between items-center text-sm">
              <span className="text-white/80">Uptime SLA</span>
              <motion.span
                className="text-white font-semibold"
                animate={{ opacity: [0.7, 1, 0.7] }}
                transition={{ duration: 2, delay: 0.9, repeat: Infinity }}
              >
                99.99%
              </motion.span>
            </div>
          </div>

          <motion.div
            className="absolute bottom-0 left-0 h-0.5 bg-white"
            initial={{ width: 0 }}
            whileHover={{ width: "100%" }}
            transition={{ duration: 0.3 }}
          />
        </div>
      </motion.div>

      {/* Feature Card 4 - Analytics */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ delay: 0.4 }}
        whileHover={{ y: -10 }}
        className="group relative"
      >
        <motion.div
          className="absolute -inset-0.5 bg-gradient-to-r from-[#2CA1AE] via-[#6ad8df] to-[#1b7c8d] rounded-2xl opacity-0 group-hover:opacity-30 blur transition-all duration-500"
          animate={{
            background: [
              "linear-gradient(90deg, #2CA1AE, #6ad8df, #1b7c8d)",
              "linear-gradient(180deg, #2CA1AE, #6ad8df, #1b7c8d)",
              "linear-gradient(270deg, #2CA1AE, #6ad8df, #1b7c8d)",
            ],
          }}
          transition={{ duration: 4, repeat: Infinity }}
        />

        <div className="relative bg-gradient-to-r from-[#2CA1AE] to-[#1b7c8d] rounded-2xl p-8 shadow-xl overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

          <div className="relative mb-6">
            <motion.div
              className="w-20 h-20 mx-auto bg-white/20 rounded-2xl flex items-center justify-center border border-white/30 backdrop-blur-sm"
              whileHover={{ rotate: 5, scale: 1.05 }}
              transition={{ type: "spring", stiffness: 300 }}
            >
              <motion.span
                className="text-4xl"
                animate={{
                  y: [0, -5, 0],
                }}
                transition={{ duration: 3, delay: 0.6, repeat: Infinity }}
              >
                📊
              </motion.span>
            </motion.div>
            <motion.div
              className="absolute inset-0 rounded-2xl border-2 border-white/0"
              animate={{
                scale: [1, 1.2, 1],
                opacity: [0, 0.5, 0],
                borderColor: ["#ffffff00", "#ffffff", "#ffffff00"],
              }}
              transition={{ duration: 2, delay: 0.9, repeat: Infinity }}
            />
          </div>

          <h3 className="text-xl font-bold text-white text-center mb-4">
            Analytics
          </h3>

          <div className="border-t border-white/20 pt-4">
            <div className="flex justify-between items-center text-sm mb-3">
              <span className="text-white/80">Data Points</span>
              <motion.span
                className="text-white font-semibold"
                animate={{ opacity: [0.7, 1, 0.7] }}
                transition={{ duration: 2, delay: 0.6, repeat: Infinity }}
              >
                50+
              </motion.span>
            </div>
            <div className="flex justify-between items-center text-sm">
              <span className="text-white/80">Report Types</span>
              <motion.span
                className="text-white font-semibold"
                animate={{ opacity: [0.7, 1, 0.7] }}
                transition={{ duration: 2, delay: 1.1, repeat: Infinity }}
              >
                12
              </motion.span>
            </div>
          </div>

          <motion.div
            className="absolute bottom-0 left-0 h-0.5 bg-white"
            initial={{ width: 0 }}
            whileHover={{ width: "100%" }}
            transition={{ duration: 0.3 }}
          />
        </div>
      </motion.div>

      {/* Feature Card 5 - CRM Integration */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ delay: 0.5 }}
        whileHover={{ y: -10 }}
        className="group relative"
      >
        <motion.div
          className="absolute -inset-0.5 bg-gradient-to-r from-[#2CA1AE] via-[#6ad8df] to-[#1b7c8d] rounded-2xl opacity-0 group-hover:opacity-30 blur transition-all duration-500"
          animate={{
            background: [
              "linear-gradient(90deg, #2CA1AE, #6ad8df, #1b7c8d)",
              "linear-gradient(180deg, #2CA1AE, #6ad8df, #1b7c8d)",
              "linear-gradient(270deg, #2CA1AE, #6ad8df, #1b7c8d)",
            ],
          }}
          transition={{ duration: 4, repeat: Infinity }}
        />

        <div className="relative bg-gradient-to-r from-[#2CA1AE] to-[#1b7c8d] rounded-2xl p-8 shadow-xl overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

          <div className="relative mb-6">
            <motion.div
              className="w-20 h-20 mx-auto bg-white/20 rounded-2xl flex items-center justify-center border border-white/30 backdrop-blur-sm"
              whileHover={{ rotate: 5, scale: 1.05 }}
              transition={{ type: "spring", stiffness: 300 }}
            >
              <motion.span
                className="text-4xl"
                animate={{
                  y: [0, -5, 0],
                }}
                transition={{ duration: 3, delay: 0.8, repeat: Infinity }}
              >
                🔄
              </motion.span>
            </motion.div>
            <motion.div
              className="absolute inset-0 rounded-2xl border-2 border-white/0"
              animate={{
                scale: [1, 1.2, 1],
                opacity: [0, 0.5, 0],
                borderColor: ["#ffffff00", "#ffffff", "#ffffff00"],
              }}
              transition={{ duration: 2, delay: 1.2, repeat: Infinity }}
            />
          </div>

          <h3 className="text-xl font-bold text-white text-center mb-4">
            CRM Integration
          </h3>

          <div className="border-t border-white/20 pt-4">
            <div className="flex justify-between items-center text-sm mb-3">
              <span className="text-white/80">Integrations</span>
              <motion.span
                className="text-white font-semibold"
                animate={{ opacity: [0.7, 1, 0.7] }}
                transition={{ duration: 2, delay: 0.8, repeat: Infinity }}
              >
                25+
              </motion.span>
            </div>
            <div className="flex justify-between items-center text-sm">
              <span className="text-white/80">Setup Time</span>
              <motion.span
                className="text-white font-semibold"
                animate={{ opacity: [0.7, 1, 0.7] }}
                transition={{ duration: 2, delay: 1.3, repeat: Infinity }}
              >
                &lt;5min
              </motion.span>
            </div>
          </div>

          <motion.div
            className="absolute bottom-0 left-0 h-0.5 bg-white"
            initial={{ width: 0 }}
            whileHover={{ width: "100%" }}
            transition={{ duration: 0.3 }}
          />
        </div>
      </motion.div>

      {/* Feature Card 6 - Enterprise Security */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ delay: 0.6 }}
        whileHover={{ y: -10 }}
        className="group relative"
      >
        <motion.div
          className="absolute -inset-0.5 bg-gradient-to-r from-[#2CA1AE] via-[#6ad8df] to-[#1b7c8d] rounded-2xl opacity-0 group-hover:opacity-30 blur transition-all duration-500"
          animate={{
            background: [
              "linear-gradient(90deg, #2CA1AE, #6ad8df, #1b7c8d)",
              "linear-gradient(180deg, #2CA1AE, #6ad8df, #1b7c8d)",
              "linear-gradient(270deg, #2CA1AE, #6ad8df, #1b7c8d)",
            ],
          }}
          transition={{ duration: 4, repeat: Infinity }}
        />

        <div className="relative bg-gradient-to-r from-[#2CA1AE] to-[#1b7c8d] rounded-2xl p-8 shadow-xl overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

          <div className="relative mb-6">
            <motion.div
              className="w-20 h-20 mx-auto bg-white/20 rounded-2xl flex items-center justify-center border border-white/30 backdrop-blur-sm"
              whileHover={{ rotate: 5, scale: 1.05 }}
              transition={{ type: "spring", stiffness: 300 }}
            >
              <motion.span
                className="text-4xl"
                animate={{
                  y: [0, -5, 0],
                }}
                transition={{ duration: 3, delay: 1.0, repeat: Infinity }}
              >
                🔒
              </motion.span>
            </motion.div>
            <motion.div
              className="absolute inset-0 rounded-2xl border-2 border-white/0"
              animate={{
                scale: [1, 1.2, 1],
                opacity: [0, 0.5, 0],
                borderColor: ["#ffffff00", "#ffffff", "#ffffff00"],
              }}
              transition={{ duration: 2, delay: 1.5, repeat: Infinity }}
            />
          </div>

          <h3 className="text-xl font-bold text-white text-center mb-4">
            Enterprise Security
          </h3>

          <div className="border-t border-white/20 pt-4">
            <div className="flex justify-between items-center text-sm mb-3">
              <span className="text-white/80">Encryption</span>
              <motion.span
                className="text-white font-semibold"
                animate={{ opacity: [0.7, 1, 0.7] }}
                transition={{ duration: 2, delay: 1.0, repeat: Infinity }}
              >
                AES-256
              </motion.span>
            </div>
            <div className="flex justify-between items-center text-sm">
              <span className="text-white/80">Compliance</span>
              <motion.span
                className="text-white font-semibold"
                animate={{ opacity: [0.7, 1, 0.7] }}
                transition={{ duration: 2, delay: 1.5, repeat: Infinity }}
              >
                SOC2, GDPR
              </motion.span>
            </div>
          </div>

          <motion.div
            className="absolute bottom-0 left-0 h-0.5 bg-white"
            initial={{ width: 0 }}
            whileHover={{ width: "100%" }}
            transition={{ duration: 0.3 }}
          />
        </div>
      </motion.div>
    </div>

    {/* Bottom CTA - REMOVED as requested */}
  </div>
</motion.section>
      {/* Pricing Calculator Section */}
      <motion.section
        id="pricing"
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true }}
        className="bg-[#f4f6f7] py-24 relative overflow-hidden"
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.8, x: 100, y: 100, rotate: -35 }}
          animate={{ opacity: 1, scale: 1, x: -1000, y: -600, rotate: -35 }}
          transition={{ duration: 1.5, delay: 0.2, ease: "easeOut" }}
          className="absolute right-[5%] -bottom-[50%] w-[1200px] h-[450px] bg-[#2ca1ae] rounded-full pointer-events-none z-0"
        />
        <motion.div
          initial={{ opacity: 0, scale: 0.8, x: 100, y: 100, rotate: -35 }}
          animate={{ opacity: 1, scale: 1, x: -1000, y: -600, rotate: -35 }}
          transition={{ duration: 1.5, ease: "aseOut" }}
          className="absolute -right-[10%] -bottom-[55%] w-[1200px] h-[450px] bg-[#1b7c8d] rounded-full pointer-events-none z-0"
        />
        <div className="max-w-6xl mx-auto px-6 grid md:grid-cols-2 gap-10 items-stretch">
          {/* LEFT CARD */}
          <Reveal direction="up">
            <motion.div
              className="bg-gradient-to-b from-white via-white to-[#abdbdf] rounded-[24px] rounded-br-none shadow-xl p-10 relative border-b-[8px] border-b-[#2da0ad] h-full flex flex-col justify-between"
              whileHover={{
                y: -10,
                boxShadow: "0 30px 60px rgba(0,0,0,0.1)"
              }}
              transition={{ duration: 0.3 }}
            >
              <h3 className="text-xl font-semibold text-center text-[#4a5f74]">
                How many emails do you have?
              </h3>

              <motion.div
                className="mt-6 border border-[#2da0ad] rounded-xl py-4 text-center text-xl font-bold text-[#4a5f74]"
              >
                <AnimatedCounter from={0} to={2000000} duration={2} />
              </motion.div>

              <div className="mt-8 relative pt-2">
                <input
                  type="range"
                  min="1000"
                  max="5000000"
                  defaultValue="2000000"
                  className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-[#2da0ad]"
                />
                <div className="flex justify-between text-[#8b9cac] mt-2 text-xs font-medium">
                  <span>1000</span>
                  <span>5M</span>
                </div>
              </div>

              <p className="text-center mt-6 text-[#8b9cac] text-sm">
                or, select an amount...
              </p>

              <div className="grid grid-cols-4 gap-4 mt-6">
                {["5k", "50K", "100K", "250K", "500K", "1M", "2M", "5M"].map((item, index) => (
                  <motion.button
                    key={index}
                    whileHover={{ scale: 1.05, y: -2 }}
                    whileTap={{ scale: 0.95 }}
                    className={`rounded-2xl py-5 text-xl font-bold shadow-sm transition border ${item === "2M"
                      ? "bg-[#2da0ad] text-white border-[#2da0ad]"
                      : "bg-white text-[#2a4563] border-gray-100 hover:border-[#2da0ad]"
                      }`}
                  >
                    {item}
                  </motion.button>
                ))}
              </div>
            </motion.div>
          </Reveal>

          {/* RIGHT CARD */}
          <Reveal direction="up" delay={0.2}>
            <motion.div
              className="bg-white rounded-[24px] rounded-br-[64px] shadow-xl pt-10 pb-6 px-10 relative overflow-hidden bg-gradient-to-b from-white via-white to-[#abdbdf] border border-white h-full flex flex-col justify-between"
              whileHover={{
                y: -10,
                boxShadow: "0 30px 60px rgba(0,0,0,0.1)"
              }}
              transition={{ duration: 0.3 }}
            >
              <div className="flex items-center gap-3 text-sm text-[#4a5f74] font-medium justify-center whitespace-nowrap">
                <span>Pay-As-You-Go</span>
                <div className="w-10 h-5 bg-[#d8ebed] rounded-full relative cursor-pointer flex items-center px-1">
                  <motion.div className="w-3.5 h-3.5 bg-[#2da0ad] rounded-full absolute right-1" />
                </div>
                <span className="text-[#13324f] font-bold">Monthly</span>
              </div>

              <div className="text-center mt-6">
                <p className="line-through text-[#8b9cac] text-lg font-medium inline-block mr-2">
                  $800.00
                </p>
                <div className="flex flex-col items-center">
                  <motion.h2
                    className="text-6xl font-extrabold text-[#113250] tracking-tight -mt-1"
                  >
                    $736.00
                  </motion.h2>
                  <p className="text-center text-white bg-[#2da0ad] mt-2 text-sm px-3 rounded-full font-medium inline-block mx-auto border border-white">
                    Save $64.00
                  </p>
                </div>
              </div>

              <div className="flex justify-center items-center w-full mt-6 mb-4 text-[#13324f]">
                <div className="text-center pr-8 border-r border-[#8b9cac]/30">
                  <p className="text-sm font-semibold mb-1 uppercase text-[#8b9cac] text-xs tracking-wider">ANNUAL</p>
                  <p className="text-xl font-bold">$736.00</p>
                  <p className="text-[#8b9cac] text-xs">Credit</p>
                </div>
                <div className="text-center pl-8">
                  <p className="text-sm font-semibold mb-1 uppercase text-[#8b9cac] text-xs tracking-wider">MONTHLY</p>
                  <p className="text-xl font-bold">$0.0004</p>
                  <p className="text-[#8b9cac] text-xs">Cost per credit</p>
                </div>
              </div>

              <MagneticButton className="w-full mt-4 bg-[#113250] text-white py-4 rounded-3xl text-lg font-semibold shadow-lg hover:bg-[#0a233b]">
                Get Started Free!
              </MagneticButton>

              <p className="text-center text-xs text-[#4a5f74] mt-3 font-medium">
                Includes 100 free credits
              </p>

              <div className="w-full mt-6">
                <ul className="space-y-3 text-[#2da0ad] text-sm font-medium tracking-tight">
                  {[
                    "No Monthly Payments",
                    "Credits Never Expire",
                    "No Upfront Fee",
                    "All Prices Include Taxes And Fees."
                  ].map((feature, index) => (
                    <motion.li
                      key={index}
                      className="flex items-start gap-2"
                      whileHover={{ x: 5 }}
                      transition={{ duration: 0.2 }}
                    >
                      <svg className="w-5 h-5 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      {feature}
                    </motion.li>
                  ))}
                </ul>
              </div>

              <div className="mt-8 text-center text-xs font-bold text-[#113250]">
                <p>We support</p>
                <div className="flex justify-center gap-2 mt-3 text-xs w-full max-w-[240px] mx-auto">
                  {["PayPal", "VISA", "stripe", "AMEX"].map((payment, index) => (
                    <motion.span
                      key={index}
                      className="flex-1 py-1.5 bg-white text-[#113250] rounded border border-gray-200 font-bold uppercase"
                      whileHover={{ scale: 1.1, y: -2 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      {payment}
                    </motion.span>
                  ))}
                </div>
              </div>
            </motion.div>
          </Reveal>
        </div>
      </motion.section>

      {/* Enterprise FAQ Section */}
      <motion.section
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true }}
        className="bg-white pt-28 pb-96 relative overflow-hidden"
      >
        <div className="max-w-5xl mx-auto px-6 text-center">
          <motion.h2
            initial={{ scale: 0.8, opacity: 0 }}
            whileInView={{ scale: 1, opacity: 1 }}
            viewport={{ once: true }}
            transition={{ type: "spring", stiffness: 100 }}
            className="text-4xl font-bold text-black"
          >
            Enterprise Email Validation — FAQ
          </motion.h2>

          <motion.p
            initial={{ y: 20, opacity: 0 }}
            whileInView={{ y: 0, opacity: 1 }}
            viewport={{ once: true }}
            transition={{ delay: 0.2 }}
            className="text-gray-600 text-lg mt-6 leading-relaxed max-w-3xl mx-auto"
          >
            Answers to the most common questions about scaling, securing, and integrating enterprise-grade email validation.
          </motion.p>
        </div>

        <Reveal direction="up" className="relative z-10">
          <FAQAccordion />
        </Reveal>

        {/* Footer Shapes & Background */}
        <motion.div
          initial={{ opacity: 0, scale: 0.8, x: 100, y: 100, rotate: 35 }}
          animate={{ opacity: 1, scale: 1, x: 800, y: -150, rotate: 35 }}
          transition={{ duration: 1.5, delay: 0.2, ease: "easeOut" }}
          className="absolute right-[10%] -bottom-[45%] w-[1160px] h-[434px] bg-[#2ca1ae] rounded-full pointer-events-none z-0"
        />
        <motion.div
          initial={{ opacity: 0, scale: 0.8, x: 100, y: 100, rotate: 35 }}
          animate={{ opacity: 1, scale: 1, x: 300, y: -100, rotate: 35 }}
          transition={{ duration: 1.5, ease: "easeOut" }}
          className="absolute -right-[10%] -bottom-[40%] w-[1200px] h-[450px] bg-[#1b7c8d] rounded-full pointer-events-none z-0"
        />


      </motion.section>

      {/* Footer / Data Protection Area */}
      <motion.footer
        className="relative bg-gradient-to-b from-white via-[#eaf4f5] to-[#aedee3] pt-32 pb-24 overflow-hidden"
      >
        <div className="flex flex-wrap justify-center gap-x-12 gap-y-4 text-[#115b6d] font-medium text-[15px] mt-10 z-10 relative">
          <a href="#" className="hover:text-teal-700 transition">Data Protection Policy</a>
          <a href="#" className="hover:text-teal-700 transition">Privacy Policy</a>
          <a href="#" className="hover:text-teal-700 transition">Terms and Conditions</a>
        </div>

        {/* Floating Chat Button */}
        <motion.button
          whileHover={{ scale: 1.1 }}
          whileTap={{ scale: 0.9 }}
          className="fixed bottom-8 right-8 w-[68px] h-[68px] bg-[#115b6d] rounded-full shadow-[0_10px_30px_rgba(17,91,109,0.4)] flex items-center justify-center z-50 text-white cursor-pointer"
        >
          <svg className="w-8 h-8" viewBox="0 0 24 24" fill="white">
            <path d="M3 8a3 3 0 0 1 3-3h12a3 3 0 0 1 3 3v8a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3V8zm5 5h8v-2H8v2z" />
          </svg>
        </motion.button>
      </motion.footer>
    </motion.div>
  );
}

function FAQAccordion() {
  const [activeIndex, setActiveIndex] = useState(null);

  const faqs = [
    {
      question: "What makes your email validation solution enterprise-grade?",
      answer:
        "Our platform uses advanced SMTP checks, AI-powered detection, and real-time verification infrastructure designed to handle millions of emails securely and efficiently.",
    },
    {
      question: "How secure is the data we upload?",
      answer:
        "We use enterprise-level encryption (SSL/TLS), secure servers, and strict data handling policies.",
    },
    {
      question: "Can we integrate email validation into our internal systems?",
      answer:
        "Yes, we provide REST APIs and integration support.",
    },
    {
      question: "Is onboarding and support included for enterprise clients?",
      answer:
        "Enterprise clients receive dedicated onboarding and priority support.",
    },
    {
      question: "How is pricing structured for enterprise volumes?",
      answer:
        "Pricing is flexible and volume-based with custom enterprise plans.",
    },
  ];

  return (
    <div className="max-w-5xl mx-auto mt-16 px-6">
      <motion.div
        className="bg-white rounded-3xl shadow-xl divide-y"
        variants={{
          hidden: { opacity: 0 },
          visible: {
            opacity: 1,
            transition: {
              staggerChildren: 0.1
            }
          }
        }}
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true }}
      >
        {faqs.map((faq, index) => (
          <motion.div
            key={index}
            variants={{
              hidden: { y: 20, opacity: 0 },
              visible: { y: 0, opacity: 1 }
            }}
            className="p-6"
          >
            <motion.button
              onClick={() => setActiveIndex(activeIndex === index ? null : index)}
              className="w-full flex justify-between items-center text-left"
              whileHover={{ x: 5 }}
              whileTap={{ scale: 0.99 }}
            >
              <span
                className={`text-lg font-medium ${activeIndex === index ? "text-teal-700" : "text-gray-800"
                  }`}
              >
                {faq.question}
              </span>

              <motion.span
                animate={{ rotate: activeIndex === index ? 180 : 0 }}
                transition={{ duration: 0.3 }}
                className="text-teal-600"
              >
                ▼
              </motion.span>
            </motion.button>

            <AnimatePresence>
              {activeIndex === index && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.3 }}
                  className="overflow-hidden"
                >
                  <p className="text-gray-600 text-sm mt-4">
                    {faq.answer}
                  </p>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        ))}
      </motion.div>
    </div>
  );
}