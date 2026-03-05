const dns = require("dns");
const net = require("net");

// ── Use fast DNS servers ──
dns.setServers(["1.1.1.1", "8.8.8.8"]);

// ── MX Cache — same domain never looked up twice ──
const mxCache = new Map();

// ── SMTP Cache — same email never checked twice ──
const smtpCache = new Map();

// ── Prefetch all MX records in parallel before bulk validation ──
exports.prefetchMx = async (emails) => {
  const domains = [
    ...new Set(
      emails
        .filter((e) => e && e.includes("@") && e.split("@").length === 2)
        .map((e) => e.split("@")[1].toLowerCase())
    ),
  ];
  await Promise.all(domains.map(getMx));
};

// ── Cached MX lookup ──
function getMx(domain) {
  if (mxCache.has(domain)) return Promise.resolve(mxCache.get(domain));

  return new Promise((resolve) => {
    dns.resolveMx(domain, (err, addresses) => {
      if (err || !addresses || !addresses.length) {
        mxCache.set(domain, null);
        resolve(null);
      } else {
        const host = addresses.sort((a, b) => a.priority - b.priority)[0].exchange;
        mxCache.set(domain, host);
        resolve(host);
      }
    });
  });
}

// ── Bounce Code Classification (Supports Standard + Enhanced Codes) ──
const classifyBounce = (code) => {
  if (!code) return "Unknown";

  const codeStr  = code.toString().trim();
  const mainDigit = codeStr[0];

  const hardCodes = [
    "500","501","502","503","504",
    "510","511","512","513","523",
    "530","541","550","551","552",
    "553","554",
  ];
  const softCodes = [
    "420","421","422","431","432",
    "441","442","446","447","449",
    "450","451","452","471",
  ];

  if (hardCodes.includes(codeStr)) return "Hard";
  if (softCodes.includes(codeStr)) return "Soft";

  // Enhanced Bounce Codes e.g. 5.1.1
  if (codeStr.includes(".")) {
    if (codeStr.startsWith("4.")) return "Soft";
    if (codeStr.startsWith("5.")) return "Hard";
  }

  if (mainDigit === "5") return "Hard";
  if (mainDigit === "4") return "Soft";
  if (codeStr.startsWith("9")) return "Hard";

  return "Unknown";
};

// ── Raw SMTP check — original accurate logic, unchanged ──
function smtpCheck(email, mxHost) {
  return new Promise((resolve) => {
    const socket = net.createConnection(25, mxHost);
    socket.setTimeout(15000);

    let step = 0;
    let resolved = false;
    let finalResult = {
      smtp:       false,
      code:       "Unknown",
      bounceType: "Unknown",
      reason:     "Unknown error",
    };

    const done = (result) => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve(result);
      }
    };

    socket.on("data", (data) => {
      const msg       = data.toString();
      const codeMatch = msg.match(/^(\d{3})/);

      if (step === 0 && msg.startsWith("220")) {
        socket.write("HELO test.com\r\n");
        step++;
        return;
      }

      if (step === 1 && msg.startsWith("250")) {
        socket.write("MAIL FROM:<check@test.com>\r\n");
        step++;
        return;
      }

      if (step === 2 && msg.startsWith("250")) {
        socket.write(`RCPT TO:<${email}>\r\n`);
        step++;
        return;
      }

      if (step === 3) {
        if (codeMatch) {
          const code       = codeMatch[1];
          const bounceType = classifyBounce(code);

          if (code.startsWith("250")) {
            finalResult = { smtp: true,  code, bounceType: "None", reason: "OK" };
          } else {
            finalResult = { smtp: false, code, bounceType, reason: msg.trim() };
          }
        }
        socket.end();
      }
    });

    socket.on("timeout", () =>
      done({ smtp: false, code: "Timeout",          bounceType: "Soft", reason: "SMTP connection timeout" })
    );
    socket.on("error",   () =>
      done({ smtp: false, code: "Connection Error", bounceType: "Soft", reason: "SMTP connection error"   })
    );
    socket.on("close",   () => done(finalResult));
  });
}

// ── Main exported function ──
exports.checkSMTP = async (email) => {
  // Guard
  if (!email || !email.includes("@")) {
    return { smtp: false, code: "Invalid", bounceType: "Hard", reason: "Invalid email format" };
  }
  const parts = email.split("@");
  if (parts.length !== 2 || !parts[1]) {
    return { smtp: false, code: "Invalid", bounceType: "Hard", reason: "Invalid email format" };
  }

  const domain = parts[1].toLowerCase();

  // Cache hit — return instantly
  if (smtpCache.has(email)) return smtpCache.get(email);

  // Cached MX lookup
  const mxHost = await getMx(domain);

  if (!mxHost) {
    const result = { smtp: false, code: "No MX", bounceType: "Hard", reason: "No MX server found" };
    smtpCache.set(email, result);
    return result;
  }

  // Real SMTP check — original accurate logic
  const result = await smtpCheck(email, mxHost);
  smtpCache.set(email, result);
  return result;
};