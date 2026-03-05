const dns = require("dns");
const net = require("net");

// Generate random email ID
function randomEmail(domain) {
  const random = Math.random().toString(36).substring(2, 12);
  return `${random}@${domain}`;
}

function smtpCheck(email, host) {
  return new Promise((resolve) => {
    const socket = net.createConnection(25, host);
    let step = 0;

    socket.on("data", (data) => {
      const msg = data.toString();

      if (step === 0 && msg.startsWith("220")) {
        socket.write("HELO test.com\r\n");
        step++;
      } 
      else if (step === 1 && msg.startsWith("250")) {
        socket.write("MAIL FROM:<check@test.com>\r\n");
        step++;
      } 
      else if (step === 2 && msg.includes("250")) {
        socket.write(`RCPT TO:<${email}>\r\n`);
        step++;
      } 
      else if (step === 3) {
        if (msg.startsWith("250")) {
          resolve(true);   // server accepts email
        } else {
          resolve(false);  // rejected
        }
        socket.end();
      }
    });

    socket.on("error", () => resolve(false));
  });
}

exports.checkCatchAll = async (email) => {
  const domain = email.split("@")[1];

  // Step 1: Get MX
  const mxHost = await new Promise((resolve, reject) => {
    dns.resolveMx(domain, (err, addresses) => {
      if (err || !addresses.length) reject(null);
      else resolve(addresses[0].exchange);
    });
  }).catch(() => null);

  if (!mxHost) return { catchAll: false };

  // Step 2: Test real mailbox
  const realCheck = await smtpCheck(email, mxHost);

  // Step 3: Test fake mailbox
  const fakeEmail = randomEmail(domain);
  const fakeCheck = await smtpCheck(fakeEmail, mxHost);

  // Step 4: Determine catch-all
  if (realCheck && fakeCheck) {
    return { catchAll: true };
  }

  return { catchAll: false };
};
