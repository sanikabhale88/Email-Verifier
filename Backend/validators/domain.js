const dns = require("dns");

exports.checkDomain = (domain) => {
  return new Promise((resolve) => {
    dns.lookup(domain, (err) => {
      // dns.lookup uses the OS resolver (getaddrinfo), which is more robust
      // against local DNS config issues than dns.resolve (c-ares).
      // If it finds an address, the domain exists.
      resolve(!err);
    });
  });
};
