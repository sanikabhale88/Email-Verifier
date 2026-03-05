const dns = require("dns");

const { Resolver } = require("dns");

exports.checkMx = (domain) => {
  return new Promise((resolve) => {
    // Helper to try resolving with a specific resolver instance
    const attemptResolve = (resolverInstance, isRetry = false) => {
      resolverInstance.resolveMx(domain, (err, addresses) => {
        if (err || !addresses || addresses.length === 0) {
          if (!isRetry) {
             // If default failed, try Google DNS explicitly
             const googleResolver = new Resolver();
             googleResolver.setServers(['8.8.8.8', '8.8.4.4']);
             attemptResolve(googleResolver, true);
          } else {
             // Both failed
             resolve({ valid: false });
          }
        } else {
          resolve({ valid: true, mx: addresses });
        }
      });
    };

    attemptResolve(dns);
  });
};
