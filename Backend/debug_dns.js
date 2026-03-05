const dns = require("dns");

const domains = ["gmail.com", "sphurti.net", "yahoo.com"];

console.log("Starting DNS Debug...");

domains.forEach(domain => {
    // 1. Check A Record
    dns.resolve(domain, 'A', (err, addresses) => {
        if (err) {
            console.log(`[A] ${domain} FAILED: ${err.code} - ${err.message}`);
        } else {
            console.log(`[A] ${domain} SUCCESS: ${JSON.stringify(addresses)}`);
        }
    });

    // 2. Check MX Record
    dns.resolve(domain, 'MX', (err, addresses) => {
        if (err) {
            console.log(`[MX] ${domain} FAILED: ${err.code} - ${err.message}`);
        } else {
            console.log(`[MX] ${domain} SUCCESS: Found ${addresses.length} records`);
        }
    });
});
