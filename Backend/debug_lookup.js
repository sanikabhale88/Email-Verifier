const dns = require("dns");

console.log("Current DNS Servers:", dns.getServers());

// Test 1: dns.lookup (OS Resolver)
console.log("\n--- Testing dns.lookup ---");
dns.lookup("gmail.com", (err, address) => {
    console.log(`lookup gmail.com: ${err ? err.message : address}`);
});

dns.lookup("sphurti.net", (err, address) => {
    console.log(`lookup sphurti.net: ${err ? err.message : address}`);
});

// Test 2: Force Public DNS
setTimeout(() => {
    console.log("\n--- Testing dns.resolve with 8.8.8.8 ---");
    try {
        dns.setServers(["8.8.8.8"]);
        console.log("Set DNS to 8.8.8.8");
        
        dns.resolveMx("sphurti.net", (err, addresses) => {
             console.log(`resolveMx sphurti.net (8.8.8.8): ${err ? err.message : JSON.stringify(addresses)}`);
        });

    } catch (e) {
        console.log("Error setting servers:", e.message);
    }
}, 2000);
