const { checkDomain } = require("./validators/domain");
const { checkMx } = require("./validators/mx");

async function testV2() {
  const domains = ["gmail.com", "sphurti.net", "yahoo.com"];
  
  console.log("Running V2 Validation Tests...");

  for (const d of domains) {
      console.log(`\nTesting: ${d}`);
      
      const domainValid = await checkDomain(d);
      console.log(`  - Domain Valid (dns.lookup): ${domainValid}`);
      
      if (domainValid) {
          const mx = await checkMx(d);
          console.log(`  - MX Valid: ${mx.valid}`);
          if (mx.valid) {
              console.log(`    Records: ${mx.mx.length}`);
          }
      }
  }
}

testV2();
