const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    // Check if MONGO_URI is set
    if (!process.env.MONGO_URI) {
      console.error("❌ MongoDB Connection Error: MONGO_URI is not set in .env file");
      console.error("Please add MONGO_URI to your .env file");
      console.error("Example: MONGO_URI=mongodb://localhost:27017/email-verifier");
      process.exit(1);
    }

    // Validate connection string format
    const mongoUri = process.env.MONGO_URI.trim();
    if (!mongoUri.startsWith("mongodb://") && !mongoUri.startsWith("mongodb+srv://")) {
      console.error("❌ MongoDB Connection Error: Invalid MONGO_URI format");
      console.error("MONGO_URI must start with 'mongodb://' or 'mongodb+srv://'");
      console.error(`Current value: ${mongoUri.substring(0, 20)}...`);
      process.exit(1);
    }

    console.log("🔄 Connecting to MongoDB...");
    console.log(`📍 Connection string: ${mongoUri.substring(0, 80)}...`);

    // Simplest, recommended Mongoose connection (lets the driver handle options from URI)
    const conn = await mongoose.connect(mongoUri);

    console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
    console.log(`✅ Database: ${conn.connection.name}`);
  } catch (error) {
    console.error(`❌ MongoDB Connection Error: ${error.message}`);
    
    // Provide specific error messages
    if (error.message.includes("querySrv")) {
      console.error("\n💡 DNS Resolution Error (querySrv):");
      console.error("This usually means:");
      console.error("1. Your network/firewall is blocking DNS queries");
      console.error("2. Try using a non-SRV connection string (mongodb:// instead of mongodb+srv://)");
      console.error("3. Check your internet connection");
      console.error("4. Try using a VPN if you're on a restricted network");
    } else if (error.message.includes("authentication")) {
      console.error("\n💡 Authentication Error:");
      console.error("1. Check your username and password in MONGO_URI");
      console.error("2. Make sure special characters in password are URL-encoded");
      console.error("3. Verify the user exists in MongoDB Atlas Database Access");
    } else if (error.message.includes("ECONNREFUSED") || error.message.includes("timeout")) {
      console.error("\n💡 Connection Timeout/Refused:");
      console.error("This usually means your IP is NOT whitelisted in MongoDB Atlas!");
      console.error("\n🔧 FIX THIS:");
      console.error("1. Go to: https://cloud.mongodb.com");
      console.error("2. Click 'Network Access' → 'Add IP Address'");
      console.error("3. Add: 0.0.0.0/0 (for development - allows all IPs)");
      console.error("   OR add your specific IP: 103.116.169.2/32");
      console.error("4. Wait 1-2 minutes after adding, then restart server");
      console.error("\n📝 Your current IP: 103.116.169.2");
    }
    
    console.error("\n💡 General Troubleshooting:");
    console.error("1. Verify your MONGO_URI in .env file is correct");
    console.error("2. For local MongoDB: mongodb://localhost:27017/email-verifier");
    console.error("3. For MongoDB Atlas: mongodb+srv://username:password@cluster.mongodb.net/email-verifier");
    console.error("4. Make sure there are no extra spaces or quotes in MONGO_URI");
    
    process.exit(1);
  }
};

module.exports = connectDB;
