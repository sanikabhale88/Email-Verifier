// Quick MongoDB connection test
require('dotenv').config();
const mongoose = require('mongoose');

async function testConnection() {
  try {
    console.log('🔄 Testing MongoDB connection...');
    console.log(`Connection string: ${process.env.MONGO_URI?.substring(0, 60)}...`);
    
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
    });
    
    console.log('✅ Connection successful!');
    console.log(`Host: ${mongoose.connection.host}`);
    console.log(`Database: ${mongoose.connection.name}`);
    process.exit(0);
  } catch (error) {
    console.error('❌ Connection failed:', error.message);
    
    if (error.message.includes('timeout')) {
      console.error('\n💡 Server Selection Timeout usually means:');
      console.error('1. Your IP address is NOT whitelisted in MongoDB Atlas');
      console.error('2. Go to MongoDB Atlas → Network Access → Add IP Address');
      console.error('3. Add 0.0.0.0/0 for development (allows all IPs)');
      console.error('4. Or add your current IP address');
    }
    
    process.exit(1);
  }
}

testConnection();
