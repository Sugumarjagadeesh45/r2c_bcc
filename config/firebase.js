// // config/firebase.js - Simplified version
// const admin = require('firebase-admin');

// console.log('\n=== FIREBASE INITIALIZATION ===');

// try {
//   // Try to load from JSON file first
//   let serviceAccount;
//   try {
//     serviceAccount = require('./serviceAccountKey.json');
//     console.log('✅ Loaded serviceAccountKey.json');
//   } catch (jsonError) {
//     console.log('❌ serviceAccountKey.json not found, trying env variables');
    
//     // Fallback to env variables
//     if (!process.env.FIREBASE_PRIVATE_KEY) {
//       throw new Error('No Firebase configuration found');
//     }
    
//     serviceAccount = {
//       type: process.env.FIREBASE_TYPE || "service_account",
//       project_id: process.env.FIREBASE_PROJECT_ID,
//       private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
//       private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
//       client_email: process.env.FIREBASE_CLIENT_EMAIL,
//       client_id: process.env.FIREBASE_CLIENT_ID,
//       auth_uri: process.env.FIREBASE_AUTH_URI || "https://accounts.google.com/o/oauth2/auth",
//       token_uri: process.env.FIREBASE_TOKEN_URI || "https://oauth2.googleapis.com/token",
//       auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL || "https://www.googleapis.com/oauth2/v1/certs",
//       client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
//       universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN || "googleapis.com"
//     };
//   }

//   // Initialize Firebase
//   if (!admin.apps.length) {
//     admin.initializeApp({
//       credential: admin.credential.cert(serviceAccount),
//       projectId: serviceAccount.project_id
//     });
//     console.log('✅ Firebase Admin SDK initialized');
//   }
  
// } catch (error) {
//   console.error('❌ Firebase initialization failed:', error.message);
//   console.error('FCM will not work until this is fixed');
// }

// module.exports = admin;


















// // D:\good_r2c-main\config\firebase.js
// const admin = require('firebase-admin');
// const fs = require('fs');
// const path = require('path');

// let firebaseInitialized = false;

// // Initialize Firebase Admin SDK
// function initializeFirebase() {
//   try {
//     if (firebaseInitialized || admin.apps.length > 0) {
//       console.log('✅ Firebase already initialized');
//       firebaseInitialized = true;
//       return admin;
//     }

//     const serviceAccountPath = path.join(__dirname, './serviceAccountKey.json');
//     const hasLocalFile = fs.existsSync(serviceAccountPath);

//     if (hasLocalFile) {
//       console.log('📁 Using local service-account-key.json for Firebase');
//       const serviceAccount = require(serviceAccountPath);
//       admin.initializeApp({
//         credential: admin.credential.cert(serviceAccount),
//         projectId: serviceAccount.project_id
//       });
//     } else if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_PRIVATE_KEY) {
//       console.log('🌍 Using .env variables for Firebase');
//       const privateKey = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
//       admin.initializeApp({
//         credential: admin.credential.cert({
//           projectId: process.env.FIREBASE_PROJECT_ID,
//           clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
//           privateKey,
//         }),
//       });
//     } else {
//       throw new Error('No Firebase credentials found');
//     }

//     firebaseInitialized = true;
//     console.log('✅ Firebase initialized successfully');
//     console.log('✅ Firebase apps count:', admin.apps.length);
    
//     // Test if messaging is available
//     if (admin.messaging) {
//       console.log('✅ Firebase messaging is available');
//     } else {
//       console.log('❌ Firebase messaging is NOT available');
//     }
    
//     return admin;

//   } catch (error) {
//     console.error('❌ Firebase initialization failed:', error.message);
//     return null;
//   }
// }

// // Initialize Firebase immediately
// const firebaseAdmin = initializeFirebase();

// // Firebase status
// function getFirebaseStatus() {
//   return {
//     initialized: firebaseInitialized,
//     appsCount: admin.apps.length,
//     method: process.env.FIREBASE_PROJECT_ID ? 'environment-variables' : 'service-account-file',
//     messagingAvailable: !!(admin.apps.length > 0 && admin.messaging)
//   };
// }

// // Exported properly
// module.exports = {
//   initializeFirebase,
//   admin: firebaseAdmin, // Make sure to export the initialized admin instance
//   getFirebaseStatus,
// };





















// config/firebase.js
const admin = require("firebase-admin");

function initFirebase() {
  if (admin.apps.length > 0) {
    return admin.apps[0];
  }

  if (
    !process.env.FIREBASE_PROJECT_ID ||
    !process.env.FIREBASE_CLIENT_EMAIL ||
    !process.env.FIREBASE_PRIVATE_KEY
  ) {
    throw new Error("❌ Firebase ENV variables missing");
  }

  const privateKey = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n");

  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey,
    }),
  });

  console.log("✅ Firebase Admin initialized (ENV)");
}

initFirebase();

module.exports = admin;
// // D:\good_r2c-main\config\firebase.js
// const admin = require('firebase-admin');
// const fs = require('fs');
// const path = require('path');

// let firebaseInitialized = false;
// let firebaseAdmin = null;

// // Initialize Firebase Admin SDK
// function initializeFirebase() {
//   try {
//     if (firebaseInitialized) {
//       console.log('✅ Firebase already initialized');
//       return firebaseAdmin;
//     }

//     if (admin.apps.length > 0) {
//       firebaseAdmin = admin.apps[0];
//       firebaseInitialized = true;
//       console.log('✅ Using existing Firebase app');
//       return firebaseAdmin;
//     }

//     const serviceAccountPath = path.join(__dirname, './serviceAccountKey.json');
//     const hasLocalFile = fs.existsSync(serviceAccountPath);

//     if (hasLocalFile) {
//       console.log('📁 Using local service-account-key.json for Firebase');
//       const serviceAccount = require(serviceAccountPath);
//       firebaseAdmin = admin.initializeApp({
//         credential: admin.credential.cert(serviceAccount),
//         projectId: serviceAccount.project_id
//       });
//     } else if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_PRIVATE_KEY) {
//       console.log('🌍 Using .env variables for Firebase');
//       const privateKey = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
//       firebaseAdmin = admin.initializeApp({
//         credential: admin.credential.cert({
//           projectId: process.env.FIREBASE_PROJECT_ID,
//           clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
//           privateKey,
//         }),
//       });
//     } else {
//       throw new Error('No Firebase credentials found');
//     }

//     firebaseInitialized = true;
//     console.log('✅ Firebase initialized successfully');
//     console.log('✅ Firebase apps count:', admin.apps.length);
    
//     // Test if messaging is available
//     if (firebaseAdmin.messaging) {
//       console.log('✅ Firebase messaging is available');
//     } else {
//       console.log('❌ Firebase messaging is NOT available');
//     }
    
//     return firebaseAdmin;

//   } catch (error) {
//     console.error('❌ Firebase initialization failed:', error.message);
//     return null;
//   }
// }

// // Initialize Firebase immediately
// firebaseAdmin = initializeFirebase();

// // Firebase status
// function getFirebaseStatus() {
//   return {
//     initialized: firebaseInitialized,
//     appsCount: admin.apps.length,
//     method: process.env.FIREBASE_PROJECT_ID ? 'environment-variables' : 'service-account-file',
//     messagingAvailable: !!(admin.apps.length > 0 && admin.messaging)
//   };
// }

// // Create a helper function to get the admin instance
// function getAdmin() {
//   if (!firebaseAdmin && !firebaseInitialized) {
//     firebaseAdmin = initializeFirebase();
//   }
//   return firebaseAdmin;
// }

// // Export the admin directly, not as a property
// module.exports = {
//   admin: getAdmin(), // Direct admin instance
//   getFirebaseStatus,
//   getAdmin
// };















//waste













// // D:\reals2chat_backend-main\config\firebase.js
// const admin = require('firebase-admin');

// console.log('\n=== FIREBASE INITIALIZATION START ===');
// console.log('Checking Firebase configuration...');

// try {
//   // Check what configuration method is available
//   const hasEnvVars = process.env.FIREBASE_PRIVATE_KEY && 
//                     process.env.FIREBASE_PROJECT_ID && 
//                     process.env.FIREBASE_CLIENT_EMAIL;
  
//   console.log(`Environment detection:`);
//   console.log(`- FIREBASE_PRIVATE_KEY exists: ${!!process.env.FIREBASE_PRIVATE_KEY}`);
//   console.log(`- FIREBASE_PROJECT_ID exists: ${!!process.env.FIREBASE_PROJECT_ID}`);
//   console.log(`- FIREBASE_CLIENT_EMAIL exists: ${!!process.env.FIREBASE_CLIENT_EMAIL}`);
  
//   let firebaseConfig = null;
//   let configSource = '';

//   if (hasEnvVars) {
//     console.log('\n✅ Using environment variables');
//     configSource = 'Environment Variables';
    
//     // CRITICAL: Properly format the private key
//     let privateKey = process.env.FIREBASE_PRIVATE_KEY;
//     console.log(`Private key length: ${privateKey.length} chars`);
    
//     // Fix 1: Replace all different types of escaped newlines with actual newlines
//     privateKey = privateKey.replace(/\\n/g, '\n');
    
//     // Fix 2: Remove any extra quotes that might be added by the platform
//     if (privateKey.startsWith('"') && privateKey.endsWith('"')) {
//       privateKey = privateKey.slice(1, -1);
//     }
    
//     // Fix 3: Ensure it has proper BEGIN/END markers
//     if (!privateKey.includes('-----BEGIN PRIVATE KEY-----')) {
//       console.error('❌ Private key missing BEGIN marker');
//       throw new Error('Invalid private key format - missing BEGIN marker');
//     }
    
//     if (!privateKey.includes('-----END PRIVATE KEY-----')) {
//       console.error('❌ Private key missing END marker');
//       throw new Error('Invalid private key format - missing END marker');
//     }
    
//     console.log(`Formatted key length: ${privateKey.length} chars`);
    
//     // Verify the key is properly formatted by checking for key patterns
//     if (!privateKey.includes('MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj')) {
//       console.warn('⚠️ Private key might not be properly formatted');
//     }
    
//     firebaseConfig = {
//       type: process.env.FIREBASE_TYPE || "service_account",
//       project_id: process.env.FIREBASE_PROJECT_ID,
//       private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
//       private_key: privateKey,
//       client_email: process.env.FIREBASE_CLIENT_EMAIL,
//       client_id: process.env.FIREBASE_CLIENT_ID,
//       auth_uri: process.env.FIREBASE_AUTH_URI || "https://accounts.google.com/o/oauth2/auth",
//       token_uri: process.env.FIREBASE_TOKEN_URI || "https://oauth2.googleapis.com/token",
//       auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL || "https://www.googleapis.com/oauth2/v1/certs",
//       client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
//       universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN || "googleapis.com"
//     };
    
//   } else {
//     console.log('\n⚠️ No env vars found, trying local serviceAccountKey.json');
//     try {
//       firebaseConfig = require('./serviceAccountKey.json');
//       configSource = 'Local JSON File';
//       console.log('✅ Loaded local serviceAccountKey.json');
//     } catch (jsonError) {
//       console.error('❌ No Firebase configuration found anywhere');
//       console.error('Error:', jsonError.message);
//       firebaseConfig = null;
//     }
//   }

//   if (firebaseConfig) {
//     console.log(`\n📋 Config Source: ${configSource}`);
//     console.log(`🔑 Project ID: ${firebaseConfig.project_id}`);
//     console.log(`📧 Client Email: ${firebaseConfig.client_email}`);
//     console.log(`🔐 Private Key ID: ${firebaseConfig.private_key_id || 'Not specified'}`);
    
//     // DEBUG: Log first and last 50 chars of private key (without exposing the full key)
//     if (firebaseConfig.private_key) {
//       const keyStart = firebaseConfig.private_key.substring(0, 50);
//       const keyEnd = firebaseConfig.private_key.substring(firebaseConfig.private_key.length - 50);
//       console.log(`🔑 Private Key Start: ${keyStart}`);
//       console.log(`🔑 Private Key End: ${keyEnd}`);
//     }

//     // Initialize Firebase if not already initialized
//     if (!admin.apps.length) {
//       console.log('\n🚀 Initializing Firebase Admin SDK...');
      
//       try {
//         admin.initializeApp({
//           credential: admin.credential.cert(firebaseConfig),
//           projectId: firebaseConfig.project_id
//         });
        
//         console.log('✅ Firebase Admin SDK initialized successfully!');
        
//         // Test Firebase connection with a simple operation
//         console.log('\n🧪 Testing Firebase connection...');
//         const testAuth = admin.auth();
//         console.log(`✅ Firebase Auth service available`);
        
//         // Test messaging service
//         const testMessaging = admin.messaging();
//         console.log(`✅ Firebase Messaging service available`);
        
//       } catch (initError) {
//         console.error('❌ Firebase initialization error:', initError.message);
//         console.error('Full error:', initError);
//         throw initError;
//       }
//     } else {
//       console.log('\nℹ️ Firebase already initialized');
//     }
//   } else {
//     console.error('\n❌ No Firebase configuration available');
//     console.error('FCM notifications will NOT work');
//   }

// } catch (error) {
//   console.error('\n❌❌❌ FIREBASE INITIALIZATION FAILED ❌❌❌');
//   console.error('Error:', error.message);
//   console.error('\n👉 Troubleshooting steps:');
//   console.error('1. Check FIREBASE_PRIVATE_KEY in .env file');
//   console.error('2. Ensure private key has proper newline characters');
//   console.error('3. Verify the key hasn\'t been revoked in Firebase Console');
//   console.error('4. Regenerate service account key if needed');
  
//   // Don't crash the app
//   console.error('\n⚠️ App will run without FCM notifications');
// }

// console.log('\n=== FIREBASE INITIALIZATION COMPLETE ===\n');
// module.exports = admin;