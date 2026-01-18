const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { google } = require('googleapis');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const https = require('https'); // Native HTTPS module for EmailJS
const User = require('../models/userModel');
const UserData = require('../models/UserData');
const UserIdService = require('../services/userIdService');
const { OAuth2Client } = require('google-auth-library');
const admin = require('firebase-admin');

// Initialize Google OAuth client
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Generate token function
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, userId: user.userId }, 
    process.env.JWT_SECRET, 
    { expiresIn: '7d' }
  );
};

// In-memory OTP storage (use Redis in production)
const otpStorage = new Map();

// Generate a secure 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Create NodeMailer transporter
const createNodeMailerTransporter = async () => {
  try {
    console.log('Creating NodeMailer transporter...');
    console.log('Email config check:', {
      hasGmailEmail: !!process.env.GMAIL_EMAIL,
      hasGmailPassword: !!process.env.GMAIL_PASSWORD,
      hasSmtpHost: !!process.env.SMTP_HOST,
      hasSmtpPort: !!process.env.SMTP_PORT,
      hasSmtpUser: !!process.env.SMTP_USER,
      hasSmtpPass: !!process.env.SMTP_PASS,
      env: process.env.NODE_ENV
    });

    // Priority 1: SMTP Configuration (more reliable for production)
    if (process.env.SMTP_HOST && process.env.SMTP_PORT && process.env.SMTP_USER && process.env.SMTP_PASS) {
      console.log('Using SMTP configuration');
      const transporterConfig = {
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT),
        secure: process.env.SMTP_PORT === '465' || process.env.SMTP_PORT === '587',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        },
        tls: {
          rejectUnauthorized: false
        },
        debug: false, // Disable debug for faster execution
        logger: false
      };
      
      const transporter = nodemailer.createTransport(transporterConfig);
      
      // Verify the transporter
      await transporter.verify();
      console.log('NodeMailer transporter verified successfully');
      
      return transporter;
    }
    // Priority 2: Gmail Configuration
    else if (process.env.GMAIL_EMAIL && process.env.GMAIL_PASSWORD) {
      console.log('Using Gmail configuration');
      const transporterConfig = {
        service: 'gmail',
        auth: {
          user: process.env.GMAIL_EMAIL.trim(),
          pass: process.env.GMAIL_PASSWORD.trim(),
        },
        secure: true,
        tls: {
          rejectUnauthorized: false
        },
        debug: false, // Disable debug for faster execution
        logger: false
      };
      
      const transporter = nodemailer.createTransport(transporterConfig);
      
      // Verify the transporter
      await transporter.verify();
      console.log('NodeMailer transporter verified successfully');
      
      return transporter;
    }
    // Priority 3: Development fallback (ethereal.email for testing)
    else {
      console.log('Using Ethereal test email service');
      // Create a test account using ethereal.email
      const testAccount = await nodemailer.createTestAccount();
      const transporterConfig = {
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass
        }
      };
      
      const transporter = nodemailer.createTransport(transporterConfig);
      
      // Verify the transporter
      await transporter.verify();
      console.log('NodeMailer transporter verified successfully');
      
      return transporter;
    }
  } catch (error) {
    console.error('Failed to create NodeMailer transporter:', error.message);
    throw error;
  }
};

// Send OTP via NodeMailer with 3-second timeout and improved handling
const sendOTPWithNodeMailer = async (email, name, otp, timeout = 3000) => {
  return new Promise(async (resolve, reject) => {
    let timeoutId;
    let emailSent = false;
    let nodeMailerCompleted = false;
    
    try {
      const transporter = await createNodeMailerTransporter();
      
      const mailOptions = {
        from: `"Reals TO Chat" <${process.env.GMAIL_EMAIL || process.env.SMTP_USER || 'no-reply@reals2chat.com'}>`,
        to: email,
        subject: 'OTP for your Reals TO Chat authentication',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f5f7fa;">
            <div style="background: linear-gradient(135deg, #FF0050, #8A2BE2); color: white; padding: 30px 20px; text-align: center; border-radius: 8px 8px 0 0;">
              <h1 style="margin: 0; font-size: 28px;">Reals TO Chat</h1>
              <p style="margin: 10px 0 0 0;">Create. Connect. Chat.</p>
            </div>
            <div style="background-color: white; padding: 30px 20px; border-radius: 0 0 8px 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);">
              <h2 style="color: #333; margin-top: 0;">Verify Your Email Address</h2>
              <p>Hello ${name || 'User'},</p>
              <p>Thank you for registering with <strong>Reals TO Chat</strong>! To complete your registration, please use the following One-Time Password (OTP) to verify your email address:</p>
              <div style="background-color: #f8f9fa; border-radius: 8px; padding: 20px; text-align: center; margin: 25px 0;">
                <p style="margin: 0 0 15px 0; font-size: 16px;">Your OTP is:</p>
                <div style="font-size: 36px; font-weight: bold; color: #FF0050; letter-spacing: 8px; margin: 15px 0;">${otp}</div>
                <p style="margin: 15px 0 0 0; font-size: 14px;">This OTP is valid for <strong>10 minutes</strong> only.</p>
              </div>
              <p>If you didn't request this verification, please ignore this email.</p>
              <p>Thank you,<br>The Reals TO Chat Team</p>
            </div>
          </div>
        `,
        text: `Your OTP for Reals TO Chat is: ${otp}. This OTP is valid for 10 minutes.`
      };

      // Set up timeout for 3 seconds
      timeoutId = setTimeout(() => {
        console.log('NodeMailer timeout after 3 seconds, switching to EmailJS');
        if (!nodeMailerCompleted) {
          reject(new Error('NodeMailer timeout'));
        }
      }, timeout);

      // Send email
      const result = await transporter.sendMail(mailOptions);
      
      // Mark NodeMailer as completed
      nodeMailerCompleted = true;
      emailSent = true;
      
      // Clear timeout if email was sent successfully
      clearTimeout(timeoutId);
      
      console.log('NodeMailer email sent successfully:', result.messageId);
      resolve({
        success: true,
        messageId: result.messageId,
        provider: 'NodeMailer'
      });
    } catch (error) {
      // Mark NodeMailer as completed (even if with error)
      nodeMailerCompleted = true;
      
      // Clear timeout if there was an error
      if (timeoutId) clearTimeout(timeoutId);
      console.error('NodeMailer error:', error.message);
      reject(error);
    }
  });
};

// Send OTP via EmailJS with browser-like headers and fixed recipient issue
const sendOTPWithEmailJS = async (email, name, otp) => {
  return new Promise((resolve, reject) => {
    try {
      console.log('📧 Sending via EmailJS to:', email);
      
      // Prepare EmailJS data - Fix the recipient field name
      const emailjsData = {
        service_id: process.env.EMAILJS_SERVICE_ID,
        template_id: process.env.EMAILJS_TEMPLATE_ID,
        user_id: process.env.EMAILJS_PUBLIC_KEY,
        accessToken: process.env.EMAILJS_PRIVATE_KEY,
        template_params: {
          to_email: email,  // Make sure this matches your EmailJS template
          user_name: name || 'User',
          otp_code: otp,
          from_name: 'Reals TO Chat',
          reply_to: 'msugumar0410@gmail.com'
        }
      };
      
      console.log('📨 EmailJS request data:', {
        service_id: emailjsData.service_id,
        template_id: emailjsData.template_id,
        to: email
      });
      
      const postData = JSON.stringify(emailjsData);
      
      const options = {
        hostname: 'api.emailjs.com',
        path: '/api/v1.0/email/send',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData),
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
          'Accept': 'application/json, text/plain, */*',
          'Accept-Language': 'en-US,en;q=0.9',
          'Accept-Encoding': 'gzip, deflate, br',
          'Connection': 'keep-alive',
          'Sec-Fetch-Dest': 'empty',
          'Sec-Fetch-Mode': 'cors',
          'Sec-Fetch-Site': 'cross-site',
          'Origin': 'https://www.emailjs.com',
          'Referer': 'https://www.emailjs.com/'
        }
      };
      
      const req = https.request(options, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
          data += chunk;
        });
        
        res.on('end', () => {
          console.log('EmailJS response status:', res.statusCode);
          console.log('EmailJS response body:', data);
          
          try {
            // Try to parse as JSON
            const result = JSON.parse(data);
            
            if (res.statusCode === 200) {
              console.log('✅ EmailJS email sent successfully:', result);
              resolve({
                success: true,
                messageId: `emailjs-${Date.now()}`,
                provider: 'EmailJS',
                response: result
              });
            } else {
              console.error('❌ EmailJS error:', result);
              reject(new Error(result.message || 'EmailJS failed to send email'));
            }
          } catch (parseError) {
            // If parsing fails, check if response indicates success
            if (res.statusCode === 200 || data.includes('OK') || data.includes('200')) {
              console.log('✅ EmailJS email sent successfully (non-JSON response)');
              resolve({
                success: true,
                messageId: `emailjs-${Date.now()}`,
                provider: 'EmailJS',
                response: { status: 'OK', message: 'Email sent successfully' }
              });
            } else {
              console.error('❌ EmailJS parsing error:', parseError.message);
              reject(new Error(`EmailJS returned non-JSON response: ${data}`));
            }
          }
        });
      });
      
      req.on('error', (error) => {
        console.error('❌ EmailJS request error:', error.message);
        reject(error);
      });
      
      // Write data to request body
      req.write(postData);
      req.end();
      
    } catch (error) {
      console.error('❌ EmailJS sending error:', error);
      reject(error);
    }
  });
};

// Dual email provider with 3-second timeout for NodeMailer
const sendOTPWithDualProvider = async (email, name, otp) => {
  const startTime = Date.now();
  let primaryProviderResult = null;
  let fallbackProviderResult = null;
  let usedProvider = '';
  let deliveryTime = 0;
  let nodeMailerTimeoutFired = false;
  
  // Start NodeMailer with timeout
  const nodeMailerPromise = sendOTPWithNodeMailer(email, name, otp, 3000)
    .then(result => {
      primaryProviderResult = result;
      usedProvider = 'NodeMailer';
      deliveryTime = Date.now() - startTime;
      return { success: true, result, provider: 'NodeMailer', fallback: false };
    })
    .catch(error => {
      // Check if this was a timeout
      if (error.message === 'NodeMailer timeout') {
        nodeMailerTimeoutFired = true;
        // Don't reject yet, we'll try EmailJS
        return { success: false, error, provider: 'NodeMailer', fallback: true };
      } else {
        // Some other error, still try EmailJS
        return { success: false, error, provider: 'NodeMailer', fallback: true };
      }
    });
  
  // Wait for NodeMailer to complete or timeout
  await nodeMailerPromise;
  
  // If NodeMailer succeeded, return the result
  if (primaryProviderResult && primaryProviderResult.success) {
    console.log(`✅ OTP sent successfully via ${usedProvider} in ${deliveryTime}ms`);
    return {
      success: true,
      provider: usedProvider,
      deliveryTime,
      messageId: primaryProviderResult.messageId,
      primaryProviderSuccess: true,
      fallbackProviderUsed: false
    };
  }
  
  // If we get here, NodeMailer failed or timed out, try EmailJS
  if (nodeMailerTimeoutFired || !primaryProviderResult) {
    try {
      console.log('🔄 Falling back to EmailJS (secondary provider)');
      const fallbackStartTime = Date.now();
      
      // Fall back to EmailJS
      fallbackProviderResult = await sendOTPWithEmailJS(email, name, otp);
      usedProvider = 'EmailJS';
      deliveryTime = Date.now() - startTime;
      const fallbackTime = Date.now() - fallbackStartTime;
      
      console.log(`✅ OTP sent successfully via ${usedProvider} in ${deliveryTime}ms total (${fallbackTime}ms for fallback)`);
      return {
        success: true,
        provider: usedProvider,
        deliveryTime,
        messageId: fallbackProviderResult.messageId,
        primaryProviderSuccess: false,
        fallbackProviderUsed: true,
        primaryError: nodeMailerTimeoutFired ? 'NodeMailer timeout' : 'NodeMailer error'
      };
    } catch (fallbackError) {
      console.error(`❌ Both providers failed. NodeMailer: ${nodeMailerTimeoutFired ? 'timeout' : 'error'}, EmailJS: ${fallbackError.message}`);
      deliveryTime = Date.now() - startTime;
      
      return {
        success: false,
        provider: 'None',
        deliveryTime,
        primaryProviderSuccess: false,
        fallbackProviderUsed: false,
        primaryError: nodeMailerTimeoutFired ? 'NodeMailer timeout' : 'NodeMailer error',
        fallbackError: fallbackError.message
      };
    }
  }
};

// Store OTP with expiry (10 minutes)
const storeOTP = (email, otp) => {
  const key = email.toLowerCase();
  otpStorage.set(key, {
    otp,
    expiry: Date.now() + 10 * 60 * 1000, // 10 minutes
    attempts: 0,
    createdAt: Date.now()
  });

  // Clean up expired OTPs after 10 minutes
  setTimeout(() => {
    const stored = otpStorage.get(key);
    if (stored && Date.now() > stored.expiry) {
      otpStorage.delete(key);
      console.log(`Cleaned up expired OTP for: ${key}`);
    }
  }, 10 * 60 * 1000);
  
  console.log(`Stored OTP for ${key}: ${otp}, expires at: ${new Date(Date.now() + 10 * 60 * 1000).toLocaleTimeString()}`);
};

// Verify OTP
const verifyStoredOTP = (email, userOtp) => {
  const key = email.toLowerCase();
  const stored = otpStorage.get(key);
  
  if (!stored) {
    return { valid: false, message: 'OTP not found or expired. Please request a new OTP.' };
  }

  if (Date.now() > stored.expiry) {
    otpStorage.delete(key);
    return { valid: false, message: 'OTP has expired. Please request a new OTP.' };
  }

  if (stored.attempts >= 5) {
    otpStorage.delete(key);
    return { valid: false, message: 'Too many attempts. Please request a new OTP.' };
  }

  stored.attempts++;
  
  console.log(`OTP verification attempt for ${key}: Attempt ${stored.attempts}, Expected: ${stored.otp}, Provided: ${userOtp}`);

  if (stored.otp === userOtp) {
    otpStorage.delete(key);
    return { valid: true, message: 'OTP verified successfully' };
  }

  const remainingAttempts = 5 - stored.attempts;
  return { 
    valid: false, 
    message: `Invalid OTP. ${remainingAttempts} attempt(s) remaining.` 
  };
};

// Send OTP Email with Dual Provider System
const sendOTPEmail = async (req, res) => {
  try {
    const { email, name } = req.body;
    
    console.log('Attempting to send OTP email to:', email);
    console.log('Server environment:', process.env.NODE_ENV);
    
    if (!email) {
      return res.status(400).json({ 
        success: false,
        message: 'Email is required' 
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Generate OTP
    const otp = generateOTP();
    
    // Store OTP for verification
    storeOTP(email, otp);
    console.log(`Generated OTP for ${email}: ${otp}`);

    // Send OTP using dual provider system
    const startTime = Date.now();
    const result = await sendOTPWithDualProvider(email, name, otp);
    const totalTime = Date.now() - startTime;
    
    // Prepare response
    const isDevelopment = process.env.NODE_ENV !== 'production' || !result.success;
    
    const response = {
      success: result.success,
      message: result.success 
        ? `OTP sent successfully via ${result.provider}` 
        : 'Failed to send OTP. Please try again.',
      emailSent: result.success,
      emailService: result.provider,
      deliveryTime: result.deliveryTime,
      totalTime: totalTime,
      primaryProviderSuccess: result.primaryProviderSuccess,
      fallbackProviderUsed: result.fallbackProviderUsed,
      developmentMode: isDevelopment
    };

    // Include error details if available
    if (result.primaryError) {
      response.primaryError = process.env.NODE_ENV === 'development' ? result.primaryError : 'Primary provider failed';
    }
    if (result.fallbackError) {
      response.fallbackError = process.env.NODE_ENV === 'development' ? result.fallbackError : 'Fallback provider failed';
    }

    // Always include OTP in response for development/debugging
    if (isDevelopment) {
      response.otp = otp;
      response.note = 'In development mode, use this OTP for verification';
    }

    // Log delivery details
    console.log(`Email delivery result:`, {
      success: result.success,
      provider: result.provider,
      deliveryTime: result.deliveryTime,
      totalTime: totalTime,
      primaryProviderSuccess: result.primaryProviderSuccess,
      fallbackProviderUsed: result.fallbackProviderUsed
    });

    res.json(response);
    
  } catch (error) {
    console.error('Send OTP email error:', error);
    
    // Generate OTP even in case of server error for development
    const otp = generateOTP();
    if (req.body.email) {
      storeOTP(req.body.email, otp);
    }
    
    res.status(200).json({ 
      success: true,
      message: 'Server responded with OTP for testing',
      otp: otp,
      emailSent: false,
      developmentMode: true,
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Verify Email OTP
const verifyEmailOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ 
        success: false,
        message: 'Email and OTP are required' 
      });
    }

    console.log(`Verifying OTP for: ${email}, OTP: ${otp}`);
    
    const result = verifyStoredOTP(email, otp);
    
    if (result.valid) {
      // Update user's email verification status if they exist
      const user = await User.findOne({ email: email.toLowerCase() });
      if (user) {
        user.isEmailVerified = true;
        await user.save();
        console.log(`Email verified for user: ${email}`);
      }
      
      return res.json({
        success: true,
        message: result.message,
        emailVerified: true
      });
    } else {
      return res.status(400).json({
        success: false,
        message: result.message,
        emailVerified: false
      });
    }
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during OTP verification' 
    });
  }
};

// Check User ID availability
const checkUserId = async (req, res) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        message: 'User ID is required' 
      });
    }
    
    if (!UserIdService.validateCustomUserId(userId)) {
      return res.status(400).json({
        success: false,
        message: 'User ID must be at least 6 characters, contain at least one number, and no special characters'
      });
    }
    
    const isAvailable = await UserIdService.isUserIdAvailable(userId);
    
    if (!isAvailable) {
      return res.status(400).json({
        success: false,
        message: 'This User ID is already taken. Please enter another one.'
      });
    }
    
    res.json({
      success: true,
      message: 'User ID is available'
    });
  } catch (error) {
    console.error('Check user ID error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
};

// Generate User ID
const generateUserId = async (req, res) => {
  try {
    const userId = await UserIdService.generateUserId();
    
    res.json({
      success: true,
      userId: userId
    });
  } catch (error) {
    console.error('Generate user ID error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to generate User ID' 
    });
  }
};

// Register User
const register = async (req, res) => {
  try {
    const { 
      name, 
      phoneNumber, 
      phone, 
      email, 
      password, 
      dateOfBirth, 
      gender, 
      isPhoneVerified, 
      isEmailVerified,
      userId
    } = req.body;
    
    const actualPhoneNumber = phoneNumber || phone;
    const emailLower = email.toLowerCase();
    
    console.log(`Registration attempt for email: ${emailLower}, phone: ${actualPhoneNumber}, userId: ${userId}`);
    
    // Validate required fields
    const requiredFields = { name, email, dateOfBirth, gender, userId };
    const missingFields = Object.entries(requiredFields)
      .filter(([_, value]) => !value)
      .map(([key]) => key);
    
    if (missingFields.length > 0) {
      console.log('Missing required fields:', missingFields);
      return res.status(400).json({ 
        success: false, 
        message: `Missing required fields: ${missingFields.join(', ')}` 
      });
    }
    
    // Validate User ID availability
    const isUserIdAvailable = await UserIdService.isUserIdAvailable(userId);
    if (!isUserIdAvailable) {
      return res.status(400).json({
        success: false,
        message: 'User ID is already taken'
      });
    }
    
    // Check for existing email
    const existingUserByEmail = await User.findOne({ email: emailLower });
    if (existingUserByEmail) {
      console.log(`Email already in use: ${emailLower}`);
      return res.status(400).json({ success: false, message: 'Email already in use' });
    }
    
    // Check for existing phone number
    if (actualPhoneNumber) {
      const existingUserByPhone = await User.findOne({ phone: actualPhoneNumber });
      if (existingUserByPhone) {
        console.log(`Phone number already in use: ${actualPhoneNumber}`);
        return res.status(400).json({ success: false, message: 'Phone number already in use' });
      }
    }
    
    // Hash password if provided
    let hashedPassword = password;
    if (password) {
      const salt = await bcrypt.genSalt(10);
      hashedPassword = await bcrypt.hash(password, salt);
    }
    
    // Create new user
    const newUser = new User({
      name,
      phone: actualPhoneNumber,
      email: emailLower,
      password: hashedPassword,
      userId: userId.toUpperCase().trim(),
      dateOfBirth,
      gender,
      isPhoneVerified: isPhoneVerified || false,
      isEmailVerified: isEmailVerified || false,
      registrationComplete: true,
    });
    
    await newUser.save();
    console.log(`User registered successfully: ${emailLower} with ID: ${userId}`);
    
    // Create userData entry
    const userData = new UserData({
      userId: newUser._id
    });
    await userData.save();

    // Generate token
    const token = generateToken(newUser);
    
    res.status(201).json({
      success: true,
      token,
      user: {
        id: newUser._id,
        userId: newUser.userId,
        name: newUser.name,
        email: newUser.email,
        phone: newUser.phone,
        dateOfBirth: newUser.dateOfBirth,
        gender: newUser.gender,
        isEmailVerified: newUser.isEmailVerified,
        isPhoneVerified: newUser.isPhoneVerified,
        registrationComplete: true
      },
      message: 'Registration successful'
    });
  } catch (error) {
    console.error('Register error:', error);
    
    if (error.code === 11000) {
      let message = 'Registration failed';
      if (error.keyPattern && error.keyPattern.email) {
        message = 'Email already in use';
      } else if (error.keyPattern && error.keyPattern.phone) {
        message = 'Phone number already in use';
      } else if (error.keyPattern && error.keyPattern.userId) {
        message = 'User ID already in use';
      }
      console.log(`Duplicate key error: ${message}`);
      return res.status(400).json({ success: false, message });
    }
    
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(val => val.message);
      return res.status(400).json({ success: false, message: messages.join(', ') });
    }
    
    res.status(500).json({ 
      success: false, 
      message: 'Server error during registration',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Reset Password
const resetPassword = async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    
    if (!email || !newPassword) {
      return res.status(400).json({ success: false, message: 'Email and new password are required' });
    }
    
    const emailLower = email.toLowerCase();
    const user = await User.findOne({ email: emailLower });
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Hash the new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();
    
    res.status(200).json({
      success: true,
      message: 'Password reset successfully'
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Google Sign In
const googleSignIn = async (req, res) => {
  try {
    const { idToken } = req.body;
    
    if (!idToken) {
      return res.status(400).json({ success: false, message: 'Google ID token is required' });
    }
    
    let email, name, picture, googleId;

    try {
      // Try verifying with Firebase Admin SDK first (since frontend sends Firebase token)
      const decodedToken = await admin.auth().verifyIdToken(idToken);
      email = decodedToken.email;
      name = decodedToken.name;
      picture = decodedToken.picture;
      googleId = decodedToken.uid;
    } catch (firebaseError) {
      // Fallback to Google OAuth2 verification
      try {
        const ticket = await client.verifyIdToken({
          idToken: idToken,
          audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        email = payload.email;
        name = payload.name;
        picture = payload.picture;
        googleId = payload.sub;
      } catch (googleError) {
        console.error('Token verification failed:', googleError.message);
        return res.status(401).json({ success: false, message: 'Invalid token' });
      }
    }

    // Check if user exists
    let user = await User.findOne({ 
      $or: [
        { email: email.toLowerCase() },
        { googleId: googleId }
      ] 
    });

    if (!user) {
      // Create new user
      const userId = await UserIdService.generateUserId();
      
      user = new User({
        email: email.toLowerCase(),
        name: name,
        googleId: googleId,
        photoURL: picture,
        userId: userId,
        isEmailVerified: true,
        registrationComplete: false
      });

      await user.save();
      
      // Create UserData entry
      const userDataEntry = new UserData({ userId: user._id });
      await userDataEntry.save();

    } else {
      // Update existing user if needed
      if (!user.googleId) {
        user.googleId = googleId;
        await user.save();
      }
      
      // Check if profile is incomplete
      if (!user.dateOfBirth || !user.gender) {
        user.registrationComplete = false;
        await user.save();
      }
    }

    const token = generateToken(user);

    res.json({
      success: true,
      token: token,
      user: {
        id: user._id,
        userId: user.userId,
        name: user.name,
        email: user.email,
        photoURL: user.photoURL,
        registrationComplete: user.registrationComplete,
        isEmailVerified: user.isEmailVerified
      }
    });

  } catch (error) {
    console.error('Google sign-in error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during Google sign-in',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Verify Phone
const verifyPhone = async (req, res) => {
  try {
    const { phoneNumber, phone } = req.body;
    const actualPhoneNumber = phoneNumber || phone;
    
    console.log(`Phone verification attempt for: ${actualPhoneNumber}`);
    
    if (!actualPhoneNumber) {
      return res.status(400).json({ success: false, message: 'Phone number is required' });
    }
    
    let user = await User.findOne({ phone: actualPhoneNumber });
    
    if (!user) {
      const generatedUserId = await UserIdService.generateUserId();
      
      user = new User({
        phone: actualPhoneNumber,
        userId: generatedUserId,
        isPhoneVerified: true,
        registrationComplete: false,
      });
      await user.save();
      console.log(`New user created for phone: ${actualPhoneNumber} with ID: ${generatedUserId}`);
      
      // Create userData entry for new user
      const userData = new UserData({
        userId: user._id
      });
      await userData.save();
    } else {
      // Update existing user
      user.isPhoneVerified = true;
      await user.save();
      console.log(`Existing user found and verified: ${actualPhoneNumber}`);

      // Ensure UserData exists for existing users
      const userDataExists = await UserData.exists({ userId: user._id });
      if (!userDataExists) {
        await new UserData({ userId: user._id }).save();
        console.log('Created missing UserData for existing user');
      }
    }
    
    const token = generateToken(user);
    
    // Return complete user data
    return res.json({
      success: true,
      token,
      user: {
        id: user._id,
        userId: user.userId,
        name: user.name || '',
        email: user.email || '',
        phone: user.phone,
        dateOfBirth: user.dateOfBirth || '',
        gender: user.gender || '',
        isPhoneVerified: user.isPhoneVerified,
        isEmailVerified: user.isEmailVerified || false,
        registrationComplete: user.registrationComplete
      },
    });
  } catch (error) {
    console.error('Verify phone error:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({ 
        success: false, 
        message: 'Phone number already in use' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: 'Server error during phone verification',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Update Profile
const updateProfile = async (req, res) => {
  try {
    const { phone, phoneNumber, isPhoneVerified, name, dateOfBirth, gender } = req.body;
    const actualPhoneNumber = phoneNumber || phone;
    
    if (!name || !dateOfBirth || !gender) {
      return res.status(400).json({ 
        success: false, 
        message: 'Name, date of birth, and gender are required' 
      });
    }
    
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    let user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Check phone number availability if changing
    if (actualPhoneNumber && actualPhoneNumber !== user.phone) {
      const existingUserWithPhone = await User.findOne({ phone: actualPhoneNumber });
      if (existingUserWithPhone && existingUserWithPhone._id.toString() !== user._id.toString()) {
        return res.status(400).json({ 
          success: false, 
          message: 'Phone number already in use by another account' 
        });
      }
      user.phone = actualPhoneNumber;
    }
    
    user.name = name;
    user.dateOfBirth = dateOfBirth;
    user.gender = gender;
    
    if (isPhoneVerified !== undefined) {
      user.isPhoneVerified = isPhoneVerified;
    }
    
    user.registrationComplete = true;
    await user.save();
    
    const newToken = generateToken(user);
    res.status(200).json({
      success: true,
      token: newToken,
      user: {
        id: user._id,
        userId: user.userId,
        name: user.name,
        email: user.email,
        phone: user.phone,
        dateOfBirth: user.dateOfBirth,
        gender: user.gender,
        isPhoneVerified: user.isPhoneVerified,
        isEmailVerified: user.isEmailVerified,
        registrationComplete: user.registrationComplete
      },
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Google Phone Number Fetch
const googlePhone = async (req, res) => {
  try {
    const { serverAuthCode } = req.body;
    
    if (!serverAuthCode) {
      return res.status(400).json({ success: false, message: 'Server auth code is required' });
    }
    
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      console.error('Google OAuth credentials not configured');
      return res.status(500).json({
        success: false,
        message: 'Server configuration error: Google OAuth credentials missing',
      });
    }
    
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      'postmessage'
    );
    
    const { tokens } = await oauth2Client.getToken(serverAuthCode);
    oauth2Client.setCredentials(tokens);
    
    const people = google.people({ version: 'v1', auth: oauth2Client });
    const response = await people.people.get({
      resourceName: 'people/me',
      personFields: 'phoneNumbers',
    });
    
    const phoneNumbers = response.data.phoneNumbers;
    let phoneNumber = null;
    
    if (phoneNumbers && phoneNumbers.length > 0) {
      phoneNumber = phoneNumbers[0].value;
    }
    
    res.json({ success: true, phoneNumber });
  } catch (error) {
    console.error('Google phone number fetch error:', error);
    
    if (error.response && error.response.data) {
      console.error('Google API error details:', error.response.data);
    }
    
    if (error.code === 401 && error.response?.data?.error === 'invalid_client') {
      return res.status(500).json({
        success: false,
        message: 'Google OAuth configuration error. Please check your Google API credentials.',
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to fetch phone number from Google',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
};

// Check User
const checkUser = async (req, res) => {
  try {
    const { phone, phoneNumber, email } = req.body;
    const actualPhoneNumber = phoneNumber || phone;
    
    console.log(`Check user attempt - email: ${email}, phone: ${actualPhoneNumber}`);
    
    let query = {};
    if (actualPhoneNumber) query.phone = actualPhoneNumber;
    if (email) query.email = email.toLowerCase();
    
    if (!actualPhoneNumber && !email) {
      return res.status(400).json({ success: false, message: 'Phone or email is required' });
    }
    
    const user = await User.findOne(query).select('-password');
    
    if (!user) {
      console.log(`User not found for query:`, query);
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    console.log(`User found: ${user.name}, has password: ${!!user.password}`);
    
    res.status(200).json({
      success: true,
      user: {
        id: user._id,
        userId: user.userId,
        name: user.name,
        email: user.email,
        phone: user.phone,
        canLoginWithPassword: !!user.password,
        registrationComplete: user.registrationComplete,
        isEmailVerified: user.isEmailVerified,
        isPhoneVerified: user.isPhoneVerified
      },
    });
  } catch (error) {
    console.error('Check user error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Login
const login = async (req, res) => {
  try {
    const { email, password, phone, phoneNumber } = req.body;
    const actualPhoneNumber = phoneNumber || phone;

    console.log(`Login attempt - Email: ${email}, Phone: ${actualPhoneNumber}`);

    if ((!email && !actualPhoneNumber) || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email/Phone and password are required' 
      });
    }

    let user;
    let identifier = email || actualPhoneNumber;

    if (email) {
      user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    } else {
      user = await User.findOne({ phone: actualPhoneNumber }).select('+password');
    }

    if (!user) {
      console.log(`User not found: ${identifier}`);
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    console.log(`User found: ${user.name}, has password: ${!!user.password}`);

    if (!user.password) {
      console.log(`User ${identifier} has no password set`);
      return res.status(400).json({
        success: false,
        message: 'This account was created with Google Sign-In or phone verification. Please use the original sign-in method.',
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log(`Invalid password for user: ${identifier}`);
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }

    console.log(`Login successful for user: ${identifier}`);

    const token = generateToken(user);

    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        userId: user.userId,
        name: user.name,
        email: user.email,
        phone: user.phone,
        dateOfBirth: user.dateOfBirth,
        gender: user.gender,
        isEmailVerified: user.isEmailVerified,
        isPhoneVerified: user.isPhoneVerified,
        registrationComplete: user.registrationComplete,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Logout
const logout = async (req, res) => {
  try {
    res.status(200).json({ 
      success: true, 
      message: 'Logged out successfully' 
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
};

// Set Password
const setPassword = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
    }
    
    const emailLower = email.toLowerCase();
    const user = await User.findOne({ email: emailLower });
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }
    
    // Hash the password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    
    await user.save();
    
    res.status(200).json({
      success: true,
      message: 'Password set successfully',
      user: {
        id: user._id,
        userId: user.userId,
        name: user.name,
        email: user.email,
        phone: user.phone,
        registrationComplete: user.registrationComplete,
      }
    });
  } catch (error) {
    console.error('Set password error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Check Google Config
const checkGoogleConfig = async (req, res) => {
  try {
    const hasClientId = !!process.env.GOOGLE_CLIENT_ID;
    const hasClientSecret = !!process.env.GOOGLE_CLIENT_SECRET;
    
    res.json({
      success: true,
      hasGoogleClientId: hasClientId,
      hasGoogleClientSecret: hasClientSecret,
      clientIdLength: hasClientId ? process.env.GOOGLE_CLIENT_ID.length : 0,
      clientSecretLength: hasClientSecret ? process.env.GOOGLE_CLIENT_SECRET.length : 0,
      clientIdPrefix: hasClientId ? process.env.GOOGLE_CLIENT_ID.substring(0, 10) + '...' : 'None',
      env: process.env.NODE_ENV
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};

// Check Email Config
const checkEmailConfig = async (req, res) => {
  try {
    const hasGmailEmail = !!process.env.GMAIL_EMAIL;
    const hasGmailPassword = !!process.env.GMAIL_PASSWORD;
    const hasSmtpHost = !!process.env.SMTP_HOST;
    const hasSmtpPort = !!process.env.SMTP_PORT;
    const hasSmtpUser = !!process.env.SMTP_USER;
    const hasSmtpPass = !!process.env.SMTP_PASS;
    const hasEmailJS = !!(process.env.EMAILJS_SERVICE_ID && process.env.EMAILJS_TEMPLATE_ID && process.env.EMAILJS_PUBLIC_KEY);
    
    res.json({
      success: true,
      emailConfig: {
        hasGmailEmail,
        hasGmailPassword,
        hasSmtpHost,
        hasSmtpPort,
        hasSmtpUser,
        hasSmtpPass,
        hasEmailJS,
        emailJSServiceId: process.env.EMAILJS_SERVICE_ID ? process.env.EMAILJS_SERVICE_ID.substring(0, 5) + '...' : 'None',
        emailJSTemplateId: process.env.EMAILJS_TEMPLATE_ID ? process.env.EMAILJS_TEMPLATE_ID.substring(0, 5) + '...' : 'None',
        emailJSPublicKey: process.env.EMAILJS_PUBLIC_KEY ? process.env.EMAILJS_PUBLIC_KEY.substring(0, 5) + '...' : 'None',
      },
      env: process.env.NODE_ENV
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};

// Get OTP Status (for debugging)
const getOTPStatus = async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }
    
    const key = email.toLowerCase();
    const stored = otpStorage.get(key);
    
    const status = {
      email: key,
      hasOTP: !!stored,
      ...(stored ? {
        attempts: stored.attempts,
        expiresIn: Math.max(0, stored.expiry - Date.now()),
        expiryTime: new Date(stored.expiry).toLocaleTimeString(),
        createdAt: new Date(stored.createdAt).toLocaleTimeString()
      } : {}),
      totalStoredOTPs: otpStorage.size,
      environment: process.env.NODE_ENV
    };
    
    res.json({
      success: true,
      status
    });
  } catch (error) {
    console.error('Get OTP status error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// Test Email Delivery
const testEmailDelivery = async (req, res) => {
  try {
    const { email, name } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }
    
    // Generate a test OTP
    const otp = generateOTP();
    
    console.log(`Testing email delivery to ${email} with OTP: ${otp}`);
    
    // Test dual provider system
    const result = await sendOTPWithDualProvider(email, name || 'Test User', otp);
    
    res.json({
      success: true,
      result,
      testOTP: process.env.NODE_ENV !== 'production' ? otp : undefined
    });
  } catch (error) {
    console.error('Test email delivery error:', error);
    res.status(500).json({
      success: false,
      message: 'Test failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Test EmailJS Directly
const testEmailJSDirectly = async (req, res) => {
  try {
    const { email, name } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }
    
    // Generate a test OTP
    const otp = generateOTP();
    
    console.log(`Testing EmailJS directly to ${email} with OTP: ${otp}`);
    
    // Test EmailJS directly
    const result = await sendOTPWithEmailJS(email, name || 'Test User', otp);
    
    res.json({
      success: true,
      result,
      testOTP: process.env.NODE_ENV !== 'production' ? otp : undefined
    });
  } catch (error) {
    console.error('Test EmailJS directly error:', error);
    res.status(500).json({
      success: false,
      message: 'Test failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

module.exports = {
  sendOTPEmail,
  verifyEmailOTP,
  getOTPStatus,
  register,
  googleSignIn,
  verifyPhone,
  updateProfile,
  googlePhone,
  checkUserId,
  generateUserId,
  resetPassword,
  checkGoogleConfig,
  checkEmailConfig,
  login,
  logout,
  checkUser,
  setPassword,
  testEmailDelivery,
  testEmailJSDirectly
};



// // D:\reals2chat_backend-main\controllers\authController.js
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// const { google } = require('googleapis');
// const nodemailer = require('nodemailer');
// const crypto = require('crypto');
// const User = require('../models/userModel');
// const UserData = require('../models/UserData');
// const UserIdService = require('../services/userIdService');
// const { OAuth2Client } = require('google-auth-library');
// const admin = require('firebase-admin');

// // Initialize Google OAuth client
// const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// // Generate token function
// const generateToken = (user) => {
//   return jwt.sign(
//     { id: user._id, userId: user.userId }, 
//     process.env.JWT_SECRET, 
//     { expiresIn: '7d' }
//   );
// };

// // In-memory OTP storage (use Redis in production)
// const otpStorage = new Map();

// // Generate a secure 6-digit OTP
// const generateOTP = () => {
//   return Math.floor(100000 + Math.random() * 900000).toString();
// };

// // Create email transporter with better error handling and fallback options
// const createTransporter = async () => {
//   try {
//     console.log('Creating email transporter...');
//     console.log('Email config check:', {
//       hasGmailEmail: !!process.env.GMAIL_EMAIL,
//       hasGmailPassword: !!process.env.GMAIL_PASSWORD,
//       hasSmtpHost: !!process.env.SMTP_HOST,
//       hasSmtpPort: !!process.env.SMTP_PORT,
//       hasSmtpUser: !!process.env.SMTP_USER,
//       hasSmtpPass: !!process.env.SMTP_PASS,
//       env: process.env.NODE_ENV
//     });

//     // Check for environment variables and use appropriate configuration
//     let transporterConfig;

//     // Priority 1: SMTP Configuration (more reliable for production)
//     if (process.env.SMTP_HOST && process.env.SMTP_PORT && process.env.SMTP_USER && process.env.SMTP_PASS) {
//       console.log('Using SMTP configuration');
//       transporterConfig = {
//         host: process.env.SMTP_HOST,
//         port: parseInt(process.env.SMTP_PORT),
//         secure: process.env.SMTP_PORT === '465' || process.env.SMTP_PORT === '587',
//         auth: {
//           user: process.env.SMTP_USER,
//           pass: process.env.SMTP_PASS
//         },
//         tls: {
//           rejectUnauthorized: false
//         },
//         debug: true,
//         logger: true
//       };
//     }
//     // Priority 2: Gmail Configuration
//     else if (process.env.GMAIL_EMAIL && process.env.GMAIL_PASSWORD) {
//       console.log('Using Gmail configuration');
//       transporterConfig = {
//         service: 'gmail',
//         auth: {
//           user: process.env.GMAIL_EMAIL.trim(),
//           pass: process.env.GMAIL_PASSWORD.trim(),
//         },
//         secure: true,
//         tls: {
//           rejectUnauthorized: false
//         },
//         debug: true,
//         logger: true
//       };
//     }
//     // Priority 3: Development fallback (ethereal.email for testing)
//     else {
//       console.log('Using Ethereal test email service');
//       // Create a test account using ethereal.email
//       const testAccount = await nodemailer.createTestAccount();
//       transporterConfig = {
//         host: 'smtp.ethereal.email',
//         port: 587,
//         secure: false,
//         auth: {
//           user: testAccount.user,
//           pass: testAccount.pass
//         }
//       };
//     }

//     const transporter = nodemailer.createTransport(transporterConfig);

//     // Verify the transporter
//     await transporter.verify();
//     console.log('Email transporter verified successfully');
    
//     return transporter;
//   } catch (error) {
//     console.error('Failed to create email transporter:', error.message);
    
//     // If all else fails, create a dummy transporter that logs emails
//     console.log('Creating dummy transporter for development');
//     return {
//       sendMail: async (mailOptions) => {
//         console.log('\n========== EMAIL LOG (NOT SENT) ==========');
//         console.log('To:', mailOptions.to);
//         console.log('Subject:', mailOptions.subject);
//         console.log('OTP would be:', mailOptions.html?.match(/\d{6}/)?.[0] || 'Not found');
//         console.log('===========================================\n');
        
//         return {
//           messageId: 'dummy-' + Date.now(),
//           response: 'Email logged but not sent (development mode)'
//         };
//       }
//     };
//   }
// };

// // Store OTP with expiry (10 minutes)
// const storeOTP = (email, otp) => {
//   const key = email.toLowerCase();
//   otpStorage.set(key, {
//     otp,
//     expiry: Date.now() + 10 * 60 * 1000, // 10 minutes
//     attempts: 0,
//     createdAt: Date.now()
//   });

//   // Clean up expired OTPs after 10 minutes
//   setTimeout(() => {
//     const stored = otpStorage.get(key);
//     if (stored && Date.now() > stored.expiry) {
//       otpStorage.delete(key);
//       console.log(`Cleaned up expired OTP for: ${key}`);
//     }
//   }, 10 * 60 * 1000);
  
//   console.log(`Stored OTP for ${key}: ${otp}, expires at: ${new Date(Date.now() + 10 * 60 * 1000).toLocaleTimeString()}`);
// };

// // Verify OTP
// const verifyStoredOTP = (email, userOtp) => {
//   const key = email.toLowerCase();
//   const stored = otpStorage.get(key);
  
//   if (!stored) {
//     return { valid: false, message: 'OTP not found or expired. Please request a new OTP.' };
//   }

//   if (Date.now() > stored.expiry) {
//     otpStorage.delete(key);
//     return { valid: false, message: 'OTP has expired. Please request a new OTP.' };
//   }

//   if (stored.attempts >= 5) {
//     otpStorage.delete(key);
//     return { valid: false, message: 'Too many attempts. Please request a new OTP.' };
//   }

//   stored.attempts++;
  
//   console.log(`OTP verification attempt for ${key}: Attempt ${stored.attempts}, Expected: ${stored.otp}, Provided: ${userOtp}`);

//   if (stored.otp === userOtp) {
//     otpStorage.delete(key);
//     return { valid: true, message: 'OTP verified successfully' };
//   }

//   const remainingAttempts = 5 - stored.attempts;
//   return { 
//     valid: false, 
//     message: `Invalid OTP. ${remainingAttempts} attempt(s) remaining.` 
//   };
// };

// // Send OTP Email - Production Ready
// const sendOTPEmail = async (req, res) => {
//   try {
//     const { email, name } = req.body;
    
//     console.log('Attempting to send OTP email to:', email);
//     console.log('Server environment:', process.env.NODE_ENV);
    
//     if (!email) {
//       return res.status(400).json({ 
//         success: false,
//         message: 'Email is required' 
//       });
//     }

//     const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//     if (!emailRegex.test(email)) {
//       return res.status(400).json({
//         success: false,
//         message: 'Invalid email format'
//       });
//     }

//     // Generate OTP
//     const otp = generateOTP();
    
//     // Store OTP for verification
//     storeOTP(email, otp);
//     console.log(`Generated OTP for ${email}: ${otp}`);

//     let emailSent = false;
//     let emailError = null;
//     let emailInfo = null;
    
//     try {
//       const transporter = await createTransporter();
      
//       const mailOptions = {
//         from: `"Reals TO Chat" <${process.env.GMAIL_EMAIL || process.env.SMTP_USER || 'no-reply@reals2chat.com'}>`,
//         to: email,
//         subject: 'OTP for your Reals TO Chat authentication',
//         html: `
//           <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f5f7fa;">
//             <div style="background: linear-gradient(135deg, #FF0050, #8A2BE2); color: white; padding: 30px 20px; text-align: center; border-radius: 8px 8px 0 0;">
//               <h1 style="margin: 0; font-size: 28px;">Reals TO Chat</h1>
//               <p style="margin: 10px 0 0 0;">Create. Connect. Chat.</p>
//             </div>
//             <div style="background-color: white; padding: 30px 20px; border-radius: 0 0 8px 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);">
//               <h2 style="color: #333; margin-top: 0;">Verify Your Email Address</h2>
//               <p>Hello ${name || 'User'},</p>
//               <p>Thank you for registering with <strong>Reals TO Chat</strong>! To complete your registration, please use the following One-Time Password (OTP) to verify your email address:</p>
//               <div style="background-color: #f8f9fa; border-radius: 8px; padding: 20px; text-align: center; margin: 25px 0;">
//                 <p style="margin: 0 0 15px 0; font-size: 16px;">Your OTP is:</p>
//                 <div style="font-size: 36px; font-weight: bold; color: #FF0050; letter-spacing: 8px; margin: 15px 0;">${otp}</div>
//                 <p style="margin: 15px 0 0 0; font-size: 14px;">This OTP is valid for <strong>10 minutes</strong> only.</p>
//               </div>
//               <p>If you didn't request this verification, please ignore this email.</p>
//               <p>Thank you,<br>The Reals TO Chat Team</p>
//             </div>
//           </div>
//         `,
//         text: `Your OTP for Reals TO Chat is: ${otp}. This OTP is valid for 10 minutes.`
//       };

//       emailInfo = await transporter.sendMail(mailOptions);
      
//       // Check if this is a dummy transporter
//       if (emailInfo.response && emailInfo.response.includes('development mode')) {
//         console.log('Email logged in development mode');
//         emailSent = false;
//       } else {
//         console.log('OTP email sent successfully to:', email);
//         console.log('Message ID:', emailInfo.messageId);
//         emailSent = true;
//       }
      
//     } catch (error) {
//       console.error('Email sending failed:', error.message);
//       emailError = error.message;
//     }

//     // In development or if email fails, include OTP in response
//     const isDevelopment = process.env.NODE_ENV !== 'production' || !emailSent;
    
//     const response = {
//       success: true,
//       message: emailSent 
//         ? 'OTP sent successfully to your email' 
//         : (isDevelopment ? 'Development mode: OTP returned below' : 'Email service temporarily unavailable'),
//       emailSent: emailSent,
//       developmentMode: isDevelopment
//     };

//     // Always include OTP in response for development/debugging
//     if (isDevelopment) {
//       response.otp = otp;
//       response.note = 'In development mode, use this OTP for verification';
//     }

//     res.json(response);
    
//   } catch (error) {
//     console.error('Send OTP email error:', error);
    
//     // Generate OTP even in case of server error for development
//     const otp = generateOTP();
//     if (req.body.email) {
//       storeOTP(req.body.email, otp);
//     }
    
//     res.status(200).json({ 
//       success: true,
//       message: 'Server responded with OTP for testing',
//       otp: otp,
//       emailSent: false,
//       developmentMode: true,
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined
//     });
//   }
// };

// // Verify Email OTP
// const verifyEmailOTP = async (req, res) => {
//   try {
//     const { email, otp } = req.body;
    
//     if (!email || !otp) {
//       return res.status(400).json({ 
//         success: false,
//         message: 'Email and OTP are required' 
//       });
//     }

//     console.log(`Verifying OTP for: ${email}, OTP: ${otp}`);
    
//     const result = verifyStoredOTP(email, otp);
    
//     if (result.valid) {
//       // Update user's email verification status if they exist
//       const user = await User.findOne({ email: email.toLowerCase() });
//       if (user) {
//         user.isEmailVerified = true;
//         await user.save();
//         console.log(`Email verified for user: ${email}`);
//       }
      
//       return res.json({
//         success: true,
//         message: result.message,
//         emailVerified: true
//       });
//     } else {
//       return res.status(400).json({
//         success: false,
//         message: result.message,
//         emailVerified: false
//       });
//     }
//   } catch (error) {
//     console.error('Verify OTP error:', error);
//     res.status(500).json({ 
//       success: false,
//       message: 'Server error during OTP verification' 
//     });
//   }
// };

// // Check User ID availability
// const checkUserId = async (req, res) => {
//   try {
//     const { userId } = req.body;
    
//     if (!userId) {
//       return res.status(400).json({ 
//         success: false, 
//         message: 'User ID is required' 
//       });
//     }
    
//     if (!UserIdService.validateCustomUserId(userId)) {
//       return res.status(400).json({
//         success: false,
//         message: 'User ID must be at least 6 characters, contain at least one number, and no special characters'
//       });
//     }
    
//     const isAvailable = await UserIdService.isUserIdAvailable(userId);
    
//     if (!isAvailable) {
//       return res.status(400).json({
//         success: false,
//         message: 'This User ID is already taken. Please enter another one.'
//       });
//     }
    
//     res.json({
//       success: true,
//       message: 'User ID is available'
//     });
//   } catch (error) {
//     console.error('Check user ID error:', error);
//     res.status(500).json({ 
//       success: false, 
//       message: 'Server error' 
//     });
//   }
// };

// // Generate User ID
// const generateUserId = async (req, res) => {
//   try {
//     const userId = await UserIdService.generateUserId();
    
//     res.json({
//       success: true,
//       userId: userId
//     });
//   } catch (error) {
//     console.error('Generate user ID error:', error);
//     res.status(500).json({ 
//       success: false, 
//       message: 'Failed to generate User ID' 
//     });
//   }
// };

// // Register User
// const register = async (req, res) => {
//   try {
//     const { 
//       name, 
//       phoneNumber, 
//       phone, 
//       email, 
//       password, 
//       dateOfBirth, 
//       gender, 
//       isPhoneVerified, 
//       isEmailVerified,
//       userId
//     } = req.body;
    
//     const actualPhoneNumber = phoneNumber || phone;
//     const emailLower = email.toLowerCase();
    
//     console.log(`Registration attempt for email: ${emailLower}, phone: ${actualPhoneNumber}, userId: ${userId}`);
    
//     // Validate required fields
//     const requiredFields = { name, email, dateOfBirth, gender, userId };
//     const missingFields = Object.entries(requiredFields)
//       .filter(([_, value]) => !value)
//       .map(([key]) => key);
    
//     if (missingFields.length > 0) {
//       console.log('Missing required fields:', missingFields);
//       return res.status(400).json({ 
//         success: false, 
//         message: `Missing required fields: ${missingFields.join(', ')}` 
//       });
//     }
    
//     // Validate User ID availability
//     const isUserIdAvailable = await UserIdService.isUserIdAvailable(userId);
//     if (!isUserIdAvailable) {
//       return res.status(400).json({
//         success: false,
//         message: 'User ID is already taken'
//       });
//     }
    
//     // Check for existing email
//     const existingUserByEmail = await User.findOne({ email: emailLower });
//     if (existingUserByEmail) {
//       console.log(`Email already in use: ${emailLower}`);
//       return res.status(400).json({ success: false, message: 'Email already in use' });
//     }
    
//     // Check for existing phone number
//     if (actualPhoneNumber) {
//       const existingUserByPhone = await User.findOne({ phone: actualPhoneNumber });
//       if (existingUserByPhone) {
//         console.log(`Phone number already in use: ${actualPhoneNumber}`);
//         return res.status(400).json({ success: false, message: 'Phone number already in use' });
//       }
//     }
    
//     // Hash password if provided
//     let hashedPassword = password;
//     if (password) {
//       const salt = await bcrypt.genSalt(10);
//       hashedPassword = await bcrypt.hash(password, salt);
//     }
    
//     // Create new user
//     const newUser = new User({
//       name,
//       phone: actualPhoneNumber,
//       email: emailLower,
//       password: hashedPassword,
//       userId: userId.toUpperCase().trim(),
//       dateOfBirth,
//       gender,
//       isPhoneVerified: isPhoneVerified || false,
//       isEmailVerified: isEmailVerified || false,
//       registrationComplete: true,
//     });
    
//     await newUser.save();
//     console.log(`User registered successfully: ${emailLower} with ID: ${userId}`);
    
//     // Create userData entry
//     const userData = new UserData({
//       userId: newUser._id
//     });
//     await userData.save();

//     // Generate token
//     const token = generateToken(newUser);
    
//     res.status(201).json({
//       success: true,
//       token,
//       user: {
//         id: newUser._id,
//         userId: newUser.userId,
//         name: newUser.name,
//         email: newUser.email,
//         phone: newUser.phone,
//         dateOfBirth: newUser.dateOfBirth,
//         gender: newUser.gender,
//         isEmailVerified: newUser.isEmailVerified,
//         isPhoneVerified: newUser.isPhoneVerified,
//         registrationComplete: true
//       },
//       message: 'Registration successful'
//     });
//   } catch (error) {
//     console.error('Register error:', error);
    
//     if (error.code === 11000) {
//       let message = 'Registration failed';
//       if (error.keyPattern && error.keyPattern.email) {
//         message = 'Email already in use';
//       } else if (error.keyPattern && error.keyPattern.phone) {
//         message = 'Phone number already in use';
//       } else if (error.keyPattern && error.keyPattern.userId) {
//         message = 'User ID already in use';
//       }
//       console.log(`Duplicate key error: ${message}`);
//       return res.status(400).json({ success: false, message });
//     }
    
//     if (error.name === 'ValidationError') {
//       const messages = Object.values(error.errors).map(val => val.message);
//       return res.status(400).json({ success: false, message: messages.join(', ') });
//     }
    
//     res.status(500).json({ 
//       success: false, 
//       message: 'Server error during registration',
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined
//     });
//   }
// };

// // Reset Password
// const resetPassword = async (req, res) => {
//   try {
//     const { email, newPassword } = req.body;
    
//     if (!email || !newPassword) {
//       return res.status(400).json({ success: false, message: 'Email and new password are required' });
//     }
    
//     const emailLower = email.toLowerCase();
//     const user = await User.findOne({ email: emailLower });
    
//     if (!user) {
//       return res.status(404).json({ success: false, message: 'User not found' });
//     }
    
//     // Hash the new password
//     const salt = await bcrypt.genSalt(10);
//     user.password = await bcrypt.hash(newPassword, salt);
//     await user.save();
    
//     res.status(200).json({
//       success: true,
//       message: 'Password reset successfully'
//     });
//   } catch (error) {
//     console.error('Reset password error:', error);
//     res.status(500).json({ 
//       success: false, 
//       message: 'Server error',
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined
//     });
//   }
// };

// // Google Sign In
// const googleSignIn = async (req, res) => {
//   try {
//     const { idToken } = req.body;
    
//     if (!idToken) {
//       return res.status(400).json({ success: false, message: 'Google ID token is required' });
//     }
    
//     let email, name, picture, googleId;

//     try {
//       // Try verifying with Firebase Admin SDK first (since frontend sends Firebase token)
//       const decodedToken = await admin.auth().verifyIdToken(idToken);
//       email = decodedToken.email;
//       name = decodedToken.name;
//       picture = decodedToken.picture;
//       googleId = decodedToken.uid;
//     } catch (firebaseError) {
//       // Fallback to Google OAuth2 verification
//       try {
//         const ticket = await client.verifyIdToken({
//           idToken: idToken,
//           audience: process.env.GOOGLE_CLIENT_ID,
//         });
//         const payload = ticket.getPayload();
//         email = payload.email;
//         name = payload.name;
//         picture = payload.picture;
//         googleId = payload.sub;
//       } catch (googleError) {
//         console.error('Token verification failed:', googleError.message);
//         return res.status(401).json({ success: false, message: 'Invalid token' });
//       }
//     }

//     // Check if user exists
//     let user = await User.findOne({ 
//       $or: [
//         { email: email.toLowerCase() },
//         { googleId: googleId }
//       ] 
//     });

//     if (!user) {
//       // Create new user
//       const userId = await UserIdService.generateUserId();
      
//       user = new User({
//         email: email.toLowerCase(),
//         name: name,
//         googleId: googleId,
//         photoURL: picture,
//         userId: userId,
//         isEmailVerified: true,
//         registrationComplete: false
//       });

//       await user.save();
      
//       // Create UserData entry
//       const userDataEntry = new UserData({ userId: user._id });
//       await userDataEntry.save();

//     } else {
//       // Update existing user if needed
//       if (!user.googleId) {
//         user.googleId = googleId;
//         await user.save();
//       }
      
//       // Check if profile is incomplete
//       if (!user.dateOfBirth || !user.gender) {
//         user.registrationComplete = false;
//         await user.save();
//       }
//     }

//     const token = generateToken(user);

//     res.json({
//       success: true,
//       token: token,
//       user: {
//         id: user._id,
//         userId: user.userId,
//         name: user.name,
//         email: user.email,
//         photoURL: user.photoURL,
//         registrationComplete: user.registrationComplete,
//         isEmailVerified: user.isEmailVerified
//       }
//     });

//   } catch (error) {
//     console.error('Google sign-in error:', error);
//     res.status(500).json({ 
//       success: false, 
//       message: 'Server error during Google sign-in',
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined
//     });
//   }
// };

// // Verify Phone
// const verifyPhone = async (req, res) => {
//   try {
//     const { phoneNumber, phone } = req.body;
//     const actualPhoneNumber = phoneNumber || phone;
    
//     console.log(`Phone verification attempt for: ${actualPhoneNumber}`);
    
//     if (!actualPhoneNumber) {
//       return res.status(400).json({ success: false, message: 'Phone number is required' });
//     }
    
//     let user = await User.findOne({ phone: actualPhoneNumber });
    
//     if (!user) {
//       const generatedUserId = await UserIdService.generateUserId();
      
//       user = new User({
//         phone: actualPhoneNumber,
//         userId: generatedUserId,
//         isPhoneVerified: true,
//         registrationComplete: false,
//       });
//       await user.save();
//       console.log(`New user created for phone: ${actualPhoneNumber} with ID: ${generatedUserId}`);
      
//       // Create userData entry for new user
//       const userData = new UserData({
//         userId: user._id
//       });
//       await userData.save();
//     } else {
//       // Update existing user
//       user.isPhoneVerified = true;
//       await user.save();
//       console.log(`Existing user found and verified: ${actualPhoneNumber}`);

//       // Ensure UserData exists for existing users
//       const userDataExists = await UserData.exists({ userId: user._id });
//       if (!userDataExists) {
//         await new UserData({ userId: user._id }).save();
//         console.log('Created missing UserData for existing user');
//       }
//     }
    
//     const token = generateToken(user);
    
//     // Return complete user data
//     return res.json({
//       success: true,
//       token,
//       user: {
//         id: user._id,
//         userId: user.userId,
//         name: user.name || '',
//         email: user.email || '',
//         phone: user.phone,
//         dateOfBirth: user.dateOfBirth || '',
//         gender: user.gender || '',
//         isPhoneVerified: user.isPhoneVerified,
//         isEmailVerified: user.isEmailVerified || false,
//         registrationComplete: user.registrationComplete
//       },
//     });
//   } catch (error) {
//     console.error('Verify phone error:', error);
    
//     if (error.code === 11000) {
//       return res.status(400).json({ 
//         success: false, 
//         message: 'Phone number already in use' 
//       });
//     }
    
//     res.status(500).json({ 
//       success: false, 
//       message: 'Server error during phone verification',
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined
//     });
//   }
// };

// // Update Profile
// const updateProfile = async (req, res) => {
//   try {
//     const { phone, phoneNumber, isPhoneVerified, name, dateOfBirth, gender } = req.body;
//     const actualPhoneNumber = phoneNumber || phone;
    
//     if (!name || !dateOfBirth || !gender) {
//       return res.status(400).json({ 
//         success: false, 
//         message: 'Name, date of birth, and gender are required' 
//       });
//     }
    
//     const token = req.headers.authorization?.split(' ')[1];
//     if (!token) {
//       return res.status(401).json({ success: false, message: 'No token provided' });
//     }
    
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     let user = await User.findById(decoded.id);
    
//     if (!user) {
//       return res.status(404).json({ success: false, message: 'User not found' });
//     }
    
//     // Check phone number availability if changing
//     if (actualPhoneNumber && actualPhoneNumber !== user.phone) {
//       const existingUserWithPhone = await User.findOne({ phone: actualPhoneNumber });
//       if (existingUserWithPhone && existingUserWithPhone._id.toString() !== user._id.toString()) {
//         return res.status(400).json({ 
//           success: false, 
//           message: 'Phone number already in use by another account' 
//         });
//       }
//       user.phone = actualPhoneNumber;
//     }
    
//     user.name = name;
//     user.dateOfBirth = dateOfBirth;
//     user.gender = gender;
    
//     if (isPhoneVerified !== undefined) {
//       user.isPhoneVerified = isPhoneVerified;
//     }
    
//     user.registrationComplete = true;
//     await user.save();
    
//     const newToken = generateToken(user);
//     res.status(200).json({
//       success: true,
//       token: newToken,
//       user: {
//         id: user._id,
//         userId: user.userId,
//         name: user.name,
//         email: user.email,
//         phone: user.phone,
//         dateOfBirth: user.dateOfBirth,
//         gender: user.gender,
//         isPhoneVerified: user.isPhoneVerified,
//         isEmailVerified: user.isEmailVerified,
//         registrationComplete: user.registrationComplete
//       },
//     });
//   } catch (error) {
//     console.error('Update profile error:', error);
//     res.status(500).json({ 
//       success: false, 
//       message: 'Server error',
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined
//     });
//   }
// };

// // Google Phone Number Fetch
// const googlePhone = async (req, res) => {
//   try {
//     const { serverAuthCode } = req.body;
    
//     if (!serverAuthCode) {
//       return res.status(400).json({ success: false, message: 'Server auth code is required' });
//     }
    
//     if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
//       console.error('Google OAuth credentials not configured');
//       return res.status(500).json({
//         success: false,
//         message: 'Server configuration error: Google OAuth credentials missing',
//       });
//     }
    
//     const oauth2Client = new google.auth.OAuth2(
//       process.env.GOOGLE_CLIENT_ID,
//       process.env.GOOGLE_CLIENT_SECRET,
//       'postmessage'
//     );
    
//     const { tokens } = await oauth2Client.getToken(serverAuthCode);
//     oauth2Client.setCredentials(tokens);
    
//     const people = google.people({ version: 'v1', auth: oauth2Client });
//     const response = await people.people.get({
//       resourceName: 'people/me',
//       personFields: 'phoneNumbers',
//     });
    
//     const phoneNumbers = response.data.phoneNumbers;
//     let phoneNumber = null;
    
//     if (phoneNumbers && phoneNumbers.length > 0) {
//       phoneNumber = phoneNumbers[0].value;
//     }
    
//     res.json({ success: true, phoneNumber });
//   } catch (error) {
//     console.error('Google phone number fetch error:', error);
    
//     if (error.response && error.response.data) {
//       console.error('Google API error details:', error.response.data);
//     }
    
//     if (error.code === 401 && error.response?.data?.error === 'invalid_client') {
//       return res.status(500).json({
//         success: false,
//         message: 'Google OAuth configuration error. Please check your Google API credentials.',
//       });
//     }
    
//     res.status(500).json({
//       success: false,
//       message: 'Failed to fetch phone number from Google',
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined,
//     });
//   }
// };

// // Check User
// const checkUser = async (req, res) => {
//   try {
//     const { phone, phoneNumber, email } = req.body;
//     const actualPhoneNumber = phoneNumber || phone;
    
//     console.log(`Check user attempt - email: ${email}, phone: ${actualPhoneNumber}`);
    
//     let query = {};
//     if (actualPhoneNumber) query.phone = actualPhoneNumber;
//     if (email) query.email = email.toLowerCase();
    
//     if (!actualPhoneNumber && !email) {
//       return res.status(400).json({ success: false, message: 'Phone or email is required' });
//     }
    
//     const user = await User.findOne(query).select('-password');
    
//     if (!user) {
//       console.log(`User not found for query:`, query);
//       return res.status(404).json({ success: false, message: 'User not found' });
//     }
    
//     console.log(`User found: ${user.name}, has password: ${!!user.password}`);
    
//     res.status(200).json({
//       success: true,
//       user: {
//         id: user._id,
//         userId: user.userId,
//         name: user.name,
//         email: user.email,
//         phone: user.phone,
//         canLoginWithPassword: !!user.password,
//         registrationComplete: user.registrationComplete,
//         isEmailVerified: user.isEmailVerified,
//         isPhoneVerified: user.isPhoneVerified
//       },
//     });
//   } catch (error) {
//     console.error('Check user error:', error);
//     res.status(500).json({ 
//       success: false, 
//       message: 'Server error',
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined
//     });
//   }
// };

// // Login
// const login = async (req, res) => {
//   try {
//     const { email, password, phone, phoneNumber } = req.body;
//     const actualPhoneNumber = phoneNumber || phone;

//     console.log(`Login attempt - Email: ${email}, Phone: ${actualPhoneNumber}`);

//     if ((!email && !actualPhoneNumber) || !password) {
//       return res.status(400).json({ 
//         success: false, 
//         message: 'Email/Phone and password are required' 
//       });
//     }

//     let user;
//     let identifier = email || actualPhoneNumber;

//     if (email) {
//       user = await User.findOne({ email: email.toLowerCase() }).select('+password');
//     } else {
//       user = await User.findOne({ phone: actualPhoneNumber }).select('+password');
//     }

//     if (!user) {
//       console.log(`User not found: ${identifier}`);
//       return res.status(404).json({ 
//         success: false, 
//         message: 'User not found' 
//       });
//     }

//     console.log(`User found: ${user.name}, has password: ${!!user.password}`);

//     if (!user.password) {
//       console.log(`User ${identifier} has no password set`);
//       return res.status(400).json({
//         success: false,
//         message: 'This account was created with Google Sign-In or phone verification. Please use the original sign-in method.',
//       });
//     }

//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) {
//       console.log(`Invalid password for user: ${identifier}`);
//       return res.status(401).json({ 
//         success: false, 
//         message: 'Invalid credentials' 
//       });
//     }

//     console.log(`Login successful for user: ${identifier}`);

//     const token = generateToken(user);

//     res.status(200).json({
//       success: true,
//       token,
//       user: {
//         id: user._id,
//         userId: user.userId,
//         name: user.name,
//         email: user.email,
//         phone: user.phone,
//         dateOfBirth: user.dateOfBirth,
//         gender: user.gender,
//         isEmailVerified: user.isEmailVerified,
//         isPhoneVerified: user.isPhoneVerified,
//         registrationComplete: user.registrationComplete,
//       },
//     });
//   } catch (error) {
//     console.error('Login error:', error);
//     res.status(500).json({ 
//       success: false, 
//       message: 'Server error',
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined
//     });
//   }
// };

// // Logout
// const logout = async (req, res) => {
//   try {
//     res.status(200).json({ 
//       success: true, 
//       message: 'Logged out successfully' 
//     });
//   } catch (error) {
//     console.error('Logout error:', error);
//     res.status(500).json({ 
//       success: false, 
//       message: 'Server error' 
//     });
//   }
// };

// // Set Password
// const setPassword = async (req, res) => {
//   try {
//     const { email, password } = req.body;
    
//     if (!email || !password) {
//       return res.status(400).json({ 
//         success: false, 
//         message: 'Email and password are required' 
//       });
//     }
    
//     const emailLower = email.toLowerCase();
//     const user = await User.findOne({ email: emailLower });
    
//     if (!user) {
//       return res.status(404).json({ 
//         success: false, 
//         message: 'User not found' 
//       });
//     }
    
//     // Hash the password
//     const salt = await bcrypt.genSalt(10);
//     user.password = await bcrypt.hash(password, salt);
    
//     await user.save();
    
//     res.status(200).json({
//       success: true,
//       message: 'Password set successfully',
//       user: {
//         id: user._id,
//         userId: user.userId,
//         name: user.name,
//         email: user.email,
//         phone: user.phone,
//         registrationComplete: user.registrationComplete,
//       }
//     });
//   } catch (error) {
//     console.error('Set password error:', error);
//     res.status(500).json({ 
//       success: false, 
//       message: 'Server error',
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined
//     });
//   }
// };

// // Check Google Config
// const checkGoogleConfig = async (req, res) => {
//   try {
//     const hasClientId = !!process.env.GOOGLE_CLIENT_ID;
//     const hasClientSecret = !!process.env.GOOGLE_CLIENT_SECRET;
    
//     res.json({
//       success: true,
//       hasGoogleClientId: hasClientId,
//       hasGoogleClientSecret: hasClientSecret,
//       clientIdLength: hasClientId ? process.env.GOOGLE_CLIENT_ID.length : 0,
//       clientSecretLength: hasClientSecret ? process.env.GOOGLE_CLIENT_SECRET.length : 0,
//       clientIdPrefix: hasClientId ? process.env.GOOGLE_CLIENT_ID.substring(0, 10) + '...' : 'None',
//       env: process.env.NODE_ENV
//     });
//   } catch (error) {
//     res.status(500).json({ 
//       success: false, 
//       message: error.message 
//     });
//   }
// };

// // Get OTP Status (for debugging)
// const getOTPStatus = async (req, res) => {
//   try {
//     const { email } = req.query;
    
//     if (!email) {
//       return res.status(400).json({
//         success: false,
//         message: 'Email is required'
//       });
//     }
    
//     const key = email.toLowerCase();
//     const stored = otpStorage.get(key);
    
//     const status = {
//       email: key,
//       hasOTP: !!stored,
//       ...(stored ? {
//         attempts: stored.attempts,
//         expiresIn: Math.max(0, stored.expiry - Date.now()),
//         expiryTime: new Date(stored.expiry).toLocaleTimeString(),
//         createdAt: new Date(stored.createdAt).toLocaleTimeString()
//       } : {}),
//       totalStoredOTPs: otpStorage.size,
//       environment: process.env.NODE_ENV
//     };
    
//     res.json({
//       success: true,
//       status
//     });
//   } catch (error) {
//     console.error('Get OTP status error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Server error'
//     });
//   }
// };

// module.exports = {
//   sendOTPEmail,
//   verifyEmailOTP,
//   getOTPStatus,
//   register,
//   googleSignIn,
//   verifyPhone,
//   updateProfile,
//   googlePhone,
//   checkUserId,
//   generateUserId,
//   resetPassword,
//   checkGoogleConfig,
//   login,
//   logout,
//   checkUser,
//   setPassword
// };
