# EmailJS Integration Documentation

## 🚨 CRITICAL FIX: Error 412 (Insufficient Authentication Scopes)

If you see `Gmail_API: Request had insufficient authentication scopes`, it means the Gmail service in EmailJS does not have permission to send emails.

**Steps to Fix:**
1. Go to **EmailJS Dashboard** (https://dashboard.emailjs.com).
2. Go to **Email Services**.
3. Click on your Gmail service (e.g., `Gmail_API` or `Gmail`).
4. Click **Disconnect Service**.
5. Click **Connect Account**.
6. **IMPORTANT:** When the Google popup appears, you **MUST** check the box that says:
   > ☑️ **Send email on your behalf**
   *(If you miss this checkbox, the 412 error will continue).*
7. Click **Continue**.
8. Click **Update Service** (if applicable).
9. Restart your backend server and test again.

---

## 🔑 Configuration (.env)

Ensure these variables are set in your `.env` file:

```env
EMAILJS_SERVICE_ID=service_uy8fkde
EMAILJS_TEMPLATE_ID=template_2055esi
EMAILJS_PUBLIC_KEY=wCRiqjk8IvXUOQmPJ
EMAILJS_PRIVATE_KEY=AWOfTycKXfKd61p_9qABE
```

## 📡 API Endpoints

### 1. Send OTP Email (Public)
Generates an OTP, stores it, and sends it via email.
- **URL:** `POST /api/auth/send-otp-email`
- **Body:**
  ```json
  {
    "email": "user@example.com",
    "name": "User Name"
  }
  ```

### 2. Verify OTP (Public)
Verifies the OTP entered by the user.
- **URL:** `POST /api/auth/verify-email-otp`
- **Body:**
  ```json
  {
    "email": "user@example.com",
    "otp": "123456"
  }
  ```

### 3. Test Email Delivery (Debug)
Generates a test OTP and attempts to send it immediately. Useful for debugging configuration.
- **URL:** `POST /api/auth/test-email-delivery`
- **Body:**
  ```json
  {
    "email": "your-email@gmail.com",
    "name": "Test User"
  }
  ```

## 📝 Important Notes

1. **Template Parameters:**
   Your EmailJS template (`template_2055esi`) must accept these variables:
   - `{{email}}` or `{{to_email}}`
   - `{{name}}` or `{{user_name}}`
   - `{{otp}}` or `{{otp_code}}`

2. **OTP Expiry:**
   OTPs are valid for **10 minutes**.

3. **Rate Limiting:**
   The backend limits OTP verification attempts to **5 tries** per OTP to prevent brute-force attacks.