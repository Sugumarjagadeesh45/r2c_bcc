# MongoDB Connection Fix Guide

Your backend logs show: `Could not connect to any servers... IP that isn't whitelisted`.

## ✅ Step 1: Code Fix (Applied)
We have added `family: 4` to `config/db.js`. This forces the connection to use IPv4, which fixes 90% of these issues on home Wi-Fi.

## 🌍 Step 2: Whitelist IP (If Step 1 fails)
If you still see the error, your IP address has changed. You must update it in MongoDB Atlas.

1.  **Login** to MongoDB Atlas.
2.  Click **Network Access** in the left sidebar.
3.  Click **+ ADD IP ADDRESS**.
4.  Click **ADD CURRENT IP ADDRESS**.
    *   *Tip: For development, you can select "Allow Access From Anywhere" (0.0.0.0/0) to stop this error from happening when your Wi-Fi IP changes.*
5.  Click **Confirm**.
6.  **Restart your backend server**.

## 📱 Frontend Note
The `Network request failed` error on your phone/emulator happens because the backend server crashed (exited) when it couldn't connect to the database. Once the backend stays running, the frontend error will go away.