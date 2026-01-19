# CySA+ Exam Prep Tool - Setup & Deployment Guide

## Prerequisites
- Google account
- Node.js installed (for Firebase CLI)

## Step 1: Create Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click **"Create a project"**
3. Enter project name (e.g., "cysa-exam-prep")
4. Disable Google Analytics (optional) and click **Create**

## Step 2: Enable Authentication

1. In Firebase Console, go to **Build > Authentication**
2. Click **"Get started"**
3. Go to **Sign-in method** tab
4. Enable **Email/Password** provider
5. Click **Save**

## Step 3: Create Firestore Database

1. Go to **Build > Firestore Database**
2. Click **"Create database"**
3. Select **"Start in production mode"**
4. Choose a location closest to your users
5. Click **Enable**

## Step 4: Get Firebase Config

1. Go to **Project Settings** (gear icon)
2. Scroll down to **"Your apps"**
3. Click the web icon **(</>)** to add a web app
4. Register app with a nickname (e.g., "CySA Web App")
5. Copy the `firebaseConfig` object

## Step 5: Update Firebase Config

1. Open `firebase-config.js` in your project
2. Replace the placeholder values with your config:

```javascript
const firebaseConfig = {
    apiKey: "your-actual-api-key",
    authDomain: "your-project-id.firebaseapp.com",
    projectId: "your-project-id",
    storageBucket: "your-project-id.appspot.com",
    messagingSenderId: "your-sender-id",
    appId: "your-app-id"
};
```

## Step 6: Deploy Security Rules

1. In Firebase Console, go to **Firestore Database > Rules**
2. Copy contents from `firestore.rules` file
3. Paste and click **Publish**

## Step 7: Deploy to Firebase Hosting

### Install Firebase CLI
```bash
npm install -g firebase-tools
```

### Login to Firebase
```bash
firebase login
```

### Initialize Firebase in your project
```bash
cd C:\Users\kevin\Desktop\Log-Analysis-Tool
firebase init
```

Select:
- **Hosting**: Configure files for Firebase Hosting
- Choose your project
- Public directory: `.` (current directory)
- Single-page app: **No**
- Don't overwrite index.html

### Deploy
```bash
firebase deploy
```

Your app will be live at: `https://your-project-id.web.app`

## Step 8: Create First Admin User

1. Go to your deployed app and create an account
2. In Firebase Console, go to **Firestore Database**
3. Find your user document in the `users` collection
4. Click on the document and edit the `isAdmin` field to `true`
5. Now you can access `/admin.html` to manage users

## File Structure

```
Log-Analysis-Tool/
├── index.html          # Main application
├── admin.html          # Admin dashboard
├── styles.css          # Main styles
├── admin.css           # Admin-specific styles
├── app.js              # Main app logic
├── auth.js             # Authentication handling
├── admin.js            # Admin dashboard logic
├── data.js             # Practice scenarios data
├── firebase-config.js  # Firebase configuration
├── firestore.rules     # Security rules
└── SETUP.md            # This file
```

## Accessing Admin Dashboard

After setting up your admin account:
- Go to `https://your-app-url/admin.html`
- You'll see all registered users
- You can grant/revoke admin access to other users
- Export user list as CSV

## Troubleshooting

### "Permission denied" errors
- Make sure Firestore rules are deployed
- Verify user document has correct `isAdmin` value

### Auth not working
- Check Firebase config values are correct
- Ensure Email/Password auth is enabled

### Users not appearing in admin
- Check browser console for errors
- Verify Firestore rules allow admin reads
