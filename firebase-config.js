// Firebase Configuration
// IMPORTANT: Replace these values with your own Firebase project config
// Get these from: Firebase Console > Project Settings > General > Your apps > Web app

const firebaseConfig = {
    apiKey: "AIzaSyDev3900M-3W8VAsDsg2qOnynqgVT85w9U",
    authDomain: "cysa-exam-prep.firebaseapp.com",
    projectId: "cysa-exam-prep",
    storageBucket: "cysa-exam-prep.firebasestorage.app",
    messagingSenderId: "379907092142",
    appId: "1:379907092142:web:e019c76b9fe8753cc1c73f"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);

// Initialize services
const auth = firebase.auth();
const db = firebase.firestore();

// Auth state observer
let currentUser = null;

auth.onAuthStateChanged(async (user) => {
    currentUser = user;
    if (user) {
        // User is signed in
        console.log('User signed in:', user.email);
        document.body.classList.add('logged-in');
        document.body.classList.remove('logged-out');

        // Update user's last login
        updateUserLastLogin(user);

        // Update UI with user info
        updateUserUI(user);

        // Check if user is admin and show admin link
        const isAdmin = await checkIsAdmin(user.uid);
        const adminLink = document.getElementById('adminLink');
        if (adminLink) {
            adminLink.style.display = isAdmin ? 'inline-block' : 'none';
        }
    } else {
        // User is signed out
        console.log('User signed out');
        document.body.classList.remove('logged-in');
        document.body.classList.add('logged-out');

        // Hide admin link when logged out
        const adminLink = document.getElementById('adminLink');
        if (adminLink) {
            adminLink.style.display = 'none';
        }
    }
});

// Update user's last login timestamp
async function updateUserLastLogin(user) {
    try {
        await db.collection('users').doc(user.uid).update({
            lastLogin: firebase.firestore.FieldValue.serverTimestamp()
        });
    } catch (error) {
        // Document might not exist yet, that's okay
        console.log('Could not update last login:', error.message);
    }
}

// Update UI with user info
function updateUserUI(user) {
    const userEmailEl = document.getElementById('userEmail');
    if (userEmailEl) {
        userEmailEl.textContent = user.email;
    }
}

// Sign up new user
async function signUp(email, password) {
    try {
        const userCredential = await auth.createUserWithEmailAndPassword(email, password);
        const user = userCredential.user;

        // Create user document in Firestore
        await db.collection('users').doc(user.uid).set({
            email: user.email,
            signupDate: firebase.firestore.FieldValue.serverTimestamp(),
            lastLogin: firebase.firestore.FieldValue.serverTimestamp(),
            isAdmin: false
        });

        return { success: true, user };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Sign in existing user
async function signIn(email, password) {
    try {
        const userCredential = await auth.signInWithEmailAndPassword(email, password);
        return { success: true, user: userCredential.user };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Sign out
async function signOut() {
    try {
        await auth.signOut();
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Password reset
async function resetPassword(email) {
    try {
        await auth.sendPasswordResetEmail(email);
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Check if user is admin
async function checkIsAdmin(uid) {
    try {
        const doc = await db.collection('users').doc(uid).get();
        if (doc.exists) {
            return doc.data().isAdmin === true;
        }
        return false;
    } catch (error) {
        return false;
    }
}
