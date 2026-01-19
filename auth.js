// Authentication UI Handler

document.addEventListener('DOMContentLoaded', () => {
    initAuthUI();
});

function initAuthUI() {
    // Auth modal elements
    const authModal = document.getElementById('authModal');
    const authTabs = document.querySelectorAll('.auth-tab');
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const forgotPasswordLink = document.getElementById('forgotPasswordLink');
    const logoutBtn = document.getElementById('logoutBtn');

    // Tab switching
    authTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetForm = tab.dataset.form;
            authTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            document.getElementById('loginFormContainer').style.display =
                targetForm === 'login' ? 'block' : 'none';
            document.getElementById('signupFormContainer').style.display =
                targetForm === 'signup' ? 'block' : 'none';

            clearAuthErrors();
        });
    });

    // Login form submission
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('loginEmail').value;
            const password = document.getElementById('loginPassword').value;
            const submitBtn = loginForm.querySelector('button[type="submit"]');

            submitBtn.disabled = true;
            submitBtn.textContent = 'Signing in...';
            clearAuthErrors();

            const result = await signIn(email, password);

            if (result.success) {
                hideAuthModal();
                loginForm.reset();
            } else {
                showAuthError('loginError', result.error);
            }

            submitBtn.disabled = false;
            submitBtn.textContent = 'Sign In';
        });
    }

    // Signup form submission
    if (signupForm) {
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('signupEmail').value;
            const password = document.getElementById('signupPassword').value;
            const confirmPassword = document.getElementById('signupConfirmPassword').value;
            const submitBtn = signupForm.querySelector('button[type="submit"]');

            clearAuthErrors();

            // Validate passwords match
            if (password !== confirmPassword) {
                showAuthError('signupError', 'Passwords do not match');
                return;
            }

            // Validate password strength
            if (password.length < 6) {
                showAuthError('signupError', 'Password must be at least 6 characters');
                return;
            }

            submitBtn.disabled = true;
            submitBtn.textContent = 'Creating account...';

            const result = await signUp(email, password);

            if (result.success) {
                hideAuthModal();
                signupForm.reset();
            } else {
                showAuthError('signupError', result.error);
            }

            submitBtn.disabled = false;
            submitBtn.textContent = 'Create Account';
        });
    }

    // Forgot password
    if (forgotPasswordLink) {
        forgotPasswordLink.addEventListener('click', async (e) => {
            e.preventDefault();
            const email = document.getElementById('loginEmail').value;

            if (!email) {
                showAuthError('loginError', 'Please enter your email address first');
                return;
            }

            const result = await resetPassword(email);

            if (result.success) {
                showAuthSuccess('loginError', 'Password reset email sent! Check your inbox.');
            } else {
                showAuthError('loginError', result.error);
            }
        });
    }

    // Logout button
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            await signOut();
        });
    }

    // Close modal on background click
    if (authModal) {
        authModal.addEventListener('click', (e) => {
            if (e.target === authModal) {
                // Only allow closing if user is logged in
                if (currentUser) {
                    hideAuthModal();
                }
            }
        });
    }
}

function showAuthModal() {
    const modal = document.getElementById('authModal');
    if (modal) {
        modal.style.display = 'flex';
    }
}

function hideAuthModal() {
    const modal = document.getElementById('authModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function showAuthError(elementId, message) {
    const errorEl = document.getElementById(elementId);
    if (errorEl) {
        errorEl.textContent = message;
        errorEl.className = 'auth-message error';
        errorEl.style.display = 'block';
    }
}

function showAuthSuccess(elementId, message) {
    const errorEl = document.getElementById(elementId);
    if (errorEl) {
        errorEl.textContent = message;
        errorEl.className = 'auth-message success';
        errorEl.style.display = 'block';
    }
}

function clearAuthErrors() {
    document.querySelectorAll('.auth-message').forEach(el => {
        el.style.display = 'none';
        el.textContent = '';
    });
}

// Show auth modal if user is not logged in
auth.onAuthStateChanged((user) => {
    if (!user) {
        // Small delay to ensure page is loaded
        setTimeout(() => {
            showAuthModal();
        }, 100);
    }
});
