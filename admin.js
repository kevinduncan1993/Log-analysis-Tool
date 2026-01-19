// Admin Dashboard JavaScript

let allUsers = [];

// Initialize admin page
document.addEventListener('DOMContentLoaded', () => {
    // Check authentication and admin status
    auth.onAuthStateChanged(async (user) => {
        if (!user) {
            // Not logged in, redirect to main page
            window.location.href = 'index.html';
            return;
        }

        // Check if user is admin
        const isAdmin = await checkIsAdmin(user.uid);

        if (!isAdmin) {
            // Not an admin, show denied message
            document.getElementById('adminLoading').style.display = 'none';
            document.getElementById('adminDenied').style.display = 'block';
            return;
        }

        // User is admin, show dashboard
        document.getElementById('adminLoading').style.display = 'none';
        document.getElementById('adminMain').style.display = 'block';

        // Load users
        await loadUsers();

        // Initialize event listeners
        initAdminListeners();
    });
});

function initAdminListeners() {
    // Logout button
    document.getElementById('adminLogoutBtn').addEventListener('click', async () => {
        await signOut();
        window.location.href = 'index.html';
    });

    // Refresh users
    document.getElementById('refreshUsers').addEventListener('click', loadUsers);

    // Export CSV
    document.getElementById('exportUsers').addEventListener('click', exportUsersCSV);

    // Search users
    document.getElementById('userSearch').addEventListener('input', (e) => {
        filterUsers(e.target.value);
    });
}

async function loadUsers() {
    try {
        const snapshot = await db.collection('users').orderBy('signupDate', 'desc').get();

        allUsers = [];
        snapshot.forEach(doc => {
            allUsers.push({
                id: doc.id,
                ...doc.data()
            });
        });

        updateStats();
        displayUsers(allUsers);

    } catch (error) {
        console.error('Error loading users:', error);
        alert('Error loading users: ' + error.message);
    }
}

function updateStats() {
    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const weekStart = new Date(todayStart);
    weekStart.setDate(weekStart.getDate() - 7);

    let totalUsers = allUsers.length;
    let todaySignups = 0;
    let weekSignups = 0;
    let activeToday = 0;

    allUsers.forEach(user => {
        const signupDate = user.signupDate?.toDate?.() || new Date(user.signupDate);
        const lastLogin = user.lastLogin?.toDate?.() || new Date(user.lastLogin);

        if (signupDate >= todayStart) {
            todaySignups++;
        }
        if (signupDate >= weekStart) {
            weekSignups++;
        }
        if (lastLogin >= todayStart) {
            activeToday++;
        }
    });

    document.getElementById('totalUsers').textContent = totalUsers;
    document.getElementById('todaySignups').textContent = todaySignups;
    document.getElementById('weekSignups').textContent = weekSignups;
    document.getElementById('activeToday').textContent = activeToday;
}

function displayUsers(users) {
    const tbody = document.getElementById('usersTableBody');

    if (users.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" style="text-align: center; padding: 40px; color: var(--text-muted);">
                    No users found
                </td>
            </tr>
        `;
        document.getElementById('userCount').textContent = 'Showing 0 users';
        return;
    }

    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());

    tbody.innerHTML = users.map(user => {
        const signupDate = formatDate(user.signupDate);
        const lastLogin = formatDate(user.lastLogin);
        const lastLoginDate = user.lastLogin?.toDate?.() || new Date(user.lastLogin);
        const isActive = lastLoginDate >= todayStart;

        return `
            <tr data-user-id="${user.id}">
                <td class="email-cell">${escapeHtml(user.email)}</td>
                <td class="date-cell">${signupDate}</td>
                <td class="date-cell">${lastLogin}</td>
                <td>
                    <span class="status-badge ${isActive ? 'active' : 'inactive'}">
                        ${isActive ? 'Active' : 'Inactive'}
                    </span>
                </td>
                <td>
                    <span class="admin-badge ${user.isAdmin ? 'yes' : 'no'}">
                        ${user.isAdmin ? 'Yes' : 'No'}
                    </span>
                </td>
                <td>
                    <button class="action-btn" onclick="toggleAdmin('${user.id}', ${!user.isAdmin})">
                        ${user.isAdmin ? 'Remove Admin' : 'Make Admin'}
                    </button>
                </td>
            </tr>
        `;
    }).join('');

    document.getElementById('userCount').textContent = `Showing ${users.length} user${users.length !== 1 ? 's' : ''}`;
}

function filterUsers(searchTerm) {
    const term = searchTerm.toLowerCase().trim();

    if (!term) {
        displayUsers(allUsers);
        return;
    }

    const filtered = allUsers.filter(user =>
        user.email.toLowerCase().includes(term)
    );

    displayUsers(filtered);
}

async function toggleAdmin(userId, makeAdmin) {
    const action = makeAdmin ? 'grant admin privileges to' : 'remove admin privileges from';

    if (!confirm(`Are you sure you want to ${action} this user?`)) {
        return;
    }

    try {
        await db.collection('users').doc(userId).update({
            isAdmin: makeAdmin
        });

        // Update local data
        const user = allUsers.find(u => u.id === userId);
        if (user) {
            user.isAdmin = makeAdmin;
        }

        // Refresh display
        const searchTerm = document.getElementById('userSearch').value;
        if (searchTerm) {
            filterUsers(searchTerm);
        } else {
            displayUsers(allUsers);
        }

    } catch (error) {
        console.error('Error updating user:', error);
        alert('Error updating user: ' + error.message);
    }
}

function exportUsersCSV() {
    if (allUsers.length === 0) {
        alert('No users to export');
        return;
    }

    const headers = ['Email', 'Signup Date', 'Last Login', 'Is Admin'];
    const rows = allUsers.map(user => [
        user.email,
        formatDateForCSV(user.signupDate),
        formatDateForCSV(user.lastLogin),
        user.isAdmin ? 'Yes' : 'No'
    ]);

    const csvContent = [
        headers.join(','),
        ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);

    link.setAttribute('href', url);
    link.setAttribute('download', `cysa-users-${formatDateForFilename(new Date())}.csv`);
    link.style.visibility = 'hidden';

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Utility functions
function formatDate(timestamp) {
    if (!timestamp) return 'N/A';

    const date = timestamp.toDate ? timestamp.toDate() : new Date(timestamp);

    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function formatDateForCSV(timestamp) {
    if (!timestamp) return '';

    const date = timestamp.toDate ? timestamp.toDate() : new Date(timestamp);

    return date.toISOString();
}

function formatDateForFilename(date) {
    return date.toISOString().split('T')[0];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
