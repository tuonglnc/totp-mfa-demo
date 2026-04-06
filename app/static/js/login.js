/**
 * login.js — Login form handler with 2-phase auth support
 */

const form = document.getElementById('login-form');
const alertArea = document.getElementById('alert-area');
const loginBtn = document.getElementById('login-btn');
const togglePwd = document.getElementById('toggle-password');
const pwdInput = document.getElementById('password');

// Toggle password visibility
togglePwd?.addEventListener('click', () => {
  pwdInput.type = pwdInput.type === 'password' ? 'text' : 'password';
});

function showAlert(message, type = 'error') {
  const icons = { error: '❌', success: '✅', warning: '⚠️', info: 'ℹ️' };
  alertArea.innerHTML = `<div class="alert alert-${type}">${icons[type]} ${message}</div>`;
}

function setLoading(loading) {
  loginBtn.disabled = loading;
  loginBtn.innerHTML = loading
    ? '<span class="btn-loading"></span>'
    : '<span>Sign In</span>';
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  alertArea.innerHTML = '';

  const username = document.getElementById('username').value.trim();
  const password = pwdInput.value;

  if (!username || !password) {
    showAlert('Please enter username and password.');
    return;
  }

  setLoading(true);

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (res.status === 423) {
      const mins = Math.ceil((data.retry_after_seconds || 900) / 60);
      showAlert(`Account locked. Try again in ${mins} minute(s).`, 'warning');
      setLoading(false);
      return;
    }

    if (res.status === 429) {
      showAlert('Too many requests. Please wait a moment.', 'warning');
      setLoading(false);
      return;
    }

    if (!res.ok) {
      // Shake username/password inputs
      ['username', 'password'].forEach(id => {
        const el = document.getElementById(id);
        el.classList.add('error');
        setTimeout(() => el.classList.remove('error'), 600);
      });
      showAlert(data.error || 'Invalid credentials.');
      setLoading(false);
      return;
    }

    if (data.requires_2fa) {
      // Store session token and redirect to MFA verification
      sessionStorage.setItem('pending_session_token', data.session_token);
      showAlert('Password verified. Redirecting to 2FA...', 'success');
      setTimeout(() => window.location.href = '/verify-mfa', 800);
    } else {
      showAlert('Login successful!', 'success');
      setTimeout(() => window.location.href = data.redirect || '/dashboard', 800);
    }
  } catch {
    showAlert('Network error. Please try again.');
    setLoading(false);
  }
});
