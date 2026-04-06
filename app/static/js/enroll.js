/**
 * enroll.js — 2FA enrollment wizard logic
 * Steps: 1 (get app) → 2 (scan QR) → 3 (verify code)
 */

let currentStep = 1;
let enrollingSecret = null;
let enrollingUserId = null;

const alertArea = document.getElementById('alert-area');

function showAlert(msg, type = 'error') {
  const icons = { error: '❌', success: '✅', warning: '⚠️', info: 'ℹ️' };
  alertArea.innerHTML = `<div class="alert alert-${type}">${icons[type]} ${msg}</div>`;
}

function showStep(step) {
  [1, 2, 3].forEach(n => {
    document.getElementById(`step-${n}`).classList.toggle('hidden', n !== step);
    const ind = document.getElementById(`step-ind-${n}`);
    ind.classList.remove('active', 'completed');
    if (n < step) ind.classList.add('completed');
    if (n === step) ind.classList.add('active');
  });
  currentStep = step;
  alertArea.innerHTML = '';
}

// ── Step 1 → 2 ────────────────────────────────────────────────────────────
document.getElementById('step1-next').addEventListener('click', async () => {
  const btn = document.getElementById('step1-next');
  btn.disabled = true;
  btn.innerHTML = '<span class="btn-loading"></span>';

  enrollingUserId = sessionStorage.getItem('enrolling_user_id');

  try {
    const body = enrollingUserId ? { user_id: enrollingUserId } : {};
    const res = await fetch('/api/enroll-2fa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      credentials: 'same-origin',
    });
    const data = await res.json();

    if (!res.ok) {
      showAlert(data.error || 'Failed to generate QR code. Please log in first.');
      btn.disabled = false;
      btn.innerHTML = 'I have the app →';
      return;
    }

    enrollingSecret = data.manual_secret;

    // Show QR image
    document.getElementById('qr-loading').classList.add('hidden');
    const qrImg = document.getElementById('qr-image');
    qrImg.src = data.qr_image;
    document.getElementById('qr-wrapper').classList.remove('hidden');
    document.getElementById('secret-display').textContent = data.manual_secret;

    showStep(2);
  } catch {
    showAlert('Network error. Please try again.');
    btn.disabled = false;
    btn.innerHTML = 'I have the app →';
  }
});

document.getElementById('step2-back').addEventListener('click', () => showStep(1));
document.getElementById('step2-next').addEventListener('click', () => {
  showStep(3);
  // Initialize OTP inputs for step 3
  setupOtpInputs();
  document.getElementById('e0').focus();
});
document.getElementById('step3-back').addEventListener('click', () => showStep(2));

// ── OTP Inputs for Step 3 ─────────────────────────────────────────────────
const eDigits = Array.from({ length: 6 }, (_, i) => document.getElementById(`e${i}`));
const confirmBtn = document.getElementById('confirm-btn');

function setupOtpInputs() {
  eDigits.forEach((digit, idx) => {
    digit.value = '';
    digit.classList.remove('filled', 'error', 'success');

    digit.oninput = (e) => {
      const val = e.target.value.replace(/\D/g, '');
      digit.value = val ? val[val.length - 1] : '';
      if (digit.value) {
        digit.classList.add('filled');
        if (idx < 5) eDigits[idx + 1].focus();
      } else {
        digit.classList.remove('filled');
      }
      confirmBtn.disabled = eDigits.map(d => d.value).join('').length !== 6;
    };

    digit.onkeydown = (e) => {
      if (e.key === 'Backspace' && !digit.value && idx > 0) {
        eDigits[idx - 1].value = '';
        eDigits[idx - 1].classList.remove('filled');
        eDigits[idx - 1].focus();
        confirmBtn.disabled = true;
      }
    };

    digit.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasted = (e.clipboardData || window.clipboardData)
        .getData('text').replace(/\D/g, '').slice(0, 6);
      pasted.split('').forEach((ch, i) => {
        if (eDigits[i]) { eDigits[i].value = ch; eDigits[i].classList.add('filled'); }
      });
      if (pasted.length === 6) { eDigits[5].focus(); confirmBtn.disabled = false; }
    });
  });
}

// ── Confirm Enrollment ─────────────────────────────────────────────────────
confirmBtn.addEventListener('click', async () => {
  const code = eDigits.map(d => d.value).join('');
  if (code.length !== 6) return;

  confirmBtn.disabled = true;
  confirmBtn.innerHTML = '<span class="btn-loading"></span>';

  try {
    const body = { totp_code: code };
    if (enrollingUserId) body.user_id = enrollingUserId;
    if (enrollingSecret) body.secret = enrollingSecret;

    const res = await fetch('/api/confirm-2fa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      credentials: 'same-origin',
    });
    const data = await res.json();

    if (res.ok) {
      eDigits.forEach(d => { d.classList.remove('error'); d.classList.add('success'); });
      sessionStorage.removeItem('enrolling_user_id');
      showAlert('✅ 2FA enabled! Redirecting to dashboard...', 'success');
      setTimeout(() => window.location.href = data.redirect || '/dashboard', 1200);
    } else {
      eDigits.forEach(d => { d.classList.add('error'); d.value = ''; d.classList.remove('filled'); });
      showAlert(data.error || 'Invalid code. Please try again.');
      confirmBtn.disabled = false;
      confirmBtn.innerHTML = '<span>✅ Confirm &amp; Enable 2FA</span>';
      eDigits[0].focus();
    }
  } catch {
    showAlert('Network error. Please try again.');
    confirmBtn.disabled = false;
    confirmBtn.innerHTML = '<span>✅ Confirm &amp; Enable 2FA</span>';
  }
});
