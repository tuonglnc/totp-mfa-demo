/**
 * verify.js — TOTP verification page logic
 * Features: auto-advance OTP inputs, 30s countdown ring, replay-safe submission
 */

const digits = Array.from({ length: 6 }, (_, i) => document.getElementById(`d${i}`));
const verifyBtn = document.getElementById('verify-btn');
const alertArea = document.getElementById('alert-area');
const timerCount = document.getElementById('timer-count');
const timerProgress = document.getElementById('timer-progress');
const attemptsInfo = document.getElementById('attempts-info');

const CIRCUMFERENCE = 138; // 2π × 22 ≈ 138

// ── TOTP Countdown Timer ──────────────────────────────────────────────────
function updateTimer() {
  const now = Math.floor(Date.now() / 1000);
  const remaining = 30 - (now % 30);
  const fraction = remaining / 30;

  timerCount.textContent = remaining;
  timerProgress.style.strokeDashoffset = CIRCUMFERENCE * (1 - fraction);

  // Color feedback
  if (remaining <= 5) {
    timerProgress.style.stroke = 'var(--danger)';
    timerCount.style.color = 'var(--danger)';
  } else if (remaining <= 10) {
    timerProgress.style.stroke = 'var(--warning)';
    timerCount.style.color = 'var(--warning)';
  } else {
    timerProgress.style.stroke = 'var(--accent-1)';
    timerCount.style.color = 'var(--accent-1)';
  }
}
updateTimer();
setInterval(updateTimer, 500);

// ── OTP Input Handling ────────────────────────────────────────────────────
digits.forEach((digit, idx) => {
  digit.addEventListener('input', (e) => {
    const val = e.target.value.replace(/\D/g, '');
    digit.value = val ? val[val.length - 1] : '';

    if (digit.value) {
      digit.classList.remove('error');
      digit.classList.add('filled');
      if (idx < 5) digits[idx + 1].focus();
    } else {
      digit.classList.remove('filled');
    }
    updateSubmitBtn();
  });

  digit.addEventListener('keydown', (e) => {
    if (e.key === 'Backspace') {
      if (!digit.value && idx > 0) {
        digits[idx - 1].value = '';
        digits[idx - 1].classList.remove('filled');
        digits[idx - 1].focus();
      }
      updateSubmitBtn();
    }
    if (e.key === 'ArrowLeft' && idx > 0) digits[idx - 1].focus();
    if (e.key === 'ArrowRight' && idx < 5) digits[idx + 1].focus();
  });

  // Allow pasting a full 6-digit code
  digit.addEventListener('paste', (e) => {
    e.preventDefault();
    const pasted = (e.clipboardData || window.clipboardData)
      .getData('text').replace(/\D/g, '').slice(0, 6);
    pasted.split('').forEach((ch, i) => {
      if (digits[i]) {
        digits[i].value = ch;
        digits[i].classList.add('filled');
      }
    });
    if (pasted.length === 6) digits[5].focus();
    updateSubmitBtn();
  });
});

// Focus first digit on load
digits[0].focus();

function getCode() { return digits.map(d => d.value).join(''); }
function updateSubmitBtn() { verifyBtn.disabled = getCode().length !== 6; }

function showAlert(msg, type = 'error') {
  const icons = { error: '❌', success: '✅', warning: '⚠️', info: 'ℹ️' };
  alertArea.innerHTML = `<div class="alert alert-${type}">${icons[type]} ${msg}</div>`;
}

function setDigitsState(state) {
  digits.forEach(d => {
    d.classList.remove('error', 'success');
    if (state) d.classList.add(state);
  });
}

function clearDigits() {
  digits.forEach(d => {
    d.value = '';
    d.classList.remove('filled', 'error', 'success');
  });
  updateSubmitBtn();
  digits[0].focus();
}

// ── Form Submission ───────────────────────────────────────────────────────
document.getElementById('totp-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const sessionToken = sessionStorage.getItem('pending_session_token');
  if (!sessionToken) {
    showAlert('Session expired. <a href="/login">Log in again</a>.', 'warning');
    return;
  }

  const code = getCode();
  if (code.length !== 6) return;

  verifyBtn.disabled = true;
  verifyBtn.innerHTML = '<span class="btn-loading"></span>';
  alertArea.innerHTML = '';

  try {
    const res = await fetch('/api/verify-totp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_token: sessionToken,
        totp_code: code,
      }),
    });
    const data = await res.json();

    if (res.ok) {
      setDigitsState('success');
      digits.forEach(d => d.classList.add('animate-success'));
      sessionStorage.removeItem('pending_session_token');
      showAlert('Authenticated! Redirecting...', 'success');
      setTimeout(() => window.location.href = data.redirect || '/dashboard', 900);
    } else {
      setDigitsState('error');

      if (res.status === 423) {
        const mins = Math.ceil((data.retry_after_seconds || 900) / 60);
        showAlert(`Account locked for ${mins} min. Too many failed attempts.`, 'warning');
      } else if (res.status === 429) {
        showAlert('Too many requests. Please wait.', 'warning');
      } else {
        const remaining = data.failed_attempts
          ? `${Math.max(0, 5 - data.failed_attempts)} attempt(s) remaining.`
          : '';
        showAlert(`${data.error} ${remaining}`);
        if (data.failed_attempts) {
          attemptsInfo.textContent = `Failed attempts: ${data.failed_attempts}/5`;
        }
      }

      // Clear and re-focus after shake animation
      setTimeout(() => {
        clearDigits();
        verifyBtn.disabled = false;
        verifyBtn.innerHTML = '<span>Verify Code</span>';
      }, 600);
    }
  } catch {
    showAlert('Network error. Please try again.');
    clearDigits();
    verifyBtn.disabled = false;
    verifyBtn.innerHTML = '<span>Verify Code</span>';
  }
});
