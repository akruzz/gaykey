'use strict';

/**
 * gaykey — Password Generator
 *
 * Modules
 * ───────
 * CharsetService    — builds character pools based on selected options.
 * PasswordGenerator — pure crypto-secure generation with guaranteed coverage.
 * StrengthEvaluator — entropy-based strength scoring, 1–4 scale.
 * UI                — sole DOM-aware module; wires everything together.
 */

/* ============================================================
   CharsetService
   ============================================================ */
const CharsetService = (() => {
  const POOLS = {
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    numbers:   '0123456789',
    symbols:   '!@#$%^&*()_+-=[]{}|;:,.<>?',
  };

  const AMBIGUOUS = new Set(['l', 'I', '1', 'O', '0', 'o']);

  function build(types, excludeAmbiguous) {
    const pools = {};
    for (const key of Object.keys(POOLS)) {
      if (!types[key]) continue;
      let chars = POOLS[key];
      if (excludeAmbiguous) chars = [...chars].filter(c => !AMBIGUOUS.has(c)).join('');
      if (chars.length) pools[key] = chars;
    }
    return { pools, combined: Object.values(pools).join('') };
  }

  return { build };
})();


/* ============================================================
   PasswordGenerator
   ============================================================ */
const PasswordGenerator = (() => {
  function secureRandom(max) {
    const buf = new Uint32Array(1);
    crypto.getRandomValues(buf);
    return buf[0] % max;
  }

  function pick(charset) {
    return charset[secureRandom(charset.length)];
  }

  function shuffle(arr) {
    const out = [...arr];
    for (let i = out.length - 1; i > 0; i--) {
      const j = secureRandom(i + 1);
      [out[i], out[j]] = [out[j], out[i]];
    }
    return out;
  }

  function generate(length, types, excludeAmbiguous) {
    const { pools, combined } = CharsetService.build(types, excludeAmbiguous);
    if (!combined) throw new Error('Select at least one character type.');

    // Guarantee ≥1 char from every active pool, then fill the rest randomly.
    const guaranteed = Object.values(pools).map(pick);
    const fill       = Array.from({ length: Math.max(length - guaranteed.length, 0) }, () => pick(combined));

    return shuffle([...guaranteed, ...fill]).slice(0, length).join('');
  }

  return { generate };
})();


/* ============================================================
   StrengthEvaluator
   ============================================================ */
const StrengthEvaluator = (() => {
  const SCORES = [
    { min: 0,  label: 'Weak',      score: 1 },
    { min: 36, label: 'Medium',    score: 2 },
    { min: 60, label: 'Strong',    score: 3 },
    { min: 80, label: 'Very Strong', score: 4 },
  ];

  function evaluate(password) {
    if (!password) return { label: '—', score: 0 };

    const poolSize =
      (/[A-Z]/.test(password)     ? 26 : 0) +
      (/[a-z]/.test(password)     ? 26 : 0) +
      (/[0-9]/.test(password)     ? 10 : 0) +
      (/[^A-Za-z0-9]/.test(password) ? 26 : 0);

    const variety =
      (/[A-Z]/.test(password)     ? 1 : 0) +
      (/[a-z]/.test(password)     ? 1 : 0) +
      (/[0-9]/.test(password)     ? 1 : 0) +
      (/[^A-Za-z0-9]/.test(password) ? 1 : 0);

    const entropy = password.length * Math.log2(Math.max(poolSize, 2));

    let result = SCORES[0];
    for (const s of SCORES) {
      if (entropy >= s.min) result = s;
    }

    // Clamp very-strong to only if variety ≥ 3
    if (result.score === 4 && variety < 3) result = SCORES[2];

    return result;
  }

  return { evaluate };
})();


/* ============================================================
   UI
   ============================================================ */
const UI = (() => {
  /* ── Element refs ─────────────────────────────────────── */
  const $ = id => document.getElementById(id);
  const el = {
    passwordField:  $('passwordField'),
    passwordOutput: $('passwordOutput'),
    copyToast:      $('copyToast'),
    copyIconDefault: $('copyIconDefault'),
    copyIconDone:   $('copyIconDone'),
    strengthFill:   $('strengthFill'),
    strengthLabel:  $('strengthLabel'),
    length:         $('length'),
    lengthValue:    $('lengthValue'),
    uppercase:      $('uppercase'),
    lowercase:      $('lowercase'),
    numbers:        $('numbers'),
    symbols:        $('symbols'),
    excludeAmbig:   $('excludeAmbiguous'),
    generateBtn:    $('generateBtn'),
    errorMsg:       $('errorMsg'),
  };

  let copyTimer  = null;
  let hasGenerated = false;

  /* ── Helpers ──────────────────────────────────────────── */
  function types() {
    return {
      uppercase: el.uppercase.checked,
      lowercase: el.lowercase.checked,
      numbers:   el.numbers.checked,
      symbols:   el.symbols.checked,
    };
  }

  function updateSliderFill() {
    const min = Number(el.length.min);
    const max = Number(el.length.max);
    const val = Number(el.length.value);
    const pct = ((val - min) / (max - min)) * 100;
    el.length.style.setProperty('--fill', `${pct}%`);
    el.lengthValue.textContent = val;
  }

  function renderStrength(password) {
    const { label, score } = StrengthEvaluator.evaluate(password);
    el.strengthLabel.textContent = label;
    el.strengthFill.setAttribute('data-strength', score);
    const bar = el.strengthFill.closest('[role="progressbar"]');
    if (bar) bar.setAttribute('aria-valuenow', score * 25);
  }

  function showError(msg) {
    el.errorMsg.textContent = msg;
    el.errorMsg.hidden = false;
  }

  function clearError() {
    el.errorMsg.hidden = true;
  }

  /* ── Copy to clipboard ────────────────────────────────── */
  async function copyPassword() {
    const text = el.passwordOutput.textContent;
    if (!text || !hasGenerated) return;

    try {
      await navigator.clipboard.writeText(text);
    } catch {
      /* Fallback for file:// or restricted contexts */
      const tmp = document.createElement('textarea');
      tmp.value = text;
      tmp.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
      document.body.appendChild(tmp);
      tmp.select();
      document.execCommand('copy');
      document.body.removeChild(tmp);
    }

    /* Visual feedback */
    el.passwordField.classList.add('is-copied');
    el.copyIconDefault.style.display = 'none';
    el.copyIconDone.style.display    = 'block';
    el.copyToast.classList.add('is-visible');

    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => {
      el.passwordField.classList.remove('is-copied');
      el.copyIconDefault.style.display = 'block';
      el.copyIconDone.style.display    = 'none';
      el.copyToast.classList.remove('is-visible');
    }, 1800);
  }

  /* ── Generate ─────────────────────────────────────────── */
  function generate() {
    try {
      const password = PasswordGenerator.generate(
        Number(el.length.value),
        types(),
        el.excludeAmbig.checked
      );

      el.passwordOutput.textContent = password;
      el.passwordOutput.classList.remove('is-placeholder');
      clearError();
      renderStrength(password);
      hasGenerated = true;

      /* Brief pop animation on the field */
      el.passwordField.animate(
        [{ transform: 'scale(1)' }, { transform: 'scale(1.012)' }, { transform: 'scale(1)' }],
        { duration: 200, easing: 'ease-out' }
      );
    } catch (err) {
      showError(err.message);
      renderStrength('');
    }
  }

  /* ── Events ───────────────────────────────────────────── */
  function bind() {
    el.generateBtn.addEventListener('click', generate);
    el.passwordField.addEventListener('click', copyPassword);

    el.length.addEventListener('input', () => {
      updateSliderFill();
      if (hasGenerated) generate();
    });

    [el.uppercase, el.lowercase, el.numbers, el.symbols, el.excludeAmbig].forEach(cb => {
      cb.addEventListener('change', () => { if (hasGenerated) generate(); });
    });
  }

  /* ── Init ─────────────────────────────────────────────── */
  function init() {
    updateSliderFill();
    bind();

    /* Show placeholder state */
    el.passwordOutput.classList.add('is-placeholder');
    renderStrength('');
  }

  return { init };
})();

document.addEventListener('DOMContentLoaded', UI.init);
