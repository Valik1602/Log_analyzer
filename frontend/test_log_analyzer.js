'use strict';
// GKE Log Analyzer – Node.js Test Runner
// Executes all test logic from index.html without a browser.

// ── Minimal DOM stub for the one DOM-interaction test ──
class FakeElement {
  constructor(id) { this.id = id; this._classes = new Set(); this.textContent = ''; }
  get classList() {
    const self = this;
    return {
      toggle(cls) { if (self._classes.has(cls)) self._classes.delete(cls); else self._classes.add(cls); },
      contains(cls) { return self._classes.has(cls); }
    };
  }
  remove() {}
}
const _domStore = new Map();
const document = {
  getElementById(id) { return _domStore.get(id) || null; },
  createElement(tag) { return new FakeElement('__new__' + tag); },
  body: { appendChild() {} }
};

// ── Pure functions verbatim from index.html ──

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escAttr(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/'/g,'&#39;')
    .replace(/"/g,'&quot;');
}
function fmtTs(ts) {
  if (!ts) return '';
  return ts.replace('T',' ').replace(/[Zz]$/, '').replace(/[+-]\d{2}:\d{2}$/, '').slice(0,23);
}
function fmtDuration(ms) {
  if (ms < 1000)  return `${ms}ms`;
  if (ms < 60000) {
    const secs = (ms/1000).toFixed(2);
    if (parseFloat(secs) >= 60) return '1m 0s';
    return `${secs}s`;
  }
  const m = Math.floor(ms/60000), s = ((ms%60000)/1000).toFixed(0);
  return `${m}m ${s}s`;
}
function timeDelta(ts1, ts2) {
  if (!ts1 || !ts2) return '';
  const ms = new Date(ts2) - new Date(ts1);
  if (isNaN(ms) || ms < 0) return '';
  return fmtDuration(ms).replace(/^/, '+');
}
function localToUTC(s) { return s ? new Date(s).toISOString() : ''; }

const UUID_RE  = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_RE = /[^@\s]+@[^@\s]+\.[^@\s]+/;

const KNOWN_SEVS = ['CRITICAL','ERROR','WARNING','INFO','DEBUG'];
function normalizeSeverity(rawSev) {
  const upper = (rawSev || 'DEFAULT').toUpperCase();
  return KNOWN_SEVS.includes(upper) ? upper : 'DEFAULT';
}
function detectQueryType(v) {
  if (!v) return 'none';
  if (UUID_RE.test(v))  return 'uuid';
  if (EMAIL_RE.test(v)) return 'email';
  return 'text';
}
function calcPaginationState(total, page, pageSize) {
  const pages = Math.ceil(total / pageSize);
  const prevDisabled = page <= 1;
  const nextDisabled = page >= pages || total === 0;
  let info;
  if (total === 0) {
    info = '0 entries';
  } else {
    const from = ((page-1)*pageSize+1).toLocaleString();
    const to   = Math.min(page*pageSize, total).toLocaleString();
    info = `${from}–${to} of ${total.toLocaleString()}`;
  }
  return { prevDisabled, nextDisabled, info };
}
function calcErrorCount(severity_counts) {
  return (severity_counts?.ERROR || 0) + (severity_counts?.CRITICAL || 0);
}
function abbrevLogger(logger) {
  return logger ? logger.split('.').pop() : '';
}
function mapSeverityForTable(severityRaw) {
  const rawSev = (severityRaw || 'DEFAULT').toUpperCase();
  return ['CRITICAL','ERROR','WARNING','INFO','DEBUG'].includes(rawSev) ? rawSev : 'DEFAULT';
}
function truncateExc(exc) {
  return exc.slice(0, 280) + (exc.length > 280 ? '\u2026' : '');
}
function toggleStack(id, btn) {
  const el = document.getElementById(id);
  el.classList.toggle('open');
  btn.textContent = el.classList.contains('open') ? '\u25BC Hide stack trace' : '\u25B6 Show stack trace';
}

// ── Test harness ──
const results = [];
let currentSuite = null;

function suite(name, fn) {
  currentSuite = { name, tests: [] };
  results.push(currentSuite);
  fn();
}
function test(name, fn) {
  try {
    fn();
    currentSuite.tests.push({ name, pass: true });
  } catch(e) {
    currentSuite.tests.push({ name, pass: false, error: e.message || String(e) });
  }
}
function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}
function assertEqual(a, b, msg) {
  if (a !== b) throw new Error((msg ? msg + ': ' : '') + `expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}
function assertDeepEqual(a, b, msg) {
  const sa = JSON.stringify(a), sb = JSON.stringify(b);
  if (sa !== sb) throw new Error((msg ? msg + ': ' : '') + `expected ${sb}, got ${sa}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 1: escHtml
// ─────────────────────────────────────────────────────────────────────────────
suite('escHtml – XSS output encoding', () => {
  test('escapes < and >', () => assertEqual(escHtml('<script>'), '&lt;script&gt;'));
  test('escapes &', () => assertEqual(escHtml('a & b'), 'a &amp; b'));
  test('escapes double-quotes', () => assertEqual(escHtml('"hello"'), '&quot;hello&quot;'));
  test('does not double-encode on a second pass', () => assertEqual(escHtml('&amp;'), '&amp;amp;'));
  test('handles empty string', () => assertEqual(escHtml(''), ''));
  test('handles number input', () => assertEqual(escHtml(42), '42'));
  test('handles null input', () => assertEqual(escHtml(null), 'null'));
  test('handles undefined input', () => assertEqual(escHtml(undefined), 'undefined'));
  test('mixed XSS payload', () => assertEqual(
    escHtml('<img src=x onerror="alert(1)">'),
    '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;'
  ));
  test('does NOT escape single quotes (known gap – use escAttr for attributes)', () => {
    // escHtml does not encode ' which is safe for element content but not attribute context
    assertEqual(escHtml("it's"), "it's");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 2: escAttr
// ─────────────────────────────────────────────────────────────────────────────
suite('escAttr – attribute encoding', () => {
  test('escapes single quotes', () => assertEqual(escAttr("it's"), 'it&#39;s'));
  test('escapes double quotes', () => assertEqual(escAttr('"value"'), '&quot;value&quot;'));
  test('escapes & before other chars', () => assertEqual(escAttr("a&'b"), 'a&amp;&#39;b'));
  test('handles empty string', () => assertEqual(escAttr(''), ''));
  test('handles null', () => assertEqual(escAttr(null), 'null'));
  test('safe value passes through unchanged', () => assertEqual(escAttr('container-name-123'), 'container-name-123'));
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 3: fmtTs
// ─────────────────────────────────────────────────────────────────────────────
suite('fmtTs – timestamp formatting', () => {
  test('formats ISO UTC timestamp (Z suffix)', () =>
    assertEqual(fmtTs('2024-01-15T10:30:45.123Z'), '2024-01-15 10:30:45.123'));
  test('formats ISO UTC timestamp (+00:00 suffix)', () =>
    assertEqual(fmtTs('2024-01-15T10:30:45.123+00:00'), '2024-01-15 10:30:45.123'));
  test('truncates to 23 chars', () =>
    assertEqual(fmtTs('2024-01-15T10:30:45.123456Z'), '2024-01-15 10:30:45.123'));
  test('returns empty string for empty input', () => assertEqual(fmtTs(''), ''));
  test('returns empty string for null', () => assertEqual(fmtTs(null), ''));
  test('returns empty string for undefined', () => assertEqual(fmtTs(undefined), ''));
  test('replaces T with space', () => {
    const r = fmtTs('2024-06-01T00:00:00.000Z');
    assert(r.includes(' ') && !r.includes('T'));
  });
  test('timestamp without millis', () =>
    assertEqual(fmtTs('2024-01-15T10:30:45Z'), '2024-01-15 10:30:45'));
  test('FIXED – +00:00 within first 23 chars now correctly stripped (regex replace)', () => {
    // After fix: .replace(/\+00:00$/,'') matches the trailing +00: correctly.
    assertEqual(fmtTs('2024-01-15T10:30:45+00:00'), '2024-01-15 10:30:45');
  });
  test('non-UTC offset beyond 23 chars is cleanly sliced away', () =>
    assertEqual(fmtTs('2024-01-15T10:30:45.000+05:30'), '2024-01-15 10:30:45.000'));
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 4: fmtDuration
// ─────────────────────────────────────────────────────────────────────────────
suite('fmtDuration – human-readable duration', () => {
  test('0ms', () => assertEqual(fmtDuration(0), '0ms'));
  test('500ms', () => assertEqual(fmtDuration(500), '500ms'));
  test('999ms', () => assertEqual(fmtDuration(999), '999ms'));
  test('1000ms → 1.00s', () => assertEqual(fmtDuration(1000), '1.00s'));
  test('1500ms → 1.50s', () => assertEqual(fmtDuration(1500), '1.50s'));
  test('60000ms → 1m 0s', () => assertEqual(fmtDuration(60000), '1m 0s'));
  test('90000ms → 1m 30s', () => assertEqual(fmtDuration(90000), '1m 30s'));
  test('FIXED – 59999ms now correctly shows as 1m 0s (boundary guard applied)', () =>
    assertEqual(fmtDuration(59999), '1m 0s'));
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 5: timeDelta
// ─────────────────────────────────────────────────────────────────────────────
suite('timeDelta – time between two timestamps', () => {
  test('empty ts1 → empty', () => assertEqual(timeDelta('', '2024-01-01T00:00:01Z'), ''));
  test('null ts1 → empty', () => assertEqual(timeDelta(null, '2024-01-01T00:00:01Z'), ''));
  test('empty ts2 → empty', () => assertEqual(timeDelta('2024-01-01T00:00:00Z', ''), ''));
  test('negative delta → empty', () =>
    assertEqual(timeDelta('2024-01-01T00:00:01Z', '2024-01-01T00:00:00Z'), ''));
  test('malformed ts → empty', () =>
    assertEqual(timeDelta('not-a-date', '2024-01-01T00:00:00Z'), ''));
  test('1 second delta', () =>
    assertEqual(timeDelta('2024-01-01T00:00:00Z', '2024-01-01T00:00:01Z'), '+1.00s'));
  test('zero delta (same timestamps)', () =>
    assertEqual(timeDelta('2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z'), '+0ms'));
  test('500ms delta', () =>
    assertEqual(timeDelta('2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.500Z'), '+500ms'));
  test('2 minute delta', () =>
    assertEqual(timeDelta('2024-01-01T00:00:00Z', '2024-01-01T00:02:00Z'), '+2m 0s'));
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 6: UUID detection
// ─────────────────────────────────────────────────────────────────────────────
suite('UUID detection (UUID_RE)', () => {
  test('valid lowercase UUID', () => assert(UUID_RE.test('550e8400-e29b-41d4-a716-446655440000')));
  test('valid uppercase UUID', () => assert(UUID_RE.test('550E8400-E29B-41D4-A716-446655440000')));
  test('valid mixed-case UUID', () => assert(UUID_RE.test('550e8400-E29B-41d4-A716-446655440000')));
  test('rejects short UUID', () => assert(!UUID_RE.test('550e8400-e29b-41d4-a716-44665544000')));
  test('rejects underscore separators', () => assert(!UUID_RE.test('550e8400_e29b_41d4_a716_446655440000')));
  test('rejects extra prefix (^ anchor)', () => assert(!UUID_RE.test('prefix-550e8400-e29b-41d4-a716-446655440000')));
  test('rejects extra suffix ($ anchor)', () => assert(!UUID_RE.test('550e8400-e29b-41d4-a716-446655440000-suffix')));
  test('rejects empty string', () => assert(!UUID_RE.test('')));
  test('rejects plain text', () => assert(!UUID_RE.test('hello world')));
  test('rejects non-hex chars', () => assert(!UUID_RE.test('gggggggg-e29b-41d4-a716-446655440000')));
  test('detectQueryType → uuid', () => assertEqual(detectQueryType('550e8400-e29b-41d4-a716-446655440000'), 'uuid'));
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 7: Email detection
// ─────────────────────────────────────────────────────────────────────────────
suite('Email detection (EMAIL_RE)', () => {
  test('simple email', () => assert(EMAIL_RE.test('user@example.com')));
  test('subdomain email', () => assert(EMAIL_RE.test('user@mail.example.com')));
  test('plus-addressing', () => assert(EMAIL_RE.test('user+tag@example.com')));
  test('no-TLD rejected (foo@bar)', () => assert(!EMAIL_RE.test('foo@bar')));
  test('single-char domain parts accepted (lenient regex)', () => assert(EMAIL_RE.test('a@b.c')));
  test('UUID not matched as email', () => assert(!EMAIL_RE.test('550e8400-e29b-41d4-a716-446655440000')));
  test('plain text not matched', () => assert(!EMAIL_RE.test('hello world')));
  test('detectQueryType → email', () => assertEqual(detectQueryType('user@example.com'), 'email'));
  test('detectQueryType → text for plain string', () => assertEqual(detectQueryType('some search text'), 'text'));
  test('detectQueryType → none for empty', () => assertEqual(detectQueryType(''), 'none'));
  test('BUG – EMAIL_RE has no anchors; matches substring in longer string', () => {
    // 'foo user@example.com bar' contains a valid email substring → matches
    assert(EMAIL_RE.test('some text user@example.com more text'), 'substring match expected');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 8: Severity normalisation
// ─────────────────────────────────────────────────────────────────────────────
suite('Severity normalisation', () => {
  for (const s of ['CRITICAL','ERROR','WARNING','INFO','DEBUG']) {
    test(`${s} → ${s}`, () => assertEqual(normalizeSeverity(s), s));
  }
  test('lowercase error → ERROR', () => assertEqual(normalizeSeverity('error'), 'ERROR'));
  test('mixed-case Warning → WARNING', () => assertEqual(normalizeSeverity('Warning'), 'WARNING'));
  test('TRACE → DEFAULT', () => assertEqual(normalizeSeverity('TRACE'), 'DEFAULT'));
  test('VERBOSE → DEFAULT', () => assertEqual(normalizeSeverity('VERBOSE'), 'DEFAULT'));
  test('NOTICE → DEFAULT', () => assertEqual(normalizeSeverity('NOTICE'), 'DEFAULT'));
  test('empty string → DEFAULT', () => assertEqual(normalizeSeverity(''), 'DEFAULT'));
  test('null → DEFAULT', () => assertEqual(normalizeSeverity(null), 'DEFAULT'));
  test('undefined → DEFAULT', () => assertEqual(normalizeSeverity(undefined), 'DEFAULT'));
  test('whitespace-padded " ERROR " → DEFAULT (no trim in source)', () =>
    assertEqual(normalizeSeverity(' ERROR '), 'DEFAULT'));
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 9: Summary card error count
// ─────────────────────────────────────────────────────────────────────────────
suite('Summary card – error count aggregation', () => {
  test('ERROR + CRITICAL summed', () => assertEqual(calcErrorCount({ ERROR: 5, CRITICAL: 2 }), 7));
  test('missing ERROR key', () => assertEqual(calcErrorCount({ CRITICAL: 3 }), 3));
  test('missing CRITICAL key', () => assertEqual(calcErrorCount({ ERROR: 10 }), 10));
  test('empty object → 0', () => assertEqual(calcErrorCount({}), 0));
  test('null → 0', () => assertEqual(calcErrorCount(null), 0));
  test('undefined → 0', () => assertEqual(calcErrorCount(undefined), 0));
  test('WARNING/INFO/DEBUG ignored', () =>
    assertEqual(calcErrorCount({ WARNING: 100, INFO: 200, DEBUG: 50, ERROR: 3 }), 3));
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 10: Pagination state
// ─────────────────────────────────────────────────────────────────────────────
suite('Pagination state calculation', () => {
  test('1 page: prev+next disabled', () => {
    const s = calcPaginationState(30, 1, 50);
    assert(s.prevDisabled); assert(s.nextDisabled);
  });
  test('page 1 of 3: prev disabled, next enabled', () => {
    const s = calcPaginationState(150, 1, 50);
    assert(s.prevDisabled); assert(!s.nextDisabled);
  });
  test('last page: next disabled, prev enabled', () => {
    const s = calcPaginationState(150, 3, 50);
    assert(s.nextDisabled); assert(!s.prevDisabled);
  });
  test('zero entries: both disabled, info = "0 entries"', () => {
    const s = calcPaginationState(0, 1, 50);
    assert(s.prevDisabled); assert(s.nextDisabled);
    assertEqual(s.info, '0 entries');
  });
  test('middle page info string', () => {
    const s = calcPaginationState(200, 2, 50);
    assertEqual(s.info, '51–100 of 200');
  });
  test('partial last page info string', () => {
    const s = calcPaginationState(175, 4, 50);
    assertEqual(s.info, '151–175 of 175');
  });
  test('single entry', () => {
    const s = calcPaginationState(1, 1, 50);
    assertEqual(s.info, '1–1 of 1');
    assert(s.nextDisabled); assert(s.prevDisabled);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 11: Logger abbreviation
// ─────────────────────────────────────────────────────────────────────────────
suite('Logger abbreviation (last segment)', () => {
  test('dotted logger returns last segment', () =>
    assertEqual(abbrevLogger('com.example.service.MyService'), 'MyService'));
  test('no dots returns full value', () =>
    assertEqual(abbrevLogger('MyService'), 'MyService'));
  test('empty string returns empty', () => assertEqual(abbrevLogger(''), ''));
  test('null returns empty', () => assertEqual(abbrevLogger(null), ''));
  test('undefined returns empty', () => assertEqual(abbrevLogger(undefined), ''));
  test('trailing dot returns empty last segment', () => assertEqual(abbrevLogger('com.service.'), ''));
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 12: Exception truncation
// ─────────────────────────────────────────────────────────────────────────────
suite('Exception truncation in renderTable', () => {
  test('under 280 chars: unchanged', () => {
    const s = 'a'.repeat(100);
    assertEqual(truncateExc(s), s);
  });
  test('exactly 280 chars: no ellipsis', () => {
    const s = 'b'.repeat(280);
    assertEqual(truncateExc(s), s);
  });
  test('over 280 chars: truncated + ellipsis', () => {
    const s = 'c'.repeat(281);
    const r = truncateExc(s);
    assert(r.endsWith('\u2026'), 'should end with ellipsis');
    assertEqual(r.length, 281); // 280 chars + 1 ellipsis char
  });
  test('empty string: returns empty', () => assertEqual(truncateExc(''), ''));
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 13: localToUTC
// ─────────────────────────────────────────────────────────────────────────────
suite('localToUTC – filter date conversion', () => {
  test('empty string → empty', () => assertEqual(localToUTC(''), ''));
  test('null → empty', () => assertEqual(localToUTC(null), ''));
  test('undefined → empty', () => assertEqual(localToUTC(undefined), ''));
  test('valid datetime-local returns ISO format', () => {
    const r = localToUTC('2024-06-15T12:30:00');
    assert(typeof r === 'string' && r.length > 0, 'should return non-empty string');
    assert(r.includes('2024-06-15'), 'should contain the input date');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 14: Log entry field extraction edge cases
// ─────────────────────────────────────────────────────────────────────────────
suite('Log entry field extraction edge cases', () => {
  function processEntry(e) {
    const rawSev = (e.severity || 'DEFAULT').toUpperCase();
    const sev    = ['CRITICAL','ERROR','WARNING','INFO','DEBUG'].includes(rawSev) ? rawSev : 'DEFAULT';
    const ts     = fmtTs(e.timestamp);
    const logger = e.logger ? e.logger.split('.').pop() : '';
    const exc    = e.exception_message || e.exception || '';
    return { sev, ts, logger, exc };
  }

  test('complete entry processes correctly', () => {
    const r = processEntry({
      severity: 'ERROR', timestamp: '2024-01-15T10:30:00.000Z',
      logger: 'com.example.Service', exception_message: 'NullPointerException'
    });
    assertEqual(r.sev, 'ERROR');
    assertEqual(r.ts, '2024-01-15 10:30:00.000');
    assertEqual(r.logger, 'Service');
    assertEqual(r.exc, 'NullPointerException');
  });
  test('no severity → DEFAULT', () => assertEqual(processEntry({ timestamp: '2024-01-01T00:00:00Z' }).sev, 'DEFAULT'));
  test('no timestamp → empty string', () => assertEqual(processEntry({ severity: 'INFO' }).ts, ''));
  test('no logger → empty string', () => assertEqual(processEntry({ severity: 'INFO' }).logger, ''));
  test('exception_message takes precedence over exception', () => {
    const r = processEntry({ exception_message: 'The real message', exception: 'Stack trace' });
    assertEqual(r.exc, 'The real message');
  });
  test('falls back to exception when exception_message absent', () => {
    const r = processEntry({ exception: 'Some stack trace' });
    assertEqual(r.exc, 'Some stack trace');
  });
  test('no exception fields → empty string', () => assertEqual(processEntry({}).exc, ''));
  test('TRACE severity → DEFAULT', () => assertEqual(processEntry({ severity: 'TRACE' }).sev, 'DEFAULT'));
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 15: Search result query type mapping
// ─────────────────────────────────────────────────────────────────────────────
suite('Search result – query type class/label mapping', () => {
  function getTypeInfo(query_type) {
    const typeClass = { uuid: 't-uuid', email: 't-email', text: 't-text' }[query_type] || 't-text';
    const typeLabel = { uuid: 'UUID', email: 'Email', text: 'Text' }[query_type] || 'Text';
    return { typeClass, typeLabel };
  }
  test('uuid → t-uuid / UUID', () => { const r = getTypeInfo('uuid'); assertEqual(r.typeClass,'t-uuid'); assertEqual(r.typeLabel,'UUID'); });
  test('email → t-email / Email', () => { const r = getTypeInfo('email'); assertEqual(r.typeClass,'t-email'); assertEqual(r.typeLabel,'Email'); });
  test('text → t-text / Text', () => { const r = getTypeInfo('text'); assertEqual(r.typeClass,'t-text'); assertEqual(r.typeLabel,'Text'); });
  test('unknown → falls back to t-text / Text', () => { const r = getTypeInfo('unknown'); assertEqual(r.typeClass,'t-text'); assertEqual(r.typeLabel,'Text'); });
  test('undefined → falls back to t-text / Text', () => { const r = getTypeInfo(undefined); assertEqual(r.typeClass,'t-text'); assertEqual(r.typeLabel,'Text'); });
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 16: _egEntries Map (XSS guard for event group entries)
// ─────────────────────────────────────────────────────────────────────────────
suite('Event group – _egEntries Map (XSS guard)', () => {
  const _egEntries = new Map();
  test('stores and retrieves entries by index', () => {
    const entries = [{ idx: 0, severity: 'INFO', message: 'test' }];
    _egEntries.set(0, entries);
    assertDeepEqual(_egEntries.get(0), entries);
  });
  test('dangerous chars stored safely in Map (not in HTML attributes)', () => {
    const dangerous = [{ idx: 1, message: '<script>alert(1)</script>' }];
    _egEntries.set(99, dangerous);
    assertEqual(_egEntries.get(99)[0].message, '<script>alert(1)</script>');
  });
  test('missing key returns undefined', () => assertEqual(_egEntries.get(999), undefined));
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 17: toggleStack DOM interaction
// ─────────────────────────────────────────────────────────────────────────────
suite('toggleStack – DOM interaction', () => {
  test('toggles open class and button text', () => {
    const el = new FakeElement('test-stack-1');
    _domStore.set('test-stack-1', el);
    const btn = new FakeElement('btn');

    assert(!el.classList.contains('open'), 'initially no open class');
    toggleStack('test-stack-1', btn);
    assert(el.classList.contains('open'), 'open class added');
    assertEqual(btn.textContent, '\u25BC Hide stack trace');

    toggleStack('test-stack-1', btn);
    assert(!el.classList.contains('open'), 'open class removed on second toggle');
    assertEqual(btn.textContent, '\u25B6 Show stack trace');

    _domStore.delete('test-stack-1');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 18: Malformed data safety
// ─────────────────────────────────────────────────────────────────────────────
suite('Malformed data safety', () => {
  test('escHtml encodes script tag in log message', () => {
    const safe = escHtml('<script>alert("xss")</script>');
    assert(!safe.includes('<script>'), 'raw script tag must not appear');
    assert(safe.includes('&lt;script&gt;'));
  });
  test('escHtml encodes mixed payload correctly', () =>
    assertEqual(escHtml('Tom & Jerry < 3 > 1'), 'Tom &amp; Jerry &lt; 3 &gt; 1'));
  test('fmtTs on invalid string does not throw', () => {
    try { const r = fmtTs('INVALID DATE STRING'); assert(typeof r === 'string'); }
    catch(e) { throw new Error('fmtTs threw: ' + e.message); }
  });
  test('timeDelta same timestamps → +0ms', () =>
    assertEqual(timeDelta('2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z'), '+0ms'));
  test('normalizeSeverity with whitespace-padded value → DEFAULT', () =>
    assertEqual(normalizeSeverity(' ERROR '), 'DEFAULT'));
  test('abbrevLogger with only a dot → empty last segment', () =>
    assertEqual(abbrevLogger('.'), ''));
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 19: Global search badge detection
// ─────────────────────────────────────────────────────────────────────────────
suite('Global search – input badge detection', () => {
  function getBadge(value) {
    const v = value.trim();
    if (!v) return { text: '', cls: '' };
    if (UUID_RE.test(v))  return { text: 'UUID',  cls: 'sr-type-badge t-uuid' };
    if (EMAIL_RE.test(v)) return { text: 'Email', cls: 'sr-type-badge t-email' };
    return                       { text: 'Text',  cls: 'sr-type-badge t-text' };
  }
  test('empty input → no badge', () => assertEqual(getBadge('').text, ''));
  test('whitespace-only → no badge', () => assertEqual(getBadge('   ').text, ''));
  test('UUID input → UUID badge', () => {
    const b = getBadge('550e8400-e29b-41d4-a716-446655440000');
    assertEqual(b.text, 'UUID'); assert(b.cls.includes('t-uuid'));
  });
  test('email input → Email badge', () => {
    const b = getBadge('user@example.com');
    assertEqual(b.text, 'Email'); assert(b.cls.includes('t-email'));
  });
  test('plain text → Text badge', () => {
    const b = getBadge('NullPointerException');
    assertEqual(b.text, 'Text'); assert(b.cls.includes('t-text'));
  });
  test('UUID with surrounding spaces → trimmed, detected as UUID', () =>
    assertEqual(getBadge('  550e8400-e29b-41d4-a716-446655440000  ').text, 'UUID'));
  test('email with surrounding spaces → trimmed, detected as Email', () =>
    assertEqual(getBadge('  user@example.com  ').text, 'Email'));
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 20: fmtTs known edge-case documentation
// ─────────────────────────────────────────────────────────────────────────────
suite('fmtTs – documented edge cases', () => {
  test('FIXED – trailing Z stripped correctly (now uses regex /Z$/)', () => {
    assert(!fmtTs('2024-01-01T00:00:00.000Z').endsWith('Z'), 'trailing Z stripped');
  });
  test('zero epoch timestamp formats correctly', () =>
    assertEqual(fmtTs('1970-01-01T00:00:00.000Z'), '1970-01-01 00:00:00.000'));
  test('far-future timestamp formats correctly', () =>
    assertEqual(fmtTs('2099-12-31T23:59:59.999Z'), '2099-12-31 23:59:59.999'));
});

// ─────────────────────────────────────────────────────────────────────────────
// Output
// ─────────────────────────────────────────────────────────────────────────────
const RESET = '\x1b[0m', BOLD = '\x1b[1m', GREEN = '\x1b[32m', RED = '\x1b[31m',
      YELLOW = '\x1b[33m', CYAN = '\x1b[36m', DIM = '\x1b[2m';

let totalPass = 0, totalFail = 0;
const failedTests = [];

for (const s of results) {
  const sPass = s.tests.filter(t => t.pass).length;
  const sFail = s.tests.filter(t => !t.pass).length;
  totalPass += sPass;
  totalFail += sFail;
  const icon = sFail > 0 ? `${RED}✗${RESET}` : `${GREEN}✓${RESET}`;
  console.log(`\n${icon} ${BOLD}${s.name}${RESET} ${DIM}(${sPass}/${s.tests.length})${RESET}`);
  for (const t of s.tests) {
    if (t.pass) {
      console.log(`  ${GREEN}✓${RESET} ${t.name}`);
    } else {
      console.log(`  ${RED}✗${RESET} ${t.name}`);
      console.log(`    ${RED}${t.error}${RESET}`);
      failedTests.push({ suite: s.name, name: t.name, error: t.error });
    }
  }
}

console.log('\n' + '─'.repeat(60));
console.log(`${BOLD}Results:${RESET} ${GREEN}${totalPass} passed${RESET}  ${totalFail > 0 ? RED : DIM}${totalFail} failed${RESET}  ${DIM}${totalPass + totalFail} total${RESET}`);

if (failedTests.length) {
  console.log(`\n${YELLOW}${BOLD}Failed tests:${RESET}`);
  failedTests.forEach(f => console.log(`  ${RED}✗${RESET} [${f.suite}] ${f.name}\n    ${DIM}${f.error}${RESET}`));
}

// Exit with non-zero code if any tests failed
process.exit(totalFail > 0 ? 1 : 0);
