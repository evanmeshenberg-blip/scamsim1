// =============================================================================
// scamAnalyzer.js — Pattern matching + AI hook for scam risk classification
// =============================================================================

// ─── REGEX PATTERN LIBRARY ────────────────────────────────────────────────────
// Each entry: { label, regex, weight }
//   label  — human-readable trigger name shown in the UI as a pill tag
//   regex  — tested against "subject + body + snippet" combined corpus
//   weight — risk points added when the pattern fires (sum drives risk tier)

const SCAM_PATTERNS = [

  // ── Urgency / Pressure ──────────────────────────────────────────────────────
  { label: 'Urgency language',
    regex: /\b(urgent|act now|immediate(ly)?|right now|last chance|final notice|time sensitive|don't (delay|wait)|before it'?s too late|this offer expires|action required|response required|requires (your )?(immediate|urgent) (action|attention))\b/i,
    weight: 1 },

  { label: 'Short deadline',
    regex: /\b(expires? in \d+\s*(hours?|days?|minutes?)|within (the next )?\d+\s*(hours?|days?)|24[\s-]hour|48[\s-]hour)\b/i,
    weight: 2 },

  { label: 'Do not ignore',
    regex: /\b(do not (ignore|delete|discard) this|failure to (respond|act|comply) (will|may|could)|immediately or (your|the))\b/i,
    weight: 2 },

  { label: 'Direct money demand',
    regex: /\b(wire|send|give|transfer|hotwire|forward|pay)\s+(me|us)\s+(your|the\s+)?(money|savings|life savings?|funds?|cash|bank\s*account|entire|everything)\b/i,
    weight: 4 },

  // ── Account / Security Threats ──────────────────────────────────────────────
  { label: 'Account threat',
    regex: /\b(account (has been |is )?(suspended|locked|disabled|deactivated|terminated|closed|restricted|compromised|at risk)|unusual (sign-?in|login|activity|access)|unauthorized access)\b/i,
    weight: 2 },

  { label: 'Account closure warning',
    regex: /\b(account will (be )?(closed|terminated|deleted|suspended|deactivated)|permanently (deleted|banned|suspended))\b/i,
    weight: 2 },

  { label: 'Security alert',
    regex: /\b(security (alert|breach|warning|notice|update required)|data breach|your (password|credentials?) (was|were|has been|have been) (changed|reset|compromised|exposed|leaked))\b/i,
    weight: 2 },

  { label: 'Suspicious login detected',
    regex: /\b((suspicious|unusual|unrecognised|unrecognized|unauthorized|new) (sign-?in|login|access|device)|sign-?in attempt|login attempt|accessed from (an? )?(new|unknown|different|unusual))\b/i,
    weight: 2 },

  // ── Credential Phishing ─────────────────────────────────────────────────────
  { label: 'Credential request',
    regex: /\b(verify your (account|password|email|identity|information|details)|confirm your (details|information|payment|identity|account)|update your (card|billing|info|credentials?|payment method))\b/i,
    weight: 3 },

  { label: 'Login prompt',
    regex: /\b(click (here |the link )?(to |and )?(log ?in|sign ?in|verify|confirm|restore|unlock|reactivate|validate|authenticate)|sign in (to |and )?(verify|secure|restore|confirm))\b/i,
    weight: 2 },

  { label: 'Enter credentials',
    regex: /\b(enter your (username|password|credentials?|login|pin|passcode)|provide your (account|personal|banking|card) (details|information|number|data)|submit your (details|information|credentials?))\b/i,
    weight: 3 },

  { label: 'OTP / verification code',
    regex: /\b(one-?time (password|code|pin|passcode)|OTP|verification code|auth(entication)? code).{0,80}(do not share|never share|share (it )?with no ?one)/is,
    weight: 3 },

  // ── Sensitive Data Requests ─────────────────────────────────────────────────
  { label: 'SSN request',
    regex: /\b(social security (number|#|no\.?)|SSN)\b/i,
    weight: 3 },

  { label: 'Financial details request',
    regex: /\b(bank account (number|details|info)|routing number|credit card (number|details|cvv|security code)|card (number|details) (below|above|here|via)|sort code)\b/i,
    weight: 3 },

  { label: 'Personal ID request',
    regex: /\b(passport (number|details|copy)|driver'?s (licen[sc]e|licence) (number|copy)|date of birth|mother'?s maiden name|national (id|insurance) (number|#))\b/i,
    weight: 2 },

  // ── Financial Bait ──────────────────────────────────────────────────────────
  { label: 'Prize / lottery',
    regex: /\b(you'?ve? won|you are (a )?winner|prize|lottery|sweepstakes|jackpot|reward awaits|claim your (prize|reward|winnings?)|congratulations.{0,30}(won|selected|chosen))\b/i,
    weight: 2 },

  { label: 'Inheritance / fund transfer',
    regex: /\b(inheritance|unclaimed (funds?|money|property|assets?|refund)|beneficiary|next of kin|transfer (of )?funds?|\$[\d,]+\s*million|million (dollars?|pounds?|euros?))\b/i,
    weight: 3 },

  { label: 'Advance-fee fraud',
    regex: /\b(processing fee|release fee|admin(istration)? fee|handling fee|pay (a )?(small )?(fee|charge|amount) to (receive|claim|release|access)|small fee (to|and) (receive|unlock))\b/i,
    weight: 3 },

  { label: 'Get-rich-quick',
    regex: /\b(make (money|cash) (fast|quickly|easily|online|from home)|earn \$[\d,]+(\.[\d]+)? (a |per )?(day|week|month)|get rich|become (a )?millionaire|financial freedom|work from home.{0,30}earn|no experience (needed|required))\b/i,
    weight: 2 },

  { label: 'Tax / government refund bait',
    regex: /\b(tax (refund|rebate|return|credit).{0,30}(click|link|claim|apply)|stimulus (check|payment|relief)|government (grant|benefit|check|payment).{0,30}(claim|qualify|eligible))\b/i,
    weight: 2 },

  { label: 'Debt / loan trap',
    regex: /\b(debt (relief|consolidation|settlement|forgiveness)|you (owe|are owed)|outstanding (balance|debt|amount).{0,30}(pay|settle|clear)|loan (approved|guaranteed|no credit check))\b/i,
    weight: 1 },

  // ── Crypto / Investment Scams ───────────────────────────────────────────────
  { label: 'Crypto scam',
    regex: /\b(bitcoin|ethereum|crypto(currency)?|NFT|token sale|ICO|send (bitcoin|eth|crypto)|crypto(currency)? (wallet|payment|transfer)|trading (signals?|bot|platform))\b/i,
    weight: 2 },

  { label: 'Guaranteed returns',
    regex: /\b(guaranteed (profit|return|income)|100% (risk-free|guaranteed|profit)|double your (money|investment|bitcoin)|passive income|forex|binary options|trading (secret|method|system))\b/i,
    weight: 2 },

  // ── Delivery / Package Scams ────────────────────────────────────────────────
  { label: 'Failed delivery scam',
    regex: /\b(your (package|parcel|shipment|delivery|order) (could not|failed to|was unable to|has been|is) (be )?(delivered|processed|completed)|delivery (failed|unsuccessful|attempt failed)|package (on hold|held|waiting|pending clearance))\b/i,
    weight: 2 },

  { label: 'Customs / redelivery fee',
    regex: /\b(customs (fee|duty|charge|clearance)|redelivery (fee|charge|cost)|reschedule (your )?(delivery|shipment).{0,40}(click|link|pay|fee))\b/i,
    weight: 3 },

  { label: 'Courier impersonation',
    regex: /\b(USPS|FedEx|UPS|DHL|Royal Mail|Australia Post|Canada Post|Hermes|Evri).{0,60}(click|track|confirm|verify|update|fee|action|link)\b/i,
    weight: 2 },

  // ── Tech Support Scams ──────────────────────────────────────────────────────
  { label: 'Device infected',
    regex: /\b(your (computer|device|PC|Mac|phone|iPhone|Android) (has been|is|may be) (infected|hacked|compromised|at risk|under attack)|virus (detected|found|alert|warning)|malware (detected|found|alert))\b/i,
    weight: 3 },

  { label: 'License expired',
    regex: /\b(your (Windows|Microsoft|antivirus|security|protection) (license|subscription|key) (has )?expired|Windows (activation|license).{0,30}(expired|invalid|disabled))\b/i,
    weight: 2 },

  { label: 'Tech support call prompt',
    regex: /\b(call (this |our |the )?(number|helpline|support line|toll-?free)|contact (our |the )?(support|tech(nical)? support|helpdesk).{0,40}immediately|(toll-?free|1-?8(00|44|55|66|77|88))[\s\-]?\(?\d)\b/i,
    weight: 2 },

  // ── Government / Authority Impersonation ────────────────────────────────────
  { label: 'IRS / tax authority',
    regex: /\b(IRS|HMRC|ATO|CRA).{0,80}(refund|penalty|audit|debt|unpaid|action|contact|call|arrest)\b/i,
    weight: 3 },

  { label: 'Law enforcement threat',
    regex: /\b(FBI|CIA|DEA|Interpol|police|sheriff|federal agent).{0,60}(warrant|arrest|investigation|charges?|indictment|subpoena)\b/i,
    weight: 3 },

  { label: 'Legal / court threat',
    regex: /\b(legal action|lawsuit|court (order|summons|hearing|date)|arrest warrant|civil (suit|case|judgment)|criminal (charges?|complaint)|prosecution|sue you)\b/i,
    weight: 2 },

  // ── Brand Impersonation ─────────────────────────────────────────────────────
  { label: 'PayPal impersonation',
    regex: /\bpaypal\b/i,
    weight: 2 },

  { label: 'Amazon impersonation',
    regex: /\bamazon\b/i,
    weight: 2 },

  { label: 'Apple impersonation',
    regex: /\b(apple( id)?|icloud)\b/i,
    weight: 2 },

  { label: 'Bank impersonation',
    regex: /\b(chase|wells fargo|bank of america|citibank|barclays|lloyds|hsbc|natwest|halifax|santander|td bank|capital one)\b/i,
    weight: 2 },

  { label: 'Streaming / subscription impersonation',
    regex: /\b(netflix|spotify|disney\+?|hulu|amazon prime)\b.{0,120}\b(payment (failed|declined|issue)|subscription (cancelled?|expired|suspended)|update (your )?(payment|billing|card))\b/i,
    weight: 2 },

  { label: 'Microsoft impersonation',
    regex: /\b(microsoft|outlook|office 365|azure)\b/i,
    weight: 2 },

  // ── Payment Methods Favored by Scammers ─────────────────────────────────────
  { label: 'Gift card demand',
    regex: /\b(gift card|iTunes card|Google Play card|Amazon gift card|steam (card|wallet)|prepaid (card|debit card)).{0,80}(buy|purchase|send|pay|provide|number|code)\b/i,
    weight: 3 },

  { label: 'Wire / money transfer',
    regex: /\b(wire transfer|bank transfer|Western Union|MoneyGram|Ria (Money)?|money order).{0,60}(send|transfer|pay)\b/i,
    weight: 3 },

  { label: 'Peer-to-peer payment scam',
    regex: /\b(send (money|funds?|payment|cash) (via|through|using) (Zelle|CashApp|Cash App|Venmo|PayPal).{0,80}(urgent|now|immediately|today)|Zelle|CashApp|Cash App.{0,80}(fraud|scam|problem|unusual|reverse))\b/i,
    weight: 2 },

  // ── Generic Phishing Structure ──────────────────────────────────────────────
  { label: 'Generic salutation',
    regex: /\b(dear (customer|user|member|client|valued (customer|member|client)|account holder|sir|madam|sir or madam)|to whom it may concern)\b/i,
    weight: 1 },

  { label: 'Unsolicited contact framing',
    regex: /\b(we are (writing|contacting|reaching out) (to inform|to notify|you) (that|about|of)|this (email|message|letter|notice) (is to|serves to) (inform|notify|advise))\b/i,
    weight: 1 },

  { label: 'Click-link instruction',
    regex: /\b(please (click|follow|visit|use) (the |this )?(link|url|button|attachment) (below|above|provided|here)|click (the |this |on the )?(link|button|here) to (verify|confirm|update|restore|access|login|sign))\b/i,
    weight: 1 },

  { label: 'Confidentiality demand',
    regex: /\b(strictly confidential|do not (share|forward|show|disclose) this (email|message|information|letter)|delete (this |the )?(email|message) after|for your eyes only)\b/i,
    weight: 2 },

  { label: 'Specially selected',
    regex: /\b(you (have been|were) (specially |uniquely )?(selected|chosen|picked|identified)|exclusive (offer|invitation|opportunity) (for you|reserved for)|hand-?picked)\b/i,
    weight: 1 },

  { label: 'Not a scam disclaimer',
    regex: /\b(this is not (a )?(spam|scam|phishing|junk)|we will never (ask|request) (for )?your (password|pin)|legitimate (email|message|company))\b/i,
    weight: 1 },

  // ── Romance / Relationship Scams ────────────────────────────────────────────
  { label: 'Romance scam signals',
    regex: /\b(i am (a )?(widow(er)?|military officer|soldier|doctor) (working|serving|stationed) (in|abroad)|fell in love with your (profile|photo|picture)|send (me )?(money|funds?) (so|to) (i can|we can|help me))\b/i,
    weight: 3 },

  // ── Health / Pharmaceutical Scams ───────────────────────────────────────────
  { label: 'Miracle cure / pharma scam',
    regex: /\b(lose \d+ (pounds?|lbs?|kg) (in|within)|miracle (cure|treatment|pill|supplement)|doctors? (hate|don't want)|100% (natural|safe|effective|guaranteed) (cure|treatment|remedy)|no prescription (needed|required))\b/i,
    weight: 2 },

];

// ─── SENDER BLOCKLIST ─────────────────────────────────────────────────────────
// TODO: Replace/extend with a fetched blocklist or threat-intel feed.
const BLOCKED_SENDER_PATTERNS = [
  /[@.](ru|cn|tk|ml|ga|cf|gq|pw|cc|ws)$/i,            // High-abuse TLDs
  /@.*\.(xyz|top|loan|click|work|bid|win|racing)$/i,   // Common spam TLDs
  /\d{6,}@/,                                            // Long numeric local-part
  /noreply.{0,10}@(?!google|microsoft|apple|amazon|paypal|github|linkedin|twitter|facebook|instagram)\S+\.(com|net|org)$/i,
];

// ─── HEURISTIC CHECKS ─────────────────────────────────────────────────────────
// Structural signals that don't fit a single pattern well.

function heuristicScore(email) {
  const hits = [];
  let score = 0;

  const corpus = `${email.subject} ${email.body} ${email.snippet}`;

  // Excessive punctuation: "!!!" or "???" — common in spam subject lines
  if (/[!?]{3,}/.test(corpus)) {
    score += 1;
    hits.push('Excessive punctuation');
  }

  // ALL-CAPS words (3+ consecutive uppercase words): common in scam subjects
  if ((corpus.match(/\b[A-Z]{4,}\b/g) || []).length >= 3) {
    score += 1;
    hits.push('Excessive caps');
  }

  // IP-address links in body (e.g. http://192.168.1.1/login)
  if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(email.body)) {
    score += 3;
    hits.push('IP-address link');
  }

  // Suspicious domains: brand/payment keyword in the domain but not the real site.
  // Catches bare domains like "payzimu.com", "paypal-secure.ru", "amaz0n-login.net".
  const domainRe    = /(?:https?:\/\/)?([a-z0-9][-a-z0-9]{1,62}\.(?:com|net|org|io|co|me|info|biz|online|site|store|shop|club|top|xyz|ru|cn|tk)(?:\/\S*)?)/gi;
  const brandInDom  = /^(pay|paypal|amaz(?:on)?|apple|microsoft|google|netflix|chase|wellsfargo|bankof|citibank|hsbc|lloyds|barclays)/i;
  const realDomains = /^(paypal\.com|amazon\.com|apple\.com|microsoft\.com|google\.com|netflix\.com|chase\.com|wellsfargo\.com|bankofamerica\.com|citibank\.com)$/i;
  const searchText  = `${email.body} ${email.snippet}`;
  let domMatch;
  while ((domMatch = domainRe.exec(searchText)) !== null) {
    const domain = domMatch[1].split('/')[0].toLowerCase();
    if (brandInDom.test(domain) && !realDomains.test(domain)) {
      score += 3;
      hits.push('Brand-spoofing URL');
      break;
    }
  }

  // Free email domain pretending to be a brand (From: "PayPal" <support@gmail.com>)
  const displayName = (email.from.match(/^([^<]+)</) || [])[1] || '';
  const fromAddr    = (email.from.match(/<([^>]+)>/) || [])[1] || email.from;
  const brandNames  = /paypal|amazon|apple|microsoft|google|netflix|chase|bank of america|irs|fedex|ups|usps|dhl/i;
  const freemail    = /@(gmail|yahoo|hotmail|outlook|aol|protonmail|icloud)\./i;
  if (brandNames.test(displayName) && freemail.test(fromAddr)) {
    score += 4;
    hits.push('Brand name spoofed via free email');
  }

  return { score, hits };
}

// ─── RISK THRESHOLDS ─────────────────────────────────────────────────────────
// Adjust to tune sensitivity vs. false-positive rate.
const THRESHOLD_DANGEROUS = 5;
const THRESHOLD_CAUTION   = 2;

// =============================================================================
// analyzeEmail — public API
// =============================================================================

/**
 * Classifies one parsed email object and returns a risk report.
 *
 * @param {{ subject: string, from: string, body: string, snippet: string }} email
 * @returns {{ risk: 'Safe'|'Caution'|'Dangerous', score: number, reasons: string[] }}
 *
 * ── WHERE TO PLUG IN AI ───────────────────────────────────────────────────────
 * Make the function async and add an AI call at Step 3:
 *
 *   const res = await fetch('https://your-api/classify', {
 *     method: 'POST',
 *     headers: { 'Content-Type': 'application/json' },
 *     body: JSON.stringify({ subject: email.subject, body: email.body }),
 *   }).then(r => r.json());
 *   score += res.riskScore;
 *   reasons.push(...res.reasons);
 * ─────────────────────────────────────────────────────────────────────────────
 */
export function analyzeEmail(email) {
  const reasons = [];
  let score = 0;

  const corpus = `${email.subject} ${email.body} ${email.snippet}`;

  // ── Step 1: Regex pattern sweep ───────────────────────────────────────────
  for (const pattern of SCAM_PATTERNS) {
    if (pattern.regex.test(corpus)) {
      score += pattern.weight;
      reasons.push(pattern.label);
    }
  }

  // ── Step 2: Heuristic structural checks ───────────────────────────────────
  const { score: hScore, hits } = heuristicScore(email);
  score += hScore;
  reasons.push(...hits);

  // ── Step 3: Sender domain blocklist ───────────────────────────────────────
  if (BLOCKED_SENDER_PATTERNS.some(p => p.test(email.from))) {
    score += 3;
    reasons.push('Suspicious sender domain');
  }

  // ── Step 4: AI / semantic analysis hook ───────────────────────────────────
  // TODO: Await an async AI classification call here and merge its score.
  // ─────────────────────────────────────────────────────────────────────────

  const risk = score >= THRESHOLD_DANGEROUS ? 'Dangerous'
             : score >= THRESHOLD_CAUTION   ? 'Caution'
             :                                'Safe';

  return { risk, score, reasons };
}
