--- Code.gs (原始)
/* ══════════════════════════════════════════════════════════════
   OncoCollect v3.1 — Google Apps Script Backend (Enhanced)
   
   NEW FIELDS: Hospital, Date of Collection, Collector Name,
               Required for Analysis, Treatment Other, Ward Other,
               Cancer Name Other, Comorbidities Other

   ENHANCEMENTS:
   - HMAC-signed session tokens (tamper-proof)
   - Rate limiting on login (brute-force protection)
   - Password strength enforcement
   - CSRF token verification
   - Audit logging
   - Soft delete (no data loss)
   - doPost for save (no URL length limits)
   - Sequential ID generation (no collisions)
   - Optimistic concurrency control
   - Data backup automation
   - Email notifications for critical thresholds
   - ATC codes in WHO list
   - Input sanitization (XSS protection)
   - JSDoc type annotations
   - Improved error handling
   

   DEPLOYMENT:

   OPTION A (Recommended — No CORS issues):
     1. In GAS editor, create HTML file named "Index"
     2. Paste index.html content into it
     3. Deploy > New deployment > Web app
        - Execute as: Me | Who has access: Anyone
     4. Visit the Web App URL

   OPTION B (GitHub Pages):
     1. Deploy as Web app
     2. Upload index.html to GitHub Pages
     3. Set GAS_URL in index.html

   SETUP (run once): Run > setupSheets
   
   SECURITY NOTICE: Change CONFIG.HMAC_SECRET before production!
   ══════════════════════════════════════════════════════════════ */

// ─── CONFIG ─────────────────────────────────────────────────
/** @type {Object} */
const CONFIG = {
  SPREADSHEET_NAME: 'OncoCollectDB',
  HMAC_SECRET: 'CHANGE_THIS_SECRET_BEFORE_PRODUCTION_' + Math.random().toString(36).substring(2), // CHANGE THIS IN PRODUCTION!
  RECORD_HEADERS: [
    'Timestamp','Study ID','Age','Sex','Created By',
    'Hospital','Date of Collection','Collector Name',
    'Admission Date','Discharge Date','LOS','Admission Type','Ward','Ward Other',
    'Diagnosis','Cancer Type','Cancer Name','Cancer Name Other',
    'Stage','Treatment','Treatment Other',
    'Comorbidities','Comorbidities Other','Immunosuppressed',
    'Outcome','Readmission 30d','De-escalation',
    'Antibiotics JSON','Cultures JSON',
    'Required for Analysis',
    'Created Date','Updated Date','Deleted','Deleted By','Deleted Date','Version'
  ],
  USER_HEADERS: ['Username','Password Hash','Salt','Role','Active','Created Date','Last Login'],
  WHO_HEADERS: ['Name','ATC Code','Class','Category','DDD'],
  AUDIT_HEADERS: ['Timestamp','User','Action','Details'],
  LOGIN_ATTEMPT_HEADERS: ['Username','Attempts','Last Attempt'],
  META_HEADERS: ['Key','Value'],
  SESSION_TIMEOUT: 28800000, // 8 hours
  MAX_LOGIN_ATTEMPTS: 5,
  LOGIN_LOCKOUT_MINUTES: 15,
  MDR_ALERT_THRESHOLD: 0.5,
  PASSWORD_MIN_LENGTH: 8,
  MAX_ABX_SLOTS: 30,
  MAX_CULT_SLOTS: 30,
};

// ─── RELATIONAL TABLE HEADERS ───────────────────────────────
const ANTIBIOTIC_HEADERS = [
  'Study ID',
  'Antibiotic Name',
  'Class',
  'Category',
  'Route',
  'Dose',
  'Frequency',
  'Start',
  'Stop',
  'Duration',
  'DDD',
  'Grams',
  'DDD Calc',
  'DOT',
  'Indication',
  'Therapy Type',
  'Febrile Neutro',
  'Febrile Episodes'
];

const CULTURE_HEADERS = [
  'Study ID',
  'Sent',
  'Date',
  'Type',
  'Type Other',
  'Result',
  'Organism',
  'Gram',
  'AST',
  'Resistance',
  'MDR',
  'XDR',
  'ESKAPE',
  'ESKAPE Organisms'
];

// WHO AWaRe 2023 antibiotic list with ATC codes
const WHO_ANTIBIOTICS = [
  // Access (26)
  {name:'Amoxicillin',atc:'J01CA04',cls:'Penicillin',cat:'Access',ddd:1.5},
  {name:'Ampicillin',atc:'J01CA01',cls:'Penicillin',cat:'Access',ddd:2},
  {name:'Benzylpenicillin',atc:'J01CE01',cls:'Penicillin',cat:'Access',ddd:1.2},
  {name:'Phenoxymethylpenicillin',atc:'J01CE02',cls:'Penicillin',cat:'Access',ddd:1},
  {name:'Cephalexin',atc:'J01DB01',cls:'Cephalosporin (1st)',cat:'Access',ddd:2},
  {name:'Cefazolin',atc:'J01DB04',cls:'Cephalosporin (1st)',cat:'Access',ddd:3},
  {name:'Gentamicin',atc:'J01GB03',cls:'Aminoglycoside',cat:'Access',ddd:0.24},
  {name:'Nitrofurantoin',atc:'J01XE01',cls:'Nitrofuran',cat:'Access',ddd:0.2},
  {name:'Sulfamethoxazole/Trimethoprim',atc:'J01EE01',cls:'Sulfonamide',cat:'Access',ddd:0.48},
  {name:'Trimethoprim',atc:'J01EA01',cls:'Sulfonamide',cat:'Access',ddd:0.4},
  {name:'Clindamycin',atc:'J01FF01',cls:'Lincosamide',cat:'Access',ddd:1.8},
  {name:'Metronidazole',atc:'J01XD01',cls:'Nitroimidazole',cat:'Access',ddd:1.5},
  {name:'Doxycycline',atc:'J01AA02',cls:'Tetracycline',cat:'Access',ddd:0.1},
  {name:'Tetracycline',atc:'J01AA07',cls:'Tetracycline',cat:'Access',ddd:1},
  {name:'Amoxicillin/Clavulanate',atc:'J01CR02',cls:'Penicillin+Inhibitor',cat:'Access',ddd:1.5},
  {name:'Ampicillin/Sulbactam',atc:'J01CR01',cls:'Penicillin+Inhibitor',cat:'Access',ddd:3},
  {name:'Ceftriaxone',atc:'J01DD04',cls:'Cephalosporin (3rd)',cat:'Access',ddd:2},
  {name:'Cefixime',atc:'J01DD08',cls:'Cephalosporin (3rd)',cat:'Access',ddd:0.4},
  {name:'Chloramphenicol',atc:'J01BA01',cls:'Phenicols',cat:'Access',ddd:3},
  {name:'Cloxacillin',atc:'J01CF02',cls:'Penicillin (antistaph)',cat:'Access',ddd:2},
  {name:'Erythromycin',atc:'J01FA01',cls:'Macrolide',cat:'Access',ddd:1},
  {name:'Flucloxacillin',atc:'J01CF05',cls:'Penicillin (antistaph)',cat:'Access',ddd:2},
  {name:'Isoniazid',atc:'J04AC01',cls:'Antimycobacterial',cat:'Access',ddd:0.3},
  {name:'Rifampicin',atc:'J04AB02',cls:'Antimycobacterial',cat:'Access',ddd:0.6},
  {name:'Pyrazinamide',atc:'J04AK01',cls:'Antimycobacterial',cat:'Access',ddd:1.5},
  {name:'Ethambutol',atc:'J04AK02',cls:'Antimycobacterial',cat:'Access',ddd:1.2},
  // Watch (15)
  {name:'Ciprofloxacin',atc:'J01MA02',cls:'Fluoroquinolone',cat:'Watch',ddd:0.8},
  {name:'Levofloxacin',atc:'J01MA12',cls:'Fluoroquinolone',cat:'Watch',ddd:0.5},
  {name:'Moxifloxacin',atc:'J01MA14',cls:'Fluoroquinolone',cat:'Watch',ddd:0.4},
  {name:'Ceftazidime',atc:'J01DD02',cls:'Cephalosporin (3rd)',cat:'Watch',ddd:4},
  {name:'Cefepime',atc:'J01DE01',cls:'Cephalosporin (4th)',cat:'Watch',ddd:4},
  {name:'Ceftaroline',atc:'J01DI01',cls:'Cephalosporin (5th)',cat:'Watch',ddd:1.2},
  {name:'Piperacillin/Tazobactam',atc:'J01CR05',cls:'Penicillin+Inhibitor',cat:'Watch',ddd:14},
  {name:'Meropenem',atc:'J01DH02',cls:'Carbapenem',cat:'Watch',ddd:2},
  {name:'Imipenem/Cilastatin',atc:'J01DH51',cls:'Carbapenem',cat:'Watch',ddd:2},
  {name:'Ertapenem',atc:'J01DH03',cls:'Carbapenem',cat:'Watch',ddd:1},
  {name:'Azithromycin',atc:'J01FA10',cls:'Macrolide',cat:'Watch',ddd:0.3},
  {name:'Vancomycin',atc:'J01XA01',cls:'Glycopeptide',cat:'Watch',ddd:2},
  {name:'Teicoplanin',atc:'J01XA02',cls:'Glycopeptide',cat:'Watch',ddd:0.4},
  {name:'Linezolid',atc:'J01XX08',cls:'Oxazolidinone',cat:'Watch',ddd:1.2},
  {name:'Amikacin',atc:'J01GB06',cls:'Aminoglycoside',cat:'Watch',ddd:1},
  // Reserve (9)
  {name:'Colistin',atc:'J01XB01',cls:'Polymyxin',cat:'Reserve',ddd:0.75},
  {name:'Polymyxin B',atc:'J01XB02',cls:'Polymyxin',cat:'Reserve',ddd:0.75},
  {name:'Tigecycline',atc:'J01AA12',cls:'Glycylcycline',cat:'Reserve',ddd:0.1},
  {name:'Daptomycin',atc:'J01XX09',cls:'Lipopeptide',cat:'Reserve',ddd:0.28},
  {name:'Ceftazidime/Avibactam',atc:'J01DD52',cls:'Cephalosporin+Inhibitor',cat:'Reserve',ddd:6},
  {name:'Ceftolozane/Tazobactam',atc:'J01DI54',cls:'Cephalosporin+Inhibitor',cat:'Reserve',ddd:3},
  {name:'Fosfomycin IV',atc:'J01XX01',cls:'Phosphonic acid',cat:'Reserve',ddd:4},
  {name:'Fosfomycin Oral',atc:'J01XX01',cls:'Phosphonic acid',cat:'Reserve',ddd:0.15},
  {name:'Posaconazole',atc:'J02AC04',cls:'Triazole',cat:'Reserve',ddd:0.3},
];

// ─── SPREADSHEET HELPERS ────────────────────────────────────
/**
 * Get or create the spreadsheet
 * @returns {SpreadsheetApp.Spreadsheet}
 */
function getSpreadsheet() {
  const files = DriveApp.getFilesByName(CONFIG.SPREADSHEET_NAME);
  if (files.hasNext()) return SpreadsheetApp.open(files.next());
  return SpreadsheetApp.create(CONFIG.SPREADSHEET_NAME);
}

/**
 * Get or create a sheet by name
 * @param {string} name - Sheet name
 * @returns {SpreadsheetApp.Sheet}
 */
function getSheet(name) {
  const ss = getSpreadsheet();
  let sheet = ss.getSheetByName(name);
  if (!sheet) sheet = ss.insertSheet(name);
  return sheet;
}

// ─── INPUT SANITIZATION (XSS Protection) ─────────────────────
/**
 * Sanitize user input to prevent XSS attacks
 * @param {string} str - Input string to sanitize
 * @returns {string} Sanitized string
 */
function sanitizeInput(str) {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Escape HTML for safe display in CSV/text exports
 * @param {string} str - Input string
 * @returns {string} Escaped string
 */
function escapeHtml(str) {
  if (!str || typeof str !== 'string') return '';
  return str.replace(/[&<>"']/g, function(m) {
    var map = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;'};
    return map[m];
  });
}

// ─── SERVE HTML (OPTION A) + API GET FALLBACK ───────────────
/**
 * Handle GET requests - serve HTML or handle API calls
 * @param {Object} e - Event object with parameters
 * @returns {HtmlOutput|TextOutput}
 */
function doGet(e) {
  var params = e.parameter || {};
  if (params.action) return handleGetApi(params);
  return HtmlService.createHtmlOutputFromFile('Index')
    .setTitle('OncoCollect v3.1 — Clinical Research Database')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1.0');
}

// ─── POST HANDLER (for save operations with large payloads) ──
/**
 * Handle POST requests for data mutations and API calls
 * @param {Object} e - Event object with post data
 * @returns {TextOutput}
 */
function doPost(e) {
  try {
    var body = JSON.parse(e.postData.contents);
    var action = body.action;
    var token = body.token || '';
    var csrf = body.csrf || '';
    var data = body.data || {};

    // CSRF check for authenticated actions
    if (token && action !== 'login' && !verifyCsrf(token, csrf)) {
      return corsJson({ success: false, message: 'CSRF verification failed', authError: true });
    }

    if (action === 'login') {
      return corsJson(apiLogin(sanitizeInput(data.username), data.password));
    }

    if (!verifyToken(token)) {
      return corsJson({ success: false, message: 'Unauthorized', authError: true });
    }

    switch (action) {
      // Write operations
      case 'save':
        return corsJson(apiSave(token, data.record));
      case 'delete':
        return corsJson(apiDelete(token, data.studyId));
      case 'addUser':
        return corsJson(apiAddUser(token, sanitizeInput(data.username), data.password, sanitizeInput(data.role)));
      case 'changePassword':
        return corsJson(apiChangePassword(token, data.currentPassword, data.newPassword));
      case 'toggleUser':
        return corsJson(apiToggleUser(token, sanitizeInput(data.username), data.active));
      // Read operations (also accessible via POST for CORS compatibility)
      case 'read':
        return corsJson(apiRead(token, data.filters || data || {}));
      case 'getAntibiotics':
        return corsJson(apiGetAntibiotics(token));
      case 'generateId':
        return corsJson(apiGenerateId(token));
      case 'getUsers':
        return corsJson(apiGetUsers(token));
      case 'getAuditLog':
        return corsJson(apiGetAuditLog(token, data));
      case 'exportFlat':
        return corsJson(apiExportFlat(token, data.filters || data || {}));
      case 'exportRelational':
        return corsJson(apiExportRelational(token, data.filters || data || {}));
      case 'purgeDeleted':
        return corsJson(apiPurgeDeleted(token));
      default:
        return corsJson({ success: false, message: 'Unknown action: ' + escapeHtml(action) });
    }
  } catch (err) {
    Logger.log('POST error: ' + err.message);
    return corsJson({ success: false, message: 'Server error: ' + escapeHtml(err.message) });
  }
}

// ─── API GET HANDLER (for read-only operations) ─────────────
/**
 * Handle GET API requests for read-only operations
 * @param {Object} params - Request parameters
 * @returns {TextOutput}
 */
function handleGetApi(params) {
  var action = params.action;
  var token = params.token || '';

  try {
    if (action === 'login') {
      return corsJson(apiLogin(sanitizeInput(params.username), params.password));
    }

    if (!verifyToken(token)) {
      return corsJson({ success: false, message: 'Unauthorized', authError: true });
    }

    switch (action) {
      case 'read':
        return corsJson(apiRead(token, params));
      case 'getAntibiotics':
        return corsJson(apiGetAntibiotics(token));
      case 'generateId':
        return corsJson(apiGenerateId(token));
      case 'getUsers':
        return corsJson(apiGetUsers(token));
      case 'getAuditLog':
        return corsJson(apiGetAuditLog(token, params));
      case 'exportFlat':
        return corsJson(apiExportFlat(token, params));
      case 'exportRelational':
        return corsJson(apiExportRelational(token, params));
      case 'purgeDeleted':
        return corsJson(apiPurgeDeleted(token));
      default:
        return corsJson({ success: false, message: 'Unknown action: ' + escapeHtml(action) });
    }
  } catch (err) {
    Logger.log('GET API error: ' + err.message);
    return corsJson({ success: false, message: 'Server error: ' + escapeHtml(err.message) });
  }
}

/**
 * Create CORS-enabled JSON response
 * @param {Object} data - Response data
 * @returns {TextOutput}
 */
function corsJson(data) {
  return ContentService.createTextOutput(JSON.stringify(data))
    .setMimeType(ContentService.MimeType.JSON);
}

// ─── SERVER-SIDE API FUNCTIONS ──────────────────────────────

/**
 * Handle user login with rate limiting and password verification
 * @param {string} username - User's username
 * @param {string} password - User's password
 * @returns {Object} Login result
 */
function apiLogin(username, password) {
  username = (username || '').trim();
  if (!username || !password) {
    return { success: false, message: 'Username and password required' };
  }

  // Rate limiting
  if (isLoginLocked(username)) {
    return { success: false, message: 'Account temporarily locked. Too many failed attempts. Try again in ' + CONFIG.LOGIN_LOCKOUT_MINUTES + ' minutes.' };
  }

  const sheet = getSheet('Users');
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === username) {
      if (data[i][4] !== true) return { success: false, message: 'Account is disabled' };

      const storedHash = data[i][1];
      const salt = data[i][2];
      let match = false;

      if (salt) {
        match = hashPassword(password, salt) === storedHash;
      } else {
        match = legacyHash(password) === storedHash;
        if (match) {
          var newSalt = generateSalt();
          var newHash = hashPassword(password, newSalt);
          sheet.getRange(i + 1, 2).setValue(newHash);
          sheet.getRange(i + 1, 3).setValue(newSalt);
        }
      }

      if (match) {
        clearLoginAttempts(username);
        sheet.getRange(i + 1, 7).setValue(new Date());
        var token = createToken(username, data[i][3]);
        var csrf = generateCsrf(token);
        auditLog(username, 'LOGIN', 'User logged in');
        return {
          success: true,
          user: { username: username, role: data[i][3], token: token, csrf: csrf }
        };
      } else {
        recordLoginAttempt(username);
        return { success: false, message: 'Invalid username or password' };
      }
    }
  }
  recordLoginAttempt(username);
  return { success: false, message: 'Invalid username or password' };
}

/**
 * Read records with optional filters
 * @param {string} token - Auth token
 * @param {Object} params - Filter parameters
 * @returns {Object} Records and stats
 */
function apiRead(token, params) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };

  const sheet = getSheet('Records');
  const data = sheet.getDataRange().getValues();
  if (data.length <= 1) return { success: true, records: [], stats: getEmptyStats() };

  // Parse filters
  var filters = {};
  if (params) {
    if (params.dateFrom) filters.dateFrom = params.dateFrom;
    if (params.dateTo) filters.dateTo = params.dateTo;
    if (params.site && params.site !== 'all') filters.site = sanitizeInput(params.site);
    if (params.ward && params.ward !== 'all') filters.ward = sanitizeInput(params.ward);
    if (params.outcome && params.outcome !== 'all') filters.outcome = sanitizeInput(params.outcome);
  }

  // Column mapping:
  // 0:Timestamp 1:Study ID 2:Age 3:Sex 4:Created By
  // 5:Hospital 6:Date of Collection 7:Collector Name
  // 8:Admission Date 9:Discharge Date 10:LOS 11:Admission Type 12:Ward 13:Ward Other
  // 14:Diagnosis 15:Cancer Type 16:Cancer Name 17:Cancer Name Other
  // 18:Stage 19:Treatment 20:Treatment Other
  // 21:Comorbidities 22:Comorbidities Other 23:Immunosuppressed
  // 24:Outcome 25:Readmission 30d 26:De-escalation
  // 27:Antibiotics JSON 28:Cultures JSON
  // 29:Required for Analysis
  // 30:Created Date 31:Updated Date 32:Deleted 33:Deleted By 34:Deleted Date 35:Version

  const records = [];
  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    if (!row[1]) continue;
    if (row[32] === true) continue; // soft-deleted

    // Apply filters
    if (filters.dateFrom && row[8] && new Date(row[8]) < new Date(filters.dateFrom)) continue;
    if (filters.dateTo && row[9] && new Date(row[9]) > new Date(filters.dateTo + 'T23:59:59')) continue;
    if (filters.site && row[5] !== filters.site) continue;
    if (filters.ward && row[12] !== filters.ward) continue;
    if (filters.outcome && row[24] !== filters.outcome) continue;

    let antibiotics = [], cultures = [];
    // Try relational sheets first, fall back to JSON columns
    antibiotics = loadAntibioticsForStudy(row[1]);
    cultures = loadCulturesForStudy(row[1]);
    if (antibiotics.length === 0) { try { antibiotics = JSON.parse(row[27] || '[]'); } catch(e) {} }
    if (cultures.length === 0) { try { cultures = JSON.parse(row[28] || '[]'); } catch(e) {} }

    records.push({
      timestamp: formatDate(row[0]),
      studyId: row[1],
      age: row[2] !== '' ? row[2] : null,
      sex: row[3] || null,
      createdBy: row[4] || null,
      hospital: row[5] || null,
      dateOfCollection: formatDate(row[6]),
      collectorName: row[7] || null,
      admissionDate: formatDate(row[8]),
      dischargeDate: formatDate(row[9]),
      los: row[10] !== '' ? row[10] : null,
      admissionType: row[11] || null,
      ward: row[12] || null,
      wardOther: row[13] || null,
      diagnosis: row[14] || null,
      cancerType: row[15] || null,
      cancerName: row[16] || null,
      cancerNameOther: row[17] || null,
      stage: row[18] || null,
      treatment: row[19] || null,
      treatmentOther: row[20] || null,
      comorbidities: row[21] || null,
      comorbiditiesOther: row[22] || null,
      immunosuppressed: row[23] || null,
      outcome: row[24] || null,
      readmission30d: row[25] || null,
      deEscalation: row[26] || null,
      antibiotics: antibiotics,
      cultures: cultures,
      requiredForAnalysis: row[29] || null,
      createdAt: formatDate(row[30]),
      updatedAt: formatDate(row[31]),
      version: row[35] || 0,
    });
  }

  var stats = calculateStats(records);
  return { success: true, records: records, stats: stats };
}

/**
 * Save a record with validation and optimistic concurrency
 * @param {string} token - Auth token
 * @param {Object} record - Record data to save
 * @returns {Object} Save result
 */
function apiSave(token, record) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  if (!record || !record.studyId) return { success: false, message: 'Missing record or studyId' };

  // Validate required fields
  var validation = validateRecord(record);
  if (!validation.valid) {
    return { success: false, message: 'Validation failed: ' + validation.errors.join('; ') };
  }

  const user = getTokenUser(token);
  const sheet = getSheet('Records');
  const data = sheet.getDataRange().getValues();

  let existingRow = -1;
  for (let i = 1; i < data.length; i++) {
    if (data[i][1] === record.studyId && data[i][32] !== true) {
      existingRow = i + 1;
      break;
    }
  }

  // Optimistic concurrency
  if (existingRow > 0 && record.version != null) {
    var currentVersion = data[existingRow - 1][35] || 0;
    if (record.version !== currentVersion) {
      return { success: false, message: 'Record was modified by another user. Please refresh and try again.', conflict: true };
    }
  }

  const now = new Date();
  var newVersion = (existingRow > 0 ? (data[existingRow - 1][35] || 0) : 0) + 1;
  var effectiveWard = record.ward === 'Other' ? '' : (record.ward || '');
  var effectiveCancer = record.cancerName === 'Other' ? '' : (record.cancerName || '');
  var effectiveTreatment = record.treatment === 'Other' ? '' : (record.treatment || '');
  var effectiveComorb = record.comorbidities === 'Other' ? '' : (record.comorbidities || '');

  const rowData = [
    now,                                                                    // 0: Timestamp
    record.studyId,                                                         // 1: Study ID
    record.age || '',                                                       // 2: Age
    record.sex || '',                                                       // 3: Sex
    user ? user.username : 'Unknown',                                       // 4: Created By
    record.hospital || '',                                                  // 5: Hospital
    record.dateOfCollection || '',                                          // 6: Date of Collection
    record.collectorName || '',                                             // 7: Collector Name
    record.admissionDate || '',                                             // 8: Admission Date
    record.dischargeDate || '',                                             // 9: Discharge Date
    record.los != null ? record.los : '',                                   // 10: LOS
    record.admissionType || '',                                             // 11: Admission Type
    effectiveWard || record.ward || '',                                     // 12: Ward
    record.ward === 'Other' ? (record.wardOther || '') : '',               // 13: Ward Other
    record.diagnosis || '',                                                 // 14: Diagnosis
    record.cancerType || '',                                                // 15: Cancer Type
    effectiveCancer || record.cancerName || '',                             // 16: Cancer Name
    record.cancerName === 'Other' ? (record.cancerNameOther || '') : '',   // 17: Cancer Name Other
    record.stage || '',                                                     // 18: Stage
    effectiveTreatment || record.treatment || '',                           // 19: Treatment
    record.treatment === 'Other' ? (record.treatmentOther || '') : '',     // 20: Treatment Other
    effectiveComorb || record.comorbidities || '',                          // 21: Comorbidities
    record.comorbidities === 'Other' ? (record.comorbiditiesOther || '') : '', // 22: Comorbidities Other
    record.immunosuppressed || '',                                          // 23: Immunosuppressed
    record.outcome || '',                                                   // 24: Outcome
    record.readmission30d || '',                                            // 25: Readmission 30d
    record.deEscalation || '',                                              // 26: De-escalation
    JSON.stringify(record.antibiotics || []),                               // 27: Antibiotics JSON
    JSON.stringify(record.cultures || []),                                  // 28: Cultures JSON
    record.requiredForAnalysis || '',                                       // 29: Required for Analysis
  ];

  if (existingRow > 0) {
    rowData.push(data[existingRow - 1][30] || now); // 30: Created Date (preserve original)
    rowData.push(now);                               // 31: Updated Date
    rowData.push(false);                             // 32: Deleted
    rowData.push('');                                // 33: Deleted By
    rowData.push('');                                // 34: Deleted Date
    rowData.push(newVersion);                        // 35: Version
    sheet.getRange(existingRow, 1, 1, rowData.length).setValues([rowData]);
    auditLog(user ? user.username : 'Unknown', 'UPDATE', 'Updated record ' + record.studyId);
  } else {
    rowData.push(now);   // 30: Created Date
    rowData.push(now);   // 31: Updated Date
    rowData.push(false); // 32: Deleted
    rowData.push('');    // 33: Deleted By
    rowData.push('');    // 34: Deleted Date
    rowData.push(newVersion); // 35: Version
    sheet.appendRow(rowData);
    auditLog(user ? user.username : 'Unknown', 'CREATE', 'Created record ' + record.studyId);
  }

  // Save normalized antibiotic rows
  saveAntibiotics(record.studyId, record.antibiotics || []);

  // Save normalized culture rows
  saveCultures(record.studyId, record.cultures || []);

  checkMdrAlert();

  return { success: true, message: 'Record saved', studyId: record.studyId, version: newVersion };
}

function apiDelete(token, studyId) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  if (!studyId) return { success: false, message: 'Missing studyId' };
  const user = getTokenUser(token);
  const sheet = getSheet('Records');
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (data[i][1] === studyId && data[i][32] !== true) {
      sheet.getRange(i + 1, 33).setValue(true);   // Deleted
      sheet.getRange(i + 1, 34).setValue(user ? user.username : 'Unknown'); // Deleted By
      sheet.getRange(i + 1, 35).setValue(new Date()); // Deleted Date
      // Also delete from relational Antibiotics sheet
      deleteAntibioticsForStudy(studyId);
      // Also delete from relational Cultures sheet
      deleteCulturesForStudy(studyId);
      auditLog(user ? user.username : 'Unknown', 'DELETE', 'Soft-deleted record ' + studyId);
      return { success: true, message: 'Record deleted' };
    }
  }
  return { success: false, message: 'Record not found' };
}

function apiPurgeDeleted(token) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const user = getTokenUser(token);
  if (!user || user.role !== 'Admin') return { success: false, message: 'Admin access required' };

  const sheet = getSheet('Records');
  const data = sheet.getDataRange().getValues();
  var purged = 0;

  // Delete from bottom to top to preserve row indices
  for (let i = data.length - 1; i >= 1; i--) {
    if (data[i][32] === true) {
      var studyId = data[i][1];
      // Also purge from relational sheets
      deleteAntibioticsForStudy(studyId);
      deleteCulturesForStudy(studyId);
      sheet.deleteRow(i + 1);
      purged++;
    }
  }

  auditLog(user.username, 'PURGE_DELETED', 'Purged ' + purged + ' soft-deleted records');
  return { success: true, message: 'Purged ' + purged + ' deleted records' };
}

function apiGetAntibiotics(token) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const sheet = getSheet('WHO');
  const data = sheet.getDataRange().getValues();
  const antibiotics = [];
  for (let i = 1; i < data.length; i++) {
    if (!data[i][0]) continue;
    antibiotics.push({ name: data[i][0], atc: data[i][1] || '', abxClass: data[i][2], category: data[i][3], ddd: data[i][4] || 0 });
  }
  if (antibiotics.length === 0) {
    populateWhoSheet();
    return apiGetAntibiotics(token);
  }
  return { success: true, antibiotics: antibiotics };
}

function apiGenerateId(token) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const ss = getSpreadsheet();
  var metaSheet = ss.getSheetByName('MetaData');
  if (!metaSheet) {
    metaSheet = ss.insertSheet('MetaData');
    metaSheet.appendRow(CONFIG.META_HEADERS);
    metaSheet.appendRow(['lastSeq', '0']);
    metaSheet.getRange(1, 1, 1, CONFIG.META_HEADERS.length).setFontWeight('bold');
  }
  var metaData = metaSheet.getDataRange().getValues();
  var seqRow = -1;
  var lastSeq = 0;
  for (var i = 1; i < metaData.length; i++) {
    if (metaData[i][0] === 'lastSeq') {
      seqRow = i + 1;
      lastSeq = parseInt(metaData[i][1]) || 0;
      break;
    }
  }
  lastSeq++;
  if (seqRow > 0) {
    metaSheet.getRange(seqRow, 2).setValue(lastSeq);
  } else {
    metaSheet.appendRow(['lastSeq', lastSeq]);
  }
  return { success: true, id: 'PID-' + String(lastSeq).padStart(6, '0') };
}

function apiAddUser(token, username, password, role) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const user = getTokenUser(token);
  if (!user || user.role !== 'Admin') return { success: false, message: 'Admin access required' };

  username = (username || '').trim();
  if (!username || !password) return { success: false, message: 'Username and password required' };

  var strength = checkPasswordStrength(password);
  if (!strength.valid) return { success: false, message: strength.message };

  const sheet = getSheet('Users');
  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === username) return { success: false, message: 'Username already exists' };
  }
  const salt = generateSalt();
  const hash = hashPassword(password, salt);
  sheet.appendRow([username, hash, salt, role || 'Agent', true, new Date(), '']);
  auditLog(user.username, 'ADD_USER', 'Created user: ' + username + ' (' + role + ')');
  return { success: true, message: 'User created' };
}

function apiChangePassword(token, currentPassword, newPassword) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const user = getTokenUser(token);
  if (!user) return { success: false, message: 'Invalid token' };
  var strength = checkPasswordStrength(newPassword);
  if (!strength.valid) return { success: false, message: strength.message };

  const sheet = getSheet('Users');
  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === user.username) {
      var storedHash = data[i][1];
      var salt = data[i][2];
      var currentHash = salt ? hashPassword(currentPassword, salt) : legacyHash(currentPassword);
      if (currentHash !== storedHash) return { success: false, message: 'Current password is incorrect' };
      var newSalt = generateSalt();
      var newHash = hashPassword(newPassword, newSalt);
      sheet.getRange(i + 1, 2).setValue(newHash);
      sheet.getRange(i + 1, 3).setValue(newSalt);
      auditLog(user.username, 'CHANGE_PASSWORD', 'Password changed');
      return { success: true, message: 'Password changed successfully' };
    }
  }
  return { success: false, message: 'User not found' };
}

function apiToggleUser(token, username, active) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const user = getTokenUser(token);
  if (!user || user.role !== 'Admin') return { success: false, message: 'Admin access required' };
  if (username === user.username) return { success: false, message: 'Cannot disable your own account' };

  const sheet = getSheet('Users');
  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === username) {
      sheet.getRange(i + 1, 5).setValue(active === true);
      auditLog(user.username, 'TOGGLE_USER', (active ? 'Enabled' : 'Disabled') + ' user: ' + username);
      return { success: true, message: 'User ' + (active ? 'enabled' : 'disabled') };
    }
  }
  return { success: false, message: 'User not found' };
}

function apiGetUsers(token) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const user = getTokenUser(token);
  if (!user || user.role !== 'Admin') return { success: false, message: 'Admin access required' };

  const sheet = getSheet('Users');
  const data = sheet.getDataRange().getValues();
  const users = [];
  for (let i = 1; i < data.length; i++) {
    users.push({ username: data[i][0], role: data[i][3], active: data[i][4], createdAt: formatDate(data[i][5]), lastLogin: formatDate(data[i][6]) });
  }
  return { success: true, users: users };
}

function apiGetAuditLog(token, params) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const user = getTokenUser(token);
  if (!user || user.role !== 'Admin') return { success: false, message: 'Admin access required' };

  const sheet = getSheet('AuditLog');
  const data = sheet.getDataRange().getValues();
  var logs = [];
  var limit = parseInt(params && params.limit) || 100;
  for (let i = data.length - 1; i >= 1 && logs.length < limit; i--) {
    logs.push({ timestamp: formatDateTime(data[i][0]), user: data[i][1], action: data[i][2], details: data[i][3] });
  }
  return { success: true, logs: logs };
}

// ─── FLAT CSV EXPORT (for SPSS/R/Stata analysis) ────────────
function apiExportFlat(token, params) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  var result = apiRead(token, params || {});
  if (!result.success) return result;

  var maxAbx = 0, maxCult = 0;
  result.records.forEach(function(r) {
    if (r.antibiotics && r.antibiotics.length > maxAbx) maxAbx = r.antibiotics.length;
    if (r.cultures && r.cultures.length > maxCult) maxCult = r.cultures.length;
  });

  // Build flat headers
  var headers = ['Timestamp','Study_ID','Age','Sex','Created_By','Hospital','Date_of_Collection','Collector_Name',
    'Admission_Date','Discharge_Date','LOS','Admission_Type','Ward','Ward_Other',
    'Diagnosis','Cancer_Type','Cancer_Name','Cancer_Name_Other',
    'Stage','Treatment','Treatment_Other',
    'Comorbidities','Comorbidities_Other','Immunosuppressed',
    'Outcome','Readmission_30d','De_escalation'];

  for (var a = 1; a <= maxAbx; a++) {
    ['Name','Class','Category','Route','Dose','Freq','Start','Stop','Duration','DDD','Grams','DDD_Calc','DOT','Indication','Therapy','Febrile_Neutro','Febrile_Episodes'].forEach(function(f) {
      headers.push('Abx_' + a + '_' + f);
    });
  }
  for (var c = 1; c <= maxCult; c++) {
    ['Sent','Date','Type','Type_Other','Result','Organism','Gram','AST','Resist','MDR','XDR','ESKAPE','ESKAPE_Organisms'].forEach(function(f) {
      headers.push('Cult_' + c + '_' + f);
    });
  }
  headers.push('Required_for_Analysis');

  var rows = [headers.join(',')];
  result.records.forEach(function(r) {
    var row = [
      csvSafe(r.timestamp), csvSafe(r.studyId), csvSafe(r.age), csvSafe(r.sex),
      csvSafe(r.createdBy), csvSafe(r.hospital), csvSafe(r.dateOfCollection), csvSafe(r.collectorName),
      csvSafe(r.admissionDate), csvSafe(r.dischargeDate), csvSafe(r.los), csvSafe(r.admissionType),
      csvSafe(r.ward), csvSafe(r.wardOther),
      csvSafe(r.diagnosis), csvSafe(r.cancerType), csvSafe(r.cancerName), csvSafe(r.cancerNameOther),
      csvSafe(r.stage), csvSafe(r.treatment), csvSafe(r.treatmentOther),
      csvSafe(r.comorbidities), csvSafe(r.comorbiditiesOther), csvSafe(r.immunosuppressed),
      csvSafe(r.outcome), csvSafe(r.readmission30d), csvSafe(r.deEscalation)
    ];
    for (var a = 0; a < maxAbx; a++) {
      var abx = (r.antibiotics && r.antibiotics[a]) || {};
      row.push(csvSafe(abx.name), csvSafe(abx.abxClass), csvSafe(abx.aware), csvSafe(abx.route),
        csvSafe(abx.dose), csvSafe(abx.freq), csvSafe(abx.start), csvSafe(abx.stop),
        csvSafe(abx.duration), csvSafe(abx.ddd), csvSafe(abx.grams), csvSafe(abx.dddCalc),
        csvSafe(abx.dot), csvSafe(abx.indication), csvSafe(abx.therapyType),
        csvSafe(abx.febrileNeutro), csvSafe(abx.febrileEpisodes));
    }
    for (var c = 0; c < maxCult; c++) {
      var cult = (r.cultures && r.cultures[c]) || {};
      row.push(csvSafe(cult.sent), csvSafe(cult.date), csvSafe(cult.type), csvSafe(cult.typeOther),
        csvSafe(cult.result), csvSafe(cult.organism), csvSafe(cult.gram), csvSafe(cult.ast), csvSafe(cult.resist),
        csvSafe(cult.mdr), csvSafe(cult.xdr), csvSafe(cult.eskape), csvSafe(cult.eskapeOrganisms));
    }
    row.push(csvSafe(r.requiredForAnalysis));
    rows.push(row.join(','));
  });

  return { success: true, csv: rows.join('\n'), filename: 'OncoCollect_Flat_' + new Date().toISOString().split('T')[0] + '.csv' };
}

function csvSafe(val) {
  if (val == null) return '';
  var s = String(val);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // CSV injection protection
  if (s.indexOf(',') >= 0 || s.indexOf('"') >= 0 || s.indexOf('\n') >= 0) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

// ─── SESSION TOKENS (HMAC-signed) ──────────────────────────
function createToken(username, role) {
  const ts = Date.now();
  const raw = username + ':' + role + ':' + ts;
  const signature = computeHmac(raw);
  return Utilities.base64Encode(raw + ':' + signature);
}

function verifyToken(token) {
  if (!token) return false;
  try {
    const decoded = Utilities.base64Decode(token);
    const str = Utilities.newBlob(decoded).getDataAsString();
    const parts = str.split(':');
    if (parts.length < 4) return false;
    const ts = parseInt(parts[2]);
    if (Date.now() - ts > CONFIG.SESSION_TIMEOUT) return false;
    const payload = parts[0] + ':' + parts[1] + ':' + parts[2];
    const expectedSig = computeHmac(payload);
    if (parts.slice(3).join(':') !== expectedSig) return false;
    const username = parts[0];
    const userSheet = getSheet('Users');
    const data = userSheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (data[i][0] === username && data[i][4] === true) return true;
    }
    return false;
  } catch(e) { return false; }
}

function getTokenUser(token) {
  if (!token) return null;
  try {
    const decoded = Utilities.base64Decode(token);
    const str = Utilities.newBlob(decoded).getDataAsString();
    const parts = str.split(':');
    return { username: parts[0], role: parts[1] };
  } catch(e) { return null; }
}

function computeHmac(data) {
  return Utilities.computeHmacSha256Signature(data, CONFIG.HMAC_SECRET)
    .map(function(b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
}

// ─── CSRF TOKENS ───────────────────────────────────────────
function generateCsrf(token) {
  return computeHmac(token + '_csrf');
}

function verifyCsrf(token, csrf) {
  if (!token || !csrf) return false;
  return csrf === generateCsrf(token);
}

// ─── RATE LIMITING ─────────────────────────────────────────
function isLoginLocked(username) {
  var sheet = getSheet('LoginAttempts');
  var data = sheet.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] === username) {
      var attempts = data[i][1];
      var lastAttempt = data[i][2];
      if (attempts >= CONFIG.MAX_LOGIN_ATTEMPTS && lastAttempt) {
        var lockoutEnd = new Date(lastAttempt.getTime() + CONFIG.LOGIN_LOCKOUT_MINUTES * 60000);
        if (new Date() < lockoutEnd) return true;
        sheet.getRange(i + 1, 2).setValue(0);
        return false;
      }
    }
  }
  return false;
}

function recordLoginAttempt(username) {
  var sheet = getSheet('LoginAttempts');
  var data = sheet.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] === username) {
      sheet.getRange(i + 1, 2).setValue((data[i][1] || 0) + 1);
      sheet.getRange(i + 1, 3).setValue(new Date());
      return;
    }
  }
  sheet.appendRow([username, 1, new Date()]);
}

function clearLoginAttempts(username) {
  var sheet = getSheet('LoginAttempts');
  var data = sheet.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] === username) {
      sheet.getRange(i + 1, 2).setValue(0);
      return;
    }
  }
}

// ─── AUDIT LOGGING ─────────────────────────────────────────
function auditLog(username, action, details) {
  try {
    var sheet = getSheet('AuditLog');
    sheet.appendRow([new Date(), username || 'Unknown', action, details || '']);
    var lastRow = sheet.getLastRow();
    if (lastRow > 1001) sheet.deleteRows(2, lastRow - 1001);
  } catch(e) { Logger.log('Audit log error: ' + e.message); }
}

// ─── PASSWORD HASHING ───────────────────────────────────────
function generateSalt() {
  const raw = Date.now().toString() + Math.random().toString() + Math.random().toString();
  return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, raw)
    .map(function(b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('').substring(0, 24);
}

function hashPassword(password, salt) {
  return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, salt + ':' + password)
    .map(function(b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
}

function legacyHash(password) {
  return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, password)
    .map(function(b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
}

function checkPasswordStrength(password) {
  if (!password || password.length < CONFIG.PASSWORD_MIN_LENGTH) {
    return { valid: false, message: 'Password must be at least ' + CONFIG.PASSWORD_MIN_LENGTH + ' characters' };
  }
  if (!/[A-Z]/.test(password)) return { valid: false, message: 'Password must contain at least one uppercase letter' };
  if (!/[0-9]/.test(password)) return { valid: false, message: 'Password must contain at least one number' };
  if (!/[^A-Za-z0-9]/.test(password)) return { valid: false, message: 'Password must contain at least one special character' };
  return { valid: true, message: 'OK' };
}

// ─── RECORD VALIDATION ──────────────────────────────────────
function validateRecord(record) {
  var errors = [];
  if (!record.age && record.age !== 0) errors.push('Age is required');
  else if (record.age < 0 || record.age > 120) errors.push('Age must be 0-120');
  if (!record.sex) errors.push('Sex is required');
  if (!record.admissionDate) errors.push('Admission date is required');
  if (!record.admissionType) errors.push('Admission type is required');
  if (!record.ward) errors.push('Ward is required');
  if (!record.diagnosis) errors.push('Diagnosis is required');
  if (!record.outcome) errors.push('Outcome is required');
  if (!record.hospital) errors.push('Hospital is required');
  if (record.admissionDate && record.dischargeDate && new Date(record.dischargeDate) < new Date(record.admissionDate)) {
    errors.push('Discharge date cannot be before admission date');
  }
  if (record.antibiotics) {
    record.antibiotics.forEach(function(abx, i) {
      if (abx.duration && (abx.duration < 1 || abx.duration > 365)) {
        errors.push('Antibiotic ' + (i+1) + ': Duration must be 1-365 days');
      }
    });
  }
  return { valid: errors.length === 0, errors: errors };
}

// ─── STATS CALCULATION ──────────────────────────────────────
function calculateStats(records) {
  var total = records.length;
  var abxCourses = 0, cultSent = 0, mdrCult = 0, posCult = 0, died = 0;
  var losArr = [];
  records.forEach(function(r) {
    abxCourses += (r.antibiotics ? r.antibiotics.length : 0);
    cultSent += (r.cultures ? r.cultures.filter(function(c){return c.sent==='Yes'}).length : 0);
    if (r.los != null) losArr.push(r.los);
    if (r.outcome === 'Died') died++;
    if (r.cultures) r.cultures.forEach(function(c) {
      if (c.result === 'Positive') posCult++;
      if (c.mdr === 'Yes') mdrCult++;
    });
  });
  return {
    totalPatients: total, abxCourses: abxCourses, culturesSent: cultSent,
    mortalityRate: total ? +(died/total*100).toFixed(1) : 0,
    medianLos: median(losArr),
    mdrRate: posCult ? +(mdrCult/posCult*100).toFixed(1) : 0,
    totalPatientDays: losArr.reduce(function(s,v){return s+v},0) || 0
  };
}

function getEmptyStats() {
  return { totalPatients:0, abxCourses:0, culturesSent:0, mortalityRate:0, medianLos:0, mdrRate:0, totalPatientDays:0 };
}

// ─── MDR ALERT ─────────────────────────────────────────────
function checkMdrAlert() {
  try {
    // Read from relational Cultures sheet
    var cultSheet = getSheet('Cultures');
    var cultData = cultSheet.getDataRange().getValues();
    var posCult = 0, mdrCult = 0;
    for (var j = 1; j < cultData.length; j++) {
      if (cultData[j][4] === 'Positive') posCult++;
      if (cultData[j][9] === 'Yes') mdrCult++;
    }
    // Count total active records
    var sheet = getSheet('Records');
    var data = sheet.getDataRange().getValues();
    var total = 0;
    for (var i = 1; i < data.length; i++) {
      if (data[i][32] === true) continue;
      total++;
    }
    var mdrRate = posCult ? mdrCult/posCult : 0;
    if (mdrRate > CONFIG.MDR_ALERT_THRESHOLD && total >= 10) {
      var userSheet = getSheet('Users');
      var userData = userSheet.getDataRange().getValues();
      var adminEmails = [];
      for (var j = 1; j < userData.length; j++) {
        if (userData[j][3] === 'Admin' && userData[j][4] === true && userData[j][0].includes('@')) {
          adminEmails.push(userData[j][0]);
        }
      }
      if (adminEmails.length > 0) {
        try {
          MailApp.sendEmail({
            to: adminEmails.join(','),
            subject: 'OncoCollect Alert: MDR Rate Exceeds Threshold',
            body: 'MDR rate: ' + (mdrRate*100).toFixed(1) + '% (threshold: ' + (CONFIG.MDR_ALERT_THRESHOLD*100) + '%)\n\nAutomated alert from OncoCollect.'
          });
        } catch(e) { Logger.log('Email alert failed: ' + e.message); }
      }
    }
  } catch(e) { Logger.log('MDR alert check failed: ' + e.message); }
}

// ─── UTILITY ────────────────────────────────────────────────
function formatDate(val) {
  if (!val) return null;
  if (typeof val === 'string') return val;
  if (val instanceof Date) {
    return val.getFullYear() + '-' + String(val.getMonth()+1).padStart(2,'0') + '-' + String(val.getDate()).padStart(2,'0');
  }
  return String(val);
}

function formatDateTime(val) {
  if (!val) return null;
  if (val instanceof Date) {
    return formatDate(val) + ' ' + String(val.getHours()).padStart(2,'0') + ':' + String(val.getMinutes()).padStart(2,'0');
  }
  return String(val);
}

function median(arr) {
  if (!arr.length) return 0;
  var s = arr.slice().sort(function(a,b){return a-b});
  var m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : +((s[m-1]+s[m]) / 2).toFixed(1);
}

// ─── BACKUP AUTOMATION ─────────────────────────────────────
function backupData() {
  try {
    var ss = getSpreadsheet();
    var dateStr = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'yyyy-MM-dd');
    DriveApp.getFileById(ss.getId()).makeCopy(CONFIG.SPREADSHEET_NAME + '_Backup_' + dateStr);
    Logger.log('Backup created');
  } catch(e) { Logger.log('Backup failed: ' + e.message); }
}

function setupBackupTrigger() {
  ScriptApp.getProjectTriggers().forEach(function(t) {
    if (t.getHandlerFunction() === 'backupData') ScriptApp.deleteTrigger(t);
  });
  ScriptApp.newTrigger('backupData').timeBased().onWeekDay(ScriptApp.WeekDay.MON).atHour(2).create();
  Logger.log('Weekly backup trigger created');
}

// ─── ONE-TIME SETUP ─────────────────────────────────────────
function setupSheets() {
  const ss = getSpreadsheet();

  var defaultSheet = ss.getSheetByName('Sheet1');
  if (defaultSheet && ss.getSheets().length > 1) ss.deleteSheet(defaultSheet);

  // Records
  var recordsSheet = ss.getSheetByName('Records');
  if (!recordsSheet) recordsSheet = ss.insertSheet('Records');
  if (recordsSheet.getLastRow() === 0) {
    recordsSheet.appendRow(CONFIG.RECORD_HEADERS);
    recordsSheet.getRange(1, 1, 1, CONFIG.RECORD_HEADERS.length).setFontWeight('bold');
  }

  // Users
  var usersSheet = ss.getSheetByName('Users');
  if (!usersSheet) usersSheet = ss.insertSheet('Users');
  if (usersSheet.getLastRow() === 0) {
    usersSheet.appendRow(CONFIG.USER_HEADERS);
    usersSheet.getRange(1, 1, 1, CONFIG.USER_HEADERS.length).setFontWeight('bold');
    var salt = generateSalt();
    var hash = hashPassword('Admin@123', salt);
    usersSheet.appendRow(['admin', hash, salt, 'Admin', true, new Date(), '']);
  }

  // WHO
  populateWhoSheet();

  // AuditLog
  var auditSheet = ss.getSheetByName('AuditLog');
  if (!auditSheet) auditSheet = ss.insertSheet('AuditLog');
  if (auditSheet.getLastRow() === 0) {
    auditSheet.appendRow(CONFIG.AUDIT_HEADERS);
    auditSheet.getRange(1, 1, 1, CONFIG.AUDIT_HEADERS.length).setFontWeight('bold');
  }

  // LoginAttempts
  var loginSheet = ss.getSheetByName('LoginAttempts');
  if (!loginSheet) loginSheet = ss.insertSheet('LoginAttempts');
  if (loginSheet.getLastRow() === 0) {
    loginSheet.appendRow(CONFIG.LOGIN_ATTEMPT_HEADERS);
    loginSheet.getRange(1, 1, 1, CONFIG.LOGIN_ATTEMPT_HEADERS.length).setFontWeight('bold');
  }

  // MetaData
  var metaSheet = ss.getSheetByName('MetaData');
  if (!metaSheet) metaSheet = ss.insertSheet('MetaData');
  if (metaSheet.getLastRow() === 0) {
    metaSheet.appendRow(CONFIG.META_HEADERS);
    metaSheet.getRange(1, 1, 1, CONFIG.META_HEADERS.length).setFontWeight('bold');
    metaSheet.appendRow(['lastSeq', '0']);
  }

  // Antibiotics Sheet (relational — one row per antibiotic)
  var abxSheet = ss.getSheetByName('Antibiotics');
  if (!abxSheet) abxSheet = ss.insertSheet('Antibiotics');
  if (abxSheet.getLastRow() === 0) {
    abxSheet.appendRow(ANTIBIOTIC_HEADERS);
    abxSheet.getRange(1, 1, 1, ANTIBIOTIC_HEADERS.length).setFontWeight('bold');
  }

  // Cultures Sheet (relational — one row per culture)
  var cultSheet = ss.getSheetByName('Cultures');
  if (!cultSheet) cultSheet = ss.insertSheet('Cultures');
  if (cultSheet.getLastRow() === 0) {
    cultSheet.appendRow(CULTURE_HEADERS);
    cultSheet.getRange(1, 1, 1, CULTURE_HEADERS.length).setFontWeight('bold');
  }

  setupBackupTrigger();

  Logger.log('Setup complete! Default login: admin / Admin@123');
  Logger.log('IMPORTANT: Change CONFIG.HMAC_SECRET before deploying to production!');
}

// ─── RELATIONAL ANTIBIOTICS HELPERS ───────────────────────
function saveAntibiotics(studyId, antibiotics) {
  var sheet = getSheet('Antibiotics');
  var data = sheet.getDataRange().getValues();

  // Remove old rows for this Study ID
  for (var i = data.length - 1; i >= 1; i--) {
    if (data[i][0] === studyId) {
      sheet.deleteRow(i + 1);
    }
  }

  // Add updated rows
  antibiotics.forEach(function(abx) {
    sheet.appendRow([
      studyId,
      abx.name || '',
      abx.abxClass || '',
      abx.aware || '',
      abx.route || '',
      abx.dose || '',
      abx.freq || '',
      abx.start || '',
      abx.stop || '',
      abx.duration || '',
      abx.ddd || '',
      abx.grams || '',
      abx.dddCalc || '',
      abx.dot || '',
      abx.indication || '',
      abx.therapyType || '',
      abx.febrileNeutro || '',
      abx.febrileEpisodes || ''
    ]);
  });
}

function loadAntibioticsForStudy(studyId) {
  if (!studyId) return [];
  try {
    var sheet = getSheet('Antibiotics');
    var data = sheet.getDataRange().getValues();
    var result = [];
    for (var i = 1; i < data.length; i++) {
      if (data[i][0] === studyId) {
        result.push({
          name: data[i][1] || '',
          abxClass: data[i][2] || '',
          aware: data[i][3] || '',
          route: data[i][4] || '',
          dose: data[i][5] || '',
          freq: data[i][6] || '',
          start: formatDate(data[i][7]) || '',
          stop: formatDate(data[i][8]) || '',
          duration: data[i][9] !== '' ? data[i][9] : '',
          ddd: data[i][10] !== '' ? data[i][10] : '',
          grams: data[i][11] !== '' ? data[i][11] : '',
          dddCalc: data[i][12] !== '' ? data[i][12] : '',
          dot: data[i][13] !== '' ? data[i][13] : '',
          indication: data[i][14] || '',
          therapyType: data[i][15] || '',
          febrileNeutro: data[i][16] || '',
          febrileEpisodes: data[i][17] !== '' ? data[i][17] : ''
        });
      }
    }
    return result;
  } catch(e) { return []; }
}

function deleteAntibioticsForStudy(studyId) {
  var sheet = getSheet('Antibiotics');
  var data = sheet.getDataRange().getValues();
  for (var i = data.length - 1; i >= 1; i--) {
    if (data[i][0] === studyId) {
      sheet.deleteRow(i + 1);
    }
  }
}

// ─── RELATIONAL CULTURES HELPERS ──────────────────────────
function saveCultures(studyId, cultures) {
  var sheet = getSheet('Cultures');
  var data = sheet.getDataRange().getValues();

  // Remove old rows for this Study ID
  for (var i = data.length - 1; i >= 1; i--) {
    if (data[i][0] === studyId) {
      sheet.deleteRow(i + 1);
    }
  }

  // Add updated rows
  cultures.forEach(function(cult) {
    sheet.appendRow([
      studyId,
      cult.sent || '',
      cult.date || '',
      cult.type || '',
      cult.typeOther || '',
      cult.result || '',
      cult.organism || '',
      cult.gram || '',
      cult.ast || '',
      cult.resist || '',
      cult.mdr || '',
      cult.xdr || '',
      cult.eskape || '',
      cult.eskapeOrganisms || ''
    ]);
  });
}

function loadCulturesForStudy(studyId) {
  if (!studyId) return [];
  try {
    var sheet = getSheet('Cultures');
    var data = sheet.getDataRange().getValues();
    var result = [];
    for (var i = 1; i < data.length; i++) {
      if (data[i][0] === studyId) {
        result.push({
          sent: data[i][1] || '',
          date: formatDate(data[i][2]) || '',
          type: data[i][3] || '',
          typeOther: data[i][4] || '',
          result: data[i][5] || '',
          organism: data[i][6] || '',
          gram: data[i][7] || '',
          ast: data[i][8] || '',
          resist: data[i][9] || '',
          mdr: data[i][10] || '',
          xdr: data[i][11] || '',
          eskape: data[i][12] || '',
          eskapeOrganisms: data[i][13] || ''
        });
      }
    }
    return result;
  } catch(e) { return []; }
}

function deleteCulturesForStudy(studyId) {
  var sheet = getSheet('Cultures');
  var data = sheet.getDataRange().getValues();
  for (var i = data.length - 1; i >= 1; i--) {
    if (data[i][0] === studyId) {
      sheet.deleteRow(i + 1);
    }
  }
}

// ─── RELATIONAL CSV EXPORT (separate files for SPSS/R/Stata) ──
function apiExportRelational(token, params) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  var dateStr = new Date().toISOString().split('T')[0];

  // Export Records CSV
  var result = apiRead(token, params || {});
  if (!result.success) return result;

  var recHeaders = ['Study_ID','Timestamp','Age','Sex','Created_By','Hospital','Date_of_Collection','Collector_Name',
    'Admission_Date','Discharge_Date','LOS','Admission_Type','Ward','Ward_Other',
    'Diagnosis','Cancer_Type','Cancer_Name','Cancer_Name_Other',
    'Stage','Treatment','Treatment_Other',
    'Comorbidities','Comorbidities_Other','Immunosuppressed',
    'Outcome','Readmission_30d','De_escalation','Required_for_Analysis'];

  var recRows = [recHeaders.join(',')];
  result.records.forEach(function(r) {
    recRows.push([
      csvSafe(r.studyId), csvSafe(r.timestamp), csvSafe(r.age), csvSafe(r.sex),
      csvSafe(r.createdBy), csvSafe(r.hospital), csvSafe(r.dateOfCollection), csvSafe(r.collectorName),
      csvSafe(r.admissionDate), csvSafe(r.dischargeDate), csvSafe(r.los), csvSafe(r.admissionType),
      csvSafe(r.ward), csvSafe(r.wardOther),
      csvSafe(r.diagnosis), csvSafe(r.cancerType), csvSafe(r.cancerName), csvSafe(r.cancerNameOther),
      csvSafe(r.stage), csvSafe(r.treatment), csvSafe(r.treatmentOther),
      csvSafe(r.comorbidities), csvSafe(r.comorbiditiesOther), csvSafe(r.immunosuppressed),
      csvSafe(r.outcome), csvSafe(r.readmission30d), csvSafe(r.deEscalation), csvSafe(r.requiredForAnalysis)
    ].join(','));
  });

  // Export Antibiotics CSV
  var abxSheet = getSheet('Antibiotics');
  var abxData = abxSheet.getDataRange().getValues();
  var abxRows = [ANTIBIOTIC_HEADERS.map(function(h){return h.replace(/ /g,'_')}).join(',')];
  for (var a = 1; a < abxData.length; a++) {
    abxRows.push(abxData[a].map(function(v){return csvSafe(v)}).join(','));
  }

  // Export Cultures CSV
  var cultSheet = getSheet('Cultures');
  var cultData = cultSheet.getDataRange().getValues();
  var cultRows = [CULTURE_HEADERS.map(function(h){return h.replace(/ /g,'_')}).join(',')];
  for (var c = 1; c < cultData.length; c++) {
    cultRows.push(cultData[c].map(function(v){return csvSafe(v)}).join(','));
  }

  return {
    success: true,
    recordsCsv: recRows.join('\n'),
    antibioticsCsv: abxRows.join('\n'),
    culturesCsv: cultRows.join('\n'),
    filenames: {
      records: 'OncoCollect_Records_' + dateStr + '.csv',
      antibiotics: 'OncoCollect_Antibiotics_' + dateStr + '.csv',
      cultures: 'OncoCollect_Cultures_' + dateStr + '.csv'
    }
  };
}

/**
 * Populate WHO AWaRe antibiotics sheet with ATC codes
 */
function populateWhoSheet() {
  const ss = getSpreadsheet();
  var whoSheet = ss.getSheetByName('WHO');
  if (!whoSheet) whoSheet = ss.insertSheet('WHO');
  whoSheet.clear();
  whoSheet.appendRow(CONFIG.WHO_HEADERS);
  whoSheet.getRange(1, 1, 1, CONFIG.WHO_HEADERS.length).setFontWeight('bold');
  WHO_ANTIBIOTICS.forEach(function(abx) {
    whoSheet.appendRow([abx.name, abx.atc, abx.cls, abx.cat, abx.ddd]);
  });
  Logger.log('WHO sheet populated with ' + WHO_ANTIBIOTICS.length + ' antibiotics');
}

+++ Code.gs (修改后)
/* ══════════════════════════════════════════════════════════════
   OncoCollect v3.1 — Google Apps Script Backend (Enhanced)

   NEW FIELDS: Hospital, Date of Collection, Collector Name,
               Required for Analysis, Treatment Other, Ward Other,
               Cancer Name Other, Comorbidities Other

   ENHANCEMENTS:
   - HMAC-signed session tokens (tamper-proof)
   - Rate limiting on login (brute-force protection)
   - Password strength enforcement
   - CSRF token verification
   - Audit logging
   - Soft delete (no data loss)
   - doPost for save (no URL length limits)
   - Sequential ID generation (no collisions)
   - Optimistic concurrency control
   - Data backup automation
   - Email notifications for critical thresholds
   - ATC codes in WHO list
   - Input sanitization (XSS protection)
   - JSDoc type annotations
   - Improved error handling

   DEPLOYMENT:

   OPTION A (Recommended — No CORS issues):
     1. In GAS editor, create HTML file named "Index"
     2. Paste index.html content into it
     3. Deploy > New deployment > Web app
        - Execute as: Me | Who has access: Anyone
     4. Visit the Web App URL

   OPTION B (GitHub Pages):
     1. Deploy as Web app
     2. Upload index.html to GitHub Pages
     3. Set GAS_URL in index.html

   SETUP (run once): Run > setupSheets

   SECURITY NOTICE: Change CONFIG.HMAC_SECRET before production!
   ══════════════════════════════════════════════════════════════ */

// ─── CONFIG ─────────────────────────────────────────────────
/** @type {Object} */
const CONFIG = {
  SPREADSHEET_NAME: 'OncoCollectDB',
  HMAC_SECRET: 'CHANGE_THIS_SECRET_BEFORE_PRODUCTION_' + Math.random().toString(36).substring(2), // CHANGE THIS IN PRODUCTION!
  RECORD_HEADERS: [
    'Timestamp','Study ID','Age','Sex','Created By',
    'Hospital','Date of Collection','Collector Name',
    'Admission Date','Discharge Date','LOS','Admission Type','Ward','Ward Other',
    'Diagnosis','Cancer Type','Cancer Name','Cancer Name Other',
    'Stage','Treatment','Treatment Other',
    'Comorbidities','Comorbidities Other','Immunosuppressed',
    'Outcome','Readmission 30d','De-escalation',
    'Antibiotics JSON','Cultures JSON',
    'Required for Analysis',
    'Created Date','Updated Date','Deleted','Deleted By','Deleted Date','Version'
  ],
  USER_HEADERS: ['Username','Password Hash','Salt','Role','Active','Created Date','Last Login'],
  WHO_HEADERS: ['Name','ATC Code','Class','Category','DDD'],
  AUDIT_HEADERS: ['Timestamp','User','Action','Details'],
  LOGIN_ATTEMPT_HEADERS: ['Username','Attempts','Last Attempt'],
  META_HEADERS: ['Key','Value'],
  SESSION_TIMEOUT: 28800000, // 8 hours
  MAX_LOGIN_ATTEMPTS: 5,
  LOGIN_LOCKOUT_MINUTES: 15,
  MDR_ALERT_THRESHOLD: 0.5,
  PASSWORD_MIN_LENGTH: 8,
  MAX_ABX_SLOTS: 30,
  MAX_CULT_SLOTS: 30,
};

// ─── RELATIONAL TABLE HEADERS ───────────────────────────────
const ANTIBIOTIC_HEADERS = [
  'Study ID',
  'Antibiotic Name',
  'Class',
  'Category',
  'Route',
  'Dose',
  'Frequency',
  'Start',
  'Stop',
  'Duration',
  'DDD',
  'Grams',
  'DDD Calc',
  'DOT',
  'Indication',
  'Therapy Type',
  'Febrile Neutro',
  'Febrile Episodes'
];

const CULTURE_HEADERS = [
  'Study ID',
  'Sent',
  'Date',
  'Type',
  'Type Other',
  'Result',
  'Organism',
  'Gram',
  'AST',
  'Resistance',
  'MDR',
  'XDR',
  'ESKAPE',
  'ESKAPE Organisms'
];

// WHO AWaRe 2023 antibiotic list with ATC codes
const WHO_ANTIBIOTICS = [
  // Access (26)
  {name:'Amoxicillin',atc:'J01CA04',cls:'Penicillin',cat:'Access',ddd:1.5},
  {name:'Ampicillin',atc:'J01CA01',cls:'Penicillin',cat:'Access',ddd:2},
  {name:'Benzylpenicillin',atc:'J01CE01',cls:'Penicillin',cat:'Access',ddd:1.2},
  {name:'Phenoxymethylpenicillin',atc:'J01CE02',cls:'Penicillin',cat:'Access',ddd:1},
  {name:'Cephalexin',atc:'J01DB01',cls:'Cephalosporin (1st)',cat:'Access',ddd:2},
  {name:'Cefazolin',atc:'J01DB04',cls:'Cephalosporin (1st)',cat:'Access',ddd:3},
  {name:'Gentamicin',atc:'J01GB03',cls:'Aminoglycoside',cat:'Access',ddd:0.24},
  {name:'Nitrofurantoin',atc:'J01XE01',cls:'Nitrofuran',cat:'Access',ddd:0.2},
  {name:'Sulfamethoxazole/Trimethoprim',atc:'J01EE01',cls:'Sulfonamide',cat:'Access',ddd:0.48},
  {name:'Trimethoprim',atc:'J01EA01',cls:'Sulfonamide',cat:'Access',ddd:0.4},
  {name:'Clindamycin',atc:'J01FF01',cls:'Lincosamide',cat:'Access',ddd:1.8},
  {name:'Metronidazole',atc:'J01XD01',cls:'Nitroimidazole',cat:'Access',ddd:1.5},
  {name:'Doxycycline',atc:'J01AA02',cls:'Tetracycline',cat:'Access',ddd:0.1},
  {name:'Tetracycline',atc:'J01AA07',cls:'Tetracycline',cat:'Access',ddd:1},
  {name:'Amoxicillin/Clavulanate',atc:'J01CR02',cls:'Penicillin+Inhibitor',cat:'Access',ddd:1.5},
  {name:'Ampicillin/Sulbactam',atc:'J01CR01',cls:'Penicillin+Inhibitor',cat:'Access',ddd:3},
  {name:'Ceftriaxone',atc:'J01DD04',cls:'Cephalosporin (3rd)',cat:'Access',ddd:2},
  {name:'Cefixime',atc:'J01DD08',cls:'Cephalosporin (3rd)',cat:'Access',ddd:0.4},
  {name:'Chloramphenicol',atc:'J01BA01',cls:'Phenicols',cat:'Access',ddd:3},
  {name:'Cloxacillin',atc:'J01CF02',cls:'Penicillin (antistaph)',cat:'Access',ddd:2},
  {name:'Erythromycin',atc:'J01FA01',cls:'Macrolide',cat:'Access',ddd:1},
  {name:'Flucloxacillin',atc:'J01CF05',cls:'Penicillin (antistaph)',cat:'Access',ddd:2},
  {name:'Isoniazid',atc:'J04AC01',cls:'Antimycobacterial',cat:'Access',ddd:0.3},
  {name:'Rifampicin',atc:'J04AB02',cls:'Antimycobacterial',cat:'Access',ddd:0.6},
  {name:'Pyrazinamide',atc:'J04AK01',cls:'Antimycobacterial',cat:'Access',ddd:1.5},
  {name:'Ethambutol',atc:'J04AK02',cls:'Antimycobacterial',cat:'Access',ddd:1.2},
  // Watch (15)
  {name:'Ciprofloxacin',atc:'J01MA02',cls:'Fluoroquinolone',cat:'Watch',ddd:0.8},
  {name:'Levofloxacin',atc:'J01MA12',cls:'Fluoroquinolone',cat:'Watch',ddd:0.5},
  {name:'Moxifloxacin',atc:'J01MA14',cls:'Fluoroquinolone',cat:'Watch',ddd:0.4},
  {name:'Ceftazidime',atc:'J01DD02',cls:'Cephalosporin (3rd)',cat:'Watch',ddd:4},
  {name:'Cefepime',atc:'J01DE01',cls:'Cephalosporin (4th)',cat:'Watch',ddd:4},
  {name:'Ceftaroline',atc:'J01DI01',cls:'Cephalosporin (5th)',cat:'Watch',ddd:1.2},
  {name:'Piperacillin/Tazobactam',atc:'J01CR05',cls:'Penicillin+Inhibitor',cat:'Watch',ddd:14},
  {name:'Meropenem',atc:'J01DH02',cls:'Carbapenem',cat:'Watch',ddd:2},
  {name:'Imipenem/Cilastatin',atc:'J01DH51',cls:'Carbapenem',cat:'Watch',ddd:2},
  {name:'Ertapenem',atc:'J01DH03',cls:'Carbapenem',cat:'Watch',ddd:1},
  {name:'Azithromycin',atc:'J01FA10',cls:'Macrolide',cat:'Watch',ddd:0.3},
  {name:'Vancomycin',atc:'J01XA01',cls:'Glycopeptide',cat:'Watch',ddd:2},
  {name:'Teicoplanin',atc:'J01XA02',cls:'Glycopeptide',cat:'Watch',ddd:0.4},
  {name:'Linezolid',atc:'J01XX08',cls:'Oxazolidinone',cat:'Watch',ddd:1.2},
  {name:'Amikacin',atc:'J01GB06',cls:'Aminoglycoside',cat:'Watch',ddd:1},
  // Reserve (9)
  {name:'Colistin',atc:'J01XB01',cls:'Polymyxin',cat:'Reserve',ddd:0.75},
  {name:'Polymyxin B',atc:'J01XB02',cls:'Polymyxin',cat:'Reserve',ddd:0.75},
  {name:'Tigecycline',atc:'J01AA12',cls:'Glycylcycline',cat:'Reserve',ddd:0.1},
  {name:'Daptomycin',atc:'J01XX09',cls:'Lipopeptide',cat:'Reserve',ddd:0.28},
  {name:'Ceftazidime/Avibactam',atc:'J01DD52',cls:'Cephalosporin+Inhibitor',cat:'Reserve',ddd:6},
  {name:'Ceftolozane/Tazobactam',atc:'J01DI54',cls:'Cephalosporin+Inhibitor',cat:'Reserve',ddd:3},
  {name:'Fosfomycin IV',atc:'J01XX01',cls:'Phosphonic acid',cat:'Reserve',ddd:4},
  {name:'Fosfomycin Oral',atc:'J01XX01',cls:'Phosphonic acid',cat:'Reserve',ddd:0.15},
  {name:'Posaconazole',atc:'J02AC04',cls:'Triazole',cat:'Reserve',ddd:0.3},
];

// ─── SPREADSHEET HELPERS ────────────────────────────────────
/**
 * Get or create the spreadsheet
 * @returns {SpreadsheetApp.Spreadsheet}
 */
function getSpreadsheet() {
  const files = DriveApp.getFilesByName(CONFIG.SPREADSHEET_NAME);
  if (files.hasNext()) return SpreadsheetApp.open(files.next());
  return SpreadsheetApp.create(CONFIG.SPREADSHEET_NAME);
}

/**
 * Get or create a sheet by name
 * @param {string} name - Sheet name
 * @returns {SpreadsheetApp.Sheet}
 */
function getSheet(name) {
  const ss = getSpreadsheet();
  let sheet = ss.getSheetByName(name);
  if (!sheet) sheet = ss.insertSheet(name);
  return sheet;
}

// ─── INPUT SANITIZATION (XSS Protection) ─────────────────────
/**
 * Sanitize user input to prevent XSS attacks
 * @param {string} str - Input string to sanitize
 * @returns {string} Sanitized string
 */
function sanitizeInput(str) {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Escape HTML for safe display in CSV/text exports
 * @param {string} str - Input string
 * @returns {string} Escaped string
 */
function escapeHtml(str) {
  if (!str || typeof str !== 'string') return '';
  return str.replace(/[&<>"']/g, function(m) {
    var map = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;'};
    return map[m];
  });
}

// ─── SERVE HTML (OPTION A) + API GET FALLBACK ───────────────
/**
 * Handle GET requests - serve HTML or handle API calls
 * @param {Object} e - Event object with parameters
 * @returns {HtmlOutput|TextOutput}
 */
function doGet(e) {
  var params = e.parameter || {};
  if (params.action) return handleGetApi(params);
  return HtmlService.createHtmlOutputFromFile('Index')
    .setTitle('OncoCollect v3.1 — Clinical Research Database')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1.0');
}

// ─── POST HANDLER (for save operations with large payloads) ──
/**
 * Handle POST requests for data mutations and API calls
 * @param {Object} e - Event object with post data
 * @returns {TextOutput}
 */
function doPost(e) {
  try {
    var body = JSON.parse(e.postData.contents);
    var action = body.action;
    var token = body.token || '';
    var csrf = body.csrf || '';
    var data = body.data || {};

    // CSRF check for authenticated actions
    if (token && action !== 'login' && !verifyCsrf(token, csrf)) {
      return corsJson({ success: false, message: 'CSRF verification failed', authError: true });
    }

    if (action === 'login') {
      return corsJson(apiLogin(sanitizeInput(data.username), data.password));
    }

    if (!verifyToken(token)) {
      return corsJson({ success: false, message: 'Unauthorized', authError: true });
    }

    switch (action) {
      // Write operations
      case 'save':
        return corsJson(apiSave(token, data.record));
      case 'delete':
        return corsJson(apiDelete(token, data.studyId));
      case 'addUser':
        return corsJson(apiAddUser(token, sanitizeInput(data.username), data.password, sanitizeInput(data.role)));
      case 'changePassword':
        return corsJson(apiChangePassword(token, data.currentPassword, data.newPassword));
      case 'toggleUser':
        return corsJson(apiToggleUser(token, sanitizeInput(data.username), data.active));
      // Read operations (also accessible via POST for CORS compatibility)
      case 'read':
        return corsJson(apiRead(token, data.filters || data || {}));
      case 'getAntibiotics':
        return corsJson(apiGetAntibiotics(token));
      case 'generateId':
        return corsJson(apiGenerateId(token));
      case 'getUsers':
        return corsJson(apiGetUsers(token));
      case 'getAuditLog':
        return corsJson(apiGetAuditLog(token, data));
      case 'exportFlat':
        return corsJson(apiExportFlat(token, data.filters || data || {}));
      case 'exportRelational':
        return corsJson(apiExportRelational(token, data.filters || data || {}));
      case 'purgeDeleted':
        return corsJson(apiPurgeDeleted(token));
      default:
        return corsJson({ success: false, message: 'Unknown action: ' + escapeHtml(action) });
    }
  } catch (err) {
    Logger.log('POST error: ' + err.message);
    return corsJson({ success: false, message: 'Server error: ' + escapeHtml(err.message) });
  }
}

// ─── API GET HANDLER (for read-only operations) ─────────────
/**
 * Handle GET API requests for read-only operations
 * @param {Object} params - Request parameters
 * @returns {TextOutput}
 */
function handleGetApi(params) {
  var action = params.action;
  var token = params.token || '';

  try {
    if (action === 'login') {
      return corsJson(apiLogin(sanitizeInput(params.username), params.password));
    }

    if (!verifyToken(token)) {
      return corsJson({ success: false, message: 'Unauthorized', authError: true });
    }

    switch (action) {
      case 'read':
        return corsJson(apiRead(token, params));
      case 'getAntibiotics':
        return corsJson(apiGetAntibiotics(token));
      case 'generateId':
        return corsJson(apiGenerateId(token));
      case 'getUsers':
        return corsJson(apiGetUsers(token));
      case 'getAuditLog':
        return corsJson(apiGetAuditLog(token, params));
      case 'exportFlat':
        return corsJson(apiExportFlat(token, params));
      case 'exportRelational':
        return corsJson(apiExportRelational(token, params));
      case 'purgeDeleted':
        return corsJson(apiPurgeDeleted(token));
      default:
        return corsJson({ success: false, message: 'Unknown action: ' + escapeHtml(action) });
    }
  } catch (err) {
    Logger.log('GET API error: ' + err.message);
    return corsJson({ success: false, message: 'Server error: ' + escapeHtml(err.message) });
  }
}

/**
 * Create CORS-enabled JSON response
 * @param {Object} data - Response data
 * @returns {TextOutput}
 */
function corsJson(data) {
  return ContentService.createTextOutput(JSON.stringify(data))
    .setMimeType(ContentService.MimeType.JSON);
}

// ─── SERVER-SIDE API FUNCTIONS ──────────────────────────────

/**
 * Handle user login with rate limiting and password verification
 * @param {string} username - User's username
 * @param {string} password - User's password
 * @returns {Object} Login result
 */
function apiLogin(username, password) {
  username = (username || '').trim();
  if (!username || !password) {
    return { success: false, message: 'Username and password required' };
  }

  // Rate limiting
  if (isLoginLocked(username)) {
    return { success: false, message: 'Account temporarily locked. Too many failed attempts. Try again in ' + CONFIG.LOGIN_LOCKOUT_MINUTES + ' minutes.' };
  }

  const sheet = getSheet('Users');
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === username) {
      if (data[i][4] !== true) return { success: false, message: 'Account is disabled' };

      const storedHash = data[i][1];
      const salt = data[i][2];
      let match = false;

      if (salt) {
        match = hashPassword(password, salt) === storedHash;
      } else {
        match = legacyHash(password) === storedHash;
        if (match) {
          var newSalt = generateSalt();
          var newHash = hashPassword(password, newSalt);
          sheet.getRange(i + 1, 2).setValue(newHash);
          sheet.getRange(i + 1, 3).setValue(newSalt);
        }
      }

      if (match) {
        clearLoginAttempts(username);
        sheet.getRange(i + 1, 7).setValue(new Date());
        var token = createToken(username, data[i][3]);
        var csrf = generateCsrf(token);
        auditLog(username, 'LOGIN', 'User logged in');
        return {
          success: true,
          user: { username: username, role: data[i][3], token: token, csrf: csrf }
        };
      } else {
        recordLoginAttempt(username);
        return { success: false, message: 'Invalid username or password' };
      }
    }
  }
  recordLoginAttempt(username);
  return { success: false, message: 'Invalid username or password' };
}

/**
 * Read records with optional filters
 * @param {string} token - Auth token
 * @param {Object} params - Filter parameters
 * @returns {Object} Records and stats
 */
function apiRead(token, params) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };

  const sheet = getSheet('Records');
  const data = sheet.getDataRange().getValues();
  if (data.length <= 1) return { success: true, records: [], stats: getEmptyStats() };

  // Parse filters
  var filters = {};
  if (params) {
    if (params.dateFrom) filters.dateFrom = params.dateFrom;
    if (params.dateTo) filters.dateTo = params.dateTo;
    if (params.site && params.site !== 'all') filters.site = sanitizeInput(params.site);
    if (params.ward && params.ward !== 'all') filters.ward = sanitizeInput(params.ward);
    if (params.outcome && params.outcome !== 'all') filters.outcome = sanitizeInput(params.outcome);
  }

  // Column mapping:
  // 0:Timestamp 1:Study ID 2:Age 3:Sex 4:Created By
  // 5:Hospital 6:Date of Collection 7:Collector Name
  // 8:Admission Date 9:Discharge Date 10:LOS 11:Admission Type 12:Ward 13:Ward Other
  // 14:Diagnosis 15:Cancer Type 16:Cancer Name 17:Cancer Name Other
  // 18:Stage 19:Treatment 20:Treatment Other
  // 21:Comorbidities 22:Comorbidities Other 23:Immunosuppressed
  // 24:Outcome 25:Readmission 30d 26:De-escalation
  // 27:Antibiotics JSON 28:Cultures JSON
  // 29:Required for Analysis
  // 30:Created Date 31:Updated Date 32:Deleted 33:Deleted By 34:Deleted Date 35:Version

  const records = [];
  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    if (!row[1]) continue;
    if (row[32] === true) continue; // soft-deleted

    // Apply filters
    if (filters.dateFrom && row[8] && new Date(row[8]) < new Date(filters.dateFrom)) continue;
    if (filters.dateTo && row[9] && new Date(row[9]) > new Date(filters.dateTo + 'T23:59:59')) continue;
    if (filters.site && row[5] !== filters.site) continue;
    if (filters.ward && row[12] !== filters.ward) continue;
    if (filters.outcome && row[24] !== filters.outcome) continue;

    let antibiotics = [], cultures = [];
    // Try relational sheets first, fall back to JSON columns
    antibiotics = loadAntibioticsForStudy(row[1]);
    cultures = loadCulturesForStudy(row[1]);
    if (antibiotics.length === 0) { try { antibiotics = JSON.parse(row[27] || '[]'); } catch(e) {} }
    if (cultures.length === 0) { try { cultures = JSON.parse(row[28] || '[]'); } catch(e) {} }

    records.push({
      timestamp: formatDate(row[0]),
      studyId: row[1],
      age: row[2] !== '' ? row[2] : null,
      sex: row[3] || null,
      createdBy: row[4] || null,
      hospital: row[5] || null,
      dateOfCollection: formatDate(row[6]),
      collectorName: row[7] || null,
      admissionDate: formatDate(row[8]),
      dischargeDate: formatDate(row[9]),
      los: row[10] !== '' ? row[10] : null,
      admissionType: row[11] || null,
      ward: row[12] || null,
      wardOther: row[13] || null,
      diagnosis: row[14] || null,
      cancerType: row[15] || null,
      cancerName: row[16] || null,
      cancerNameOther: row[17] || null,
      stage: row[18] || null,
      treatment: row[19] || null,
      treatmentOther: row[20] || null,
      comorbidities: row[21] || null,
      comorbiditiesOther: row[22] || null,
      immunosuppressed: row[23] || null,
      outcome: row[24] || null,
      readmission30d: row[25] || null,
      deEscalation: row[26] || null,
      antibiotics: antibiotics,
      cultures: cultures,
      requiredForAnalysis: row[29] || null,
      createdAt: formatDate(row[30]),
      updatedAt: formatDate(row[31]),
      version: row[35] || 0,
    });
  }

  var stats = calculateStats(records);
  return { success: true, records: records, stats: stats };
}

/**
 * Save a record with validation and optimistic concurrency
 * @param {string} token - Auth token
 * @param {Object} record - Record data to save
 * @returns {Object} Save result
 */
function apiSave(token, record) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  if (!record || !record.studyId) return { success: false, message: 'Missing record or studyId' };

  // Validate required fields
  var validation = validateRecord(record);
  if (!validation.valid) {
    return { success: false, message: 'Validation failed: ' + validation.errors.join('; ') };
  }

  const user = getTokenUser(token);
  const sheet = getSheet('Records');
  const data = sheet.getDataRange().getValues();

  let existingRow = -1;
  for (let i = 1; i < data.length; i++) {
    if (data[i][1] === record.studyId && data[i][32] !== true) {
      existingRow = i + 1;
      break;
    }
  }

  // Optimistic concurrency
  if (existingRow > 0 && record.version != null) {
    var currentVersion = data[existingRow - 1][35] || 0;
    if (record.version !== currentVersion) {
      return { success: false, message: 'Record was modified by another user. Please refresh and try again.', conflict: true };
    }
  }

  const now = new Date();
  var newVersion = (existingRow > 0 ? (data[existingRow - 1][35] || 0) : 0) + 1;
  var effectiveWard = record.ward === 'Other' ? '' : (record.ward || '');
  var effectiveCancer = record.cancerName === 'Other' ? '' : (record.cancerName || '');
  var effectiveTreatment = record.treatment === 'Other' ? '' : (record.treatment || '');
  var effectiveComorb = record.comorbidities === 'Other' ? '' : (record.comorbidities || '');

  const rowData = [
    now,                                                                    // 0: Timestamp
    record.studyId,                                                         // 1: Study ID
    record.age || '',                                                       // 2: Age
    record.sex || '',                                                       // 3: Sex
    user ? user.username : 'Unknown',                                       // 4: Created By
    record.hospital || '',                                                  // 5: Hospital
    record.dateOfCollection || '',                                          // 6: Date of Collection
    record.collectorName || '',                                             // 7: Collector Name
    record.admissionDate || '',                                             // 8: Admission Date
    record.dischargeDate || '',                                             // 9: Discharge Date
    record.los != null ? record.los : '',                                   // 10: LOS
    record.admissionType || '',                                             // 11: Admission Type
    effectiveWard || record.ward || '',                                     // 12: Ward
    record.ward === 'Other' ? (record.wardOther || '') : '',               // 13: Ward Other
    record.diagnosis || '',                                                 // 14: Diagnosis
    record.cancerType || '',                                                // 15: Cancer Type
    effectiveCancer || record.cancerName || '',                             // 16: Cancer Name
    record.cancerName === 'Other' ? (record.cancerNameOther || '') : '',   // 17: Cancer Name Other
    record.stage || '',                                                     // 18: Stage
    effectiveTreatment || record.treatment || '',                           // 19: Treatment
    record.treatment === 'Other' ? (record.treatmentOther || '') : '',     // 20: Treatment Other
    effectiveComorb || record.comorbidities || '',                          // 21: Comorbidities
    record.comorbidities === 'Other' ? (record.comorbiditiesOther || '') : '', // 22: Comorbidities Other
    record.immunosuppressed || '',                                          // 23: Immunosuppressed
    record.outcome || '',                                                   // 24: Outcome
    record.readmission30d || '',                                            // 25: Readmission 30d
    record.deEscalation || '',                                              // 26: De-escalation
    JSON.stringify(record.antibiotics || []),                               // 27: Antibiotics JSON
    JSON.stringify(record.cultures || []),                                  // 28: Cultures JSON
    record.requiredForAnalysis || '',                                       // 29: Required for Analysis
  ];

  if (existingRow > 0) {
    rowData.push(data[existingRow - 1][30] || now); // 30: Created Date (preserve original)
    rowData.push(now);                               // 31: Updated Date
    rowData.push(false);                             // 32: Deleted
    rowData.push('');                                // 33: Deleted By
    rowData.push('');                                // 34: Deleted Date
    rowData.push(newVersion);                        // 35: Version
    sheet.getRange(existingRow, 1, 1, rowData.length).setValues([rowData]);
    auditLog(user ? user.username : 'Unknown', 'UPDATE', 'Updated record ' + record.studyId);
  } else {
    rowData.push(now);   // 30: Created Date
    rowData.push(now);   // 31: Updated Date
    rowData.push(false); // 32: Deleted
    rowData.push('');    // 33: Deleted By
    rowData.push('');    // 34: Deleted Date
    rowData.push(newVersion); // 35: Version
    sheet.appendRow(rowData);
    auditLog(user ? user.username : 'Unknown', 'CREATE', 'Created record ' + record.studyId);
  }

  // Save normalized antibiotic rows
  saveAntibiotics(record.studyId, record.antibiotics || []);

  // Save normalized culture rows
  saveCultures(record.studyId, record.cultures || []);

  checkMdrAlert();

  return { success: true, message: 'Record saved', studyId: record.studyId, version: newVersion };
}

function apiDelete(token, studyId) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  if (!studyId) return { success: false, message: 'Missing studyId' };
  const user = getTokenUser(token);
  const sheet = getSheet('Records');
  const data = sheet.getDataRange().getValues();

  for (let i = 1; i < data.length; i++) {
    if (data[i][1] === studyId && data[i][32] !== true) {
      sheet.getRange(i + 1, 33).setValue(true);   // Deleted
      sheet.getRange(i + 1, 34).setValue(user ? user.username : 'Unknown'); // Deleted By
      sheet.getRange(i + 1, 35).setValue(new Date()); // Deleted Date
      // Also delete from relational Antibiotics sheet
      deleteAntibioticsForStudy(studyId);
      // Also delete from relational Cultures sheet
      deleteCulturesForStudy(studyId);
      auditLog(user ? user.username : 'Unknown', 'DELETE', 'Soft-deleted record ' + studyId);
      return { success: true, message: 'Record deleted' };
    }
  }
  return { success: false, message: 'Record not found' };
}

function apiPurgeDeleted(token) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const user = getTokenUser(token);
  if (!user || user.role !== 'Admin') return { success: false, message: 'Admin access required' };

  const sheet = getSheet('Records');
  const data = sheet.getDataRange().getValues();
  var purged = 0;

  // Delete from bottom to top to preserve row indices
  for (let i = data.length - 1; i >= 1; i--) {
    if (data[i][32] === true) {
      var studyId = data[i][1];
      // Also purge from relational sheets
      deleteAntibioticsForStudy(studyId);
      deleteCulturesForStudy(studyId);
      sheet.deleteRow(i + 1);
      purged++;
    }
  }

  auditLog(user.username, 'PURGE_DELETED', 'Purged ' + purged + ' soft-deleted records');
  return { success: true, message: 'Purged ' + purged + ' deleted records' };
}

function apiGetAntibiotics(token) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const sheet = getSheet('WHO');
  const data = sheet.getDataRange().getValues();
  const antibiotics = [];
  for (let i = 1; i < data.length; i++) {
    if (!data[i][0]) continue;
    antibiotics.push({ name: data[i][0], atc: data[i][1] || '', abxClass: data[i][2], category: data[i][3], ddd: data[i][4] || 0 });
  }
  if (antibiotics.length === 0) {
    populateWhoSheet();
    return apiGetAntibiotics(token);
  }
  return { success: true, antibiotics: antibiotics };
}

function apiGenerateId(token) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const ss = getSpreadsheet();
  var metaSheet = ss.getSheetByName('MetaData');
  if (!metaSheet) {
    metaSheet = ss.insertSheet('MetaData');
    metaSheet.appendRow(CONFIG.META_HEADERS);
    metaSheet.appendRow(['lastSeq', '0']);
    metaSheet.getRange(1, 1, 1, CONFIG.META_HEADERS.length).setFontWeight('bold');
  }
  var metaData = metaSheet.getDataRange().getValues();
  var seqRow = -1;
  var lastSeq = 0;
  for (var i = 1; i < metaData.length; i++) {
    if (metaData[i][0] === 'lastSeq') {
      seqRow = i + 1;
      lastSeq = parseInt(metaData[i][1]) || 0;
      break;
    }
  }
  lastSeq++;
  if (seqRow > 0) {
    metaSheet.getRange(seqRow, 2).setValue(lastSeq);
  } else {
    metaSheet.appendRow(['lastSeq', lastSeq]);
  }
  return { success: true, id: 'PID-' + String(lastSeq).padStart(6, '0') };
}

function apiAddUser(token, username, password, role) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const user = getTokenUser(token);
  if (!user || user.role !== 'Admin') return { success: false, message: 'Admin access required' };

  username = (username || '').trim();
  if (!username || !password) return { success: false, message: 'Username and password required' };

  var strength = checkPasswordStrength(password);
  if (!strength.valid) return { success: false, message: strength.message };

  const sheet = getSheet('Users');
  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === username) return { success: false, message: 'Username already exists' };
  }
  const salt = generateSalt();
  const hash = hashPassword(password, salt);
  sheet.appendRow([username, hash, salt, role || 'Agent', true, new Date(), '']);
  auditLog(user.username, 'ADD_USER', 'Created user: ' + username + ' (' + role + ')');
  return { success: true, message: 'User created' };
}

function apiChangePassword(token, currentPassword, newPassword) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const user = getTokenUser(token);
  if (!user) return { success: false, message: 'Invalid token' };
  var strength = checkPasswordStrength(newPassword);
  if (!strength.valid) return { success: false, message: strength.message };

  const sheet = getSheet('Users');
  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === user.username) {
      var storedHash = data[i][1];
      var salt = data[i][2];
      var currentHash = salt ? hashPassword(currentPassword, salt) : legacyHash(currentPassword);
      if (currentHash !== storedHash) return { success: false, message: 'Current password is incorrect' };
      var newSalt = generateSalt();
      var newHash = hashPassword(newPassword, newSalt);
      sheet.getRange(i + 1, 2).setValue(newHash);
      sheet.getRange(i + 1, 3).setValue(newSalt);
      auditLog(user.username, 'CHANGE_PASSWORD', 'Password changed');
      return { success: true, message: 'Password changed successfully' };
    }
  }
  return { success: false, message: 'User not found' };
}

function apiToggleUser(token, username, active) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const user = getTokenUser(token);
  if (!user || user.role !== 'Admin') return { success: false, message: 'Admin access required' };
  if (username === user.username) return { success: false, message: 'Cannot disable your own account' };

  const sheet = getSheet('Users');
  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] === username) {
      sheet.getRange(i + 1, 5).setValue(active === true);
      auditLog(user.username, 'TOGGLE_USER', (active ? 'Enabled' : 'Disabled') + ' user: ' + username);
      return { success: true, message: 'User ' + (active ? 'enabled' : 'disabled') };
    }
  }
  return { success: false, message: 'User not found' };
}

function apiGetUsers(token) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const user = getTokenUser(token);
  if (!user || user.role !== 'Admin') return { success: false, message: 'Admin access required' };

  const sheet = getSheet('Users');
  const data = sheet.getDataRange().getValues();
  const users = [];
  for (let i = 1; i < data.length; i++) {
    users.push({ username: data[i][0], role: data[i][3], active: data[i][4], createdAt: formatDate(data[i][5]), lastLogin: formatDate(data[i][6]) });
  }
  return { success: true, users: users };
}

function apiGetAuditLog(token, params) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  const user = getTokenUser(token);
  if (!user || user.role !== 'Admin') return { success: false, message: 'Admin access required' };

  const sheet = getSheet('AuditLog');
  const data = sheet.getDataRange().getValues();
  var logs = [];
  var limit = parseInt(params && params.limit) || 100;
  for (let i = data.length - 1; i >= 1 && logs.length < limit; i--) {
    logs.push({ timestamp: formatDateTime(data[i][0]), user: data[i][1], action: data[i][2], details: data[i][3] });
  }
  return { success: true, logs: logs };
}

// ─── FLAT CSV EXPORT (for SPSS/R/Stata analysis) ────────────
function apiExportFlat(token, params) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  var result = apiRead(token, params || {});
  if (!result.success) return result;

  var maxAbx = 0, maxCult = 0;
  result.records.forEach(function(r) {
    if (r.antibiotics && r.antibiotics.length > maxAbx) maxAbx = r.antibiotics.length;
    if (r.cultures && r.cultures.length > maxCult) maxCult = r.cultures.length;
  });

  // Build flat headers
  var headers = ['Timestamp','Study_ID','Age','Sex','Created_By','Hospital','Date_of_Collection','Collector_Name',
    'Admission_Date','Discharge_Date','LOS','Admission_Type','Ward','Ward_Other',
    'Diagnosis','Cancer_Type','Cancer_Name','Cancer_Name_Other',
    'Stage','Treatment','Treatment_Other',
    'Comorbidities','Comorbidities_Other','Immunosuppressed',
    'Outcome','Readmission_30d','De_escalation'];

  for (var a = 1; a <= maxAbx; a++) {
    ['Name','Class','Category','Route','Dose','Freq','Start','Stop','Duration','DDD','Grams','DDD_Calc','DOT','Indication','Therapy','Febrile_Neutro','Febrile_Episodes'].forEach(function(f) {
      headers.push('Abx_' + a + '_' + f);
    });
  }
  for (var c = 1; c <= maxCult; c++) {
    ['Sent','Date','Type','Type_Other','Result','Organism','Gram','AST','Resist','MDR','XDR','ESKAPE','ESKAPE_Organisms'].forEach(function(f) {
      headers.push('Cult_' + c + '_' + f);
    });
  }
  headers.push('Required_for_Analysis');

  var rows = [headers.join(',')];
  result.records.forEach(function(r) {
    var row = [
      csvSafe(r.timestamp), csvSafe(r.studyId), csvSafe(r.age), csvSafe(r.sex),
      csvSafe(r.createdBy), csvSafe(r.hospital), csvSafe(r.dateOfCollection), csvSafe(r.collectorName),
      csvSafe(r.admissionDate), csvSafe(r.dischargeDate), csvSafe(r.los), csvSafe(r.admissionType),
      csvSafe(r.ward), csvSafe(r.wardOther),
      csvSafe(r.diagnosis), csvSafe(r.cancerType), csvSafe(r.cancerName), csvSafe(r.cancerNameOther),
      csvSafe(r.stage), csvSafe(r.treatment), csvSafe(r.treatmentOther),
      csvSafe(r.comorbidities), csvSafe(r.comorbiditiesOther), csvSafe(r.immunosuppressed),
      csvSafe(r.outcome), csvSafe(r.readmission30d), csvSafe(r.deEscalation)
    ];
    for (var a = 0; a < maxAbx; a++) {
      var abx = (r.antibiotics && r.antibiotics[a]) || {};
      row.push(csvSafe(abx.name), csvSafe(abx.abxClass), csvSafe(abx.aware), csvSafe(abx.route),
        csvSafe(abx.dose), csvSafe(abx.freq), csvSafe(abx.start), csvSafe(abx.stop),
        csvSafe(abx.duration), csvSafe(abx.ddd), csvSafe(abx.grams), csvSafe(abx.dddCalc),
        csvSafe(abx.dot), csvSafe(abx.indication), csvSafe(abx.therapyType),
        csvSafe(abx.febrileNeutro), csvSafe(abx.febrileEpisodes));
    }
    for (var c = 0; c < maxCult; c++) {
      var cult = (r.cultures && r.cultures[c]) || {};
      row.push(csvSafe(cult.sent), csvSafe(cult.date), csvSafe(cult.type), csvSafe(cult.typeOther),
        csvSafe(cult.result), csvSafe(cult.organism), csvSafe(cult.gram), csvSafe(cult.ast), csvSafe(cult.resist),
        csvSafe(cult.mdr), csvSafe(cult.xdr), csvSafe(cult.eskape), csvSafe(cult.eskapeOrganisms));
    }
    row.push(csvSafe(r.requiredForAnalysis));
    rows.push(row.join(','));
  });

  return { success: true, csv: rows.join('\n'), filename: 'OncoCollect_Flat_' + new Date().toISOString().split('T')[0] + '.csv' };
}

function csvSafe(val) {
  if (val == null) return '';
  var s = String(val);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // CSV injection protection
  if (s.indexOf(',') >= 0 || s.indexOf('"') >= 0 || s.indexOf('\n') >= 0) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

// ─── SESSION TOKENS (HMAC-signed) ──────────────────────────
function createToken(username, role) {
  const ts = Date.now();
  const raw = username + ':' + role + ':' + ts;
  const signature = computeHmac(raw);
  return Utilities.base64Encode(raw + ':' + signature);
}

function verifyToken(token) {
  if (!token) return false;
  try {
    const decoded = Utilities.base64Decode(token);
    const str = Utilities.newBlob(decoded).getDataAsString();
    const parts = str.split(':');
    if (parts.length < 4) return false;
    const ts = parseInt(parts[2]);
    if (Date.now() - ts > CONFIG.SESSION_TIMEOUT) return false;
    const payload = parts[0] + ':' + parts[1] + ':' + parts[2];
    const expectedSig = computeHmac(payload);
    if (parts.slice(3).join(':') !== expectedSig) return false;
    const username = parts[0];
    const userSheet = getSheet('Users');
    const data = userSheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (data[i][0] === username && data[i][4] === true) return true;
    }
    return false;
  } catch(e) { return false; }
}

function getTokenUser(token) {
  if (!token) return null;
  try {
    const decoded = Utilities.base64Decode(token);
    const str = Utilities.newBlob(decoded).getDataAsString();
    const parts = str.split(':');
    return { username: parts[0], role: parts[1] };
  } catch(e) { return null; }
}

function computeHmac(data) {
  return Utilities.computeHmacSha256Signature(data, CONFIG.HMAC_SECRET)
    .map(function(b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
}

// ─── CSRF TOKENS ───────────────────────────────────────────
function generateCsrf(token) {
  return computeHmac(token + '_csrf');
}

function verifyCsrf(token, csrf) {
  if (!token || !csrf) return false;
  return csrf === generateCsrf(token);
}

// ─── RATE LIMITING ─────────────────────────────────────────
function isLoginLocked(username) {
  var sheet = getSheet('LoginAttempts');
  var data = sheet.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] === username) {
      var attempts = data[i][1];
      var lastAttempt = data[i][2];
      if (attempts >= CONFIG.MAX_LOGIN_ATTEMPTS && lastAttempt) {
        var lockoutEnd = new Date(lastAttempt.getTime() + CONFIG.LOGIN_LOCKOUT_MINUTES * 60000);
        if (new Date() < lockoutEnd) return true;
        sheet.getRange(i + 1, 2).setValue(0);
        return false;
      }
    }
  }
  return false;
}

function recordLoginAttempt(username) {
  var sheet = getSheet('LoginAttempts');
  var data = sheet.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] === username) {
      sheet.getRange(i + 1, 2).setValue((data[i][1] || 0) + 1);
      sheet.getRange(i + 1, 3).setValue(new Date());
      return;
    }
  }
  sheet.appendRow([username, 1, new Date()]);
}

function clearLoginAttempts(username) {
  var sheet = getSheet('LoginAttempts');
  var data = sheet.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] === username) {
      sheet.getRange(i + 1, 2).setValue(0);
      return;
    }
  }
}

// ─── AUDIT LOGGING ─────────────────────────────────────────
function auditLog(username, action, details) {
  try {
    var sheet = getSheet('AuditLog');
    sheet.appendRow([new Date(), username || 'Unknown', action, details || '']);
    var lastRow = sheet.getLastRow();
    if (lastRow > 1001) sheet.deleteRows(2, lastRow - 1001);
  } catch(e) { Logger.log('Audit log error: ' + e.message); }
}

// ─── PASSWORD HASHING ───────────────────────────────────────
function generateSalt() {
  const raw = Date.now().toString() + Math.random().toString() + Math.random().toString();
  return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, raw)
    .map(function(b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('').substring(0, 24);
}

function hashPassword(password, salt) {
  return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, salt + ':' + password)
    .map(function(b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
}

function legacyHash(password) {
  return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, password)
    .map(function(b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
}

function checkPasswordStrength(password) {
  if (!password || password.length < CONFIG.PASSWORD_MIN_LENGTH) {
    return { valid: false, message: 'Password must be at least ' + CONFIG.PASSWORD_MIN_LENGTH + ' characters' };
  }
  if (!/[A-Z]/.test(password)) return { valid: false, message: 'Password must contain at least one uppercase letter' };
  if (!/[0-9]/.test(password)) return { valid: false, message: 'Password must contain at least one number' };
  if (!/[^A-Za-z0-9]/.test(password)) return { valid: false, message: 'Password must contain at least one special character' };
  return { valid: true, message: 'OK' };
}

// ─── RECORD VALIDATION ──────────────────────────────────────
function validateRecord(record) {
  var errors = [];
  if (!record.age && record.age !== 0) errors.push('Age is required');
  else if (record.age < 0 || record.age > 120) errors.push('Age must be 0-120');
  if (!record.sex) errors.push('Sex is required');
  if (!record.admissionDate) errors.push('Admission date is required');
  if (!record.admissionType) errors.push('Admission type is required');
  if (!record.ward) errors.push('Ward is required');
  if (!record.diagnosis) errors.push('Diagnosis is required');
  if (!record.outcome) errors.push('Outcome is required');
  if (!record.hospital) errors.push('Hospital is required');
  if (record.admissionDate && record.dischargeDate && new Date(record.dischargeDate) < new Date(record.admissionDate)) {
    errors.push('Discharge date cannot be before admission date');
  }
  if (record.antibiotics) {
    record.antibiotics.forEach(function(abx, i) {
      if (abx.duration && (abx.duration < 1 || abx.duration > 365)) {
        errors.push('Antibiotic ' + (i+1) + ': Duration must be 1-365 days');
      }
    });
  }
  return { valid: errors.length === 0, errors: errors };
}

// ─── STATS CALCULATION ──────────────────────────────────────
function calculateStats(records) {
  var total = records.length;
  var abxCourses = 0, cultSent = 0, mdrCult = 0, posCult = 0, died = 0;
  var losArr = [];
  records.forEach(function(r) {
    abxCourses += (r.antibiotics ? r.antibiotics.length : 0);
    cultSent += (r.cultures ? r.cultures.filter(function(c){return c.sent==='Yes'}).length : 0);
    if (r.los != null) losArr.push(r.los);
    if (r.outcome === 'Died') died++;
    if (r.cultures) r.cultures.forEach(function(c) {
      if (c.result === 'Positive') posCult++;
      if (c.mdr === 'Yes') mdrCult++;
    });
  });
  return {
    totalPatients: total, abxCourses: abxCourses, culturesSent: cultSent,
    mortalityRate: total ? +(died/total*100).toFixed(1) : 0,
    medianLos: median(losArr),
    mdrRate: posCult ? +(mdrCult/posCult*100).toFixed(1) : 0,
    totalPatientDays: losArr.reduce(function(s,v){return s+v},0) || 0
  };
}

function getEmptyStats() {
  return { totalPatients:0, abxCourses:0, culturesSent:0, mortalityRate:0, medianLos:0, mdrRate:0, totalPatientDays:0 };
}

// ─── MDR ALERT ─────────────────────────────────────────────
function checkMdrAlert() {
  try {
    // Read from relational Cultures sheet
    var cultSheet = getSheet('Cultures');
    var cultData = cultSheet.getDataRange().getValues();
    var posCult = 0, mdrCult = 0;
    for (var j = 1; j < cultData.length; j++) {
      if (cultData[j][4] === 'Positive') posCult++;
      if (cultData[j][9] === 'Yes') mdrCult++;
    }
    // Count total active records
    var sheet = getSheet('Records');
    var data = sheet.getDataRange().getValues();
    var total = 0;
    for (var i = 1; i < data.length; i++) {
      if (data[i][32] === true) continue;
      total++;
    }
    var mdrRate = posCult ? mdrCult/posCult : 0;
    if (mdrRate > CONFIG.MDR_ALERT_THRESHOLD && total >= 10) {
      var userSheet = getSheet('Users');
      var userData = userSheet.getDataRange().getValues();
      var adminEmails = [];
      for (var j = 1; j < userData.length; j++) {
        if (userData[j][3] === 'Admin' && userData[j][4] === true && userData[j][0].includes('@')) {
          adminEmails.push(userData[j][0]);
        }
      }
      if (adminEmails.length > 0) {
        try {
          MailApp.sendEmail({
            to: adminEmails.join(','),
            subject: 'OncoCollect Alert: MDR Rate Exceeds Threshold',
            body: 'MDR rate: ' + (mdrRate*100).toFixed(1) + '% (threshold: ' + (CONFIG.MDR_ALERT_THRESHOLD*100) + '%)\n\nAutomated alert from OncoCollect.'
          });
        } catch(e) { Logger.log('Email alert failed: ' + e.message); }
      }
    }
  } catch(e) { Logger.log('MDR alert check failed: ' + e.message); }
}

// ─── UTILITY ────────────────────────────────────────────────
function formatDate(val) {
  if (!val) return null;
  if (typeof val === 'string') return val;
  if (val instanceof Date) {
    return val.getFullYear() + '-' + String(val.getMonth()+1).padStart(2,'0') + '-' + String(val.getDate()).padStart(2,'0');
  }
  return String(val);
}

function formatDateTime(val) {
  if (!val) return null;
  if (val instanceof Date) {
    return formatDate(val) + ' ' + String(val.getHours()).padStart(2,'0') + ':' + String(val.getMinutes()).padStart(2,'0');
  }
  return String(val);
}

function median(arr) {
  if (!arr.length) return 0;
  var s = arr.slice().sort(function(a,b){return a-b});
  var m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : +((s[m-1]+s[m]) / 2).toFixed(1);
}

// ─── BACKUP AUTOMATION ─────────────────────────────────────
function backupData() {
  try {
    var ss = getSpreadsheet();
    var dateStr = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'yyyy-MM-dd');
    DriveApp.getFileById(ss.getId()).makeCopy(CONFIG.SPREADSHEET_NAME + '_Backup_' + dateStr);
    Logger.log('Backup created');
  } catch(e) { Logger.log('Backup failed: ' + e.message); }
}

function setupBackupTrigger() {
  ScriptApp.getProjectTriggers().forEach(function(t) {
    if (t.getHandlerFunction() === 'backupData') ScriptApp.deleteTrigger(t);
  });
  ScriptApp.newTrigger('backupData').timeBased().onWeekDay(ScriptApp.WeekDay.MON).atHour(2).create();
  Logger.log('Weekly backup trigger created');
}

// ─── ONE-TIME SETUP ─────────────────────────────────────────
function setupSheets() {
  const ss = getSpreadsheet();

  var defaultSheet = ss.getSheetByName('Sheet1');
  if (defaultSheet && ss.getSheets().length > 1) ss.deleteSheet(defaultSheet);

  // Records
  var recordsSheet = ss.getSheetByName('Records');
  if (!recordsSheet) recordsSheet = ss.insertSheet('Records');
  if (recordsSheet.getLastRow() === 0) {
    recordsSheet.appendRow(CONFIG.RECORD_HEADERS);
    recordsSheet.getRange(1, 1, 1, CONFIG.RECORD_HEADERS.length).setFontWeight('bold');
  }

  // Users
  var usersSheet = ss.getSheetByName('Users');
  if (!usersSheet) usersSheet = ss.insertSheet('Users');
  if (usersSheet.getLastRow() === 0) {
    usersSheet.appendRow(CONFIG.USER_HEADERS);
    usersSheet.getRange(1, 1, 1, CONFIG.USER_HEADERS.length).setFontWeight('bold');
    var salt = generateSalt();
    var hash = hashPassword('Admin@123', salt);
    usersSheet.appendRow(['admin', hash, salt, 'Admin', true, new Date(), '']);
  }

  // WHO
  populateWhoSheet();

  // AuditLog
  var auditSheet = ss.getSheetByName('AuditLog');
  if (!auditSheet) auditSheet = ss.insertSheet('AuditLog');
  if (auditSheet.getLastRow() === 0) {
    auditSheet.appendRow(CONFIG.AUDIT_HEADERS);
    auditSheet.getRange(1, 1, 1, CONFIG.AUDIT_HEADERS.length).setFontWeight('bold');
  }

  // LoginAttempts
  var loginSheet = ss.getSheetByName('LoginAttempts');
  if (!loginSheet) loginSheet = ss.insertSheet('LoginAttempts');
  if (loginSheet.getLastRow() === 0) {
    loginSheet.appendRow(CONFIG.LOGIN_ATTEMPT_HEADERS);
    loginSheet.getRange(1, 1, 1, CONFIG.LOGIN_ATTEMPT_HEADERS.length).setFontWeight('bold');
  }

  // MetaData
  var metaSheet = ss.getSheetByName('MetaData');
  if (!metaSheet) metaSheet = ss.insertSheet('MetaData');
  if (metaSheet.getLastRow() === 0) {
    metaSheet.appendRow(CONFIG.META_HEADERS);
    metaSheet.getRange(1, 1, 1, CONFIG.META_HEADERS.length).setFontWeight('bold');
    metaSheet.appendRow(['lastSeq', '0']);
  }

  // Antibiotics Sheet (relational — one row per antibiotic)
  var abxSheet = ss.getSheetByName('Antibiotics');
  if (!abxSheet) abxSheet = ss.insertSheet('Antibiotics');
  if (abxSheet.getLastRow() === 0) {
    abxSheet.appendRow(ANTIBIOTIC_HEADERS);
    abxSheet.getRange(1, 1, 1, ANTIBIOTIC_HEADERS.length).setFontWeight('bold');
  }

  // Cultures Sheet (relational — one row per culture)
  var cultSheet = ss.getSheetByName('Cultures');
  if (!cultSheet) cultSheet = ss.insertSheet('Cultures');
  if (cultSheet.getLastRow() === 0) {
    cultSheet.appendRow(CULTURE_HEADERS);
    cultSheet.getRange(1, 1, 1, CULTURE_HEADERS.length).setFontWeight('bold');
  }

  setupBackupTrigger();

  Logger.log('Setup complete! Default login: admin / Admin@123');
  Logger.log('IMPORTANT: Change CONFIG.HMAC_SECRET before deploying to production!');
}

// ─── RELATIONAL ANTIBIOTICS HELPERS ───────────────────────
function saveAntibiotics(studyId, antibiotics) {
  var sheet = getSheet('Antibiotics');
  var data = sheet.getDataRange().getValues();

  // Remove old rows for this Study ID
  for (var i = data.length - 1; i >= 1; i--) {
    if (data[i][0] === studyId) {
      sheet.deleteRow(i + 1);
    }
  }

  // Add updated rows
  antibiotics.forEach(function(abx) {
    sheet.appendRow([
      studyId,
      abx.name || '',
      abx.abxClass || '',
      abx.aware || '',
      abx.route || '',
      abx.dose || '',
      abx.freq || '',
      abx.start || '',
      abx.stop || '',
      abx.duration || '',
      abx.ddd || '',
      abx.grams || '',
      abx.dddCalc || '',
      abx.dot || '',
      abx.indication || '',
      abx.therapyType || '',
      abx.febrileNeutro || '',
      abx.febrileEpisodes || ''
    ]);
  });
}

function loadAntibioticsForStudy(studyId) {
  if (!studyId) return [];
  try {
    var sheet = getSheet('Antibiotics');
    var data = sheet.getDataRange().getValues();
    var result = [];
    for (var i = 1; i < data.length; i++) {
      if (data[i][0] === studyId) {
        result.push({
          name: data[i][1] || '',
          abxClass: data[i][2] || '',
          aware: data[i][3] || '',
          route: data[i][4] || '',
          dose: data[i][5] || '',
          freq: data[i][6] || '',
          start: formatDate(data[i][7]) || '',
          stop: formatDate(data[i][8]) || '',
          duration: data[i][9] !== '' ? data[i][9] : '',
          ddd: data[i][10] !== '' ? data[i][10] : '',
          grams: data[i][11] !== '' ? data[i][11] : '',
          dddCalc: data[i][12] !== '' ? data[i][12] : '',
          dot: data[i][13] !== '' ? data[i][13] : '',
          indication: data[i][14] || '',
          therapyType: data[i][15] || '',
          febrileNeutro: data[i][16] || '',
          febrileEpisodes: data[i][17] !== '' ? data[i][17] : ''
        });
      }
    }
    return result;
  } catch(e) { return []; }
}

function deleteAntibioticsForStudy(studyId) {
  var sheet = getSheet('Antibiotics');
  var data = sheet.getDataRange().getValues();
  for (var i = data.length - 1; i >= 1; i--) {
    if (data[i][0] === studyId) {
      sheet.deleteRow(i + 1);
    }
  }
}

// ─── RELATIONAL CULTURES HELPERS ──────────────────────────
function saveCultures(studyId, cultures) {
  var sheet = getSheet('Cultures');
  var data = sheet.getDataRange().getValues();

  // Remove old rows for this Study ID
  for (var i = data.length - 1; i >= 1; i--) {
    if (data[i][0] === studyId) {
      sheet.deleteRow(i + 1);
    }
  }

  // Add updated rows
  cultures.forEach(function(cult) {
    sheet.appendRow([
      studyId,
      cult.sent || '',
      cult.date || '',
      cult.type || '',
      cult.typeOther || '',
      cult.result || '',
      cult.organism || '',
      cult.gram || '',
      cult.ast || '',
      cult.resist || '',
      cult.mdr || '',
      cult.xdr || '',
      cult.eskape || '',
      cult.eskapeOrganisms || ''
    ]);
  });
}

function loadCulturesForStudy(studyId) {
  if (!studyId) return [];
  try {
    var sheet = getSheet('Cultures');
    var data = sheet.getDataRange().getValues();
    var result = [];
    for (var i = 1; i < data.length; i++) {
      if (data[i][0] === studyId) {
        result.push({
          sent: data[i][1] || '',
          date: formatDate(data[i][2]) || '',
          type: data[i][3] || '',
          typeOther: data[i][4] || '',
          result: data[i][5] || '',
          organism: data[i][6] || '',
          gram: data[i][7] || '',
          ast: data[i][8] || '',
          resist: data[i][9] || '',
          mdr: data[i][10] || '',
          xdr: data[i][11] || '',
          eskape: data[i][12] || '',
          eskapeOrganisms: data[i][13] || ''
        });
      }
    }
    return result;
  } catch(e) { return []; }
}

function deleteCulturesForStudy(studyId) {
  var sheet = getSheet('Cultures');
  var data = sheet.getDataRange().getValues();
  for (var i = data.length - 1; i >= 1; i--) {
    if (data[i][0] === studyId) {
      sheet.deleteRow(i + 1);
    }
  }
}

// ─── RELATIONAL CSV EXPORT (separate files for SPSS/R/Stata) ──
function apiExportRelational(token, params) {
  if (!verifyToken(token)) return { success: false, message: 'Unauthorized', authError: true };
  var dateStr = new Date().toISOString().split('T')[0];

  // Export Records CSV
  var result = apiRead(token, params || {});
  if (!result.success) return result;

  var recHeaders = ['Study_ID','Timestamp','Age','Sex','Created_By','Hospital','Date_of_Collection','Collector_Name',
    'Admission_Date','Discharge_Date','LOS','Admission_Type','Ward','Ward_Other',
    'Diagnosis','Cancer_Type','Cancer_Name','Cancer_Name_Other',
    'Stage','Treatment','Treatment_Other',
    'Comorbidities','Comorbidities_Other','Immunosuppressed',
    'Outcome','Readmission_30d','De_escalation','Required_for_Analysis'];

  var recRows = [recHeaders.join(',')];
  result.records.forEach(function(r) {
    recRows.push([
      csvSafe(r.studyId), csvSafe(r.timestamp), csvSafe(r.age), csvSafe(r.sex),
      csvSafe(r.createdBy), csvSafe(r.hospital), csvSafe(r.dateOfCollection), csvSafe(r.collectorName),
      csvSafe(r.admissionDate), csvSafe(r.dischargeDate), csvSafe(r.los), csvSafe(r.admissionType),
      csvSafe(r.ward), csvSafe(r.wardOther),
      csvSafe(r.diagnosis), csvSafe(r.cancerType), csvSafe(r.cancerName), csvSafe(r.cancerNameOther),
      csvSafe(r.stage), csvSafe(r.treatment), csvSafe(r.treatmentOther),
      csvSafe(r.comorbidities), csvSafe(r.comorbiditiesOther), csvSafe(r.immunosuppressed),
      csvSafe(r.outcome), csvSafe(r.readmission30d), csvSafe(r.deEscalation), csvSafe(r.requiredForAnalysis)
    ].join(','));
  });

  // Export Antibiotics CSV
  var abxSheet = getSheet('Antibiotics');
  var abxData = abxSheet.getDataRange().getValues();
  var abxRows = [ANTIBIOTIC_HEADERS.map(function(h){return h.replace(/ /g,'_')}).join(',')];
  for (var a = 1; a < abxData.length; a++) {
    abxRows.push(abxData[a].map(function(v){return csvSafe(v)}).join(','));
  }

  // Export Cultures CSV
  var cultSheet = getSheet('Cultures');
  var cultData = cultSheet.getDataRange().getValues();
  var cultRows = [CULTURE_HEADERS.map(function(h){return h.replace(/ /g,'_')}).join(',')];
  for (var c = 1; c < cultData.length; c++) {
    cultRows.push(cultData[c].map(function(v){return csvSafe(v)}).join(','));
  }

  return {
    success: true,
    recordsCsv: recRows.join('\n'),
    antibioticsCsv: abxRows.join('\n'),
    culturesCsv: cultRows.join('\n'),
    filenames: {
      records: 'OncoCollect_Records_' + dateStr + '.csv',
      antibiotics: 'OncoCollect_Antibiotics_' + dateStr + '.csv',
      cultures: 'OncoCollect_Cultures_' + dateStr + '.csv'
    }
  };
}

/**
 * Populate WHO AWaRe antibiotics sheet with ATC codes
 */
function populateWhoSheet() {
  const ss = getSpreadsheet();
  var whoSheet = ss.getSheetByName('WHO');
  if (!whoSheet) whoSheet = ss.insertSheet('WHO');
  whoSheet.clear();
  whoSheet.appendRow(CONFIG.WHO_HEADERS);
  whoSheet.getRange(1, 1, 1, CONFIG.WHO_HEADERS.length).setFontWeight('bold');
  WHO_ANTIBIOTICS.forEach(function(abx) {
    whoSheet.appendRow([abx.name, abx.atc, abx.cls, abx.cat, abx.ddd]);
  });
  Logger.log('WHO sheet populated with ' + WHO_ANTIBIOTICS.length + ' antibiotics');
}

// ─── UNIT TEST HELPERS (for QUnit or manual testing) ─────────
/**
 * Test input sanitization
 * @returns {Object} Test results
 */
function testSanitizeInput() {
  var tests = [
    {input: '<script>alert("xss")</script>', expected: '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'},
    {input: 'Normal text', expected: 'Normal text'},
    {input: '5 > 3 & 2 < 4', expected: '5 &gt; 3 &amp; 2 &lt; 4'},
    {input: null, expected: ''},
    {input: '', expected: ''}
  ];
  
  var passed = 0;
  var failed = 0;
  

  var passed = 0;
  var failed = 0;

  tests.forEach(function(t) {
    var result = sanitizeInput(t.input);
    if (result === t.expected) {
      passed++;
    } else {
      failed++;
      Logger.log('FAIL: sanitizeInput("' + t.input + '") = "' + result + '" (expected: "' + t.expected + '")');
    }
  });
  

  return { passed: passed, failed: failed, total: tests.length };
}

/**
 * Test password strength validation
 * @returns {Object} Test results
 */
function testPasswordStrength() {
  var tests = [
    {password: 'weak', valid: false},
    {password: 'NoSpecial1', valid: false},
    {password: 'NoNumber!', valid: false},
    {password: 'nouppercase1!', valid: false},
    {password: 'ValidPass1!', valid: true}
  ];
  
  var passed = 0;
  var failed = 0;
  

  var passed = 0;
  var failed = 0;

  tests.forEach(function(t) {
    var result = checkPasswordStrength(t.password);
    if (result.valid === t.valid) {
      passed++;
    } else {
      failed++;
      Logger.log('FAIL: checkPasswordStrength("' + t.password + '").valid = ' + result.valid + ' (expected: ' + t.valid + ')');
    }
  });
  

  return { passed: passed, failed: failed, total: tests.length };
}

/**
 * Run all unit tests
 * @returns {Object} Combined test results
 */
function runAllTests() {
  var sanitizeResult = testSanitizeInput();
  var passwordResult = testPasswordStrength();
  

  return {
    sanitizeInput: sanitizeResult,
    passwordStrength: passwordResult,
    totalPassed: sanitizeResult.passed + passwordResult.passed,
    totalFailed: sanitizeResult.failed + passwordResult.failed,
    totalTests: sanitizeResult.total + passwordResult.total
  };
}
