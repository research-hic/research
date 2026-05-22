// ============================================================================
// RESEARCH DATA COLLECTOR - GOOGLE APPS SCRIPT BACKEND
// Manages authentication, data storage, and retrieval for the web portal
// ============================================================================

// Configuration
const CONFIG = {
  CREDENTIALS_SHEET: 'Users',
  DATA_SHEET: 'Records',
  BACKUP_SHEET: 'Backup',
  VERSION: '1.0'
};

// ============================================================================
// INITIALIZATION - Set up sheets on first run
// ============================================================================

function onOpen() {
  SpreadsheetApp.getUi()
    .createMenu('Research Portal')
    .addItem('Initialize Database', 'initializeDatabase')
    .addItem('View Credentials', 'viewCredentials')
    .addSeparator()
    .addItem('Clear All Data', 'clearAllData')
    .addToUi();
}

function initializeDatabase() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  
  // Create Users sheet if not exists
  if (!ss.getSheetByName(CONFIG.CREDENTIALS_SHEET)) {
    const usersSheet = ss.insertSheet(CONFIG.CREDENTIALS_SHEET);
    usersSheet.appendRow(['Username', 'Password Hash', 'Role', 'Created', 'Active']);
    // Add default admin user (password: admin123)
    usersSheet.appendRow(['admin', hashPassword('admin123'), 'Admin', new Date(), true]);
    usersSheet.appendRow(['agent1', hashPassword('agent123'), 'Agent', new Date(), true]);
  }
  
  // Create Records sheet if not exists
  if (!ss.getSheetByName(CONFIG.DATA_SHEET)) {
    const dataSheet = ss.insertSheet(CONFIG.DATA_SHEET);
    const headers = [
      'Study ID', 'Age', 'Sex', 'Diagnosis', 'Cancer Type', 'Specific Cancer', 'Stage', 'Treatment', 
      'Comorbidities', 'Immunosuppressed', 'Admission Date', 'Discharge Date', 'Length of Stay', 
      'Admission Type', 'Ward', 'Outcome', 'Readmission 30d', 'De-escalation', 
      'Antibiotics (JSON)', 'Cultures (JSON)', 'Created By', 'Created Date', 'Last Updated'
    ];
    dataSheet.appendRow(headers);
  }
  
  // Create Backup sheet if not exists
  if (!ss.getSheetByName(CONFIG.BACKUP_SHEET)) {
    ss.insertSheet(CONFIG.BACKUP_SHEET);
  }
  
  SpreadsheetApp.getUi().alert('Database initialized successfully!');
}

// ============================================================================
// AUTHENTICATION
// ============================================================================

function loginAttempt(username, password) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const usersSheet = ss.getSheetByName(CONFIG.CREDENTIALS_SHEET);
    
    if (!usersSheet) {
      return { success: false, message: 'Database not initialized' };
    }
    
    const data = usersSheet.getDataRange().getValues();
    
    // Find user (skip header row)
    for (let i = 1; i < data.length; i++) {
      if (data[i][0] === username && data[i][4] === true) { // Check if active
        if (verifyPassword(password, data[i][1])) {
          return {
            success: true,
            user: {
              username: data[i][0],
              role: data[i][2],
              createdDate: data[i][3]
            }
          };
        }
      }
    }
    
    return { success: false, message: 'Invalid credentials' };
  } catch (e) {
    Logger.log('Login error: ' + e);
    return { success: false, message: 'Authentication error' };
  }
}

// ============================================================================
// DATA RETRIEVAL
// ============================================================================

function getAllRecords() {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const dataSheet = ss.getSheetByName(CONFIG.DATA_SHEET);
    
    if (!dataSheet) {
      return [];
    }
    
    const data = dataSheet.getDataRange().getValues();
    const records = [];
    const headers = data[0];
    
    // Convert rows to objects (skip header)
    for (let i = 1; i < data.length; i++) {
      if (data[i][0]) { // Only if Study ID exists
        const record = {};
        headers.forEach((header, index) => {
          record[header] = data[i][index];
        });
        
        // Parse JSON fields
        try {
          record.antibiotics = JSON.parse(record['Antibiotics (JSON)'] || '[]');
          record.cultures = JSON.parse(record['Cultures (JSON)'] || '[]');
        } catch (e) {
          record.antibiotics = [];
          record.cultures = [];
        }
        
        // Map to frontend field names
        record.id = record['Study ID'];
        record.A2 = record['Age'];
        record.A3 = record['Sex'];
        record.A4 = record['Diagnosis'];
        record.A5 = record['Cancer Type'];
        record.A6 = record['Specific Cancer'];
        record.A7 = record['Stage'];
        record.A8 = record['Treatment'];
        record.A9 = record['Comorbidities'];
        record.A10 = record['Immunosuppressed'];
        record.B1 = record['Admission Date'];
        record.B2 = record['Discharge Date'];
        record.B3 = record['Length of Stay'];
        record.B4 = record['Admission Type'];
        record.B5 = record['Ward'];
        record.B6 = record['Outcome'];
        record.B7 = record['Readmission 30d'];
        record.E3 = record['De-escalation'];
        record.createdBy = record['Created By'];
        
        records.push(record);
      }
    }
    
    return records;
  } catch (e) {
    Logger.log('Get all records error: ' + e);
    return [];
  }
}

function getRecordById(id) {
  try {
    const records = getAllRecords();
    return records.find(r => r.id === id) || null;
  } catch (e) {
    Logger.log('Get record error: ' + e);
    return null;
  }
}

// ============================================================================
// DATA SAVE
// ============================================================================

function saveRecordToSheet(record, user) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const dataSheet = ss.getSheetByName(CONFIG.DATA_SHEET);
    
    if (!dataSheet) {
      return { success: false, message: 'Data sheet not found' };
    }
    
    // Check if record exists
    const existingRecord = getRecordById(record.id);
    
    const rowData = [
      record.id,
      record.A2,
      record.A3,
      record.A4,
      record.A5,
      record.A6,
      record.A7,
      record.A8,
      record.A9,
      record.A10,
      record.B1,
      record.B2,
      record.B3,
      record.B4,
      record.B5,
      record.B6,
      record.B7,
      record.E3,
      JSON.stringify(record.antibiotics || []),
      JSON.stringify(record.cultures || []),
      user.username,
      new Date(),
      new Date()
    ];
    
    if (existingRecord) {
      // Update existing record
      const data = dataSheet.getDataRange().getValues();
      for (let i = 1; i < data.length; i++) {
        if (data[i][0] === record.id) {
          dataSheet.getRange(i + 1, 1, 1, rowData.length).setValues([rowData]);
          return { success: true, message: 'Record updated' };
        }
      }
    } else {
      // Add new record
      dataSheet.appendRow(rowData);
      return { success: true, message: 'Record saved' };
    }
  } catch (e) {
    Logger.log('Save record error: ' + e);
    return { success: false, message: 'Error saving record: ' + e.toString() };
  }
}

// ============================================================================
// DATA DELETE
// ============================================================================

function deleteRecordById(id, userRole) {
  try {
    // Only admins can delete
    if (userRole !== 'Admin') {
      return { success: false, message: 'Only admins can delete records' };
    }
    
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const dataSheet = ss.getSheetByName(CONFIG.DATA_SHEET);
    
    if (!dataSheet) {
      return { success: false, message: 'Data sheet not found' };
    }
    
    const data = dataSheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (data[i][0] === id) {
        dataSheet.deleteRow(i + 1);
        return { success: true, message: 'Record deleted' };
      }
    }
    
    return { success: false, message: 'Record not found' };
  } catch (e) {
    Logger.log('Delete record error: ' + e);
    return { success: false, message: 'Error deleting record: ' + e.toString() };
  }
}

// ============================================================================
// PASSWORD UTILITIES
// ============================================================================

function hashPassword(password) {
  // Simple hash using Utilities.getUuid() - in production use proper hashing
  // For demo, we'll store a simple hash
  return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, password)
    .reduce((str, chr) => (str + String.fromCharCode(chr)).slice(-2), '');
}

function verifyPassword(password, hash) {
  return hashPassword(password) === hash;
}

// ============================================================================
// ADMIN UTILITIES
// ============================================================================

function viewCredentials() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const usersSheet = ss.getSheetByName(CONFIG.CREDENTIALS_SHEET);
  
  if (!usersSheet) {
    SpreadsheetApp.getUi().alert('Users sheet not found');
    return;
  }
  
  const data = usersSheet.getDataRange().getValues();
  let output = 'Current Users:\n\n';
  
  for (let i = 1; i < data.length; i++) {
    output += `Username: ${data[i][0]}\nRole: ${data[i][2]}\nActive: ${data[i][4]}\n\n`;
  }
  
  SpreadsheetApp.getUi().alert(output);
}

function addUser(username, password, role = 'Agent') {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const usersSheet = ss.getSheetByName(CONFIG.CREDENTIALS_SHEET);
    
    if (!usersSheet) {
      return { success: false, message: 'Users sheet not found' };
    }
    
    // Check if user exists
    const data = usersSheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (data[i][0] === username) {
        return { success: false, message: 'User already exists' };
      }
    }
    
    usersSheet.appendRow([username, hashPassword(password), role, new Date(), true]);
    return { success: true, message: 'User added' };
  } catch (e) {
    Logger.log('Add user error: ' + e);
    return { success: false, message: 'Error adding user' };
  }
}

function clearAllData() {
  const ui = SpreadsheetApp.getUi();
  const response = ui.alert('Are you sure? This will delete all records.',
    ui.ButtonSet.YES_NO);
  
  if (response === ui.Button.YES) {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const dataSheet = ss.getSheetByName(CONFIG.DATA_SHEET);
    
    if (dataSheet) {
      // Keep header, delete data
      const range = dataSheet.getRange('A2:Z');
      range.clearContent();
      ui.alert('All records cleared');
    }
  }
}

// ============================================================================
// EXPORT UTILITIES
// ============================================================================

function exportRecordsToCSV() {
  try {
    const records = getAllRecords();
    
    if (records.length === 0) {
      return { success: false, message: 'No records to export' };
    }
    
    const headers = Object.keys(records[0]);
    let csv = headers.join(',') + '\n';
    
    records.forEach(record => {
      const row = headers.map(h => {
        const val = record[h];
        if (typeof val === 'object') {
          return '"' + JSON.stringify(val).replace(/"/g, '""') + '"';
        }
        return '"' + String(val).replace(/"/g, '""') + '"';
      });
      csv += row.join(',') + '\n';
    });
    
    return { success: true, csv: csv };
  } catch (e) {
    Logger.log('Export error: ' + e);
    return { success: false, message: 'Export failed' };
  }
}

// ============================================================================
// BACKUP
// ============================================================================

function backupData() {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const dataSheet = ss.getSheetByName(CONFIG.DATA_SHEET);
    const backupSheet = ss.getSheetByName(CONFIG.BACKUP_SHEET);
    
    if (!dataSheet || !backupSheet) {
      return { success: false, message: 'Required sheets not found' };
    }
    
    const data = dataSheet.getDataRange().getValues();
    backupSheet.clearContents();
    backupSheet.getRange(1, 1, data.length, data[0].length).setValues(data);
    
    return { success: true, message: 'Backup created at ' + new Date() };
  } catch (e) {
    Logger.log('Backup error: ' + e);
    return { success: false, message: 'Backup failed' };
  }
}
