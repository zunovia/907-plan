/**
 * Serial Number Management - Google Spreadsheet Webhook Receiver
 *
 * This Google Apps Script receives webhook events from the Cloudflare Worker
 * and records them in app-specific sheets:
 *   経理_操作ログ     / 経理_シリアル一覧
 *   声_操作ログ       / 声_シリアル一覧
 *
 * Routing is based on payload.app ("keiri" or "voice").
 */

// =============================================
// Configuration
// =============================================
var APPS = {
  keiri: { log: '経理_操作ログ', serials: '経理_シリアル一覧' },
  voice: { log: '声_操作ログ',   serials: '声_シリアル一覧'   }
};

var LOG_HEADERS = [
  'タイムスタンプ', 'イベント種別', 'シリアル番号', 'ステータス',
  'アプリ', '有効期限', 'アクティベート日', 'IPアドレス', '残日数', '備考'
];

var SERIAL_HEADERS = [
  'シリアル番号', 'アプリ', 'ステータス', '作成日', 'アクティベート日',
  '有効期限', '残日数', '使用者IP', '使用開始日', '最終イベント', '最終更新'
];

// =============================================
// doPost - Webhook Entry Point
// =============================================
function doPost(e) {
  try {
    var payload = JSON.parse(e.postData.contents);
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var app = payload.app || 'keiri'; // default to keiri for legacy

    // Append to operation log
    appendToLog(ss, payload, app);

    // Update serial list (upsert)
    if (payload.serial && payload.serial !== '-') {
      upsertSerialList(ss, payload, app);
    }

    return ContentService
      .createTextOutput(JSON.stringify({ success: true }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (err) {
    return ContentService
      .createTextOutput(JSON.stringify({ success: false, error: err.message }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

// =============================================
// Sheet: 操作ログ (Append-only, per app)
// =============================================
function appendToLog(ss, payload, app) {
  var sheetNames = APPS[app] || APPS['keiri'];
  var sheet = getOrCreateSheet(ss, sheetNames.log, LOG_HEADERS);

  var row = [
    payload.timestamp || new Date().toISOString(),
    payload.event || '',
    payload.serial || '',
    payload.status || '',
    app,
    payload.expiresAt || '',
    payload.activatedAt || '',
    payload.ip || '',
    payload.remainingDays != null ? payload.remainingDays : '',
    payload.note || ''
  ];

  sheet.appendRow(row);
}

// =============================================
// Sheet: シリアル一覧 (Upsert by serial number, per app)
// =============================================
function upsertSerialList(ss, payload, app) {
  var sheetNames = APPS[app] || APPS['keiri'];
  var sheet = getOrCreateSheet(ss, sheetNames.serials, SERIAL_HEADERS);
  var serial = payload.serial;

  // Find existing row for this serial
  var data = sheet.getDataRange().getValues();
  var rowIndex = -1;
  for (var i = 1; i < data.length; i++) {
    if (data[i][0] === serial) {
      rowIndex = i + 1; // 1-based row number
      break;
    }
  }

  var now = new Date().toISOString();
  var newRow = [
    serial,
    app,
    resolveStatus(payload),
    payload.createdAt || (rowIndex > 0 ? data[rowIndex - 1][3] : now),
    payload.activatedAt || (rowIndex > 0 ? data[rowIndex - 1][4] : ''),
    payload.expiresAt || (rowIndex > 0 ? data[rowIndex - 1][5] : ''),
    payload.remainingDays != null ? payload.remainingDays : '',
    payload.ip || (rowIndex > 0 ? data[rowIndex - 1][7] : ''),
    payload.usedAt || (rowIndex > 0 ? data[rowIndex - 1][8] : ''),
    payload.event || '',
    now
  ];

  if (rowIndex > 0) {
    // Update existing row
    sheet.getRange(rowIndex, 1, 1, newRow.length).setValues([newRow]);
  } else {
    // Append new row
    sheet.appendRow(newRow);
  }
}

// =============================================
// Helpers
// =============================================
function resolveStatus(payload) {
  if (payload.event === 'REVOKE') return 'revoked';
  if (payload.status) return payload.status;
  if (payload.event === 'GENERATE') return 'active';
  if (payload.event === 'VERIFY_SUCCESS') return 'active';
  if (payload.event === 'VERIFY_FAIL') return 'unknown';
  return '';
}

function getOrCreateSheet(ss, name, headers) {
  var sheet = ss.getSheetByName(name);
  if (!sheet) {
    sheet = ss.insertSheet(name);
    sheet.appendRow(headers);
    // Bold header row
    sheet.getRange(1, 1, 1, headers.length).setFontWeight('bold');
    // Freeze header
    sheet.setFrozenRows(1);
    // Auto-resize columns
    for (var i = 1; i <= headers.length; i++) {
      sheet.setColumnWidth(i, 140);
    }
  }
  return sheet;
}

// =============================================
// Manual Setup Helper (run once to create all 4 sheets)
// =============================================
function setupAllSheets() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var apps = Object.keys(APPS);
  for (var a = 0; a < apps.length; a++) {
    var appName = apps[a];
    getOrCreateSheet(ss, APPS[appName].log, LOG_HEADERS);
    getOrCreateSheet(ss, APPS[appName].serials, SERIAL_HEADERS);
  }
  SpreadsheetApp.getUi().alert('All 4 sheets created successfully!\n\n' +
    '- 経理_操作ログ\n- 経理_シリアル一覧\n- 声_操作ログ\n- 声_シリアル一覧');
}
