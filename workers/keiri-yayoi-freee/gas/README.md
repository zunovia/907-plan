# Google Spreadsheet Webhook Setup

Serial number operations (generate, verify, revoke) are recorded in real-time to a Google Spreadsheet via Google Apps Script webhook.

## Setup Steps

### 1. Create Google Spreadsheet

1. Open [Google Sheets](https://sheets.google.com) and create a new spreadsheet
2. Name it (e.g., "Serial Number Management")

### 2. Add Google Apps Script

1. In the spreadsheet, go to **Extensions > Apps Script**
2. Delete the default `myFunction` code
3. Copy and paste the entire contents of `Code.gs` into the editor
4. Click **Save** (Ctrl+S)

### 3. Run Initial Setup

1. In the Apps Script editor, select `setupSheets` from the function dropdown
2. Click **Run**
3. When prompted, authorize the script (review and allow permissions)
4. Two sheets will be created: "Operation Log" and "Serial List"

### 4. Deploy as Web App

1. Click **Deploy > New deployment**
2. Click the gear icon and select **Web app**
3. Set the following:
   - **Description**: Serial Webhook Receiver
   - **Execute as**: Me
   - **Who has access**: Anyone
4. Click **Deploy**
5. Copy the **Web app URL** (format: `https://script.google.com/macros/s/XXXXX/exec`)

### 5. Configure Worker

Set the webhook URL as an environment variable:

```bash
# For production (recommended - uses encrypted secrets)
wrangler secret put SPREADSHEET_WEBHOOK_URL
# Paste the Web app URL when prompted

# Or set in wrangler.toml (less secure, but simpler for development)
# [vars]
# SPREADSHEET_WEBHOOK_URL = "https://script.google.com/macros/s/XXXXX/exec"
```

### 6. Verify

1. Open the admin page (`/admin`)
2. Generate a test serial number
3. Check the Google Spreadsheet - a new row should appear in both sheets

## Sheet Structure

### Sheet 1: Operation Log
All events in chronological order.

| Column | Description |
|--------|-------------|
| Timestamp | ISO 8601 timestamp |
| Event Type | GENERATE / VERIFY_SUCCESS / VERIFY_FAIL / REVOKE |
| Serial Number | XXXX-XXXX-XXXX-XXXX |
| Status | active / expired / revoked |
| Expires At | Expiration date |
| IP Address | Client IP |
| Remaining Days | Days until expiration |
| Note | Additional context |

### Sheet 2: Serial List
Latest status per serial number (auto-updated).

| Column | Description |
|--------|-------------|
| Serial Number | Unique serial |
| Status | Current status |
| Created At | Issue date |
| Expires At | Expiration date |
| Remaining Days | Days remaining |
| Used By IP | First user's IP |
| First Used At | First verification date |
| Last Event | Most recent event type |
| Last Updated | Last update timestamp |

## Updating the Script

If you update `Code.gs`:
1. Replace the code in Apps Script editor
2. Click **Deploy > Manage deployments**
3. Click the edit (pencil) icon on the active deployment
4. Change **Version** to "New version"
5. Click **Deploy**

## Troubleshooting

- **No data appearing**: Check that the Web app URL is correctly set in the Worker environment
- **Permission errors**: Re-deploy with "Anyone" access
- **Rate limits**: Google Apps Script has a limit of ~60 writes/minute. Normal serial operations should not hit this limit
