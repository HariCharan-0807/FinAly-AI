"""
FinAly AI — Gmail API Setup Script (run once locally)
This script helps you get the OAuth2 credentials needed to send emails.

Usage:
  1. Follow the setup steps in the console
  2. Copy the 3 values it gives you into Railway Variables
  3. Done — emails will work forever (tokens auto-refresh)
"""
import json
import sys

def main():
    print()
    print("=" * 60)
    print("  FinAly AI — Gmail API Setup")
    print("=" * 60)
    print()
    print("This script will help you set up Gmail API for sending")
    print("verification and password-reset emails from your app.")
    print()
    print("─" * 60)
    print("  STEP 1: Create a Google Cloud Project")
    print("─" * 60)
    print()
    print("  1. Go to: https://console.cloud.google.com/")
    print("  2. Click the project dropdown (top-left) → 'New Project'")
    print("  3. Name it: 'FinAly AI'  → Click 'Create'")
    print("  4. Make sure 'FinAly AI' is selected as active project")
    print()
    input("  Press Enter when done...")

    print()
    print("─" * 60)
    print("  STEP 2: Enable Gmail API")
    print("─" * 60)
    print()
    print("  1. Go to: https://console.cloud.google.com/apis/library/gmail.googleapis.com")
    print("  2. Click 'Enable'")
    print()
    input("  Press Enter when done...")

    print()
    print("─" * 60)
    print("  STEP 3: Configure OAuth Consent Screen")
    print("─" * 60)
    print()
    print("  1. Go to: https://console.cloud.google.com/apis/credentials/consent")
    print("  2. Select 'External' → Click 'Create'")
    print("  3. Fill in:")
    print("     - App name: FinAly AI")
    print("     - User support email: finalyai.help@gmail.com")
    print("     - Developer contact: finalyai.help@gmail.com")
    print("  4. Click 'Save and Continue'")
    print("  5. On 'Scopes' page → Click 'Add or Remove Scopes'")
    print("     → Search 'gmail.send' → Check it → Click 'Update' → 'Save and Continue'")
    print("  6. On 'Test users' page → Click 'Add Users'")
    print("     → Enter: finalyai.help@gmail.com → Click 'Add' → 'Save and Continue'")
    print("  7. Click 'Back to Dashboard'")
    print()
    input("  Press Enter when done...")

    print()
    print("─" * 60)
    print("  STEP 4: Create OAuth2 Credentials")
    print("─" * 60)
    print()
    print("  1. Go to: https://console.cloud.google.com/apis/credentials")
    print("  2. Click '+ Create Credentials' → 'OAuth client ID'")
    print("  3. Application type: 'Desktop app'")
    print("  4. Name: 'FinAly AI Email'")
    print("  5. Click 'Create'")
    print("  6. You'll see Client ID and Client Secret — copy them below")
    print()

    client_id = input("  Paste your Client ID: ").strip()
    client_secret = input("  Paste your Client Secret: ").strip()

    if not client_id or not client_secret:
        print("\n  ❌ Both Client ID and Client Secret are required!")
        sys.exit(1)

    print()
    print("─" * 60)
    print("  STEP 5: Get Refresh Token (browser will open)")
    print("─" * 60)
    print()

    try:
        from google_auth_oauthlib.flow import InstalledAppFlow

        flow = InstalledAppFlow.from_client_config(
            {
                "installed": {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": ["http://localhost"],
                }
            },
            scopes=["https://www.googleapis.com/auth/gmail.send"],
        )

        print("  A browser window will open. Sign in with finalyai.help@gmail.com")
        print("  and click 'Allow' to grant email sending permission.")
        print()

        creds = flow.run_local_server(port=8090, prompt="consent", access_type="offline")

        refresh_token = creds.refresh_token

        if not refresh_token:
            print("\n  ❌ No refresh token received. Try again and make sure to click 'Allow'.")
            sys.exit(1)

        print()
        print("=" * 60)
        print("  ✅ SUCCESS! Add these 3 variables to Railway:")
        print("=" * 60)
        print()
        print(f"  GMAIL_CLIENT_ID     = {client_id}")
        print(f"  GMAIL_CLIENT_SECRET = {client_secret}")
        print(f"  GMAIL_REFRESH_TOKEN = {refresh_token}")
        print()
        print("  Go to Railway → your service → Variables tab")
        print("  Add all 3 variables above, then Railway auto-redeploys.")
        print()
        print("  You can also remove old variables:")
        print("  - BREVO_API_KEY (delete)")
        print("  - RESEND_API_KEY (delete)")
        print("  - GMAIL_WEBHOOK_URL (delete)")
        print()
        print("  That's it! Emails will now work for ANY recipient. 🎉")
        print("=" * 60)

    except ImportError:
        print("  Installing required package...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "google-auth-oauthlib"])
        print("\n  ✅ Installed. Please run this script again:")
        print(f"     python {__file__}")
        sys.exit(0)
    except Exception as e:
        print(f"\n  ❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
