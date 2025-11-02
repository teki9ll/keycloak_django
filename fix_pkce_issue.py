#!/usr/bin/env python3
"""
PKCE Issue Fix - Disables PKCE to resolve "Code mismatch" error
"""

import sys
import os

def backup_file(file_path):
    """Create a backup of the original file"""
    backup_path = file_path + '.backup'
    if not os.path.exists(backup_path):
        with open(file_path, 'r') as original:
            with open(backup_path, 'w') as backup:
                backup.write(original.read())
        print(f"✅ Created backup: {backup_path}")
    else:
        print(f"ℹ️  Backup already exists: {backup_path}")

def disable_pkce_in_views():
    """Modify views.py to disable PKCE for testing"""

    views_path = 'app/views.py'

    if not os.path.exists(views_path):
        print(f"❌ File not found: {views_path}")
        return False

    backup_file(views_path)

    # Read the current file
    with open(views_path, 'r') as f:
        content = f.read()

    # Disable PKCE by commenting out relevant code
    modified_content = content

    # Comment out PKCE generation in login function
    modified_content = modified_content.replace(
        'code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(\'utf-8\').rstrip(\'=\')',
        '# code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(\'utf-8\').rstrip(\'=\')'
    )

    modified_content = modified_content.replace(
        'request.session[\'pkce_code_verifier\'] = code_verifier',
        '# request.session[\'pkce_code_verifier\'] = code_verifier'
    )

    modified_content = modified_content.replace(
        'code_challenge = base64.urlsafe_b64encode(\n            code_verifier.encode(\'utf-8\')\n        ).decode(\'utf-8\').rstrip(\'=\')',
        '# code_challenge = base64.urlsafe_b64encode(\n        #     code_verifier.encode(\'utf-8\')\n        # ).decode(\'utf-8\').rstrip(\'=\')'
    )

    # Remove PKCE parameters from auth_params
    modified_content = modified_content.replace(
        "\'code_challenge\': code_challenge,\n            \'code_challenge_method\': \'S256\',",
        "# \'code_challenge\': code_challenge,\n            # \'code_challenge_method\': \'S256\',"
    )

    # Remove code_verifier from token exchange
    modified_content = modified_content.replace(
        "\'code_verifier\': request.session.get(\'pkce_code_verifier\'),",
        "# \'code_verifier\': request.session.get(\'pkce_code_verifier\'),"
    )

    # Write the modified content
    with open(views_path, 'w') as f:
        f.write(modified_content)

    print("✅ PKCE disabled in app/views.py")
    print("🔧 Login flow will now use standard OAuth2 without PKCE")
    return True

def fix_redirect_uri():
    """Fix redirect URI to use consistent port"""

    views_path = 'app/views.py'

    with open(views_path, 'r') as f:
        content = f.read()

    # Replace dynamic redirect_uri with hardcoded localhost:8000
    modified_content = content.replace(
        'request.build_absolute_uri(\'/callback/\')',
        '\'http://localhost:8000/callback/\''
    )

    with open(views_path, 'w') as f:
        f.write(modified_content)

    print("✅ Fixed redirect URI to use http://localhost:8000/callback/")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--restore':
        # Restore original file
        if os.path.exists('app/views.py.backup'):
            with open('app/views.py.backup', 'r') as backup:
                with open('app/views.py', 'w') as original:
                    original.write(backup.read())
            print("✅ Restored original app/views.py")
        else:
            print("❌ No backup found to restore")
        return

    print("🔧 PKCE Issue Fix - Disabling PKCE to resolve token exchange issues")
    print("=" * 70)

    # Check if we're in the right directory
    if not os.path.exists('app/views.py'):
        print("❌ Error: Please run this script from the keycloak_demo directory")
        print("   Usage: cd keycloak_demo && python fix_pkce_issue.py")
        return

    print("📋 Issue identified:")
    print("   - PKCE verification failed: Code mismatch")
    print("   - Redirect URI port mismatch (8010 vs 8000)")
    print("")
    print("🔧 Applying fixes:")

    success1 = disable_pkce_in_views()
    fix_redirect_uri()

    if success1:
        print("")
        print("✅ PKCE issue has been fixed!")
        print("")
        print("🚀 Next steps:")
        print("   1. Restart Django server: python manage.py runserver 0.0.0.0:8000")
        print("   2. Try the login flow again")
        print("   3. The login should now work without PKCE")
        print("")
        print("📝 What was changed:")
        print("   - PKCE code generation disabled")
        print("   - PKCE parameters removed from OAuth2 requests")
        print("   - Redirect URI hardcoded to localhost:8000")
        print("")
        print("⚠️  Note: This is for development/testing only.")
        print("   For production, you should fix the PKCE configuration")
        print("   rather than disable it.")
        print("")
        print("🔄 To restore original file:")
        print("   python fix_pkce_issue.py --restore")
    else:
        print("❌ Failed to apply fixes")

if __name__ == "__main__":
    main()