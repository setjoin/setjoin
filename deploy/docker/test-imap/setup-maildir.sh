#!/bin/sh
set -e

# Create vmail user with fixed UID/GID for predictable mailbox ownership
addgroup -g 5000 vmail 2>/dev/null || true
adduser -D -h /var/mail -u 5000 -G vmail vmail 2>/dev/null || true

# --- alice@test.local ---
ALICE="/var/mail/alice@test.local"
mkdir -p "$ALICE/cur" "$ALICE/new" "$ALICE/tmp"

cat > "$ALICE/cur/1737000001.V10001Iabc.test-imap:2,S" << 'EOF'
From: sender@example.com
To: alice@test.local
Subject: Welcome to the team
Date: Mon, 01 Jan 2026 09:00:00 +0000
Message-ID: <msg-001@test-imap>

Hello Alice! Welcome aboard.
EOF

cat > "$ALICE/cur/1737000002.V10002Iabc.test-imap:2," << 'EOF'
From: bob@example.com
To: alice@test.local
Subject: Meeting tomorrow
Date: Mon, 01 Jan 2026 10:00:00 +0000
Message-ID: <msg-002@test-imap>

Hi Alice, let's meet at 2pm tomorrow.
EOF

cat > "$ALICE/cur/1737000003.V10003Iabc.test-imap:2,F" << 'EOF'
From: urgent@example.com
To: alice@test.local
Subject: URGENT: Action required
Date: Mon, 01 Jan 2026 11:00:00 +0000
Message-ID: <msg-003@test-imap>

Please review the attached immediately.
EOF

# Set ownership
chown -R vmail:vmail /var/mail
