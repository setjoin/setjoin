-- ════════════════════════════════════════════════════════════════════════
-- V018__welcome_email_config.sql — forward migration.
--
-- Seeds the org-wide welcome-email configuration consumed by
-- notify.SendWelcomeEmail and edited in the admin console
-- (/admin/system/welcome-email). One system_config key, JSONB:
--   { enabled, default_locale, locales{en,zh,de}{subject,body_text,body_html} }
-- Enabled by default (spec §7); content mirrors the historical hard-coded
-- notify/welcome.go strings so the feature works out-of-the-box. Idempotent:
-- ON CONFLICT DO NOTHING never clobbers an admin-edited value on re-apply.
-- ════════════════════════════════════════════════════════════════════════

INSERT INTO public.system_config (key, value, encrypted, description)
VALUES (
  'welcome_email',
  jsonb_build_object(
    'enabled', true,
    'default_locale', 'en',
    'locales', jsonb_build_object(
      'en', jsonb_build_object(
        'subject', 'Welcome to SetJoin — Your New Email Is Ready',
        'body_text', E'Welcome to SetJoin!\n\nYour email account has been created and is ready to use.\n\nQuick Start:\n• Webmail: open your browser and go to your organization''s webmail URL\n• Desktop: download the SetJoin Desktop app for Windows, Mac, or Linux\n• Mobile: get the SetJoin app on iOS from the App Store, or on Android from Google Play\n\nYour mailbox includes email, calendar, contacts, and tasks — all integrated.\n\nNeed help? Contact your IT administrator.\n\n——The SetJoin Team',
        'body_html', ''
      ),
      'zh', jsonb_build_object(
        'subject', '欢迎使用 SetJoin — 您的邮箱已就绪',
        'body_text', E'欢迎使用 SetJoin！\n\n您的邮箱账户已创建，可以开始使用了。\n\n快速上手：\n• Webmail：在浏览器中打开您组织的 Webmail 网址\n• 桌面端：下载 SetJoin 桌面应用（支持 Windows、Mac、Linux）\n• 移动端：从 App Store 下载 iOS 版 SetJoin，或从应用商店下载 Android 版\n\n您的邮箱集成了邮件、日历、联系人和任务功能。\n\n需要帮助？请联系您的 IT 管理员。\n\n——SetJoin 团队',
        'body_html', ''
      ),
      'de', jsonb_build_object(
        'subject', 'Willkommen bei SetJoin — Ihre E-Mail ist bereit',
        'body_text', E'Willkommen bei SetJoin!\n\nIhr E-Mail-Konto wurde erstellt und ist einsatzbereit.\n\nErste Schritte:\n• Webmail: Öffnen Sie die Webmail-URL Ihrer Organisation im Browser\n• Desktop: Laden Sie die SetJoin Desktop-App für Windows, Mac oder Linux herunter\n• Mobil: Holen Sie sich die SetJoin-App für iOS aus dem App Store oder für Android von Google Play\n\nIhr Postfach umfasst E-Mail, Kalender, Kontakte und Aufgaben — alles integriert.\n\nBrauchen Sie Hilfe? Wenden Sie sich an Ihren IT-Administrator.\n\n——Das SetJoin-Team',
        'body_html', ''
      )
    )
  ),
  false,
  'Welcome email sent on mailbox creation (admin-editable; see /admin/system/welcome-email)'
)
ON CONFLICT (key) DO NOTHING;

-- ── schema_migrations self-insert ───────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (18, now())
    ON CONFLICT (version) DO NOTHING;
