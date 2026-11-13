package authn

import "strings"

// PushTemplateKey identifies a notification type for localization.
type PushTemplateKey string

const (
	TemplateNewDeviceLogin PushTemplateKey = "new_device_login"
	TemplatePasswordChange PushTemplateKey = "password_change"
	TemplateMFASetup       PushTemplateKey = "mfa_setup"
	TemplateAdminLock      PushTemplateKey = "admin_lock"
	TemplateAdminWipe      PushTemplateKey = "admin_wipe"
)

// pushTemplates maps template keys to locale-to-message maps.
// Placeholders: {device}, {platform}, {time}, {method}, {admin} are replaced at render time.
var pushTemplates = map[PushTemplateKey]map[string]string{
	TemplateNewDeviceLogin: {
		"en": "New login from {device} on {platform}",
		"zh": "新设备登录：{device}（{platform}）",
		"de": "Neue Anmeldung von {device} auf {platform}",
	},
	TemplatePasswordChange: {
		"en": "Your password was changed",
		"zh": "您的密码已更改",
		"de": "Ihr Passwort wurde geändert",
	},
	TemplateMFASetup: {
		"en": "Multi-factor authentication ({method}) was set up on your account",
		"zh": "您的账户已设置多因素认证（{method}）",
		"de": "Multi-Faktor-Authentifizierung ({method}) wurde für Ihr Konto eingerichtet",
	},
	TemplateAdminLock: {
		"en": "Your account has been locked by {admin}",
		"zh": "您的账户已被 {admin} 锁定",
		"de": "Ihr Konto wurde von {admin} gesperrt",
	},
	TemplateAdminWipe: {
		"en": "Your devices have been remotely wiped by {admin}",
		"zh": "您的设备已被 {admin} 远程擦除",
		"de": "Ihre Geräte wurden von {admin} aus der Ferne gelöscht",
	},
}

// PushTitle returns the localized title for push notifications.
func PushTitle(locale string) string {
	titles := map[string]string{
		"en": "SetJoin Security",
		"zh": "SetJoin 安全通知",
		"de": "SetJoin Sicherheit",
	}
	if t, ok := titles[locale]; ok {
		return t
	}
	return titles["en"]
}

// PushBody renders a localized push notification body by replacing placeholders.
// locale is a 2-char code (en/zh/de). Falls back to English if locale is unknown.
func PushBody(key PushTemplateKey, locale string, params map[string]string) string {
	messages, ok := pushTemplates[key]
	if !ok {
		return ""
	}
	msg, ok := messages[locale]
	if !ok {
		msg = messages["en"]
	}
	for placeholder, value := range params {
		msg = strings.ReplaceAll(msg, "{"+placeholder+"}", value)
	}
	return msg
}
