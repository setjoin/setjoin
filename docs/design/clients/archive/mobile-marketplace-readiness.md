# Mobile Marketplace Readiness — Design Spec

Date: 2026-06-06
Status: Design

## Goal

Ship iOS and Android as fully functional native apps — not architectural shells with placeholder screens. Extend mail-core with JMAP Calendar/Contacts/Tasks bindings, build platform-native ViewModels, wire to UI, add auth/push/MAM, and submit to App Store + Google Play + AppGallery.

## Architecture

```
┌─ iOS ──────────────────────────┐  ┌─ Android ─────────────────────┐
│  SwiftUI Views                  │  │  Jetpack Compose Views         │
│       │                         │  │       │                       │
│  ViewModels (@Observable)       │  │  ViewModels (StateFlow)        │
│       │                         │  │       │                       │
│  ┌─ UniFFI Bridge ──────────┐  │  │  ┌─ UniFFI Bridge ────────┐  │
│  │  mail-core  │ guard-core  │  │  │  │  mail-core │ guard-core│  │
│  └─────────────┴─────────────┘  │  │  └─────────────┴──────────┘  │
│       │              │          │  │       │              │        │
│  ┌────┴──────────────┴──────┐  │  │  ┌────┴──────────────┴────┐  │
│  │  Local SQLite cache       │  │  │  │  Encrypted Keystore     │  │
│  │  (mail data + settings)   │  │  │  │  (tokens + secrets)     │  │
│  └───────────────────────────┘  │  │  └─────────────────────────┘  │
└─────────────────────────────────┘  └───────────────────────────────┘
```

Both platforms share the same Rust core. The UI layer is platform-native. The ViewModel layer is the bridge — handles state, lifecycle, error handling, and offline sync.

## Phase 1: Rust Core — JMAP Extensions

### mail-core: Calendar

```rust
// New UniFFI-exported types and methods in mail-core
pub struct CalendarEvent {
    pub id: String,
    pub title: String,
    pub start: String,        // ISO 8601
    pub end: String,
    pub all_day: bool,
    pub location: String,
    pub description: String,
    pub attendees: Vec<Attendee>,
    pub recurrence_rule: Option<String>,
    pub is_organizer: bool,
}

pub struct Attendee {
    pub name: String,
    pub email: String,
    pub status: AttendeeStatus,  // accepted/declined/tentative
}

impl MailCore {
    fn list_events(&self, start: String, end: String) -> Vec<CalendarEvent>;
    fn create_event(&self, event: CalendarEvent) -> String;  // returns id
    fn update_event(&self, id: String, event: CalendarEvent);
    fn delete_event(&self, id: String);
    fn get_free_busy(&self, emails: Vec<String>, start: String, end: String) -> Vec<FreeBusySlot>;
}
```

### mail-core: Contacts

```rust
// New UniFFI-exported
pub struct ContactCard {
    pub id: String,
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    pub company: String,
    pub job_title: String,
    pub emails: Vec<ContactEmail>,
    pub phones: Vec<ContactPhone>,
    pub avatar_blob_id: Option<String>,
}

impl MailCore {
    fn list_contacts(&self, address_book_id: Option<String>) -> Vec<ContactCard>;
    fn search_contacts(&self, query: String) -> Vec<ContactCard>;  // GAL search
    fn create_contact(&self, contact: ContactCard) -> String;
    fn update_contact(&self, id: String, contact: ContactCard);
    fn delete_contact(&self, id: String);
}
```

### mail-core: Tasks

```rust
pub struct TaskCard {
    pub id: String,
    pub title: String,
    pub description: String,
    pub due_date: Option<String>,
    pub completed: bool,
    pub priority: TaskPriority,  // low/medium/high
    pub list_id: Option<String>,
    pub subtasks: Vec<TaskCard>,
}

impl MailCore {
    fn list_tasks(&self, list_id: Option<String>) -> Vec<TaskCard>;
    fn create_task(&self, task: TaskCard) -> String;
    fn update_task(&self, id: String, task: TaskCard);
    fn delete_task(&self, id: String);
}
```

## Phase 2: Shared ViewModel Pattern (Both Platforms)

Each platform gets the same ViewModel structure. Different language, identical logic:

```
MailViewModel:
  → mailCore: MailCore              // UniFFI handle
  → inbox: [EmailSummary]           // @Published / StateFlow
  → selectedEmail: Email?           // detail view
  → loading, error                  // state management
  → loadInbox(), selectEmail(), sendReply(), composeNew()
  → Called from: MailListView, ReadingPane, ComposeView

CalendarViewModel:
  → mailCore: MailCore
  → events: [CalendarEvent]
  → selectedDate: Date
  → loadEvents(), createEvent(), deleteEvent()
  → Called from: CalendarView, EventDetailView

ContactsViewModel:
  → mailCore: MailCore
  → contacts: [ContactCard]
  → searchResults: [ContactCard]    // GAL live search
  → loadContacts(), searchGAL(), openDetail()
  → Called from: ContactsView, ContactDetailView

TasksViewModel:
  → mailCore: MailCore
  → tasks: [TaskCard]
  → loadTasks(), createTask(), toggleComplete()
  → Called from: TasksView, TaskDetailView

AuthViewModel:
  → serverUrl: String              // from .well-known/setjoin
  → accessToken: String?           // stored in Keychain/Keystore
  → isLoggedIn: Bool
  → login(), logout(), refreshToken()
  → Called from: LoginView, App.swift/MainActivity.kt (startup gate)

GuardViewModel:
  → guardCore: GuardCore
  → totpAccounts: [TotpAccount]
  → currentCode: TotpCode?
  → loadAccounts(), generateCode(), addAccount(), removeAccount()
  → Called from: TOTPView

MAMViewModel:
  → guardCore: GuardCore
  → policy: MAMPolicy
  → isLocked: Bool
  → checkin(), applyPolicy(), reportEvent()
  → Called from: App lifecycle, MAM enforcer
```

## Phase 3: Authentication Flow

```
App launch:
  │
  ├── 1. Check Keychain/Keystore for stored token
  │      ├── Has valid token → init MailCore(token) → go to inbox
  │      └── No token → show login screen
  │
  ├── 2. Login screen:
  │      ├── User enters server URL (or auto-discover from .well-known/setjoin)
  │      ├── User enters email + password
  │      ├── App sends POST /auth/login
  │      ├── If MFA required → show TOTP/Push MFA screen
  │      ├── On success: store token in Keychain/Keystore
  │      └── Init MailCore + GuardCore with token
  │
  ├── 3. Post-login init:
  │      ├── MailCore.sync() — pull latest mail data to SQLite cache
  │      ├── Register push token (APNs/FCM/HMS)
  │      ├── POST /device/checkin (MAM enrollment)
  │      └── Navigate to inbox
  │
  └── 4. Auto-refresh:
         ├── Token expiry approaching → POST /auth/refresh
         ├── On refresh fail → show login screen
         └── Background sync every 15 min (or push-triggered)
```

## Phase 4: Push Notifications

```
iOS:
  AppDelegate.didRegisterForRemoteNotificationsWithDeviceToken
    → pushToken = token
    → send to server: POST /device/checkin {push_token: token, platform: "ios"}
  
  AppDelegate.didReceiveRemoteNotification
    → if APS payload has category "new_mail"
      → MailCore.sync()
      → update badge count
    → if APS payload has category "security"
      → show local notification (MFA push, new device alert)

Android:
  FirebaseMessagingService.onNewToken
    → pushToken = token
    → send to server: POST /device/checkin {push_token: token, platform: "android"}
  
  FirebaseMessagingService.onMessageReceived
    → same dispatch as iOS

HMS (HarmonyOS + China Android):
  pushService.on('pushMessage', callback)
    → same dispatch
```

## Phase 5: MAM Integration

Device checkin happens on app launch and every 30 minutes:

```
App launch → MAM checkin flow:
  1. Load device_fingerprint from Keychain/Keystore (generate if new)
  2. POST /device/checkin {
       device_id: fingerprint,
       platform: "ios"|"android",
       app_version: "1.0.0",
       os_version: "18.0",
       policy_version: last_known_version,
     }
  3. Response includes:
     - policies: {require_pin, block_screenshots, ...}
     - wipe_command: null or {level: "account"}
     - lock_command: null or true
  4. Apply policies locally:
     - block_screenshots → enable FLAG_SECURE / window.setWindowPrivacyMode
     - require_pin → biometric gate on app open
     - wipe_command → delete all local data, exit app
```

## Phase 6: Offline Support

mail-core already has SQLite cache. The ViewModel layer reads from cache first, then syncs:

```
InboxViewModel.loadInbox():
  1. Read from local SQLite cache (instant)
  2. Show cached data immediately
  3. mailCore.sync() (background)
  4. On sync complete → update cache → refresh UI
  
Compose:
  1. User composes email, taps Send
  2. mailCore.sendEmail(draft) → JMAP Submission
  3. If offline (network error) → save to outbox, retry on next sync
  4. If online → send immediately, move to Sent folder
```

## Phase 7: Store Submission Checklist

### iOS (App Store)

- [ ] App Store Connect entry created
- [ ] App icon (1024x1024) for all required sizes
- [ ] Screenshots (6.7" iPhone + 12.9" iPad minimum)
- [ ] Privacy nutrition labels declared
- [ ] App Review Guidelines compliance (no private APIs, no hidden features)
- [ ] TestFlight beta for internal testing
- [ ] E2E test: install via TestFlight, login, read email, compose, reply

### Android (Google Play)

- [ ] Google Play Console entry created
- [ ] App icon (512x512) adaptive icon
- [ ] Feature graphic (1024x500) for store listing
- [ ] Screenshots (phone + tablet)
- [ ] Privacy policy linked
- [ ] Data safety section completed
- [ ] Internal testing track → closed alpha → open beta → production
- [ ] E2E test: install via Play, login, read email, compose, reply

### Android (Direct APK)

- [ ] Self-signed release keystore
- [ ] APK served from gateway /downloads/android
- [ ] Version check against gateway /updates/android
- [ ] Self-update via APK download → Intent install

### HarmonyOS (AppGallery)

- [ ] AppGallery Connect entry
- [ ] App icon + screenshots
- [ ] HAP signing with Huawei certificate
- [ ] E2E test on HarmonyOS device/emulator

## References

- `clients/rust/mail-core/src/` — existing JMAP Email bindings (mailbox, email, sync)
- `clients/rust/guard-core/src/` — existing TOTP, ECDH, vault bindings
- `clients/apple/mail/Bindings/` — UniFFI-generated Swift bindings
- `clients/android/app/src/main/kotlin/com/setjoin/mail/bindings/` — UniFFI-generated Kotlin bindings
- `docs/design/clients/phase12-client-architecture.md` — original client architecture
- Apple App Store Review Guidelines
- Google Play Developer Program Policies
- Huawei AppGallery Review Guidelines
