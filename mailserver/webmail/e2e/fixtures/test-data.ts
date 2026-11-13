export const TEST_USERS = {
  alice: { email: 'alice@test.local', password: 'TestPass123!' },
  bob:   { email: 'bob@test.local',   password: 'TestPass123!' },
  visual:{ email: 'visual@test.local',password: 'TestPass123!' },
  admin: { email: 'admin@test.local', password: 'AdminPass123!' },
  limitedAdmin: { email: 'limited-admin@test.local', password: 'AdminPass123!' },
} as const;

export const AUTH_FILE_USER  = 'playwright/.auth/user.json';
export const AUTH_FILE_ADMIN = 'playwright/.auth/admin.json';
export const AUTH_FILE_LIMITED_ADMIN = 'playwright/.auth/limited-admin.json';
