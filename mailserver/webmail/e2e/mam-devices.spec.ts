import { test, expect } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { loginAsAdmin, psql } from "./helpers";

// MAM is an admin-only surface. The fixture is intentionally arranged through
// the real disposable-stack DB because there is no product endpoint that
// enrolls an arbitrary registry device for an E2E account. The rows are unique
// per run and the stack is reset between runs; raw SQL teardown is not used.
const RUN = Date.now();
const sql = (value: string) => `'${value.replaceAll("'", "''")}'`;
const USER_ID = "(SELECT id FROM users WHERE email = 'admin@test.local')";

const fixtures = [
  {
    key: "missing",
    name: `MAM E2E Registry-only ${RUN}`,
    platform: "",
    status: "unknown",
    fingerprint: randomUUID(),
    lastSeen: "now() - interval '1 minute'",
  },
  {
    key: "ios",
    name: `MAM E2E iPhone ${RUN}`,
    platform: "ios",
    status: "compliant",
    fingerprint: randomUUID(),
    lastSeen: "now() - interval '2 minutes'",
    osVersion: "17.5",
    appVersion: "1.0.0",
  },
  {
    key: "android",
    name: `MAM E2E Pixel ${RUN}`,
    platform: "android",
    status: "non_compliant",
    fingerprint: randomUUID(),
    lastSeen: "now() - interval '3 minutes'",
    osVersion: "14",
    appVersion: "1.1.0",
  },
  {
    key: "grace",
    name: `MAM E2E iPad ${RUN}`,
    platform: "ios",
    status: "grace",
    fingerprint: randomUUID(),
    lastSeen: "now() - interval '4 minutes'",
    osVersion: "17.4",
    appVersion: "1.2.0",
  },
  {
    key: "quarantined",
    name: `MAM E2E Tablet ${RUN}`,
    platform: "android",
    status: "quarantined",
    fingerprint: randomUUID(),
    lastSeen: "now() - interval '5 minutes'",
    osVersion: "13",
    appVersion: "1.3.0",
  },
] as const;

function arrangeMAMFixtures() {
  const registryValues = fixtures
    .map(
      (device) =>
        `(${USER_ID}, ${sql(`mam-e2e-${RUN}-${device.key}`)}, 'MAM E2E', ${device.lastSeen}, ${device.lastSeen}, ${sql(device.fingerprint)})`,
    )
    .join(",\n");
  const stateValues = fixtures
    .filter((device) => device.platform)
    .map((device) => {
      const osVersion = "osVersion" in device ? device.osVersion : "";
      const appVersion = "appVersion" in device ? device.appVersion : "";
      return `(${sql(device.fingerprint)}, ${USER_ID}, ${sql(device.platform)}, ${sql(device.name)}, ${sql(osVersion)}, ${sql(appVersion)}, ${sql(device.status)}, ${sql(device.key === "quarantined" ? "pending" : "none")}, ${device.lastSeen}, now() - interval '1 day', now())`;
    })
    .join(",\n");

  psql(`
		INSERT INTO device_registry (user_id, device_hash, user_agent, first_seen, last_seen, device_fingerprint)
		VALUES ${registryValues};
		INSERT INTO mdm_device_state (
			device_id, user_id, platform, device_name, os_version, app_version,
			compliance_status, wipe_requested, last_checkin_at, created_at, updated_at
		)
		VALUES ${stateValues};
	`);
}

test.describe("MAM device console @admin", () => {
  test("projects list fields, platform/status filters, and device detail", async ({
    page,
  }) => {
    arrangeMAMFixtures();
    await loginAsAdmin(page);

    const listAck = page.waitForResponse(
      (response) =>
        response.url().includes("/api/admin/mam/devices") &&
        response.request().method() === "GET" &&
        !response.url().includes("/events"),
    );
    await page.goto("/admin/mam/devices");
    await expect(
      page.getByRole("heading", { name: "MAM Devices" }),
    ).toBeVisible({ timeout: 15000 });
    const payload = (await (await listAck).json()) as {
      devices: Array<{
        id: number;
        device_name: string;
        platform: string;
        compliance_status: string;
        last_checkin_at: string | null;
      }>;
    };

    for (const fixture of fixtures.filter((device) => device.platform)) {
      const device = payload.devices.find(
        (candidate) => candidate.device_name === fixture.name,
      );
      expect(device, `wire row for ${fixture.name}`).toBeDefined();
      expect(device?.platform).toBe(fixture.platform || "unknown");
      expect(device?.compliance_status).toBe(fixture.status);
      expect(
        device?.last_checkin_at,
        `last check-in for ${fixture.name}`,
      ).not.toBeNull();
    }
    const registryOnly = payload.devices.find(
      (candidate) => candidate.compliance_status === "unknown",
    );
    expect(registryOnly, "registry-only row remains in the list").toBeDefined();
    expect(registryOnly?.platform).toBe("unknown");
    expect(registryOnly?.device_name).toBe("");
    expect(registryOnly?.last_checkin_at).not.toBeNull();

    const androidFilter = page.locator(".filters select").nth(0);
    await androidFilter.selectOption("android");
    await expect(
      page.locator("tbody tr").filter({ hasText: fixtures[2].name }),
    ).toHaveCount(1);
    await expect(
      page.locator("tbody tr").filter({ hasText: fixtures[4].name }),
    ).toHaveCount(1);
    await expect(
      page.locator("tbody tr").filter({ hasText: fixtures[1].name }),
    ).toHaveCount(0);

    const statusFilter = page.locator(".filters select").nth(1);
    await statusFilter.selectOption("quarantined");
    await expect(
      page.locator("tbody tr").filter({ hasText: fixtures[4].name }),
    ).toHaveCount(1);
    await expect(
      page.locator("tbody tr").filter({ hasText: fixtures[2].name }),
    ).toHaveCount(0);

    await androidFilter.selectOption("");
    await statusFilter.selectOption("");
    const iosDevice = payload.devices.find(
      (device) => device.device_name === fixtures[1].name,
    );
    expect(iosDevice).toBeDefined();
    await page
      .getByRole("link", { name: fixtures[1].name, exact: true })
      .click();
    await expect(page).toHaveURL(
      new RegExp(`/admin/mam/devices/${iosDevice?.id}$`),
    );
    await expect(
      page.getByRole("heading", { name: "Device Details" }),
    ).toBeVisible({ timeout: 15000 });
    const info = page.getByText("Device Information").locator("..");
    await expect(info).toContainText(fixtures[1].name);
    await expect(info).toContainText("ios");
    await expect(info).toContainText("17.5");
    await expect(info).toContainText("1.0.0");
    await expect(info).toContainText("Compliant");
    await expect(info).toContainText("Last Check-in");
  });
});
