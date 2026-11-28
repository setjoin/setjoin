import { expect, test, type Page, type Route } from "@playwright/test";
import { reloadAfterServiceWorkerControl } from "./helpers";

type RegistryMode = "observe" | "enforce";

type FeatureRow = {
  key: string;
  enabled: boolean;
  storedEnabled: boolean | null;
  defaultEnabled: boolean;
  classification: "known" | "unknown";
  registryMode: RegistryMode;
  gatewayEffective: boolean;
  gatewaySource: "environment" | "database" | "default";
  authserverEffective: null;
  authserverSource: "not_reported";
  description: string;
};

const unknownKey = "legacy.custom_flag.with_a_deliberately_long_suffix";

function row(key: string, overrides: Partial<FeatureRow> = {}): FeatureRow {
  return {
    key,
    enabled: false,
    storedEnabled: false,
    defaultEnabled: false,
    classification: "known",
    registryMode: "observe",
    gatewayEffective: false,
    gatewaySource: "database",
    authserverEffective: null,
    authserverSource: "not_reported",
    description: "",
    ...overrides,
  };
}

function initialRows(): FeatureRow[] {
  return [
    row("feature.imap", {
      enabled: true,
      storedEnabled: true,
      defaultEnabled: true,
      gatewayEffective: true,
      description: "IMAP listener",
    }),
    row("feature.smtp_submission", {
      enabled: true,
      storedEnabled: null,
      defaultEnabled: true,
      gatewayEffective: true,
      gatewaySource: "default",
      description: "Authenticated message submission listener",
    }),
    row("feature.identity_transitions", {
      description: "Guarded identity transition authority",
    }),
    row(unknownKey, {
      enabled: true,
      storedEnabled: true,
      defaultEnabled: true,
      classification: "unknown",
      gatewayEffective: true,
      description: "Out-of-band setting awaiting operator review",
    }),
  ];
}

async function json(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

async function installMocks(
  page: Page,
  state: { rows: FeatureRow[]; mutationDelayMs: number },
) {
  await page.addInitScript(() => {
    localStorage.setItem("sj-welcome-tour:admin@test.local", "1");
  });
  await page.route(/^https?:\/\/[^/]+\/(auth|jmap|api)\b/, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: "{}" }),
  );
  await page.route(/\/auth\/me(?:\?|$)/, (route) =>
    json(route, {
      email: "admin@test.local",
      display_name: "Admin",
      is_admin: true,
      has_mailbox: true,
      totp_enabled: true,
      delegates: [],
      impersonating: false,
    }),
  );
  await page.route(/(?:\.well-known\/jmap|\/jmap\/session)(?:\?|$)/, (route) =>
    json(route, {
      apiUrl: "/jmap",
      downloadUrl: "/blobs/{blobId}",
      uploadUrl: "/upload",
      eventSourceUrl: "/events",
      state: "state-1",
      username: "admin@test.local",
      accounts: {
        admin: {
          name: "admin@test.local",
          isPersonal: true,
          accountCapabilities: {},
        },
      },
      primaryAccounts: { "urn:ietf:params:jmap:mail": "admin" },
      capabilities: {
        "urn:setjoin:params:jmap:mail": {
          admin: { consoles: ["system"], permissions: ["system.config"] },
        },
      },
    }),
  );
  await page.route(/\/api\/user\/offline\/caps(?:\?|$)/, (route) =>
    json(route, { allowed: false }),
  );
  await page.route(
    /\/api\/admin\/features\/registry-mode(?:\?|$)/,
    async (route) => {
      if (route.request().method() !== "PUT") return json(route, {}, 405);
      const { mode } = route.request().postDataJSON() as { mode: RegistryMode };
      await new Promise((resolve) =>
        setTimeout(resolve, state.mutationDelayMs),
      );
      state.rows = state.rows.map((feature) => ({
        ...feature,
        registryMode: mode,
      }));
      await json(route, { mode, registryDigest: "a".repeat(64) });
    },
  );
  await page.route(
    /\/api\/admin\/features\/(?!registry-mode(?:\?|$))([^/?]+)(?:\?|$)/,
    async (route) => {
      const key = decodeURIComponent(
        new URL(route.request().url()).pathname.split("/").at(-1) ?? "",
      );
      await new Promise((resolve) =>
        setTimeout(resolve, state.mutationDelayMs),
      );
      if (route.request().method() === "DELETE") {
        state.rows = state.rows.filter((feature) => feature.key !== key);
        return route.fulfill({ status: 204, body: "" });
      }
      if (route.request().method() === "PUT") {
        const { enabled } = route.request().postDataJSON() as {
          enabled: boolean;
        };
        state.rows = state.rows.map((feature) =>
          feature.key === key
            ? {
                ...feature,
                enabled,
                storedEnabled: enabled,
                gatewayEffective: enabled,
              }
            : feature,
        );
        return route.fulfill({ status: 204, body: "" });
      }
      return json(route, {}, 405);
    },
  );
  await page.route(/\/api\/admin\/features(?:\?|$)/, (route) =>
    json(route, state.rows),
  );
}

async function show(
  page: Page,
  locale: "en" | "de" | "zh",
  viewport: { width: number; height: number },
  expectUnknown = true,
) {
  await page.setViewportSize(viewport);
  await page.goto("/admin/features");
  await page.evaluate(
    (nextLocale) => localStorage.setItem("locale", nextLocale),
    locale,
  );
  page = await reloadAfterServiceWorkerControl(page);
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  if (expectUnknown)
    await expect(page.getByText(unknownKey, { exact: true })).toBeVisible();
  await expect
    .poll(() =>
      page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    )
    .toBe(true);
  await page.evaluate(() => document.fonts.ready);
}

test.describe("Feature registry operator safety and visual contract @admin", () => {
  test.use({
    storageState: { cookies: [], origins: [] },
    timezoneId: "UTC",
    reducedMotion: "reduce",
    serviceWorkers: "block",
  });

  test("reflows at 320/400 CSS pixels and the 200% desktop equivalent in all locales", async ({
    page,
  }) => {
    const state = { rows: initialRows(), mutationDelayMs: 0 };
    await installMocks(page, state);
    for (const [locale, viewport] of [
      ["en", { width: 640, height: 900 }],
      ["de", { width: 320, height: 800 }],
      ["zh", { width: 400, height: 860 }],
    ] as const) {
      await show(page, locale, viewport);
      await expect(
        page.getByRole("button", {
          name:
            locale === "en"
              ? "Enforce registered settings"
              : locale === "de"
                ? "Registrierte Einstellungen erzwingen"
                : "强制使用已注册设置",
        }),
      ).toBeDisabled();
      const unknownLayout = await page
        .locator(".sj-feature-row--unknown")
        .evaluate((element) => {
          const rowRect = element.getBoundingClientRect();
          const infoRect = element
            .querySelector(".sj-feature-info")
            ?.getBoundingClientRect();
          return {
            direction: getComputedStyle(element).flexDirection,
            infoWidthRatio: infoRect ? infoRect.width / rowRect.width : 0,
          };
        });
      expect(unknownLayout.direction).toBe("column");
      expect(unknownLayout.infoWidthRatio).toBeGreaterThan(0.8);
    }
  });

  test("keeps destructive confirmation keyboard-safe and blocks dismissal while reconciling", async ({
    page,
  }) => {
    const state = { rows: initialRows(), mutationDelayMs: 400 };
    await installMocks(page, state);
    await show(page, "en", { width: 400, height: 860 });

    const remove = page.getByRole("button", {
      name: `Remove unknown setting ${unknownKey}`,
    });
    await remove.click();
    const dialog = page.getByRole("dialog", {
      name: "Remove unrecognized setting?",
    });
    const exactKey = dialog.getByLabel(`Type ${unknownKey} to confirm`);
    await expect(exactKey).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);

    await remove.click();
    await exactKey.fill(unknownKey);
    await dialog
      .getByLabel("Audit reason")
      .fill("retire unknown compatibility row");
    await dialog.getByRole("button", { name: "Remove setting" }).click();
    await expect(dialog.getByRole("button", { name: "Cancel" })).toBeDisabled();
    await page.keyboard.press("Escape");
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveCount(0, { timeout: 5000 });

    const enforce = page.getByRole("button", {
      name: "Enforce registered settings",
    });
    await expect(enforce).toBeEnabled();
    await enforce.click();
    const modeDialog = page.getByRole("dialog", { name: "Registry mode" });
    await modeDialog
      .getByLabel("Audit reason")
      .fill("registry reviewed and reconciled");
    await modeDialog.getByRole("button", { name: "Confirm" }).click();
    await expect(
      page.getByRole("button", { name: "Return to observe mode" }),
    ).toBeVisible();
  });

  test("pins the distinct desktop and narrow multilingual layouts", async ({
    page,
  }) => {
    const state = { rows: initialRows(), mutationDelayMs: 0 };
    await installMocks(page, state);

    await show(page, "en", { width: 1440, height: 900 });
    await expect(page).toHaveScreenshot(
      "feature-registry-observe-en-desktop.png",
      { fullPage: true },
    );

    await show(page, "de", { width: 320, height: 800 });
    await page
      .getByRole("button", {
        name: `Unbekannte Einstellung ${unknownKey} entfernen`,
      })
      .click();
    const germanDialog = page.getByRole("dialog");
    await expect(germanDialog).toBeVisible();
    await expect
      .poll(() =>
        germanDialog.evaluate(
          (element) => element.scrollWidth <= element.clientWidth,
        ),
      )
      .toBe(true);
    await expect(page).toHaveScreenshot("feature-registry-remove-de-320.png", {
      fullPage: true,
    });

    await page.keyboard.press("Escape");
    state.rows = state.rows
      .filter((feature) => feature.classification === "known")
      .map((feature) => ({ ...feature, registryMode: "enforce" }));
    await show(page, "zh", { width: 400, height: 860 }, false);
		const firstSwitch = page.getByRole("switch").first();
		await firstSwitch.focus();
		await expect(firstSwitch).toBeFocused();
		await page.keyboard.press("Space");
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page).toHaveScreenshot("feature-registry-enforce-zh-400.png", {
      fullPage: true,
    });
  });
});
