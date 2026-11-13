import { test, expect } from "@playwright/test";
import { CONSOLES } from "../src/lib/admin/consoles";

interface ExpectedHTTPFailure {
  status: number;
  url: RegExp;
  visible: RegExp;
}

// These are deliberate default-stack states, not blanket status exceptions.
// Each entry pins the exact request and the operator-visible explanation.
const EXPECTED_HTTP_FAILURES: Record<string, ExpectedHTTPFailure[]> = {
  "/admin/storage": [
    {
      status: 503,
      url: /\/api\/admin\/storage\/status$/,
      visible: /Request failed \(503\)/,
    },
  ],
  "/admin/migration": [
    {
      status: 404,
      url: /\/api\/admin\/migration\/source\/imap$/,
      visible: /Source Configuration/,
    },
  ],
  "/admin/system": [
    {
      status: 404,
      url: /\/api\/admin\/system\/config\/get\?key=listen\.addr$/,
      visible: /Default: :443/,
    },
  ],
  "/admin/logs": [
    {
      status: 404,
      url: /\/api\/admin\/system\/logs\?/,
      visible: /Request failed \(404\)/,
    },
  ],
  "/admin/recovery": [
    {
      status: 404,
      url: /\/api\/admin\/system\/recovery\/signals\?/,
      visible: /Request failed \(404\)/,
    },
    {
      status: 404,
      url: /\/api\/admin\/system\/recovery\/incidents\?/,
      visible: /Request failed \(404\)/,
    },
  ],
  "/admin/guests": [
    { status: 404, url: /\/api\/admin\/guests$/, visible: /not found/i },
    {
      status: 404,
      url: /\/api\/admin\/guest-profiles$/,
      visible: /not found/i,
    },
    {
      status: 404,
      url: /\/api\/admin\/guest-profile-domains$/,
      visible: /not found/i,
    },
  ],
  "/admin/chat-compliance": [
    {
      status: 404,
      url: /\/api\/admin\/chat-compliance\/overview$/,
      visible: /not found/i,
    },
  ],
  "/admin/drive": [
    {
      status: 404,
      url: /\/api\/drive\/spaces\?admin=1$/,
      visible: /An error occurred/,
    },
  ],
};

/**
 * Every canonical admin navigation target must load through the real gateway.
 * Feature-specific specs own mutations and option matrices; this suite is the
 * source-bound route/visibility/error floor and grows automatically with the
 * console catalog.
 */
test.describe("Canonical admin route matrix @admin", () => {
  for (const item of CONSOLES.flatMap((console) => console.items)) {
    test(`${item.path} loads with its exact browser and API state`, async ({
      page,
    }) => {
      const httpFailures: Array<{
        status: number;
        method: string;
        url: string;
      }> = [];
      const consoleErrors: string[] = [];

      await page.addInitScript(() => {
        const trackedWindow = window as typeof window & {
          __setjoinPendingFetches?: number;
        };
        trackedWindow.__setjoinPendingFetches = 0;
        const originalFetch = window.fetch.bind(window);
        window.fetch = async (...args) => {
          trackedWindow.__setjoinPendingFetches =
            (trackedWindow.__setjoinPendingFetches ?? 0) + 1;
          try {
            return await originalFetch(...args);
          } finally {
            trackedWindow.__setjoinPendingFetches = Math.max(
              0,
              (trackedWindow.__setjoinPendingFetches ?? 1) - 1,
            );
          }
        };
      });

      page.on("response", (response) => {
        if (response.status() >= 400) {
          httpFailures.push({
            status: response.status(),
            method: response.request().method(),
            url: response.url(),
          });
        }
      });
      page.on("console", (message) => {
        if (message.type() === "error") consoleErrors.push(message.text());
      });

      const response = await page.goto(item.path, {
        waitUntil: "domcontentloaded",
      });
      expect(response?.status(), `${item.path} document status`).toBeLessThan(
        400,
      );
      await expect(
        page
          .locator('main h1, main [role="heading"][aria-level="1"], h1')
          .first(),
      ).toBeVisible();
      await page.waitForFunction(async () => {
        const trackedWindow = window as typeof window & {
          __setjoinPendingFetches?: number;
        };
        if ((trackedWindow.__setjoinPendingFetches ?? 0) !== 0) return false;
        await new Promise<void>((resolve) =>
          requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
        );
        return (trackedWindow.__setjoinPendingFetches ?? 0) === 0;
      });

      const expectedFailures = EXPECTED_HTTP_FAILURES[item.path] ?? [];
      const unexpectedFailures = httpFailures.filter(
        (failure) =>
          !expectedFailures.some(
            (expected) =>
              expected.status === failure.status &&
              expected.url.test(failure.url),
          ),
      );
      expect(
        unexpectedFailures,
        `${item.path} unexpected HTTP failures`,
      ).toEqual([]);
      for (const expectedFailure of expectedFailures) {
        expect(
          httpFailures.some(
            (failure) =>
              expectedFailure.status === failure.status &&
              expectedFailure.url.test(failure.url),
          ),
          `${item.path} expected ${expectedFailure.status} ${expectedFailure.url}`,
        ).toBe(true);
        await expect(
          page.getByText(expectedFailure.visible).first(),
        ).toBeVisible();
      }

      const actionableConsoleErrors = consoleErrors.filter(
        (message) =>
          !/^Failed to load resource: the server responded with a status of (404|503)/.test(
            message,
          ),
      );
      expect(actionableConsoleErrors).toEqual([]);
      await expect(page).toHaveURL(
        new RegExp(
          `${item.path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:/|\\?|$)`,
        ),
      );
    });
  }
});
