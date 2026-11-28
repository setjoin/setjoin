import { test, expect, type Page } from "@playwright/test";
import { apiLogin } from "./helpers";

const SEEN_KEY = "sj-welcome-tour:alice@test.local";
const PRIME_KEY = "sj-e2e-welcome-tour-primed";
const tour = (page: Page) => page.locator('[role="region"][data-tour-step]');

async function primeFirstRun(page: Page) {
  await page.addInitScript(
    ({ seenKey, primeKey }) => {
      if (sessionStorage.getItem(primeKey) === "1") return;
      localStorage.removeItem(seenKey);
      sessionStorage.setItem(primeKey, "1");
    },
    { seenKey: SEEN_KEY, primeKey: PRIME_KEY },
  );
}

async function startFirstRun(page: Page) {
  await primeFirstRun(page);
  await page.goto("/inbox");
  await expect(tour(page)).toBeVisible({ timeout: 10000 });
  await expect(tour(page)).toHaveAttribute("data-tour-state", "settled");
}

test.describe("@user Welcome tour", () => {
  test.beforeEach(async ({ page }) => {
    await apiLogin(page, "alice@test.local", "TestPass123!");
  });

  test("first populated inbox visit shows exact four-step non-modal tour and Skip persists", async ({
    page,
  }) => {
    await startFirstRun(page);

    await expect(tour(page)).toHaveAttribute("data-tour-step", "apps");
    await expect(tour(page)).toHaveAttribute("data-tour-total", "4");
    await expect(page.getByText("Step 1 of 4", { exact: true })).toBeVisible();
    await expect(
      page.getByRole("dialog").filter({ hasText: "Switch between your apps" }),
    ).toHaveCount(0);
    await expect(
      page.locator(".sj-tour-blocker, .sj-tour-cutout, .sj-tour-scrim"),
    ).toHaveCount(0);

    await page.getByRole("button", { name: "Skip" }).click();
    await expect(tour(page)).toHaveCount(0);
    await expect
      .poll(() => page.evaluate((key) => localStorage.getItem(key), SEEN_KEY))
      .toBe("1");

    const reopenedPage = await page.context().newPage();
    await reopenedPage.goto("/inbox");
    await expect(tour(reopenedPage)).toHaveCount(0);
    await reopenedPage.close();
  });

  test("automatic start preserves focus and the highlighted Search remains usable", async ({
    page,
  }) => {
    await primeFirstRun(page);
    await page.goto("/inbox");
    const search = page.getByRole("textbox", { name: "Search mail" });
    await search.focus();

    await expect(tour(page)).toBeVisible({ timeout: 10000 });
    await expect(search).toBeFocused();
    await page.getByRole("button", { name: "Next" }).click();
    await page.getByRole("button", { name: "Next instead" }).click();
    await expect(tour(page)).toHaveAttribute("data-tour-step", "search");

    await search.fill("from:alice");
    await expect(search).toHaveValue("from:alice");
    await expect(tour(page)).toHaveAttribute("data-tour-step", "search");
  });

  test("Compose interaction suspends the tour and resumes on the next logical step", async ({
    page,
  }) => {
    await startFirstRun(page);
    await page.getByRole("button", { name: "Next" }).click();
    await expect(tour(page)).toHaveAttribute("data-tour-step", "compose");

    await page.locator('[data-tour="compose"]:visible').click();
    const compose = page.getByRole("dialog", { name: "New message" });
    await expect(compose).toBeVisible();
    await expect(tour(page)).toHaveCount(0);

    await compose.getByRole("button", { name: "Close" }).click();
    await expect(compose).toHaveCount(0);
    await expect(tour(page)).toHaveAttribute("data-tour-step", "search");
    await expect(tour(page)).toHaveAttribute("data-tour-state", "settled");
  });

  test("mobile drawer owns Escape and tour resumes after the shell surface closes", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 360, height: 800 });
    await startFirstRun(page);
    await page.locator('[data-tour="apps"]:visible').click();
    await expect(
      page.getByRole("dialog", { name: "Navigation menu" }),
    ).toBeVisible();
    await expect(tour(page)).toHaveCount(0);

    await page.keyboard.press("Escape");
    await expect(
      page.getByRole("dialog", { name: "Navigation menu" }),
    ).toHaveCount(0);
    await expect(tour(page)).toHaveAttribute("data-tour-step", "compose");
  });

  test("explicit replay starts fresh, focuses its primary action, and shows completion feedback", async ({
    page,
  }) => {
    await page.goto("/settings/appearance");
    await page.evaluate((key) => localStorage.setItem(key, "1"), SEEN_KEY);

    const replay = page.getByRole("button", { name: "Replay welcome tour" });
    await replay.focus();
    await replay.click();
    await expect(page).toHaveURL(/\/inbox/);
    await expect(tour(page)).toHaveAttribute("data-tour-step", "apps");
    await expect(page.getByRole("button", { name: "Next" })).toBeFocused();

    await page.getByRole("button", { name: "Next" }).click();
    await page.getByRole("button", { name: "Next instead" }).click();
    await page.getByRole("button", { name: "Next" }).click();
    await page.getByRole("button", { name: "Done" }).click();
    await expect(tour(page)).toHaveCount(0);
    await expect(
      page
        .getByText("Welcome tour complete. Replay it anytime from Appearance.")
        .first(),
    ).toBeVisible();
  });
});
