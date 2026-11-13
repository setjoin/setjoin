import { test, expect, type Locator, type Page } from "@playwright/test";
import { apiLogin } from "./helpers";
import { TEST_USERS } from "./fixtures/test-data";

const SEEN_KEY = `sj-welcome-tour:${TEST_USERS.visual.email}`;
const STEPS = ["apps", "compose", "search", "organize"] as const;
type Step = (typeof STEPS)[number];
type Locale = "en" | "zh";
type Theme = "light" | "dark";

const TITLES: Record<Locale, Record<Step, string>> = {
  en: {
    apps: "Switch between your apps",
    compose: "Write a new message",
    search: "Find anything fast",
    organize: "Organize as you go",
  },
  zh: {
    apps: "在应用间切换",
    compose: "写新邮件",
    search: "快速找到任何邮件",
    organize: "随手整理",
  },
};

const CANONICAL: Record<number, { locale: Locale; theme: Theme }> = {
  360: { locale: "zh", theme: "light" },
  768: { locale: "en", theme: "dark" },
  1024: { locale: "zh", theme: "dark" },
  1440: { locale: "en", theme: "light" },
};

const CANONICAL_TEST_TITLES: Record<number, string> = {
  360: "matrix 360 zh light validates four steps and canonical screenshots",
  768: "matrix 768 en dark validates four steps and canonical screenshots",
  1024: "matrix 1024 zh dark validates four steps and canonical screenshots",
  1440: "matrix 1440 en light validates four steps and canonical screenshots",
};

const tour = (page: Page) => page.locator('[role="region"][data-tour-step]');

async function startStableRun(
  page: Page,
  width: number,
  locale: Locale,
  theme: Theme,
) {
  await page.setViewportSize({ width, height: width < 1024 ? 900 : 820 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await apiLogin(page, TEST_USERS.visual.email, TEST_USERS.visual.password);
  await page.clock.install({ time: new Date("2026-07-29T05:00:00.000Z") });
  await page.addInitScript(
    ({ key, locale, theme }) => {
      localStorage.removeItem(key);
      localStorage.setItem("locale", locale);
      localStorage.setItem("sj-theme", theme);
      localStorage.setItem("density", "comfortable");
    },
    { key: SEEN_KEY, locale, theme },
  );
  await page.goto("/inbox");
  await page.addStyleTag({
    content: `
			*, *::before, *::after {
				animation: none !important;
				transition: none !important;
				caret-color: transparent !important;
			}
			.sj-mailrow__time {
				visibility: hidden !important;
			}
		`,
  });
  await expect(tour(page)).toBeVisible({ timeout: 10000 });
  await expect(tour(page)).toHaveAttribute("data-tour-total", "4");
  await expect(tour(page)).toHaveAttribute("data-tour-state", "settled");
}

async function expectInsideViewport(locator: Locator, page: Page) {
  const box = await locator.boundingBox();
  expect(box).not.toBeNull();
  const viewport = page.viewportSize();
  expect(viewport).not.toBeNull();
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.y).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual(viewport!.width);
  expect(box!.y + box!.height).toBeLessThanOrEqual(viewport!.height);
}

async function expectAttachedWithoutOverlap(page: Page, step: Step) {
  const card = tour(page);
  const targets = page.locator(`[data-tour="${step}"]:visible`);
  expect(await targets.count()).toBeGreaterThan(0);
  const target = targets.first();
  const [cardBox, targetBox, className] = await Promise.all([
    card.boundingBox(),
    target.boundingBox(),
    card.getAttribute("class"),
  ]);
  expect(cardBox).not.toBeNull();
  expect(targetBox).not.toBeNull();

  const overlapWidth = Math.max(
    0,
    Math.min(cardBox!.x + cardBox!.width, targetBox!.x + targetBox!.width) -
      Math.max(cardBox!.x, targetBox!.x),
  );
  const overlapHeight = Math.max(
    0,
    Math.min(cardBox!.y + cardBox!.height, targetBox!.y + targetBox!.height) -
      Math.max(cardBox!.y, targetBox!.y),
  );
  expect(overlapWidth * overlapHeight).toBeLessThanOrEqual(1);

  const placement = className?.match(
    /sj-tour-tip--(top|bottom|left|right)/,
  )?.[1];
  expect(placement).toBeTruthy();
  if (placement === "top")
    expect(cardBox!.y + cardBox!.height).toBeLessThanOrEqual(targetBox!.y);
  if (placement === "bottom")
    expect(cardBox!.y).toBeGreaterThanOrEqual(targetBox!.y + targetBox!.height);
  if (placement === "left")
    expect(cardBox!.x + cardBox!.width).toBeLessThanOrEqual(targetBox!.x);
  if (placement === "right")
    expect(cardBox!.x).toBeGreaterThanOrEqual(targetBox!.x + targetBox!.width);
}

test.describe("@user Welcome tour responsive visual matrix", () => {
  for (const width of [360, 768, 1024, 1440]) {
    for (const locale of ["en", "zh"] as const) {
      for (const theme of ["light", "dark"] as const) {
        const canonical =
          CANONICAL[width].locale === locale &&
          CANONICAL[width].theme === theme;
        const title = canonical
          ? CANONICAL_TEST_TITLES[width]
          : `matrix ${width} ${locale} ${theme} validates four steps`;

        test(title, async ({ page }) => {
          await startStableRun(page, width, locale, theme);
          await expect(
            page.locator('[data-tour="compose"]:visible'),
          ).toHaveCount(1);
          expect(await page.locator("html").getAttribute("data-theme")).toBe(
            theme === "dark" ? "dark" : null,
          );

          for (const [index, step] of STEPS.entries()) {
            await expect(tour(page)).toHaveAttribute("data-tour-step", step);
            await expect(
              tour(page).getByRole("heading", { name: TITLES[locale][step] }),
            ).toBeVisible();
            await expect(tour(page)).toHaveAttribute(
              "data-tour-state",
              "settled",
            );
            await expectInsideViewport(tour(page), page);
            await expectAttachedWithoutOverlap(page, step);
            await expect(page.locator(".sj-tour-ring")).toHaveCSS(
              "pointer-events",
              "none",
            );

            if (canonical) {
              await expect(page).toHaveScreenshot(
                `welcome-tour-${width}-${locale}-${theme}-${step}.png`,
                {
                  animations: "disabled",
                  caret: "hide",
                  fullPage: false,
                  maxDiffPixels: 100,
                  threshold: 0.15,
                },
              );
            }

            if (index < STEPS.length - 1) {
              await tour(page)
                .locator(".sj-tour-actions button:last-child")
                .click();
              await expect(tour(page)).toHaveAttribute(
                "data-tour-step",
                STEPS[index + 1],
              );
              await expect(tour(page)).toHaveAttribute(
                "data-tour-state",
                "settled",
              );
            }
          }
        });
      }
    }
  }
});
