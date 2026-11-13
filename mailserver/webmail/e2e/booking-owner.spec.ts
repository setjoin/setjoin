import { expect, test } from "@playwright/test";
import { apiToken, loginAsUser, reloadAfterServiceWorkerControl } from "./helpers";
import { TEST_USERS } from "./fixtures/test-data";
import {
  bookingPage,
  BASE,
  createBookingPage,
  deleteBookingPage,
  setBookingFeature,
  type BookingPageFixture,
} from "./booking-fixtures";

test.describe("Booking owner settings @user", () => {
  let adminToken = "";
  let ownerToken = "";
  const createdIds = new Set<string>();

  test.beforeEach(async ({ request }) => {
    ({ adminToken, ownerToken } = await setBookingFeature(
      request,
      true,
      adminToken,
      ownerToken,
    ));
  });

  test.afterEach(async ({ request }) => {
    for (const id of createdIds) {
      await deleteBookingPage(request, ownerToken, id);
    }
    createdIds.clear();
    if (adminToken) {
      await setBookingFeature(request, false, adminToken, ownerToken).catch(
        () => undefined,
      );
    }
    adminToken = "";
    ownerToken = "";
  });

  test("owner creates, edits, reloads, and deletes a page with persisted options", async ({
    page,
    request,
  }) => {
    await loginAsUser(page);
    await page.goto("/settings/booking");
    await expect(
      page.getByRole("heading", { level: 1, name: "Booking pages" }),
    ).toBeVisible();

    await page
      .getByRole("button", { name: "New booking page", exact: true })
      .click();
    const run = Date.now();
    const slug = `e2e-owner-${run}`;
    const title = `Owner page ${run}`;
    await page.getByLabel("Page title").fill(title);
    await page.getByLabel("Link name").fill(slug);
    await page
      .getByLabel("Description")
      .fill("Owner create/edit persistence journey.");
    await page.getByLabel("Meeting length (minutes)").fill("45");
    await page.getByLabel("Buffer between meetings (minutes)").fill("10");
    await page.getByLabel("Max bookings per day").fill("3");
    await page.getByLabel("Minimum notice (minutes)").fill("60");
    await page.getByLabel("Booking horizon (days)").fill("14");
    await expect(
      page.getByRole("switch", { name: "Page is live" }),
    ).toBeChecked();

    // Default availability is Mon–Fri. Make Sunday explicit and disable Monday,
    // then assert the emitted JSON below rather than only trusting the controls.
    await page.getByRole("switch", { name: "Sunday" }).click();
    await page.getByRole("switch", { name: "Monday" }).click();
    const timeInputs = page.locator('input[type="time"]');
    await expect(timeInputs).toHaveCount(10);
    await timeInputs.nth(0).fill("10:00");
    await timeInputs.nth(1).fill("11:00");

    await page
      .getByRole("button", { name: "Add question", exact: true })
      .click();
    await page.getByLabel("Question").fill("What should we prepare?");
    await page.getByRole("switch", { name: "Required" }).click();

    const putRequest = page.waitForRequest(
      (r) => r.url().includes("/api/booking/pages") && r.method() === "PUT",
    );
    const putResponse = page.waitForResponse(
      (r) =>
        r.url().includes("/api/booking/pages") &&
        r.request().method() === "PUT",
    );
    await page.getByRole("button", { name: "Save", exact: true }).click();
    const [requestSent, response] = await Promise.all([
      putRequest,
      putResponse,
    ]);
    expect(response.status()).toBe(200);
    const emitted = requestSent.postDataJSON() as BookingPageFixture;
    expect(emitted.slug).toBe(slug);
    expect(emitted.durationMinutes).toBe(45);
    expect(emitted.bufferMinutes).toBe(10);
    expect(emitted.maxPerDay).toBe(3);
    expect(emitted.minNoticeMinutes).toBe(60);
    expect(emitted.maxAdvanceDays).toBe(14);
    expect(emitted.enabled).toBe(true);
    expect(emitted.availability).toEqual(
      expect.arrayContaining([{ dow: 0, start: "10:00", end: "11:00" }]),
    );
    expect(emitted.availability).not.toEqual(
      expect.arrayContaining([expect.objectContaining({ dow: 1 })]),
    );
    expect(emitted.questions).toEqual([
      expect.objectContaining({
        label: "What should we prepare?",
        required: true,
      }),
    ]);
    const created = (await response.json()) as { id: string };
    expect(created.id).toMatch(/^[1-9][0-9]*$/);
    createdIds.add(created.id);

    await expect(page.getByRole("status")).toHaveText("Saved");
    const row = page.locator(".sj-booking-row").filter({ hasText: title });
    await expect(row).toContainText(`/book/${slug}`);

    // Edit the same row, persist a disabled state, then reload the route so the
    // assertions prove the values came back from the owner API.
    await row.getByRole("button", { name: "Edit", exact: true }).click();
    await page.getByLabel("Page title").fill(`${title} edited`);
    await page
      .getByLabel("Description")
      .fill("Edited description survives reload.");
    await page.getByLabel("Meeting length (minutes)").fill("60");
    await page.getByRole("switch", { name: "Page is live" }).click();

    const editResponse = page.waitForResponse(
      (r) =>
        r.url().includes("/api/booking/pages") &&
        r.request().method() === "PUT",
    );
    await page.getByRole("button", { name: "Save", exact: true }).click();
    const editAck = await editResponse;
    expect(editAck.status()).toBe(200);
    const edited = (await editAck.json()) as { id: string };
    expect(edited.id).toBe(created.id);
    await expect(page.locator(".sj-booking-row")).toContainText(
      `${title} edited`,
    );
    await expect(page.locator(".sj-booking-row")).toContainText("(disabled)");

    page = await reloadAfterServiceWorkerControl(page);
    const reloadedRow = page
      .locator(".sj-booking-row")
      .filter({ hasText: `${title} edited` });
    await expect(reloadedRow).toContainText(`/book/${slug} (disabled)`);
    await reloadedRow
      .getByRole("button", { name: "Edit", exact: true })
      .click();
    await expect(page.getByLabel("Description")).toHaveValue(
      "Edited description survives reload.",
    );
    await expect(page.getByLabel("Meeting length (minutes)")).toHaveValue("60");
    await expect(
      page.getByRole("switch", { name: "Page is live" }),
    ).not.toBeChecked();
    await page.getByRole("button", { name: "Cancel", exact: true }).click();

    const deleteAck = page.waitForResponse(
      (r) =>
        r.url().includes("/api/booking/pages") &&
        r.request().method() === "DELETE",
    );
    await page
      .locator(".sj-booking-row")
      .filter({ hasText: `${title} edited` })
      .getByRole("button", { name: "Delete page", exact: true })
      .click();
    expect((await deleteAck).status()).toBe(200);
    createdIds.delete(created.id);
    await expect(
      page.getByText("You have no booking pages yet."),
    ).toBeVisible();

    // The public side of the deleted page is also gone, proving the product
    // teardown path was exercised rather than a local list-only deletion.
    const publicGone = await request.get(`/api/public/booking/${slug}`);
    expect(publicGone.status()).toBe(404);
  });

  test("owner form/API validation and auth boundaries are denied without a 403 fiction", async ({
    page,
    request,
    playwright,
  }) => {
    await loginAsUser(page);
    await page.goto("/settings/booking");
    await page
      .getByRole("button", { name: "New booking page", exact: true })
      .click();
    const save = page.getByRole("button", { name: "Save", exact: true });
    await expect(save).toBeDisabled();
    await page.getByLabel("Page title").fill("Invalid owner page");
    await page.getByLabel("Link name").fill("bad slug");
    await expect(save).toBeEnabled();

    const invalidAck = page.waitForResponse(
      (r) =>
        r.url().includes("/api/booking/pages") &&
        r.request().method() === "PUT",
    );
    await save.click();
    expect((await invalidAck).status()).toBeGreaterThanOrEqual(400);
    await expect(page.getByRole("alert")).toBeVisible();
    await page.getByRole("button", { name: "Cancel", exact: true }).click();

    const anonymous = await playwright.request.newContext({
      baseURL: BASE,
      storageState: { cookies: [], origins: [] },
    });
    try {
      const unauthenticated = await anonymous.get("/api/booking/pages");
      expect(unauthenticated.status()).toBe(401);
    } finally {
      await anonymous.dispose();
    }

    const owned = await createBookingPage(
      request,
      ownerToken,
      bookingPage(`e2e-auth-${Date.now()}`),
    );
    createdIds.add(owned.id);
    const bobToken = await apiToken(
      request,
      TEST_USERS.bob.email,
      TEST_USERS.bob.password,
    );
    const crossOwnerUpdate = await request.put("/api/booking/pages", {
      headers: {
        Authorization: `Bearer ${bobToken}`,
        "Content-Type": "application/json",
      },
      data: { ...owned, title: "must not cross owner boundary" },
    });
    // booking_page_upsert uses BZ134 for not-owned IDs, projected to 404.
    // There is no 403 contract on this product route; this records the real
    // denial semantics instead of asserting an unsupported status.
    expect(crossOwnerUpdate.status()).toBe(404);
  });
});
