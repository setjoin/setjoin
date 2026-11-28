import {
  expect,
  test,
  type APIRequestContext,
  type Page,
} from "@playwright/test";
import {
  bookingRequestCount,
  bookingPage,
  createBookingPage,
  deleteBookingPage,
  firstBookingSlot,
  BASE,
  setBookingFeature,
} from "./booking-fixtures";

test.describe("Booking public page @user", () => {
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

  async function makePage(
    request: APIRequestContext,
    suffix: string,
    questions: Array<{ id: string; label: string; required: boolean }> = [],
  ) {
    const fixture = bookingPage(`e2e-public-${suffix}`, { questions });
    const created = await createBookingPage(request, ownerToken, fixture);
    createdIds.add(created.id);
    return created;
  }

  async function openPage(page: Page, slug: string, title: string) {
    await page.goto(`/book/${slug}`);
    await expect(
      page.getByRole("heading", { name: title, exact: true }),
    ).toBeVisible();
    await expect(page.locator("button.sj-book-slot").first()).toBeVisible();
  }

  test("unknown and disabled slugs have the same non-enumerating public state", async ({
    page,
    request,
  }) => {
    const publicRequests: string[] = [];
    page.on("request", (requestEvent) =>
      publicRequests.push(requestEvent.url()),
    );

    const unknown = `e2e-public-unknown-${Date.now()}`;
    await page.goto(`/book/${unknown}`);
    await expect(page.getByText("This page doesn't exist.")).toBeVisible();
    expect(
      publicRequests.some(
        (url) => url.includes("/jmap") || url.includes("/auth/"),
      ),
    ).toBe(false);

    const disabled = await makePage(request, `disabled-${Date.now()}`);
    await request
      .put("/api/booking/pages", {
        headers: {
          Authorization: `Bearer ${ownerToken}`,
          "Content-Type": "application/json",
        },
        data: { ...disabled, enabled: false },
      })
      .then((response) => expect(response.status()).toBe(200));
    await page.goto(`/book/${disabled.slug}`);
    await expect(page.getByText("This page doesn't exist.")).toBeVisible();
  });

  test("shows a visible network error and retries the failed slot request", async ({
    page,
    request,
  }) => {
    const created = await makePage(request, `retry-${Date.now()}`);
    let injectedFailures = 0;
    await page.route(
      `**/api/public/booking/${created.slug}/slots?*`,
      async (route) => {
        injectedFailures += 1;
        await route.abort("internetdisconnected");
      },
      { times: 1 },
    );

    await page.goto(`/book/${created.slug}`);
    const alert = page.getByRole("alert");
    await expect(alert).toHaveText(
      "We couldn't load the available times. Check your connection and try again.",
    );
    await expect(page.locator("button.sj-book-slot")).toHaveCount(0);

    const recoveredMeta = page.waitForResponse(
      (response) =>
        response.url().endsWith(`/api/public/booking/${created.slug}`) &&
        response.request().method() === "GET",
    );
    const recoveredSlots = page.waitForResponse(
      (response) =>
        response.url().includes(`/api/public/booking/${created.slug}/slots?`) &&
        response.request().method() === "GET",
    );
    await page.getByRole("button", { name: "Retry", exact: true }).click();
    const [metaResponse, slotsResponse] = await Promise.all([
      recoveredMeta,
      recoveredSlots,
    ]);
    expect(metaResponse.status()).toBe(200);
    expect(slotsResponse.status()).toBe(200);
    await expect(
      page.getByRole("heading", { name: created.title, exact: true }),
    ).toBeVisible();
    await expect(page.locator("button.sj-book-slot").first()).toBeVisible();
    expect(injectedFailures).toBe(1);
  });

  test("selects a slot, enforces required questions, and submits a real booking", async ({
    page,
    request,
  }) => {
    const suffix = `${Date.now()}`;
    const created = await makePage(request, suffix, [
      { id: "purpose", label: "Purpose of the meeting", required: true },
      { id: "notes", label: "Optional notes", required: false },
    ]);
    await openPage(page, created.slug, created.title);

    const slot = page.locator("button.sj-book-slot").first();
    await slot.click();
    await expect(
      page.getByRole("heading", { name: "Your details" }),
    ).toBeVisible();
    const requiredQuestion = page.getByLabel("Purpose of the meeting");
    await expect(requiredQuestion).toHaveAttribute("required", "");
    await page.getByLabel("Name").fill("E2E Booker");
    const email = `booking-required-${suffix}@example.test`;
    await page.getByLabel("Email").fill(email);

    // Native required validation keeps the request from being sent until the
    // answer is present; the server-side BZ135 path is covered below by the
    // direct public API assertion because the UI cannot honestly bypass it.
    await page.getByRole("button", { name: "Book", exact: true }).click();
    await expect(requiredQuestion).toHaveValue("");
    await expect(
      page.getByRole("heading", { name: "Your details" }),
    ).toBeVisible();

    await requiredQuestion.fill("Project kickoff");
    const bookRequest = page.waitForRequest(
      (r) =>
        r.url().includes(`/api/public/booking/${created.slug}/book`) &&
        r.method() === "POST",
    );
    const bookResponse = page.waitForResponse(
      (r) =>
        r.url().includes(`/api/public/booking/${created.slug}/book`) &&
        r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Book", exact: true }).click();
    const [sent, ack] = await Promise.all([bookRequest, bookResponse]);
    expect(ack.status()).toBe(200);
    const payload = sent.postDataJSON() as {
      start: string;
      email: string;
      answers: Record<string, string>;
      website: string;
    };
    expect(payload.email).toBe(email);
    expect(payload.answers).toEqual({ purpose: "Project kickoff" });
    expect(payload.website).toBe("");
    await expect(
      page.getByText(`We sent a confirmation link to ${email}.`),
    ).toBeVisible();
    await expect.poll(() => bookingRequestCount(created.slug, email)).toBe(1);
  });

  test("honeypot returns the deliberate success response without creating a request", async ({
    page,
    request,
  }) => {
    const suffix = `${Date.now()}`;
    const created = await makePage(request, `honeypot-${suffix}`);
    await openPage(page, created.slug, created.title);
    await page.locator("button.sj-book-slot").first().click();
    const email = `booking-honeypot-${suffix}@example.test`;
    await page.getByLabel("Name").fill("Automated bot");
    await page.getByLabel("Email").fill(email);
    await page.locator("#booking-website").fill("https://bot.example.test");

    const bookResponse = page.waitForResponse(
      (r) =>
        r.url().includes(`/api/public/booking/${created.slug}/book`) &&
        r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Book", exact: true }).click();
    expect((await bookResponse).status()).toBe(200);
    await expect(
      page.getByText(`We sent a confirmation link to ${email}.`),
    ).toBeVisible();
    await expect.poll(() => bookingRequestCount(created.slug, email)).toBe(0);
  });

  test("returns 400 for a semantic missing-answer request through the real public API", async ({
    request,
  }) => {
    const suffix = `${Date.now()}`;
    const created = await makePage(request, `semantic-${suffix}`, [
      { id: "required", label: "Required answer", required: true },
    ]);
    const slot = await firstBookingSlot(request, created.slug);
    const response = await request.post(
      `/api/public/booking/${created.slug}/book`,
      {
        data: {
          start: slot.start,
          email: `booking-semantic-${suffix}@example.test`,
          name: "Semantic error",
          answers: {},
          website: "",
        },
      },
    );
    expect(response.status()).toBe(400);
    const problem = (await response.json()) as { detail?: string };
    expect(problem.detail).toMatch(/required|invalid/i);
  });

  test("refreshes a stale selected slot after the API returns 409", async ({
    page,
    browser,
    request,
  }) => {
    const suffix = `${Date.now()}`;
    const created = await makePage(request, `race-${suffix}`);
    await openPage(page, created.slug, created.title);
    const slot = page.locator("button.sj-book-slot").first();
    const slotName = await slot.getAttribute("aria-label");
    expect(slotName).toBeTruthy();

    const raceContext = await browser.newContext({ baseURL: BASE });
    const racePage = await raceContext.newPage();
    try {
      await openPage(racePage, created.slug, created.title);
      await slot.click();
      const staleSlot = racePage.getByRole("button", {
        name: slotName!,
        exact: true,
      });
      await staleSlot.click();

      const firstEmail = `booking-race-first-${suffix}@example.test`;
      await page.getByLabel("Name").fill("First race booker");
      await page.getByLabel("Email").fill(firstEmail);
      const firstAck = page.waitForResponse(
        (r) =>
          r.url().includes(`/api/public/booking/${created.slug}/book`) &&
          r.request().method() === "POST",
      );
      await page.getByRole("button", { name: "Book", exact: true }).click();
      expect((await firstAck).status()).toBe(200);

      const secondEmail = `booking-race-second-${suffix}@example.test`;
      await racePage.getByLabel("Name").fill("Second race booker");
      await racePage.getByLabel("Email").fill(secondEmail);
      const secondAck = racePage.waitForResponse(
        (r) =>
          r.url().includes(`/api/public/booking/${created.slug}/book`) &&
          r.request().method() === "POST",
      );
      await racePage.getByRole("button", { name: "Book", exact: true }).click();
      expect((await secondAck).status()).toBe(409);
      await expect(racePage.locator(".sj-book-live")).toHaveText(
        "That time was just taken — please pick another.",
      );
      await expect(
        racePage.getByRole("heading", { name: "Pick a time" }),
      ).toBeVisible();
      await expect
        .poll(() => bookingRequestCount(created.slug, secondEmail))
        .toBe(0);
    } finally {
      await raceContext.close();
    }
  });
});
