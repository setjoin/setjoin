import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  render,
  screen,
  fireEvent,
  waitFor,
} from "@testing-library/svelte/svelte5";
import { page } from "$app/state";
import PublicBookingPage from "./[slug]/+page.svelte";
import ConfirmPage from "./confirm/+page.svelte";

const {
  getBookingPage,
  getBookingSlots,
  submitBooking,
  confirmBooking,
  cancelBooking,
  BookingNotFoundError,
  BookingSlotGoneError,
  BookingTokenInvalidError,
} = vi.hoisted(() => {
  class BookingNotFoundError extends Error {}
  class BookingSlotGoneError extends Error {}
  class BookingTokenInvalidError extends Error {}
  return {
    getBookingPage: vi.fn(),
    getBookingSlots: vi.fn(),
    submitBooking: vi.fn(async () => {}),
    confirmBooking: vi.fn(),
    cancelBooking: vi.fn(async () => {}),
    BookingNotFoundError,
    BookingSlotGoneError,
    BookingTokenInvalidError,
  };
});

vi.mock("$lib/api/publicBooking", () => ({
  getBookingPage,
  getBookingSlots,
  submitBooking,
  confirmBooking,
  cancelBooking,
  BookingNotFoundError,
  BookingSlotGoneError,
  BookingTokenInvalidError,
}));

const META = {
  slug: "jane-30",
  title: "30 min chat",
  description: "A quick intro",
  durationMinutes: 30,
  timezone: "UTC",
  questions: [],
  ownerName: "Jane",
};

function futureSlot(hoursFromNow: number): { start: string; end: string } {
  const start = new Date(Date.now() + hoursFromNow * 3600_000);
  const end = new Date(start.getTime() + 30 * 60_000);
  return { start: start.toISOString(), end: end.toISOString() };
}

describe("/book/[slug] (public booking page)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (page as { params: Record<string, string> }).params = { slug: "jane-30" };
  });
  afterEach(() => {
    (page as { params: Record<string, string> }).params = {};
  });

  it("shows a generic not-found state for an unknown slug", async () => {
    getBookingPage.mockRejectedValue(new BookingNotFoundError());
    render(PublicBookingPage);
    await waitFor(() => {
      expect(screen.getByText("This page doesn't exist.")).toBeTruthy();
    });
  });

  it("shows a retryable error when slots fail to load and recovers without reloading the page", async () => {
    getBookingPage.mockResolvedValue(META);
    getBookingSlots
      .mockRejectedValueOnce(new Error("network down"))
      .mockResolvedValueOnce([futureSlot(48)]);
    render(PublicBookingPage);

    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toMatch(
        /couldn't load the available times/i,
      );
    });
    await fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    await waitFor(() => expect(screen.getByText("30 min chat")).toBeTruthy());
    expect(getBookingPage).toHaveBeenCalledTimes(2);
    expect(getBookingSlots).toHaveBeenCalledTimes(2);
  });

  it("renders slots grouped by day and reveals the form on pick", async () => {
    getBookingPage.mockResolvedValue(META);
    getBookingSlots.mockResolvedValue([futureSlot(48)]);
    render(PublicBookingPage);
    await waitFor(() => expect(screen.getByText("30 min chat")).toBeTruthy());

    const slotButtons = await screen.findAllByRole("button", { name: /./ });
    const timeSlot = slotButtons.find((b) =>
      b.getAttribute("aria-label")?.match(/\d/),
    );
    expect(timeSlot).toBeTruthy();
    await fireEvent.click(timeSlot!);

    await waitFor(() => expect(screen.getByText("Your details")).toBeTruthy());
  });

  it("submitting the form posts start/email/name/answers/website and shows the check-email state", async () => {
    getBookingPage.mockResolvedValue(META);
    getBookingSlots.mockResolvedValue([futureSlot(48)]);
    render(PublicBookingPage);
    await waitFor(() => expect(screen.getByText("30 min chat")).toBeTruthy());

    const slotButtons = await screen.findAllByRole("button", { name: /./ });
    const timeSlot = slotButtons.find((b) =>
      b.getAttribute("aria-label")?.match(/\d/),
    );
    await fireEvent.click(timeSlot!);
    await waitFor(() => expect(screen.getByText("Your details")).toBeTruthy());

    const emailInput = screen.getByLabelText("Email") as HTMLInputElement;
    await fireEvent.input(emailInput, { target: { value: "ext@example.org" } });
    await fireEvent.click(screen.getByRole("button", { name: "Book" }));

    await waitFor(() => expect(submitBooking).toHaveBeenCalledTimes(1));
    const call = submitBooking.mock.calls[0] as unknown as [
      string,
      {
        start: string;
        email: string;
        name: string;
        answers: Record<string, string>;
        website: string;
      },
    ];
    expect(call[0]).toBe("jane-30");
    expect(call[1].email).toBe("ext@example.org");
    expect(call[1].website).toBe(""); // honeypot never filled by a real user
    expect(screen.getByText(/We sent a confirmation link/)).toBeTruthy();
  });

  it("a 409 slot-gone response re-fetches slots and announces assertively", async () => {
    getBookingPage.mockResolvedValue(META);
    getBookingSlots
      .mockResolvedValueOnce([futureSlot(48)])
      .mockResolvedValueOnce([]);
    submitBooking.mockRejectedValueOnce(new BookingSlotGoneError());
    render(PublicBookingPage);
    await waitFor(() => expect(screen.getByText("30 min chat")).toBeTruthy());

    const slotButtons = await screen.findAllByRole("button", { name: /./ });
    const timeSlot = slotButtons.find((b) =>
      b.getAttribute("aria-label")?.match(/\d/),
    );
    await fireEvent.click(timeSlot!);
    await waitFor(() => expect(screen.getByText("Your details")).toBeTruthy());

    const emailInput = screen.getByLabelText("Email") as HTMLInputElement;
    await fireEvent.input(emailInput, { target: { value: "ext@example.org" } });
    await fireEvent.click(screen.getByRole("button", { name: "Book" }));

    await waitFor(() => expect(getBookingSlots).toHaveBeenCalledTimes(2));
    const live = document.querySelector('[aria-live="assertive"]');
    expect(live?.textContent).toMatch(/just taken/);
  });
});

describe("/book/confirm (email-verification + cancel landing)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (page as { url: { searchParams: URLSearchParams } }).url.searchParams =
      new URLSearchParams();
  });
  afterEach(() => {
    (page as { url: { searchParams: URLSearchParams } }).url.searchParams =
      new URLSearchParams();
  });

  it("confirms a valid token and shows the confirmed state", async () => {
    (page as { url: { searchParams: URLSearchParams } }).url.searchParams =
      new URLSearchParams("token=tok1");
    confirmBooking.mockResolvedValue({ ok: true, cancelToken: "cxl1" });
    render(ConfirmPage);
    await waitFor(() =>
      expect(screen.getByText(/booking is confirmed/i)).toBeTruthy(),
    );
    expect(confirmBooking).toHaveBeenCalledWith("tok1");
  });

  it("shows an invalid-token state for a bad/expired token", async () => {
    (page as { url: { searchParams: URLSearchParams } }).url.searchParams =
      new URLSearchParams("token=bad");
    confirmBooking.mockRejectedValue(new BookingTokenInvalidError());
    render(ConfirmPage);
    await waitFor(() =>
      expect(screen.getByText(/invalid or has expired/i)).toBeTruthy(),
    );
  });

  it("cancels via ?cancel= and shows the cancelled state", async () => {
    (page as { url: { searchParams: URLSearchParams } }).url.searchParams =
      new URLSearchParams("cancel=cxl1");
    cancelBooking.mockResolvedValue(undefined);
    render(ConfirmPage);
    await waitFor(() =>
      expect(screen.getByText(/has been cancelled/i)).toBeTruthy(),
    );
    expect(cancelBooking).toHaveBeenCalledWith("cxl1");
  });
});
