import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  fireEvent,
  screen,
  waitFor,
  within,
} from "@testing-library/svelte/svelte5";
import { renderAsUser, resetStores, mockSessionLoad } from "$lib/test-utils";
import { jmapSession } from "$lib/stores/session";

const api = vi.hoisted(() => ({
  get: vi.fn(),
  configure: vi.fn(),
  qualify: vi.fn(),
  activate: vi.fn(),
  remove: vi.fn(),
  feature: vi.fn(),
}));
vi.mock("$lib/admin/client", () => ({
  adminOfficeGet: api.get,
  adminOfficeConfigureProvider: api.configure,
  adminOfficeQualifyProvider: api.qualify,
  adminOfficeActivateProvider: api.activate,
  adminOfficeRemoveProvider: api.remove,
  adminFeatureSet: api.feature,
}));
import Page from "./+page.svelte";

const provider = {
  providerId: "collabora",
  enabled: false,
  draining: false,
  generation: 3,
  routeState: "connected_inactive",
  configSha256: "a".repeat(64),
  activeQualificationId: null,
  allowedClassifications: ["regular"],
  allowedPlatforms: ["web"],
  allowedFileFamilies: ["word"],
  entitlementState: "unknown",
  entitlementRef: null,
  buildId: "25.04",
  proofDiscoveryUrl: "https://office.test/hosting/discovery",
  wopiPublicBaseUrl: "https://setjoin.test",
  editorUrl: "https://office.test/browser/editor.html",
  removedAt: null,
  updatedAt: "2026-08-24T00:00:00Z",
};
const state = {
  providers: [provider],
  qualifications: [],
  health: [],
  operations: [],
  features: {
    driveHistory: true,
    officeEditing: false,
    officeLocalOpen: false,
    officeManagedDelivery: true,
  },
};
function grant(perms: string[]) {
  jmapSession.set({
    accounts: {},
    primaryAccounts: {},
    capabilities: {
      "urn:setjoin:params:jmap:mail": {
        admin: { consoles: ["system"], permissions: perms },
      },
    },
  } as never);
}

describe("Office provider qualification UI", () => {
  beforeEach(() => {
    resetStores();
    mockSessionLoad();
    vi.clearAllMocks();
    api.get.mockResolvedValue(structuredClone(state));
    api.configure.mockResolvedValue({ ...provider, generation: 4 });
    api.qualify.mockResolvedValue({ status: "passed" });
  });
  it("shows inactive routing and separates managed installation", async () => {
    await renderAsUser(Page, {}, { isAdmin: true });
    grant(["office.view"]);
    expect(
      await screen.findByText("Preview and download available"),
    ).toBeInTheDocument();
    expect(screen.getByText("connected_inactive")).toBeInTheDocument();
    expect(screen.getByText("You can inspect Office state, but you cannot change provider routing.")).toBeInTheDocument();
  });
  it("configures without direct activation", async () => {
    await renderAsUser(Page, {}, { isAdmin: true });
    grant(["office.manage"]);
    await fireEvent.click(
      await screen.findByRole("button", { name: "Configure" }),
    );
    const dialog = screen.getByRole("dialog", {
      name: "Connect an existing Collabora provider",
    });
    expect(within(dialog).getByRole("list", { name: "Office connection progress" })).toBeInTheDocument();
    expect(within(dialog).getByRole("heading", { name: "Endpoints" })).toBeInTheDocument();
    await fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    await fireEvent.input(within(dialog).getByLabelText("Audit reason"), {
      target: { value: "approve existing provider endpoints" },
    });
    await fireEvent.click(
      within(dialog).getByRole("button", { name: "Configure" }),
    );
    await waitFor(() => expect(api.configure).toHaveBeenCalled());
    expect(api.activate).not.toHaveBeenCalled();
    await fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    expect(within(dialog).getByText("Save proof comes from the synthetic Drive document receipt; it is not reported as a network probe.")).toBeInTheDocument();
  });
  it("qualifies the configured generation with a synthetic Drive receipt", async () => {
    await renderAsUser(Page, {}, { isAdmin: true });
    grant(["office.manage"]);
    await fireEvent.click(await screen.findByRole("button", { name: "Configure" }));
    const dialog = screen.getByRole("dialog", { name: "Connect an existing Collabora provider" });
    await fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    await fireEvent.input(within(dialog).getByLabelText("Audit reason"), { target: { value: "configure then qualify" } });
    await fireEvent.click(within(dialog).getByRole("button", { name: "Configure" }));
    await waitFor(() => expect(api.configure).toHaveBeenCalled());
    await fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    await fireEvent.input(within(dialog).getByLabelText("Synthetic save receipt ID"), { target: { value: "17" } });
    await fireEvent.input(within(dialog).getByLabelText("Audit reason"), { target: { value: "accept synthetic save" } });
    await fireEvent.click(within(dialog).getByRole("button", { name: "Run qualification" }));
    await waitFor(() => expect(api.qualify).toHaveBeenCalledWith("collabora", { expectedGeneration: 4, syntheticReceiptId: 17 }, "accept synthetic save"));
    expect(within(dialog).getByText("Qualified and connected inactive. Existing routing is unchanged.")).toBeInTheDocument();
  });
  it("activates only a passed qualification through the audited confirmation dialog", async () => {
    const qualificationId = "11111111-1111-4111-8111-111111111111";
    api.get.mockResolvedValue({ ...structuredClone(state), qualifications: [{
      qualificationId, providerId: "collabora", providerGeneration: 3,
      configSha256: "a".repeat(64), status: "passed", profile: "existing-provider",
      checks: { discovery: "pass" }, buildDigest: null, routeRevision: 1,
      createdAt: "2026-08-24T00:00:00Z", expiresAt: "2026-08-25T00:00:00Z",
    }] });
    api.activate.mockResolvedValue({ providerId: "collabora", generation: 4, routeState: "active_for_scope", qualificationId, scope: { type: "all" } });
    await renderAsUser(Page, {}, { isAdmin: true });
    grant(["office.manage"]);
    await fireEvent.click(await screen.findByRole("button", { name: "Activate routing" }));
    const dialog = screen.getByRole("dialog", { name: "Activate Office routing" });
    await fireEvent.input(within(dialog).getByLabelText("Audit reason"), { target: { value: "activate qualified provider" } });
    await fireEvent.click(within(dialog).getByRole("button", { name: "Activate routing" }));
    await waitFor(() => expect(api.activate).toHaveBeenCalledWith("collabora", {
      expectedGeneration: 3, qualificationId, scope: { type: "all" },
    }, "activate qualified provider"));
  });
  it("uses an audited dialog for feature changes", async () => {
    api.feature.mockResolvedValue({});
    await renderAsUser(Page, {}, { isAdmin: true });
    grant(["system.config"]);
    const enableButtons = await screen.findAllByRole("button", { name: "Enable" });
    await fireEvent.click(enableButtons[0]);
    const dialog = screen.getByRole("dialog", { name: "Release controls" });
    await fireEvent.input(within(dialog).getByLabelText("Audit reason"), {
      target: { value: "enable controlled test cohort" },
    });
    await fireEvent.click(within(dialog).getByRole("button", { name: "Enable" }));
    await waitFor(() => expect(api.feature).toHaveBeenCalledWith(
      "feature.office_editing",
      true,
      "enable controlled test cohort",
    ));
  });
});
