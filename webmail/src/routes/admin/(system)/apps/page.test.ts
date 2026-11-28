import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/svelte/svelte5";
import { renderAsUser, resetStores, mockSessionLoad } from "$lib/test-utils";
import { jmapSession } from "$lib/stores/session";
const api = vi.hoisted(() => ({
  apps: vi.fn(),
  install: vi.fn(),
}));
vi.mock("$lib/admin/client", () => ({
  adminOfficeAppsGet: api.apps,
  adminOfficeAppInstall: api.install,
}));
import Page from "./+page.svelte";

function grant(permissions: string[]) {
  jmapSession.set({
    accounts: {},
    primaryAccounts: {},
    capabilities: {
      "urn:setjoin:params:jmap:mail": {
        admin: { consoles: ["system"], permissions },
      },
    },
  } as never);
}

const recoverableOperation = {
  operationId: "operation-1",
  kind: "install",
  state: "paused_recoverable",
  stateGeneration: 4,
  phase: "recover",
  progress: { step: 4, steps: 7 },
  error: { code: "runtime_uncertain" },
  providerId: "collabora",
  allowedActions: ["recover"],
  recovery: {
    problem: "Runtime state is uncertain",
    effect: "New launches remain disabled",
    remedy: "Restore Docker access and recover",
  },
  createdAt: "2026-08-25T00:00:00Z",
  updatedAt: "2026-08-25T00:02:00Z",
};

describe("curated Collabora app", () => {
  beforeEach(() => {
    resetStores();
    mockSessionLoad();
    vi.clearAllMocks();
    api.apps.mockResolvedValue({
      app: {
        appId: "collabora-code",
        name: "Collabora CODE",
        channel: "test",
        managedDeliveryEnabled: true,
        allowedActions: ["install"],
        providerReadiness: {
          providerId: "collabora",
          generation: 2,
          ready: true,
          state: "connected_inactive",
          remedy: "ready",
        },
      },
      revisions: [],
      operations: [],
    });
  });
  it("lets apps.manage install without loading or requiring Office permission", async () => {
    await renderAsUser(Page, {}, { isAdmin: true });
    grant(["apps.manage"]);
    expect(
      await screen.findByText("Self-supported test editor"),
    ).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Install" }));
    expect(
      screen.getByRole("dialog", {
        name: "Install Collabora CODE test editor",
      }),
    ).toBeInTheDocument();
    expect(api.install).not.toHaveBeenCalled();
  });

  it("shows an explicit view-only state and server-projected revisions", async () => {
    api.apps.mockResolvedValue({
      app: {
        appId: "collabora-code",
        name: "Collabora CODE",
        channel: "test",
        managedDeliveryEnabled: true,
        allowedActions: [],
        providerReadiness: null,
      },
      revisions: [{
        revisionId: "revision-1",
        revision: 1,
        providerId: "collabora",
        state: "active",
        imageReference: "collabora/code",
        imageDigest: `sha256:${"a".repeat(64)}`,
        artifactReceipt: {},
        runtimeConfig: {},
        createdAt: "2026-08-25T00:00:00Z",
        updatedAt: "2026-08-25T00:00:00Z",
      }],
      operations: [recoverableOperation],
    });
    await renderAsUser(Page, {}, { isAdmin: true });
    grant(["apps.view"]);

    expect(await screen.findByText("You can inspect application state, but you cannot request changes.")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Image digest" })).toBeInTheDocument();
    expect(screen.getByText("Auto-refreshing active operation")).toBeInTheDocument();
    expect(screen.getByText("Restore Docker access and recover")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Install" })).not.toBeInTheDocument();
  });
});
