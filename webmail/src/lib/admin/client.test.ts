import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  adminHealth,
  adminOfficeGet,
  adminOfficeConfigureProvider,
  adminOfficeQualifyProvider,
  adminOfficeActivateProvider,
  adminOfficeRemoveProvider,
  adminOfficeAppsGet,
  adminOfficeAppInstall,
  adminMailboxLifecycleTransition,
  adminMailboxPurgeSchedule,
  adminMailboxPurgeCancel,
  adminExchangeRegistry,
  adminExchangeProjects,
  adminCreateExchangeProject,
  adminExchangeRuns,
  adminCreateExchangeRun,
  adminExchangeTransitionRun,
  adminExchangeDecision,
  adminExchangeAttest,
  adminExchangeResolveClaims,
  adminExchangeAudit,
  adminExchangePublish,
  adminExchangeDelete,
  adminUserList,
  adminUserCreate,
  adminUserResetPassword,
  adminUserAliases,
  adminUserAddAlias,
  adminUserRemoveAlias,
  adminUserQuota,
  adminUserSetQuota,
  adminRuleList,
  adminDeptTree,
  adminUpdateGroupMappings,
  adminIdentitySources,
  adminIdentityPeople,
  adminIdentityConflicts,
  adminIdentityTransitions,
  adminIdentityEvents,
  adminIdentitySourceDetail,
  adminIdentitySourcePlan,
  adminIdentitySourceApply,
  adminIdentitySourceDryRun,
  adminIdentitySourceActivate,
  adminIdentitySourcePause,
  adminIdentitySourceResume,
  adminIdentitySourceRetire,
  adminIdentitySourceSecret,
  adminIdentityPersonDetail,
  adminIdentityConflictDetail,
  adminIdentityConflictDecide,
  adminIdentityUpgradeStatus,
  adminIdentityTransitionPreview,
  adminIdentityTransitionDetail,
  adminIdentityTransitionChallenge,
  adminIdentityTransitionChallengeComplete,
  adminIdentityTransitionRequest,
  adminIdentityTransitionApprove,
  adminIdentityTransitionDeny,
  adminIdentityTransitionExecute,
  adminIdentityTransitionCancel,
  adminIdentityTransitionRetry,
  adminIdentityTransitionRollbackPreview,
  adminIdentityTransitionRollback,
  adminIdentityTransitionReport,
  adminUpgradeConsole,
  adminUpgradePreview,
  adminUpgradeChallenge,
  adminUpgradeCompleteChallenge,
  adminUpgradeRequest,
  adminUpgradeIntent,
  adminUpgradeCancel,
  chatChannelAuditCsvUrl,
  getM365ConnectUrl,
  type GroupMapping,
  type IdentityConflictDetail,
  type IdentitySourceDocument,
  type IdentityTransitionDetail,
  type IdentityTransitionPreview,
  type UpgradeIntent,
  type UpgradePreview,
} from "./client";

describe("admin client", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    vi.stubGlobal("window", { location: { href: "" } });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("adminHealth returns parsed response", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        status: "ok",
        checks: [{ check_name: "db_ping", status: "ok" }],
      }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const data = await adminHealth();
    expect(data.status).toBe("ok");
    expect(data.checks).toHaveLength(1);
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("/admin/health"),
      expect.objectContaining({ credentials: "include" }),
    );
  });

  it("Office control-plane clients preserve encoded identity, audit reason, and trimmed URLs", async () => {
    const payload = {
      providers: [],
      qualifications: [],
      health: [],
      operations: [],
      features: {
        driveHistory: false,
        officeEditing: false,
        officeLocalOpen: false,
        officeManagedDelivery: false,
      },
    };
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => payload })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          providerId: "collabora/code",
          generation: 4,
          routeState: "connected_inactive",
          configSha256: "a".repeat(64),
          qualified: false,
        }),
      })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({}) });
    vi.stubGlobal("fetch", mockFetch);

    await expect(adminOfficeGet()).resolves.toEqual(payload);
    await adminOfficeConfigureProvider(
      "collabora/code",
      {
        expectedGeneration: 3,
        profile: "existing-provider",
        entitlementState: "valid",
        buildId: "24.04.7",
        proofDiscoveryUrl: " https://office.test/hosting/discovery ",
        wopiPublicBaseUrl: " https://setjoin.test ",
        editorUrl: " https://office.test/browser/editor.html ",
        privateAllowHosts: [],
        privateAllowCidrs: [],
      },
      "approve pinned provider",
    );
    await adminOfficeRemoveProvider("collabora/code", "retire pinned provider");

    expect(mockFetch.mock.calls[0][0]).toBe("/api/admin/office");
    expect(mockFetch.mock.calls[1][0]).toBe(
      "/api/admin/office/providers/collabora%2Fcode",
    );
    const setOptions = mockFetch.mock.calls[1][1] as RequestInit;
    expect(setOptions.method).toBe("PUT");
    expect(setOptions.headers).toEqual(
      expect.objectContaining({ "X-Audit-Reason": "approve pinned provider" }),
    );
    expect(JSON.parse(String(setOptions.body))).toEqual(
      expect.objectContaining({
        config: {
          proofDiscoveryUrl: "https://office.test/hosting/discovery",
          wopiPublicBaseUrl: "https://setjoin.test",
          editorUrl: "https://office.test/browser/editor.html",
          profile: "existing-provider",
          privateAllowHosts: [],
          privateAllowCidrs: [],
        },
      }),
    );
    expect(mockFetch.mock.calls[2][1]).toEqual(
      expect.objectContaining({
        method: "DELETE",
        headers: expect.objectContaining({
          "X-Audit-Reason": "retire pinned provider",
        }),
      }),
    );
  });

  it("Office application clients decode readiness/actions and preserve install idempotency", async () => {
    const operationId = "11111111-1111-4111-8111-111111111111";
    const idempotencyKey = "22222222-2222-4222-8222-222222222222";
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          app: {
            appId: "collabora-code",
            name: "Collabora CODE",
            channel: "test",
            managedDeliveryEnabled: true,
            allowedActions: ["install"],
            providerReadiness: {
              providerId: "collabora",
              generation: 4,
              ready: true,
              state: "connected_inactive",
              remedy: "ready",
            },
          },
          revisions: [],
          operations: [],
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 202,
        json: async () => ({
          operationId,
          state: "requested",
          stateGeneration: 1,
          phase: "requested",
          replayed: false,
        }),
      });
    vi.stubGlobal("fetch", mockFetch);

    await expect(adminOfficeAppsGet()).resolves.toMatchObject({
      app: { allowedActions: ["install"], providerReadiness: { ready: true } },
    });
    await expect(adminOfficeAppInstall({
      providerId: "collabora",
      expectedProviderGeneration: 4,
      profile: "managed-customer-proxy",
      ingress: { hostname: "office.test" },
      reason: "install test editor",
      idempotencyKey,
    })).resolves.toMatchObject({ operationId, replayed: false });

    expect(mockFetch.mock.calls[1][0]).toBe("/api/admin/apps/collabora-code/operations");
    expect(mockFetch.mock.calls[1][1]).toEqual(expect.objectContaining({
      method: "POST",
      headers: expect.objectContaining({
        "X-Audit-Reason": "install test editor",
        "Idempotency-Key": idempotencyKey,
      }),
    }));
  });

  it("Office qualification and mailbox lifecycle mutations preserve every audit and generation fence", async () => {
    const qualificationId = "11111111-1111-4111-8111-111111111111";
    const responses = [
      { providerId: "collabora/code", generation: 5, routeState: "connected_inactive", qualificationId, expiresAt: "2026-08-26T00:00:00Z", qualified: true },
      { providerId: "collabora/code", generation: 6, routeState: "active_for_scope", qualificationId, scope: { type: "all" } },
      { mailboxId: "7", state: "suspended", generation: "4" },
      { purgeRequestId: "8", approvalRequestId: 9, eligibleAt: "2026-09-01T00:00:00Z" },
      { purgeRequestId: "8", mailboxId: "7", state: "cancelled", generation: "2" },
    ];
    const mockFetch = vi.fn();
    for (const payload of responses) mockFetch.mockResolvedValueOnce({ ok: true, status: 200, json: async () => payload });
    vi.stubGlobal("fetch", mockFetch);

    await adminOfficeQualifyProvider("collabora/code", { expectedGeneration: 4, syntheticReceiptId: 17, routeRevision: 3 }, "qualify provider");
    await adminOfficeActivateProvider("collabora/code", { expectedGeneration: 5, qualificationId, scope: { type: "all" } }, "activate provider");
    await adminMailboxLifecycleTransition(7, "suspend", "3", "suspend mailbox", { note: "case-7" });
    await adminMailboxPurgeSchedule(7, "4", "digest", 11, "schedule purge");
    await adminMailboxPurgeCancel("8", "cancel purge");

    expect(mockFetch.mock.calls.map((call) => call[0])).toEqual([
      "/api/admin/office/providers/collabora%2Fcode/qualify",
      "/api/admin/office/providers/collabora%2Fcode/activate",
      "/api/admin/mailboxes/7/lifecycle",
      "/api/admin/mailboxes/7/purge",
      "/api/admin/mailbox-purges/8/cancel",
    ]);
    expect(JSON.parse(String(mockFetch.mock.calls[2][1].body))).toEqual(expect.objectContaining({ action: "suspend", expectedGeneration: "3", note: "case-7" }));
    expect(JSON.parse(String(mockFetch.mock.calls[3][1].body))).toEqual(expect.objectContaining({ expectedGeneration: "4", previewDigest: "digest", approverUserId: "11" }));
    for (const call of mockFetch.mock.calls) expect(call[1]).toEqual(expect.objectContaining({ method: "POST", headers: expect.objectContaining({ "X-Audit-Reason": expect.any(String) }) }));
  });

  it("Exchange comparison clients exercise every read, transition, evidence, publish, and deletion contract", async () => {
    const mockFetch = vi
      .fn()
      .mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ ok: true }),
      });
    vi.stubGlobal("fetch", mockFetch);
    await adminExchangeRegistry();
    await adminExchangeProjects();
    await adminCreateExchangeProject({ domainId: 7, name: "Migration" });
    await adminExchangeRuns(11);
    await adminCreateExchangeRun(11, {
      supportCellId: "cell",
      supportCellDigest: "digest",
      registryVersion: 1,
      registryDigest: "registry",
      catalogVersion: 1,
      collectorVersion: "1.0.0",
    });
    await adminExchangeTransitionRun(12, 3, "collecting");
    await adminExchangeDecision(12, {
      expectedGeneration: 4,
      capabilityId: "calendar",
      outcomeMapping: "native",
      decision: "accepted",
      reason: "兼容性已验证",
    });
    await adminExchangeAttest(12, {
      kind: "operator",
      subjectDigest: "subject",
      statement: { verified: true },
    });
    await adminExchangeResolveClaims(12, 5);
    await adminExchangeAudit(12);
    await adminExchangePublish(12, "projection");
    await adminExchangeDelete(11, {
      scope: "run",
      runId: 12,
      reason: "expired evidence",
    });

    expect(mockFetch).toHaveBeenCalledTimes(12);
    expect(mockFetch.mock.calls.map((call) => call[0])).toContain(
      "/api/admin/exchange-replacement/runs/12/publications",
    );
    const decision = mockFetch.mock.calls.find((call) =>
      String(call[0]).endsWith("/decisions"),
    )?.[1] as RequestInit;
    expect(decision.headers).toEqual(
      expect.objectContaining({
        "X-Audit-Reason": "Record Exchange assessment decision",
      }),
    );
    expect(JSON.parse(String(decision.body)).reason).toBe("兼容性已验证");
  });

  it("redirects to login on 401", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => "Unauthorized",
    });
    vi.stubGlobal("fetch", mockFetch);

    await expect(adminHealth()).rejects.toThrow("Session expired");
    expect(window.location.href).toBe("/login");
  });

  it("throws on 403", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      text: async () => "Forbidden",
    });
    vi.stubGlobal("fetch", mockFetch);

    await expect(adminHealth()).rejects.toThrow("Admin access required");
  });

  it("adminUserList builds query params", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => [{ id: 1, email: "a@b.com" }],
    });
    vi.stubGlobal("fetch", mockFetch);

    await adminUserList("search", 10, 5);
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("q=search");
    expect(url).toContain("limit=10");
    expect(url).toContain("offset=5");
  });

  it("adminUserList normalizes a null body (Go nil slice) to []", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => null,
    });
    vi.stubGlobal("fetch", mockFetch);

    await expect(adminUserList("no-match")).resolves.toEqual([]);
  });

  it("adminDeptTree normalizes a null body (zero departments) to []", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => null,
    });
    vi.stubGlobal("fetch", mockFetch);

    await expect(adminDeptTree()).resolves.toEqual([]);
  });

  it("adminUserCreate sends POST with body", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => ({ id: 42 }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const result = await adminUserCreate({
      email: "new@example.com",
      password: "secret88",
    });
    expect(result.id).toBe(42);
    const opts = mockFetch.mock.calls[0][1];
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body)).toEqual({
      email: "new@example.com",
      password: "secret88",
    });
  });

  it("adminUserResetPassword sends correct payload", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, status: 204 });
    vi.stubGlobal("fetch", mockFetch);

    await adminUserResetPassword(7, "newpass88", true);
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("/admin/users/7/password");
    const opts = mockFetch.mock.calls[0][1];
    expect(opts.method).toBe("PUT");
    expect(JSON.parse(opts.body)).toEqual({
      password: "newpass88",
      mustChange: true,
    });
  });

  it("adminUserResetPassword defaults mustChange to true", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, status: 204 });
    vi.stubGlobal("fetch", mockFetch);

    await adminUserResetPassword(7, "newpass88");
    const opts = mockFetch.mock.calls[0][1];
    expect(JSON.parse(opts.body).mustChange).toBe(true);
  });

  it("identity v2 list clients preserve bounded items and normalize missing items", async () => {
    const responses = [
      { items: [{ sourceKey: "legacy:ad" }] },
      { items: [{ userId: "42" }] },
      { items: [{ id: "conflict-1" }] },
      { items: [{ id: "transition-1" }] },
      {},
    ];
    const mockFetch = vi.fn().mockImplementation(async () => ({
      ok: true,
      status: 200,
      json: async () => responses.shift(),
    }));
    vi.stubGlobal("fetch", mockFetch);

    await expect(adminIdentitySources()).resolves.toEqual([
      { sourceKey: "legacy:ad" },
    ]);
    await expect(adminIdentityPeople()).resolves.toEqual([{ userId: "42" }]);
    await expect(adminIdentityConflicts()).resolves.toEqual([
      { id: "conflict-1" },
    ]);
    await expect(adminIdentityTransitions()).resolves.toEqual([
      { id: "transition-1" },
    ]);
    await expect(adminIdentityEvents()).resolves.toEqual([]);
    expect(mockFetch.mock.calls.map((call) => call[0])).toEqual([
      "/api/admin/identity/v2/sources",
      "/api/admin/identity/v2/people",
      "/api/admin/identity/v2/conflicts",
      "/api/admin/identity/v2/transitions",
      "/api/admin/identity/v2/events",
    ]);
  });

  it("identity transition clients require challenge, elevation, and exact mutation fences", async () => {
    const preview: IdentityTransitionPreview = {
      transitionId: "transition/id",
      state: "previewed",
      transitionGeneration: "2",
      previewDigest: "a".repeat(64),
      previewExpiresAt: "2026-07-25T12:05:00Z",
      protected: false,
      recoveryReady: true,
      sourceGeneration: "3",
      linkGeneration: "4",
      lifecycleGeneration: "1",
      replayed: false,
    };
    const detail: IdentityTransitionDetail = {
      transitionId: preview.transitionId,
      correlationId: "correlation-id",
      personId: "42",
      type: "directory_to_local",
      state: "authorized",
      transitionGeneration: "4",
      previewVersion: "1",
      previewDigest: preview.previewDigest,
      previewExpiresAt: preview.previewExpiresAt,
      protected: false,
      rollback: { boundary: "not_committed" },
      effects: [],
    };
    const challenge = {
      challengeId: "challenge-id",
      transitionId: preview.transitionId,
      transitionGeneration: preview.transitionGeneration,
      previewDigest: preview.previewDigest,
      expiresAt: preview.previewExpiresAt,
      handoffMethod: "browser" as const,
      displayCode: "ABC12345",
      completed: false,
      invalidated: false,
    };
    const elevation = {
      challengeId: challenge.challengeId,
      elevationId: "elevation-id",
      transitionId: preview.transitionId,
      transitionGeneration: preview.transitionGeneration,
      expiresAt: preview.previewExpiresAt,
      consumed: false,
      invalidated: false,
      replayed: false,
    };
    const report = new Blob(["{}"], { type: "application/json" });
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => preview,
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => challenge,
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => elevation,
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 202,
        json: async () => detail,
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 202,
        json: async () => detail,
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        blob: async () => report,
      });
    vi.stubGlobal("fetch", mockFetch);

    await expect(
      adminIdentityTransitionPreview("42", "approved migration", "idem-1"),
    ).resolves.toEqual(preview);
    await expect(
      adminIdentityTransitionChallenge(preview, "idem-2"),
    ).resolves.toEqual(challenge);
    await expect(
      adminIdentityTransitionChallengeComplete(
        preview,
        challenge.challengeId,
        "idem-3",
      ),
    ).resolves.toEqual(elevation);
    await adminIdentityTransitionRequest(
      preview,
      elevation.elevationId,
      "approved migration",
      "idem-4",
    );
    await adminIdentityTransitionExecute(
      detail,
      elevation.elevationId,
      "approved migration",
      "idem-5",
      "9007199254740993",
    );
    await expect(
      adminIdentityTransitionReport(preview.transitionId),
    ).resolves.toBe(report);

    const previewOptions = mockFetch.mock.calls[0][1];
    expect(previewOptions.headers).toEqual(
      expect.objectContaining({
        "X-Audit-Reason": "approved migration",
        "Idempotency-Key": "idem-1",
      }),
    );
    expect(JSON.parse(previewOptions.body)).toEqual({
      userId: "42",
      reason: "approved migration",
      idempotencyKey: "idem-1",
    });
    expect(mockFetch.mock.calls[1][0]).toBe(
      "/api/admin/identity/v2/transitions/transition%2Fid/step-up/challenge",
    );
    expect(mockFetch.mock.calls[1][1].headers).toEqual(
      expect.objectContaining({
        "Idempotency-Key": "idem-2",
        "If-Match": `"${preview.previewDigest}"`,
      }),
    );
    expect(JSON.parse(mockFetch.mock.calls[2][1].body)).toEqual({
      challengeId: challenge.challengeId,
      previewDigest: preview.previewDigest,
      idempotencyKey: "idem-3",
    });
    expect(JSON.parse(mockFetch.mock.calls[3][1].body)).toEqual({
      previewDigest: preview.previewDigest,
      elevationId: elevation.elevationId,
      reason: "approved migration",
      idempotencyKey: "idem-4",
    });
    expect(JSON.parse(mockFetch.mock.calls[4][1].body)).toEqual({
      previewDigest: preview.previewDigest,
      elevationId: elevation.elevationId,
      reason: "approved migration",
      idempotencyKey: "idem-5",
      approvalRequestId: "9007199254740993",
    });
    expect(mockFetch.mock.calls[5][0]).toBe(
      "/api/admin/identity/v2/transitions/transition%2Fid/report",
    );
  });

  it("identity clients preserve safe reducer code and remediation evidence", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 409,
        json: async () => ({
          title: "Conflict",
          detail: "identity transition preview is stale",
          code: "BZ235",
          retryable: false,
          remediation: "Generate a new preview and authorize its exact digest.",
        }),
      }),
    );
    await expect(
      adminIdentityTransitionPreview("42", "approved", "idem-2"),
    ).rejects.toThrow(
      "identity transition preview is stale — BZ235 · Generate a new preview and authorize its exact digest.",
    );
  });

  it("identity source clients preserve plan/apply, generation, reason, and secret fences", async () => {
    const document: IdentitySourceDocument = {
      apiVersion: "setjoin.io/v1",
      kind: "IdentitySource",
      metadata: { sourceKey: "corp/ad", displayName: "Corporate AD" },
      spec: { type: "ad" },
    };
    const response = { sourceKey: "corp/ad", state: "draft", generation: "8" };
    const mockFetch = vi.fn().mockImplementation(async () => ({
      ok: true,
      status: 200,
      json: async () => response,
    }));
    vi.stubGlobal("fetch", mockFetch);

    await adminIdentitySourceDetail("corp/ad");
    await adminIdentitySourcePlan(document);
    await adminIdentitySourceApply(
      document,
      "approved source update",
      "source-1",
      "7",
    );
    await adminIdentitySourceActivate(
      "corp/ad",
      "8",
      "approved source activation",
      "source-2",
    );
    await adminIdentitySourceSecret(
      "corp/ad",
      "bind/password",
      "top-secret-test-value",
      "9",
      "approved secret rotation",
      "source-3",
      true,
    );

    expect(mockFetch.mock.calls.map((call) => call[0])).toEqual([
      "/api/admin/identity/v2/sources/corp%2Fad",
      "/api/admin/identity/v2/sources/plan",
      "/api/admin/identity/v2/sources/corp%2Fad",
      "/api/admin/identity/v2/sources/corp%2Fad/activate",
      "/api/admin/identity/v2/sources/corp%2Fad/secrets/bind%2Fpassword/rotate",
    ]);
    expect(mockFetch.mock.calls[2][1]).toEqual(
      expect.objectContaining({
        method: "PUT",
        headers: expect.objectContaining({
          "Idempotency-Key": "source-1",
          "If-Match": '"7"',
          "X-Audit-Reason": "approved source update",
        }),
      }),
    );
    expect(JSON.parse(mockFetch.mock.calls[3][1].body)).toEqual({
      expectedGeneration: "8",
      reason: "approved source activation",
      idempotencyKey: "source-2",
    });
    expect(mockFetch.mock.calls[4][1]).toEqual(
      expect.objectContaining({
        method: "POST",
        body: "top-secret-test-value",
        headers: expect.objectContaining({
          "Content-Type": "application/octet-stream",
          "Idempotency-Key": "source-3",
          "If-Match": '"9"',
          "X-Audit-Reason": "approved secret rotation",
          "X-Identity-Reason": "approved secret rotation",
        }),
      }),
    );
  });

  it("identity detail, conflict decision, and upgrade status use stable IDs and exact generations", async () => {
    const conflict: IdentityConflictDetail = {
      id: "candidate/id",
      source: {
        sourceKey: "legacy:ad",
        displayName: "Legacy AD",
        kind: "ad",
        state: "active",
        generation: "4",
      },
      subjectFingerprint: "fingerprint",
      evidenceClass: "immutable",
      evidenceDigest: "digest",
      explanation: "immutable anchor match",
      state: "pending",
      generation: "5",
      createdAt: "2026-07-25T00:00:00Z",
      expiresAt: "2026-07-26T00:00:00Z",
      allowedDecisions: ["link"],
      decisionHistory: [],
    };
    const responses: unknown[] = [
      { userId: "42" },
      conflict,
      { decision: "link", status: "resolved" },
      { schemaVersion: 164, masterEnabled: false },
    ];
    const mockFetch = vi.fn().mockImplementation(async () => ({
      ok: true,
      status: 200,
      json: async () => responses.shift(),
    }));
    vi.stubGlobal("fetch", mockFetch);

    await adminIdentityPersonDetail("42/primary");
    await adminIdentityConflictDetail(conflict.id);
    await adminIdentityConflictDecide(
      conflict,
      "link",
      "approved immutable match",
      "decision-1",
      "42",
    );
    await adminIdentityUpgradeStatus();

    expect(mockFetch.mock.calls.map((call) => call[0])).toEqual([
      "/api/admin/identity/v2/people/42%2Fprimary",
      "/api/admin/identity/v2/conflicts/candidate%2Fid",
      "/api/admin/identity/v2/conflicts/candidate%2Fid/decision",
      "/api/admin/identity/v2/upgrade/status",
    ]);
    expect(mockFetch.mock.calls[2][1].headers).toEqual(
      expect.objectContaining({
        "If-Match": '"5"',
        "Idempotency-Key": "decision-1",
        "X-Audit-Reason": "approved immutable match",
      }),
    );
    expect(JSON.parse(mockFetch.mock.calls[2][1].body)).toEqual({
      decision: "link",
      personId: "42",
      expectedGeneration: "5",
      reason: "approved immutable match",
      idempotencyKey: "decision-1",
    });
  });

  it("transactional upgrade clients bind bounded routes, audit headers, decimal IDs, and failures", async () => {
    const preview: UpgradePreview = {
      preview: {
        releaseId: "release-180",
        targetVersion: "180",
        channel: "enterprise",
        manifestDigest: "a".repeat(64),
        recoverySetId: "11111111-1111-4111-8111-111111111111",
        recoverySetDigest: "b".repeat(64),
        recoverySetExpiresAt: "2026-08-02T00:00:00Z",
        approvalRequired: true,
      },
      previewDigest: "c".repeat(64),
      expiresAt: "2026-08-01T13:00:00Z",
    };
    const intent: UpgradeIntent = {
      intentId: "9007199254740993",
      releaseId: "release-180",
      manifestDigest: "a".repeat(64),
      recoverySetId: preview.preview.recoverySetId,
      recoverySetDigest: preview.preview.recoverySetDigest,
      state: "scheduled",
      stateGeneration: "7",
      reason: "approved production upgrade",
      scheduleAt: "2026-08-02T01:00:00Z",
      expiresAt: "2026-08-02T02:00:00Z",
      result: null,
      events: [],
    };
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ intentId: intent.intentId, state: intent.state }),
      text: async () => "",
    });
    vi.stubGlobal("fetch", mockFetch);
    await adminUpgradeConsole();
    await adminUpgradePreview(
      preview.preview.releaseId,
      intent.reason,
      intent.scheduleAt,
    );
    await adminUpgradeChallenge(
      preview,
      intent.reason,
      intent.scheduleAt,
      "44444444-4444-4444-8444-444444444444",
    );
    await adminUpgradeCompleteChallenge("55555555-5555-4555-8555-555555555555");
    await adminUpgradeRequest(
      preview,
      intent.reason,
      intent.scheduleAt,
      "66666666-6666-4666-8666-666666666666",
      "77777777-7777-4777-8777-777777777777",
    );
    await adminUpgradeIntent(intent.intentId);
    await adminUpgradeCancel(intent, "cancel approved upgrade safely");
    expect(mockFetch.mock.calls.map((call) => call[0])).toEqual([
      "/api/admin/system/upgrades",
      "/api/admin/system/upgrades/preview",
      "/api/admin/system/upgrades/challenges",
      "/api/admin/system/upgrades/challenges/complete",
      "/api/admin/system/upgrades/intents",
      "/api/admin/system/upgrades/intents/9007199254740993",
      "/api/admin/system/upgrades/intents/9007199254740993/cancel",
    ]);
    expect(mockFetch.mock.calls[2][1]).toEqual(
      expect.objectContaining({
        headers: expect.objectContaining({
          "X-Audit-Reason": intent.reason,
          "Idempotency-Key": "44444444-4444-4444-8444-444444444444",
        }),
      }),
    );
    expect(JSON.parse(mockFetch.mock.calls[6][1].body)).toEqual({
      expectedGeneration: "7",
      reason: "cancel approved upgrade safely",
    });
    await expect(adminUpgradeIntent("01")).rejects.toThrow(
      "invalid upgrade intent id",
    );

    const failures: Array<() => Promise<unknown>> = [
      () => adminUpgradeConsole(),
      () => adminUpgradePreview(preview.preview.releaseId, intent.reason, null),
      () =>
        adminUpgradeChallenge(
          preview,
          intent.reason,
          null,
          "44444444-4444-4444-8444-444444444444",
        ),
      () =>
        adminUpgradeCompleteChallenge("55555555-5555-4555-8555-555555555555"),
      () =>
        adminUpgradeRequest(
          preview,
          intent.reason,
          null,
          "66666666-6666-4666-8666-666666666666",
          "77777777-7777-4777-8777-777777777777",
        ),
      () => adminUpgradeIntent(intent.intentId),
      () => adminUpgradeCancel(intent, "cancel approved upgrade safely"),
    ];
    for (const failure of failures) {
      vi.stubGlobal(
        "fetch",
        vi
          .fn()
          .mockResolvedValue({
            ok: false,
            status: 400,
            text: async () => "upgrade denied",
          }),
      );
      await expect(failure()).rejects.toThrow("Request failed (400)");
    }
  });

  it("identity v2 clients cover create, lifecycle, decision, and rollback variants", async () => {
    const document: IdentitySourceDocument = {
      apiVersion: "setjoin.io/v1",
      kind: "IdentitySource",
      metadata: { sourceKey: "corp/ldap", displayName: "Corporate LDAP" },
      spec: { type: "ldap" },
    };
    const preview = {
      transitionId: "transition/variant",
      state: "previewed",
      transitionGeneration: "2",
      previewDigest: "b".repeat(64),
      previewExpiresAt: "2026-07-25T12:05:00Z",
      protected: false,
      recoveryReady: true,
      sourceGeneration: "3",
      linkGeneration: "4",
      lifecycleGeneration: "1",
      replayed: false,
    } satisfies IdentityTransitionPreview;
    const detail = {
      transitionId: preview.transitionId,
      correlationId: "correlation-variant",
      personId: "42",
      type: "directory_to_local",
      state: "failed",
      transitionGeneration: "7",
      previewVersion: "1",
      previewDigest: preview.previewDigest,
      previewExpiresAt: preview.previewExpiresAt,
      protected: false,
      rollback: {
        boundary: "committed",
        previewDigest: "c".repeat(64),
      },
      effects: [
        {
          effectId: "effect/1",
          kind: "auth_sessions",
          state: "failed",
          attemptCount: 1,
          nextAttemptAt: "",
        },
      ],
    } satisfies IdentityTransitionDetail;
    const conflict = {
      id: "candidate/variant",
      source: {
        sourceKey: "corp/ldap",
        displayName: "Corporate LDAP",
        kind: "ldap",
        state: "active",
        generation: "4",
      },
      subjectFingerprint: "fingerprint",
      evidenceClass: "immutable",
      evidenceDigest: "digest",
      explanation: "immutable anchor match",
      state: "pending",
      generation: "5",
      createdAt: "2026-07-25T00:00:00Z",
      expiresAt: "2026-07-26T00:00:00Z",
      allowedDecisions: ["create"],
      decisionHistory: [],
    } satisfies IdentityConflictDetail;
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => detail,
    });
    vi.stubGlobal("fetch", mockFetch);

    await adminIdentitySources("active");
    await adminIdentitySourceApply(document, "create", "create-1");
    await adminIdentitySourceDryRun("corp/ldap", "1", "dry run", "dry-1");
    await adminIdentitySourcePause("corp/ldap", "2", "pause", "pause-1");
    await adminIdentitySourceResume("corp/ldap", "3", "resume", "resume-1");
    await adminIdentitySourceRetire("corp/ldap", "4", "retire", "retire-1");
    await adminIdentitySourceSecret(
      "corp/ldap",
      "bind/password",
      "secret",
      "5",
      "set secret",
      "secret-1",
      false,
    );
    await adminIdentityConflictDecide(
      conflict,
      "create",
      "create person",
      "decision-2",
    );
    await adminIdentityTransitionDetail(detail.transitionId);
    await adminIdentityTransitionApprove(
      detail,
      "elevation-1",
      "approve",
      "approve-1",
    );
    await adminIdentityTransitionDeny(detail, "elevation-1", "deny", "deny-1");
    await adminIdentityTransitionCancel(detail, "cancel", "cancel-1");
    await adminIdentityTransitionRetry(detail, "effect/1", "retry", "retry-1");
    await adminIdentityTransitionRollbackPreview(
      detail,
      "rollback preview",
      "rollback-preview-1",
    );
    await adminIdentityTransitionRollback(
      detail,
      "elevation-2",
      "rollback",
      "rollback-1",
      "approval-1",
    );

    expect(mockFetch.mock.calls[0][0]).toBe(
      "/api/admin/identity/v2/sources?filter=active",
    );
    expect(mockFetch.mock.calls[1][0]).toBe("/api/admin/identity/v2/sources");
    expect(mockFetch.mock.calls[1][1].method).toBe("POST");
    expect(mockFetch.mock.calls[2][0]).toContain("/dry-run");
    expect(mockFetch.mock.calls[3][0]).toContain("/pause");
    expect(mockFetch.mock.calls[4][0]).toContain("/resume");
    expect(mockFetch.mock.calls[5][0]).toContain("/retire");
    expect(mockFetch.mock.calls[6][0]).not.toContain("/rotate");
    expect(JSON.parse(mockFetch.mock.calls[7][1].body)).not.toHaveProperty(
      "personId",
    );
    expect(mockFetch.mock.calls[12][0]).toContain("/effects/effect%2F1/retry");
    expect(mockFetch.mock.calls[14][0]).toContain("/rollback");
  });

  it("identity problem responses keep safe fallbacks and retry evidence", async () => {
    const responses = [
      {
        json: async () => {
          throw new Error("invalid JSON");
        },
      },
      { json: async () => ({ title: "Identity denied" }) },
      {
        json: async () => ({
          detail: "Identity state is busy",
          code: "BZ236",
          retryable: true,
        }),
      },
    ];
    const mockFetch = vi.fn().mockImplementation(async () => ({
      ok: false,
      status: 409,
      ...(responses.shift() ?? { json: async () => ({}) }),
    }));
    vi.stubGlobal("fetch", mockFetch);

    await expect(adminIdentityPeople()).rejects.toThrow(
      "Identity operation failed",
    );
    await expect(adminIdentityConflicts()).rejects.toThrow("Identity denied");
    await expect(adminIdentityTransitions()).rejects.toThrow(
      "Identity state is busy — BZ236 · Retry is safe without changing the request.",
    );
  });

  it("identity rollback refuses a missing rollback preview digest before network I/O", async () => {
    const mockFetch = vi.fn();
    vi.stubGlobal("fetch", mockFetch);
    const detail = {
      transitionId: "transition-no-rollback-preview",
      correlationId: "correlation-id",
      personId: "42",
      type: "directory_to_local",
      state: "failed",
      transitionGeneration: "7",
      previewVersion: "1",
      previewDigest: "d".repeat(64),
      previewExpiresAt: "2026-07-25T12:05:00Z",
      protected: false,
      rollback: { boundary: "committed" },
      effects: [],
    } satisfies IdentityTransitionDetail;
    await expect(
      adminIdentityTransitionRollback(
        detail,
        "elevation-1",
        "rollback",
        "rollback-1",
        "approval-1",
      ),
    ).rejects.toThrow("Rollback preview is missing or stale.");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("adminUserAliases returns parsed list", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => [
        { id: 1, email: "alias@example.com", isPrimary: false },
      ],
    });
    vi.stubGlobal("fetch", mockFetch);

    const data = await adminUserAliases(3);
    expect(data).toHaveLength(1);
    expect(data[0].email).toBe("alias@example.com");
  });

  it("adminUserAddAlias sends POST", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => ({ id: 99 }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const result = await adminUserAddAlias(3, "alias@example.com");
    expect(result.id).toBe(99);
    const opts = mockFetch.mock.calls[0][1];
    expect(opts.method).toBe("POST");
  });

  it("adminUserRemoveAlias sends DELETE", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, status: 204 });
    vi.stubGlobal("fetch", mockFetch);

    await adminUserRemoveAlias(3, 99);
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("/admin/users/3/aliases/99");
    expect(mockFetch.mock.calls[0][1].method).toBe("DELETE");
  });

  it("adminUserQuota returns parsed quota", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        quotaBytes: 1073741824,
        usedBytes: 1048576,
        sendingQuotaDay: 500,
        sendingSentToday: 10,
      }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const data = await adminUserQuota(1);
    expect(data.quotaBytes).toBe(1073741824);
  });

  it("adminUserSetQuota sends PUT", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, status: 204 });
    vi.stubGlobal("fetch", mockFetch);

    await adminUserSetQuota(1, { quotaBytes: 2147483648 });
    const opts = mockFetch.mock.calls[0][1];
    expect(opts.method).toBe("PUT");
    expect(JSON.parse(opts.body)).toEqual({ quotaBytes: 2147483648 });
  });

  it("adminRuleList returns rules", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => [{ id: 1, name: "Test Rule", enabled: true }],
    });
    vi.stubGlobal("fetch", mockFetch);

    const data = await adminRuleList();
    expect(data).toHaveLength(1);
  });

  it("aborts on timeout", async () => {
    const mockFetch = vi.fn().mockImplementation(() => {
      return new Promise((_resolve, reject) => {
        // Never resolves, should be aborted
        setTimeout(() => reject(new Error("should be aborted")), 100);
      });
    });
    vi.stubGlobal("fetch", mockFetch);

    // We can't easily test the timeout without actually waiting 30s,
    // but we can verify AbortController is passed.
    await adminHealth().catch(() => {});
    const opts = mockFetch.mock.calls[0][1];
    expect(opts.signal).toBeInstanceOf(AbortSignal);
  });
});

// ── adminUpdateGroupMappings — X-Audit-Reason header (identity area) ─────────

describe("adminUpdateGroupMappings — X-Audit-Reason header", () => {
  beforeEach(() => {
    vi.stubGlobal("window", { location: { href: "" } });
  });
  afterEach(() => vi.unstubAllGlobals());

  const mappings: GroupMapping[] = [
    { idp_group: "Engineering", admin_role: "super_admin" },
  ];

  it("sends X-Audit-Reason when reason is provided", async () => {
    const mockFetch = vi
      .fn()
      .mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    vi.stubGlobal("fetch", mockFetch);

    await adminUpdateGroupMappings("saml", "okta", mappings, "identity review");

    const [, opts] = mockFetch.mock.calls[0];
    const headers = opts?.headers ?? {};
    expect(headers["X-Audit-Reason"]).toBe("identity review");
  });

  it("does NOT send X-Audit-Reason when no reason provided", async () => {
    const mockFetch = vi
      .fn()
      .mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    vi.stubGlobal("fetch", mockFetch);

    await adminUpdateGroupMappings("saml", "okta", mappings);

    const [, opts] = mockFetch.mock.calls[0];
    const headers = opts?.headers ?? {};
    expect(headers["X-Audit-Reason"]).toBeUndefined();
  });

  // Pure same-origin URL builders (no transport): the migration connect link
  // percent-encodes the caller-supplied cloud selector so it cannot inject
  // query/segment delimiters, and the chat audit evidence CSV is a plain
  // cookie-auth GET under the gateway's /api mux.
  describe("url builders", () => {
    it("getM365ConnectUrl encodes the cloud selector into the connect URL", () => {
      expect(getM365ConnectUrl("global")).toBe(
        "/admin/migration/m365/connect?cloud=global"
      );
      expect(getM365ConnectUrl("china")).toBe(
        "/admin/migration/m365/connect?cloud=china"
      );
      // Delimiter-bearing values cannot cross the query boundary.
      expect(getM365ConnectUrl("global&evil=1")).toBe(
        "/admin/migration/m365/connect?cloud=global%26evil%3D1"
      );
    });

    it("chatChannelAuditCsvUrl targets the audit evidence CSV endpoint", () => {
      expect(chatChannelAuditCsvUrl(7)).toBe(
        "/api/admin/chat-channels/7/audit?format=csv"
      );
    });
  });
});
