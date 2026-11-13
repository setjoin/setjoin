import {
  test,
  expect,
  type Page,
  type APIRequestContext,
} from "@playwright/test";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { apiLogin, apiToken, loginAsAdmin, psql, setFeature } from "./helpers";
import { TEST_USERS } from "./fixtures/test-data";

const exec = promisify(execFile);
const live = process.env.E2E_MANAGED_OFFICE === "1";
const externalRunner = process.env.E2E_MANAGED_OFFICE_EXTERNAL_RUNNER === "1";
const root = resolve(import.meta.dirname, "../../..");
const updater =
  process.env.SETJOIN_UPDATER_BIN ??
  join(
    tmpdir(),
    `setjoin-e2e-${process.env.E2E_DB_NAME ?? "mailserver_e2e"}-${process.env.E2E_GATEWAY_PORT ?? "8080"}`,
    "setjoin-updater",
  );
const workerCredentials = "setjoin_worker:" + "e2e-worker@";
const workerDSN =
  process.env.E2E_OFFICE_WORKER_DSN ??
  `postgres://${workerCredentials}${process.env.E2E_PGHOST ?? "127.0.0.1"}:${process.env.E2E_PGPORT ?? "5432"}/${process.env.E2E_DB_NAME ?? "mailserver_e2e"}?sslmode=disable`;

async function docker(...args: string[]) {
  return exec("docker", args, { timeout: 120_000 });
}

async function cleanupRuntime() {
  await docker("container", "rm", "--force", "setjoin-collabora-code").catch(
    () => null,
  );
  await docker("network", "rm", "setjoin-office").catch(() => null);
  await docker("volume", "rm", "setjoin-collabora-config").catch(() => null);
}

const MIME =
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

async function minimalDocx(): Promise<Buffer> {
  const dir = await mkdtemp(join(tmpdir(), "setjoin-code-docx-"));
  await mkdir(join(dir, "_rels"));
  await mkdir(join(dir, "word", "_rels"), { recursive: true });
  await writeFile(
    join(dir, "[Content_Types].xml"),
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
  );
  await writeFile(
    join(dir, "_rels", ".rels"),
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
  );
  await writeFile(
    join(dir, "word", "_rels", "document.xml.rels"),
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>`,
  );
  await writeFile(
    join(dir, "word", "document.xml"),
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Setjoin Collabora E2E baseline</w:t></w:r></w:p><w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr></w:body></w:document>`,
  );
  const path = join(dir, "baseline.docx");
  await exec(
    "zip",
    ["-q", "-r", path, "[Content_Types].xml", "_rels", "word"],
    { cwd: dir },
  );
  return readFile(path);
}

function discoveryEditorURL(xml: string): string {
  const actions = xml.match(/<action\b[^>]*>/g) ?? [];
  const action = actions.find(
    (tag) => /ext="docx"/.test(tag) && /name="edit"/.test(tag),
  );
  const encoded = action?.match(/urlsrc="([^"]+)"/)?.[1];
  if (!encoded)
    throw new Error("Collabora discovery lacks the DOCX edit action");
  return encoded.replaceAll("&amp;", "&");
}

async function openEditor(
  page: Page,
  launch: { editorUrl: string; accessToken: string },
) {
  page.setDefaultTimeout(10_000);
  await page.goto("about:blank");
  await page.evaluate(({ editorUrl, accessToken }) => {
    const form = document.createElement("form");
    form.method = "POST";
    form.action = editorUrl;
    for (const [name, value] of Object.entries({
      access_token: accessToken,
      access_token_ttl: String(Date.now() + 28_800_000),
    })) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = value;
      form.append(input);
    }
    document.body.append(form);
    form.submit();
  }, launch);
  await page.waitForURL(/127[.]0[.]0[.]1:9980\/browser\//, { timeout: 90_000 });
  await expect(page.locator("#document-container")).toBeVisible({
    timeout: 90_000,
  });
  await expect(
    page.getByText("Your session has expired", { exact: false }),
  ).toHaveCount(0);
  await page.keyboard.press("Escape");
  await page.keyboard.press("Escape");
  const welcomeClose = page
    .locator(".ui-dialog-titlebar-close, .lokdialog_container .close-button")
    .first();
  if (await welcomeClose.isVisible().catch(() => false)) {
    await welcomeClose.click({ force: true });
  }
  const welcomeText = page.getByText(
    "Enjoy the latest developments in online productivity",
    { exact: false },
  );
  if (await welcomeText.isVisible().catch(() => false)) {
    const modalBox = await welcomeText.evaluate((node) => {
      let current: HTMLElement | null = node as HTMLElement;
      while (current) {
        const rect = current.getBoundingClientRect();
        if (rect.width > 500 && rect.height > 300) {
          return {
            x: rect.x,
            y: rect.y,
            width: rect.width,
            height: rect.height,
          };
        }
        current = current.parentElement;
      }
      return null;
    });
    if (!modalBox)
      throw new Error("Collabora welcome surface has no modal box");
    await page.mouse.click(modalBox.x + modalBox.width - 28, modalBox.y + 28);
    await expect(welcomeText).toBeHidden();
  }
}

async function editDocument(page: Page, marker: string) {
  const canvas = page.locator("#document-canvas");
  const box = await canvas.boundingBox();
  if (!box) throw new Error("Collabora document canvas has no layout box");
  await page.mouse.click(
    box.x + Math.min(220, box.width / 4),
    box.y + Math.min(110, box.height / 4),
  );
  await page
    .locator("#clipboard-area")
    .evaluate((node: HTMLElement) => node.focus());
  expect(await page.evaluate(() => document.activeElement?.id)).toBe(
    "clipboard-area",
  );
  expect(
    await page.locator("#clipboard-area").getAttribute("aria-disabled"),
  ).not.toBe("true");
  await page.keyboard.press("Control+End");
  await page.keyboard.press("Enter");
  await page.keyboard.type(marker, { delay: 35 });
}

async function launch(
  request: APIRequestContext,
  token: string,
  fileId: number,
  baseVersionId: number,
  deviceId: string,
  cohortKey = `file-${fileId}`,
) {
  const response = await request.post(
    `/api/drive/files/${fileId}/office/launches`,
    {
      headers: { Authorization: `Bearer ${token}` },
      data: {
        baseVersionId,
        providerId: "collabora",
        deviceId,
        cohortKey,
      },
    },
  );
  expect(
    response.status(),
    `launch ${deviceId}: ${await response.text()}`,
  ).toBe(201);
  return response.json() as Promise<{
    launchId: string;
    sessionId: string;
    accessToken: string;
    editorUrl: string;
  }>;
}

test.describe("Managed Collabora install continuity @admin", () => {
  test.skip(
    !live,
    "set E2E_MANAGED_OFFICE=1 for the real Docker installation lane",
  );

  test.afterEach(async ({ request }) => {
    if (!externalRunner) await cleanupRuntime();
    const token = await apiToken(
      request,
      TEST_USERS.admin.email,
      TEST_USERS.admin.password,
    ).catch(() => "");
    if (token)
      await setFeature(
        request,
        token,
        "feature.office_managed_delivery",
        false,
      ).catch(() => null);
  });

  test("admin card installs the pinned image through reducer queue and updater runner", async ({
    page,
    request,
  }) => {
    test.setTimeout(12 * 60_000);
    if (!externalRunner) await cleanupRuntime();
    const adminToken = await apiToken(
      request,
      TEST_USERS.admin.email,
      TEST_USERS.admin.password,
    );
    await setFeature(
      request,
      adminToken,
      "feature.office_managed_delivery",
      true,
    );

    const configured = await request.put(
      "/api/admin/office/providers/collabora",
      {
        headers: {
          Authorization: `Bearer ${adminToken}`,
          "X-Audit-Reason": "E2E managed Collabora provider preflight",
        },
        data: {
          expectedGeneration: 0,
          profile: "managed-customer-proxy",
          entitlementState: "unknown",
          buildId: "e2e-managed-code",
          config: {
            profile: "managed-customer-proxy",
            proofMode: "test_disabled",
            proofDiscoveryUrl: "http://127.0.0.1:9980/hosting/discovery",
            wopiPublicBaseUrl: `http://host.docker.internal:${process.env.E2E_GATEWAY_PORT ?? "8188"}`,
            editorUrl: "http://127.0.0.1:9980/browser/bootstrap/cool.html?",
            privateAllowHosts: ["127.0.0.1", "host.docker.internal"],
            privateAllowCidrs: [],
          },
        },
      },
    );
    expect(
      configured.ok(),
      `configure provider: ${await configured.text()}`,
    ).toBeTruthy();

    await loginAsAdmin(page);
    await page.goto("/admin/apps");
    await expect(
      page.getByRole("heading", { name: "Applications" }),
    ).toBeVisible();
    await expect(
      page.getByText("Collabora CODE", { exact: true }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Install", exact: true }).click();
    await expect(
      page.getByRole("dialog", { name: "Install Collabora CODE test editor" }),
    ).toBeVisible();
    await page.getByLabel("Final editor hostname").fill("office.e2e.invalid");
    await page
      .getByLabel("Audit reason")
      .fill("E2E install pinned Collabora CODE");
    await page.getByRole("button", { name: "Install test editor" }).click();
    await expect(page.getByText(/install · requested/i)).toBeVisible();

    if (!externalRunner) {
      const runDir = await mkdtemp(
        join(tmpdir(), "setjoin-office-install-e2e-"),
      );
      const dsnFile = join(runDir, "worker-dsn");
      const appStateDir = join(runDir, "app-state");
      await writeFile(dsnFile, `${workerDSN}\n`, { mode: 0o600 });
      const result = await exec(
        updater,
        [
          "--once",
          "--office-app-execution",
          "--office-app-only",
          "--office-app-test-direct-http",
          "--office-app-worker-dsn-file",
          dsnFile,
          "--office-app-manifest",
          join(root, "config/office-managed-app-v1.json"),
          "--office-app-state-dir",
          appStateDir,
          "--executor-id",
          "e2e-office-installer",
        ],
        { timeout: 10 * 60_000, maxBuffer: 4 * 1024 * 1024 },
      );
      expect(result.stderr).not.toContain("managed app attempt failed");
    }

    await expect
      .poll(
        async () => {
          const response = await request.get("/api/admin/apps", {
            headers: { Authorization: `Bearer ${adminToken}` },
          });
          if (!response.ok()) return `http-${response.status()}`;
          const state = (await response.json()) as {
            operations: Array<{ state: string }>;
          };
          return state.operations[0]?.state ?? "missing";
        },
        { timeout: externalRunner ? 10 * 60_000 : 30_000 },
      )
      .toBe("connected_inactive");
    await page.reload();
    await expect(
      page.getByText("install · installed_inactive", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText("connected_inactive", { exact: true }),
    ).toBeVisible();
    const discovery = await request.get(
      "http://127.0.0.1:9980/hosting/discovery",
    );
    expect(discovery.status()).toBe(200);
    const discoveryXML = await discovery.text();
    expect(discoveryXML).toContain("urlsrc");
    const editorUrl = discoveryEditorURL(discoveryXML);
    const manifest = JSON.parse(
      await readFile(join(root, "config/office-managed-app-v1.json"), "utf8"),
    ) as { digest: string };
    const appsResponse = await request.get("/api/admin/apps", {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    expect(
      appsResponse.ok(),
      `list app revisions: ${await appsResponse.text()}`,
    ).toBeTruthy();
    const appState = (await appsResponse.json()) as {
      revisions: Array<{ imageDigest: string }>;
    };
    expect(appState.revisions[0]?.imageDigest).toBe(manifest.digest);

    const reconfigured = await request.put(
      "/api/admin/office/providers/collabora",
      {
        headers: {
          Authorization: `Bearer ${adminToken}`,
          "X-Audit-Reason": "Bind live CODE discovery action",
        },
        data: {
          expectedGeneration: 1,
          profile: "managed-customer-proxy",
          entitlementState: "evaluation",
          buildId: "e2e-managed-code",
          config: {
            profile: "managed-customer-proxy",
            proofMode: "test_disabled",
            proofDiscoveryUrl: "http://127.0.0.1:9980/hosting/discovery",
            wopiPublicBaseUrl: `http://host.docker.internal:${process.env.E2E_GATEWAY_PORT ?? "8188"}`,
            editorUrl,
            privateAllowHosts: ["127.0.0.1", "host.docker.internal"],
            privateAllowCidrs: [],
          },
        },
      },
    );
    expect(
      reconfigured.ok(),
      `reconfigure live CODE: ${await reconfigured.text()}`,
    ).toBeTruthy();

    const aliceToken = await apiToken(
      request,
      TEST_USERS.alice.email,
      TEST_USERS.alice.password,
    );
    const bobToken = await apiToken(
      request,
      TEST_USERS.bob.email,
      TEST_USERS.bob.password,
    );
    const source = await minimalDocx();
    const sourceSha = createHash("sha256").update(source).digest("hex");
    const spaceResponse = await request.post("/api/drive/spaces", {
      headers: { Authorization: `Bearer ${aliceToken}` },
      data: { name: `Live CODE ${Date.now()}`, classification: "regular" },
    });
    expect(spaceResponse.status(), await spaceResponse.text()).toBe(201);
    const spaceId = ((await spaceResponse.json()) as { id: number }).id;
    const nodeResponse = await request.post("/api/drive/nodes", {
      headers: { Authorization: `Bearer ${aliceToken}` },
      data: {
        spaceId,
        parentId: null,
        kind: "file",
        name: "collabora-live.docx",
        contentType: MIME,
      },
    });
    expect(nodeResponse.status(), await nodeResponse.text()).toBe(201);
    const fileId = ((await nodeResponse.json()) as { id: number }).id;
    expect(
      (
        await request.put(`/api/drive/chunks/${sourceSha}?space=${spaceId}`, {
          headers: { Authorization: `Bearer ${aliceToken}` },
          data: source,
        })
      ).ok(),
    ).toBeTruthy();
    const versionResponse = await request.post(
      `/api/drive/files/${fileId}/versions`,
      {
        headers: { Authorization: `Bearer ${aliceToken}` },
        data: {
          contentSha256: sourceSha,
          size: source.length,
          contentType: MIME,
          baseVersionId: null,
          manifest: [{ sha256: sourceSha, size: source.length }],
        },
      },
    );
    expect(versionResponse.status(), await versionResponse.text()).toBe(201);
    const baseVersionId = (
      (await versionResponse.json()) as { versionId: number }
    ).versionId;
    const aliceId = psql(
      `SELECT id FROM users WHERE email='${TEST_USERS.alice.email.replaceAll("'", "''")}'`,
    );
    const bobId = psql(
      `SELECT id FROM users WHERE email='${TEST_USERS.bob.email.replaceAll("'", "''")}'`,
    );
    const adminId = psql(
      `SELECT id FROM users WHERE email='${TEST_USERS.admin.email.replaceAll("'", "''")}'`,
    );
    psql(`SELECT drive_member_grant(${aliceId},${spaceId},${bobId},'editor')`);

    psql(`WITH s AS (
			INSERT INTO office_editor_sessions(space_id,file_node_id,base_version_id,provider_id,cohort_key,status,lease_expires_at)
			VALUES(${spaceId},${fileId},${baseVersionId},'collabora','qualification-e2e','closed',now()+interval '1 hour') RETURNING id)
			INSERT INTO office_save_receipts(session_id,space_id,file_node_id,provider_id,operation_key,expected_base_id,content_sha256,result_version_id,response_class)
			SELECT id,${spaceId},${fileId},'collabora','qualification-e2e',${baseVersionId},'${sourceSha}',${baseVersionId},'accepted' FROM s`);
    const receiptId = psql(
      `SELECT id FROM office_save_receipts WHERE provider_id='collabora' AND operation_key='qualification-e2e'`,
    );
    const configSha = psql(
      `SELECT config_sha256 FROM office_provider_policies WHERE provider_id='collabora'`,
    );
    const qualification =
      psql(`SELECT office_provider_qualify(${adminId},'collabora',2,'managed-customer-proxy','${configSha}',
			'{"discovery":"pass","proof":"pass","editor":"pass","wopiSave":"pass"}'::jsonb,
			'${createHash("sha256").update(discoveryXML).digest("hex")}','${manifest.digest}',1,${receiptId},'Live CODE E2E qualification')`);
    const qualificationId = (
      JSON.parse(qualification) as { qualificationId: string }
    ).qualificationId;
    psql(
      `SELECT office_provider_activate(${adminId},'collabora',2,'${qualificationId}'::uuid,'{}'::jsonb,'Live CODE E2E activation')`,
    );

    const aliceLaunch = await launch(
      request,
      aliceToken,
      fileId,
      baseVersionId,
      "alice-live-code",
    );
    const bobLaunch = await launch(
      request,
      bobToken,
      fileId,
      baseVersionId,
      "bob-live-code",
    );
    expect(
      bobLaunch.sessionId,
      "two users join one reducer-authoritative cohort",
    ).toBe(aliceLaunch.sessionId);
    const staleLaunch = await launch(
      request,
      aliceToken,
      fileId,
      baseVersionId,
      "alice-stale-conflict",
      `stale-file-${fileId}`,
    );

    const aliceEditor = await page.context().newPage();
    const bobEditor = await page.context().newPage();
    await Promise.all([
      openEditor(aliceEditor, aliceLaunch),
      openEditor(bobEditor, bobLaunch),
    ]);
    await editDocument(aliceEditor, "ALICE-LIVE-CODE");
    await aliceEditor.waitForTimeout(1500);
    await editDocument(bobEditor, "BOB-LIVE-CODE");
    await bobEditor.keyboard.press("Control+s");
    await bobEditor.mouse.click(54, 18);

    await expect
      .poll(
        () =>
          Number(
            psql(
              `SELECT count(*) FROM drive_file_versions WHERE file_node_id=${fileId}`,
            ),
          ),
        { timeout: 90_000, intervals: [1000, 2000, 5000] },
      )
      .toBeGreaterThan(1);
    const latestVersionId = Number(
      psql(`SELECT head_version_id FROM drive_files WHERE node_id=${fileId}`),
    );
    const latest = await request.get(
      `/api/drive/versions/${latestVersionId}/content`,
      {
        headers: {
          Authorization: `Bearer ${aliceToken}`,
          "X-Setjoin-Drive-Export": "acknowledged",
        },
      },
    );
    expect(
      latest.ok(),
      `download saved CODE version: ${await latest.text()}`,
    ).toBeTruthy();
    const savedDir = await mkdtemp(join(tmpdir(), "setjoin-code-saved-"));
    const savedPath = join(savedDir, "saved.docx");
    await writeFile(savedPath, await latest.body());
    const { stdout: documentXML } = await exec("unzip", [
      "-p",
      savedPath,
      "word/document.xml",
    ]);
    expect(documentXML).toContain("ALICE-LIVE-CODE");
    expect(documentXML).toContain("BOB-LIVE-CODE");
    await Promise.all([aliceEditor.close(), bobEditor.close()]);
    await page.waitForTimeout(2000);

    const staleSave = await request.post(
      `/api/office/wopi/files/${fileId}/contents?access_token=${encodeURIComponent(staleLaunch.accessToken)}`,
      {
        headers: {
          "X-Setjoin-Operation-Key": "live-code-stale-save",
          "Content-Type": "application/octet-stream",
        },
        data: source,
      },
    );
    expect(staleSave.ok(), await staleSave.text()).toBeTruthy();
    expect((await staleSave.json()) as { conflict: boolean }).toMatchObject({
      conflict: true,
    });
    expect(
      Number(
        psql(
          `SELECT count(*) FROM drive_file_branches WHERE file_node_id=${fileId}`,
        ),
      ),
    ).toBeGreaterThan(0);
    const historyResponse = await request.get(
      `/api/drive/files/${fileId}/history?limit=100`,
      { headers: { Authorization: `Bearer ${aliceToken}` } },
    );
    expect(historyResponse.ok(), await historyResponse.text()).toBeTruthy();
    const history = (await historyResponse.json()) as {
      items: Array<{ source: string; kind: string }>;
    };
    expect(history.items).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ source: "office", kind: "office.save" }),
        expect.objectContaining({
          source: "office",
          kind: "office.save.branch",
        }),
        expect.objectContaining({ source: "branch", kind: "branch.created" }),
      ]),
    );
  });
});
