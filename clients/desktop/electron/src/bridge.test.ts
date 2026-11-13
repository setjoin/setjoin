import { describe, it, expect } from "vitest";
import {
  buildBridge,
  DESKTOP_CAPABILITIES,
  BRIDGE_VERSION,
  VAULT_VERSION,
} from "./bridge";

// C0 mirror (mailserver/webmail/src/lib/native/types.ts NATIVE_CAPABILITIES).
// Kept in lock-step; the subset test proves desktop advertises only a subset.
const C0_NATIVE_CAPABILITIES = [
  "push",
  "biometric",
  "secureStore",
  "vault",
  "share",
  "pickFile",
  "notify",
  "openExternal",
  "mailDb",
  "deviceProof",
  "driveMirror",
  "drive",
  "recoveryBlob",
];

function recordingInvoke() {
  const calls: Array<{ channel: string; args: unknown[] }> = [];
  const invoke = async (
    channel: string,
    ...args: unknown[]
  ): Promise<unknown> => {
    calls.push({ channel, args });
    switch (channel) {
      case "vault_unlock":
        return true;
      case "pick_file":
        return {
          name: "a.png",
          type: "image/png",
          dataBase64: Buffer.from("hi").toString("base64"),
        };
      case "db_query":
        return '[{"x":1}]';
      case "db_migrate_store":
        return '{"version":2}';
      case "device_proof":
        return { hmac: "deadbeef" };
      default:
        return undefined;
    }
  };
  return { calls, invoke };
}

describe("bridge contract", () => {
  it("defines every SetjoinNativeBridge member (mirrors bridge_js_defines_contract_methods)", () => {
    const b = buildBridge(async () => undefined) as Record<string, unknown>;
    for (const member of [
      "version",
      "capabilities",
      "pushRegister",
      "pushDevicePublicKey",
      "biometricUnlock",
      "secureStore",
      "vault",
      "share",
      "pickFile",
      "notify",
      "openExternal",
      "db",
      "deviceProof",
      "driveMirror",
      "drive",
      "recoveryBlob",
    ]) {
      expect(b[member], `bridge missing ${member}`).toBeDefined();
    }
  });

  it("version is 1 and capabilities is the desktop capability set", () => {
    const b = buildBridge(async () => undefined);
    expect(b.version).toBe(BRIDGE_VERSION);
    expect(b.version).toBe(1);
    expect(b.capabilities).toEqual([
      "secureStore",
      "vault",
      "share",
      "pickFile",
      "notify",
      "openExternal",
      "mailDb",
      "deviceProof",
      "driveMirror",
      "drive",
      "recoveryBlob",
    ]);
  });

  it("DESKTOP_CAPABILITIES ⊆ C0 NATIVE_CAPABILITIES (mirrors the Rust parity test)", () => {
    for (const cap of DESKTOP_CAPABILITIES) {
      expect(C0_NATIVE_CAPABILITIES).toContain(cap);
    }
  });

  it("invokes every known command channel (mirrors bridge_js_invokes_known_commands)", async () => {
    const { calls, invoke } = recordingInvoke();
    const b = buildBridge(invoke);
    await b.secureStore.get("k");
    await b.secureStore.set("k", "v");
    await b.secureStore.remove("k");
    await b.vault.unlock("p");
    await b.vault.isUnlocked();
    await b.vault.listTotp();
    await b.vault.generateTotp("id");
    await b.share({ text: "hi" });
    await b.pickFile();
    await b.notify({ title: "t", body: "b" });
    await b.openExternal("https://x");
    await b.db.open("mail");
    await b.db.isOpen("mail");
    await b.db.exec("mail", "SELECT 1");
    // Authorized one-shot schema-init seam (med-offcore-sqlguard-001 r3).
    await b.db.execSchemaInit("mail", "CREATE TABLE t(x);");
    // E4-I native transaction freeze entries.
    await b.db.transactionBatch("mail", [{ sql: "UPDATE t SET x = ?" }], {
      maxStatements: 64,
      maxParamBytes: 1048576,
    });
    await b.db.migrateStore("mail", 2);
    await b.db.query("mail", "SELECT 1");
    await b.db.wipe("mail");
    await b.recoveryBlob.writeBegin("a".repeat(64), 1);
    await b.recoveryBlob.writeChunk("h", 0, new Uint8Array([1]));
    await b.recoveryBlob.writeCommit("h");
    await b.recoveryBlob.writeAbort("h");
    await b.recoveryBlob.readOpen("a".repeat(64));
    await b.recoveryBlob.readChunk("r", 0, 1);
    await b.recoveryBlob.readClose("r");
    await b.recoveryBlob.ref("a".repeat(64));
    await b.recoveryBlob.unref("a".repeat(64));
    await b.deviceProof({ deviceId: "1", timestamp: "2" });
    await b.driveMirror.status();
    await b.driveMirror.configure({ serverOrigin: "http://x", spaces: [] });
    await b.driveMirror.refreshToken("tok", "2026-01-01T00:00:00Z");
    await b.driveMirror.setPaused(true);
    await b.driveMirror.resync();
    await b.driveMirror.openRoot(1);
    await b.drive.importFile("/tmp/x");
    await b.drive.fetchChunk("http://x", "tok", "deadbeef", 4096);
    await b.drive.pushChunk("http://x", "tok", "deadbeef");
    await b.drive.hasChunk("deadbeef");
    await b.drive.deleteChunks(["deadbeef"]);
    await b.drive.serveStart();
    await b.drive.serveGrant({ size: 0, chunks: [] });
    await b.drive.serveRevoke("/t/abc");

    const channels = new Set(calls.map((c) => c.channel));
    for (const cmd of [
      "secure_store_get",
      "secure_store_set",
      "secure_store_remove",
      "vault_unlock",
      "vault_is_unlocked",
      "vault_list_totp",
      "vault_generate_totp",
      "open_external",
      "pick_file",
      "notify",
      "db_open",
      "db_is_open",
      "db_exec",
      "db_exec_schema_init",
      "db_transaction_batch",
      "db_migrate_store",
      "db_query",
      "db_wipe",
      "device_proof",
      "drive_mirror_status",
      "drive_mirror_configure",
      "drive_mirror_refresh_token",
      "drive_mirror_set_paused",
      "drive_mirror_resync",
      "drive_mirror_open_root",
      "drive_import_file",
      "drive_fetch_chunk",
      "drive_push_chunk",
      "drive_has_chunk",
      "drive_delete_chunks",
      "drive_serve_start",
      "drive_serve_grant",
      "drive_serve_revoke",
    ]) {
      expect(channels, `missing invoke('${cmd}')`).toContain(cmd);
    }
  });

  it("driveMirror carries its own sub-shape version (DRIVE_MIRROR_VERSION)", () => {
    const b = buildBridge(async () => undefined);
    expect(b.driveMirror.version).toBe(3);
  });

  it("honest desktop answers: push→null, biometric→false, isEnrolled→false", async () => {
    const b = buildBridge(async () => undefined);
    expect(await b.pushRegister()).toBeNull();
    expect(await b.pushDevicePublicKey()).toBeNull();
    expect(await b.biometricUnlock("r")).toBe(false);
    expect(await b.vault.unlockBiometric()).toBe(false);
    expect(await b.vault.isEnrolled()).toBe(false);
  });

  it("unlockPassphrase aliases vault_unlock (the closed Tauri drift)", async () => {
    const { calls, invoke } = recordingInvoke();
    const b = buildBridge(invoke);
    expect(await b.vault.unlockPassphrase("secret")).toBe(true);
    expect(calls).toContainEqual({ channel: "vault_unlock", args: ["secret"] });
  });

  it("vault carries its own sub-shape version (C2 Task 2 Step 3b)", async () => {
    const b = buildBridge(async () => undefined);
    expect(b.vault.version).toBe(VAULT_VERSION);
  });

  it("share falls back to a mailto: via open_external", async () => {
    const { calls, invoke } = recordingInvoke();
    const b = buildBridge(invoke);
    await b.share({ title: "Hi", text: "body", url: "https://x" });
    const call = calls.find((c) => c.channel === "open_external");
    expect(call).toBeDefined();
    const url = String(call!.args[0]);
    expect(url.startsWith("mailto:?subject=Hi")).toBe(true);
    expect(url).toContain(encodeURIComponent("body https://x"));
  });

  it("db.query JSON-parses the native string result", async () => {
    const { invoke } = recordingInvoke();
    const b = buildBridge(invoke);
    expect(await b.db.query("mail", "SELECT 1")).toEqual([{ x: 1 }]);
  });

  it("E4-I entries: transactionBatch forwards the batch, migrateStore parses the version", async () => {
    const { calls, invoke } = recordingInvoke();
    const b = buildBridge(invoke);
    const statements = [{ sql: "UPDATE t SET x = ?", params: [1] }];
    const budget = { maxStatements: 64, maxParamBytes: 1048576 };
    const changed = await b.db.transactionBatch("mail", statements, budget);
    expect(changed).toBeUndefined(); // recording invoke answers undefined
    expect(calls.find((c) => c.channel === "db_transaction_batch")?.args).toEqual([
      "mail",
      statements,
      budget,
    ]);
    // migrateStore parses the native {"version":N} JSON like db.query does.
    expect(await b.db.migrateStore("mail", 2)).toEqual({ version: 2 });
    expect(calls.find((c) => c.channel === "db_migrate_store")?.args).toEqual(["mail", 2]);
  });

  // ER5 occ_84092b66054634ea88d3b489 / occ_f10aa5892bfc1a7769b17b49: the
  // renderer-supplied drive bearer never crosses the bridge — the parameter
  // stays (renderer contract shape is fixed) but `null` is what reaches the
  // main-process handler, which in turn credentials transfers only from its
  // own DriveTokenOwner.
  it("drive chunk transfers forward a null bearer, never the renderer-supplied credential", async () => {
    const { calls, invoke } = recordingInvoke();
    const b = buildBridge(invoke);
    await b.drive.fetchChunk("https://gw.example.org/chunk", "renderer-secret", "deadbeef", 4096);
    await b.drive.pushChunk("https://gw.example.org/chunk", "renderer-secret", "deadbeef");
    const fetch = calls.find((c) => c.channel === "drive_fetch_chunk");
    const push = calls.find((c) => c.channel === "drive_push_chunk");
    expect(fetch).toBeDefined();
    expect(push).toBeDefined();
    expect(fetch!.args).toEqual(["https://gw.example.org/chunk", null, "deadbeef", 4096]);
    expect(push!.args).toEqual(["https://gw.example.org/chunk", null, "deadbeef"]);
    for (const call of [fetch!, push!]) {
      expect(JSON.stringify(call.args)).not.toContain("renderer-secret");
    }
  });

  it("pickFile reconstructs a File from the base64 result", async () => {
    const { invoke } = recordingInvoke();
    const b = buildBridge(invoke);
    const f = await b.pickFile();
    expect(f).toBeInstanceOf(File);
    expect(f!.name).toBe("a.png");
    expect(f!.type).toBe("image/png");
    expect(await f!.text()).toBe("hi");
  });
});
