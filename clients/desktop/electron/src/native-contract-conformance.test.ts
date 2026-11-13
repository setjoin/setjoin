import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it, vi } from "vitest";

const ipcHandlers = new Map<string, (...args: unknown[]) => unknown>();
vi.mock("electron", () => ({
  ipcMain: {
    handle: (channel: string, handler: (...args: unknown[]) => unknown) =>
      ipcHandlers.set(channel, handler),
  },
}));

import { buildBridge } from "./bridge";
import {
  _resetForTest,
  configureAllowedOrigins,
  registerHandlers,
  registeredChannelList,
} from "./ipc";
import type { NativeBinding } from "./native";
import { makeVaultHandlers } from "./handlers/vault";
import { makeSecureStoreHandlers } from "./handlers/securestore";
import { makeDbHandlers } from "./handlers/db";
import { makeRecoveryBlobHandlers } from "./handlers/recoveryBlob";
import { makeDriveHandlers } from "./handlers/drive";
import { makeOsHandlers } from "./handlers/os";
import { makeMamHandlers } from "./mam";
import {
  makeDriveMirrorHandlers,
  type MirrorService,
} from "./drive/service";

interface ContractGroup {
  required: string[];
  optional: string[];
}

interface ContractFixture {
  authority: string;
  groups: Record<string, ContractGroup>;
}

const contractPath = fileURLToPath(
  new URL(
    "../../../../mailserver/webmail/src/lib/native/testdata/contract-members.generated.json",
    import.meta.url,
  ),
);
const contract = JSON.parse(
  fs.readFileSync(contractPath, "utf8"),
) as ContractFixture;

const groupProperty: Record<string, string> = {
  SecureStore: "secureStore",
  VaultBridge: "vault",
  OfflineDbBridge: "db",
  RecoveryBlobBridge: "recoveryBlob",
  DriveMirrorBridge: "driveMirror",
  DriveBridge: "drive",
};

function nativeStub(): NativeBinding {
  return new Proxy(
    {},
    {
      get: (_target, property) => {
        if (property === "recoveryBlobWriteBegin")
          return () => '{"handle":"h","nextOffset":0}';
        if (property === "recoveryBlobReadOpen")
          return () => '{"handle":"h","size":1}';
        if (property === "driveImportFile" || property === "driveServeStart")
          return async () => "{}";
        if (property === "driveFetchChunk" || property === "drivePushChunk")
          return async () => undefined;
        return () => undefined;
      },
    },
  ) as NativeBinding;
}

function registerProductionHandlerMaps(): Set<string> {
  const native = nativeStub();
  registerHandlers(makeVaultHandlers(native, "/tmp/setjoin-contract"));
  registerHandlers(makeSecureStoreHandlers(native));
  registerHandlers(makeDbHandlers(native, "/tmp/setjoin-contract"));
  registerHandlers(makeRecoveryBlobHandlers(native));
  registerHandlers(makeDriveHandlers(native));
  registerHandlers(
    makeOsHandlers({
      showNotification: () => undefined,
      pickFilePath: async () => null,
      openExternalUrl: async () => undefined,
    }),
  );
  registerHandlers(
    makeMamHandlers(native, { clearStorage: async () => undefined }),
  );
  registerHandlers(makeDriveMirrorHandlers({} as MirrorService));
  return new Set(registeredChannelList());
}

function assertMembers(
  label: string,
  value: Record<string, unknown>,
  expected: ContractGroup,
): void {
  for (const member of expected.required) {
    expect(value[member], `${label} missing ${member}`).toBeDefined();
  }
  const allowed = new Set([...expected.required, ...expected.optional]);
  for (const member of Object.keys(value)) {
    expect(allowed.has(member), `${label} exposes unknown ${member}`).toBe(true);
  }
}

function argsFor(path: string, arity: number): unknown[] {
  if (path === "deviceProof") return [{ deviceId: "1", timestamp: "2" }];
  if (path === "share") return [{}];
  if (path === "notify") return [{ title: "contract" }];
  if (path === "driveMirror.configure")
    return [{ serverOrigin: "https://setjoin.invalid", spaces: [] }];
  if (path === "recoveryBlob.writeChunk")
    return ["handle", 0, new Uint8Array([1])];
  return Array.from({ length: arity }, () => "x");
}

async function exerciseProjectedMethods(
  bridge: Record<string, unknown>,
): Promise<string[]> {
  const invoked: string[] = [];
  const recordingInvoke = async (channel: string): Promise<unknown> => {
    invoked.push(channel);
    if (channel === "db_query") return "[]";
    if (channel === "pick_file") return null;
    return undefined;
  };
  const executable = buildBridge(recordingInvoke) as Record<string, unknown>;

  for (const member of contract.groups.SetjoinNativeBridge.required) {
    const value = executable[member];
    if (typeof value === "function") {
      await value(...argsFor(member, value.length));
    }
  }
  for (const [interfaceName, property] of Object.entries(groupProperty)) {
    const group = executable[property] as Record<string, unknown> | undefined;
    if (!group) continue;
    for (const member of contract.groups[interfaceName].required) {
      const value = group[member];
      if (typeof value === "function") {
        await value(...argsFor(`${property}.${member}`, value.length));
      }
    }
  }
  expect(bridge).toBeDefined();
  return invoked;
}

beforeEach(() => {
  ipcHandlers.clear();
  _resetForTest();
  configureAllowedOrigins(["file:///setjoin/index.html"]);
});

describe("generated native contract against Electron production seams", () => {
  it("buildBridge exposes the generated authority shape", () => {
    const bridge = buildBridge(async () => undefined) as Record<string, unknown>;
    assertMembers(
      "SetjoinNativeBridge",
      bridge,
      contract.groups.SetjoinNativeBridge,
    );
    for (const [interfaceName, property] of Object.entries(groupProperty)) {
      const group = bridge[property] as Record<string, unknown> | undefined;
      expect(group, `Electron is expected to implement ${property}`).toBeDefined();
      assertMembers(interfaceName, group!, contract.groups[interfaceName]);
    }
  });

  it("every generated callable dispatches only to a production-registered IPC channel", async () => {
    const registered = registerProductionHandlerMaps();
    const bridge = buildBridge(async () => undefined) as Record<string, unknown>;
    const invoked = await exerciseProjectedMethods(bridge);
    expect(invoked.length).toBeGreaterThan(0);
    for (const channel of invoked) {
      expect(
        registered.has(channel),
        `buildBridge invokes unregistered IPC channel ${channel}`,
      ).toBe(true);
    }
  });
});
