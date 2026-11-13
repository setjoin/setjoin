#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import vm from "node:vm";
import { createRequire } from "node:module";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const AUTHORITY = path.join(
  ROOT,
  "mailserver/webmail/src/lib/native/types.ts",
);
const TSCONFIG = path.join(ROOT, "mailserver/webmail/tsconfig.json");
const GENERATED = path.join(
  ROOT,
  "mailserver/webmail/src/lib/native/testdata/contract-members.generated.json",
);
const ELECTRON_BRIDGE = path.join(
  ROOT,
  "clients/desktop/electron/src/bridge.ts",
);
const TAURI_BRIDGE = path.join(
  ROOT,
  "clients/desktop/src-tauri/src/bridge_js.rs",
);
const HARMONY_MAIN = path.join(
  ROOT,
  "clients/harmonyos/entry/src/main/ets/pages/MainPage.ets",
);
const HARMONY_PROXY = path.join(
  ROOT,
  "clients/harmonyos/entry/src/main/ets/native/BridgeProxy.ets",
);
const HARMONY_SHIM = path.join(
  ROOT,
  "clients/harmonyos/entry/src/main/ets/native/BridgeShim.ets",
);

const require = createRequire(import.meta.url);
const ts = require(
  path.join(ROOT, "mailserver/webmail/node_modules/typescript/lib/typescript.js"),
);

const GROUP_PROPERTIES = new Map([
  ["secureStore", "SecureStore"],
  ["vault", "VaultBridge"],
  ["db", "OfflineDbBridge"],
  ["recoveryBlob", "RecoveryBlobBridge"],
  ["driveMirror", "DriveMirrorBridge"],
  ["drive", "DriveBridge"],
]);

const CAPABILITY_REQUIREMENTS = new Map([
  ["push", ["pushRegister", "pushDevicePublicKey"]],
  ["biometric", ["biometricUnlock", "vault.unlockBiometric", "vault.isEnrolled"]],
  ["secureStore", ["secureStore"]],
  ["vault", ["vault"]],
  ["share", ["share"]],
  ["pickFile", ["pickFile"]],
  ["notify", ["notify"]],
  ["openExternal", ["openExternal"]],
  ["mailDb", ["db"]],
  ["deviceProof", ["deviceProof"]],
  ["driveMirror", ["driveMirror"]],
  ["drive", ["drive"]],
  ["recoveryBlob", ["recoveryBlob"]],
]);

class ContractError extends Error {}

function fail(message) {
  throw new ContractError(`E_NATIVE_CONTRACT_STALE: ${message}`);
}

function relative(file) {
  return path.relative(ROOT, file);
}

function diagnosticText(diagnostic) {
  const message = ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
  if (!diagnostic.file || diagnostic.start === undefined) return message;
  const pos = diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start);
  return `${relative(diagnostic.file.fileName)}:${pos.line + 1}:${pos.character + 1}: ${message}`;
}

function propertyName(node) {
  if (!node) return null;
  if (ts.isIdentifier(node) || ts.isStringLiteral(node)) return node.text;
  fail(
    `unsupported computed member in ${relative(AUTHORITY)}; ` +
      "use an identifier or string literal so the projection fails closed",
  );
}

function readContract() {
  const configRead = ts.readConfigFile(TSCONFIG, ts.sys.readFile);
  if (configRead.error) fail(`TypeScript config diagnostic: ${diagnosticText(configRead.error)}`);
  const parsed = ts.parseJsonConfigFileContent(
    configRead.config,
    ts.sys,
    path.dirname(TSCONFIG),
    undefined,
    TSCONFIG,
  );
  if (parsed.errors.length > 0) {
    fail(`TypeScript config diagnostic: ${diagnosticText(parsed.errors[0])}`);
  }
  const program = ts.createProgram(parsed.fileNames, parsed.options);
  const source = program.getSourceFile(AUTHORITY);
  if (!source) fail(`authority was not loaded by ${relative(TSCONFIG)}: ${relative(AUTHORITY)}`);

  const relevantDiagnostics = [
    ...program.getSyntacticDiagnostics(source),
    ...program.getSemanticDiagnostics(source),
  ];
  if (relevantDiagnostics.length > 0) {
    fail(`compiler diagnostic in authority: ${diagnosticText(relevantDiagnostics[0])}`);
  }

  const checker = program.getTypeChecker();
  const moduleSymbol = checker.getSymbolAtLocation(source);
  if (!moduleSymbol) fail(`cannot resolve module symbol for ${relative(AUTHORITY)}`);
  const exports = new Map(
    checker.getExportsOfModule(moduleSymbol).map((symbol) => [symbol.name, symbol]),
  );

  const interfaceNodes = new Map();
  for (const statement of source.statements) {
    if (ts.isInterfaceDeclaration(statement)) {
      interfaceNodes.set(statement.name.text, statement);
      const seen = new Set();
      for (const member of statement.members) {
        const name = propertyName(member.name);
        if (seen.has(name)) fail(`duplicate method/member ${statement.name.text}.${name} in ${relative(AUTHORITY)}`);
        seen.add(name);
      }
    }
  }

  const wanted = ["SetjoinNativeBridge", ...new Set(GROUP_PROPERTIES.values())];
  const groups = {};
  for (const interfaceName of wanted) {
    const symbol = exports.get(interfaceName);
    const declaration = interfaceNodes.get(interfaceName);
    if (!symbol || !declaration) {
      fail(`unresolved reachable interface ${interfaceName} in ${relative(AUTHORITY)}`);
    }
    const type = checker.getDeclaredTypeOfSymbol(symbol);
    const required = [];
    const optional = [];
    for (const prop of checker.getPropertiesOfType(type)) {
      const target = (prop.flags & ts.SymbolFlags.Optional) !== 0 ? optional : required;
      target.push(prop.name);
    }
    required.sort();
    optional.sort();
    groups[interfaceName] = { required, optional };
  }

  const capabilitiesSymbol = exports.get("NATIVE_CAPABILITIES");
  const declaration = capabilitiesSymbol?.valueDeclaration;
  if (!declaration || !ts.isVariableDeclaration(declaration) || !declaration.initializer) {
    fail(`NATIVE_CAPABILITIES is not a resolvable const array in ${relative(AUTHORITY)}`);
  }
  let initializer = declaration.initializer;
  if (ts.isAsExpression(initializer)) initializer = initializer.expression;
  if (!ts.isArrayLiteralExpression(initializer)) {
    fail(`NATIVE_CAPABILITIES must remain an array literal with string elements in ${relative(AUTHORITY)}`);
  }
  const capabilities = initializer.elements.map((element) => {
    if (!ts.isStringLiteral(element)) {
      fail(`unsupported NATIVE_CAPABILITIES element in ${relative(AUTHORITY)}`);
    }
    return element.text;
  });
  if (new Set(capabilities).size !== capabilities.length) {
    fail(`duplicate NATIVE_CAPABILITIES entry in ${relative(AUTHORITY)}`);
  }
  for (const capability of capabilities) {
    if (!CAPABILITY_REQUIREMENTS.has(capability)) {
      fail(`capability ${capability} has no structural requirement mapping in ${relative(import.meta.url)}`);
    }
  }

  return {
    schemaVersion: 1,
    authority: relative(AUTHORITY),
    typescriptVersion: ts.version,
    capabilities,
    groups,
  };
}

function stableJSON(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function transpileElectron(sourceText) {
  const output = ts.transpileModule(sourceText, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
    fileName: ELECTRON_BRIDGE,
    reportDiagnostics: true,
  });
  if (output.diagnostics?.length) {
    fail(`Electron bridge compiler diagnostic: ${diagnosticText(output.diagnostics[0])}`);
  }
  const module = { exports: {} };
  vm.runInNewContext(output.outputText, {
    module,
    exports: module.exports,
    Uint8Array,
    Promise,
    JSON,
    encodeURIComponent,
  });
  return module.exports;
}

function objectShape(value) {
  const result = new Map();
  result.set("SetjoinNativeBridge", new Set(Object.keys(value)));
  for (const [property, interfaceName] of GROUP_PROPERTIES) {
    if (value[property] !== undefined) {
      if (value[property] === null || typeof value[property] !== "object") {
        fail(`shell member ${property} must be an object implementing ${interfaceName}`);
      }
      result.set(interfaceName, new Set(Object.keys(value[property])));
    }
  }
  return result;
}

function assertShellShape(shell, contract, shape, capabilities) {
  const allowedCapabilities = new Set(contract.capabilities);
  for (const capability of capabilities) {
    if (!allowedCapabilities.has(capability)) {
      fail(`${shell} advertises unsupported capability ${capability}; authority is ${relative(AUTHORITY)}`);
    }
    for (const requiredPath of CAPABILITY_REQUIREMENTS.get(capability)) {
      const [group, member] = requiredPath.split(".");
      const root = shape.get("SetjoinNativeBridge");
      if (!root.has(group)) {
        fail(`${shell} advertises ${capability} but group/member ${requiredPath} is absent`);
      }
      if (member) {
        const interfaceName = GROUP_PROPERTIES.get(group);
        if (!shape.get(interfaceName)?.has(member)) {
          fail(`${shell} advertises ${capability} but ${requiredPath} is absent`);
        }
      }
    }
  }

  for (const [interfaceName, actual] of shape) {
    const expected = contract.groups[interfaceName];
    if (!expected) fail(`${shell} exposes unknown group ${interfaceName}`);
    for (const member of expected.required) {
      if (!actual.has(member)) {
        fail(`${shell} is missing required ${interfaceName}.${member} from ${relative(AUTHORITY)}`);
      }
    }
    const allowed = new Set([...expected.required, ...expected.optional]);
    for (const member of actual) {
      if (!allowed.has(member)) fail(`${shell} exposes unknown ${interfaceName}.${member}`);
    }
  }
}

function electronProjection(contract, sourceText = fs.readFileSync(ELECTRON_BRIDGE, "utf8")) {
  const exports = transpileElectron(sourceText);
  if (typeof exports.buildBridge !== "function") {
    fail(`Electron seam ${relative(ELECTRON_BRIDGE)} does not export buildBridge(recordingInvoke)`);
  }
  const calls = [];
  const recordingInvoke = async (channel, ...args) => {
    calls.push({ channel, args });
    if (channel === "db_query") return "[]";
    if (channel === "pick_file") return null;
    return undefined;
  };
  const bridge = exports.buildBridge(recordingInvoke);
  const shape = objectShape(bridge);
  assertShellShape("Electron buildBridge", contract, shape, bridge.capabilities);
  return { bridge, shape, calls };
}

function extractRustTemplate(file, constantName) {
  const source = fs.readFileSync(file, "utf8");
  const marker = `const ${constantName}: &str = r#"`;
  const start = source.indexOf(marker);
  if (start < 0) fail(`${relative(file)} is missing ${constantName} raw string`);
  const bodyStart = start + marker.length;
  const end = source.indexOf('"#;', bodyStart);
  if (end < 0) fail(`${relative(file)} has unsupported ${constantName} raw-string syntax`);
  return source.slice(bodyStart, end);
}

function findAssignedObject(js, fileLabel) {
  const source = ts.createSourceFile(fileLabel, js, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
  if (source.parseDiagnostics.length > 0) {
    fail(`${fileLabel} rendered-JS diagnostic: ${diagnosticText(source.parseDiagnostics[0])}`);
  }
  let found = null;
  function visit(node) {
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      node.left.getText(source) === "window.setjoinNative" &&
      ts.isObjectLiteralExpression(node.right)
    ) {
      found = node.right;
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
  if (!found) fail(`${fileLabel} does not assign an object literal to window.setjoinNative`);
  return { source, object: found };
}

function objectLiteralShape(parsed) {
  const shape = new Map();
  const root = new Set();
  shape.set("SetjoinNativeBridge", root);
  for (const member of parsed.object.properties) {
    const name = propertyName(member.name);
    root.add(name);
    const interfaceName = GROUP_PROPERTIES.get(name);
    if (interfaceName) {
      if (!ts.isPropertyAssignment(member) || !ts.isObjectLiteralExpression(member.initializer)) {
        fail(`rendered bridge group ${name} has unsupported non-object syntax`);
      }
      shape.set(
        interfaceName,
        new Set(member.initializer.properties.map((child) => propertyName(child.name))),
      );
    }
  }
  return shape;
}

function tauriProjection(contract, templateOverride) {
  let js = templateOverride ?? extractRustTemplate(TAURI_BRIDGE, "BRIDGE_INIT_JS_TEMPLATE");
  const replacements = new Map([
    ["__CAPABILITIES__", "[]"],
    ["__PUSH_REGISTER__", "async pushRegister() { return null; }"],
    ["__BIOMETRIC_UNLOCK__", "async biometricUnlock() { return false; }"],
    ["__SHARE__", "share: async function () {}"],
    ["__VAULT_IS_ENROLLED__", "isEnrolled: async function () { return false; }"],
    ["__VAULT_VERSION__", "1"],
    // DESKTOP-007 Android-only route watcher (drives the FLAG_SECURE window
    // flag). It is document-start side-channel injection, not a bridge method,
    // so the shape projection renders the non-Android variant: an empty
    // substitution, exactly what desktop/iOS builds ship.
    ["__SURFACE_ROUTE_WATCHER__", ""],
  ]);
  for (const [from, to] of replacements) js = js.replaceAll(from, to);
  const unresolved = [...js.matchAll(/__([A-Z][A-Z0-9_]*)__/g)]
    .map((match) => match[0])
    .filter((name) => name !== "__TAURI__");
  if (unresolved.length > 0) {
    fail(`${relative(TAURI_BRIDGE)} contains unsupported init placeholder ${unresolved[0]}`);
  }
  const parsed = findAssignedObject(js, relative(TAURI_BRIDGE));
  const shape = objectLiteralShape(parsed);
  const capabilities = [
    "secureStore",
    "vault",
    "share",
    "pickFile",
    "notify",
    "openExternal",
    "mailDb",
    "deviceProof",
    "recoveryBlob",
  ];
  assertShellShape("Tauri rendered init JS", contract, shape, capabilities);
  return { js, shape };
}

function extractStringArray(source, name, file) {
  const pattern = new RegExp(`const\\s+${name}\\s*:[^=]+?=\\s*\\[([\\s\\S]*?)\\];`);
  const match = source.match(pattern);
  if (!match) fail(`${relative(file)} has unsupported ${name} declaration`);
  const withoutComments = match[1].replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
  const values = [];
  let rest = withoutComments;
  const item = /^\s*(?:'([^']+)'|"([^"]+)")\s*,?/;
  while (rest.trim().length > 0) {
    const parsed = rest.match(item);
    if (!parsed) fail(`${relative(file)} ${name} contains unsupported ArkTS syntax`);
    values.push(parsed[1] ?? parsed[2]);
    rest = rest.slice(parsed[0].length);
  }
  if (new Set(values).size !== values.length) fail(`${relative(file)} ${name} contains a duplicate method`);
  return values;
}

function extractProxyMethods(source) {
  const classAt = source.indexOf("export class BridgeProxy");
  if (classAt < 0) fail(`${relative(HARMONY_PROXY)} is missing BridgeProxy`);
  const classBody = source.slice(classAt);
  const names = new Set();
  const re = /^\s{2}(?:private\s+|public\s+|protected\s+)?(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*:/gm;
  for (const match of classBody.matchAll(re)) names.add(match[1]);
  if (names.size === 0) fail(`${relative(HARMONY_PROXY)} method syntax is unsupported or empty`);
  return names;
}

function harmonyProjection(contract, overrides = {}) {
  const mainSource = overrides.main ?? fs.readFileSync(HARMONY_MAIN, "utf8");
  const proxySource = overrides.proxy ?? fs.readFileSync(HARMONY_PROXY, "utf8");
  const shimSource = overrides.shim ?? fs.readFileSync(HARMONY_SHIM, "utf8");
  const registered = new Set([
    ...extractStringArray(mainSource, "PROXY_METHODS", HARMONY_MAIN),
    ...extractStringArray(mainSource, "PROXY_ASYNC_METHODS", HARMONY_MAIN),
  ]);
  const proxyMethods = extractProxyMethods(proxySource);
  for (const method of registered) {
    if (!proxyMethods.has(method)) {
      fail(`Harmony registration ${method} in ${relative(HARMONY_MAIN)} is absent from ${relative(HARMONY_PROXY)}`);
    }
  }

  const capMatch = shimSource.match(/const\s+CAPABILITIES_JSON\s*=\s*JSON\.stringify\(\s*\[([\s\S]*?)\]\s*\);/);
  if (!capMatch) fail(`${relative(HARMONY_SHIM)} has unsupported CAPABILITIES_JSON syntax`);
  const capabilities = [];
  for (const match of capMatch[1].matchAll(/['"]([^'"]+)['"]/g)) capabilities.push(match[1]);
  if (capabilities.length === 0) fail(`${relative(HARMONY_SHIM)} capabilities parsed empty`);

  const returnMatch = shimSource.match(/return\s+`([\s\S]*?)`;\s*\n}/);
  if (!returnMatch) fail(`${relative(HARMONY_SHIM)} has unsupported bridge template syntax`);
  const js = returnMatch[1].replace("${CAPABILITIES_JSON}", "[]");
  const parsed = findAssignedObject(js, relative(HARMONY_SHIM));
  const shape = objectLiteralShape(parsed);
  assertShellShape("Harmony BridgeShim", contract, shape, capabilities);

  const nativeCalls = new Set();
  for (const match of js.matchAll(/native\.([A-Za-z_$][\w$]*)\s*\(/g)) nativeCalls.add(match[1]);
  for (const method of nativeCalls) {
    if (!registered.has(method)) {
      fail(`Harmony shim calls ${method} but it is absent from PROXY_METHODS/PROXY_ASYNC_METHODS in ${relative(HARMONY_MAIN)}`);
    }
    if (!proxyMethods.has(method)) {
      fail(`Harmony shim calls ${method} but it is absent from BridgeProxy in ${relative(HARMONY_PROXY)}`);
    }
  }
  return { capabilities, registered, shape };
}

function runChecks(contract) {
  electronProjection(contract);
  tauriProjection(contract);
  harmonyProjection(contract);
}

function expectFailure(label, fn, includes) {
  try {
    fn();
  } catch (error) {
    if (error instanceof ContractError && error.message.includes(includes)) return error.message;
    throw new ContractError(`E_NATIVE_CONTRACT_STALE: self-test ${label} produced wrong diagnostic: ${error}`);
  }
  throw new ContractError(`E_NATIVE_CONTRACT_STALE: self-test ${label} did not fail`);
}

function selfTest(contract) {
  const electronSource = fs.readFileSync(ELECTRON_BRIDGE, "utf8");
  const diagnostics = [expectFailure(
    "Electron advertised absent group",
    () => electronProjection(contract, electronSource.replace('"recoveryBlob",\n] as const', '"ghostCapability",\n  "recoveryBlob",\n] as const')),
    "unsupported capability ghostCapability",
  )];

  const tauriTemplate = extractRustTemplate(TAURI_BRIDGE, "BRIDGE_INIT_JS_TEMPLATE");
  diagnostics.push(expectFailure(
    "Tauri missing shell method",
    () => tauriProjection(contract, tauriTemplate.replace("isUnlocked: () => invoke('vault_is_unlocked'),", "")),
    "VaultBridge.isUnlocked",
  ));
  diagnostics.push(expectFailure(
    "Tauri unregistered init placeholder",
    () => tauriProjection(contract, tauriTemplate.replace("__SURFACE_ROUTE_WATCHER__", "__FUTURE_PLACEHOLDER__")),
    "unsupported init placeholder __FUTURE_PLACEHOLDER__",
  ));

  const harmonyMain = fs.readFileSync(HARMONY_MAIN, "utf8");
  diagnostics.push(expectFailure(
    "Harmony missing native registration",
    () => harmonyProjection(contract, { main: harmonyMain.replace("'secureStoreGet', ", "") }),
    "shim calls secureStoreGet",
  ));

  diagnostics.push(expectFailure(
    "Harmony fail-closed array syntax",
    () => harmonyProjection(contract, { main: harmonyMain.replace("'ping',", "...EXTRA_METHODS,") }),
    "unsupported ArkTS syntax",
  ));
  for (const diagnostic of diagnostics) console.error(`${diagnostic} self_test_caught=true rerun='bash scripts/check-native-contract-conformance.sh'`);
}

function usage() {
  console.log(`usage: node scripts/native-contract-conformance.mjs <--check|--write|--self-test|--help>

--check      verify the generated TypeScript projection and all three shell seams
--write      atomically regenerate contract-members.generated.json, then verify
--self-test  plant missing-member, advertisement, registration, and syntax drift
--help       show this help`);
}

function atomicWrite(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, content, { mode: 0o600 });
  fs.renameSync(temporary, file);
}

function main() {
  const args = process.argv.slice(2);
  if (args.length !== 1 || !["--check", "--write", "--self-test", "--help"].includes(args[0])) {
    usage();
    process.exitCode = 2;
    return;
  }
  if (args[0] === "--help") {
    usage();
    return;
  }
  const contract = readContract();
  const expected = stableJSON(contract);
  if (args[0] === "--write") atomicWrite(GENERATED, expected);
  if (!fs.existsSync(GENERATED)) {
    fail(
      `${relative(GENERATED)} is missing; authority ${relative(AUTHORITY)}. ` +
        "Run `node scripts/native-contract-conformance.mjs --write` then `bash scripts/check-native-contract-conformance.sh`.",
    );
  }
  const actual = fs.readFileSync(GENERATED, "utf8");
  if (actual !== expected) {
    fail(
      `${relative(GENERATED)} is stale for ${relative(AUTHORITY)} (TypeScript ${ts.version}). ` +
        "Run `node scripts/native-contract-conformance.mjs --write` then `bash scripts/check-native-contract-conformance.sh`.",
    );
  }
  runChecks(contract);
  if (args[0] === "--self-test") selfTest(contract);
  console.log(
    `native-contract-conformance: OK (${contract.capabilities.length} capabilities, ` +
      `${Object.keys(contract.groups).length} groups; Electron/Tauri/Harmony seams)`,
  );
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  if (error instanceof ContractError) {
    console.error(`  authority: ${relative(AUTHORITY)}`);
    console.error(`  generated: ${relative(GENERATED)}`);
    console.error("  repair: node scripts/native-contract-conformance.mjs --write");
    console.error("  verify: bash scripts/check-native-contract-conformance.sh");
  }
  process.exitCode = error instanceof ContractError ? 1 : 2;
}
