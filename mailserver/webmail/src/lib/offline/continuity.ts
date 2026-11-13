import { continuityGet, continuityPresent } from "$lib/jmap/client";
import { hasCapability } from "$lib/native";

const TOKEN_PREFIX = "continuity-token:";

/** Present the last external witness before replacing it with the newest token. */
export async function observeContinuity(accountId: string): Promise<string> {
  const native =
    typeof window === "undefined" ? undefined : window.setjoinNative;
  if (!native || !hasCapability("recoveryBlob")) return "unavailable";
  const key = TOKEN_PREFIX + accountId;
  const prior = await native.secureStore.get(key);
  let signal = "none";
  if (prior) {
    const result = await continuityPresent(prior, accountId);
    signal = result.signalClass;
  }
  const newest = await continuityGet(accountId);
  await native.secureStore.set(key, newest.token);
  return signal;
}
