import { BaichuanClient } from "../src/mod.ts";

const host = Deno.env.get("REOLINK_HOST");
if (!host) {
  console.error("Set REOLINK_HOST, REOLINK_USER, REOLINK_PASS");
  Deno.exit(1);
}

const cam = new BaichuanClient({
  host,
  username: Deno.env.get("REOLINK_USER") ?? "admin",
  password: Deno.env.get("REOLINK_PASS") ?? "",
  encryption: (Deno.env.get("REOLINK_ENC") as "auto" | "bc" | "aes" | "none") ?? "auto",
  loginStyle: (Deno.env.get("REOLINK_LOGIN") as "auto" | "legacy" | "nonce") ?? "auto",
  debug: Deno.env.get("REOLINK_DEBUG") === "1",
});

const info = await cam.login();
console.log(info);
console.log("--- version ---");
console.log(await cam.getVersion());
console.log("--- support ---");
console.log(await cam.getSupport());
await cam.close();
