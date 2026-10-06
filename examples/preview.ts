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
  debug: Deno.env.get("REOLINK_DEBUG") === "1",
});

await cam.login();
const out = await Deno.open("preview.h264", { write: true, create: true, truncate: true });
let frames = 0;
for await (const packet of cam.preview({ stream: "sub" })) {
  if (packet.kind === "iframe" || packet.kind === "pframe") {
    await out.write(packet.payload);
    frames++;
    if (frames === 1) console.log(packet.codec, packet.unixTime);
  }
  if (frames >= 60) break;
}
out.close();
await cam.close();
console.log(`wrote ${frames} frames to preview.h264`);
