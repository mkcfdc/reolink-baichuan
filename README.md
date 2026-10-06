# reolink-baichuan

Zero-dependency Deno client for Reolink's Baichuan protocol (TCP/9000).

This is an independent implementation of the wire format published by the Neolink, leolink, and reolink_aio reverse-engineering notes. It does not ship Reolink firmware, SDKs, or code from those projects.

Battery cameras that have no RTSP still need the UID/P2P rendezvous (`p2p.reolink.com` UDP/9999). That path is not implemented; the constants are exported. LAN TCP/9000 is.

## Use

```ts
import { BaichuanClient } from "jsr:@mkcfdc/reolink-baichuan";

const cam = new BaichuanClient({
  host: "192.168.1.50",
  username: "admin",
  password: "secret",
  encryption: "auto", // "none" | "bc" | "aes" | "auto"
  loginStyle: "auto", // "legacy" | "nonce" | "auto"
  channel: 0,
});

await cam.login();
console.log(await cam.getSupport());

for await (const packet of cam.preview({ stream: "sub" })) {
  if (packet.kind === "iframe" || packet.kind === "pframe") {
    // Annex-B H.264 / H.265
  }
}
await cam.close();
```

From a checkout:

```sh
deno task test
REOLINK_HOST=192.168.1.50 REOLINK_PASS=secret deno task info
```

## What is covered

- 20-byte legacy and 24-byte modern headers, magic `0x0abcdef0`, NVR magic, reversed stop magic
- Baichuan XOR (`1f 2d 3c 4b 5a 69 78 ff`) and AES-128-CFB (`IV = 0123456789abcdef`, key = first 16 chars of `MD5(nonce-password)` uppercase hex)
- Legacy 64-byte MD5 login and nonce-then-modern XML login
- Command ids from the public dissectors: login, preview, replay, talk, PTZ, OSD, shelter, record, compression, ability, IP, storage, LED, floodlight, AI state, privacy mode, and the unnamed ids in between
- Stream types `mainStream`, `subStream`, `externStream`, `mobileStream`
- BcMedia demux for `1001`/`1002` info, `00dc`/`01dc` video, `05wb` AAC, `01wb` ADPCM

Encryption and login differ by firmware. `encryption: "auto"` offers AES on the nonce request, then falls back to the legacy MD5 body. Set `encryption: "bc"` for cameras that reject AES, or `aesKeyDash: false` if the key is `MD5(nonce + password)` with no dash.

## Not in this module

- SongP2P hole-punch and relay. Hosts and UDP magics are exported only.
- A full XML schema for every firmware year. Unknown commands go through `request(id, xml)`.
- RTSP remux. `preview()` yields Annex-B access units.
