import { assertEquals } from "jsr:@std/assert@1";
import { AES_IV, Command, EncFlag, MAGIC, MessageClass } from "../src/commands.ts";
import { aes128CfbDecrypt, aes128CfbEncrypt, aes128EncryptBlock, credentialHash, md5Hex } from "../src/crypto.ts";
import { decodeFrame, encodeFrame } from "../src/frame.ts";
import { demuxMedia } from "../src/media.ts";
import { bcXor, extractTag, loginXml } from "../src/xml.ts";

Deno.test("md5 matches known vectors", () => {
  assertEquals(md5Hex("", false), "d41d8cd98f00b204e9800998ecf8427e");
  assertEquals(md5Hex("abc", false), "900150983cd24fb0d6963f7d28e17f72");
  assertEquals(credentialHash("admin"), "21232F297A57A5A743894A0E4A801FC");
});

Deno.test("aes-128 block matches NIST", () => {
  const key = Uint8Array.from([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  ]);
  const plain = Uint8Array.from([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  ]);
  const cipher = aes128EncryptBlock(plain, key);
  assertEquals(
    [...cipher].map((b) => b.toString(16).padStart(2, "0")).join(""),
    "69c4e0d86a7b0430d8cdb78070b4c55a",
  );
});

Deno.test("aes-cfb round trip uses the Baichuan IV", () => {
  const key = new TextEncoder().encode("0123456789abcdef");
  const plain = new TextEncoder().encode("<body><Preview version=\"1.1\">ok</Preview></body>");
  const enc = aes128CfbEncrypt(plain, key, AES_IV);
  assertEquals(aes128CfbDecrypt(enc, key, AES_IV), plain);
});

Deno.test("bc xor is symmetric and uses byte 12 as the offset", () => {
  const plain = new TextEncoder().encode("<Encryption><nonce>ABC</nonce></Encryption>");
  const enc = bcXor(plain, 0);
  assertEquals(bcXor(enc, 0), plain);
  assertEquals(bcXor(bcXor(plain, 3), 3), plain);
});

Deno.test("legacy and modern frames round trip", () => {
  const body = new TextEncoder().encode(loginXml("USER", "PASS"));
  const modern = encodeFrame({
    id: Command.login,
    body,
    messageClass: MessageClass.modernRequest,
    channelId: 0,
    streamId: 1,
    handle: 7,
    code: 0,
    payloadOffset: 0,
  });
  assertEquals(modern.length, 24 + body.length);
  assertEquals(modern[0], 0xf0);
  assertEquals(modern[1], 0xde);
  const decoded = decodeFrame(modern);
  assertEquals(decoded?.id, 1);
  assertEquals(decoded?.messageClass, MessageClass.modernRequest);
  assertEquals(decoded?.handle, 7);
  assertEquals(decoded?.body, body);

  const legacy = encodeFrame({
    id: Command.login,
    body: new Uint8Array(64),
    messageClass: MessageClass.legacyRequest,
    code: EncFlag.bc,
  });
  assertEquals(legacy.length, 84);
  const view = new DataView(legacy.buffer);
  assertEquals(view.getUint32(0, true), MAGIC);
  assertEquals(view.getUint16(16, true), EncFlag.bc);
  assertEquals(view.getUint16(18, true), MessageClass.legacyRequest);
});

Deno.test("media demux finds an info block and an iframe", () => {
  const info = new Uint8Array(32);
  info.set(new TextEncoder().encode("1001"));
  const v = new DataView(info.buffer);
  v.setUint32(4, 32, true);
  v.setUint32(8, 2560, true);
  v.setUint32(12, 1440, true);
  info[17] = 20;
  const iframe = new Uint8Array(32 + 4);
  iframe.set(new TextEncoder().encode("00dc"));
  iframe.set(new TextEncoder().encode("H265"), 4);
  new DataView(iframe.buffer).setUint32(8, 4, true);
  iframe.set([0, 0, 0, 1], 32);
  const blob = new Uint8Array(info.length + iframe.length);
  blob.set(info);
  blob.set(iframe, info.length);
  const packets = [...demuxMedia(blob)];
  assertEquals(packets.length, 2);
  assertEquals(packets[0].width, 2560);
  assertEquals(packets[0].fps, 20);
  assertEquals(packets[1].codec, "H265");
  assertEquals([...packets[1].payload], [0, 0, 0, 1]);
});

Deno.test("nonce xml extracts", () => {
  const xml = `<Encryption version="1.1"><type>md5</type><nonce>9F89BBCE447CAB52</nonce></Encryption>`;
  assertEquals(extractTag(xml, "nonce"), "9F89BBCE447CAB52");
});
