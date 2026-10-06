import { XML_KEY } from "./commands.ts";

/** Symmetric Baichuan XML obfuscation. `offset` is header byte 12. */
export function bcXor(data: Uint8Array, offset: number): Uint8Array {
  const out = new Uint8Array(data.length);
  const off = offset & 0xff;
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i] ^ XML_KEY[(i + off) % 8] ^ off;
  }
  return out;
}

export function xmlDocument(inner: string): string {
  const body = inner.trim().startsWith("<body>")
    ? inner.trim()
    : `<body>\n${inner.trim()}\n</body>`;
  return `<?xml version="1.0" encoding="UTF-8" ?>\n${body}`;
}

export function tag(name: string, value: string | number, attrs = ""): string {
  const a = attrs ? ` ${attrs}` : "";
  return `<${name}${a}>${value}</${name}>`;
}

export function extractTag(xml: string, name: string): string | undefined {
  const re = new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, "i");
  return re.exec(xml)?.[1]?.trim();
}

export function extractTags(xml: string, name: string): string[] {
  const re = new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, "gi");
  return [...xml.matchAll(re)].map((m) => m[1].trim());
}

export function loginXml(userHash: string, passHash: string): string {
  return xmlDocument(
    `<LoginUser version="1.1">
<userName>${userHash}</userName>
<password>${passHash}</password>
<userVer>1</userVer>
</LoginUser>
<LoginNet version="1.1">
<type>LAN</type>
<udpPort>0</udpPort>
</LoginNet>`,
  );
}

export function logoutXml(username: string, password: string): string {
  return xmlDocument(
    `<LoginUser version="1.1">
<userName>${username}</userName>
<password>${password}</password>
</LoginUser>`,
  );
}

export function previewXml(
  channelId: number,
  handle: number,
  streamType: string,
): string {
  return xmlDocument(
    `<Preview version="1.1">
<channelId>${channelId}</channelId>
<handle>${handle}</handle>
<streamType>${streamType}</streamType>
</Preview>`,
  );
}

export function ptzXml(
  channelId: number,
  command: string,
  speed: number,
  presetId?: number,
): string {
  const preset = presetId === undefined ? "" : `<presetId>${presetId}</presetId>\n`;
  return xmlDocument(
    `<PtzControl version="1.1">
<channelId>${channelId}</channelId>
<command>${command}</command>
<speed>${speed}</speed>
${preset}</PtzControl>`,
  );
}

export function extensionXml(binary = false, channelId?: number): string {
  const channel = channelId === undefined ? "" : `<channelId>${channelId}</channelId>\n`;
  const bin = binary ? `<binaryData>1</binaryData>\n` : "";
  return xmlDocument(`<Extension version="1.1">\n${channel}${bin}</Extension>`);
}
