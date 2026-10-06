/** Message ids observed across public Baichuan dissectors and clients. */
export const Command = {
  login: 1,
  logout: 2,
  preview: 3,
  previewStop: 4,
  replay: 5,
  replayStop: 7,
  downloadVideo: 8,
  talkAbility: 10,
  fileDownload: 13,
  fileInfo: 14,
  fileInfo15: 15,
  fileInfo16: 16,
  ptzControl: 18,
  reboot: 23,
  videoInputWrite: 25,
  videoInput: 26,
  subscribeEvents: 31,
  alarmEventList: 33,
  serverPortWrite: 36,
  serverPort: 37,
  unknown38: 38,
  unknown39Write: 39,
  unknown40: 40,
  unknown41Write: 41,
  unknown42: 42,
  unknown43Write: 43,
  osdChannelName: 44,
  osdChannelNameWrite: 45,
  motionAlarm: 46,
  motionAlarmWrite: 47,
  unknown50: 50,
  unknown51Write: 51,
  shelter: 52,
  shelterWrite: 53,
  recordCfg: 54,
  recordCfgWrite: 55,
  compression: 56,
  compressionWrite: 57,
  abilitySupport: 58,
  abilitySupportWrite: 59,
  configExport: 65,
  configImport: 66,
  firmwareUpgrade: 67,
  unknown68: 68,
  unknown69Write: 69,
  unknown70: 70,
  unknown71Write: 71,
  ip: 76,
  ipWrite: 77,
  videoInputPush: 78,
  serialPtz: 79,
  versionInfo: 80,
  recordSchedule: 81,
  recordScheduleWrite: 82,
  unknown83: 83,
  unknown84Write: 84,
  unknown91: 91,
  unknown92Write: 92,
  linkType: 93,
  unknown97: 97,
  unknown98Write: 98,
  factoryDefault: 99,
  unknown100Write: 100,
  unknown101: 101,
  hddInfoList: 102,
  hddFormat: 103,
  systemGeneral: 104,
  systemGeneralWrite: 105,
  unknown106: 106,
  unknown107Write: 107,
  unknown108: 108,
  wifiSignal: 115,
  videoInputAdvance: 132,
  rfAlarm: 133,
  channelInfo: 145,
  streamInfoList: 146,
  abilityInfo: 151,
  ptzPreset: 190,
  keepalive: 192,
  support: 199,
  talkConfig: 201,
  talk: 202,
  rfAlarmWrite: 204,
  ledState: 208,
  ledStateWrite: 209,
  audioCfgWrite: 264,
  floodlightManual: 288,
  floodlight: 289,
  floodlightTaskWrite: 290,
  floodlightStatus: 291,
  aiState: 342,
  floodlightTask: 438,
  ptzPosition: 433,
  privacyMode: 574,
} as const;

export type CommandName = keyof typeof Command;

export const COMMAND_NAMES: Record<number, string> = Object.fromEntries(
  Object.entries(Command).map(([name, id]) => [id, name]),
);

/** Header class selects the 20-byte legacy header or the 24-byte modern header. */
export const MessageClass = {
  legacyRequest: 0x6514,
  legacyReply: 0x6614,
  modernRequest: 0x6414,
  modernReply: 0x0000,
  modernReplyAlt: 0x6482,
} as const;

export const MAGIC = 0x0abcdef0;
export const MAGIC_REVERSED = 0xf0debc0a;
export const NVR_MAGIC = 0x0fedcda0;

export const XML_KEY = Uint8Array.from([
  0x1f, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0xff,
]);

/** Legacy header field at offset 16. Stored as a host integer; written little-endian. */
export const EncFlag = {
  none: 0xdc00,
  bc: 0xdc01,
  aes: 0xdc12,
  aesOffer: 0xdc03,
  bcAck: 0xdd01,
  aesAck: 0xdd02,
} as const;

export const AES_IV = new TextEncoder().encode("0123456789abcdef");

export const StreamType = {
  main: "mainStream",
  sub: "subStream",
  ext: "externStream",
  mobile: "mobileStream",
} as const;

export type StreamName = typeof StreamType[keyof typeof StreamType];

/** Header stream-id byte used by some firmwares alongside the XML streamType. */
export const StreamByte = {
  mainStream: 0x00,
  subStream: 0x01,
  externStream: 0x04,
  mobileStream: 0x02,
} as const;

export const PtzCommand = {
  stop: "Stop",
  left: "Left",
  right: "Right",
  up: "Up",
  down: "Down",
  leftUp: "LeftUp",
  leftDown: "LeftDown",
  rightUp: "RightUp",
  rightDown: "RightDown",
  zoomIn: "ZoomInc",
  zoomOut: "ZoomDec",
  focusIn: "FocusInc",
  focusOut: "FocusDec",
  irisIn: "IrisInc",
  irisOut: "IrisDec",
  auto: "Auto",
  toPos: "ToPos",
  setPreset: "SetPreset",
  gotoPreset: "GotoPreset",
  clearPreset: "ClearPreset",
} as const;

export type PtzCommandName = typeof PtzCommand[keyof typeof PtzCommand];

export const MediaMagic = {
  infoV1: "1001",
  infoV2: "1002",
  iFrame: "00dc",
  pFrame: "01dc",
  aac: "05wb",
  adpcm: "01wb",
} as const;

export const UdpMagic = {
  discovery: 0x2a87cf3a,
  ack: 0x2a87cf20,
  data: 0x2a87cf10,
} as const;

export const P2P_HOSTS = [
  "p2p.reolink.com",
  "p2p1.reolink.com",
  "p2p2.reolink.com",
  "p2p3.reolink.com",
  "p2p4.reolink.com",
  "p2p5.reolink.com",
  "p2p6.reolink.com",
  "p2p7.reolink.com",
  "p2p8.reolink.com",
  "p2p9.reolink.com",
  "p2p10.reolink.com",
  "p2p11.reolink.com",
] as const;

export const P2P_PORT = 9999;

export function headerLength(messageClass: number): number {
  return messageClass === MessageClass.legacyRequest ||
      messageClass === MessageClass.legacyReply
    ? 20
    : 24;
}
