
export type BaseResponse = { returnCode: number; errorMessage: string };

export type VersionResponse = BaseResponse & {
  testMode: boolean;
  major: number;
  minor: number;
  patch: number;
  deviceLocked: boolean;
  targetId: string;
};

export type AppInfoResponse = BaseResponse &  {
  appName: string;
  appVersion: string;
  flagLen: number;
  flagsValue: number;
  flagRecovery: boolean;
  flagSignedMcuCode: boolean;
  flagOnboarded: boolean;
  flagPinValidated: boolean;
}

export type DeviceInfoResponse = BaseResponse &  {
  targetId: string
  seVersion: string
  flag: string
  mcuVersion: string
}

export type SignResponse = BaseResponse &  {
  signature?: Buffer
}

export type PubKeyResponse = BaseResponse &  {
  compressedPk: Buffer
}

export type AddressPubKeyResponse = PubKeyResponse &  {
  bech32Address: string
}
