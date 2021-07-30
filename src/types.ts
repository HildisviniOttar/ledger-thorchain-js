
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
  flagPINValidated: boolean;
}

export type SignResponse = BaseResponse &  {
  signature: Buffer
}
