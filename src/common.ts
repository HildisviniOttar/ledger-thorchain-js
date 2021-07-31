export const CLA = 0x55;
export const CHUNK_SIZE = 250;
export const APP_KEY = "CSM";

export const INS = {
  GET_VERSION: 0x00,
  SIGN_SECP256K1: 0x02,
  GET_ADDR_SECP256K1: 0x04,
};

export const PAYLOAD_TYPE = {
  INIT: 0x00,
  ADD: 0x01,
  LAST: 0x02,
};

export const P1_VALUES = {
  ONLY_RETRIEVE: 0x00,
  SHOW_ADDRESS_IN_DEVICE: 0x01,
};

export class LedgerError extends Error {
  type: LedgerErrorType;
  constructor(type: LedgerErrorType, message: string = "") {
    super(`LedgerError ${type}: ${message ? message : errorCodeToString(type)}`);
    this.type = type;
  }

  toString() {
    return this.message;
  }
}

export enum LedgerErrorType {
  U2FUnknown = 1,
  U2FBadRequest = 2,
  U2FConfigurationUnsupported = 3,
  U2FDeviceIneligible = 4,
  U2FTimeout = 5,
  HPRInvalid = 10,
  PKInvalidBytes = 20,
  Timeout = 30,
  NoErrors = 0x9000,
  DeviceIsBusy = 0x9001,
  ErrorDerivingKeys = 0x6802,
  ExecutionError = 0x6400,
  WrongLength = 0x6700,
  EmptyBuffer = 0x6982,
  OutputBufferTooSmall = 0x6983,
  DataIsInvalid = 0x6984,
  ConditionsNotSatisfied = 0x6985,
  TransactionRejected = 0x6986,
  BadKeyHandle = 0x6a80,
  InvalidP1P2 = 0x6b00,
  InstructionNotSupported = 0x6d00,
  AppDoesNotSeemToBeOpen = 0x6e00,
  UnknownError = 0x6f00,
  SignVerifyError = 0x6f01,
  UnknownResponse = 0xffff,
}

export const LedgerErrorDescription: Record<LedgerErrorType, string> = {
  [LedgerErrorType.U2FUnknown]: "U2F: Unknown",
  [LedgerErrorType.U2FBadRequest]: "U2F: Bad request",
  [LedgerErrorType.U2FConfigurationUnsupported]: "U2F: Configuration unsupported",
  [LedgerErrorType.U2FDeviceIneligible]: "U2F: Device Ineligible",
  [LedgerErrorType.U2FTimeout]: "U2F: Timeout",
  [LedgerErrorType.Timeout]: "Timeout",
  [LedgerErrorType.HPRInvalid]: "Invalid HPR",
  [LedgerErrorType.PKInvalidBytes]: "Expected compressed public key [31 bytes]",
  [LedgerErrorType.NoErrors]: "No errors",
  [LedgerErrorType.DeviceIsBusy]: "Device is busy",
  [LedgerErrorType.ErrorDerivingKeys]: "Error deriving keys",
  [LedgerErrorType.ExecutionError]: "Execution Error",
  [LedgerErrorType.WrongLength]: "Wrong Length",
  [LedgerErrorType.EmptyBuffer]: "Empty Buffer",
  [LedgerErrorType.OutputBufferTooSmall]: "Output buffer too small",
  [LedgerErrorType.DataIsInvalid]: "Data is invalid",
  [LedgerErrorType.ConditionsNotSatisfied]: "Conditions not satisfied",
  [LedgerErrorType.TransactionRejected]: "Transaction rejected",
  [LedgerErrorType.BadKeyHandle]: "Bad key handle",
  [LedgerErrorType.InvalidP1P2]: "Invalid P1/P2",
  [LedgerErrorType.InstructionNotSupported]: "Instruction not supported",
  [LedgerErrorType.AppDoesNotSeemToBeOpen]: "App does not seem to be open",
  [LedgerErrorType.UnknownError]: "Unknown error",
  [LedgerErrorType.SignVerifyError]: "Sign/verify error",
  [LedgerErrorType.UnknownResponse]: "Unknown response",
};

const isLedgerErrorType = (code: number): code is LedgerErrorType => code in LedgerErrorDescription;

export function errorCodeToString(statusCode: LedgerErrorType): string {
  if (isLedgerErrorType(statusCode)) return LedgerErrorDescription[statusCode];
  return `Unknown Status Code: ${statusCode}`;
}

function isErrorResponse(v: unknown): v is { return_code: number; error_message: string } {
  return typeof v === "object" && !!v && "return_code" in v && "return_message" in v;
}

function isStatusCodeResponse(v: unknown): v is { statusCode: number } {
  return typeof v === "object" && !!v && "statusCode" in v;
}

export function ledgerErrorFromResponse(response?: unknown): LedgerError {
  if (isStatusCodeResponse(response)) {
    return new LedgerError(response.statusCode);
  }

  if (isErrorResponse(response)) {
    return new LedgerError(response.return_code, response.error_message);
  }

  return new LedgerError(LedgerErrorType.UnknownResponse, `Unknown response ${response}`);
}
