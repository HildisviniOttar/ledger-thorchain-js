import type Transport from "@ledgerhq/hw-transport";
import * as Helpers from "./helper";
import {
  APP_KEY,
  CHUNK_SIZE,
  CLA,
  INS,
  LedgerError,
  errorCodeToString,
  P1_VALUES,
  LedgerErrorType,
  ledgerErrorFromResponse,
} from "./common";
import {
  AddressPubKeyResponse,
  AppInfoResponse,
  DeviceInfoResponse,
  PubKeyResponse,
  SignResponse,
  VersionResponse,
} from "./types";

export class THORChainApp {
  transport: Transport;

  constructor(transport: Transport, scrambleKey: string = APP_KEY) {
    if (!transport) {
      throw new Error("Transport has not been defined");
    }

    this.transport = transport;
    transport.decorateAppAPIMethods(
      this,
      ["getVersion", "sign", "getAddressAndPubKey", "appInfo", "deviceInfo", "getBech32FromPK"],
      scrambleKey,
    );
  }

  async serializePath(path: number[]): Promise<Buffer> {
    const version = await Helpers.getVersion(this.transport);

    if (version.returnCode !== LedgerErrorType.NoErrors) {
      throw new LedgerError(version.returnCode, version.errorMessage);
    }

    switch (version.major) {
      case 2:
        return Helpers.serializePath(path);
      default:
        throw new LedgerError(LedgerErrorType.ExecutionError, "App Version is not supported");
    }
  }

  async signGetChunks(path: number[], message: string): Promise<Buffer[]> {
    const serializedPath: Buffer = await this.serializePath(path);

    const chunks = [];
    chunks.push(serializedPath);
    const buffer = Buffer.from(message);

    for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
      let end = i + CHUNK_SIZE;
      if (i > buffer.length) {
        end = buffer.length;
      }
      chunks.push(buffer.slice(i, end));
    }

    return chunks;
  }

  async getVersion(): Promise<VersionResponse> {
    return Helpers.getVersion(this.transport);
  }

  async getAppInfo(): Promise<AppInfoResponse> {
    try {
      const response: Buffer = await this.transport.send(0xb0, 0x01, 0, 0);
      const errorCodeData = response.slice(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

      if (response[0] !== 1) {
        // Ledger responds with format ID 1. There is no spec for any format != 1
        throw new LedgerError(LedgerErrorType.DeviceIsBusy, "response format ID not recognized");
      }

      const appNameLen = response[1];
      const appName = response.slice(2, 2 + appNameLen).toString("ascii");
      let idx = 2 + appNameLen;
      const appVersionLen = response[idx];
      idx += 1;
      const appVersion = response.slice(idx, idx + appVersionLen).toString("ascii");
      idx += appVersionLen;
      const appFlagsLen = response[idx];
      idx += 1;
      const flagLen = appFlagsLen;
      const flagsValue = response[idx];

      return {
        returnCode,
        errorMessage: errorCodeToString(returnCode),
        appName,
        appVersion,
        flagLen,
        flagsValue,
        // eslint-disable-next-line no-bitwise
        flagRecovery: (flagsValue & 1) !== 0,
        // eslint-disable-next-line no-bitwise
        flagSignedMcuCode: (flagsValue & 2) !== 0,
        // eslint-disable-next-line no-bitwise
        flagOnboarded: (flagsValue & 4) !== 0,
        // eslint-disable-next-line no-bitwise
        flagPinValidated: (flagsValue & 128) !== 0,
      };
    } catch (error) {
      throw ledgerErrorFromResponse(error);
    }
  }

  async getDeviceInfo(): Promise<DeviceInfoResponse> {
    try {
      const response: Buffer = await this.transport.send(0xe0, 0x01, 0, 0, Buffer.from([]), [
        LedgerErrorType.NoErrors,
        LedgerErrorType.AppDoesNotSeemToBeOpen,
      ]);

      const errorCodeData = response.slice(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

      if (returnCode === LedgerErrorType.AppDoesNotSeemToBeOpen) {
        throw new LedgerError(returnCode, "This command is only available in the Dashboard");
      }

      const targetId = response.slice(0, 4).toString("hex");

      let pos = 4;
      const secureElementVersionLen = response[pos];
      pos += 1;
      const seVersion = response.slice(pos, pos + secureElementVersionLen).toString();
      pos += secureElementVersionLen;

      const flagsLen = response[pos];
      pos += 1;
      const flag = response.slice(pos, pos + flagsLen).toString("hex");
      pos += flagsLen;

      const mcuVersionLen = response[pos];
      pos += 1;
      // Patch issue in mcu version
      let tmp = response.slice(pos, pos + mcuVersionLen);
      if (tmp[mcuVersionLen - 1] === 0) {
        tmp = response.slice(pos, pos + mcuVersionLen - 1);
      }
      const mcuVersion = tmp.toString();

      return {
        returnCode,
        errorMessage: errorCodeToString(returnCode),
        targetId,
        seVersion,
        flag,
        mcuVersion,
      };
    } catch (error) {
      throw ledgerErrorFromResponse(error);
    }
  }

  async getPublicKey(path: number[]): Promise<PubKeyResponse> {
    try {
      const serializedPath = await this.serializePath(path);
      const version = await this.getVersion();

      switch (version.major) {
        case 2: {
          const data = Buffer.concat([Helpers.serializeHRP("thor"), serializedPath]);
          return Helpers.getPublicKey(this.transport, data);
        }
        default:
          throw new LedgerError(LedgerErrorType.ExecutionError, "App Version is not supported");
      }
    } catch (e) {
      throw ledgerErrorFromResponse(e);
    }
  }

  async getAddressAndPubKey(path: number[], hrp: string): Promise<AddressPubKeyResponse> {
    const serializedPath: Buffer = await this.serializePath(path);
    const serializedHRP = Helpers.serializeHRP(hrp);
    const data = Buffer.concat([serializedHRP, serializedPath]);
    const response: Buffer = await this.transport.send(
      CLA,
      INS.GET_ADDR_SECP256K1,
      P1_VALUES.ONLY_RETRIEVE,
      0,
      data,
      [LedgerErrorType.NoErrors],
    );
    const errorCodeData = response.slice(-2);
    const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

    const compressedPk = Buffer.from(response.slice(0, 33));
    const bech32Address = Buffer.from(response.slice(33, -2)).toString();

    return {
      bech32Address,
      compressedPk,
      returnCode,
      errorMessage: errorCodeToString(returnCode),
    };
  }

  async showAddressAndPubKey(path: number[], hrp: string): Promise<AddressPubKeyResponse> {
    const serializedPath: Buffer = await this.serializePath(path);
    const data = Buffer.concat([Helpers.serializeHRP(hrp), serializedPath]);
    const response: Buffer = await this.transport.send(
      CLA,
      INS.GET_ADDR_SECP256K1,
      P1_VALUES.SHOW_ADDRESS_IN_DEVICE,
      0,
      data,
      [LedgerErrorType.NoErrors],
    );
    const errorCodeData = response.slice(-2);
    const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

    const compressedPk = Buffer.from(response.slice(0, 33));
    const bech32Address = Buffer.from(response.slice(33, -2)).toString();

    return {
      bech32Address,
      compressedPk,
      returnCode: returnCode,
      errorMessage: errorCodeToString(returnCode),
    };
  }

  async signSendChunk(chunkIdx: number, chunkNum: number, chunk: Buffer): Promise<SignResponse> {
    const version = await Helpers.getVersion(this.transport);
    switch (version.major) {
      case 2:
        return Helpers.signSendChunk(this.transport, chunkIdx, chunkNum, chunk);
      default:
        throw new LedgerError(LedgerErrorType.ExecutionError, "App Version is not supported");
    }
  }

  async sign(path: number[], message: string): Promise<SignResponse> {
    const chunks: Buffer[] = await this.signGetChunks(path, message);
    let response: SignResponse = await this.signSendChunk(1, chunks.length, chunks[0]);

    for (let i = 1; i < chunks.length; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      response = await this.signSendChunk(1 + i, chunks.length, chunks[i]);
      if (response.returnCode !== LedgerErrorType.NoErrors) {
        break;
      }
    }

    return response;
  }
}
