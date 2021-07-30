/** ******************************************************************************
 *  (c) 2019 ZondaX GmbH
 *  (c) 2016-2017 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import type Transport from "@ledgerhq/hw-transport";
import crypto from "crypto";
import Ripemd160 from "ripemd160";
import { bech32 } from "bech32";
import { publicKeyv2, serializePathv2, signSendChunkv2 } from "./helper";
import {
  APP_KEY,
  CHUNK_SIZE,
  CLA,
  INS,
  LedgerError,
  errorCodeToString,
  getVersion,
  P1_VALUES,
  LedgerErrorType,
  ledgerErrorFromResponse,
} from "./common";
import { AppInfoResponse, SignResponse, VersionResponse } from "./types";

export * from "./types";
export { LedgerError };

export default class THORChainApp {
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

  static serializeHRP(hrp: string): Buffer {
    if (hrp == null || hrp.length < 3 || hrp.length > 83) {
      throw new LedgerError(LedgerErrorType.HPRInvalid);
    }
    const buf = Buffer.alloc(1 + hrp.length);
    buf.writeUInt8(hrp.length, 0);
    buf.write(hrp, 1);
    return buf;
  }

  static getBech32FromPK(hrp: string, pk: string): string {
    if (pk.length !== 33) {
      throw new LedgerError(LedgerErrorType.PKInvalidBytes);
    }

    const hashSha256 = crypto.createHash("sha256").update(pk).digest();
    const hashRip = new Ripemd160().update(hashSha256).digest();
    const words = bech32.toWords(hashRip);
    return bech32.encode(hrp, words);
  }

  async serializePath(path: number[]): Promise<Buffer> {
    const version = await getVersion(this.transport);

    if (version.returnCode !== LedgerErrorType.NoErrors) {
      throw new LedgerError(version.returnCode, version.errorMessage);
    }

    switch (version.major) {
      case 2:
        return serializePathv2(path);
      default:
        throw new LedgerError(LedgerErrorType.ExecutionError, "App Version is not supported");
    }
  }

  async signGetChunks(path: number[], message: Buffer): Promise<Buffer[]> {
    const serializedPath = await this.serializePath(path);

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
    return getVersion(this.transport);
  }

  async getAppInfo(): Promise<AppInfoResponse> {
    try {
      const response: Buffer = await this.transport.send(0xb0, 0x01, 0, 0);
      const errorCodeData = response.slice(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

      let appName = "err";
      let appVersion = "err";
      let flagLen = 0;
      let flagsValue = 0;

      if (response[0] !== 1) {
        // Ledger responds with format ID 1. There is no spec for any format != 1
        throw new LedgerError(LedgerErrorType.DeviceIsBusy, "response format ID not recognized");
      } else {
        const appNameLen = response[1];
        appName = response.slice(2, 2 + appNameLen).toString("ascii");
        let idx = 2 + appNameLen;
        const appVersionLen = response[idx];
        idx += 1;
        appVersion = response.slice(idx, idx + appVersionLen).toString("ascii");
        idx += appVersionLen;
        const appFlagsLen = response[idx];
        idx += 1;
        flagLen = appFlagsLen;
        flagsValue = response[idx];
      }

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
        flagPINValidated: (flagsValue & 128) !== 0,
      };
    } catch (error) {
      throw ledgerErrorFromResponse(error);
    }
  }

  async deviceInfo() {
    try {
      const response: Buffer = await this.transport.send(0xe0, 0x01, 0, 0, Buffer.from([]), [
        LedgerErrorType.NoErrors,
        LedgerErrorType.AppDoesNotSeemToBeOpen,
      ]);

      const errorCodeData = response.slice(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

      if (returnCode === 0x6e00) {
        return {
          return_code: returnCode,
          error_message: "This command is only available in the Dashboard",
        };
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
        return_code: returnCode,
        error_message: errorCodeToString(returnCode),
        // //
        targetId,
        seVersion,
        flag,
        mcuVersion,
      };
    } catch (error) {
      throw ledgerErrorFromResponse(error);
    }
  }

  async publicKey(path: number[]) {
    try {
      const serializedPath = await this.serializePath(path);
      const version = await this.getVersion();

      switch (version.major) {
        case 2: {
          const data = Buffer.concat([THORChainApp.serializeHRP("thor"), serializedPath]);
          return publicKeyv2(this.transport, data);
        }
        default:
          throw new LedgerError(LedgerErrorType.ExecutionError, "App Version is not supported");
      }
    } catch (e) {
      throw ledgerErrorFromResponse(e);
    }
  }

  async getAddressAndPubKey(path: number[], hrp: string) {
    const serializedPath: Buffer = await this.serializePath(path);
    const serializedHRP = THORChainApp.serializeHRP(hrp);
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
      bech32_address: bech32Address,
      compressed_pk: compressedPk,
      returnCode: returnCode,
      errorMessage: errorCodeToString(returnCode),
    };
  }

  async showAddressAndPubKey(path: number[], hrp: string) {
    const serializedPath: Buffer = await this.serializePath(path);
    const data = Buffer.concat([THORChainApp.serializeHRP(hrp), serializedPath]);
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
      bech32_address: bech32Address,
      compressed_pk: compressedPk,
      returnCode: returnCode,
      errorMessage: errorCodeToString(returnCode),
    };
  }

  async signSendChunk(chunkIdx: number, chunkNum: number, chunk: Buffer) {
    const version = await this.getVersion();
    switch (version.major) {
      case 2:
        return signSendChunkv2(this.transport, chunkIdx, chunkNum, chunk);
      default:
        throw new LedgerError(LedgerErrorType.ExecutionError, "App Version is not supported");
    }
  }

  async sign(path: number[], message: Buffer) {
    const chunks: Buffer[] = await this.signGetChunks(path, message)
    const response: SignResponse = await this.signSendChunk(1, chunks.length, chunks[0])
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
          signature: null as null | Buffer,
        };

        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i]);
          if (result.returnCode !== LedgerErrorType.NoErrors) {
            break;
          }
        }

        return {
          returnCode: result.returnCode,
          errorMessage: result.errorMessage,
          signature: result.signature,
        };
  }
}
