import THORChainApp, { LedgerErrorType } from "../../src/index";
import TransportNodeHid from "@ledgerhq/hw-transport-node-hid";
import secp256k1 from "secp256k1";
import crypto from "crypto";
import Transport from "@ledgerhq/hw-transport";

require("dotenv").config({ path: "./.e2e.env" });

const { THOR_ADDRESS = "unknown address", THOR_PUB_KEY = "unknown pub key" } = process.env;

const JEST_TIMEOUT = 60000;
// Use same time out for all tests in this file
jest.setTimeout(JEST_TIMEOUT);

describe("THORChainApp e2e", () => {
  let transport: Transport;
  let app: THORChainApp;
  beforeAll(async () => {
    transport = await TransportNodeHid.create(1000);
    app = new THORChainApp(transport);
  });

  afterAll(async () => {});

  it("getVersion", async () => {
    // *****
    // Requirements: Open `THORChain` app on Ledger
    // *****
    const resp = await app.getVersion();

    console.log(resp);

    expect(resp.returnCode).toEqual(LedgerErrorType.NoErrors);
    expect(resp.errorMessage).toEqual("No errors");
    expect(resp).toHaveProperty("testMode");
    expect(resp).toHaveProperty("major");
    expect(resp).toHaveProperty("minor");
    expect(resp).toHaveProperty("patch");
    expect(resp.testMode).toEqual(false);
  });

  it("publicKey", async () => {
    // *****
    // Requirements: Open `THORChain` app on Ledger
    // *****

    // Derivation path. First 3 items are automatically hardened!
    const path = [44, 931, 0, 0, 0];

    const resp = await app.getPublicKey(path);

    // console.log(resp);

    expect(resp.returnCode).toEqual(LedgerErrorType.NoErrors);
    expect(resp.errorMessage).toEqual("No errors");
    expect(resp).toHaveProperty("compressedPk");
    expect(resp.compressedPk.length).toEqual(33);
    expect(resp.compressedPk.toString("hex")).toEqual(THOR_PUB_KEY);
  });

  it("getAddressAndPubKey", async () => {
    // *****
    // Requirements: Open `THORChain` app on Ledger
    // *****

    // Derivation path. First 3 items are automatically hardened!
    const path = [44, 931, 0, 0, 0];
    const resp = await app.getAddressAndPubKey(path, "thor");

    // console.log(resp);

    expect(resp.returnCode).toEqual(LedgerErrorType.NoErrors);
    expect(resp.errorMessage).toEqual("No errors");

    expect(resp).toHaveProperty("bech32Address");
    expect(resp).toHaveProperty("compressedPk");

    expect(resp.bech32Address).toEqual(THOR_ADDRESS);
    expect(resp.compressedPk.length).toEqual(33);
  });

  it("appInfo", async () => {
    // *****
    // Requirements: Open `THORChain` app on Ledger
    // *****
    const resp = await app.getAppInfo();

    // console.log(resp);

    expect(resp.returnCode).toEqual(LedgerErrorType.NoErrors);
    expect(resp.errorMessage).toEqual("No errors");

    expect(resp).toHaveProperty("appName");
    expect(resp).toHaveProperty("appVersion");
    expect(resp).toHaveProperty("flagLen");
    expect(resp).toHaveProperty("flagsValue");
    expect(resp).toHaveProperty("flagRecovery");
    expect(resp).toHaveProperty("flagSignedMcuCode");
    expect(resp).toHaveProperty("flagOnboarded");
    expect(resp).toHaveProperty("flagPinValidated");
  });

  it("deviceInfo", async () => {
    // *****
    // Requirements: Open `Dashboard` on Ledger (but not `THORChain` app)
    // *****
    const resp = await app.getDeviceInfo();

    console.log(resp);

    expect(resp.returnCode).toEqual(LedgerErrorType.NoErrors);
    expect(resp.errorMessage).toEqual("No errors");

    expect(resp).toHaveProperty("targetId");
    expect(resp).toHaveProperty("seVersion");
    expect(resp).toHaveProperty("flag");
    expect(resp).toHaveProperty("mcuVersion");
  });

  it("sign_and_verify_MsgSend", async () => {
    // *****
    // Requirements: Open `THORChain` app on Ledger and follow instructions
    // *****

    // Derivation path. First 3 items are automatically hardened!
    const path = [44, 931, 0, 0, 0];
    const message = `{"account_number":"588","chain_id":"thorchain","fee":{"amount":[],"gas":"2000000"},"memo":"TestMemo","msgs":[{"type":"thorchain/MsgSend","value":{"amount":[{"amount":"150000000","denom":"rune"}],"from_address":"${THOR_ADDRESS}","to_address":"tthor10xgrknu44d83qr4s4uw56cqxg0hsev5e68lc9z"}}],"sequence":"5"}`;

    const responsePk = await app.getPublicKey(path);
    console.log("responsePk", responsePk);
    expect(responsePk.returnCode).toEqual(LedgerErrorType.NoErrors);
    expect(responsePk.errorMessage).toEqual("No errors");

    const responseSign = await app.sign(path, message);
    console.log("responseSign", responseSign);
    expect(responseSign.returnCode).toEqual(LedgerErrorType.NoErrors);
    expect(responseSign.errorMessage).toEqual("No errors");

    // // Check signature is valid
    const hash = crypto.createHash("sha256");
    const msgHash = hash.update(message).digest();

    const signatureDER = responseSign?.signature ?? Buffer.alloc(0);
    const signature = secp256k1.signatureImport(signatureDER);
    console.log(`signature`, signature);
    const signatureOk = secp256k1.ecdsaVerify(signature, msgHash, responsePk.compressedPk);
    // console.log('signatureOks', signatureOk);
    expect(signatureOk).toBeTruthy();
  });

  it("sign_invalid", async () => {
    // *****
    // Requirements: Open `THORChain` app on Ledger and follow instructions
    // *****

    const path = [44, 931, 0, 0, 0]; // Derivation path. First 3 items are automatically hardened!
    const invalidMessage = `{"chain_id":"thorchain","fee":{"amount":[],"gas":"10000000"},"memo":"","msgs":[{"type":"thorchain/MsgDeposit","value":{"coins":[{"amount":"330000000","asset":"THOR.RUNE"}],"memo":"SWAP:BNB.BNB:tbnb1qk2m905ypazwfau9cn0qnr4c4yxz63v9u9md20:","signer":"${THOR_ADDRESS}"}}],"sequence":"6"}`;

    const responseSign = await app.sign(path, invalidMessage);

    // console.log(responseSign);

    expect(responseSign.returnCode).toEqual(LedgerErrorType.DataIsInvalid);
    expect(responseSign.errorMessage).toEqual("Data is invalid : JSON Missing account number");
  });
});
