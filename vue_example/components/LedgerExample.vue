<template>
  <div class="THORChainLedger">
    <input id="webusb" v-model="transportChoice" type="radio" value="WebUSB" />
    <label for="webusb">WebUSB</label>
    <input id="webhid" v-model="transportChoice" type="radio" value="WebHID" />
    <label for="webhid">WebHID</label>
    <br />
    <!--
        Commands
    -->
    <button @click="getVersion">
      Get Version
    </button>

    <button @click="appInfo">
      AppInfo
    </button>

    <button @click="getPublicKey">
      Get pubkey only
    </button>

    <button @click="getAddress">
      Get Address and Pubkey
    </button>

    <button @click="showAddress">
      Show Address and Pubkey
    </button>

    <button @click="signExampleTx">
      Sign Example TX
    </button>
    <!--
        Commands
    -->
    <ul id="ledger-status">
      <li v-for="item in ledgerStatus" :key="item.index">
        {{ item.msg }}
      </li>
    </ul>
  </div>
</template>

<script>
// eslint-disable-next-line import/no-extraneous-dependencies
import TransportWebUSB from "@ledgerhq/hw-transport-webusb";
// eslint-disable-next-line import/no-extraneous-dependencies
import TransportWebHID from "@ledgerhq/hw-transport-webhid";
import THORChainApp, { LedgerErrorType } from "../../lib/index";

const path = [44, 931, 0, 0, 0];

export default {
  name: "THORChainLedger",
  props: {},
  data() {
    return {
      deviceLog: [],
      transportChoice: "WebUSB",
    };
  },
  computed: {
    ledgerStatus() {
      return this.deviceLog;
    },
  },
  methods: {
    log(msg) {
      this.deviceLog.push({
        index: this.deviceLog.length,
        msg,
      });
    },
    async getTransport() {
      let transport = null;

      this.log(`Trying to connect via ${this.transportChoice}...`);
      if (this.transportChoice === "WebUSB") {
        try {
          transport = await TransportWebUSB.create();
        } catch (e) {
          this.log(e);
        }
      }

      if (this.transportChoice === "WebHID") {
        try {
          transport = await TransportWebHID.create(10000);
        } catch (e) {
          this.log(e);
        }
      }

      return transport;
    },
    async getVersion() {
      this.deviceLog = [];

      // Given a transport (WebUSB/WebHID) it is possible instantiate the app
      const transport = await this.getTransport();
      const app = new THORChainApp(transport);

      // now it is possible to access all commands in the app
      const response = await app.getVersion();
      if (response.returnCode !== LedgerErrorType.NoErrors) {
        this.log(`Error [${response.returnCode}] ${response.errorMessage}`);
        return;
      }

      this.log("Response received!");
      this.log(`App Version ${response.major}.${response.minor}.${response.patch}`);
      this.log(`Device Locked: ${response.deviceLocked}`);
      this.log(`Test mode: ${response.testMode}`);
      this.log("Full response:");
      this.log(response);
    },
    async appInfo() {
      this.deviceLog = [];

      // Given a transport (WebUSB/WebHID) it is possible instantiate the app
      const transport = await this.getTransport();
      const app = new THORChainApp(transport);

      // now it is possible to access all commands in the app
      const response = await app.getAppInfo();
      if (response.returnCode !== LedgerErrorType.NoErrors) {
        this.log(`Error [${response.returnCode}] ${response.errorMessage}`);
        return;
      }

      this.log("Response received!");
      this.log(response);
    },
    async getPublicKey() {
      this.deviceLog = [];

      // Given a transport (WebUSB/WebHID) it is possible instantiate the app
      const transport = await this.getTransport();
      const app = new THORChainApp(transport);

      let response = await app.getVersion();
      this.log(`App Version ${response.major}.${response.minor}.${response.patch}`);
      this.log(`Device Locked: ${response.deviceLocked}`);
      this.log(`Test mode: ${response.testMode}`);

      // now it is possible to access all commands in the app
      response = await app.getPublicKey(path);
      if (response.returnCode !== LedgerErrorType.NoErrors) {
        this.log(`Error [${response.returnCode}] ${response.errorMessage}`);
        return;
      }

      this.log("Response received!");
      this.log("Full response:");
      this.log(response);
    },
    async getAddress() {
      this.deviceLog = [];

      // Given a transport (WebUSB/WebHID) it is possible instantiate the app
      const transport = await this.getTransport();
      const app = new THORChainApp(transport);

      let response = await app.getVersion();
      this.log(`App Version ${response.major}.${response.minor}.${response.patch}`);
      this.log(`Device Locked: ${response.deviceLocked}`);
      this.log(`Test mode: ${response.testMode}`);

      // now it is possible to access all commands in the app
      response = await app.getAddressAndPubKey(path, "tthor");
      if (response.returnCode !== LedgerErrorType.NoErrors) {
        this.log(`Error [${response.returnCode}] ${response.errorMessage}`);
        return;
      }

      this.log("Response received!");
      this.log("Full response:");
      this.log(response);
    },
    async showAddress() {
      this.deviceLog = [];

      // Given a transport (WebUSB/WebHID) it is possible instantiate the app
      const transport = await this.getTransport();
      const app = new THORChainApp(transport);

      let response = await app.getVersion();
      this.log(`App Version ${response.major}.${response.minor}.${response.patch}`);
      this.log(`Device Locked: ${response.deviceLocked}`);
      this.log(`Test mode: ${response.testMode}`);

      // now it is possible to access all commands in the app
      this.log("Please click in the device");
      response = await app.showAddressAndPubKey(path, "tthor");
      if (response.returnCode !== LedgerErrorType.NoErrors) {
        this.log(`Error [${response.returnCode}] ${response.errorMessage}`);
        return;
      }

      this.log("Response received!");
      this.log("Full response:");
      this.log(response);
    },
    async signExampleTx() {
      this.deviceLog = [];

      // Given a transport (U2F/HID/WebUSB) it is possible instantiate the app
      const transport = await this.getTransport();
      const app = new THORChainApp(transport);

      let response = await app.getVersion();
      this.log(`App Version ${response.major}.${response.minor}.${response.patch}`);
      this.log(`Device Locked: ${response.deviceLocked}`);
      this.log(`Test mode: ${response.testMode}`);

      // now it is possible to access all commands in the app
      const message = Buffer.from('{"account_number":"588","chain_id":"thorchain","fee":{"amount":[],"gas":"2000000"},"memo":"TestMemo","msgs":[{"type":"thorchain/MsgSend","value":{"amount":[{"amount":"150000000","denom":"rune"}],"from_address":"tthor1c648xgpter9xffhmcqvs7lzd7hxh0prgv5t5gp","to_address":"tthor10xgrknu44d83qr4s4uw56cqxg0hsev5e68lc9z"}}],"sequence":"5"}');
      response = await app.sign(path, message);

      this.log("Response received!");
      this.log("Full response:");
      this.log(response);
    },
  },
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
h3 {
  margin: 40px 0 0;
}

button {
  padding: 5px;
  font-weight: bold;
  font-size: medium;
}

ul {
  padding: 10px;
  text-align: left;
  alignment: left;
  list-style-type: none;
  background: black;
  font-weight: bold;
  color: greenyellow;
}
</style>
