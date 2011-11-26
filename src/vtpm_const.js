/*
Copyright 2011 Google Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

/* jslint maxlen: 80, indent: 2 */

/*
 * Constants used by the vTPM, the vTPM user, and the vTPM worker thread.
 * Includes string literals used in the postMessage API to communicate,
 * and key policy constants.
 * 
 * To ask the worker to do something, the vTPM posts a message of the
 * following form:
 *   <command>(<args>)
 * where command is one of the vtpmComm.CMD_... constants, and args is a
 * stringified JSON object.
 * 
 * When the worker has something to return to the vTPM, it posts a message
 * of the following form:
 *   <status><vtpmComm.END_STATUS><data>
 * where <status> is one of the vtpmComm.ST_... constants and <data> is
 * the data to be returned (i.e. a stringified public key, a ciphertext, etc.).
 */

var vtpmKeyPolicy = (function () {
  "use strict";

  return {
    usage: {
      digitalSignature: 0x01,
      keyEncipherment: 0x02,
      dataEncipherment: 0x04,
      keyCertSign: 0x08,
      requireSecureUIOnSigs: 0x10,
      extendedPolicy: 0x20
    }
  };
}()),

  vtpmSecureUI = (function () {
    "use strict";

    return {
      confirmSignature: "Yes, I want to sign this statement: \"{0}\"",
      denySignature: "No, I do not want to sign.",
      confirmCertificate: "Yes, I want the website {0} to sign a public key "
        + "from the website {1}.",
      denyCertificate: "No, I do not want to sign."
    };
  }()),

  vtpmComm = (function () {
    "use strict";

    return {
      CURVE: 192,
      /*
       * Commands and responses for vTPM <-> worker communication.
       */

      worker: {
        // commands from the vTPM to the worker
        CMD_GEN_KEY_PAIR: "generateKeyPair",
        CMD_LOAD_MASTER_KEY_PAIR: "loadMasterKeyPair",
        CMD_GEN_MASTER_KEY_PAIR: "generateMasterKeyPair",
        CMD_ENCRYPT: "encrypt",
        CMD_DECRYPT: "decrypt",
        CMD_CHECK_EVICTION_ALLOWED: "checkEvictionAllowed",
        CMD_GET_KEY_PAIR: "getWrappedKeyPair",
        CMD_SIGN: "sign",
        CMD_VERIFY: "verify",
        CMD_SIGNCRYPT: "signcrypt",
        CMD_VERIFYDECRYPT: "verifydecrypt",
        CMD_CERTIFY_PK: "certifyPublicKey",
        CMD_VERIFY_PK_CERT: "verifyPublicKeyCert",
        CMD_FINISH_SIG: "signAfterSecureUICheck",
        CMD_FINISH_SIGNCRYPT: "signcryptAfterSecureUICheck",
        CMD_FINISH_CERTIFY_PK: "finishCertifyPkAfterSecureUI",

        // errors reported by the worker
        ERR_BAD_CMD: "Malformed command from vTPM",
        ERR_UNWRAP_KEY_FAIL: "Failed to unwrap secret key associated with "
                             + "public key",
        ERR_CERTIFY_UNKNOWN_KEY: "Can't certify a public key that doesn't exist"
          + " in vTPM",

        // statuses returned by the worker to the vTPM
        ST_ERROR: "ERROR",
        ST_KEY_PAIR: "onKeyPairReady",
        ST_MASTER_KEY_READY: "onMasterKeyReady",
        ST_ENCRYPT: "onEncryptionDone",
        ST_DECRYPT: "onDecryptionDone",
        ST_CHECK_EVICTION_ALLOWED: "onCheckEvictionAllowed",
        ST_WRAPPED_KEY_PAIR: "onGetWrappedKeyPair",
        ST_SIGNATURE: "onSignDone",
        ST_VERIFY: "onVerifyDone",
        ST_SIGNCRYPT: "onSigncryptionDone",
        ST_VERIFYDECRYPT: "onVerifydecryptionDone",
        ST_CERTIFY_PK: "onCertifyPkDone",
        ST_VERIFY_PK_CERT: "onVerifyCertDone",
        ST_UNWRAPPED_KEY_PAIR: "UNWRAPPED_KEY_PAIR",
        ST_NEED_SECURE_UI: "onSecureUINeeded",
        ST_WORKER_READY: "WORKER_READY",

        // errors caused by worker responses (reported by the vTPM)
        ERR_BAD_RESP: "Malformed response from vTPM worker",
        ERR_FROM_WORKER: "Error from vTPM worker",
        ERR_NO_WORKER: "No worker available",

        /*
         * Operations performed by the worker that might require a secure UI.
         */
        op: {
          SIGNATURE: "SIGNATURE",
          SIGNCRYPT: "SIGNCRYPT",
          CERTIFY_PK: "CERTIFY_PK"
        }
      },

      /*
       * Commands and responses from user <-> vTPM communication. (The user
       * is the web page using the vTPM.)
       */

      user: {
        // separate status from associated data
        END_STATUS: " ",

        NONEXISTENT_ORIGIN: "unknown website",

        // statuses returned to the user from the vTPM
        ST_ERROR: "ERROR",
        ST_READY: "READY",
        ST_LOADED: "LOADED",
        ST_GEN_POLICY: "GEN_POLICY",
        ST_GEN_KEY_PAIR: "KEY_PAIR",
        ST_ENCRYPT: "ENCRYPT",
        ST_DECRYPT: "DECRYPT",
        ST_EVICT_KEY_PAIR: "EVICT_KEY_PAIR",
        ST_GET_POLICY: "GET_POLICY",
        ST_GET_KEY_PAIR: "GET_KEY_PAIR",
        ST_SIGNATURE: "SIGNATURE",
        ST_VERIFY: "VERIFY",
        ST_SIGNCRYPT: "SIGNCRYPT",
        ST_VERIFYDECRYPT: "VERIFYDECRYPT",
        ST_CERTIFY_PK: "CERTIFY_PK",
        ST_VERIFY_PK_CERT: "VERIFY_CERT",
        ST_NEED_SECURE_UI: "NEED_SECURE_UI",
        ST_HIDE_SECURE_UI: "HIDE_SECURE_UI",
        ST_SECURE_UI_DENY: "SECURE_UI_DENY",
        ST_INSTALL_KEY_PAIR: "INSTALL_KEY_PAIR",

        // error messages reported from the vTPM to the user
        ERR_MALFORMED_REQUEST: "Malformed request",
        ERR_ALREADY_INITIALIZED: "vTPM already initialized",
        ERR_BAD_FN: "Unrecognized function call",
        ERR_GEN_KEY: "Error generating key pair",
        ERR_INVALID_ORIGIN: "Message received from invalid orign",
        ERR_VTPM_ON_SAME_ORIGIN: "Can't use the vTPM on the same origin as the"
          + " vTPM",
        ERR_CALLBACK_USED_TWICE: "Same callback index used multiple times for "
                                 + "same operations",
        ERR_MISSING_ARG: "Missing argument",

        // commands issued by user to vTPM
        CMD_INIT: "init",
        CMD_SECURE_UI_HIDDEN: "onSecureUIHidden"
      }
    };
  }());