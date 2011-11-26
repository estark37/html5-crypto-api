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
 * This script performs expensive cryptographic operations for the vTPM.
 * Ideally, this script is run in a Worker. If Workers aren't available,
 * the vTPM will include this script in an iframe, and operations will
 * run synchronously.
 */

var vtpmWorker = (function () {
  "use strict";

  var masterKey = {},
    workersEnabled = false,
    /*
     * Constants that get appened to certifyPublicKey() and sign() outputs,
     * to ensure that a public key certification can't be forged by calling
     * sign().
     */
    certifyAppend = "certify",
    signAppend = "sign";

  try {
    importScripts('sjcl.js');
    importScripts('vtpm_const.js');
    workersEnabled = true;
  } catch (err) {
    // workers aren't enabled?
    workersEnabled = false;
  }

  /*
   * Formats a message to the vTPM as a JSON object with properties "status" and
   * "data". Sends it via postMessage (if Workers are available) or just returns
   * the message if Workers aren't available.
   */
  function postVTPMMessage(status, data) {
    var msg = JSON.stringify({
      "status": status,
      "data": data
    });
    if (vtpmWorker.workers()) {
      return postMessage(msg);
    } else {
      return window.parent.postMessage(msg,
          window.location.protocol + "//" + window.location.host +
            window.location.port);
    }
  }

  /*
   * Sends an error message back to the vTPM via postMessage.
   * The error message will include the ERROR status followed by
   * "<err>: <data>".
   */
  function sendError(err, data) {
    var msg = err;
    if (data && data !== "") {
      msg += ": " + data;
    }
    return postVTPMMessage(vtpmComm.worker.ST_ERROR, msg);
  }

  /*
   * Sends a message to the vTPM letting it know that the worker has
   * the master key loaded and ready to use.
   */
  function sendMasterKey(args) {
    var pk = masterKey.pub.stringify(),
      sk = masterKey.sec.stringify();
    return postVTPMMessage(vtpmComm.worker.ST_MASTER_KEY_READY, {
      "pk": pk,
      "sk": sk,
      "cb": args.cb
    });
  }

  /*
   * Just checks if the policy dates are valid. Returns a bool.
   */
  function checkPolicyValidity(policy) {
    var now = new Date();
    return (now >= new Date(policy.notBefore) && now <=
      new Date(policy.notAfter));
  }

  function policyFromVerifiedBlob(pt) {
    return JSON.parse(sjcl.json.decode(pt.wrappedSk).adata);
  }

  /*
   * Just decrypts a wrapped secret key (doesn't check policy).
   * Returns false if the decryption fails.
   */
  function tryDecryptKey(pk, blob) {
    var wrappedSk = blob.wrappedSk, key, params, pt,
      sig, hash, masterPub;
    try {
      key = masterKey.sec.unkem(blob.tag);
      params = {
        mode: "ccm"
      };
      pt = JSON.parse(sjcl.decrypt(key, wrappedSk, params));
      sig = pt.sig;
      hash = sjcl.hash.sha256.hash(JSON.stringify({
        "pk": pk,
        "sk": pt.sk,
        "policy": policyFromVerifiedBlob(blob)
      }));
      masterPub = new sjcl.ecc.ecdsa.publicKey(
        sjcl.ecc.curves["c" + vtpmComm.CURVE],
        masterKey.pub.stringify()
      );
      masterPub.verify(hash, sig);
      return pt.sk;
    } catch (err) {
      return false;
    }
  }

  function getOrigin(pk, blob, unwrappedBlob) {
    if (unwrappedBlob) {
      return unwrappedBlob.policy.origin;
    } else if (blob) {
      var parsedBlob = JSON.parse(blob),
        skBits = tryDecryptKey(pk, parsedBlob);
      if (skBits) {
        return policyFromVerifiedBlob(parsedBlob).origin;
      }
    }
    return false;
  }

  /*
   * Checks if a cached secret key has a policy with valid dates and
   * if it's keyUsage field permits the operations specified by policy.
   * Returns false if there is a policy violation, and returns the
   * secret key bits if the policy checks pass.
   */
  function checkCachedKeyPolicy(unwrappedBlob, origin, policy) {
    var skBits = unwrappedBlob.sk;

    if (checkPolicyValidity(unwrappedBlob.policy)) {
      if (origin !== unwrappedBlob.policy.origin ||
          !(unwrappedBlob.policy.keyUsage & policy)) {
        skBits = false;
      }
    } else {
      skBits = false;
    }
    return skBits;
  }

  /*
   * Unwraps the given blob of data (wrappedSk), as long as args.origin is
   * allowed to use the key (as specified in the key's policy), the key is
   * not expired, and the given privileges are allowed by the policy.
   * 
   * keyUsage is optional: the usage policy won't be checked if keyUsage isn't
   * given.
   * 
   * Returns false if there is a policy violation or the key doesn't
   * decrypt/authenticate. Returns the key bits otherwise.
   */
  function tryUnwrapKey(pk, blob, origin, keyUsage) {
    var pt = tryDecryptKey(pk, blob), policy, genOrigin;
    if (!pt) {
      return false;
    }

    policy = policyFromVerifiedBlob(blob);

    // first verify the dates of validity
    if (checkPolicyValidity(policy)) {
      // If the key is not expired, then verify that the key usage is allowed
      if (keyUsage === null || policy.keyUsage & keyUsage) {
        // Verify that this origin is allowed to use the key
        genOrigin = policy.origin;
        if (genOrigin === origin) {
          /*
           * If we've successfully unwrapped the key, then send the unwrapped
           * key to the vTPM to cache so that we don't have to unwrap it again.
           */
          postVTPMMessage(vtpmComm.worker.ST_UNWRAPPED_KEY_PAIR, {
            "pk": pk,
            "unwrappedBlob": {"sk": pt, "policy": policy}
          });
          return pt;
        } else {
          return false;
        }
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  function checkSecureUI(args, pk, data, nextStatus, keyUsage, op, next) {
    var skBits = false, policy, blob, requireSecureUI;
    if (args.unwrappedBlob) {
      skBits = checkCachedKeyPolicy(args.unwrappedBlob, args.origin, keyUsage);
    } else if (args.blob) {
      blob = JSON.parse(args.blob);
      policy = JSON.parse(sjcl.json.decode(blob.wrappedSk).adata);
      skBits = tryUnwrapKey(pk, blob, args.origin, keyUsage);
    }

    if (!skBits) {
      return postVTPMMessage(nextStatus, {
        "error": vtpmComm.worker.ERR_UNWRAP_KEY_FAIL,
        "cb": args.cb
      });
    }

    /*
     * At this point, either args.unwrappedBlob or blob exists.
     */
    if (nextStatus === vtpmComm.worker.ST_CERTIFY_PK) {
      requireSecureUI = true;
    } else {
      requireSecureUI = (args.unwrappedBlob ?
          args.unwrappedBlob.policy.keyUsage : policy.keyUsage)
        & vtpmKeyPolicy.usage.requireSecureUIOnSigs;
    }

    if (requireSecureUI) {
      args.skBits = skBits;
      args.op = op;
      return postVTPMMessage(vtpmComm.worker.ST_NEED_SECURE_UI, args);
    } else {
      return next(args.curve, pk, skBits, data, args.cb);
    }
  }

  function signAfterSecureUICheck(curveNum, pk, skBits, data, cb) {
    var curve = sjcl.ecc.curves['c' + curveNum],
      sk = new sjcl.ecc.ecdsa.secretKey(curve, skBits),
      hash = sjcl.hash.sha256.hash(data + signAppend),
      sig = sk.sign(hash, 0);

    return postVTPMMessage(vtpmComm.worker.ST_SIGNATURE, {
      "data": sig,
      "cb": cb
    });
  }

  function signcryptAfterSecureUICheck(curveNum, rpkBits, skBits, pt, cb) {
    var curve = sjcl.ecc.curves['c' + curveNum],
      rpk = new sjcl.ecc.elGamal.publicKey(curve, rpkBits),
      // recipient's public key
      ssk = new sjcl.ecc.ecdsa.secretKey(curve, skBits),
      // sender's secret key

      // Append the recipient's public key to the data, then sign it
      data = JSON.stringify({"payload": pt, "rpk": rpkBits}),

      hash = sjcl.hash.sha256.hash(data),
      sig = ssk.sign(hash, 0),

      // Append the signature
      dataAndSig = JSON.stringify({"data": data, "sig": sig}),

      wrapKey = rpk.kem(0),

      key = wrapKey.key,
      params = {
        mode: "ccm"
      },
      ct = sjcl.encrypt(key, dataAndSig, params);

    return postVTPMMessage(vtpmComm.worker.ST_SIGNCRYPT, {
      "ct": ct,
      "tag": wrapKey.tag,
      "cb": cb
    });

  }

  function certifyPkAfterSecureUICheck(curveNum, pk, skBits, targetPk, cb) {
    var curve = sjcl.ecc.curves['c' + curveNum],

      signerSk = new sjcl.ecc.ecdsa.secretKey(curve, skBits),

      hash = sjcl.hash.sha256.hash(targetPk + certifyAppend),
      sig = signerSk.sign(hash, 0);

    return postVTPMMessage(vtpmComm.worker.ST_CERTIFY_PK, {
      "sig": sig,
      "target": targetPk,
      "cb": cb
    });
  }

  function msgHandler(event) {
    var eventData, fn, args;
    try {
      eventData = JSON.parse(event.data);
    } catch (err) {
      sendError(vtpmComm.worker.ERR_BAD_CMD);
    }

    fn = eventData.command;
    args = eventData.args;

    switch (fn) {
    case vtpmComm.worker.CMD_FINISH_SIG:
      signAfterSecureUICheck(args.curve, args.pk, args.skBits, args.data,
                             args.cb);
      break;
    case vtpmComm.worker.CMD_FINISH_SIGNCRYPT:
      signcryptAfterSecureUICheck(args.curve, args.rpk, args.skBits, args.data,
                                  args.cb);
      break;
    case vtpmComm.worker.CMD_FINISH_CERTIFY_PK:
      if (!args.targetOrigin) {
        return postVTPMMessage(vtpmComm.worker.ST_CERTIFY_PK, {
          "error": vtpmComm.worker.ERR_CERTIFY_UNKNOWN_KEY,
          "cb": args.cb
        });
      }
      certifyPkAfterSecureUICheck(args.curve, args.pk, args.skBits,
                                  args.targetPk, args.cb);
      break;
    default:
      if (typeof vtpmWorker[fn] === "function") {
        vtpmWorker[fn](args);
      } else {
        sendError(vtpmComm.worker.ERR_BAD_CMD, fn);
      }
    }
  }

  if (workersEnabled) {
    self.onmessage = msgHandler;
  } else {
    if (window.addEventListener) {
      window.addEventListener("message", msgHandler, false);
    } else if (window.attachEvent) {
      window.attachEvent("message", msgHandler);
    }
  }

  return {

    workers: function () { return workersEnabled; },

    sendReady: function () {
      return postVTPMMessage(vtpmComm.worker.ST_WORKER_READY);
    },

    /*
     * Given strings representing the master public and secret keys,
     * loads them into memory for use in crypto operations later.
     */
    loadMasterKeyPair: function (args) {
      var curve = sjcl.ecc.curves['c' + args.curve];
      masterKey.pub = new sjcl.ecc.elGamal.publicKey(curve, args.pub);
      masterKey.sec = new sjcl.ecc.elGamal.secretKey(curve, args.sec);
      return sendMasterKey(args);
    },

    /*
     * Generates a master key pair, stores it in memory, and returns it
     * to the vTPM.
     */
    generateMasterKeyPair: function (args) {
      var curve = sjcl.ecc.curves['c' + args.curve],
        keys = sjcl.ecc.elGamal.generateKeys(curve, 0);
      masterKey.pub = keys.pub;
      masterKey.sec = keys.sec;
      return sendMasterKey(args);
    },


    /*
     * Generates a (non-master) key pair and returns it to the vTPM.
     * If Workers are available, this function also sends a message to
     * the vTPM telling it to cache the unwrapped secret key for later
     * use.
     */
    generateKeyPair: function (args) {
      var curve = sjcl.ecc.curves['c' + args.curve],
        keys = sjcl.ecc.elGamal.generateKeys(curve, 0),

        pk = keys.pub.stringify(),
        sk = keys.sec.stringify(),
        masterSk,
        hash,
        sig,
        wrapKey,
        params,
        rp,
        ct;

      /*
       * Send the unwrapped key with policy back to the vTPM to cache.
       * If the key pair will be used again on this page, we won't need
       * to look it up and unwrap it again.
       */
      postVTPMMessage(vtpmComm.worker.ST_UNWRAPPED_KEY_PAIR, {
        "pk": pk,
        "unwrappedBlob": {"sk": sk, "policy": args.policy}
      });

      /*
       * Now sign it, wrap it, and return it for the vTPM to put into
       * localStorage.
       */
      masterSk = new sjcl.ecc.ecdsa.secretKey(curve, masterKey.sec.stringify());
      hash = sjcl.hash.sha256.hash(JSON.stringify({
        "pk": pk,
        "sk": sk,
        "policy": args.policy
      }));
      sig = masterSk.sign(hash, 0);

      wrapKey = masterKey.pub.kem(0);
      params = {
        mode: "ccm",
        adata: JSON.stringify(args.policy)
      };
      ct = sjcl.encrypt(wrapKey.key, JSON.stringify({
        "sk": sk,
        "sig": sig
      }), params, rp);
      return postVTPMMessage(vtpmComm.worker.ST_KEY_PAIR, {
        "pk": pk,
        "sk": sk,
        "wrappedSk": ct,
        "tag": wrapKey.tag,
        "cb": args.cb
      });
    },


    /*
     * The following functions perform expensive operations for the vTPM and
     * return the results via postMessage.
     */

    encrypt: function (args) {
      var curve = sjcl.ecc.curves['c' + args.curve],
        pk = new sjcl.ecc.elGamal.publicKey(curve, args.pk),
        wrapKey = pk.kem(0),

        key = wrapKey.key,
        params = {
          mode: "ccm"
        },
        ct = sjcl.encrypt(key, args.data, params);

      return postVTPMMessage(vtpmComm.worker.ST_ENCRYPT, {
        "ct": ct,
        "tag": wrapKey.tag,
        "cb": args.cb
      });
    },

    decrypt: function (args) {
      var curve = sjcl.ecc.curves['c' + args.curve],
        pk = new sjcl.ecc.elGamal.publicKey(curve, args.pk),
        skBits = false,
        blob,
        sk,
        tag,
        key,
        params,
        pt;

      if (args.unwrappedBlob) {
        /*
         * The unwrapped key was cached, so we just need to check the policy.
         */
        skBits = checkCachedKeyPolicy(args.unwrappedBlob, args.origin,
          vtpmKeyPolicy.usage.dataEncipherment);
      } else if (args.blob) {
        blob = JSON.parse(args.blob);
        skBits = tryUnwrapKey(args.pk, blob, args.origin,
                              vtpmKeyPolicy.usage.dataEncipherment);
      }

      // skBits == false signals that we couldn't unwrap the key
      if (!skBits) {
        return postVTPMMessage(vtpmComm.worker.ST_DECRYPT, {
          "error": vtpmComm.worker.ERR_UNWRAP_KEY_FAIL,
          "cb": args.cb
        });
      }

      // Now that we've unwrapped the key, do the actual decryption
      sk = new sjcl.ecc.elGamal.secretKey(curve, skBits);
      tag = args.ct.tag;
      key = sk.unkem(tag);
      params = {
        mode: "ccm"
      };

      try {
        pt = sjcl.decrypt(key, args.ct.ct, params);
      } catch (err) {
        pt = "";
      }

      return postVTPMMessage(vtpmComm.worker.ST_DECRYPT, {
        "data": pt,
        "valid": (pt !== ""),
        "cb": args.cb
      });
    },

    /*
     * A key eviction is allowed as long as the key is successfully unwrapped
     * and the origin that generated the key is the origin trying to evict it.
     * 
     * In the case that the key pair was in the cache, then vtpm.js will handle
     * the check and it won't ever go to the worker.
     */
    checkEvictionAllowed: function (args) {
      var skBits = false, blob, pkOrigin;
      if (args.blob) {
        blob = JSON.parse(args.blob);
        skBits = tryUnwrapKey(args.pk, blob, args.origin);
      }
      pkOrigin = {
        "pk": args.pk,
        "origin": args.origin,
        "cb": args.cb
      };

      // pkOrigin.match is true iff the key was successfully unwrapped and the
      // generating origin of the key is equal to the query origin
      pkOrigin.match = skBits && (args.origin === policyFromVerifiedBlob(blob).
                                  origin);

      return postVTPMMessage(vtpmComm.worker.ST_CHECK_EVICTION_ALLOWED,
                             pkOrigin);
    },

    /*
     * If the unwrapped key pair is cached, then the export will take place in
     * vtpm.js and won't get to the worker.
     */
    getWrappedKeyPair: function (args) {
      var skBits = false, blob;

      if (args.blob) {
        blob = JSON.parse(args.blob);
        skBits = tryUnwrapKey(args.pk, blob, args.origin);
      }

      if (skBits) {
        return postVTPMMessage(vtpmComm.worker.ST_WRAPPED_KEY_PAIR, {
          "pk": args.pk,
          "wrappedSk": blob,
          "cb": args.cb
        });
      }

      return postVTPMMessage(vtpmComm.worker.ST_WRAPPED_KEY_PAIR, {
        "pk": args.pk,
        "error": vtpmComm.worker.ERR_UNWRAP_KEY_FAIL,
        "cb": args.cb
      });
    },

    sign: function (args) {
      return checkSecureUI(args, args.pk, args.data,
        vtpmComm.worker.ST_SIGNATURE,
        vtpmKeyPolicy.usage.digitalSignature,
        vtpmComm.worker.op.SIGNATURE,
        signAfterSecureUICheck);
    },

   /*
    * This is a wrapper around signAfterSecureUICheck that is only called when
    * Workers aren't available.
    */
    finishSigAfterSecureUI: function (args) {
      return signAfterSecureUICheck(args.curve, args.pk, args.skBits, args.data,
                                    args.cb);
    },

    verify: function (args) {
      var curve = sjcl.ecc.curves['c' + args.curve],
        pk = new sjcl.ecc.ecdsa.publicKey(curve, args.pk),
        hash = sjcl.hash.sha256.hash(args.data + signAppend),

        valid;
      try {
        pk.verify(hash, args.sig);
        valid = true;
      } catch (err) {
        valid = false;
      }

      return postVTPMMessage(vtpmComm.worker.ST_VERIFY, {
        "valid": valid,
        "cb": args.cb
      });
    },


    signcrypt: function (args) {
      return checkSecureUI(args, args.rpk, args.data,
                           vtpmComm.worker.ST_SIGNCRYPT,
                           vtpmKeyPolicy.usage.digitalSignature,
                           vtpmComm.worker.op.SIGNCRYPT,
                           signcryptAfterSecureUICheck);
    },

    finishSigncryptAfterSecureUI: function (args) {
      return signcryptAfterSecureUICheck(args.curve, args.rpk, args.skBits,
                                         args.data, args.cb);
    },

    verifydecrypt: function (args) {
      var curve = sjcl.ecc.curves['c' + args.curve],
        spk = new sjcl.ecc.ecdsa.publicKey(curve, args.spk),
        rBlob,
        rsk,
        tag,
        key,
        params,
        pt,
        dataAndSig,
        data,
        sig,
        hash,

        skBits = false;
      if (args.unwrappedBlob) {
        skBits = checkCachedKeyPolicy(args.unwrappedBlob, args.origin,
                                      vtpmKeyPolicy.usage.dataEncipherment);
      } else if (args.blob) {
        rBlob = JSON.parse(args.blob);
        skBits = tryUnwrapKey(args.pk, rBlob, args.origin,
                              vtpmKeyPolicy.usage.dataEncipherment);
      }
      if (!skBits) {
        return postVTPMMessage(vtpmComm.worker.ST_VERIFYDECRYPT, {
          "error": vtpmComm.worker.ERR_UNWRAP_KEY_FAIL,
          "cb": args.cb
        });
      }

      rsk = new sjcl.ecc.elGamal.secretKey(curve, skBits);

      tag = args.ct.tag;
      key = rsk.unkem(tag);
      params = {
        mode: "ccm"
      };

      try {
        dataAndSig = JSON.parse(sjcl.decrypt(key, args.ct.ct, params));
        data = dataAndSig.data;
        sig = dataAndSig.sig;

        hash = sjcl.hash.sha256.hash(data);
        spk.verify(hash, sig);

        data = JSON.parse(data);
        /*
         * One last step: check that the public key embedded in data is the
         * recipient's public key.
         */
        if (data.rpk !== args.rpk) {
          throw "Bad recipient public key";
        }

        pt = data.payload;
      } catch (err) {
        pt = "";
      }

      return postVTPMMessage(vtpmComm.worker.ST_VERIFYDECRYPT, {
        "pt": pt,
        "valid": (pt !== ""),
        "cb": args.cb
      });
    },

    certifyPublicKey: function (args) {
       // Unwrap the target key and get the target origin
      args.targetOrigin = getOrigin(args.targetPk, args.targetBlob,
                                    args.targetUnwrappedBlob);
      if (args.targetOrigin === undefined) {
        args.targetOrigin = null;
      }

      return checkSecureUI(args, args.pk, args.targetPk,
                           vtpmComm.worker.ST_CERTIFY_PK,
                           vtpmKeyPolicy.usage.keyCertSign,
                           vtpmComm.worker.op.CERTIFY_PK,
                           certifyPkAfterSecureUICheck);
    },

    finishCertifyPkAfterSecureUI: function (args) {
      return certifyPkAfterSecureUICheck(args.curve, args.pk, args.skBits,
                                         args.targetPk, args.cb);
    },

    verifyPublicKeyCert: function (args) {
      if (args.cert.target !== args.targetPk) {
        return postVTPMMessage(vtpmComm.worker.ST_VERIFY_PK_CERT, {
          "valid": false,
          "cb": args.cb
        });
      }

      var curve = sjcl.ecc.curves['c' + args.curve],
        verifyPk = new sjcl.ecc.ecdsa.publicKey(curve, args.verifyPk),
        hash = sjcl.hash.sha256.hash(args.targetPk + certifyAppend),
        sig = args.cert.sig,
        valid;

      try {
        verifyPk.verify(hash, sig);
        valid = true;
      } catch (err) {
        valid = false;
      }

      return postVTPMMessage(vtpmComm.worker.ST_VERIFY_PK_CERT, {
        "valid": valid,
        "cb": args.cb
      });
    }

  };
}());



/*
 * If this script is being loaded as a worker,
 * then notify the vTPM that it's loaded.
 */

if (vtpmWorker.workers()) {
  vtpmWorker.sendReady();
}