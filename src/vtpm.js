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

/* jslint maxlen: 80 */

(function () {

  "use strict";

  /*
   * Add a string format function
   */
  String.prototype.format = function () {
    var args = arguments;
    return this.replace(/\{([0-9]+)\}/g, function (i, j) {
      return !!args[j] ? args[j] : "{" + j + "}";
    });
  };

   /*
    * Load an iframe to simulate Workers if the Worker API isn't available. This
    * object wraps the native Worker object if Workers are available because the
    * following construct isn't allowed in strict mode:
    * if (!Worker) {
    *   function Worker(...) { ... }
    * }
    */
  function Worker(scriptFile, htmlFile) {
    if (Worker) {
      this.worker = new window.Worker(scriptFile);
      this.postMessage = function (msg) { this.worker.postMessage(msg); };
      this.worker.onmessage = recvWorkerMessage;
    } else {
      this.worker = document.createElement("iframe");
      this.worker.style.display = "none";
      this.worker.src = htmlFile;
      document.body.appendChild(this.worker);

      this.postMessage = function (msg) {
        this.worker.contentWindow.postMessage(msg,
                                              window.location.protocol + "//" +
                                              window.location.host +
                                              window.location.port);
      };
    }
  }

  /*
   *  global values that are initialized in init()
   *  The "user" is the frame that's using the vTPM.
   *  userSource is where we postMessage responses to.
   */
  var CURRENT_VERSION = "0.1", CURVE = vtpmComm.CURVE,
    WORKER_SCRIPT = "vtpm_worker.js", WORKER_FILE = "vtpm_worker.html",
    masterKey = {}, userOrigin = null, userSource = null, worker = null,
    unwrappedKeyPairs = {}, workerCbs = [], workerHandlers = {}, vtpmAPI = {},
    /*
     * unwrappedKeyPairs is a cache of already unwrapped key pairs, to avoid 
     * expensive localStorage lookups and decryptions every time.
     */

    /*
     * We keep some state to keep track of secureUI requests that
     * can't be processed immediately because another secureUI
     * request is in progress.
     * 
     * The inProgress flag keeps track of whether a secure UI
     * is currently being shown to the user. The reqQueue
     * holds the data needed to complete secureUI operations
     * that have been requested while the user is being shown
     * a secure UI prompt for another request.
     */
    secureUI = {
      inProgress: false,
      reqQueue: []
    },

    /*
     * We remember all the callback indices that we've seen for
     * each operation; the vTPM shouldn't allow the same callback
     * index to be used twice for the same operation.
     */
    usedCbs = {};

  function policyFromBlob(blob) {
    try {
      return JSON.parse(sjcl.json.decode(JSON.parse(blob).wrappedSk).adata);
    } catch (err) {
      return false;
    }
  }

  function postUserMessage(status, data) {
    var msg = JSON.stringify({
      "status": status,
      "data": data
    });
    userSource.postMessage(msg, (userOrigin === "null") ? "*" : userOrigin);
  }

  /*
   * Formats an error message and sends to user.
   */
  function sendError(err, data) {
    var msg = err;
    if (data && data !== "") {
      msg += ": " + data;
    }
    postUserMessage(vtpmComm.user.ST_ERROR, msg);
  }

  /*
   * Asks the worker to do some computation, via a postMessage
   * to a Worker thread, or to an iframe when Workers aren't
   * available.
   */
  function tryWorker(cmd, args, cb) {
    var callObj = {"command": cmd, "args": args}, callStr, workerCb;
    if (cb !== null && cb !== undefined) {
      callObj.args.cb = [callObj.args.cb, workerCbs.push(cb) - 1];
    }
    callStr = JSON.stringify(callObj);

    if (worker) {
      worker.postMessage(callStr);
    } else {
      sendError(vtpmComm.worker.ERR_NO_WORKER);
    }
  }

  function generateMasterKeyPair() {
    tryWorker(vtpmComm.worker.CMD_GEN_MASTER_KEY_PAIR, {"curve": CURVE},
             workerHandlers.onMasterKeyReady);
  }

  /*
   * Called by initAfterWorkerReady.
   * If the master key has been previously generated, we have
   * to send it the worker (since the worker can't access it
   * by itself from localStorage).
   */
  function sendKeyToWorker() {
    var pubStr = localStorage.vtpmMasterPub,
      secStr = localStorage.vtpmMasterSec;
    if (pubStr && secStr) {
      tryWorker(vtpmComm.worker.CMD_LOAD_MASTER_KEY_PAIR,
                {"pub": pubStr, "sec": secStr, "curve": CURVE},
                workerHandlers.onMasterKeyReady);
    }
  }

  /*
   * Loads up the master key pair from localStorage.
   * If there is no master key pair, we ask the worker thread to generate one.
   */
  function initAfterWorkerReady() {
    var pubStr = localStorage.vtpmMasterPub,
      secStr = localStorage.vtpmMasterSec;
    if (!pubStr || !secStr) {
      generateMasterKeyPair();
    } else {
      sendKeyToWorker();
    }
  }


  /*
   * Processes a message from the worker thread, where the message is a JSON
   * object with "status" and "data" properties.
   * Messages are sent when the worker has completed an operation and has the 
   * result.
   */
  function recvWorkerMessage(event) {
    var eventData, status, resp, cb;
    try {
      eventData = JSON.parse(event.data);
    } catch (err) {
      return sendError(vtpmComm.worker.ERR_BAD_RESP);
    }

    status = eventData.status;
    resp = eventData.data;

    /*
     * If we have a callback for this worker operation, then resp.cb looks like
     * this: [user callback index, vtpm callback index]. The first element is 
     * the callback to be called on the user page when the whole operation 
     * comples, and the second element is the vtpm.js callback to be called when
     * the worker completes its work.
     */
    if (resp && resp.cb instanceof Array &&
        status !== vtpmComm.worker.ST_NEED_SECURE_UI) {
      // Pop off the second element to call right now
      cb = resp.cb[1];
      /*
       * Transform resp.cb back into just the index for the user callback. If
       * workerCbs[cb] returns to the vtpm via postUserMessage, vtpm_user 
       * expects to see a single callback index, not an array.
       */
      resp.cb = resp.cb[0];
      workerCbs[cb](resp, status);
      delete workerCbs[cb];
    } else {
      /*
       *  A few special cases where we don't have a callback in the message data
       *  or we don't want to use it.
       */
      switch (status) {
      case vtpmComm.worker.ST_WORKER_READY:
        if (!Worker) {
          worker = event.source;
        }
        initAfterWorkerReady();
        break;
      case vtpmComm.worker.ST_UNWRAPPED_KEY_PAIR:
        /*
         * The worker is sending us an unwrapped key pair
         * to cache for later use.
         */
        unwrappedKeyPairs[resp.pk] = resp.unwrappedBlob;
        break;
      case vtpmComm.worker.ST_ERROR:
        sendError(resp);
        break;
      case vtpmComm.worker.ST_NEED_SECURE_UI:
        workerHandlers.onSecureUINeeded(resp);
        break;
      default:
        return sendError(vtpmComm.worker.ERR_BAD_RESP, status);
      }
    }
  }

   /*
    * args is an array that we get from vtpm_user that looks like this:
    * [cbIndex, "arg1val", "arg2val", ...]
    * 
    * transformArgs produces an object that looks like this:
    * {
    *   cb: cbIndex,
    *   arg1name: "arg1val",
    *   arg2name: "arg2val",
    *   ...
    * }
    * 
    * The resulting object is used by the API methods to easily read named
    * arguments, and also passed to the worker when necessary.
    */
  function transformArgs(args, apiFn) {
    var reqArgs = apiFn.argNames, optArgs = apiFn.optArgNames || [], i, opti,
      cb, result = {};

    if (args.length === 0 || reqArgs.length > args.length - 1) {
      sendError(vtpmComm.user.ERR_MISSING_ARG);
      return null;
    }

    result.cb = args[0];

    for (i = 0; i < reqArgs.length; i = i + 1) {
      if (args[i + 1] === null) {
        sendError(vtpmComm.user.ERR_MISSING_ARG, i + 1);
        return null;
      }
      result[reqArgs[i]] = args[i + 1];
    }

    for (i = reqArgs.length + 1; i < args.length; i = i + 1) {
      opti = i - reqArgs.length - 1;
      if (opti < optArgs.length) {
        result[optArgs[opti]] = args[i];
      }
    }

    return result;
  }

  /*
   * When the vTPM user sends a message requesting an API operation,
   * parse the status and data and call the appropriate function
   * to handle it.
   * If the operation requires any serious amount of computation,
   * the called function will ask the worker to do the computation.
   */
  function recvUserMessage(event) {
    var data, source, origin, fn, args, used, transformedArgs;
    try {
      data = JSON.parse(event.data);
    } catch (err) {
      return sendError(vtpmComm.user.ERR_MALFORMED_REQUEST);
    }
    source = event.source;
    origin = event.origin;

    if (userSource && origin !== userOrigin) {
      return sendError(vtpmComm.user.ERR_INVALID_ORIGIN, origin);
    }

    fn = data.command;
    args = data.args;

    if (!fn) {
      if (userSource) {
        return sendError(vtpmComm.user.ERR_MALFORMED_REQUEST, data);
      } else {
        return source.postMessage(vtpmComm.user.ST_ERROR, origin);
      }
    }

    /*
     * Check that the same callback index hasn't been used multiple
     * times for the same operation.
     */
    if (args.length > 0 && args[0] !== null && args[0] !== undefined) {
      used = usedCbs[fn];
      if (used) {
        if (used[args[0]]) {
          return sendError(vtpmComm.user.ERR_CALLBACK_USED_TWICE,
                           fn + " callback " + args[0]);
        }
        used[args[0]] = 1;
      } else {
        usedCbs[fn] = {};
        usedCbs[fn][args[0]] = 1;
      }
    }

    if (fn === vtpmComm.user.CMD_INIT) {
      vtpmAPI[fn](event.origin, source);
    } else if (vtpmAPI[fn] && typeof vtpmAPI[fn].fn === "function") {
      transformedArgs = transformArgs(args, vtpmAPI[fn]);
      if (transformedArgs) {
        vtpmAPI[fn].fn(transformedArgs, origin);
      }
    } else {
      sendError(vtpmComm.user.ERR_BAD_FN, fn);
    }
  }

  // Convenience functions for key storage

  // Stores a key pair in localStorage, but doesn't cache it in memory
  function storeKeyPair(pk, blob) {
    localStorage[pk] = JSON.stringify(blob);
  }

  // Retrieves a key pair from localStorage (not from cache!)
  function retrieveKeyPair(pk) {
    return localStorage[pk];
  }

  // Removes a key pair from localStorage and the cache
  function removeKeyPair(pk) {
    localStorage.removeItem(pk);
    unwrappedKeyPairs[pk] = null;
  }


  /*
   * If an unwrapped key for the given public key exists
   * in the cache, then add it to args as a property named
   * "unwrappedBlob". Otherwise retrieve the key pair's blob
   * from localStorage and add it as a property named "blob".
   * 
   * blobPropName and unwrappedBlobPropName are optional;
   * if provided, then the blob or unwrapped blob will be saved
   * in args as args[blobPropName] or args[unwrappedBlobPropName]
   * instead of the default args.blob or args.unwrappedBlob.
   * 
   * If origin is not null, then the data is only returned if the
   * origin in the policy matches origin.
   */
  function getBlobOrUnwrappedBlob(pk, args, origin, blobPropName,
                                  unwrappedBlobPropName) {
    var cachedKeyPair = unwrappedKeyPairs[pk], blob, policy;
    if (cachedKeyPair && (!origin || cachedKeyPair.policy.origin === origin)) {
      args[unwrappedBlobPropName || "unwrappedBlob"] = cachedKeyPair;
    } else {
      blob = retrieveKeyPair(pk);
      if (blob) {
        policy = policyFromBlob(blob);
      }
      /*
       * If we don't have a blob and a policy, or if we're looking for a
       * specific origin and we don't have a match, then don't return the data.
       */
      if (!(blob && policy) ||
          (origin && policy.origin !== origin)) {
        blob = undefined;
      }
      args[blobPropName || "blob"] = blob;
    }
  }

  /*
   * This object wraps methods that vtpm_user.js calls by issuing a
   * postMessage to the vTPM with the method name as the command.
   * 
   * For each API method, there is the function itself plus a list of the names
   * of the required arguments to the function. This list is used to transform
   * an array of arguments passed by the user into an args object with 
   * properties corresponding to each argument to the function. For example, for
   * the API method exampleMethod(plaintext), we get from vtpm_user.js an array
   * like [0, "abc"] and transformArgs([0, "abc"], vtpmAPI.exampleMethod)
   * produces the object:
   * {
   *   "plaintext": "abc",
   *   "cb": 0
   * }
   */
  vtpmAPI = {

    /*
     * Initialization first sets up the worker thread.
     * When that's done, controls passes to initAfterWorkerReady.
     */
    init: function (origin, source) {
      // The vTPM can only be initialized once
      if (userSource && userOrigin) {
        return sendError(vtpmComm.user.ERR_ALREADY_INITIALIZED);
      }

      // The vTPM can't be framed by another page on the vTPM's origin
      var par = window, foundSameOrigin = false;
      while (par !== window.top) {
        par = par.parent;
        try {
          if (par.location.href) {
            foundSameOrigin = true;
          }
        } catch (err) {
          // we expect an error
        }

        if (foundSameOrigin) {
          return source.postMessage(JSON.stringify({
            "status": vtpmComm.user.ST_ERROR,
            "data": vtpmComm.user.ERR_VTPM_ON_SAME_ORIGIN
          }), origin);
        }
      }

      // Initialize the vTPM
      userOrigin = origin;
      userSource = source;

      worker = new Worker(WORKER_SCRIPT, WORKER_FILE);
    },

    /*
     * Create a policy object and return it to the user.
     */
    generatePolicy: {
      argNames: ["notBefore", "notAfter", "keyUsage"],
      fn: function (args) {
        var policy = {};
        policy.version = CURRENT_VERSION;
        policy.notBefore = args.notBefore;
        policy.notAfter = args.notAfter;
        policy.keyUsage = args.keyUsage;
        postUserMessage(vtpmComm.user.ST_GEN_POLICY, {
          "respData": policy,
          "cb": args.cb
        });
      }
    },

    installKeyPair: {
      argNames: ["pk", "wrappedSk"],
      fn: function (args, origin) {
        var pOrigin = JSON.parse(sjcl.json.decode(args.wrappedSk.wrappedSk).
                                 adata).origin;
        if (pOrigin === origin) {
          storeKeyPair(args.pk, args.wrappedSk);
        }
        postUserMessage(vtpmComm.user.ST_INSTALL_KEY_PAIR, {
          "respData": {},
          "cb": args.cb
        });
      }
    },

    /*
     * Generate a key pair for the vTPM user to use (not a master key pair).
     */
    generateKeyPair: {
      argNames: ["policy"],
      fn: function (args, origin) {
        var policy = args.policy;
        policy.origin = origin;
        tryWorker(vtpmComm.worker.CMD_GEN_KEY_PAIR, {
          "curve": CURVE,
          "policy": policy,
          "cb": args.cb
        },
          workerHandlers.onKeyPairReady);
      }
    },

    /*
     * If the given public key corresponds to a stored key pair, then send
     * a message to the worker checking if the calling origin is allowed
     * to evict the key pair by the key policy.
     */
    evictKeyPair: {
      argNames: ["pk"],
      fn: function (args, origin) {
        if (unwrappedKeyPairs[args.pk]) {
          // The key has already been unwrapped, so we just need to check
          // the origin.
          if (unwrappedKeyPairs[args.pk].policy.origin === origin) {
            workerHandlers.onCheckEvictionAllowed({
              "pk": args.pk,
              "match": true,
              "cb": args.cb
            });
          } else {
            workerHandlers.onCheckEvictionAllowed({
              "pk": args.pk,
              "match": false,
              "cb": args.cb
            });
          }
        } else {
          var blob = retrieveKeyPair(args.pk), policy;
          if (blob) {
            policy = policyFromBlob(blob);
          }
          if (policy && policy.origin === origin) {
            tryWorker(vtpmComm.worker.CMD_CHECK_EVICTION_ALLOWED, {
              "pk": args.pk,
              "origin": origin,
              "blob": blob,
              "cb": args.cb
            },
              workerHandlers.onCheckEvictionAllowed);
          } else {
            return postUserMessage(vtpmComm.user.ST_EVICT_KEY_PAIR, {});
          }
        }
      }
    },

    /*
     * args has properties pk and data.
     */
    encrypt: {
      argNames: ["pk", "data"],
      fn: function (args) {
        args.curve = CURVE;
        tryWorker(vtpmComm.worker.CMD_ENCRYPT, args,
                  workerHandlers.onEncryptionDone);
      }
    },

    /*
     * args has properties pk and ct.
     */
    decrypt: {
      argNames: ["pk", "ct"],
      fn: function (args, origin) {
        args.origin = origin;
        args.curve = CURVE;
        getBlobOrUnwrappedBlob(args.pk, args, origin);
        tryWorker(vtpmComm.worker.CMD_DECRYPT, args,
                  workerHandlers.onDecryptionDone);
      }
    },

    /*
     * Returns the policy associated with args.pk to the user.
     * The policy's integrity is NOT verified before returning.
     */
    getPolicy: {
      argNames: ["pk"],
      fn: function (args, origin) {
        var policy, blob;
        if (unwrappedKeyPairs[args.pk]) {
          policy = unwrappedKeyPairs[args.pk].policy;
        } else {
          blob = retrieveKeyPair(args.pk);
          if (blob) {
            policy = policyFromBlob(blob);
          }
        }

        if (policy && policy.origin !== origin) {
          return postUserMessage(vtpmComm.user.ST_GET_POLICY,
                                 {"error": "Policy not found", "cb": args.cb});
        }

        return postUserMessage(vtpmComm.user.ST_GET_POLICY, {
          "respData": policy,
          "cb": args.cb
        });
      }
    },

    /*
     * args has only the property pk.
     */
    getWrappedKeyPair: {
      argNames: ["pk"],
      fn: function (args, origin) {
        args.origin = origin;
        args.blob = retrieveKeyPair(args.pk);
        var blob, policy;
        if (unwrappedKeyPairs[args.pk]) {
          blob = JSON.parse(args.blob);
          if (unwrappedKeyPairs[args.pk].policy.origin === origin) {
            workerHandlers.onGetWrappedKeyPair({
              "pk": args.pk,
              "wrappedSk": blob,
              "cb": args.cb
            });
          } else {
            workerHandlers.onGetWrappedKeyPair({
              "pk": args.pk,
              "error": vtpmComm.worker.ERR_UNWRAP_KEY_FAIL,
              "cb": args.cb
            });
          }
        } else {
          if (args.blob) {
            policy = policyFromBlob(args.blob);
          }
          if (policy && policy.origin === origin) {
            tryWorker(vtpmComm.worker.CMD_GET_KEY_PAIR, args,
                      workerHandlers.onGetWrappedKeyPair);
          } else {
            workerHandlers.onGetWrappedKeyPair({
              "pk": args.pk,
              "error": vtpmComm.worker.ERR_UNWRAP_KEY_FAIL,
              "cb": args.cb
            });
          }
        }
      }
    },

    /*
     * args has properties pk and data.
     */
    sign: {
      argNames: ["pk", "data"],
      fn: function (args, origin) {
        args.origin = origin;
        args.curve = CURVE;
        getBlobOrUnwrappedBlob(args.pk, args, origin);
        tryWorker(vtpmComm.worker.CMD_SIGN, args, workerHandlers.onSignDone);
      }
    },

    /*
     * args has properties pk, sig, data.
     */
    verify: {
      argNames: ["pk", "sig", "data"],
      fn: function (args) {
        args.curve = CURVE;
        tryWorker(vtpmComm.worker.CMD_VERIFY, args,
          workerHandlers.onVerifyDone);
      }
    },

    /*
     * args has properties rpk, spk, data.
     */
    signcrypt: {
      argNames: ["rpk", "spk", "data"],
      fn: function (args, origin) {
        args.origin = origin;
        args.curve = CURVE;
        // Get the blob associated with the signer's public key
        getBlobOrUnwrappedBlob(args.spk, args, origin);
        tryWorker(vtpmComm.worker.CMD_SIGNCRYPT, args,
          workerHandlers.onSigncryptionDone);
      }
    },

    /*
     * args has properties rpk, spk, ct.
     */
    verifydecrypt: {
      argNames: ["rpk", "spk", "ct"],
      fn: function (args, origin) {
        args.origin = origin;
        args.curve = CURVE;
        getBlobOrUnwrappedBlob(args.rpk, args, origin);
        tryWorker(vtpmComm.worker.CMD_VERIFYDECRYPT, args,
          workerHandlers.onVerifydecryptionDone);
      }
    },

    /*
     * args has properties signingPk, targetPk.
     */
    certifyPublicKey: {
      argNames: ["signingPk", "targetPk"],
      optArgNames: ["secureUIConfirm", "secureUIDeny"],
      fn: function (args, origin) {
        args.origin = origin;
        args.curve = CURVE;
        getBlobOrUnwrappedBlob(args.signingPk, args, origin);
        getBlobOrUnwrappedBlob(args.targetPk, args, null, "targetBlob",
          "targetUnwrappedBlob");

        tryWorker(vtpmComm.worker.CMD_CERTIFY_PK, args,
          workerHandlers.onCertifyPkDone);
      }
    },

    /*
     * args has properties signingPk, targetPk, cert.
     */
    verifyPublicKeyCert: {
      argNames: ["verifyPk", "targetPk", "cert"],
      fn: function (args) {
        args.curve = CURVE;
        args.targetBlob = retrieveKeyPair(args.targetPk);
        tryWorker(vtpmComm.worker.CMD_VERIFY_PK_CERT, args,
          workerHandlers.onVerifyCertDone);
      }
    },

    onSecureUIHidden: {
      argNames: [],
      fn: function () {
        secureUI.inProgress = false;

        /*
         * If there are other secure UI requests that have been queued,
         * dequeue one and show the prompt for it now.
         */
        if (secureUI.reqQueue.length > 0) {
          workerHandlers.onSecureUINeeded(secureUI.reqQueue.shift());
        }
      }
    }
  };

  /*
   *  The following functions mostly handle worker messages by posting 
   *  appropriate responses back to the user.
   */

  workerHandlers = {

    /*
     * Once a master key pair has been generated, store the key pair in memory 
     * and in localStorage; then notify the user that the vTPM is ready to use.
     */
    onMasterKeyReady: function (args) {
      var curve = sjcl.ecc.curves['c' + CURVE];
      masterKey.pub = new sjcl.ecc.elGamal.publicKey(curve, args.pk);
      masterKey.sec = new sjcl.ecc.elGamal.secretKey(curve, args.sk);
      localStorage.vtpmMasterPub = args.pk;
      localStorage.vtpmMasterSec = args.sk;

      postUserMessage(vtpmComm.user.ST_READY, {});
    },

    /*
     * When a key pair has been generated, store it in localStorage and return 
     * the public key to the user.
     */
    onKeyPairReady: function (keyPair) {
      var storedKey = {"wrappedSk": keyPair.wrappedSk, "tag": keyPair.tag};
      storeKeyPair(keyPair.pk, storedKey);
      return postUserMessage(vtpmComm.user.ST_GEN_KEY_PAIR, {
        "respData": keyPair.pk,
        "cb": keyPair.cb
      });
    },

    /*
     * pkOrigin is an object with a match property and a pk property.
     * pkOrigin.match is true if the calling origin is allowed to evict
     * pkOrigin.pk.
     */
    onCheckEvictionAllowed: function (pkOrigin) {
      if (pkOrigin.match) {
        removeKeyPair(pkOrigin.pk);
      }
      return postUserMessage(vtpmComm.user.ST_EVICT_KEY_PAIR, {
        "respData": {},
        "cb": pkOrigin.cb
      });
    },

    onEncryptionDone: function (ct) {
      return postUserMessage(vtpmComm.user.ST_ENCRYPT, {
        "respData": ct,
        "cb": ct.cb
      });
    },

    onDecryptionDone: function (pt) {
      return postUserMessage(vtpmComm.user.ST_DECRYPT, {
        "respData": pt,
        "cb": pt.cb
      });
    },

    onGetWrappedKeyPair: function (key_pair) {
      return postUserMessage(vtpmComm.user.ST_GET_KEY_PAIR, {
        "respData": key_pair,
        "cb": key_pair.cb
      });
    },

    onSignDone: function (sigResp) {
      return postUserMessage(vtpmComm.user.ST_SIGNATURE, {
        "respData": sigResp,
        "cb": sigResp.cb
      });
    },

    onVerifyDone: function (verify) {
      return postUserMessage(vtpmComm.user.ST_VERIFY, {
        "respData": verify.valid,
        "cb": verify.cb
      });
    },

    onSigncryptionDone: function (ct) {
      return postUserMessage(vtpmComm.user.ST_SIGNCRYPT, {
        "respData": ct,
        "cb": ct.cb
      });
    },

    onVerifydecryptionDone: function (pt) {
      return postUserMessage(vtpmComm.user.ST_VERIFYDECRYPT, {
        "respData": pt,
        "cb": pt.cb
      });
    },

    onCertifyPkDone: function (cert) {
      return postUserMessage(vtpmComm.user.ST_CERTIFY_PK, {
        "respData": cert,
        "cb": cert.cb
      });
    },

    onVerifyCertDone: function (verify) {
      return postUserMessage(vtpmComm.user.ST_VERIFY_PK_CERT, {
        "respData": verify.valid,
        "cb": verify.cb
      });
    },

    onSecureUIResponse: function (opData, confirm) {
      postUserMessage(vtpmComm.user.ST_HIDE_SECURE_UI, {});
      document.getElementById("secureui").style.display = "none";

      var cmd, onFinish, denyData;
      switch (opData.op) {
      case vtpmComm.worker.op.SIGNATURE:
        cmd = vtpmComm.worker.CMD_FINISH_SIG;
        onFinish = workerHandlers.onSignDone;
        denyData = {"error": "User denied signature", "cb": opData.cb};
        break;
      case vtpmComm.worker.op.SIGNCRYPT:
        cmd = vtpmComm.worker.CMD_FINISH_SIGNCRYPT;
        onFinish = workerHandlers.onSigncryptionDone;
        denyData = {"error": "User denied signature", "cb": opData.cb};
        break;
      case vtpmComm.worker.op.CERTIFY_PK:
        cmd = vtpmComm.worker.CMD_FINISH_CERTIFY_PK;
        onFinish = workerHandlers.onCertifyPkDone;
        denyData = {"error": "User denied certificate", "cb": opData.cb};
        break;
      }

      if (confirm) {
        tryWorker(cmd, opData);
      } else {
        onFinish(denyData);
      }
    },

    onSecureUINeeded: function (opData) {
      if (secureUI.inProgress) {
        /*
         * If the user is currently looking at a secure UI prompt for a
         * different request, then we just queue this request. The secure UI for
         * this request will be shown when the user takes an action on the
         * current secure UI prompt.
         */
        secureUI.reqQueue.push(opData);
      } else {
        // Load up the secure UI content
        var confirm = document.getElementById("confirm"),
          deny = document.getElementById("deny");

        if (opData.op === vtpmComm.worker.op.SIGNATURE ||
            opData.op === vtpmComm.worker.op.SIGNCRYPT) {
          confirm.textContent = vtpmSecureUI.confirmSignature.
            format(opData.data);
          deny.textContent = vtpmSecureUI.denySignature;
        } else if (opData.op === vtpmComm.worker.op.CERTIFY_PK) {
          confirm.textContent = (opData.secureUIConfirm ||
                                 vtpmSecureUI.confirmCertificate).
            format(opData.origin, opData.targetOrigin ||
                   vtpmComm.user.NONEXISTENT_ORIGIN);
          deny.textContent = opData.secureUIDeny ||
            vtpmSecureUI.denyCertificate;
        }

        // Always default to the negative option
        deny.selected = true;

        document.getElementById("submit").onclick = function () {
          workerHandlers.onSecureUIResponse(opData, confirm.selected);
        };

        document.getElementById("secureui").style.display = "block";

        secureUI.inProgress = true;

        // Tell the vtpm user to show the iframe
        return postUserMessage(vtpmComm.user.ST_NEED_SECURE_UI, {});
      }
    }
  };

  function sendLoaded() {
    window.parent.postMessage(JSON.stringify({
      "status": vtpmComm.user.ST_LOADED
    }), "*");
  }

  function recvMessage(event) {
    if (event.origin === window.location.protocol + "//" +
        window.location.host + window.location.port) {
      recvWorkerMessage(event);
    } else {
      recvUserMessage(event);
    }
  }

  if (document.addEventListener) {
    document.addEventListener("load", sendLoaded, true);
  } else if (document.attachEvent) {
    document.attachEvent("load", sendLoaded);
  }

  if (window.addEventListener) {
    window.addEventListener("message", recvMessage, true);
  } else if (window.attachEvent) {
    window.attachEvent("message", recvMessage);
  }

}());