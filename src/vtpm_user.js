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

/* jslint maxlen: 80 , indent: 2*/

/*
 * This file defines window.crypto expandos, which handle communication
 * between the vTPM user and the vTPM itself.
 * 
 * This file should be included on the vTPM user's web page.
 */

/*
Sadly, without aliasing window.crypto, our window.crypto functions
sometimes get garbage-collected in FF.
See: https://bugzilla.mozilla.org/show_bug.cgi?id=655297
*/
var foo = window.crypto;

(function () {

  "use strict";

  var vtpmWindow = null,
    vtpmFrame = null,
    vtpmParent = null,
    loaded = false,
    initializing = false,
    postInitActions = [],
    callbacks = [],

    VTPM_ORIGIN = "http://VTPM_ORIGIN",
    VTPM_SRC = "http://URL_TO_VTPM/vtpm.html",

    // error messages
    ERR_MALFORMED_RESPONSE = "Malformed response from vTPM",
    ERR_NO_STATUS_IN_RESP = "No status in response from vTPM",
    ERR_NO_VTPM = "No vTPM detected",
    ERR_FROM_VTPM = "Error reported by vTPM",
    ERR_INVALID_ORIGIN = "Message received from non-vTPM origin",

    /*
     *  Specifies the method names of each window.crypto API call.
     */
    API = ["generatePolicy", "generateKeyPair", "evictKeyPair", "encrypt",
           "decrypt", "getPolicy", "getWrappedKeyPair", "sign", "verify",
           "signcrypt", "verifydecrypt", "certifyPublicKey",
           "verifyPublicKeyCert", "installKeyPair"];

  /*
   * Convenience function that builds a JSON object with "command" and "args"
   * properties. Returns the stringified object.
   */
  function buildFnCall(name, args) {
    return JSON.stringify({
      "command": name,
      "args": args
    });
  }

  /* 
   * Calls the registered error handling callback if there is one,
   * and throws an exception otherwise.
   */
  function handleError(msg, handler) {
    if (handler) {
      handler(msg);
    } else {
      throw msg;
    }
  }

  function pushCb(cb, cbError) {
    return (callbacks.push([cb, cbError]) - 1);
  }

  function postMessage(callStr) {
    vtpmWindow.postMessage(callStr, VTPM_ORIGIN);
  }

  /*
   *  This function is called once the vTPM is initialized, and it fills in the
   *  window.crypto functions with their real implementations that make calls in
   *  to the vTPM.
   */
  function initializeRealAPI() {
    API.forEach(function (fn) {
      window.crypto[fn] = function () {
        var msgArgs,
          cb = null,
          errorCb = null,
          i,
          sendArgs = [];
        /*
         * sendArgs is the array of arguments that we send to the vTPM, which is
         * the arguments to this function with the callback functions stripped
         * out, and the callback index tacked on to the beginning, i.e.:
         * [cbIndex, "arg1val", "arg2val", ...]
         */

        /*
         * We expect the callback to be the first function in the arguments, and
         * the error callback to be the second function.
         */
        Array.prototype.slice.call(arguments).forEach(function (arg) {
          if (typeof arg === "function") {
            if (cb === null) {
              cb = arg;
            } else if (errorCb === null) {
              errorCb = arg;
            }
          } else {
            sendArgs.push(arg);
          }
        });

        msgArgs = [pushCb(cb, errorCb)].concat(sendArgs);

        postMessage(buildFnCall(fn, msgArgs));
      };
    });
  }

  function fireSecureUIEvent(eventName) {
    var event;
    event = document.createEvent("Events");
    event.initEvent(eventName, true, false);
    document.dispatchEvent(event);
  }

  function hideSecureUI(secureUI) {
    secureUI.style.display = "none";
    postMessage(buildFnCall(vtpmComm.user.CMD_SECURE_UI_HIDDEN, {}));
    fireSecureUIEvent("secureUIInvisible");
  }

  function showSecureUI(secureUI) {
    // Fire a secureUI event to tell the vTPM user that the secure UI is now
    // visible.
    fireSecureUIEvent("secureUIVisible");
  }

  /*
   * Processes a message incoming from the vTPM.
   */
  function receiveMessage(event) {
    var eventData, status, data, errorCb = null, source = event.source,
      origin = event.origin, secureUI = vtpmFrame, i, action, fn;

    try {
      eventData = JSON.parse(event.data);
    } catch (err) {
      return handleError(ERR_MALFORMED_RESPONSE);
    }

    status = eventData.status;
    data = eventData.data;
    if (!status) {
      handleError(ERR_MALFORMED_RESPONSE);
    }

    if (initializing && data && data.cb && callbacks[data.cb] instanceof Array) {
      errorCb = callbacks[data.cb][1];
    }

    if (origin !== VTPM_ORIGIN) {
      handleError(ERR_INVALID_ORIGIN, errorCb);
      return;
    }

    if (status === vtpmComm.user.ST_LOADED) {
      if (vtpmFrame) {
        vtpmWindow = vtpmFrame.contentWindow;
      } else {
        handleError(ERR_NO_VTPM, errorCb);
      }

      if (vtpmWindow) {
        postMessage(buildFnCall(vtpmComm.user.CMD_INIT, []));
      } else {
        handleError(ERR_NO_VTPM, errorCb);
      }
    } else if (status === vtpmComm.user.ST_READY) {
      initializeRealAPI();

      /*
       *  If any window.crypto operations were requested before the
       *  vtpm was initialized, then we perform those operations now.
       */
      for (i = 0; i < postInitActions.length; i = i + 1) {
        action = postInitActions[i];
        fn = window.crypto[action.fn];
        if (typeof fn === 'function') {
          fn.apply(this, action.args);
        }
      }
      postInitActions = undefined;
    } else if (status === vtpmComm.user.ST_ERROR) {
      // vtpm sent an error message, so bubble it up to the user page
      handleError(ERR_FROM_VTPM + ": " + data);
    } else if (status === vtpmComm.user.ST_NEED_SECURE_UI) {
      /*
       * This is a special case; we just show the secure UI but don't
       * need to call a callback.
       */
      showSecureUI(secureUI);
    } else if (status === vtpmComm.user.ST_HIDE_SECURE_UI) {
      hideSecureUI(secureUI);
    } else {
      if (data.cb !== null && data.cb !== undefined 
          && callbacks[data.cb] !== undefined
          && typeof callbacks[data.cb][0] === "function") {
        callbacks[data.cb][0](data.respData);
        delete callbacks[data.cb];
      } else {
        handleError(ERR_NO_STATUS_IN_RESP + ": " + eventData, errorCb);
      }
    }
  }

  function createVTPM() {
    if (!vtpmFrame) {
      vtpmFrame = document.createElement("iframe");
      vtpmFrame.style.display = "none";
      vtpmFrame.setAttribute("id", "vtpm_frame");
      (vtpmParent || document.body).appendChild(vtpmFrame);
    }
  }

  function init() {
    if (loaded && !initializing) {
      initializing = true;
      vtpmFrame.src = VTPM_SRC;
    }
  }

  /*
   * Called when window.load is fired. Creates the iframe for the vTPM element
   * and adds it to the DOM (either to the element set via
   * window.crypto.setVTPMParent or to document.body). If API operations have
   * been requested before window.load fired, then these operations will be in
   * postInitActions, and we should go ahead and initialize the vTPM by setting
   * its src attribute.
   */
  function initAfterLoad() {
    createVTPM();
    loaded = true;

    if (postInitActions.length > 0) {
      init();
    }
  }

  /*
   * Initialize the window.crypto API with temporary functions that queue any
   * calls and defer them until after the vTPM is initialized.
   */
  API.forEach(function (fn) {
    window.crypto[fn] = function () {
      postInitActions.push({
        fn: fn,
        args: arguments
      });
      init();
    };
  });

  window.crypto.getVTPM = function () {
    return vtpmFrame;
  };

  /*
   * NOTE: setVTPMParent can only be called before the vTPM is initialized, i.e.
   * before any other window.crypto calls. This is because moving the vTPM
   * around in the DOM will cause the vTPM to reload the page inside it.
   */
  window.crypto.setVTPMParent = function (elem) {
    if (!initializing) {
      vtpmParent = elem;
      if (vtpmFrame) {
        elem.appendChild(vtpmFrame);
      }
    }
  };

  if (window.addEventListener) {
    window.addEventListener("message", receiveMessage, true);
    window.addEventListener("load", initAfterLoad, true);
  } else if (window.attachEvent) {
    window.attachEvent("message", receiveMessage);
    window.attachEvent("load", initAfterLoad);
  }

}());
