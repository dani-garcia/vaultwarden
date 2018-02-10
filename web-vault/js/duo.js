/**
 * Duo Web SDK v2
 * Copyright 2017, Duo Security
 */

(function (root, factory) {
    /*eslint-disable */
    if (typeof define === 'function' && define.amd) {
        // AMD. Register as an anonymous module.
        define([], factory);
    /*eslint-enable */
    } else if (typeof module === 'object' && module.exports) {
        // Node. Does not work with strict CommonJS, but
        // only CommonJS-like environments that support module.exports,
        // like Node.
        module.exports = factory();
    } else {
        // Browser globals (root is window)
        var Duo = factory();
        // If the Javascript was loaded via a script tag, attempt to autoload
        // the frame.
        Duo._onReady(Duo.init);

        // Attach Duo to the `window` object
        root.Duo = Duo;
  }
}(this, function() {
    var DUO_MESSAGE_FORMAT = /^(?:AUTH|ENROLL)+\|[A-Za-z0-9\+\/=]+\|[A-Za-z0-9\+\/=]+$/;
    var DUO_ERROR_FORMAT = /^ERR\|[\w\s\.\(\)]+$/;
    var DUO_OPEN_WINDOW_FORMAT = /^DUO_OPEN_WINDOW\|/;
    var VALID_OPEN_WINDOW_DOMAINS = [
        'duo.com',
        'duosecurity.com',
        'duomobile.s3-us-west-1.amazonaws.com'
    ];

    var iframeId = 'duo_iframe',
        postAction = '',
        postArgument = 'sig_response',
        host,
        sigRequest,
        duoSig,
        appSig,
        iframe,
        submitCallback;

    function throwError(message, url) {
        throw new Error(
            'Duo Web SDK error: ' + message +
            (url ? ('\n' + 'See ' + url + ' for more information') : '')
        );
    }

    function hyphenize(str) {
        return str.replace(/([a-z])([A-Z])/, '$1-$2').toLowerCase();
    }

    // cross-browser data attributes
    function getDataAttribute(element, name) {
        if ('dataset' in element) {
            return element.dataset[name];
        } else {
            return element.getAttribute('data-' + hyphenize(name));
        }
    }

    // cross-browser event binding/unbinding
    function on(context, event, fallbackEvent, callback) {
        if ('addEventListener' in window) {
            context.addEventListener(event, callback, false);
        } else {
            context.attachEvent(fallbackEvent, callback);
        }
    }

    function off(context, event, fallbackEvent, callback) {
        if ('removeEventListener' in window) {
            context.removeEventListener(event, callback, false);
        } else {
            context.detachEvent(fallbackEvent, callback);
        }
    }

    function onReady(callback) {
        on(document, 'DOMContentLoaded', 'onreadystatechange', callback);
    }

    function offReady(callback) {
        off(document, 'DOMContentLoaded', 'onreadystatechange', callback);
    }

    function onMessage(callback) {
        on(window, 'message', 'onmessage', callback);
    }

    function offMessage(callback) {
        off(window, 'message', 'onmessage', callback);
    }

    /**
     * Parse the sig_request parameter, throwing errors if the token contains
     * a server error or if the token is invalid.
     *
     * @param {String} sig Request token
     */
    function parseSigRequest(sig) {
        if (!sig) {
            // nothing to do
            return;
        }

        // see if the token contains an error, throwing it if it does
        if (sig.indexOf('ERR|') === 0) {
            throwError(sig.split('|')[1]);
        }

        // validate the token
        if (sig.indexOf(':') === -1 || sig.split(':').length !== 2) {
            throwError(
                'Duo was given a bad token.  This might indicate a configuration ' +
                'problem with one of Duo\'s client libraries.',
                'https://www.duosecurity.com/docs/duoweb#first-steps'
            );
        }

        var sigParts = sig.split(':');

        // hang on to the token, and the parsed duo and app sigs
        sigRequest = sig;
        duoSig = sigParts[0];
        appSig = sigParts[1];

        return {
            sigRequest: sig,
            duoSig: sigParts[0],
            appSig: sigParts[1]
        };
    }

    /**
     * This function is set up to run when the DOM is ready, if the iframe was
     * not available during `init`.
     */
    function onDOMReady() {
        iframe = document.getElementById(iframeId);

        if (!iframe) {
            throw new Error(
                'This page does not contain an iframe for Duo to use.' +
                'Add an element like <iframe id="duo_iframe"></iframe> ' +
                'to this page.  ' +
                'See https://www.duosecurity.com/docs/duoweb#3.-show-the-iframe ' +
                'for more information.'
            );
        }

        // we've got an iframe, away we go!
        ready();

        // always clean up after yourself
        offReady(onDOMReady);
    }

    /**
     * Validate that a MessageEvent came from the Duo service, and that it
     * is a properly formatted payload.
     *
     * The Google Chrome sign-in page injects some JS into pages that also
     * make use of postMessage, so we need to do additional validation above
     * and beyond the origin.
     *
     * @param {MessageEvent} event Message received via postMessage
     */
    function isDuoMessage(event) {
        return Boolean(
            event.origin === ('https://' + host) &&
            typeof event.data === 'string' &&
            (
                event.data.match(DUO_MESSAGE_FORMAT) ||
                event.data.match(DUO_ERROR_FORMAT) ||
                event.data.match(DUO_OPEN_WINDOW_FORMAT)
            )
        );
    }

    /**
     * Validate the request token and prepare for the iframe to become ready.
     *
     * All options below can be passed into an options hash to `Duo.init`, or
     * specified on the iframe using `data-` attributes.
     *
     * Options specified using the options hash will take precedence over
     * `data-` attributes.
     *
     * Example using options hash:
     * ```javascript
     * Duo.init({
     *     iframe: "some_other_id",
     *     host: "api-main.duo.test",
     *     sig_request: "...",
     *     post_action: "/auth",
     *     post_argument: "resp"
     * });
     * ```
     *
     * Example using `data-` attributes:
     * ```
     * <iframe id="duo_iframe"
     *         data-host="api-main.duo.test"
     *         data-sig-request="..."
     *         data-post-action="/auth"
     *         data-post-argument="resp"
     *         >
     * </iframe>
     * ```
     *
     * @param {Object} options
     * @param {String} options.iframe                         The iframe, or id of an iframe to set up
     * @param {String} options.host                           Hostname
     * @param {String} options.sig_request                    Request token
     * @param {String} [options.post_action='']               URL to POST back to after successful auth
     * @param {String} [options.post_argument='sig_response'] Parameter name to use for response token
     * @param {Function} [options.submit_callback]            If provided, duo will not submit the form instead execute
     *                                                        the callback function with reference to the "duo_form" form object
     *                                                        submit_callback can be used to prevent the webpage from reloading.
     */
    function init(options) {
        if (options) {
            if (options.host) {
                host = options.host;
            }

            if (options.sig_request) {
                parseSigRequest(options.sig_request);
            }

            if (options.post_action) {
                postAction = options.post_action;
            }

            if (options.post_argument) {
                postArgument = options.post_argument;
            }

            if (options.iframe) {
                if (options.iframe.tagName) {
                    iframe = options.iframe;
                } else if (typeof options.iframe === 'string') {
                    iframeId = options.iframe;
                }
            }

            if (typeof options.submit_callback === 'function') {
                submitCallback = options.submit_callback;
            }
        }

        // if we were given an iframe, no need to wait for the rest of the DOM
        if (false && iframe) {
            ready();
        } else {
            // try to find the iframe in the DOM
            iframe = document.getElementById(iframeId);

            // iframe is in the DOM, away we go!
            if (iframe) {
                ready();
            } else {
                // wait until the DOM is ready, then try again
                onReady(onDOMReady);
            }
        }

        // always clean up after yourself!
        offReady(init);
    }

    /**
     * This function is called when a message was received from another domain
     * using the `postMessage` API.  Check that the event came from the Duo
     * service domain, and that the message is a properly formatted payload,
     * then perform the post back to the primary service.
     *
     * @param event Event object (contains origin and data)
     */
    function onReceivedMessage(event) {
        if (isDuoMessage(event)) {
            if (event.data.match(DUO_OPEN_WINDOW_FORMAT)) {
                var url = event.data.substring("DUO_OPEN_WINDOW|".length);
                if (isValidUrlToOpen(url)) {
                    // Open the URL that comes after the DUO_WINDOW_OPEN token.
                    window.open(url, "_self");
                }
            }
            else {
                // the event came from duo, do the post back
                doPostBack(event.data);

                // always clean up after yourself!
                offMessage(onReceivedMessage);
            }
        }
    }

    /**
     * Validate that this passed in URL is one that we will actually allow to
     * be opened.
     * @param url String URL that the message poster wants to open
     * @returns {boolean} true if we allow this url to be opened in the window
     */
    function isValidUrlToOpen(url) {
        if (!url) {
            return false;
        }

        var parser = document.createElement('a');
        parser.href = url;

        if (parser.protocol === "duotrustedendpoints:") {
            return true;
        } else if (parser.protocol !== "https:") {
            return false;
        }

        for (var i = 0; i < VALID_OPEN_WINDOW_DOMAINS.length; i++) {
           if (parser.hostname.endsWith("." + VALID_OPEN_WINDOW_DOMAINS[i]) ||
                   parser.hostname === VALID_OPEN_WINDOW_DOMAINS[i]) {
               return true;
           }
        }
        return false;
    }

    /**
     * Point the iframe at Duo, then wait for it to postMessage back to us.
     */
    function ready() {
        if (!host) {
            host = getDataAttribute(iframe, 'host');

            if (!host) {
                throwError(
                    'No API hostname is given for Duo to use.  Be sure to pass ' +
                    'a `host` parameter to Duo.init, or through the `data-host` ' +
                    'attribute on the iframe element.',
                    'https://www.duosecurity.com/docs/duoweb#3.-show-the-iframe'
                );
            }
        }

        if (!duoSig || !appSig) {
            parseSigRequest(getDataAttribute(iframe, 'sigRequest'));

            if (!duoSig || !appSig) {
                throwError(
                    'No valid signed request is given.  Be sure to give the ' +
                    '`sig_request` parameter to Duo.init, or use the ' +
                    '`data-sig-request` attribute on the iframe element.',
                    'https://www.duosecurity.com/docs/duoweb#3.-show-the-iframe'
                );
            }
        }

        // if postAction/Argument are defaults, see if they are specified
        // as data attributes on the iframe
        if (postAction === '') {
            postAction = getDataAttribute(iframe, 'postAction') || postAction;
        }

        if (postArgument === 'sig_response') {
            postArgument = getDataAttribute(iframe, 'postArgument') || postArgument;
        }

        // point the iframe at Duo
        iframe.src = [
            'https://', host, '/frame/web/v1/auth?tx=', duoSig,
            '&parent=', encodeURIComponent(document.location.href),
            '&v=2.6'
        ].join('');

        // listen for the 'message' event
        onMessage(onReceivedMessage);
    }

    /**
     * We received a postMessage from Duo.  POST back to the primary service
     * with the response token, and any additional user-supplied parameters
     * given in form#duo_form.
     */
    function doPostBack(response) {
        // create a hidden input to contain the response token
        var input = document.createElement('input');
        input.type = 'hidden';
        input.name = postArgument;
        input.value = response + ':' + appSig;

        // user may supply their own form with additional inputs
        var form = document.getElementById('duo_form');

        // if the form doesn't exist, create one
        if (!form) {
            form = document.createElement('form');

            // insert the new form after the iframe
            iframe.parentElement.insertBefore(form, iframe.nextSibling);
        }

        // make sure we are actually posting to the right place
        form.method = 'POST';
        form.action = postAction;

        // add the response token input to the form
        form.appendChild(input);

        // away we go!
        if (typeof submitCallback === "function") {
            submitCallback.call(null, form);
        } else {
            form.submit();
        }
    }

    return {
        init: init,
        _onReady: onReady,
        _parseSigRequest: parseSigRequest,
        _isDuoMessage: isDuoMessage,
        _doPostBack: doPostBack
    };
}));
