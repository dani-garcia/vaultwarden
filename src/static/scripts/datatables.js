/*
 * This combined file was created by the DataTables downloader builder:
 *   https://datatables.net/download
 *
 * To rebuild or modify this file with the latest versions of the included
 * software please visit:
 *   https://datatables.net/download/#bs5/dt-3.0.3
 *
 * Included libraries:
 *   DataTables 3.0.3
 */

/*! DataTables 3.0.3
 * Copyright (c) SpryMedia Ltd - datatables.net/license
 */

(function(factory){
	if (typeof define === 'function' && define.amd) {
		// AMD
		define([], function () {
			return factory(window, document);
		});
	}
	else if (typeof exports === 'object') {
		// CommonJS
		var cjsRequires = function (root) {		};

		if (typeof window === 'undefined') {
			module.exports = function (root) {
				if (! root) {
					// CommonJS environments without a window global must pass a
					// root. This will give an error otherwise
					root = window;
				}

				cjsRequires(root);
				return factory(root, root.document);
			};
		}
		else {
			cjsRequires(window);
			module.exports = factory(window, window.document);
		}
	}
	else {
		// Browser
		window.DataTable = factory(window, document);
	}
}(function(window, document) {
'use strict';



// A collection of the regular expressions used throughout the code base. Not all are here
// just the ones that need to be reused - no need to dump single use expressions here.
// https://en.wikipedia.org/wiki/Foreign_exchange_market
// - \u20BD - Russian ruble.
// - \u20a9 - South Korean Won
// - \u20BA - Turkish Lira
// - \u20B9 - Indian Rupee
// - R - Brazil (R$) and South Africa
// - fr - Swiss Franc
// - kr - Swedish krona, Norwegian krone and Danish krone
// - \u2009 is thin space and \u202F is narrow no-break space, both used in many
// - Ƀ - Bitcoin
// - Ξ - Ethereum
//   standards as thousands separators.
const reFormattedNumeric = /['\u00A0,$£€¥%\u2009\u202F\u20BD\u20a9\u20BArfkɃΞ]/gi;
const reHtml = /<([^>]*>)/g;
// Escape regular expression special characters
const reRegexCharacters = new RegExp('(\\' +
    [
        '/',
        '.',
        '*',
        '+',
        '?',
        '|',
        '(',
        ')',
        '[',
        ']',
        '{',
        '}',
        '\\',
        '$',
        '^',
        '-',
    ].join('|\\') +
    ')', 'g');
// This is not strict ISO8601 - Date.parse() is quite lax, although
// implementations differ between browsers.
const reDate = /^\d{2,4}[./-]\d{1,2}[./-]\d{1,2}([T ]{1}\d{1,2}[:.]\d{2}([.:]\d{2})?)?$/;
const reNewLines = /[\r\n\u2028]/g;
const isoTimezone = /[T\s]\d{2}.*?(Z|[+-]\d{2}(?::?\d{2})?)$/;

var regex = /*#__PURE__*/Object.freeze({
    __proto__: null,
    isoTimezone: isoTimezone,
    reDate: reDate,
    reFormattedNumeric: reFormattedNumeric,
    reHtml: reHtml,
    reNewLines: reNewLines,
    reRegexCharacters: reRegexCharacters
});

const maxStrLen = Math.pow(2, 28);
/**
 * DataTables default string normalisation. Remove diacritics from a string by
 * decomposing it and then removing non-ascii characters.
 *
 * This function is replaceable if the user wishes to use a different library
 * for normalising a string.
 *
 * @param val Value to normalise (if a string)
 * @param both Include both the normalised and original in the return
 * @returns Normalised string, or original value if not a string
 */
let _normalize = function (val, both) {
    if (typeof val !== 'string') {
        return val;
    }
    // It is faster to just run `normalize` than it is to check if
    // we need to with a regex! (Check as it isn't available in old
    // Safari)
    var res = val.normalize ? val.normalize('NFD') : val;
    // Equally, here we check if a regex is needed or not
    return res.length !== val.length
        ? (both === true ? val + ' ' : '') + res.replace(/[\u0300-\u036f]/g, '')
        : res;
};
/**
 * DataTables default string HTML stripping from a string
 *
 * This function is replaceable if the user wishes to use a different library
 * for stripping HTML from a string.
 *
 * @param input Value to strip HTML from
 * @param replacement Value to replace the tags with
 * @returns Stripped value
 */
let _stripHtml = function (input, replacement = '') {
    if (!input || typeof input !== 'string') {
        return input;
    }
    // Irrelevant check to workaround CodeQL's false positive on the regex
    if (input.length > maxStrLen) {
        throw new Error('Exceeded max str len');
    }
    let previous;
    let next = input.replace(reHtml, replacement); // Complete tags
    // Safety for incomplete script tag - use do / while to ensure that
    // we get all instances
    do {
        previous = next;
        next = next.replace(/<script/i, '');
    } while (next !== previous);
    // T must be a string, but TS can't seem to figure that out
    return previous;
};
/**
 * DataTables default HTML entity escaping.
 *
 * This function is replaceable if the user wishes to use a different library
 * for escaping HTML entities in a string.
 *
 * @param val Value to escape HTML in
 * @returns Escaped value
 */
let _escapeHtml = function (val) {
    let d = Array.isArray(val) ? val.join(',') : val;
    return typeof d === 'string'
        ? d
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
        : d;
};
/**
 * Escape regular expression characters in a string
 *
 * @param val String to escape
 * @returns String with regex characters escaped
 */
function escapeRegex(val) {
    return val.replace(reRegexCharacters, '\\$1');
}
function escapeHtml(mixed) {
    var type = typeof mixed;
    if (type === 'function') {
        _escapeHtml = mixed;
        return;
    }
    else if (type === 'string' || Array.isArray(mixed)) {
        return _escapeHtml(mixed);
    }
    return mixed;
}
function normalize(mixed, both) {
    var type = typeof mixed;
    if (type !== 'function') {
        return _normalize(mixed, both);
    }
    _normalize = mixed;
}
function stripHtml(mixed, replacement) {
    const type = typeof mixed;
    if (type === 'function') {
        _stripHtml = mixed;
        return;
    }
    else if (type === 'string') {
        return _stripHtml(mixed, replacement);
    }
    return mixed;
}

var string = /*#__PURE__*/Object.freeze({
    __proto__: null,
    escapeHtml: escapeHtml,
    escapeRegex: escapeRegex,
    normalize: normalize,
    stripHtml: stripHtml
});

const _re_dic = {};
/**
 * Get integer value
 *
 * @param s Value
 * @returns Int, or null if not a number
 */
function intVal(s) {
    var integer = parseInt(s, 10);
    return !isNaN(integer) && isFinite(s) ? integer : null;
}
// Convert from a formatted number with characters other than `.` as the
// decimal place, to a JavaScript number
function numToDecimal(num, decimalPoint) {
    // Cache created regular expressions for speed as this function is called often
    if (!_re_dic[decimalPoint]) {
        _re_dic[decimalPoint] = new RegExp(escapeRegex(decimalPoint), 'g');
    }
    return typeof num === 'string' && decimalPoint !== '.'
        ? num.replace(/\./g, '').replace(_re_dic[decimalPoint], '.')
        : num;
}

var conv = /*#__PURE__*/Object.freeze({
    __proto__: null,
    intVal: intVal,
    numToDecimal: numToDecimal
});

function arrayLike(test) {
    return (test && // Exists
        typeof test !== 'string' && // Is not a string
        test.length !== undefined && // Has a length
        test.nodeType === undefined // Is not a text node
    );
}
/**
 * Determine if the input is a Dom instance
 *
 * @param input Value to check
 * @returns true if it is a Dom instance, false otherwise
 */
function dom(input) {
    return input && typeof input === 'object' && input._isDom;
}
/**
 * Determine if the input is an HTML element
 *
 * @param input Value to check
 * @returns true if an HTML element was passed in
 */
function element(input) {
    return typeof input === 'object' && input.nodeName;
}
/**
 * Check if a value is empty or not. Note that a string with `-` is considered
 * empty
 *
 * @param d Value to check
 * @returns `true` if empty, `false` otherwise
 */
function empty(d) {
    return !d || d === true || d === '-' ? true : false;
}
/**
 * Check if a string is HTML. Note that a string without HTML in it can be
 * considered to be HTML still!
 *
 * @todo Can we drop this?
 * @param d
 * @returns
 */
function html(d) {
    return empty(d) || typeof d === 'string';
}
/**
 * Is a string a number surrounded by HTML?
 *
 * @param d Value to check
 * @param decimalPoint Decimal place character
 * @param formatted Consider formatted numbers
 * @param allowEmpty Allow empty to be considered as a number
 * @returns True if a number, null otherwise
 */
function htmlNum(d, decimalPoint, formatted, allowEmpty) {
    if (allowEmpty && empty(d)) {
        return true;
    }
    // input and select strings mean that this isn't just a number
    if (typeof d === 'string' && d.match(/<(input|select)/i)) {
        return null;
    }
    return !html(d)
        ? null
        : num$1(stripHtml(d), decimalPoint, formatted, allowEmpty)
            ? true
            : null;
}
/**
 * Determine if an input is a jQuery instance
 *
 * @param input Value to check
 * @returns true if it is a jQuery instance, false otherwise
 */
function jquery(input) {
    return input && typeof input.jquery === 'string';
}
/**
 * Check if a given value is numeric, taking into account if it might be
 * formatted or uses a decimal point that is not a period.
 *
 * @param d Value to check
 * @param decimalPoint DP character
 * @param formatted Allow the number to be formatted or not
 * @param allowEmpty Allow an empty value to be considered a number
 * @returns `true` if numeric
 */
function num$1(d, decimalPoint, formatted, allowEmpty) {
    let type = typeof d;
    if (type === 'number' || type === 'bigint') {
        return true;
    }
    // If empty return immediately so there must be a number if it is a
    // formatted string (this stops the string "k", or "kr", etc being detected
    // as a formatted number for currency
    if (allowEmpty && empty(d)) {
        return true;
    }
    if (decimalPoint && type === 'string') {
        d = numToDecimal(d, decimalPoint);
    }
    if (formatted && type === 'string') {
        d = d.replace(reFormattedNumeric, '');
    }
    return !isNaN(parseFloat(d)) && isFinite(d);
}
/**
 * Determine if a value is a plain object or not
 *
 * @param value Value to check
 * @returns true if is a plain object, otherwise false
 */
function plainObject(value) {
    if (typeof value !== 'object' || value === null) {
        return false;
    }
    let proto = Object.getPrototypeOf(value);
    return proto === null || proto === Object.prototype;
}

var is = /*#__PURE__*/Object.freeze({
    __proto__: null,
    arrayLike: arrayLike,
    dom: dom,
    element: element,
    empty: empty,
    html: html,
    htmlNum: htmlNum,
    jquery: jquery,
    num: num$1,
    plainObject: plainObject
});

/**
 * Object iteration function, executing a callback for each key in the object
 *
 * @param input Input object
 * @param fn Function to execute
 */
function each(input, fn) {
    if (!input) {
        return;
    }
    let keys = Object.keys(input);
    for (let i = 0; i < keys.length; i++) {
        let key = keys[i];
        fn(key, input[key], i);
    }
}
/**
 * Merge the contents of two or more objects into the first object.
 *
 * @param out Object to be assigned the properties
 * @param inputs Objects to take the values from
 * @returns The `output`, just for convenience - output === the return.
 */
function assign(out, ...inputs) {
    let output = Object(out);
    // Can't just use `Object.assign` as it will assign `undefined` as a regular
    // value to the target.
    for (let i = 0; i < inputs.length; i++) {
        let options = inputs[i];
        // Filter inputs
        if (options != null) {
            // Extend the base object
            for (let name in options) {
                let copy = options[name];
                // Prevent Object.prototype pollution
                // Prevent never-ending loop
                if (name === '__proto__' || output === copy) {
                    continue;
                }
                // Ignore undefined values (this is why we can't use Object.assign)
                if (copy !== undefined) {
                    output[name] = copy;
                }
            }
        }
    }
    return output;
}
/**
 * Deep merge the contents of two or more objects into the first object. This
 * breaks references for both objects and array.
 *
 * @param out Object to be assigned the properties
 * @param inputs Objects to take the values from
 * @returns The `output`, just for convenience - output === the return.
 */
function assignDeep(out, ...inputs) {
    if (!out) {
        return {};
    }
    for (let i = 0; i < inputs.length; i++) {
        let input = inputs[i];
        if (!input) {
            continue;
        }
        for (const [key, value] of Object.entries(input)) {
            if (Array.isArray(value)) {
                if (!Array.isArray(out[key])) {
                    out[key] = [];
                }
                assignDeep(out[key], value);
            }
            else if (plainObject(value)) {
                if (!plainObject(out[key])) {
                    out[key] = {};
                }
                assignDeep(out[key], value);
            }
            else if (input[key] !== undefined) {
                out[key] = input[key];
            }
        }
    }
    return out;
}
/**
 * Deep merge objects, but shallow copy arrays. The reason we need to do this,
 * is that we don't want to deep copy array init values (such as aaSorting)
 * since the dev wouldn't be able to override them, but we do want to deep copy
 * arrays.
 *
 * @param out Object to extend
 * @param extender Object from which the properties will be applied to out
 * @param breakRefs If true, then arrays will be sliced to take an independent
 *   copy with the exception of the `data` or `aaData` parameters if they are
 *   present. This is so you can pass in a collection to DataTables and have
 *   that used as your data source without breaking the references
 * @returns out Reference, just for convenience - out === the return.
 * @todo This doesn't take account of arrays inside the deep copied objects.
 */
function assignDeepObjects(out, extender, breakRefs = false) {
    let val;
    for (let prop in extender) {
        if (Object.prototype.hasOwnProperty.call(extender, prop)) {
            val = extender[prop];
            if (plainObject(val)) {
                if (!plainObject(out[prop])) {
                    out[prop] = {};
                }
                assignDeep(out[prop], val);
            }
            else if (breakRefs &&
                prop !== 'data' &&
                prop !== 'aaData' &&
                Array.isArray(val)) {
                out[prop] = val.slice();
            }
            else {
                out[prop] = val;
            }
        }
    }
    return out;
}
/**
 * Map entries to an array
 *
 * @param obj In object
 * @param fn Map transform function. Same signature as `each`
 * @returns Result
 */
function map$1(obj, fn) {
    let out = [];
    each(obj, (key, val) => {
        out.push(fn(key, val));
    });
    return out;
}

var object = /*#__PURE__*/Object.freeze({
    __proto__: null,
    assign: assign,
    assignDeep: assignDeep,
    assignDeepObjects: assignDeepObjects,
    each: each,
    map: map$1
});

const defaults$5 = {
    cache: true,
    contentType: 'application/x-www-form-urlencoded; charset=UTF-8',
    headers: {},
    traditional: false,
    url: location.href
};
/**
 * Trigger an Ajax call to the server based on the configuration parameters
 * passed in.
 *
 * @param optionsIn Ajax options
 * @returns The XHR request
 */
function ajax(optionsIn) {
    let xhr = new XMLHttpRequest();
    let options = assign({}, defaults$5, optionsIn);
    let urlParams = queryParams(options);
    let method = httpMethod(options);
    let sendData = null;
    // Allow the data to be sent to the server as a simple JSON string -
    // primarily to be used with POST / PUT
    if (options.submitAs === 'json' && options.data) {
        options.data = JSON.stringify(options.data);
        if (!options.contentType) {
            options.contentType = 'application/json; charset=utf-8';
        }
    }
    xhr.open(method, options.url +
        (urlParams
            ? (options.url.includes('?') ? '&' : '?') + urlParams
            : ''), true, options.username || null, options.password || null);
    // Content type for FormData requests gets set by the browser.
    if (options.contentType && !(options.data instanceof FormData)) {
        xhr.setRequestHeader('Content-Type', options.contentType);
    }
    // Add a X-Request-With header, as jQuery does so and some server-side
    // platforms look for it. Only for same domain though.
    if (options.headers &&
        !options.headers['X-Requested-With'] &&
        !isCrossDomain(options.url)) {
        options.headers['X-Requested-With'] = 'XMLHttpRequest';
    }
    // Add an accept header specifically for JSON data types, again to match
    // how jQuery operates for this.
    if (options.dataType === 'json' &&
        options.headers &&
        !options.headers['accepts']) {
        options.headers['Accept'] =
            'application/json, text/javascript, */*; q=0.01';
    }
    each(options.headers, (key, val) => {
        xhr.setRequestHeader(key, val);
    });
    if (options.data instanceof FormData) {
        sendData = options.data;
    }
    else if (method !== 'GET' && options.data) {
        if (typeof options.data === 'string') {
            sendData = options.data;
        }
        else {
            sendData = serialize(options.data, options.traditional);
            sendData = convertSpaces(sendData, options);
            // So beforeSend matches how jQuery behaves
            options.data = sendData;
        }
    }
    xhr.onreadystatechange = function () {
        if (xhr.readyState != 4) {
            return;
        }
        let responseData = xhr.responseText;
        let statusText = 'success';
        if (xhr.status === 0) {
            return; // aborted
        }
        else if (xhr.status === 204 || method === 'HEAD') {
            statusText = 'nocontent';
        }
        else if (xhr.status === 304) {
            statusText = 'notmodified';
        }
        else if (xhr.status >= 400) {
            statusText = 'error';
        }
        // Return data type handling
        if (options.dataType === 'json') {
            try {
                responseData = JSON.parse(responseData);
            }
            catch (e) {
                statusText = 'parsererror';
            }
        }
        else if (!options.dataType) {
            // Data type is undefined, so attempt to parse as JSON if possible,
            // but no error if it can't be
            try {
                responseData = JSON.parse(responseData);
            }
            catch (e) {
                // noop
            }
        }
        if (statusText === 'success') {
            callback(options.success, responseData, statusText, xhr);
        }
        else {
            callback(options.error, xhr, statusText, xhr.statusText);
        }
        callback(options.complete, xhr, statusText);
    };
    if (options.beforeSend) {
        if (options.beforeSend.call(options, xhr, options) === false) {
            xhr.abort();
            return xhr;
        }
    }
    xhr.send(sendData);
    return xhr;
}
// Expose defaults and serialisation method
ajax.defaults = defaults$5;
ajax.serialize = serialize;
/**
 * Run callback functions (allowing for none, one or array)
 *
 * @param fnIn Function(s) to run
 * @param arg1 Parameters to pass to the function(s)
 * @param arg2 Parameters to pass to the function(s)
 * @param arg3 Parameters to pass to the function(s)
 */
function callback(fnIn, arg1, arg2, arg3) {
    if (!fnIn) {
        return;
    }
    let fnArr = Array.isArray(fnIn) ? fnIn : [fnIn];
    for (let i = 0; i < fnArr.length; i++) {
        fnArr[i](arg1, arg2, arg3);
    }
}
/**
 * For form submission with x-www-form-urlencoded, spaces should be submitted as
 * `+`. See the jQuery discussion on the topic here:
 * https://github.com/jquery/jquery/issues/2658#issuecomment-149024872
 *
 * @param sendData Serialised form of the data to submit
 * @param options Ajax options
 * @returns Query string
 */
function convertSpaces(sendData, options) {
    return (options.contentType || '').indexOf('application/x-www-form-urlencoded') === 0
        ? sendData.replace(/%20/g, '+')
        : sendData;
}
/**
 * Determine if a url is a cross domain request or not
 *
 * @param url URL to check
 * @returns True if cross domain, false otherwise
 */
function isCrossDomain(url) {
    // Use the current page as the base to handle relative URLs correctly
    const target = new URL(url, window.location.origin);
    return target.origin !== window.location.origin;
}
/**
 * Get the HTTP method from the Ajax request options
 *
 * @param options Ajax options
 * @returns HTTP verb
 */
function httpMethod(options) {
    let method = 'GET';
    if (options.type) {
        method = options.type;
    }
    if (options.method) {
        method = options.method;
    }
    return method.toUpperCase();
}
/**
 * Get the query parameters based on the options (method, cache and data all
 * need to be considered).
 *
 * @param options Ajax options
 * @returns URL string
 */
function queryParams(options) {
    let requestParams = [];
    if (httpMethod(options) === 'GET') {
        // Construct URL parameters string
        requestParams.push(serialize(options.data, options.traditional));
    }
    // If a DELETE method is used there are a number of servers which will
    // reject the request if it has a body. So we need to append to the URL.
    //
    // http://stackoverflow.com/questions/15088955
    // http://bugs.jquery.com/ticket/11586
    if (httpMethod(options) === 'DELETE' &&
        (options.deleteBody === undefined || options.deleteBody === true)) {
        requestParams.push(serialize(options.data, options.traditional));
        delete options.data;
    }
    if (options.cache === false) {
        requestParams.push(serialize({ _: +new Date() }));
    }
    return convertSpaces(requestParams.filter(d => !!d).join('&'), options);
}
/**
 * Convert an object into a list of parameters for a query request. Supports
 * jQuery traditional option for legacy applications.
 *
 * @param obj Object to convert
 * @param traditional If jQuery old style should be used
 * @returns Parameter-ized string
 */
function serialize(obj, traditional = false) {
    var params = [];
    if (obj === undefined || obj === null) {
        return '';
    }
    serializeNested(params, obj, traditional);
    return params.join('&');
}
/**
 * Recursive serialisation function
 *
 * @param params Array to write the serialised parameters to
 * @param obj Object / array to serialise
 * @param traditional Traditional flag for legacy
 * @param scope Recursive scope
 */
function serializeNested(params, obj, traditional, scope = '') {
    let array = Array.isArray(obj);
    for (let key in obj) {
        let value = obj[key];
        let nestDown = Array.isArray(value) || (!traditional && plainObject(value));
        if (scope) {
            // Non-scalar values need the index set on the host
            let index = !array || nestDown ? key : '';
            key = traditional ? scope : scope + '[' + index + ']';
        }
        if (!scope && array) {
            serializeAdd(params, value.name, value.value);
        }
        else if (nestDown) {
            // Nest down
            serializeNested(params, value, traditional, key);
        }
        else {
            serializeAdd(params, key, value);
        }
    }
}
/**
 * Add a name / value pair to the list of parameters
 *
 * @param params Parameter values
 * @param name Parameter name
 * @param value Parameter value
 */
function serializeAdd(params, name, value) {
    // Allow the input to be a function to match how jQuery operates
    let strVal = typeof value === 'function' ? value() : value;
    params.push(encodeURIComponent(name) +
        '=' +
        encodeURIComponent(strVal === null ? '' : strVal));
}

/**
 * Determine if all values in the array are unique. This means we can short
 * cut the _unique method at the cost of a single loop. A sorted array is used
 * to easily check the values.
 *
 * @param  src Source array
 * @return true if all unique, false otherwise
 */
function allUnique(src) {
    if (src.length < 2) {
        return true;
    }
    var sorted = src.slice().sort();
    var last = sorted[0];
    for (var i = 1, iLen = sorted.length; i < iLen; i++) {
        if (sorted[i] === last) {
            return false;
        }
        last = sorted[i];
    }
    return true;
}
/**
 * Flatten an array
 *
 * Surprisingly this is faster than [].concat.apply
 * https://jsperf.com/flatten-an-array-loop-vs-reduce/2
 *
 * @param out Array to write to
 * @param val Source array, or single value
 * @returns Flattened array
 */
function flatten(out, val) {
    if (Array.isArray(val) || arrayLike(val)) {
        for (var i = 0; i < val.length; i++) {
            flatten(out, val[i]);
        }
    }
    else {
        out.push(val);
    }
    return out;
}
function intersection(a1, a2) {
    return a1.filter(item => a2.includes(item));
}
/**
 * Pluck items from an array of objects, or from a nested array of objects
 *
 * @param a Array to get values from
 * @param prop Property to read values from
 * @param prop2 Inner property to get values from if a 2D array
 * @returns Array of read values
 */
function pluck(a, prop, prop2) {
    let out = [], i = 0, iLen = a.length;
    // Could have the test in the loop for slightly smaller code, but speed
    // is essential here
    if (prop2 !== undefined) {
        for (; i < iLen; i++) {
            if (a[i] && a[i][prop]) {
                out.push(a[i][prop][prop2]);
            }
        }
    }
    else {
        for (; i < iLen; i++) {
            if (a[i]) {
                out.push(a[i][prop]);
            }
        }
    }
    return out;
}
/**
 * Basically the same as _pluck, but rather than looping over the source array we use `order`
 * as the indexes to pick from the source array
 *
 * @param a Array to get values from
 * @param order Indexes to pick
 * @param prop Property to read values from
 * @param prop2 Inner property to get values from if a 2D array
 * @returns Array of read values
 */
function pluckOrder(a, order, prop, prop2) {
    let out = [], i = 0, iLen = order.length;
    // Could have the test in the loop for slightly smaller code, but speed
    // is essential here
    if (prop2 !== undefined) {
        for (; i < iLen; i++) {
            if (a[order[i]] && a[order[i]][prop]) {
                out.push(a[order[i]][prop][prop2]);
            }
        }
    }
    else {
        for (; i < iLen; i++) {
            if (a[order[i]]) {
                out.push(a[order[i]][prop]);
            }
        }
    }
    return out;
}
function range(len, start) {
    var out = [];
    var end;
    if (start === undefined) {
        start = 0;
        end = len;
    }
    else {
        end = start;
        start = len;
    }
    for (var i = start; i < end; i++) {
        out.push(i);
    }
    return out;
}
/**
 * Remove all falsy values from an array
 *
 * @param a Source array
 * @returns A new array, with empty values removed
 */
function removeEmpty(a) {
    var out = [];
    for (var i = 0, iLen = a.length; i < iLen; i++) {
        if (a[i]) {
            // careful - will remove all falsy values!
            out.push(a[i]);
        }
    }
    return out;
}
/**
 * Join data from an array, but only for specific columns.
 *
 * Performance testing for this available here:
 * https://jsperf.app/vejijo/2/preview.
 *
 * @param src Data source array to pick from
 * @param use Indexes we want from the array
 * @returns Joined string
 */
function selectiveJoin(src, use) {
    if (typeof use === 'number') {
        return '' + src[use];
    }
    if (use.length === 0) {
        return '';
    }
    let result = '' + src[use[0]];
    for (let i = 1; i < use.length; i++) {
        result += '  ' + src[use[i]];
    }
    return result;
}
/**
 * Find the unique elements in a source array.
 *
 * @param src Source array
 * @return Array of unique items
 */
function unique(src) {
    if (Array.from && Set) {
        return Array.from(new Set(src));
    }
    if (allUnique(src)) {
        return src.slice();
    }
    // A faster unique method is to use object keys to identify used values,
    // but this doesn't work with arrays or objects, which we must also
    // consider. See jsperf.app/compare-array-unique-versions/4 for more
    // information.
    var out = [], val, i, iLen = src.length, j, k = 0;
    again: for (i = 0; i < iLen; i++) {
        val = src[i];
        for (j = 0; j < k; j++) {
            if (out[j] === val) {
                continue again;
            }
        }
        out.push(val);
        k++;
    }
    return out;
}

var array = /*#__PURE__*/Object.freeze({
    __proto__: null,
    flatten: flatten,
    intersection: intersection,
    pluck: pluck,
    pluckOrder: pluckOrder,
    range: range,
    removeEmpty: removeEmpty,
    selectiveJoin: selectiveJoin,
    unique: unique
});

// Private variable that is used to match action syntax in the data property object
const __reArray = /\[.*?\]$/;
const __reFn = /\(\)$/;
/**
 * Split string on periods, taking into account escaped periods
 *
 * @param str String to split
 * @return Split string
 */
function splitObjNotation(str) {
    const parts = str.match(/(\\.|[^.])+/g) || [''];
    return parts.map(function (s) {
        return s.replace(/\\\./g, '.');
    });
}
/**
 * Create a function that will read data a common data point from different (but same structure)
 * data objects. This is primarily used to get data for a specific cell in a single column, but it
 * can also be used in other places, such as when using JSON notation.
 *
 * @param dataPoint The data point to get
 * @returns Function to get a data point's value from a source.
 */
function get$1(dataPoint) {
    if (dataPoint === null) {
        // Give an empty string for rendering / sorting etc
        return function (data) {
            // type, row and meta also passed, but not used
            return data;
        };
    }
    else if (typeof dataPoint === 'function') {
        return function (data, type, row, meta) {
            return dataPoint(data, type, row, meta);
        };
    }
    else if (typeof dataPoint === 'string' &&
        (dataPoint.indexOf('.') !== -1 ||
            dataPoint.indexOf('[') !== -1 ||
            dataPoint.indexOf('(') !== -1)) {
        /* If there is a . in the source string then the data source is in a
         * nested object so we loop over the data for each level to get the next
         * level down. On each loop we test for undefined, and if found immediately
         * return. This allows entire objects to be missing and sDefaultContent to
         * be used if defined, rather than throwing an error
         */
        let fetchData = function (data, type, src) {
            let arrayNotation, funcNotation, out, innerSrc;
            if (src !== '') {
                let a = splitObjNotation(src);
                for (let i = 0, iLen = a.length; i < iLen; i++) {
                    // Check if we are dealing with special notation
                    arrayNotation = a[i].match(__reArray);
                    funcNotation = a[i].match(__reFn);
                    if (arrayNotation) {
                        // Array notation
                        a[i] = a[i].replace(__reArray, '');
                        // Condition allows simply [] to be passed in
                        if (a[i] !== '') {
                            data = data[a[i]];
                        }
                        out = [];
                        // Get the remainder of the nested object to get
                        a.splice(0, i + 1);
                        innerSrc = a.join('.');
                        // Traverse each entry in the array getting the properties requested
                        if (Array.isArray(data)) {
                            for (let j = 0, jLen = data.length; j < jLen; j++) {
                                out.push(fetchData(data[j], type, innerSrc));
                            }
                        }
                        // If a string is given in between the array notation indicators, that
                        // is used to join the strings together, otherwise an array is returned
                        let join = arrayNotation[0].substring(1, arrayNotation[0].length - 1);
                        data = join === '' ? out : out.join(join);
                        // The inner call to fetchData has already traversed through the remainder
                        // of the source requested, so we exit from the loop
                        break;
                    }
                    else if (funcNotation) {
                        // Function call
                        a[i] = a[i].replace(__reFn, '');
                        data = data[a[i]]();
                        continue;
                    }
                    if (data === null || data[a[i]] === null) {
                        return null;
                    }
                    else if (data === undefined || data[a[i]] === undefined) {
                        return undefined;
                    }
                    data = data[a[i]];
                }
            }
            return data;
        };
        return function (data, type) {
            // row and meta also passed, but not used
            return fetchData(data, type, dataPoint);
        };
    }
    else if (plainObject(dataPoint)) {
        // Build an object of get functions, and wrap them in a single call
        let o = {};
        each(dataPoint, function (key, val) {
            if (val) {
                o[key] = get$1(val);
            }
        });
        return function (data, type, row, meta) {
            let t = o[type] || o._;
            return t !== undefined ? t(data, type, row, meta) : data;
        };
    }
    else {
        // Array or flat object mapping
        return function (data) {
            // row and meta also passed, but not used
            return data[dataPoint];
        };
    }
}
/**
 * Write a value into an existing data store
 *
 * @param dataPoint The data point to write to
 */
function set$1(dataPoint) {
    if (dataPoint === null) {
        // Nothing to do when the data source is null
        return function () { };
    }
    else if (typeof dataPoint === 'function') {
        return function (data, val, meta) {
            dataPoint(data, 'set', val, meta);
        };
    }
    else if (typeof dataPoint === 'string' &&
        (dataPoint.indexOf('.') !== -1 ||
            dataPoint.indexOf('[') !== -1 ||
            dataPoint.indexOf('(') !== -1)) {
        // Like the get, we need to get data from a nested object
        let setData = function (data, val, src) {
            let a = splitObjNotation(src), b;
            let aLast = a[a.length - 1];
            let arrayNotation, funcNotation, o, innerSrc;
            for (let i = 0, iLen = a.length - 1; i < iLen; i++) {
                // Protect against prototype pollution
                if (a[i] === '__proto__' || a[i] === 'constructor') {
                    throw new Error('Cannot set prototype values');
                }
                // Check if we are dealing with an array notation request
                arrayNotation = a[i].match(__reArray);
                funcNotation = a[i].match(__reFn);
                if (arrayNotation) {
                    a[i] = a[i].replace(__reArray, '');
                    data[a[i]] = [];
                    // Get the remainder of the nested object to set so we can recurse
                    b = a.slice();
                    b.splice(0, i + 1);
                    innerSrc = b.join('.');
                    // Traverse each entry in the array setting the properties requested
                    if (Array.isArray(val)) {
                        for (let j = 0, jLen = val.length; j < jLen; j++) {
                            o = {};
                            setData(o, val[j], innerSrc);
                            data[a[i]].push(o);
                        }
                    }
                    else {
                        // We've been asked to save data to an array, but it
                        // isn't array data to be saved. Best that can be done
                        // is to just save the value.
                        data[a[i]] = val;
                    }
                    // The inner call to setData has already traversed through the remainder
                    // of the source and has set the data, thus we can exit here
                    return;
                }
                else if (funcNotation) {
                    // Function call
                    a[i] = a[i].replace(__reFn, '');
                    data = data[a[i]](val);
                }
                // If the nested object doesn't currently exist - since we are
                // trying to set the value - create it
                if (data[a[i]] === null || data[a[i]] === undefined) {
                    data[a[i]] = {};
                }
                data = data[a[i]];
            }
            // Last item in the input - i.e, the actual set
            if (aLast.match(__reFn)) {
                // Function call
                data = data[aLast.replace(__reFn, '')](val);
            }
            else {
                // If array notation is used, we just want to strip it and use the property name
                // and assign the value. If it isn't used, then we get the result we want anyway
                data[aLast.replace(__reArray, '')] = val;
            }
        };
        return function (data, val) {
            // meta is also passed in, but not used
            return setData(data, val, dataPoint);
        };
    }
    else if (plainObject(dataPoint)) {
        /* Unlike get, only the underscore (global) option is used for for
         * setting data since we don't know the type here. This is why an object
         * option is not documented for `mData` (which is read/write), but it is
         * for `render` which is read only.
         */
        return set$1(dataPoint._);
    }
    else {
        // Array or flat object mapping
        return function (data, val) {
            // meta is also passed in, but not used
            data[dataPoint] = val;
        };
    }
}

var data = /*#__PURE__*/Object.freeze({
    __proto__: null,
    get: get$1,
    set: set$1
});

// Can be assigned in DateTable.use()
var __bootstrap;
var __foundation;
var __luxon$1;
var __moment$1;
var __dateTime;
var __dataTable;
var __jquery;
/**
 * Set the libraries that DataTables uses, or the global objects.
 * Note that the arguments can be either way around (legacy support)
 * and the second is optional. See docs.
 */
function external (arg1, arg2) {
    // Reverse arguments for legacy support
    var module = typeof arg1 === 'string' ? arg2 : arg1;
    var type = typeof arg2 === 'string' ? arg2 : arg1;
    // Getter
    if (module === undefined && typeof type === 'string') {
        switch (type) {
            case 'lib':
            case 'jq':
                return __jquery !== undefined ? __jquery : window.jQuery || null;
            case 'win':
                return window;
            case 'datatable':
                return __dataTable;
            case 'datetime':
                return __dateTime;
            case 'luxon':
                return __luxon$1 || window.luxon || null;
            case 'moment':
                return __moment$1 || window.moment || null;
            case 'bootstrap':
                // Use local if set, otherwise try window, which could be undefined
                return __bootstrap || window.bootstrap || null;
            case 'foundation':
                // Ditto
                return __foundation || window.Foundation || null;
            default:
                return null;
        }
    }
    // Setter
    if (type === 'lib' ||
        type === 'jq' ||
        (module && module.fn && module.fn.jquery)) {
        __jquery = module;
        jQuerySetup();
    }
    else if (type === 'datatable' || (module && module.isDataTable)) {
        __dataTable = module;
    }
    else if (type === 'win' || (module && module.document)) {
        window = module;
        document = module.document;
    }
    else if (type === 'datetime' || (module && module.type === 'DateTime')) {
        __dateTime = module;
    }
    else if (type === 'luxon' || (module && module.FixedOffsetZone)) {
        __luxon$1 = module;
    }
    else if (type === 'moment' || (module && module.isMoment)) {
        __moment$1 = module;
    }
    else if (type === 'bootstrap' ||
        (module && module.Modal && module.Modal.NAME === 'modal')) {
        // This is currently for BS5 only. BS3/4 attach to jQuery, so no need to use `.use()`
        __bootstrap = module;
    }
    else if (type === 'foundation' || (module && module.Reveal)) {
        __foundation = module;
    }
}
/**
 * Attach jQuery to DataTables
 */
function jQuerySetup() {
    if (!__dataTable || !__jquery) {
        return;
    }
    // Provide access to the host jQuery object (circular reference)
    __dataTable.$ = __jquery;
    // jQuery integration - expose the core function.
    __jquery.fn.dataTable = __dataTable;
    // jQuery wrapper - returning a DataTable instance
    __jquery.fn.DataTable = function (options) {
        let table = new __dataTable(this.toArray(), options);
        return table;
    };
    // Legacy aliases
    __jquery.fn.dataTableSettings = __dataTable.ext.settings;
    __jquery.fn.dataTableExt = __dataTable.ext;
    // All properties that are available to $.fn.dataTable should also be available
    // on $.fn.DataTable
    each(__dataTable, function (prop, val) {
        __jquery.fn.DataTable[prop] = val;
    });
}

function debounce(fn, timeout = 250) {
    let timer;
    return function (...args) {
        clearTimeout(timer);
        timer = setTimeout(() => {
            fn.call(this, ...args);
        }, timeout);
    };
}
function throttle(fn, freq = 200) {
    let last, timer;
    return function (...args) {
        const now = +new Date();
        if (last && now < last + freq) {
            clearTimeout(timer);
            timer = setTimeout(() => {
                last = undefined;
                fn.call(this, ...args);
            }, freq);
        }
        else {
            last = now;
            fn.call(this, ...args);
        }
    };
}

var timer = /*#__PURE__*/Object.freeze({
    __proto__: null,
    debounce: debounce,
    throttle: throttle
});

/**
 * Provide a common method for plug-ins to check the version of DataTables being
 * used, in order to ensure compatibility.
 *
 * @param version1 Version string to check for, in the format "X.Y.Z". Note that
 *   the formats "X" and "X.Y" are also acceptable.
 * @param version2 As above, but optional. If not given the current DataTables
 *   version will be used.
 * @returns true if this version of DataTables is greater or equal to the
 *   required version, or false if this version of DataTales is not suitable
 */
function check$1(version1, version2) {
    let dt = external('datatable');
    var parts1 = version2 ? version2.split('.') : dt.ext.version.split('.');
    var parts2 = version1.split('.');
    var int1, int2;
    for (var i = 0, iLen = parts2.length; i < iLen; i++) {
        int1 = parseInt(parts1[i], 10) || 0;
        int2 = parseInt(parts2[i], 10) || 0;
        // Parts are the same, keep comparing
        if (int1 === int2) {
            continue;
        }
        // Parts are different, return immediately
        return int1 > int2;
    }
    return true;
}

var version = /*#__PURE__*/Object.freeze({
    __proto__: null,
    check: check$1
});

// Note that the aliased properties are for compatibility with DataTables 2-
// which had a set of `util` functions.
var util = {
    ajax,
    array,
    conv,
    data,
    /** @see timer.debounce */
    debounce: debounce,
    /** @see string.normalize */
    diacritics: normalize,
    /** @see string.escapeHtml */
    escapeHtml: escapeHtml,
    /** @see string.escapeRegex */
    escapeRegex: escapeRegex,
    external,
    /** @see data.get */
    get: get$1,
    is,
    object,
    regex,
    /** @see data.set */
    set: set$1,
    string,
    /** @see string.stripHtml */
    stripHtml: stripHtml,
    /** @see timer.throttle */
    throttle: throttle,
    timer,
    /** @see array.unique */
    unique: unique,
    version
};

/** Each element with an event attached needs a unique id */
let _uidCounter = 1;
/**
 * All wrapped event handlers are stored in this array so we can refer back to
 * them for removal. Each entry in the array is for a unique element, using the
 * index to refer to it (the `uid` that is attached to the element).
 */
const _eventStore = [];
/**
 * Get a unique id that can be assigned to an element.
 *
 * @returns UID
 */
function getUid(el) {
    if (!el._event_uid) {
        el._event_uid = _uidCounter++;
    }
    return el._event_uid;
}
/**
 * Get all event handlers that have been assigned to an element
 *
 * @param el Element
 * @returns Array of functions
 */
function get(el) {
    let uid = el._event_uid;
    if (!uid || !_eventStore[uid]) {
        return null;
    }
    return _eventStore[uid];
}
/**
 * Store an event handler for an element (does not apply it)
 *
 * @param el Element
 * @param wrapper Function to set
 */
function set(el, wrapper) {
    let uid = getUid(el);
    if (_eventStore[uid] === undefined) {
        _eventStore[uid] = [];
    }
    _eventStore[uid].push(wrapper);
}
/**
 * Remove an event handler from an element's store
 *
 * @param el Element
 * @param wrapper Function to set
 * @returns void
 */
function remove$1(el, wrapper) {
    let store = get(el);
    if (!store) {
        return;
    }
    let idx = store.indexOf(wrapper);
    if (idx !== -1) {
        store.splice(idx, 1);
    }
}

/*
 * We need an events library that has many of the features of jQuery's event
 * handling - this is for backwards compatibility. Developers who have used
 * jQuery to listen for events should not need to change their code!
 *
 * DataTables uses the following features of jQuery events, which need to be
 * fully supported:
 *
 * * Namespaces
 * * Custom events
 * * Custom event object properties
 * * Arguments for custom events
 *
 * Frustratingly while `dispatchEvent` will trigger all events listened to by
 * jQuery (including namespaces with a shim of `jQuery.event.fix` to add the
 * namespace and rnamespace properties), there is no way for `dispatchEvent` to
 * pass arguments to custom event handlers.
 *
 * Also the inverse doesn't hold - using `addEventListener` followed by
 * `$().trigger()` doesn't trigger the event handler. Therefore using both
 * `dispatchEvent` and `$().trigger()` to fire off both event handlers would
 * risk triggering some event handlers twice.
 *
 * Because of the backwards compatibility constraint and the complications given
 * above, this library will act as a simple proxy to jQuery, if jQuery is
 * present. If it is not, then it will implement the features described above
 * itself. While this is not ideal (I'd prefer to have a way to trigger jQuery
 * listened for events independently of triggering those added with this
 * library, or any other `addEventListener` call), it does ensure backwards
 * compatibility.
 */
const _mouseEvents = [
    'click',
    'dblclick',
    'mousedown',
    'mouseenter',
    'mouseleave',
    'mousemove',
    'mouseout',
    'mouseover',
    'mouseup'
];
/**
 * Add a property to an event object.
 *
 * @param event Event
 * @param name Property name
 * @param value Value to give the value
 */
function setEventProp(event, name, value) {
    // Can't use do `event[name] =` - event object can't always have properties
    // added like that.
    Object.defineProperty(event, name, {
        configurable: true,
        get() {
            return value;
        }
    });
}
/**
 * Check that an element matches a given selector for a given event (ie its
 * target)
 *
 * @param el Root element
 * @param selector CSS selector
 * @param event Event that
 * @returns The matching element if there is one
 */
function delegateTarget(el, selector, event) {
    // Its a delegate - get all elements that match the selector as
    // descendants from the element the event was triggered on
    let elements = Array.from(el.querySelectorAll(selector));
    let target = event.target;
    // The event might originate below our target, so need to climb the ladder
    for (; target && target !== this; target = target.parentNode) {
        // Needs to happen for all matched descendants
        for (let element of elements) {
            // And only call it when matched
            if (element !== target) {
                continue;
            }
            return target;
        }
    }
}
/**
 * Get the event name and namespaces from a string
 *
 * @param original event name and dot delimited namespaces
 * @returns Object with split parts
 */
function parseEventName(original) {
    if (!original) {
        return {
            eventName: null,
            namespaces: []
        };
    }
    let parts = original.split('.');
    let name = parts.shift();
    let isHover = false;
    let isFocus = false;
    // mouse[enter|leave] and focus|blur don't bubble, but do have counterparts
    // which do, so we make use of them, as this allows event delegation on
    // those event names to work as expected.
    if (name === 'mouseenter') {
        name = 'mouseover';
        isHover = true;
    }
    else if (name === 'mouseleave') {
        name = 'mouseout';
        isHover = true;
    }
    else if (name === 'focus') {
        name = 'focusin';
        isFocus = true;
    }
    else if (name === 'blur') {
        name = 'focusout';
        isFocus = true;
    }
    else if (name === 'ready') {
        name = 'DOMContentLoaded';
    }
    return {
        eventName: name,
        isFocus,
        isHover,
        namespaces: parts
    };
}
/**
 * Add an event listener to a function
 *
 * @param el The element to add an event handler to
 * @param nameFull Event name. This can optionally be followed by a dot
 *   separated list of namespaces, a la jQuery. This allows for easy event
 *   removal and also matching triggering.
 * @param handler Callback function to execute
 * @param selector Delegate selector. `null` for non-delegate events
 * @param one Indicate if the event handler should execute only once and then be
 *   removed.
 */
function add(el, nameFull, handler, selector, one) {
    let jq = external('jq');
    if (jq) {
        let method = one ? 'one' : 'on';
        if (selector) {
            jq(el)[method](nameFull, selector, handler);
        }
        else {
            jq(el)[method](nameFull, handler);
        }
        return;
    }
    // No jQuery - add the event ourselves
    let { eventName, namespaces, isFocus, isHover } = parseEventName(nameFull);
    if (!eventName) {
        return;
    }
    // Special handling for the "ready" event - it will trigger when the content
    // is ready, but also if it is already ready, when added.
    if (el === document && eventName === 'DOMContentLoaded' && nameFull.includes('ready')) {
        if (document.readyState === 'complete') {
            handler(new Event('DOMContentLoaded'));
            return;
        }
    }
    // Create a function that will be the actual event handler, and performs any
    // logic we need, such as delegate handling and adding properties.
    let wrapped = function (event) {
        let callScope = el; // Scope for the callback function
        // If the event has a namespace (from a trigger), then the handler
        // should only be run if there is at least one namespace being listened
        // for that matches. This is an OR operation.
        if (event.namespace &&
            !intersection(namespaces, event.namespace.split('.')).length) {
            return;
        }
        // If a special (overridden) type, then we need to check that they apply
        if (!selector &&
            ((isFocus && event.target !== el) ||
                (isHover &&
                    event.relatedTarget &&
                    el.contains(event.relatedTarget)))) {
            return;
        }
        // For delegate events, determine if the target matches our selector
        if (selector) {
            let dTarget = delegateTarget(el, selector, event);
            if (!dTarget) {
                return;
            }
            if (isHover &&
                event.relatedTarget &&
                dTarget.contains(event.relatedTarget)) {
                return;
            }
            callScope = dTarget;
        }
        // Set the properties that jQuery adds to the event object
        setEventProp(event, 'currentTarget', callScope);
        setEventProp(event, 'delegateTarget', el);
        setEventProp(event, 'relatedTarget', event.relatedTarget);
        // If it was triggered, extra data can be passed through using the
        // arguments passed to trigger.
        let retVal = handler.apply(callScope, [event, ...(event._args || [])]);
        if (one) {
            remove(el, eventName, handler, selector);
        }
        if (retVal === false) {
            event.preventDefault();
            event.stopPropagation();
        }
        event.result = retVal;
    };
    wrapped.delegateSelector = selector;
    wrapped.original = handler;
    wrapped.one = one;
    wrapped.type = eventName;
    wrapped.namespaces = namespaces;
    set(el, wrapped);
    el.addEventListener(eventName, wrapped);
}
/**
 * Remove an event from an element
 *
 * @param el The element to remove the event(s) from
 * @param nameFull Event name and / or dot separated namespaces
 * @param handler The function to remove (optional)
 * @param selector Delegate selector (optional)
 */
function remove(el, nameFull, handler, selector) {
    let jq = external('jq');
    if (jq) {
        if (selector) {
            jq(el).off(nameFull, selector, handler);
        }
        else {
            jq(el).off(nameFull, handler);
        }
        return;
    }
    // No jQuery - do it our way
    let { eventName, namespaces } = parseEventName(nameFull);
    let removeEvents = [];
    let stored = get(el);
    if (stored === null) {
        return;
    }
    if (eventName && selector && handler) {
        removeEvents = stored.filter(wrapped => wrapped.type === eventName &&
            wrapped.delegateSelector === selector &&
            wrapped.original === handler);
    }
    else if (eventName && selector) {
        removeEvents = stored.filter(wrapped => wrapped.type === eventName &&
            wrapped.delegateSelector === selector);
    }
    else if (eventName && handler) {
        removeEvents = stored.filter(wrapped => wrapped.type === eventName && wrapped.original === handler);
    }
    else if (eventName) {
        removeEvents = stored.filter(wrapped => wrapped.type === eventName);
    }
    else {
        // No name, use all events
        removeEvents = stored;
    }
    // If namespaces were given then we need to filter down to just those event
    // handlers which have the given namespaces
    if (namespaces.length) {
        removeEvents = removeEvents.filter(
        // The event needs to match all of the namespaces given in order to
        // be removed - this matches jQuery's behaviour. The event could
        // have other namespaces. Do this by filtering to just the filtering
        // namespaces and check that the length matches
        ev => ev.namespaces.filter(ns => namespaces.includes(ns)).length ===
            namespaces.length);
    }
    removeEvents.forEach(wrapped => {
        remove$1(el, wrapped);
        el.removeEventListener(wrapped.type, wrapped);
    });
}
/**
 * Trigger an event on an element. Can have extra data given, which is useful
 * for custom events.
 *
 * @param el Element to trigger the event on
 * @param nameFull Event name with optional dot separated namespaces
 * @param bubbles If the event should bubble up through the DOM or not
 * @param args Array of arguments to pass to the event handler
 * @param eventProps Object of extra parameters to attach to the event object
 * @param returnEvent Indicate if the return should be the event object (for
 *   further processing) or the default prevented state.
 * @returns `true` if default was NOT prevented, `false` if default was
 *   prevented. If `returnEvent` is `true` then the return will be the event
 *   object.
 */
function trigger(el, nameFull, bubbles = false, args = [], eventProps = null, returnEvent = false) {
    let jq = external('jq');
    if (jq) {
        let method = bubbles ? 'trigger' : 'triggerHandler';
        let ev = jq.Event(nameFull);
        each(eventProps, (key, val) => {
            setEventProp(ev, key, val);
        });
        jq(el)[method](ev, args || []);
        if (returnEvent) {
            ev.defaultPrevented = ev.isDefaultPrevented();
            return ev;
        }
        // See note below regarding the inversion
        return !ev.isDefaultPrevented();
    }
    // No jQuery
    let { eventName, namespaces } = parseEventName(nameFull);
    if (!eventName) {
        return false;
    }
    let isMouseEvent = _mouseEvents.includes(eventName.toLowerCase());
    let event = isMouseEvent
        ? new MouseEvent(eventName, { bubbles, cancelable: true })
        : new Event(eventName, { bubbles, cancelable: true });
    // Set the extra properties for the event
    setEventProp(event, 'namespace', namespaces.join('.'));
    setEventProp(event, '_args', args || []);
    each(eventProps, (key, val) => setEventProp(event, key, val));
    el.dispatchEvent(event);
    // A lot of the old DataTables stuff checks for a `false` return to prevent
    // the default action. To maintain compatibility we return an inverted
    // `defaultPrevented` here - i.e. it becomes `do default`.
    return returnEvent ? event : !event.defaultPrevented;
}

// Window level functions
var win = {
    /**
     * Get the height of the window, excluding a horizontal scrollbar if it is
     * present.
     *
     * @returns Height in pixels
     */
    height() {
        var _a;
        return ((_a = document.querySelector('html')) === null || _a === void 0 ? void 0 : _a.clientHeight) || 0;
    },
    /**
     * Remove an event handler from the window
     *
     * @param name Event name (can include or just be a namespace)
     * @param cb Event callback function
     */
    off(name, cb = null) {
        remove(window, name, cb, null);
    },
    /**
     * Add an event handler to the window
     *
     * @param name Event name (can include a namespace)
     * @param cb Event callback function
     */
    on(name, cb) {
        add(window, name, cb, null, false);
    },
    /**
     * Add an event handler to the window that will execute just once
     *
     * @param name Event name (can include a namespace)
     * @param cb Event callback function
     */
    one(name, cb) {
        add(window, name, cb, null, true);
    },
    /**
     * Get the left scroll offset of the window / document
     *
     * @param set Set the scroll position
     * @returns Window X scroll offset in pixels
     */
    scrollLeft(set) {
        if (set !== undefined) {
            window.scrollX = set;
        }
        return window.scrollX;
    },
    /**
     * Get the top scroll offset of the window / document
     *
     * @param set Set the scroll position
     * @returns Window Y scroll offset in pixels
     */
    scrollTop(set) {
        if (set !== undefined) {
            window.scrollY = set;
        }
        return window.scrollY;
    },
    /**
     * Get the width of the window, excluding a vertical scrollbar if it is
     * present.
     *
     * @returns Width in pixels
     */
    width() {
        var _a;
        return ((_a = document.querySelector('html')) === null || _a === void 0 ? void 0 : _a.clientWidth) || 0;
    }
};

function create$3(name) {
    let el = document.createElement(name);
    return new Dom(el);
}
function select(selector) {
    return new Dom(selector);
}
/**
 * `Dom` is a class that provides a chaining UI for simple DOM manipulation and
 * selection.
 */
class Dom {
    /**
     * `Dom` is used for selection and manipulation of the DOM elements in a
     * chaining interface.
     *
     * @param selector
     */
    constructor(selector) {
        /** Number of elements in the array */
        this.length = 0;
        /** Flag to indicate that this is a Dom instance */
        this._isDom = true;
        if (selector) {
            this.add(selector);
        }
    }
    /**
     * Add an element (or multiple) to the instance. Will ensure uniqueness.
     *
     * @param selector Element(s) to add
     * @param sort Indicate if the element should be added in document order.
     * @returns Self for chaining
     */
    add(selector, sort = true) {
        if (selector) {
            if (typeof selector === 'string') {
                let elements = Array.from(document.querySelectorAll(selector));
                addArray(this, elements);
            }
            else if (selector instanceof Dom) {
                addArray(this, selector.get());
            }
            else if (typeof selector === 'object' &&
                !selector.nodeName && // <select> has a length!
                selector.length !== undefined) {
                // Array-like - could be a jQuery instance or DataTables API
                // instance
                let arrayLike = selector;
                for (let i = 0; i < arrayLike.length; i++) {
                    addArray(this, arrayLike[i]);
                }
                sort = false;
            }
            else {
                addArray(this, selector);
            }
        }
        if (sort) {
            this.sort();
        }
        return this;
    }
    /**
     * Insert the given content to each item in the result set.
     *
     * Limit your result set to a single item!
     *
     * @param content The content to append
     * @returns Self for chaining
     */
    append(content) {
        if (!content) {
            return this;
        }
        if (!arrayLike(content)) {
            content = [content];
        }
        // Generate a flat array of the content to be added, with nulls removed
        // this means it will be an array of nodes and / or strings
        let flatContent = flatten([], content).filter(c => !!c);
        /// Got a string somewhere in it, so need to use insertAdjacentHTML
        if (flatContent.find(val => typeof val === 'string')) {
            return this.each(el => {
                for (let i = 0; i < flatContent.length; i++) {
                    if (typeof flatContent[i] === 'string') {
                        el.insertAdjacentHTML('beforeend', flatContent[i]);
                    }
                    else {
                        el.append(flatContent[i]);
                    }
                }
            });
        }
        // Otherwise we can use a document fragment for a single mutation
        // on the main document
        return this.each(el => {
            let fragment = new DocumentFragment();
            for (let i = 0; i < flatContent.length; i++) {
                fragment.append(flatContent[i]);
            }
            el.append(fragment);
        });
    }
    /**
     * Append the current data set items to the element from the selector
     *
     * @param selector
     */
    appendTo(selector) {
        let inst = selector instanceof Dom ? selector : new Dom(selector);
        inst.append(this);
        return this;
    }
    attr(name, value) {
        if (typeof name === 'string' && value === undefined) {
            return this.count() ? this[0].getAttribute(name) : null;
        }
        return this.each(el => {
            if (typeof name === 'string') {
                if (value !== undefined && value !== null) {
                    el.setAttribute(name, typeof value === 'string' ? value : value.toString());
                }
            }
            else {
                each(name, (key, val) => {
                    if (val !== undefined && val !== null) {
                        el.setAttribute(key, val);
                    }
                });
            }
        });
    }
    /**
     * Remove an attribute on each element in the result set
     *
     * @param attr Attribute to remove
     * @returns Self for chaining
     */
    attrRemove(attr) {
        return this.each(el => el.removeAttribute(attr));
    }
    /**
     * Blur on the target elements
     *
     * @returns Self for chaining
     */
    blur() {
        return this.each(el => el.blur());
    }
    /**
     * Get the child from all elements in the result set
     *
     * @param selector Query string that the child much match to be selected
     * @returns New Dom instance with children as the result set
     */
    children(selector) {
        return this.map(el => {
            let children = Array.from(el.children);
            return selector
                ? children.filter(child => child.matches(selector))
                : children;
        });
    }
    /**
     * Add one or more class names to the result set
     *
     * @param name Class name(s) to set
     * @returns Self for chaining
     */
    classAdd(name) {
        if (!name) {
            return this;
        }
        let names = stringArrays(name);
        return this.each(el => {
            names.filter(n => n).forEach(n => el.classList.add(n));
        });
    }
    /**
     * Check if the first element in the result set has the given class
     *
     * @param name Class name to check for
     * @returns Self for chaining
     */
    classHas(name) {
        return this.count() ? this[0].classList.contains(name) : false;
    }
    /**
     * Remove the given class(s) from all elements in the result set
     *
     * @param name Class name to remove
     * @returns Self for chaining
     */
    classRemove(name) {
        if (!name) {
            return this;
        }
        let names = stringArrays(name);
        return this.each(el => {
            names.filter(n => n).forEach(n => el.classList.remove(n));
        });
    }
    /**
     * Toggle a class on all elements in the result set
     *
     * @param name Class name(s) to toggle - space separated
     * @param toggle Toggle on or off
     * @returns Self for chaining
     */
    classToggle(name, toggle) {
        let names = Array.isArray(name) ? name : name.split(' ');
        return this.each(el => {
            names.filter(n => n).forEach(n => el.classList.toggle(n, toggle));
        });
    }
    /**
     * Clone the nodes in the result set and return a new instance
     *
     * @param deep Include the subtree (`true`) or not (`false` - default)
     * @returns New Dom instance with new elements
     */
    clone(deep = false) {
        return this.map(el => el.cloneNode(deep));
    }
    /**
     * Find the closest ancestor for each element in the result set
     *
     * @param selector
     * @returns New Dom instance when the matching ancestors
     */
    closest(selector) {
        if (typeof selector === 'string') {
            return this.map(el => el.closest(selector));
        }
        return this.map(el => {
            // Traverse up the tree seeing if the element matches
            while (el.parentElement) {
                if (el.parentElement === selector) {
                    return selector;
                }
                el = el.parentElement;
            }
            // Nothing found
            return null;
        });
    }
    /**
     * Determine if the result set contains the element specified. Shorthand for
     * .find().count()
     *
     * @param input Element / selector to look for
     * @returns true if it does contain, false otherwise
     */
    contains(input) {
        return this.find(input).count() !== 0;
    }
    /**
     * Get the number of elements in the current result set
     *
     * @returns Number of elements
     */
    count() {
        return this.length;
    }
    css(rule, value) {
        // String getter
        if (typeof rule === 'string' && value === undefined) {
            return this.length ? getComputedStyle(this[0])[rule] : null;
        }
        return this.each(el => {
            if (typeof rule === 'string') {
                // String setter
                el.style[rule] = value;
            }
            else {
                // Object set of rules
                Object.assign(el.style, rule);
            }
        });
    }
    data(name, value) {
        if (!name) {
            let out = {};
            if (!this.count()) {
                return out;
            }
            util.object.each(this[0].dataset, (key, val) => {
                out[key] = dataConvert(val);
            });
            return out;
        }
        if (typeof name === 'string' && value === undefined) {
            return this.length ? dataConvert(this[0].dataset[name]) : null;
        }
        if (typeof name === 'string') {
            this.each(el => (el.dataset[name] = JSON.stringify(value)));
        }
        else {
            each(name, (key, val) => {
                this.each(el => (el.dataset[key] = JSON.stringify(val)));
            });
        }
        return this;
    }
    /**
     * Remove the elements in the result set from the document. Does not remove
     * event listeners.
     *
     * @returns Self for chaining
     */
    detach() {
        return this.each(el => el.remove());
    }
    /**
     * Remove the child elements from each element in the result set from the
     * document. Does not remove event listeners.
     *
     * @returns Self for chaining
     */
    detachChildren() {
        return this.each(el => {
            el.replaceChildren();
        });
    }
    /**
     * Iterate over each item in the result set and perform an action
     *
     * @param callback Callback function
     * @returns Self for chaining
     */
    each(callback) {
        for (let i = 0; i < this.length; i++) {
            let el = this[i];
            callback.call(el, el, i);
        }
        return this;
    }
    /**
     * Inverse iteration over each item in the result set and perform an action
     *
     * @param callback Callback function
     * @returns Self for chaining
     */
    eachReverse(callback) {
        for (let i = this.length - 1; i >= 0; i--) {
            let el = this[i];
            callback.call(el, el, i);
        }
        return this;
    }
    /**
     * Remove all children
     *
     * @returns Self for chaining
     */
    empty() {
        // TODO should remove event listeners
        return this.each(el => {
            var _a;
            if (el.replaceChildren) {
                el.replaceChildren();
            }
            else {
                while (el.childNodes.length) {
                    (_a = el.firstChild) === null || _a === void 0 ? void 0 : _a.remove();
                }
            }
        });
    }
    /**
     * Get a new Dom instance with just a specific element from the result set
     *
     * @param idx The element to use
     * @returns New Dom instance
     */
    eq(idx) {
        return idx < this.count() ? new Dom(this.get(idx)) : new Dom();
    }
    get(idx) {
        return idx !== undefined ? this[idx] : Array.from(this);
    }
    /**
     * Call focus on the target elements
     *
     * @returns Self for chaining
     */
    focus() {
        return this.each(el => el.focus());
    }
    /**
     * Reduce the result set based on a given filter, which can be a CSS
     * selector, an element or array of elements.
     *
     * @param filter Optional selector or function that the result set element
     *   would need to match to be selected.
     * @returns New Dom instance containing the filters elements
     */
    filter(filter) {
        return this.map(el => {
            if (filter === undefined) {
                return el;
            }
            if (typeof filter === 'function') {
                return filter(el) ? el : null;
            }
            // Direct match - allows an element to be given as the filter
            if (typeof filter !== 'string') {
                if (arrayLike(filter)) {
                    return Array.from(filter).includes(el) ? el : null;
                }
                return filter === el ? el : null;
            }
            // CSS selector
            if (!el.matches(filter)) {
                return null;
            }
            // If there is a pseudo child selector, want to check that the
            // element is actually in the document, if not, then
            // `:first-child` (etc) will match detached elements, which is
            // not desirable.
            if (!el.parentNode &&
                (filter.match(/:\w+-child/) || filter.match(/:\w+-of-type/))) {
                return null;
            }
            return el;
        });
    }
    /**
     * Get all matching descendants
     *
     * @param input Elements to find
     * @returns A new Dom instance with all matching elements
     */
    find(input) {
        if (input === null) {
            return new Dom();
        }
        // Text based selector - loop over each element in the result set, doing
        // the search on each and adding to a new instance.
        if (typeof input === 'string') {
            return this.map(el => Array.from(el.querySelectorAll(input)));
        }
        let selector = input instanceof Dom ? input.get() : input;
        // Otherwise its an element, that we need to see if one of the elements
        // in the result set is a parent of the given target
        let hasParent = false;
        this.each(el => {
            if (new Dom(selector).closest(el).count()) {
                hasParent = true;
            }
        });
        return new Dom(hasParent ? selector : []);
    }
    /**
     * Get the last element in the result set
     *
     * @returns New instance with just the selected item
     */
    first() {
        return new Dom(this.length ? this[0] : null);
    }
    height(include) {
        if (!this.count()) {
            return 0;
        }
        if (include === undefined ||
            include === 'withPadding' ||
            include === 'withBorder' ||
            include === 'withMargin' ||
            include === 'inner' ||
            include === 'outer') {
            let el = this[0];
            let computed = window.getComputedStyle(this[0]);
            let rectHeight = el.getBoundingClientRect().height;
            if (!include || include === 'content') {
                // Content. Minus scrollbar if there is one. This is basically
                // clientHeight minus padding, but that isn't fractional, so use
                // the bounding rect.
                let barHeight = el.offsetHeight -
                    parseFloat(computed.borderTop) -
                    parseFloat(computed.borderBottom) -
                    el.clientHeight;
                return (rectHeight -
                    parseFloat(computed.paddingTop) -
                    parseFloat(computed.paddingBottom) -
                    parseFloat(computed.borderTop) -
                    parseFloat(computed.borderBottom) -
                    barHeight);
            }
            else if (include === 'withPadding' || include === 'inner') {
                return (rectHeight -
                    parseFloat(computed.borderTop) -
                    parseFloat(computed.borderBottom));
            }
            else if (include === 'withBorder') {
                return rectHeight;
            }
            else {
                // withMargin
                return (rectHeight +
                    parseFloat(computed.marginTop) +
                    parseFloat(computed.marginBottom));
            }
        }
        else {
            // Setter
            return this.each(el => (el.style.height =
                typeof include === 'string' ? include : include + 'px'));
        }
    }
    /**
     * Hide an element by setting it to `display: none`
     *
     * @returns Self for chaining
     */
    hide() {
        return this.each(el => {
            el.style.display = 'none';
        });
    }
    html(data) {
        if (data !== undefined) {
            return this.each(el => {
                el.innerHTML = data;
            });
        }
        else {
            return this.count() ? this[0].innerHTML : null;
        }
    }
    /**
     * Boolean return check on if an item in the result set matches the selector
     * given. Only one need match.
     *
     * @param selector Selector to match against
     * @returns Boolean true if there is a match
     */
    is(selector) {
        return this.filter(selector).count() > 0;
    }
    /**
     * Determine if the first element in the result set is in the document or
     * not
     *
     * @returns true if is, false if detached
     */
    isAttached() {
        if (this.count() === 0) {
            return false;
        }
        return document.body.contains(this[0]);
    }
    /**
     * Determine if the first element in the result set is visible or not.
     *
     * @returns Visibility flag
     */
    isVisible() {
        if (this.count() === 0) {
            return false;
        }
        let el = this[0];
        return !!(el.offsetWidth ||
            el.offsetHeight ||
            el.getClientRects().length);
    }
    /**
     * Get the index of an element from among its siblings
     *
     * @returns Element index
     */
    index() {
        if (this.count()) {
            let el = this[0];
            return Array.from(el.parentNode.children).indexOf(el);
        }
        return -1;
    }
    /**
     * Insert each element in the result set after a target node
     *
     * @param target Element after which the insert should happen
     * @returns Self for chaining
     */
    insertAfter(target) {
        let nodes = elementArray(target);
        return this.eachReverse(el => {
            nodes.forEach(n => { var _a; return (_a = n === null || n === void 0 ? void 0 : n.parentNode) === null || _a === void 0 ? void 0 : _a.insertBefore(el, n.nextSibling); });
        });
    }
    /**
     * Insert each element in the result set before a target node
     *
     * @param target Element before which the insert should happen
     * @returns Self for chaining
     */
    insertBefore(target) {
        let nodes = elementArray(target);
        return this.each(el => {
            nodes.forEach(n => { var _a; return (_a = n === null || n === void 0 ? void 0 : n.parentNode) === null || _a === void 0 ? void 0 : _a.insertBefore(el, n); });
        });
    }
    /**
     * Get the last element in the result set
     *
     * @returns New instance with just the selected item
     */
    last() {
        let s = this;
        return new Dom(s.length ? s[s.length - 1] : null);
    }
    /**
     * Create a new Dom instance based on the results from a callback function
     * which is executed per element in the result set.
     *
     * @param fn Function to get the elements to add to the new instance
     * @returns New Dom instance with the results from the callback
     */
    map(fn) {
        let next = new Dom();
        this.each(el => {
            // Don't reorder the items
            next.add(fn(el), false);
        });
        return next;
    }
    /**
     * Create an array of any data type based on a function returning a value
     * from each element in the result set.
     *
     * @param fn Mapping function
     * @returns Array of returned objects.
     */
    mapTo(fn) {
        let result = [];
        this.each((el, idx) => result.push(fn(el, idx)));
        return result;
    }
    off(arg1, arg2, arg3) {
        let { handler, names, selector } = normaliseEventParams(arg1, arg2, arg3);
        return this.each(el => {
            names.forEach(name => {
                remove(el, name, handler, selector);
            });
        });
    }
    /**
     * Get the offset of the first element in the result set. The offset is the
     * coordinates of the element relative to the document.
     *
     * @returns Object with top and left offset
     */
    offset() {
        if (!this.count()) {
            return {
                top: 0,
                left: 0
            };
        }
        let box = this[0].getBoundingClientRect();
        let docElem = document.documentElement;
        return {
            top: box.top + window.pageYOffset - docElem.clientTop,
            left: box.left + window.pageXOffset - docElem.clientLeft
        };
    }
    /**
     * Get the offset parents of the elements in the result set.
     *
     * Departure from jQuery - it won't go up to `html`
     *
     * @returns Instance with the result set as the offset parents
     */
    offsetParent() {
        return this.map(el => el.offsetParent || document.body);
    }
    on(arg1, arg2, arg3) {
        let { handler, names, selector } = normaliseEventParams(arg1, arg2, arg3);
        return this.each(el => {
            names
                .filter(n => n !== null)
                .forEach(name => {
                add(el, name, handler, selector, false);
            });
        });
    }
    one(arg1, arg2, arg3) {
        let { handler, names, selector } = normaliseEventParams(arg1, arg2, arg3);
        return this.each(el => {
            names
                .filter(n => n !== null)
                .forEach(name => {
                add(el, name, handler, selector, true);
            });
        });
    }
    /**
     * Get the parent element for each element in the result set
     *
     * @param filter Optional selector that the parent element would need to
     *   match to be selected.
     * @returns New Dom instance containing the parent elements
     */
    parent(filter) {
        return this.map(el => {
            let parent = el.parentElement;
            if (filter) {
                return (parent === null || parent === void 0 ? void 0 : parent.matches(filter)) ? parent : null;
            }
            return parent;
        });
    }
    /**
     * Get the position of the first element in the result set. The position is
     * the coordinates relative to the offset parent.
     *
     * @returns Object with top and left position coordinates
     */
    position() {
        if (!this.count()) {
            return {
                top: 0,
                left: 0
            };
        }
        let el = this[0];
        let { marginTop, marginLeft } = getComputedStyle(el);
        return {
            top: el.offsetTop - parseInt(marginTop),
            left: el.offsetLeft - parseInt(marginLeft)
        };
    }
    /**
     * Prepend the given content to each item in the result set.
     *
     * You should limit your result set to a single item!
     *
     * @param content Item(s) to prepend
     * @returns Self for chaining
     */
    prepend(content) {
        return this.each(el => {
            if (content instanceof Dom) {
                // Reverse the array, so if there are multiple elements, they
                // end up being added sequentially, just like jQuery
                let itemsReversed = Array.from(content).reverse();
                itemsReversed.forEach(item => el.prepend(item));
            }
            else if (typeof content === 'string') {
                el.insertAdjacentHTML('afterbegin', content);
            }
            else {
                el.prepend(content);
            }
        });
    }
    /**
     * Append the current data set items to the element from the selector
     *
     * @param selector Select item to insert result sets into
     * @returns Self for chaining
     */
    prependTo(selector) {
        if (selector instanceof Dom) {
            selector.prepend(this);
        }
        else {
            new Dom(selector).prepend(this);
        }
        return this;
    }
    prop(name, value) {
        if (typeof name === 'string' && value === undefined) {
            return this.count() ? this[0][name] : null;
        }
        return this.each(el => {
            el[name] = value;
        });
    }
    /**
     * Remove a property from all elements in the result set
     *
     * @param name Property name to remove
     * @returns Self for chaining
     */
    propRemove(name) {
        return this.each(el => {
            delete el[name];
        });
    }
    /**
     * Removed all nodes in the result set from the document
     *
     * @returns Self for chaining
     */
    remove() {
        // TODO this should remove event listeners
        return this.each(el => el.remove());
    }
    /**
     * Replace the elements in the result set with those given.
     *
     * @param replacer Element(s) to insert in place of the originals
     * @returns Self
     */
    replaceWith(replacer) {
        return this.each(el => {
            if (replacer instanceof Dom) {
                el.replaceWith(...replacer.get());
            }
            else {
                el.replaceWith(replacer);
            }
        });
    }
    scrollLeft(val) {
        if (val === undefined) {
            return this.count() ? this[0].scrollLeft : 0;
        }
        return this.each(el => (el.scrollLeft = val));
    }
    scrollTop(val) {
        if (val === undefined) {
            return this.count() ? this[0].scrollTop : 0;
        }
        return this.each(el => (el.scrollTop = val));
    }
    /**
     * Get the siblings of all elements in the result set
     *
     * @returns New Dom instance containing the sibling elements
     */
    siblings() {
        return this.map(el => {
            return el.parentElement
                ? Array.from(el.parentElement.children).filter(child => child !== el)
                : [];
        });
    }
    /**
     * Set the elements in the result set to display as blocks
     *
     * @returns Self for chaining
     * @todo Could be smarter with hide, since some elements might have been a
     *   grid or flex before being hidden.
     */
    show() {
        return this.each(el => {
            el.style.display = 'block';
        });
    }
    /**
     * Sort the DOM elements into document order.
     *
     * This is normally not needed as elements selected with a DOM selector are
     * automatically sorted in document order. However, in the case of elements
     * being added as an array, their order will be retained. In such as case
     * you might wish to sort them in document order.
     */
    sort() {
        Array.prototype.sort.call(this, documentOrder);
        return this;
    }
    text(txt) {
        if (txt === undefined) {
            return this.count() ? this[0].textContent : null;
        }
        return this.each(el => {
            el.textContent = txt;
        });
    }
    /**
     * Perform a CSS transition - i.e. an animation. Note this isn't nearly as
     * comprehensive as an animation library, nor is it meant to be. It is for
     * simple transitions such as fading in only.
     *
     * To set up something like a fade in, do `dom.css({opacity:
     * 0}).transition({opacity: 1})`.
     *
     * @param css CSS properties to transition
     * @param duration Transition duration
     * @param ease CSS easing function name
     * @param cb Callback function
     * @returns Self for chaining
     */
    transition(css, duration, ease, cb) {
        if (!this.count()) {
            return this;
        }
        if (!duration && duration !== 0) {
            duration = 400;
        }
        if (!ease) {
            ease = '';
        }
        if (!cb) {
            cb = () => { };
        }
        if (Dom.transitions && duration !== 0) {
            let first = this[0];
            // If there was an existing transition, cancel its callback
            if (first._dom_tra) {
                clearTimeout(first._dom_tra);
                delete first._dom_tra;
            }
            setTimeout(() => {
                this.css('transition', 'all ' + duration + 'ms ' + ease);
                this.css(css);
            }, 0);
            first._dom_tra = setTimeout(() => {
                delete first._dom_tra;
                this.css('transition', '');
                cb.call(this);
            }, duration);
        }
        else {
            this.css(css);
            cb.call(this);
        }
        return this;
    }
    trigger(name, bubbles = true, args = null, props = null, returnEvent = false) {
        let { names } = normaliseEventParams(name);
        let ret = [];
        this.each(el => {
            names
                .filter(n => n !== null)
                .forEach(name => {
                ret.push(trigger(el, name, bubbles, args, props, returnEvent));
            });
        });
        return ret;
    }
    val(value) {
        if (value === undefined) {
            // Getter
            if (!this.count()) {
                return null;
            }
            let el = this[0];
            if (el.options && el.multiple) {
                return Array.from(el.options)
                    .filter(opt => opt.selected)
                    .map(opt => opt.value);
            }
            return el.value;
        }
        // Setter
        return this.each((el) => {
            if (el.options && el.multiple) {
                let valArr = Array.isArray(value) ? value : [value];
                Array.from(el.options).forEach(opt => (opt.selected = valArr.includes(opt.value)));
            }
            else {
                // This works for select elements as well in modern browsers
                el.value = value;
            }
        });
    }
    width(include) {
        if (!this.count()) {
            return 0;
        }
        if (include === undefined ||
            include === 'withPadding' ||
            include === 'withBorder' ||
            include === 'withMargin' ||
            include === 'inner' ||
            include === 'outer') {
            let el = this[0];
            let computed = window.getComputedStyle(el);
            let rectWidth = el.getBoundingClientRect().width;
            if (!include || include === 'content') {
                // Content. Minus scrollbar if there is one. This is basically
                // clientWidth minus padding, but that isn't fractional, so use
                // the bounding rect.
                let barWidth = el.offsetWidth -
                    parseFloat(computed.borderLeft) -
                    parseFloat(computed.borderRight) -
                    el.clientWidth;
                return (rectWidth -
                    parseFloat(computed.paddingLeft) -
                    parseFloat(computed.paddingRight) -
                    parseFloat(computed.borderLeft) -
                    parseFloat(computed.borderRight) -
                    barWidth);
            }
            else if (include === 'withPadding' || include === 'inner') {
                return (rectWidth -
                    parseFloat(computed.borderLeft) -
                    parseFloat(computed.borderRight));
            }
            else if (include === 'withBorder') {
                return rectWidth;
            }
            else {
                // withMargin
                return (rectWidth +
                    parseFloat(computed.marginLeft) +
                    parseFloat(computed.marginRight));
            }
        }
        else {
            // Setter
            return this.each(el => (el.style.width =
                typeof include === 'string' ? include : include + 'px'));
        }
    }
}
/**
 * Create a new element and wrap in a `Dom` instance (alias of `create`)
 *
 * @param name Element name to create
 * @returns Dom instance for manipulating the new element
 */
Dom.c = create$3;
/**
 * Create a new element and wrap in a `Dom` instance (alias of `c`)
 *
 * @param name Element name to create
 * @returns Dom instance for manipulating the new element
 */
Dom.create = create$3;
/**
 * Select items from the document and wrap in a `Dom` instance (alias of
 * `select`)
 *
 * @param selector Items to select
 * @returns Dom instance for manipulating the selected items
 */
Dom.s = select;
/**
 * Select items from the document and wrap in a `Dom` instance (alias of
 * `s`)
 *
 * @param selector Items to select
 * @returns Dom instance for manipulating the selected items
 */
Dom.select = select;
/**
 * Flag to indicate if transitions (animations) should be allowed. Set to
 * false to disable and have it jump to the end.
 */
Dom.transitions = true;
/**
 * Window object methods
 */
Dom.w = win;
// Aliases for jQuery-likeness. Not exposed via Typescript, but that might
// change.
Dom.prototype.addClass = Dom.prototype.classAdd;
Dom.prototype.hasClass = Dom.prototype.classHas;
Dom.prototype.removeClass = Dom.prototype.classRemove;
/**
 * Convert a data value into a typed value
 *
 * @param val Data to convert
 * @returns Converted value
 */
function dataConvert(val) {
    if (val === undefined) {
        return null;
    }
    try {
        return JSON.parse(val);
    }
    catch (e) {
        return val;
    }
}
function normaliseEventParams(name, arg2, arg3) {
    let selector;
    let handler;
    let names = name ? name.split(' ').map(str => str.trim()) : [null];
    if (typeof arg2 === 'string') {
        selector = arg2;
        handler = arg3;
    }
    else {
        selector = null;
        handler = arg2;
    }
    return {
        handler,
        names,
        selector
    };
}
function documentOrder(a, b) {
    if (a === b) {
        return 0;
    }
    let position = a.compareDocumentPosition(b);
    if (position & Node.DOCUMENT_POSITION_DISCONNECTED) {
        // One is disconnected - find which
        if (document.body.contains(a)) {
            return -1;
        }
        else if (document.body.contains(b)) {
            return 1;
        }
        return 0;
    }
    else if (position & Node.DOCUMENT_POSITION_FOLLOWING ||
        position & Node.DOCUMENT_POSITION_CONTAINED_BY) {
        return -1;
    }
    else if (position & Node.DOCUMENT_POSITION_PRECEDING ||
        position & Node.DOCUMENT_POSITION_CONTAINS) {
        return 1;
    }
    else {
        return 0;
    }
}
function elementArray(target) {
    return dom(target)
        ? target.get()
        : Array.isArray(target)
            ? target
            : [target];
}
function addArray(store, el) {
    if (util.is.arrayLike(el)) {
        for (var i = 0; i < el.length; i++) {
            let e = el[i];
            if (e !== null && e !== undefined) {
                store[store.length] = e;
                store.length++;
            }
        }
    }
    else if (el !== null && el !== undefined) {
        store[store.length] = el;
        store.length++;
    }
}
function stringArrays(name) {
    let names = [];
    let add = function (n) {
        names.push.apply(names, n.split(' '));
    };
    if (Array.isArray(name)) {
        name.forEach(n => add(n));
    }
    else {
        add(name);
    }
    return names;
}

const features = {};
const legacy = [];
/**
 * Create a new feature that can be used for layout
 *
 * @param name The name of the new feature.
 * @param cb A function that will create the elements and event listeners for
 * the feature being added.
 * @param legacyChar
 */
function register$2(name, cb, legacyChar = '') {
    features[name] = cb;
    if (legacyChar) {
        legacy.push({
            cFeature: legacyChar,
            fnInit: cb
        });
    }
}

var classes$1 = {
    container: 'dt-container',
    empty: {
        row: 'dt-empty'
    },
    info: {
        container: 'dt-info'
    },
    layout: {
        row: 'dt-layout-row',
        cell: 'dt-layout-cell',
        tableRow: 'dt-layout-table',
        tableCell: '',
        start: 'dt-layout-start',
        end: 'dt-layout-end',
        full: 'dt-layout-full'
    },
    length: {
        container: 'dt-length',
        select: 'dt-input'
    },
    order: {
        canAsc: 'dt-orderable-asc',
        canDesc: 'dt-orderable-desc',
        isAsc: 'dt-ordering-asc',
        isDesc: 'dt-ordering-desc',
        none: 'dt-orderable-none',
        position: 'sorting_'
    },
    processing: {
        container: 'dt-processing'
    },
    scrolling: {
        body: 'dt-scroll-body',
        container: 'dt-scroll',
        footer: {
            self: 'dt-scroll-foot',
            inner: 'dt-scroll-footInner'
        },
        header: {
            self: 'dt-scroll-head',
            inner: 'dt-scroll-headInner'
        }
    },
    search: {
        container: 'dt-search',
        input: 'dt-input'
    },
    table: 'dataTable',
    tbody: {
        cell: '',
        row: ''
    },
    thead: {
        cell: '',
        row: ''
    },
    tfoot: {
        cell: '',
        row: ''
    },
    paging: {
        active: 'current',
        button: 'dt-paging-button',
        container: 'dt-paging',
        disabled: 'disabled',
        nav: ''
    }
};

/**
 * Compute what number buttons to show in the paging control
 *
 * @param page Current page
 * @param pages Total number of pages
 * @param buttons Target number of number buttons
 * @param addFirstLast Indicate if page 1 and end should be included
 * @returns Buttons to show
 */
function pagingNumbers(page, pages, buttons, addFirstLast) {
    let numbers = [], half = Math.floor(buttons / 2), before = addFirstLast ? 2 : 1, after = addFirstLast ? 1 : 0;
    if (pages <= buttons) {
        numbers = range(0, pages);
    }
    else if (buttons === 1) {
        // Single button - current page only
        numbers = [page];
    }
    else if (buttons === 3) {
        // Special logic for just three buttons
        if (page <= 1) {
            numbers = [0, 1, 'ellipsis'];
        }
        else if (page >= pages - 2) {
            numbers = range(pages - 2, pages);
            numbers.unshift('ellipsis');
        }
        else {
            numbers = ['ellipsis', page, 'ellipsis'];
        }
    }
    else if (page <= half) {
        numbers = range(0, buttons - before);
        numbers.push('ellipsis');
        if (addFirstLast) {
            numbers.push(pages - 1);
        }
    }
    else if (page >= pages - 1 - half) {
        numbers = range(pages - (buttons - before), pages);
        numbers.unshift('ellipsis');
        if (addFirstLast) {
            numbers.unshift(0);
        }
    }
    else {
        numbers = range(page - half + before, page + half - after);
        numbers.push('ellipsis');
        numbers.unshift('ellipsis');
        if (addFirstLast) {
            numbers.push(pages - 1);
            numbers.unshift(0);
        }
    }
    return numbers;
}
var pager = {
    simple: function () {
        return ['previous', 'next'];
    },
    full: function () {
        return ['first', 'previous', 'next', 'last'];
    },
    numbers: function () {
        return ['numbers'];
    },
    simple_numbers: function () {
        return ['previous', 'numbers', 'next'];
    },
    full_numbers: function () {
        return ['first', 'previous', 'numbers', 'next', 'last'];
    },
    first_last: function () {
        return ['first', 'last'];
    },
    first_last_numbers: function () {
        return ['first', 'numbers', 'last'];
    },
    // For testing and plug-ins to use
    _numbers: pagingNumbers,
    // Number of number buttons - legacy, use `numbers` option for paging feature
    numbers_length: 7
};

const footer = (settings, cell, classes) => {
    cell.classAdd(classes.tfoot.cell);
};
const header = (settings, cell, classes) => {
    cell.classAdd(classes.thead.cell);
    if (!settings.features.ordering) {
        cell.classAdd(classes.order.none);
    }
    var titleRow = settings.titleRow;
    var headerRows = cell.closest('thead').find('tr');
    var rowIdx = cell.parent().index();
    // Conditions to not apply the ordering icons
    if (
    // Cells and rows which have the attribute to disable the icons
    cell.attr('data-dt-order') === 'disable' ||
        cell.parent().attr('data-dt-order') === 'disable' ||
        // titleRow support, for defining a specific row in the header
        (titleRow === true && rowIdx !== 0) ||
        (titleRow === false && rowIdx !== headerRows.count() - 1) ||
        (typeof titleRow === 'number' && rowIdx !== titleRow)) {
        return;
    }
    // No additional mark-up required. Attach a sort listener to update on sort
    // - note that using the `DT` namespace will allow the event to be removed
    // automatically on destroy, while the `dt` namespaced event is the one we
    // are listening for
    Dom.s(settings.table).on('order.dt.DT column-visibility.dt.DT', function (e, ctx, column) {
        if (settings !== ctx) {
            // need to check if this is the host
            return; // table, not a nested one
        }
        var sorting = ctx.sortDetails;
        if (!sorting) {
            return;
        }
        var orderedColumns = pluck(sorting, 'col');
        // This handler is only needed on column visibility if the column is
        // part of the ordering. If it isn't, then we can bail out to save
        // performance. It could be a separate event handler, but this is a
        // balance between code reuse / size and performance console.log(e,
        // e.name, column, orderedColumns, orderedColumns.includes(column))
        if (e.type === 'column-visibility' &&
            !orderedColumns.includes(column)) {
            return;
        }
        var i;
        var orderClasses = classes.order;
        var columns = ctx.api.columns(cell);
        var col = settings.columns[columns.flatten()[0]];
        var orderable = columns.orderable().includes(true);
        var ariaType = '';
        var indexes = columns.indexes();
        var sortDirs = columns.orderable(true).flatten();
        var tabIndex = settings.tabIndex;
        var canOrder = ctx.orderHandler && orderable;
        cell.classRemove(orderClasses.isAsc + ' ' + orderClasses.isDesc)
            .classToggle(orderClasses.none, !orderable)
            .classToggle(orderClasses.canAsc, canOrder && sortDirs.includes('asc'))
            .classToggle(orderClasses.canDesc, canOrder && sortDirs.includes('desc'));
        // Determine if all of the columns that this cell covers are
        // included in the current ordering
        var isOrdering = true;
        for (i = 0; i < indexes.length; i++) {
            if (!orderedColumns.includes(indexes[i])) {
                isOrdering = false;
            }
        }
        if (isOrdering) {
            // Get the ordering direction for the columns under this cell
            // Note that it is possible for a cell to be asc and desc
            // sorting (column spanning cells)
            var orderDirs = columns.order();
            cell.classAdd((orderDirs.includes('asc') ? orderClasses.isAsc : '') +
                (orderDirs.includes('desc') ? orderClasses.isDesc : ''));
        }
        // Find the first visible column that has ordering applied to it -
        // it get's the aria information, as the ARIA spec says that only
        // one column should be marked with aria-sort
        var firstVis = -1; // column index
        for (i = 0; i < orderedColumns.length; i++) {
            if (settings.columns[orderedColumns[i]].visible) {
                firstVis = orderedColumns[i];
                break;
            }
        }
        if (indexes[0] == firstVis) {
            var firstSort = sorting[0];
            var sortOrder = col.orderSequence;
            cell.attr('aria-sort', firstSort.dir === 'asc' ? 'ascending' : 'descending');
            // Determine if the next click will remove sorting or change the
            // sort
            ariaType =
                sortOrder && !sortOrder[firstSort.index + 1]
                    ? 'Remove'
                    : 'Reverse';
        }
        else {
            cell.attrRemove('aria-sort');
        }
        // Make the headers tab-able for keyboard navigation
        if (orderable) {
            var orderSpan = cell.find('.dt-column-order');
            orderSpan
                .attr('role', 'button')
                .attr('aria-label', orderable
                ? col.ariaTitle +
                    ctx.api.i18n('aria.orderable' + ariaType)
                : col.ariaTitle);
            if (tabIndex !== -1) {
                orderSpan.attr('tabindex', tabIndex);
            }
        }
    });
};
const layout = (settings, container, items) => {
    let classes = settings.classes.layout;
    let row = Dom
        .c('div')
        .attr('id', items.id || null)
        .classAdd(items.className || classes.row)
        .appendTo(container);
    displayRowCells(items, function (key, val) {
        var klass = '';
        if (val.table) {
            row.classAdd(classes.tableRow);
            klass += classes.tableCell + ' ';
        }
        if (key === 'start') {
            klass += classes.start;
        }
        else if (key === 'end') {
            klass += classes.end;
        }
        else {
            klass += classes.full;
        }
        Dom.c('div')
            .attr({
            id: val.id || null,
            class: val.className
                ? val.className
                : classes.cell + ' ' + klass
        })
            .append(val.contents)
            .appendTo(row);
    });
};
const pagingButton = (settings, buttonType, content, active, disabled) => {
    var classes = settings.classes.paging;
    var btnClasses = [classes.button];
    var btn;
    if (active) {
        btnClasses.push(classes.active);
    }
    if (disabled) {
        btnClasses.push(classes.disabled);
    }
    if (buttonType === 'ellipsis') {
        btn = Dom.c('span').classAdd('ellipsis').html(content).get(0);
    }
    else {
        btn = Dom
            .c('button')
            .classAdd(btnClasses.join(' '))
            .attr('role', 'link')
            .attr('type', 'button')
            .html(content)
            .get(0);
    }
    return {
        display: btn,
        clicker: btn
    };
};
const pagingContainer = (settings, buttons) => {
    // No wrapping element - just append directly to the host
    return buttons;
};
function displayRowCells(items, fn) {
    if (items.start) {
        fn('start', items.start);
    }
    if (items.end) {
        fn('end', items.end);
    }
    if (items.full) {
        fn('full', items.full);
    }
}

const store = {
    className: {},
    detect: [],
    render: {},
    search: {},
    order: {}
};
// Common function to remove new lines, strip HTML and diacritic control
function _filterString(stripHtml, normalize) {
    return function (str) {
        if (util.is.empty(str) || typeof str !== 'string') {
            return str;
        }
        str = str.replace(util.regex.reNewLines, ' ');
        if (stripHtml) {
            str = util.stripHtml(str);
        }
        {
            str = util.diacritics(str, false);
        }
        return str;
    };
}
function __numericReplace(d, decimalPlace, re1, re2) {
    if (d !== 0 && (!d || d === '-')) {
        return -Infinity;
    }
    if (typeof d === 'number' || typeof d === 'bigint') {
        return d;
    }
    // If a decimal place other than `.` is used, it needs to be given to the
    // function so we can detect it and replace with a `.` which is the only
    // decimal place JavaScript recognises - it is not locale aware.
    if (decimalPlace) {
        d = util.conv.numToDecimal(d, decimalPlace);
    }
    if (typeof d === 'string') {
        if (re1) {
            d = d.replace(re1, '');
        }
        if (re2) {
            d = d.replace(re2, '');
        }
    }
    return d * 1;
}
function register$1(name, prop, val) {
    if (!prop) {
        return {
            className: store.className[name],
            detect: store.detect.find(function (fn) {
                return fn._name === name;
            }),
            order: {
                pre: store.order[name + '-pre'],
                asc: store.order[name + '-asc'],
                desc: store.order[name + '-desc']
            },
            render: store.render[name],
            search: store.search[name]
        };
    }
    var setProp = function (prop2, propVal) {
        store[prop2][name] = propVal;
    };
    var setDetect = function (detect) {
        // `detect` can be a function or an object - we set a name
        // property for either - that is used for the detection
        Object.defineProperty(detect, '_name', { value: name });
        var idx = store.detect.findIndex(function (item) {
            return item._name === name;
        });
        if (idx === -1) {
            store.detect.unshift(detect);
        }
        else {
            store.detect.splice(idx, 1, detect);
        }
    };
    var setOrder = function (obj) {
        store.order[name + '-pre'] = obj.pre; // can be undefined
        store.order[name + '-asc'] = obj.asc; // can be undefined
        store.order[name + '-desc'] = obj.desc; // can be undefined
    };
    // prop is optional
    if (val === undefined) {
        val = prop;
        prop = undefined;
    }
    if (prop === 'className') {
        setProp('className', val);
    }
    else if (prop === 'detect') {
        setDetect(val);
    }
    else if (prop === 'order') {
        setOrder(val);
    }
    else if (prop === 'render') {
        setProp('render', val);
    }
    else if (prop === 'search') {
        setProp('search', val);
    }
    else if (!prop) {
        if (val.className) {
            setProp('className', val.className);
        }
        if (val.detect !== undefined) {
            setDetect(val.detect);
        }
        if (val.order) {
            setOrder(val.order);
        }
        if (val.render !== undefined) {
            setProp('render', val.render);
        }
        if (val.search !== undefined) {
            setProp('search', val.search);
        }
    }
}
// Get a list of types
function types() {
    return store.detect.map(function (detect) {
        return detect._name;
    });
}
var __diacriticSort = function (a, b) {
    a = a !== null && a !== undefined ? a.toString().toLowerCase() : '';
    b = b !== null && b !== undefined ? b.toString().toLowerCase() : '';
    // Checked for `navigator.languages` support in `oneOf` so this code can't execute in old
    // Safari and thus can disable this check
    // eslint-disable-next-line compat/compat
    return a.localeCompare(b, navigator.languages[0] || navigator.language, {
        numeric: true,
        ignorePunctuation: true
    });
};
var __diacriticHtmlSort = function (a, b) {
    a = util.stripHtml(a);
    b = util.stripHtml(b);
    return __diacriticSort(a, b);
};
//
// Built in data types
//
register$1('string', {
    detect: function () {
        return 'string';
    },
    order: {
        pre: function (a) {
            // This is a little complex, but faster than always calling toString,
            // http://jsperf.com/tostring-v-check
            return util.is.empty(a) && typeof a !== 'boolean'
                ? ''
                : typeof a === 'string'
                    ? a.toLowerCase()
                    : !a.toString
                        ? ''
                        : a.toString();
        }
    },
    search: _filterString(false)
});
register$1('string-utf8', {
    detect: {
        allOf: function () {
            return true;
        },
        oneOf: function (d) {
            // At least one data point must contain a non-ASCII character
            // This line will also check if navigator.languages is supported or not. If not (Safari 10.0-)
            // this data type won't be supported.
            // eslint-disable-next-line compat/compat
            return (!util.is.empty(d) &&
                navigator.languages &&
                typeof d === 'string' &&
                !!d.match(/[^\x00-\x7F]/));
        }
    },
    order: {
        asc: __diacriticSort,
        desc: function (a, b) {
            return __diacriticSort(a, b) * -1;
        }
    },
    search: _filterString(false)
});
register$1('html', {
    detect: {
        allOf: function (d) {
            return (util.is.empty(d) ||
                (typeof d === 'string' && d.indexOf('<') !== -1));
        },
        oneOf: function (d) {
            // At least one data point must contain a `<`
            return (!util.is.empty(d) &&
                typeof d === 'string' &&
                d.indexOf('<') !== -1);
        }
    },
    order: {
        pre: function (a) {
            return util.is.empty(a)
                ? ''
                : a.replace
                    ? util.stripHtml(a).trim().toLowerCase()
                    : a + '';
        }
    },
    search: _filterString(true)
});
register$1('html-utf8', {
    detect: {
        allOf: function (d) {
            return (util.is.empty(d) ||
                (typeof d === 'string' && d.indexOf('<') !== -1));
        },
        oneOf: function (d) {
            // At least one data point must contain a `<` and a non-ASCII character
            // eslint-disable-next-line compat/compat
            return (navigator.languages &&
                !util.is.empty(d) &&
                typeof d === 'string' &&
                d.indexOf('<') !== -1 &&
                typeof d === 'string' &&
                !!d.match(/[^\x00-\x7F]/));
        }
    },
    order: {
        asc: __diacriticHtmlSort,
        desc: function (a, b) {
            return __diacriticHtmlSort(a, b) * -1;
        }
    },
    search: _filterString(true)
});
register$1('date', {
    className: 'dt-type-date',
    detect: {
        allOf: function (d) {
            // V8 tries _very_ hard to make a string passed into `Date.parse()`
            // valid, so we need to use a regex to restrict date formats. Use a
            // plug-in for anything other than ISO8601 style strings
            if (d && !(d instanceof Date) && !util.regex.reDate.test(d)) {
                return null;
            }
            var parsed = Date.parse(d);
            return (parsed !== null && !isNaN(parsed)) || util.is.empty(d);
        },
        oneOf: function (d) {
            // At least one entry must be a date or a string with a date
            return (d instanceof Date ||
                (typeof d === 'string' && util.regex.reDate.test(d)));
        }
    },
    order: {
        pre: function (d) {
            var ts = Date.parse(d);
            return isNaN(ts) ? -Infinity : ts;
        }
    }
});
register$1('html-num-fmt', {
    className: 'dt-type-numeric',
    detect: {
        allOf: function (d, settings) {
            var decimal = settings.language.decimal;
            return util.is.htmlNum(d, decimal, true, false);
        },
        oneOf: function (d, settings) {
            // At least one data point must contain a numeric value
            var decimal = settings.language.decimal;
            return util.is.htmlNum(d, decimal, true, false);
        }
    },
    order: {
        pre: function (d, s) {
            var dp = s.language.decimal;
            return __numericReplace(d, dp, util.regex.reHtml, util.regex.reFormattedNumeric);
        }
    },
    search: _filterString(true)
});
register$1('html-num', {
    className: 'dt-type-numeric',
    detect: {
        allOf: function (d, settings) {
            var decimal = settings.language.decimal;
            return util.is.htmlNum(d, decimal, false, true);
        },
        oneOf: function (d, settings) {
            // At least one data point must contain a numeric value
            var decimal = settings.language.decimal;
            return util.is.htmlNum(d, decimal, false, false);
        }
    },
    order: {
        pre: function (d, s) {
            var dp = s.language.decimal;
            return __numericReplace(d, dp, util.regex.reHtml);
        }
    },
    search: _filterString(true)
});
register$1('num-fmt', {
    className: 'dt-type-numeric',
    detect: {
        allOf: function (d, settings) {
            var decimal = settings.language.decimal;
            return util.is.num(d, decimal, true, true);
        },
        oneOf: function (d, settings) {
            // At least one data point must contain a numeric value
            var decimal = settings.language.decimal;
            return util.is.num(d, decimal, true, false);
        }
    },
    order: {
        pre: function (d, s) {
            var dp = s.language.decimal;
            return __numericReplace(d, dp, util.regex.reFormattedNumeric);
        }
    }
});
register$1('num', {
    className: 'dt-type-numeric',
    detect: {
        allOf: function (d, settings) {
            var decimal = settings.language.decimal;
            return util.is.num(d, decimal, false, true);
        },
        oneOf: function (d, settings) {
            // At least one data point must contain a numeric value
            var decimal = settings.language.decimal;
            return util.is.num(d, decimal, false, false);
        }
    },
    order: {
        pre: function (d, s) {
            var dp = s.language.decimal;
            return __numericReplace(d, dp);
        }
    }
});

/**
 * DataTables extensions
 *
 * This namespace acts as a collection area for plug-ins that can be used to
 * extend DataTables capabilities. Indeed many of the build in methods
 * use this method to provide their own capabilities (sorting methods for
 * example).
 *
 * Note that this namespace is aliased to `jQuery.fn.dataTableExt` for legacy
 * reasons
 */
const ext = {
    /**
     * DataTables build type (expanded by the download builder)
     */
    builder: 'bs5/dt-3.0.3',
    /**
     * Buttons. For use with the Buttons extension for DataTables. This is
     * defined here so other extensions can define buttons regardless of load
     * order. It is _not_ used by DataTables core.
     */
    buttons: {},
    /**
     * ColumnControl buttons and content
     */
    ccContent: {},
    /**
     * Element class names
     */
    classes: classes$1,
    /**
     * Error reporting.
     *
     * How should DataTables report an error. Can take the value 'alert',
     * 'throw', 'none' or a function.
     */
    errMode: 'alert',
    /** HTML entity escaping */
    escape: {
        /** When reading data-* attributes for initialisation options */
        attributes: false
    },
    /**
     * Legacy so v1 plug-ins don't throw js errors on load
     */
    feature: legacy,
    /**
     * Feature plug-ins.
     *
     * This is an object of callbacks which provide the features for DataTables
     * to be initialised via the `layout` option.
     */
    features: features,
    /**
     * Row searching.
     *
     * This method of searching is complimentary to the default type based
     * searching, and a lot more comprehensive as it allows you complete control
     * over the searching logic. Each element in this array is a function
     * (parameters described below) that is called for every row in the table,
     * and your logic decides if it should be included in the searching data set
     * or not.
     */
    search: [],
    /**
     * Selector extensions
     *
     * The `selector` option can be used to extend the options available for the
     * selector modifier options (`selector-modifier` object data type) that
     * each of the three built in selector types offer (row, column and cell +
     * their plural counterparts). For example the Select extension uses this
     * mechanism to provide an option to select only rows, columns and cells
     * that have been marked as selected by the end user (`{selected: true}`),
     * which can be used in conjunction with the existing built in selector
     * options.
     */
    selector: {
        cell: [],
        column: [],
        row: []
    },
    settings: [],
    /**
     * Legacy configuration options. Enable and disable legacy options that
     * are available in DataTables.
     *
     *  @type object
     */
    legacy: {
        /**
         * Enable / disable DataTables 1.9 compatible server-side processing
         * requests
         */
        ajax: null
    },
    /**
     * Pagination plug-in methods.
     *
     * Each entry in this object is a function and defines which buttons should
     * be shown by the pagination rendering method that is used for the table.
     * The renderer addresses how the buttons are displayed in the document,
     * while the functions here tell it what buttons to display. This is done by
     * returning an array of button descriptions (what each button will do).
     */
    pager: pager,
    renderer: {
        footer: {
            _: footer
        },
        header: {
            _: header
        },
        layout: {
            _: layout
        },
        pagingButton: {
            _: pagingButton
        },
        pagingContainer: {
            _: pagingContainer
        }
    },
    /**
     * Rendering helper function exposed for use by the styling integrations.
     */
    rendererDisplayRowCells: displayRowCells,
    /**
     * Ordering plug-ins - custom data source
     *
     * The extension options for ordering of data available here is
     * complimentary to the default type based ordering that DataTables
     * typically uses. It allows much greater control over the data that is
     * being used to order a column, but is necessarily therefore more complex.
     */
    order: {},
    /**
     * Type based plug-ins.
     *
     * Each column in DataTables has a type assigned to it, either by automatic
     * detection or by direct assignment using the `type` option for the column.
     * The type of a column will effect how it is ordering and search (plug-ins
     * can also make use of the column type if required).
     */
    type: store,
    /**
     * Unique DataTables instance counter
     *
     * @type int
     * @private
     */
    _unique: 0,
    //
    // Depreciated
    // The following properties are retained for backwards compatibility only.
    // The should not be used in new projects and will be removed in a future
    // version
    //
    /**
     * Software version
     *  @type string
     */
    version: '3.0.3'
};
//
// Backwards compatibility. Alias to pre 1.10 Hungarian notation counter parts
//
Object.assign(ext, {
    afnFiltering: ext.search,
    aTypes: ext.type.detect,
    ofnSearch: ext.type.search,
    oSort: ext.type.order,
    afnSortData: ext.order,
    aoFeatures: ext.feature,
    oStdClasses: ext.classes,
    oPagination: ext.pager,
    sVersion: ext.version,
    fnVersionCheck: check$1
});

/**
 * Log an error message
 *
 * @param ctx DataTables settings object
 * @param level log error messages, or display them to the user
 * @param msg error message
 * @param tn Technical note id to get more information about the error.
 */
function log(ctx, level, msg, tn) {
    msg =
        'DataTables warning: ' +
            (ctx ? 'table id=' + ctx.tableId + ' - ' : '') +
            msg;
    if (tn) {
        msg +=
            '. For more information about this error, please see ' +
                'https://datatables.net/tn/' +
                tn;
    }
    {
        // Backwards compatibility pre 1.10
        var type = ext.sErrMode || ext.errMode;
        if (ctx) {
            callbackFire(ctx, null, 'dt-error', [ctx, tn, msg], true);
        }
        if (type == 'alert') {
            alert(msg);
        }
        else if (type == 'throw') {
            throw new Error(msg);
        }
        else if (typeof type == 'function') {
            type(ctx, tn, msg);
        }
    }
}
/**
 * See if a property is defined on one object, if so assign it to the other
 * object
 *
 * @param ret target object
 * @param src source object
 * @param name property
 * @param mappedName name to map too - optional, name used if not given
 */
function map(ret, src, name, mappedName) {
    if (Array.isArray(name)) {
        for (let i = 0; i < name.length; i++) {
            let val = name[i];
            if (Array.isArray(val)) {
                map(ret, src, val[0], val[1]);
            }
            else {
                map(ret, src, val);
            }
        }
        return;
    }
    if (mappedName === undefined) {
        mappedName = name;
    }
    if (src[name] !== undefined) {
        ret[mappedName] = src[name];
    }
}
/**
 * Bind an event handler to allow a click or return key to activate the callback.
 * This is good for accessibility since a return on the keyboard will have the
 * same effect as a click, if the element has focus.
 *
 * @param n Element to bind the action to
 * @param selector Selector (for delegated events)
 * @param fn Callback function for when the event is triggered
 */
function bindAction(n, selector, fn) {
    Dom.s(n)
        .on('click.DT', selector, function (e) {
        fn(e);
    })
        .on('keypress.DT', selector, function (e) {
        if (e.which === 13) {
            e.preventDefault();
            fn(e);
        }
    })
        .on('selectstart.DT', selector, function () {
        // Don't want a double click resulting in text selection
        return false;
    });
}
/**
 * Register a callback function. Easily allows a callback function to be added
 * to an array store of callback functions that can then all be called together.
 *
 * @param settings dataTables settings object
 * @param store Name of the array storage for the callbacks in settings
 * @param fn Function to be called back
 */
function callbackReg(ctx, store, fn) {
    if (fn) {
        ctx.callbacks[store].push(fn);
    }
}
/**
 * Fire callback functions and trigger events. Note that the loop over the
 * callback array store is done backwards! Further note that you do not want to
 * fire off triggers in time sensitive applications (for example cell creation)
 * as its slow.
 *
 * @param ctx DataTables settings object
 * @param callbackArr Name of the array storage for the callbacks in the context
 * @param eventName Name of the custom event to trigger. If null no trigger is
 *   fired
 * @param args Array of arguments to pass to the callback function / trigger
 * @param bubbles True if the event should bubble
 */
function callbackFire(ctx, callbackArr, eventName, args, bubbles = false) {
    var ret = [];
    if (callbackArr) {
        ret = ctx.callbacks[callbackArr]
            .slice()
            .reverse()
            .map(function (val) {
            return val.apply(ctx.instance, args);
        });
    }
    if (eventName !== null) {
        let table = Dom.s(ctx.table);
        let result = table.trigger(eventName + '.dt', bubbles, args, {
            dt: ctx.api
        });
        // If not yet attached to the document, trigger the event
        // on the body directly to sort of simulate the bubble
        if (bubbles && table.closest('body').count() === 0) {
            Dom.s('body').trigger(eventName + '.dt', bubbles, args, {
                dt: ctx.api
            });
        }
        ret.push(result[0]);
    }
    return ret;
}
function lengthOverflow(ctx) {
    var start = ctx.displayStart, end = displayEnd(ctx), len = ctx.pageLength;
    // If we have space to show extra rows (backing up from the end point - then
    // do so
    if (start >= end) {
        start = end - len;
    }
    // Keep the start record on the current page
    start -= start % len;
    if (len === -1 || start < 0) {
        start = 0;
    }
    ctx.displayStart = start;
}
/**
 * Detect the data source being used for the table. Used to simplify the code a
 * little (ajax) and to make it compress a little smaller.
 *
 * @param ctx DataTables settings object
 * @returns Data source
 */
function dataSource(ctx) {
    if (ctx.features.serverSide) {
        return 'ssp';
    }
    else if (ctx.ajax) {
        return 'ajax';
    }
    return 'dom';
}
/**
 * Common replacement for language strings
 *
 * @param ctx DataTables settings object
 * @param str String with values to replace
 * @param entries Plural number for _ENTRIES_ - can be undefined
 * @returns String
 */
function macros(ctx, str, entries) {
    // When infinite scrolling, we are always starting at 1. _iDisplayStart is
    // used only internally
    var formatter = ctx.formatNumber, start = ctx.displayStart + 1, len = ctx.pageLength, vis = recordsDisplay(ctx), max = recordsTotal(ctx), all = len === -1;
    return str
        .replace(/_START_/g, formatter(start, ctx))
        .replace(/_END_/g, formatter(displayEnd(ctx), ctx))
        .replace(/_MAX_/g, formatter(max, ctx))
        .replace(/_TOTAL_/g, formatter(vis, ctx))
        .replace(/_PAGE_/g, formatter(all ? 1 : Math.ceil(start / len), ctx))
        .replace(/_PAGES_/g, formatter(all ? 1 : Math.ceil(vis / len), ctx))
        .replace(/_ENTRIES_/g, ctx.api.i18n('entries', '', entries))
        .replace(/_ENTRIES-MAX_/g, ctx.api.i18n('entries', '', max))
        .replace(/_ENTRIES-TOTAL_/g, ctx.api.i18n('entries', '', vis));
}
/**
 * Add elements to an array as quickly as possible, but stack safe.
 *
 * @param arr Array to add the data to
 * @param data Data array that is to be added
 */
function arrayApply(arr, data) {
    if (!data) {
        return;
    }
    // Chrome can throw a max stack error if apply is called with
    // too large an array, but apply is faster.
    if (data.length < 10000) {
        arr.push.apply(arr, data);
    }
    else {
        for (var i = 0; i < data.length; i++) {
            arr.push(data[i]);
        }
    }
}
/**
 * Add one or more listeners to the table
 *
 * @param that JQ for the table
 * @param name Event name
 * @param src Listener(s)
 */
function listener(that, name, src) {
    let srcArr = Array.isArray(src) ? src : [src];
    for (var i = 0; i < srcArr.length; i++) {
        that.on(name + '.dt.DT', srcArr[i]);
    }
}
/**
 * Escape HTML entities in strings, in an object
 */
function escapeObject(obj) {
    if (ext.escape.attributes) {
        each(obj, function (key, val) {
            obj[key] = escapeHtml(val);
        });
    }
    return obj;
}

/*
 * Public helper functions. These aren't used internally by DataTables, or
 * called by any of the options passed into DataTables, but they can be used
 * externally by developers working with DataTables. They are helper functions
 * to make working with DataTables a little bit easier.
 */
/**
 * Common logic for moment, luxon or a date action.
 *
 * Happens after __mldObj, so don't need to call `resolveWindowsLibs` again
 */
function __mld(dtLib, momentFn, luxonFn, dateFn, arg1) {
    if (__moment) {
        return dtLib[momentFn](arg1);
    }
    else if (__luxon) {
        return dtLib[luxonFn](arg1);
    }
    return dateFn ? dtLib[dateFn](arg1) : dtLib;
}
var __mlWarning = false;
var __luxon;
var __moment;
/**
 *
 */
function resolveWindowLibs() {
    __luxon = util.external('luxon');
    __moment = util.external('moment');
}
function __mldObj(d, format, locale) {
    var dt;
    resolveWindowLibs();
    if (__moment) {
        dt = __moment(d, format, locale, true);
        if (!dt.isValid()) {
            return null;
        }
    }
    else if (__luxon) {
        dt =
            format && typeof d === 'string'
                ? __luxon.DateTime.fromFormat(d, format)
                : __luxon.DateTime.fromISO(d);
        if (!dt.isValid) {
            return null;
        }
        dt = dt.setLocale(locale);
    }
    else if (!format) {
        // No format given, must be ISO
        dt = new Date(d);
    }
    else {
        if (!__mlWarning) {
            alert('DataTables warning: Formatted date without Moment.js or Luxon - https://datatables.net/tn/17');
        }
        __mlWarning = true;
    }
    return dt;
}
// Wrapper for date, datetime and time which all operate the same way with the
// exception of the output string for auto locale support
function __mlHelper(localeString) {
    return function (from, to, locale, def) {
        // Luxon and Moment support
        // Argument shifting
        if (arguments.length === 0) {
            locale = 'en';
            to = null; // means toLocaleString
            from = null; // means iso8601
        }
        else if (arguments.length === 1) {
            locale = 'en';
            to = from;
            from = null;
        }
        else if (arguments.length === 2) {
            locale = to;
            to = from;
            from = null;
        }
        var typeName = 'datetime' + (to ? '-' + to : '');
        // Add type detection and sorting specific to this date format - we need
        // to be able to identify date type columns as such, rather than as
        // numbers in extensions. Hence the need for this.
        if (!store.order[typeName + '-pre']) {
            register$1(typeName, {
                detect: function (d) {
                    // The renderer will give the value to type detect as the
                    // type!
                    return d === typeName ? typeName : false;
                },
                order: {
                    pre: function (d) {
                        // The renderer gives us Moment, Luxon or Date objects
                        // for the sorting, all of which have a `valueOf` which
                        // gives milliseconds epoch
                        return d.valueOf();
                    }
                }
            });
        }
        if (!store.className[typeName]) {
            store.className[typeName] = 'dt-right';
        }
        return function (d, type) {
            // Allow for a default value
            if (d === null || d === undefined) {
                if (def === '--now') {
                    // We treat everything as UTC further down, so no changes
                    // are made, as such need to get the local date / time as if
                    // it were UTC
                    var local = new Date();
                    d = new Date(Date.UTC(local.getFullYear(), local.getMonth(), local.getDate(), local.getHours(), local.getMinutes(), local.getSeconds()));
                }
                else {
                    d = '';
                }
            }
            if (type === 'type') {
                // Typing uses the type name for fast matching
                return typeName;
            }
            if (d === '') {
                return type !== 'sort'
                    ? ''
                    : __mldObj('0000-01-01 00:00:00', null, locale);
            }
            // Shortcut. If `from` and `to` are the same, we are using the
            // renderer to format for ordering, not display - its already in the
            // display format.
            if (to !== null &&
                from === to &&
                type !== 'sort' &&
                type !== 'type' &&
                !(d instanceof Date)) {
                return d;
            }
            // Determine if there is a timezone. If there is, we want to reuse
            // it for the output, so the timezone doesn't change between the
            // input and output.
            let options = {};
            let tzMatch = typeof d === 'string' ? d.match(util.regex.isoTimezone) : null;
            if (tzMatch) {
                options.timeZone = tzMatch[1] === 'Z' ? 'UTC' : tzMatch[1];
            }
            // Get a Date object (Luxon, moment or Date)
            var dt = __mldObj(d, from, locale);
            if (dt === null) {
                return d;
            }
            if (type === 'sort') {
                return dt;
            }
            var formatted = to === null
                ? __mld(dt, 'toDate', 'toJSDate', '')[localeString](navigator.language, options)
                : __mld(dt, 'format', 'toFormat', 'toISOString', to);
            // XSS protection
            return type === 'display' ? util.escapeHtml(formatted) : formatted;
        };
    };
}
// Based on locale, determine standard number formatting
// Fallback for legacy browsers is US English
var __thousands = ',';
var __decimal = '.';
if (window.Intl !== undefined) {
    try {
        var num = new Intl.NumberFormat().formatToParts(100000.1);
        for (var i = 0; i < num.length; i++) {
            if (num[i].type === 'group') {
                __thousands = num[i].value;
            }
            else if (num[i].type === 'decimal') {
                __decimal = num[i].value;
            }
        }
    }
    catch (e) {
        // noop
    }
}
/**
 * Register a date / time format for DataTables to use.
 *
 * @param format The date / time format to detect data in. Please refer to the
 *   Moment.js or Luxon document for the full list of tokens, depending on which
 *   of the two libraries you are using.
 * @param locale The locale to pass to Moment.js / Luxon.
 */
function datetime(format, locale) {
    var typeName = 'datetime-' + format;
    if (!locale) {
        locale = 'en';
    }
    if (!store.order[typeName]) {
        register$1(typeName, {
            detect: function (d) {
                var dt = __mldObj(d, format, locale);
                return d === '' || dt ? typeName : false;
            },
            order: {
                pre: function (d) {
                    return __mldObj(d, format, locale) || 0;
                }
            }
        });
    }
    if (!store.className[typeName]) {
        store.className[typeName] = 'dt-right';
    }
}
/**
 * Helpers for `columns.render`.
 */
var helpers = {
    date: __mlHelper('toLocaleDateString'),
    datetime: __mlHelper('toLocaleString'),
    time: __mlHelper('toLocaleTimeString'),
    number: function (thousands, decimal, precision, prefix, postfix) {
        // Auto locale detection
        if (thousands === null || thousands === undefined) {
            thousands = __thousands;
        }
        if (decimal === null || decimal === undefined) {
            decimal = __decimal;
        }
        return {
            display: function (d) {
                if (typeof d !== 'number' && typeof d !== 'string') {
                    return d;
                }
                if (d === '' || d === null) {
                    return d;
                }
                var flo = typeof d === 'number' ? d : parseFloat(d);
                var negative = flo < 0 ? '-' : '';
                var abs = Math.abs(flo);
                // Scientific notation for large and small numbers
                if (abs >= 100000000000 || (abs < 0.0001 && abs !== 0)) {
                    var exp = flo.toExponential(precision).split(/e\+?/);
                    return exp[0] + ' x 10<sup>' + exp[1] + '</sup>';
                }
                // If NaN then there isn't much formatting that we can do - just
                // return immediately, escaping any HTML (this was supposed to
                // be a number after all)
                if (isNaN(flo)) {
                    return util.escapeHtml(d);
                }
                flo = flo.toFixed(precision);
                var absPart = Math.abs(flo);
                var intPart = Math.abs(parseInt(flo, 10));
                var floatPart = precision
                    ? decimal +
                        (absPart - intPart).toFixed(precision).substring(2)
                    : '';
                // If zero, then can't have a negative prefix
                if (intPart === 0 && parseFloat(floatPart) === 0) {
                    negative = '';
                }
                return (negative +
                    (prefix || '') +
                    intPart
                        .toString()
                        .replace(/\B(?=(\d{3})+(?!\d))/g, thousands) +
                    floatPart +
                    (postfix || ''));
            }
        };
    },
    text: function () {
        return {
            display: util.escapeHtml,
            filter: util.escapeHtml
        };
    }
};

/**
 * Column options that can be given to DataTables at initialisation time.
 */
const defaults$4 = {
    ariaTitle: '',
    cellType: 'td',
    className: '',
    contentPadding: '',
    createdCell: null,
    data: null,
    defaultContent: null,
    footer: null,
    name: '',
    orderable: true,
    orderData: null,
    orderDataType: 'std',
    orderSequence: ['asc', 'desc', ''],
    render: null,
    search: null,
    searchable: true,
    title: null,
    type: null,
    visible: true,
    width: null
};

/**
 * Internal settings object used for individual columns. Instances are held in
 * the setting object's `columns` array and contains all the information that
 * DataTables needs about each individual column.
 *
 * Note that this object is related to the column defaults but this one is the
 * internal data store for DataTables's cache of columns. It should NOT be
 * manipulated outside of DataTables. Any configuration should be done through
 * the initialisation options.
 */
class Settings {
    constructor() {
        /**
         * Flag to indicate if HTML5 data attributes should be used as the data
         * source for filtering or sorting. True is either are.
         */
        this.attrSrc = false;
        this.ariaTitle = '';
        /**
         * The class to apply to all cells in the table's `tbody`` for the column
         */
        this.className = null;
        /**
         * When DataTables calculates the column widths to assign to each column, it
         * finds the longest string in each column and then constructs a temporary
         * table and reads the widths from that. The problem with this is that "mmm"
         * is much wider then "iiii", but the latter is a longer string - thus the
         * calculation can go wrong (doing it properly and putting it into an DOM
         * object and measuring that is horribly(!) slow). Thus as a "work around"
         * we provide this option. It will append its value to the text that is
         * found to be the longest string for the column - i.e. padding.
         */
        this.contentPadding = null;
        /**
         * Property to read the value for the cells in the column from the data
         * source array / object. If null, then the default content is used, if a
         * function is given then the return from the function is used.
         */
        this.data = null;
        /**
         * Allows a default value to be given for a column's data, and will be used
         * whenever a null data source is encountered (this can be because mData is
         * set to null, or because the data source itself is null).
         */
        this.defaultContent = null;
        /**
         * Name for the column, allowing reference to the column by name as well as
         * by index (needs a lookup to work by name).
         */
        this.name = null;
        /**
         * A list of the columns that sorting should occur on when this column is
         * sorted. That this property is an array allows multi-column sorting to be
         * defined for a column (for example first name / last name columns would
         * benefit from this). The values are integers pointing to the columns to be
         * sorted on (typically it will be a single integer pointing at itself, but
         * that doesn't need to be the case).
         */
        this.orderData = [];
        /**
         * Custom sorting data type - defines which of the available plug-ins in
         * afnSortData the custom sorting will use - if any is defined.
         */
        this.orderDataType = 'std';
        /**
         * Class to be applied to the header element when sorting on this column
         */
        this.orderingClass = null;
        /**
         * Define the sorting directions that are applied to the column, in sequence
         * as the column is repeatedly sorted upon - i.e. the first value is used as
         * the sorting direction when the column if first sorted (clicked on). Sort
         * it again (click again) and it will move on to the next index. Repeat
         * until loop.
         */
        this.orderSequence = [];
        /**
         * Partner property to mData which is used (only when defined) to get the
         * data - i.e. it is basically the same as mData, but without the 'set'
         * option, and also the data fed to it is the result from mData. This is the
         * rendering method to match the data method of mData.
         */
        this.render = null;
        /**
         * Title of the column - what is seen in the TH element (nTh).
         */
        this.title = null;
        /**
         * Store for manual type assignment using the `column.type` option. This
         * is held in store so we can manipulate the column's `type` property.
         */
        this.typeManual = null;
        /** Cached longest strings from a column */
        this.wideStrings = null;
        /**
         * Width of the column
         */
        this.width = null;
        /**
         * Width of the column when it was first "encountered"
         */
        this.widthOrig = null;
    }
}

const defaults$3 = {
    boundary: false,
    caseInsensitive: true,
    columns: null,
    exact: false,
    regex: false,
    return: false,
    search: '',
    smart: true
};
/**
 * Create a new search options object
 *
 * @param parts Values to assign, otherwise the defaults will be used
 * @returns New object
 */
function create$2(parts = {}) {
    return util.object.assignDeep({}, defaults$3, parts);
}

const browser = {
    barWidth: -1,
    scrollbarLeft: false
};
const hungarianToCamelRe = /^(a|aa|ai|ao|as|b|fn|i|m|o|s)([A-Z])([a-z].*$)/;
/**
 * Take an object which has hungarian notation parameters and convert them to
 * camelCase style. This is to allow compatibility with DataTables 1.9 and
 * earlier which only used hungarian notation, and also with DataTables 1.10 - 2
 * which allowed it to be used.
 */
function hungarianToCamel(user) {
    if (!user) {
        return user;
    }
    let userKeys = Object.keys(user);
    let userAny = user;
    for (let i = 0; i < userKeys.length; i++) {
        let userKey = userKeys[i];
        let match = userKey.match(hungarianToCamelRe);
        // Is the key in hungarian notation?
        if (match) {
            // If so map it down
            user[match[2].toLowerCase() + match[3]] = userAny[userKey];
        }
        // Recurse down through the object
        if (util.is.plainObject(userAny[userKey])) {
            hungarianToCamel(userAny[userKey]);
        }
    }
    return user;
}
/**
 * Map one parameter onto another
 *
 * @param o Object to map
 * @param newKey The new parameter name
 * @param oldKey The old parameter name
 */
function compatMap(o, newKey, oldKey) {
    if (o[oldKey] !== undefined) {
        o[newKey] = o[oldKey];
    }
}
/**
 * Provide backwards compatibility for the main DT options. Note that the new
 * options are mapped onto the old parameters, so this is an external interface
 * change only.
 *
 * @param init Object to map
 */
function compatOpts(init) {
    // Convert any old style parameters to camelCase
    hungarianToCamel(init);
    // Map old parameter names to new
    compatMap(init, 'ordering', 'sort');
    compatMap(init, 'orderMulti', 'sortMulti');
    compatMap(init, 'orderClasses', 'sortClasses');
    compatMap(init, 'orderCellsTop', 'sortCellsTop');
    compatMap(init, 'order', 'sorting');
    compatMap(init, 'orderFixed', 'sortingFixed');
    compatMap(init, 'paging', 'paginate');
    compatMap(init, 'pagingType', 'paginationType');
    compatMap(init, 'pageLength', 'displayLength');
    compatMap(init, 'searching', 'filter');
    compatMap(init, 'stateDuration', 'cookieDuration');
    // Boolean initialisation of x-scrolling
    if (typeof init.scrollX === 'boolean') {
        init.scrollX = init.scrollX ? '100%' : '';
    }
    // Objects for ordering
    if (typeof init.ordering === 'object') {
        init.orderIndicators =
            init.ordering.indicators !== undefined
                ? init.ordering.indicators
                : true;
        init.orderHandler =
            init.ordering.handler !== undefined ? init.ordering.handler : true;
        init.ordering = true;
    }
    else if (init.ordering === false) {
        init.orderIndicators = false;
        init.orderHandler = false;
    }
    else if (init.ordering === true) {
        init.orderIndicators = true;
        init.orderHandler = true;
    }
    // Which cells are the title cells?
    if (typeof init.orderCellsTop === 'boolean') {
        init.titleRow = init.orderCellsTop;
    }
    // Column search objects are in an array, so it needs to be converted
    // element by element
    var searchCols = init.searchCols;
    if (searchCols) {
        for (var i = 0, iLen = searchCols.length; i < iLen; i++) {
            if (searchCols[i]) {
                hungarianToCamel(searchCols[i]);
            }
        }
    }
    // Enable search delay if server-side processing is enabled
    if (init.serverSide && !init.searchDelay) {
        init.searchDelay = 400;
    }
    // Language
    if (init.language && init.language.url && !init.language.ajax) {
        init.language.ajax = init.language.url;
    }
}
/**
 * Provide backwards compatibility for column options. Note that the new options
 * are mapped onto the old parameters, so this is an external interface change
 * only.
 *
 * @param init Object to map
 */
function compatCols(init) {
    // Convert any old style parameters to camelCase
    hungarianToCamel(init);
    // typeof columnDefaults
    compatMap(init, 'orderable', 'sortable');
    compatMap(init, 'orderData', 'dataSort');
    compatMap(init, 'orderSequence', 'sorting');
    compatMap(init, 'orderDataType', 'sortDataType');
    compatMap(init, 'className', 'class');
    // orderData can be given as an integer
    var dataSort = init.aDataSort;
    var orderData = init.orderData;
    if (typeof dataSort === 'number') {
        init.orderData = [dataSort];
    }
    if (typeof orderData === 'number') {
        init.orderData = [orderData];
    }
    // Backwards compatibility for mDataProp from 1.9-
    if (init.dataProp !== undefined && !init.data) {
        init.data = init.dataProp;
    }
}
/**
 * Browser feature detection for capabilities, quirks
 *
 * @param ctx DataTables settings object
 */
function browserDetect(ctx) {
    // We don't need to do this every time DataTables is constructed, the values
    // calculated are specific to the browser and OS configuration which we
    // don't expect to change between initialisations
    if (browser.barWidth === -1) {
        // Scrolling feature / quirks detection
        var n = Dom
            .c('div')
            .css({
            position: 'fixed',
            top: '0',
            left: -1 * window.pageXOffset + 'px', // allow for scrolling
            height: '1px',
            width: '1px',
            overflow: 'hidden'
        })
            .append(Dom
            .c('div')
            .css({
            position: 'absolute',
            top: '1px',
            left: '1px',
            width: '100px',
            overflow: 'scroll'
        })
            .append(Dom.c('div').css({
            width: '100%',
            height: '10px'
        })))
            .appendTo('body');
        var outer = n.children();
        var inner = outer.children();
        browser.barWidth = outer.get(0).offsetWidth - outer.get(0).clientWidth;
        browser.scrollbarLeft = Math.round(inner.offset().left) !== 1;
        n.remove();
    }
    Object.assign(ctx.browser, browser);
    ctx.scroll.barWidth = browser.barWidth;
}

const defaults$2 = {
    addedClasses: [],
    cells: [],
    data: [],
    details: undefined,
    detailsShow: undefined,
    displayData: null,
    idx: -1,
    orderCache: null,
    searchCellCache: null,
    searchRowCache: null,
    src: 'dom',
    tr: null
};
/**
 * Create a new object that is a row model
 *
 * @param parts Values to assign, otherwise the defaults will be used
 * @returns New object
 */
function create$1(parts = {}) {
    return util.object.assignDeep({}, defaults$2, parts);
}

/**
 * Add a data array to the table, creating DOM node etc. This is the parallel to
 * gatherData, but for adding rows from a JavaScript source, rather than a
 * DOM source.
 *
 * @param settings DataTables settings object
 * @param dataIn data array to be added
 * @param tr TR element to add to the table - optional. If not given, DataTables
 *   will create a row automatically
 * @param tds Array of TD|TH elements for the row - must be given if tr is.
 * @returns >=0 if successful (index of new data entry), -1 if failed
 */
function addData(settings, dataIn, tr, tds) {
    /* Create the object for storing information about this new row */
    var rowIdx = settings.data.length;
    var row = create$1({
        src: tr ? 'dom' : 'data',
        idx: rowIdx
    });
    row.data = dataIn;
    settings.data.push(row);
    var columns = settings.columns;
    for (var i = 0, iLen = columns.length; i < iLen; i++) {
        // Invalidate the column types as the new data needs to be revalidated
        columns[i].type = null;
    }
    /* Add to the display array */
    settings.displayMaster.push(rowIdx);
    var id = settings.rowIdFn(dataIn);
    if (id !== undefined) {
        settings.ids[id] = row;
    }
    /* Create the DOM information, or register it if already present */
    if (tr || !settings.features.deferRender) {
        createTr(settings, rowIdx, tr, tds);
    }
    return rowIdx;
}
/**
 * Add one or more TR elements to the table. Generally we'd expect to
 * use this for reading data from a DOM sourced table, but it could be
 * used for an TR element. Note that if a TR is given, it is used (i.e.
 * it is not cloned).
 *
 * @param settings DataTables settings object
 * @param rows The TR element(s) to add to the table
 * @returns Array of indexes for the added rows
 */
function addTr(settings, rows) {
    return rows.mapTo(el => {
        let row = getRowElementsFromNode(settings, el);
        return addData(settings, row.data, el, row.cells);
    });
}
/**
 * Get the data for a given cell from the internal cache, taking into account
 * data mapping
 *
 * @param settings DataTables settings object
 * @param rowIdx data row id
 * @param colIdx Column index
 * @param type data get type ('display', 'type' 'filter|search' 'sort|order')
 * @returns Cell data
 */
function getCellData(settings, rowIdx, colIdx, type) {
    if (type === 'search') {
        type = 'filter';
    }
    else if (type === 'order') {
        type = 'sort';
    }
    var row = settings.data[rowIdx];
    if (!row) {
        return undefined;
    }
    var draw = settings.drawCount;
    var col = settings.columns[colIdx];
    var rowData = row.data;
    var defaultContent = col.defaultContent;
    var cellData = col.dataGet(rowData, type, {
        settings: settings,
        row: rowIdx,
        col: colIdx
    });
    // Allow for a node being returned for non-display types
    if (type !== 'display' &&
        cellData &&
        typeof cellData === 'object' &&
        cellData.nodeName) {
        cellData = cellData.innerHTML;
    }
    if (cellData === undefined) {
        if (settings.drawError != draw && defaultContent === null) {
            log(settings, 0, 'Requested unknown parameter ' +
                (typeof col.data == 'function'
                    ? '{function}'
                    : "'" + col.data + "'") +
                ' for row ' +
                rowIdx +
                ', column ' +
                colIdx, 4);
            settings.drawError = draw;
        }
        return defaultContent;
    }
    // When the data source is null and a specific data type is requested (i.e.
    // not the original data), we can use default column data
    if ((cellData === rowData || cellData === null) &&
        defaultContent !== null &&
        type !== undefined) {
        cellData = defaultContent;
    }
    else if (typeof cellData === 'function') {
        // If the data source is a function, then we run it and use the return,
        // executing in the scope of the data object (for instances)
        return cellData.call(rowData);
    }
    if (cellData === null && type === 'display') {
        return '';
    }
    if (type === 'filter') {
        var formatters = ext.type.search;
        if (col.type && formatters[col.type]) {
            cellData = formatters[col.type](cellData);
        }
    }
    return cellData;
}
/**
 * Set the value for a specific cell, into the internal data cache
 *
 * @param settings DataTables settings object
 * @param rowIdx data row id
 * @param colIdx Column index
 * @param val Value to set
 */
function setCellData(settings, rowIdx, colIdx, val) {
    let row = settings.data[rowIdx];
    if (row) {
        let col = settings.columns[colIdx];
        let rowData = row.data;
        col.dataSet(rowData, val, {
            settings: settings,
            row: rowIdx,
            col: colIdx
        });
    }
}
/**
 * Write a value to a cell
 *
 * @param td Cell
 * @param val Value
 */
function writeCell(td, val) {
    let cell = Dom.s(td);
    if (val && typeof val === 'object' && val.nodeName) {
        cell.empty().append(val);
    }
    else {
        cell.html(val);
    }
}
/**
 * Return an array with the full table data
 *
 * @param settings DataTables settings object
 * @returns array {array} aData Master data array
 */
function getDataMaster(settings) {
    return util.array.pluck(settings.data, 'data');
}
/**
 * Nuke the table
 *
 * @param settings DataTables settings object
 */
function clearTable(settings) {
    settings.data.length = 0;
    settings.displayMaster.length = 0;
    settings.display.length = 0;
    settings.ids = {};
}
/**
 * Mark cached data as invalid such that a re-read of the data will occur when
 * the cached data is next requested. Also update from the data source object.
 *
 * @param settings DataTables settings object
 * @param rowIdx Row index to invalidate
 * @param src Source to invalidate from: undefined, 'auto', 'dom' or 'data'
 * @param colIdx Column index to invalidate. If undefined the whole row will be
 *    invalidated
 */
function invalidateRow(settings, rowIdx, src, colIdx) {
    var row = settings.data[rowIdx];
    var i, iLen;
    if (!row) {
        return;
    }
    // Remove the cached data for the row
    row.orderCache = null;
    row.searchCellCache = null;
    row.displayData = null;
    // Are we reading last data from DOM or the data object?
    if (src === 'dom' || ((!src || src === 'auto') && row.src === 'dom')) {
        // Read the data from the DOM
        row.data = getRowElementsFromModel(settings, row, colIdx).data;
    }
    else {
        // Reading from data object, update the DOM
        var cells = row.cells;
        var display = getRowDisplay(settings, rowIdx);
        if (cells.length) {
            if (colIdx !== undefined) {
                writeCell(cells[colIdx], display[colIdx]);
            }
            else {
                for (i = 0, iLen = cells.length; i < iLen; i++) {
                    writeCell(cells[i], display[i]);
                }
            }
        }
    }
    invalidColumn(settings, colIdx);
    // Update DataTables special `DT_*` attributes for the row
    rowAttributes(settings, row);
    callbackFire(settings, null, 'rowInvalidate', [settings, rowIdx, colIdx], false);
}
/**
 * Column specific invalidation
 *
 * @param settings DataTables settings object
 * @param colIdx Column index to invalidate, or all columns if not given
 */
function invalidColumn(settings, colIdx) {
    // Column specific invalidation
    var cols = settings.columns;
    if (colIdx !== undefined) {
        // Type - the data might have changed
        cols[colIdx].type = null;
        // Max length string. Its a fairly cheep recalculation, so not worth
        // something more complicated
        cols[colIdx].wideStrings = null;
    }
    else {
        for (let i = 0, iLen = cols.length; i < iLen; i++) {
            cols[i].type = null;
            cols[i].wideStrings = null;
        }
    }
    settings.containerWidth = -1;
}
/**
 * Get the cells and data for a given row - from a <tr> element
 *
 * @param settings DataTables settings object
 * @param row TR element from which to read data or existing row object from
 *   which to re-read the data from the cells
 */
function getRowElementsFromNode(settings, row) {
    let data = settings.rowReadObject ? {} : [];
    let cells = Dom.s(row).children('th, td');
    let id = row.getAttribute('id');
    cells.each((el, idx) => {
        readCellData(settings, el, data, idx);
    });
    if (id) {
        util.set(settings.rowId)(data, id);
    }
    return {
        data: data,
        cells: cells.get()
    };
}
/**
 * Get the cells and data for a given row - from an existing row model
 *
 * @param settings DataTables settings object
 * @param row Existing row object from which to re-read the data from the cells
 * @param colIdx Optional column index
 */
function getRowElementsFromModel(settings, row, colIdx) {
    let tds = row.cells;
    for (let i = 0; i < tds.length; i++) {
        if (colIdx === undefined || colIdx === i) {
            readCellData(settings, tds[i], row.data, i);
        }
    }
    // Read the ID from the DOM if present
    if (row.tr) {
        let id = row.tr.getAttribute('id');
        if (id) {
            util.set(settings.rowId)(row.data, id);
        }
    }
    return {
        data: row.data,
        cells: tds
    };
}
/**
 * Read data from a cell into the data source object
 *
 * @param settings DataTables settings object
 * @param cell The HTML cell element to read from
 * @param data Data object / array to store data into
 * @param colIdx The column index for the cell
 */
function readCellData(settings, cell, data, colIdx) {
    let column = settings.columns[colIdx];
    let contents = cell.innerHTML.trim();
    if (column.attrSrc) {
        // If we are working with attributes from the cell as values
        let dataPoint = column.data;
        let setter = util.set(dataPoint._);
        let attr = function (str, cell) {
            if (typeof str === 'string') {
                let idx = str.indexOf('@');
                if (idx !== -1) {
                    let att = str.substring(idx + 1);
                    let setter = util.set(str);
                    setter(data, cell.getAttribute(att));
                }
            }
        };
        setter(data, contents);
        attr(dataPoint.sort, cell);
        attr(dataPoint.type, cell);
        attr(dataPoint.filter, cell);
    }
    else {
        if (!column.setter) {
            // Cache the setter function
            column.setter = util.set(column.data);
        }
        column.setter(data, contents);
    }
}

/**
 * Recalculate the column widths, if needed (by a column having been
 * invalidated)
 *
 * @param settings DataTables settings object
 */
function columnWidths(settings) {
    if (settings.columns.map(c => c.wideStrings).includes(null)) {
        calculateColumnWidths(settings);
    }
}
/**
 * Calculate the width of columns for the table
 *
 * @param settings DataTables settings object
 */
function calculateColumnWidths(settings) {
    // Not interested in doing column width calculation if auto-width is disabled
    if (!settings.features.autoWidth) {
        return;
    }
    var table = settings.table, columns = settings.columns, scroll = settings.scroll, scrollY = scroll.y, scrollX = scroll.x, visibleColumns = getColumns(settings, 'visible'), tableWidthAttr = table.getAttribute('width'), // from DOM element
    tableContainer = table.parentElement, i, j, column, columnIdx;
    var styleWidth = table.style.width;
    var containerWidth = wrapperWidth(settings);
    // Don't re-run for the same width as the last time
    if (containerWidth === settings.containerWidth) {
        return false;
    }
    settings.containerWidth = containerWidth;
    // If there is no width applied as a CSS style or as an attribute, we assume that
    // the width is intended to be 100%, which is usually is in CSS, but it is very
    // difficult to correctly parse the rules to get the final result.
    if (!styleWidth && !tableWidthAttr) {
        table.style.width = '100%';
        styleWidth = '100%';
    }
    if (styleWidth && styleWidth.indexOf('%') !== -1) {
        tableWidthAttr = styleWidth;
    }
    // Let plug-ins know that we are doing a recalc, in case they have changed any of the
    // visible columns their own way (e.g. Responsive uses display:none).
    callbackFire(settings, null, 'column-calc', [{ visible: visibleColumns }], false);
    // Construct a worst case table with the widest, assign any user defined
    // widths, then insert it into  the DOM and allow the browser to do all
    // the hard work of calculating table widths
    var tmpTable = Dom
        .s(table.cloneNode())
        .css('visibility', 'hidden')
        .css('margin', '0')
        .attrRemove('id');
    // Clean up the table body
    tmpTable.append(Dom.c('tbody'));
    // Clone the table header and footer - we can't use the header / footer
    // from the cloned table, since if scrolling is active, the table's
    // real header and footer are contained in different table tags
    tmpTable
        .append(settings.thead.cloneNode(true))
        .append(settings.tfoot.cloneNode(true));
    // Remove any assigned widths from the footer (from scrolling)
    tmpTable.find('tfoot th, tfoot td').css('width', '');
    // Apply custom sizing to the cloned header
    tmpTable.find('thead th, thead td').each(cell => {
        // Get the `width` from the header layout
        var width = columnsSumWidth(settings, cell, true);
        if (width) {
            cell.style.width = width;
            // For scrollX we need to force the column width otherwise the
            // browser will collapse it. If this width is smaller than the
            // width the column requires, then it will have no effect
            if (scrollX) {
                cell.style.minWidth = width;
                Dom.s(cell).append(Dom.c('div').css({
                    width: width,
                    margin: '0',
                    padding: '0',
                    border: '0',
                    height: '1px'
                }));
            }
        }
        else {
            cell.style.width = '';
        }
    });
    // Get the widest strings for each of the visible columns and add them to
    // our table to create a "worst case"
    var longestData = [];
    for (i = 0; i < visibleColumns.length; i++) {
        longestData.push(getWideStrings(settings, visibleColumns[i]));
    }
    if (longestData.length) {
        for (i = 0; i < longestData[0].length; i++) {
            var tr = Dom.c('tr').appendTo(tmpTable.find('tbody'));
            for (j = 0; j < visibleColumns.length; j++) {
                columnIdx = visibleColumns[j];
                column = columns[columnIdx];
                var longest = longestData[j][i] || '';
                var autoClass = ext.type.className[column.type];
                var padding = column.contentPadding || (scrollX ? '-' : '');
                var text = longest + padding;
                var cell = Dom
                    .c('td')
                    .classAdd(autoClass)
                    .classAdd(column.className)
                    .appendTo(tr);
                if (longest.indexOf('<') === -1 &&
                    longest.indexOf('&') === -1) {
                    cell.text(text);
                }
                else {
                    cell.html(text);
                }
            }
        }
    }
    // Tidy the temporary table - remove name attributes so there aren't
    // duplicated in the dom (radio elements for example)
    tmpTable.find('[name]').attrRemove('name');
    // Table has been built, attach to the document so we can work with it.
    // A holding element is used, positioned at the top of the container
    // with minimal height, so it has no effect on if the container scrolls
    // or not. Otherwise it might trigger scrolling when it actually isn't
    // needed
    var holder = Dom
        .c('div')
        .css(scrollX || scrollY
        ? {
            position: 'absolute',
            top: '0',
            left: '0',
            height: '1px',
            right: '0',
            overflow: 'hidden'
        }
        : {})
        .append(tmpTable)
        .appendTo(tableContainer);
    // When scrolling (X or Y) we want to set the width of the table as
    // appropriate. However, when not scrolling leave the table width as it
    // is. This results in slightly different, but I think correct behaviour
    if (scrollX) {
        tmpTable.css('width', 'auto').attrRemove('width');
        // If there is no width attribute or style, then allow the table to
        // collapse
        if (tmpTable.width() < tableContainer.clientWidth && tableWidthAttr) {
            tmpTable.width(tableContainer.clientWidth);
        }
    }
    else if (scrollY) {
        tmpTable.width(tableContainer.clientWidth);
    }
    else if (tableWidthAttr) {
        tmpTable.width(tableWidthAttr);
    }
    // Get the width of each column in the constructed table
    var total = 0;
    var bodyCells = tmpTable.find('tbody tr').eq(0).children();
    for (i = 0; i < visibleColumns.length; i++) {
        // Use getBounding for sub-pixel accuracy, which we then want to round
        // up!
        var bounding = bodyCells.get(i).getBoundingClientRect().width;
        // Total is tracked to remove any sub-pixel errors as the outerWidth
        // of the table might not equal the total given here
        total += bounding;
        // Width for each column to use
        columns[visibleColumns[i]].width = stringToCss(bounding);
    }
    table.style.width = stringToCss(total);
    // Finished with the table - ditch it
    holder.remove();
    // If there is a width attr, we want to attach an event listener which
    // allows the table sizing to automatically adjust when the window is
    // resized. Use the width attr rather than CSS, since we can't know if the
    // CSS is a relative value or absolute - DOM read is always px.
    if (tableWidthAttr) {
        table.style.width = stringToCss(tableWidthAttr);
    }
    if ((tableWidthAttr || scrollX) && !settings.reszEvt) {
        var resize = util.throttle(function () {
            var newWidth = wrapperWidth(settings);
            // Don't do it if destroying or the container width is 0
            if (!settings.destroying && newWidth !== 0) {
                adjustColumnSizing(settings);
            }
        });
        // For browsers that support it (~2020 onwards for wide support) we can watch for the
        // container changing width.
        if (window.ResizeObserver) {
            // This is a tricky beast - if the element is visible when `.observe()` is called,
            // then the callback is immediately run. Which we don't want. If the element isn't
            // visible, then it isn't run, but we want it to run when it is then made visible.
            // This flag allows the above to be satisfied.
            var first = Dom.s(settings.tableWrapper).isVisible();
            // Use an empty div to attach the observer so it isn't impacted by height changes
            var resizer = Dom
                .c('div')
                .css({
                width: '100%',
                height: '0'
            })
                .classAdd('dt-autosize')
                .appendTo(settings.tableWrapper);
            settings.resizeObserver = new ResizeObserver(function (e) {
                if (first) {
                    first = false;
                }
                else {
                    resize();
                }
            });
            settings.resizeObserver.observe(resizer.get(0));
        }
        else {
            // For old browsers, the best we can do is listen for a window
            // resize
            window.addEventListener('resize', resize);
            settings.windowResizeCb = resize; // For removal in `destroy`
        }
        settings.reszEvt = true;
    }
}
/**
 * Get the width of the DataTables wrapper element
 *
 * @param settings DataTables settings object
 * @returns Width
 */
function wrapperWidth(settings) {
    let wrapper = Dom.s(settings.tableWrapper);
    return wrapper.isVisible() ? wrapper.width() : 0;
}
/**
 * Get the widest strings for each column.
 *
 * It is very difficult to determine what the widest string actually is due to variable character
 * width and kerning. Doing an exact calculation with the DOM or even Canvas would kill performance
 * and this is a critical point, so we use two techniques to determine a collection of the longest
 * strings from the column, which will likely contain the widest strings:
 *
 * 1) Get the top three longest strings from the column
 * 2) Get the top three widest words (i.e. an unbreakable phrase)
 *
 * @param settings DataTables settings object
 * @param colIdx column of interest
 * @returns Array of the longest strings
 */
function getWideStrings(settings, colIdx) {
    var column = settings.columns[colIdx];
    // Do we need to recalculate (i.e. was invalidated), or just use the cached data?
    if (!column.wideStrings) {
        var allStrings = [];
        var collection = [];
        // Create an array with the string information for the column
        for (var i = 0, iLen = settings.displayMaster.length; i < iLen; i++) {
            var rowIdx = settings.displayMaster[i];
            var data = getRowDisplay(settings, rowIdx)[colIdx];
            var cellString = data && typeof data === 'object' && data.nodeType
                ? data.innerHTML
                : data + '';
            // Remove id / name attributes from elements so they
            // don't interfere with existing elements
            cellString = cellString
                .replace(/id=".*?"/g, '')
                .replace(/name=".*?"/g, '');
            // Don't want script, dialog or template tags in the width
            // calculations as they are hidden content
            cellString = cellString
                .replace(/<script[\s\S]*?<\/script(?:\s[^>]*)?>/gi, ' ')
                .replace(/<dialog[\s\S]*?<\/dialog(?:\s[^>]*)?>/gi, ' ')
                .replace(/<template[\s\S]*?<\/template(?:\s[^>]*)?>/gi, ' ');
            var noHtml = util.string
                .stripHtml(cellString, ' ')
                .replace(/&nbsp;/g, ' ');
            collection.push({
                str: cellString,
                len: noHtml.length
            });
            allStrings.push(noHtml);
        }
        // Order and then cut down to the size we need
        collection
            .sort(function (a, b) {
            return b.len - a.len;
        })
            .splice(3);
        column.wideStrings = collection.map(function (item) {
            return item.str;
        });
        // Longest unbroken string
        const parts = allStrings.join(' ').split(' ');
        parts.sort(function (a, b) {
            return b.length - a.length;
        });
        if (parts.length) {
            column.wideStrings.push(parts[0]);
        }
        if (parts.length > 1) {
            column.wideStrings.push(parts[1]);
        }
        if (parts.length > 2) {
            column.wideStrings.push(parts[3]);
        }
    }
    return column.wideStrings;
}
/**
 * Append a CSS unit (only if required) to a string
 *
 * @param s Value to css-ify
 * @returns Value with css unit
 */
function stringToCss(s) {
    if (s === null) {
        return '0px';
    }
    if (typeof s == 'number') {
        return s < 0 ? '0px' : s + 'px';
    }
    // Check it has a unit character already
    return s.match(/\d$/) ? s + 'px' : s;
}
/**
 * Re-insert the `col` elements for current visibility
 *
 * @param settings DT settings
 */
function colGroup(settings) {
    var cols = settings.columns;
    settings.colgroup.empty();
    for (var i = 0; i < cols.length; i++) {
        if (cols[i].visible) {
            settings.colgroup.append(cols[i].colEl);
        }
    }
}

/**
 * Scrolling setup
 *
 * @param settings DataTables settings object
 * @returns Node to add to the DOM
 */
function featureTable(settings) {
    let table = Dom.s(settings.table);
    let scroll = settings.scroll;
    let scrollX = scroll.x;
    let scrollY = scroll.y;
    // No scrolling or x-scrolling only
    if (scrollY === '' && scrollX === '') {
        return table.get(0);
    }
    let classes = settings.classes.scrolling;
    let caption = settings.captionNode;
    let captionSide = caption
        ? caption._captionSide
        : null;
    let tableCloneHeader = table.clone(false);
    let tableCloneFooter = table.clone(false);
    let footer = table.children('tfoot');
    let size = function (s) {
        return !s ? '100%' : stringToCss(s);
    };
    /*
     * The HTML structure that we want to generate in this function is:
     *  div - scroller
     *    div - scroll head
     *      div - scroll head inner
     *        table - scroll head table
     *          thead - thead
     *    div - scroll body
     *      table - table (master table)
     *        thead - thead clone for sizing
     *        tbody - tbody
     *    div - scroll foot
     *      div - scroll foot inner
     *        table - scroll foot table
     *          tfoot - tfoot
     */
    let scroller = Dom.c('div')
        .classAdd(classes.container)
        .attr('role', 'table')
        .append(Dom.c('div')
        .classAdd(classes.header.self)
        .css({
        overflow: 'hidden',
        position: 'relative',
        border: '0',
        width: scrollX ? size(scrollX) : '100%'
    })
        .attr('role', 'none')
        .append(Dom.c('div')
        .classAdd(classes.header.inner)
        .css({
        'box-sizing': 'content-box',
        width: scroll.xInner || '100%'
    })
        .attr('role', 'none')
        .append(tableCloneHeader
        .attrRemove('id')
        .css('margin-left', '0')
        .append(captionSide === 'top' ? caption : null)
        .append(table.children('thead')))))
        .append(Dom.c('div')
        .classAdd(classes.body)
        .css({
        position: 'relative',
        overflow: 'auto',
        width: size(scrollX)
    })
        .attr('role', 'none')
        .append(table));
    if (footer.count()) {
        scroller.append(Dom.c('div')
            .classAdd(classes.footer.self)
            .css({
            overflow: 'hidden',
            border: '0',
            width: scrollX ? size(scrollX) : '100%'
        })
            .attr('role', 'none')
            .append(Dom.c('div')
            .classAdd(classes.footer.inner)
            .attr('role', 'none')
            .append(tableCloneFooter
            .attrRemove('id')
            .css('margin-left', '0')
            .append(captionSide === 'bottom' ? caption : null)
            .append(table.children('tfoot')))));
    }
    let children = scroller.children();
    let scrollHead = children.eq(0);
    let scrollBody = children.eq(1);
    let scrollFoot = children.eq(2);
    // When the body is scrolled, then we also want to scroll the header and
    // footer. Note that each element has its own scroll listener, and that in
    // turn sets the scroll for the other elements. However this doesn't lead to
    // an infinite loop as `scroll` is only triggered if the value changes.
    scrollBody.on('scroll.DT', () => {
        let scrollLeft = scrollBody.scrollLeft();
        scrollHead.scrollLeft(scrollLeft);
        scrollFoot.scrollLeft(scrollLeft);
    });
    scrollHead.on('scroll.DT', () => {
        let scrollLeft = scrollHead.scrollLeft();
        scrollBody.scrollLeft(scrollLeft);
        scrollFoot.scrollLeft(scrollLeft);
    });
    scrollFoot.on('scroll.DT', () => {
        let scrollLeft = scrollFoot.scrollLeft();
        scrollHead.scrollLeft(scrollLeft);
        scrollBody.scrollLeft(scrollLeft);
    });
    scrollBody.css('max-height', size(scrollY));
    if (!scroll.collapse) {
        scrollBody.css('height', size(scrollY));
    }
    settings.scrollHead = scrollHead;
    settings.scrollBody = scrollBody;
    settings.scrollFoot = scrollFoot;
    // On redraw - align columns
    settings.callbacks.draw.push(scrollDraw);
    // Aria roles - because we break the table up into parts we need to be very
    // explicit with the roles to create the accessability tree for the table,
    // otherwise browser's attempt to "fix" the tree by filling in what it
    // thinks are gaps. The static elements that we can assign roles to are done
    // here. Dynamic ones are done in the draw function below.
    table.attr('role', 'none');
    table.find('tbody').attr('role', 'rowgroup');
    tableCloneHeader.attr('role', 'none');
    tableCloneFooter.attr('role', 'none');
    settings.colgroup.find('colgroup').attr('role', 'none');
    // Move the info feature's aria desc by to the new "table"
    let describedBy = table.attr('aria-describedby');
    if (describedBy) {
        scroller.attr('aria-describedby', describedBy);
        table.attrRemove('aria-describedby');
    }
    return scroller.get(0);
}
/**
 * Update the header, footer and body tables for resizing - i.e. column
 * alignment.
 *
 * Welcome to the most horrible function DataTables. The process that this
 * function follows is basically:
 *   1. Re-create the table inside the scrolling div
 *   2. Correct colgroup > col values if needed
 *   3. Copy colgroup > col over to header and footer
 *   4. Clean up
 *
 * @param settings DataTables settings object
 */
function scrollDraw(settings) {
    // Given that this is such a monster function, a lot of variables are use
    // to try and keep the minimised size as small as possible
    let scroll = settings.scroll, barWidth = scroll.barWidth, divHeader = settings.scrollHead, divHeaderInner = divHeader.children('div'), divHeaderTable = divHeaderInner.children('table'), divBodyEl = settings.scrollBody, divBody = divBodyEl, divFooter = settings.scrollFoot, divFooterInner = divFooter.children('div'), divFooterTable = divFooterInner.children('table'), header = Dom.s(settings.thead), table = Dom.s(settings.table), footer = Dom.s(settings.tfoot), browser = settings.browser, headerCopy, footerCopy;
    // If the scrollbar visibility has changed from the last draw, we need to
    // adjust the column sizes as the table width will have changed to account
    // for the scrollbar
    let scrollBarVis = divBodyEl.get(0).scrollHeight > divBodyEl.get(0).clientHeight;
    if (settings.scrollBarVis !== scrollBarVis &&
        settings.scrollBarVis !== undefined) {
        settings.scrollBarVis = scrollBarVis;
        adjustColumnSizing(settings);
        return; // adjust column sizing will call this function again
    }
    else {
        settings.scrollBarVis = scrollBarVis;
    }
    header.find('thead').attr('role', 'rowgroup');
    footer.find('tfoot').attr('role', 'rowgroup');
    // 1. Re-create the table inside the scrolling div
    // Remove the old minimised thead and tfoot elements in the inner table
    table.children('thead, tfoot').remove();
    // Clone the current header and footer elements and then place it into the
    // inner table
    headerCopy = header.clone(true).prependTo(table);
    headerCopy.find('th, td').attrRemove('tabindex');
    headerCopy.find('[id]').attrRemove('id');
    if (footer.count()) {
        footerCopy = footer.clone(true).prependTo(table);
        footerCopy.find('[id]').attrRemove('id');
    }
    // 2. Correct colgroup > col values if needed
    // It is possible that the cell sizes are smaller than the content, so we need to
    // correct colgroup>col for such cases. This can happen if the auto width detection
    // uses a cell which has a longer string, but isn't the widest! For example
    // "Chief Executive Officer (CEO)" is the longest string in the demo, but
    // "Systems Administrator" is actually the widest string since it doesn't collapse.
    // Note the use of translating into a column index to get the `col` element. This
    // is because of Responsive which might remove `col` elements, knocking the alignment
    // of the indexes out.
    if (settings.display.length) {
        // Get the column sizes from the first row in the table. This should really be a
        // [].find, but it wasn't supported in Chrome until Sept 2015, and DT has 10 year
        // browser support
        let firstTr = null;
        let start = dataSource(settings) !== 'ssp' ? settings.displayStart : 0;
        for (let i = start; i < start + settings.display.length; i++) {
            let idx = settings.display[i];
            let row = settings.data[idx];
            if (row) {
                let tr = row.tr;
                if (tr) {
                    firstTr = tr;
                    break;
                }
            }
        }
        if (firstTr) {
            let colSizes = Dom.s(firstTr)
                .children('th, td')
                .mapTo(function (cell, idx) {
                return {
                    idx: visibleToColumnIndex(settings, idx),
                    width: Dom.s(cell).width('outer')
                };
            });
            // Check against what the colgroup > col is set to and correct if needed
            for (let i = 0; i < colSizes.length; i++) {
                let colEl = settings.columns[colSizes[i].idx].colEl;
                colEl.css('width', colSizes[i].width + 'px');
                if (scroll.x) {
                    colEl.css('minWidth', colSizes[i].width + 'px');
                }
            }
        }
    }
    // 3. Copy the colgroup over to the header and footer
    divHeaderTable.find('colgroup').remove();
    divHeaderTable.append(settings.colgroup.clone(true));
    if (footer) {
        divFooterTable.find('colgroup').remove();
        divFooterTable.append(settings.colgroup.clone(true));
    }
    // "Hide" the header and footer that we used for the sizing. We need to keep
    // the content of the cell so that the width applied to the header and body
    // both match, but we want to hide it completely.
    headerCopy.find('th, td').each(function (el) {
        Dom.c('div')
            .classAdd('dt-scroll-sizing')
            .append(Array.from(el.childNodes))
            .appendTo(el);
    });
    if (footerCopy) {
        footerCopy.find('th, td').each(function (el) {
            Dom.c('div')
                .classAdd('dt-scroll-sizing')
                .append(Array.from(el.childNodes))
                .appendTo(el);
        });
    }
    // 4. Clean up
    // Figure out if there are scrollbar present - if so then we need the header and footer to
    // provide a bit more space to allow "overflow" scrolling (i.e. past the scrollbar)
    let isScrolling = Math.floor(table.height()) > divBodyEl.get(0).clientHeight ||
        divBody.css('overflow-y') == 'scroll';
    let paddingSide = 'padding' + (browser.scrollbarLeft ? 'Left' : 'Right');
    // Set the width's of the header and footer tables
    let outerWidth = table.width('withPadding');
    divHeaderTable.css('width', stringToCss(outerWidth));
    divHeaderInner
        .css('width', stringToCss(outerWidth))
        .css(paddingSide, isScrolling ? barWidth + 'px' : '0px');
    if (footer.count()) {
        divFooterTable.css('width', stringToCss(outerWidth));
        divFooterInner
            .css('width', stringToCss(outerWidth))
            .css(paddingSide, isScrolling ? barWidth + 'px' : '0px');
    }
    // Correct DOM ordering for colgroup - comes before the thead
    table.children('colgroup').prependTo(table);
    // Remove tabindex from the hidden row elements
    table.find('thead, tfoot').find('[tabindex]').attrRemove('tabindex');
    // Dynamic ARIA roles - see setup for details on why this is needed
    table
        .find('thead, tfoot')
        .attr('role', 'none')
        .find('[role]')
        .attrRemove('role');
    table.find('tbody tr:not([role])').attr('role', 'row');
    table.find('tbody td:not([role]), tbody th:not([role])').attr('role', 'cell');
    scrollAria(headerCopy);
    scrollAria(footerCopy);
    // Adjust the position of the header in case we loose the y-scrollbar
    divBody.trigger('scroll');
    // If sorting or filtering has occurred, jump the scrolling back to the top
    // only if we aren't holding the position
    if ((settings.wasOrdered || settings.wasFiltered) && !settings.drawHold) {
        divBodyEl.scrollTop(0);
    }
}
/**
 * Apply ARIA roles for the header / footer of a scrolling table
 * @param element
 */
function scrollAria(element) {
    if (element) {
        element.find('tfoot:not([role])').attr('role', 'rowgroup');
        element.find('tr:not([role])').attr('role', 'row');
        element.find('th:not([role])').attr('role', 'columnheader');
        element.find('td:not([role])').attr('role', 'cell');
    }
}

/**
 * Add a column to the list used for the table with default values
 *
 * @param settings DataTables settings object
 */
function addColumn(settings) {
    // Add column to aoColumns array
    let columnIdx = settings.columns.length;
    let column = util.object.assign({}, new Settings(), defaults$4, {
        orderData: defaults$4.orderData
            ? defaults$4.orderData
            : [columnIdx],
        data: defaults$4.data ? defaults$4.data : columnIdx,
        idx: columnIdx,
        searchFixed: {},
        colEl: Dom
            .c('col')
            .attr('data-dt-column', columnIdx)
    });
    settings.columns.push(column);
    // Legacy support for `searchCols` property. If set, and there is a value
    // for this column, then it should be applied to the search. The new, column
    // specific `search` option is applied in `columnOptions`, but we always
    // want the search object for the column to exist.
    let searchCols = settings.searchCols;
    settings.searches[columnIdx] = create$2(searchCols[columnIdx]
        ? hungarianToCamel(searchCols[columnIdx])
        : {});
    settings.searches[columnIdx].columns = [columnIdx];
}
/**
 * Apply options for a column
 *
 * @param settings DataTables settings object
 * @param colIdx column index to consider
 * @param options Column configuration options
 */
function columnOptions(settings, colIdx, options) {
    var column = settings.columns[colIdx];
    /* User specified column options */
    if (options !== undefined && options !== null) {
        // Backwards compatibility
        compatCols(options);
        if (options.type) {
            column.typeManual = options.type;
        }
        // `class` is a reserved word in JavaScript, so we need to provide
        // the ability to use a valid name for the camel case input
        if (options.className && !options.className) {
            options.className = options.className;
        }
        var origClass = column.className;
        util.object.assign(column, options);
        map(column, options, 'width', 'widthOrig');
        // Merge class from previously defined classes with this one, rather
        // than just overwriting it in the extend above
        if (origClass !== column.className) {
            column.className = origClass + ' ' + column.className;
        }
        map(column, options, 'orderData');
        // Search term specifically for this column
        if (options.search) {
            util.object.assign(settings.searches[colIdx], options.search);
        }
    }
    /* Cache the data get and set functions for speed */
    var dataSrc = column.data;
    var dataFn = util.get(dataSrc);
    // The `render` option can be given as an array to access the helper
    // rendering methods. The first element is the rendering method to use, the
    // rest are the parameters to pass
    if (column.render && Array.isArray(column.render)) {
        var copy = column.render.slice();
        var name = copy.shift();
        column.render = helpers[name].apply(window, copy);
    }
    column.renderer = column.render ? util.get(column.render) : null;
    var attrTest = function (src) {
        return typeof src === 'string' && src.indexOf('@') !== -1;
    };
    column.attrSrc =
        !!dataSrc &&
            util.is.plainObject(dataSrc) &&
            (attrTest(dataSrc.sort) ||
                attrTest(dataSrc.type) ||
                attrTest(dataSrc.filter));
    column.setter = null;
    column.dataGet = function (rowData, type, meta) {
        var innerData = dataFn(rowData, type, undefined, meta);
        return column.renderer && type
            ? column.renderer(innerData, type, rowData, meta)
            : innerData;
    };
    column.dataSet = function (rowData, val, meta) {
        return util.set(dataSrc)(rowData, val, meta);
    };
    // Indicate if DataTables should read DOM data as an object or array
    // Used in _fnGetRowElements
    if (typeof dataSrc !== 'number' && !column._isArrayHost) {
        settings.rowReadObject = true;
    }
    // Feature sorting overrides column specific when off
    if (!settings.features.ordering) {
        column.orderable = false;
    }
}
/**
 * Adjust the table column widths for new data. Note: you would probably want to
 * do a redraw after calling this function!
 *
 * @param settings DataTables settings object
 */
function adjustColumnSizing(settings) {
    calculateColumnWidths(settings);
    columnSizes(settings);
    let scroll = settings.scroll;
    if (scroll.y !== '' || scroll.x !== '') {
        scrollDraw(settings);
    }
    callbackFire(settings, null, 'column-sizing', [settings]);
}
/**
 * Apply column sizes
 *
 * @param settings DataTables settings object
 */
function columnSizes(settings) {
    let cols = settings.columns;
    for (let i = 0; i < cols.length; i++) {
        let width = columnsSumWidth(settings, [i], false);
        if (width) {
            cols[i].colEl.css('width', width);
            if (settings.scroll.x) {
                cols[i].colEl.css('min-width', width);
            }
        }
    }
}
/**
 * Convert the index of a visible column to the index in the data array (take
 * account of hidden columns)
 *
 * @param settings DataTables settings object
 * @param visIdx Visible column index to lookup
 * @returns i the data index
 */
function visibleToColumnIndex(settings, visIdx) {
    let aiVis = getColumns(settings, 'visible');
    return typeof aiVis[visIdx] === 'number' ? aiVis[visIdx] : null;
}
/**
 * Convert the index of an index in the data array and convert it to the visible
 * column index (take account of hidden columns)
 *
 * @param settings DataTables settings object
 * @param match Column index to lookup
 * @returns The data index
 */
function columnIndexToVisible(settings, match) {
    let aiVis = getColumns(settings, 'visible');
    let iPos = aiVis.indexOf(match);
    return iPos !== -1 ? iPos : null;
}
/**
 * Get the number of visible columns
 *
 * @param settings DataTables settings object
 * @returns i the number of visible columns
 */
function visibleColumns(settings) {
    let layout = settings.header;
    let columns = settings.columns;
    let vis = 0;
    if (layout.length) {
        for (let i = 0, iLen = layout[0].length; i < iLen; i++) {
            if (columns[i].visible &&
                Dom.s(layout[0][i].cell).css('display') !== 'none') {
                vis++;
            }
        }
    }
    return vis;
}
/**
 * Get an array of column indexes that match a given property
 *
 * @param settings DataTables settings object
 * @param param Parameter in the columns array to look for
 *  @returns Array of indexes with matched properties
 */
function getColumns(settings, param) {
    let a = [];
    settings.columns.map(function (val, i) {
        if (val[param]) {
            a.push(i);
        }
    });
    return a;
}
/**
 * Allow the result from a type detection function to be `true` while
 * translating that into a string. Old type detection functions will return the
 * type name if it passes. An object store would be better, but not backwards
 * compatible.
 *
 * @param typeDetect Object or function for type detection
 * @param res Result from the type detection function
 * @returns Type name or false
 */
function _typeResult(typeDetect, res) {
    return res === true ? typeDetect._name : res;
}
/**
 * Calculate the 'type' of a column
 * @param settings DataTables settings object
 */
function columnTypes(settings, originalTypes = '') {
    var columns = settings.columns;
    var data = settings.data;
    var types = ext.type.detect;
    var i, iLen, j, jen, k, ken;
    var col, detectedType, cache;
    if (!originalTypes) {
        originalTypes = columns.map(c => c.type).join(',');
    }
    // For each column, spin over the data type detection functions, seeing if
    // one matches
    for (i = 0, iLen = columns.length; i < iLen; i++) {
        col = columns[i];
        cache = [];
        if (!col.type && col.typeManual) {
            col.type = col.typeManual;
        }
        else if (!col.type) {
            // With SSP type detection can be unreliable and error prone, so we
            // provide a way to turn it off.
            if (!settings.typeDetect) {
                return;
            }
            for (j = 0, jen = types.length; j < jen; j++) {
                let typeDetect = types[j];
                let oneOf;
                let allOf;
                let init;
                let one = false;
                // There can be either one, or three type detection functions
                if (typeof typeDetect === 'function') {
                    allOf = typeDetect;
                }
                else {
                    oneOf = typeDetect.oneOf;
                    allOf = typeDetect.allOf;
                    init = typeDetect.init;
                }
                detectedType = null;
                // Fast detect based on column assignment
                if (init) {
                    detectedType = _typeResult(typeDetect, init(settings, col, i));
                    if (detectedType) {
                        col.type = detectedType;
                        break;
                    }
                }
                for (k = 0, ken = data.length; k < ken; k++) {
                    if (!data[k]) {
                        continue;
                    }
                    // Use a cache array so we only need to get the type data
                    // from the formatter once (when using multiple detectors)
                    if (cache[k] === undefined) {
                        cache[k] = getCellData(settings, k, i, 'type');
                    }
                    // Only one data point in the column needs to match this
                    // function
                    if (oneOf && !one) {
                        one = _typeResult(typeDetect, oneOf(cache[k], settings));
                    }
                    // All data points need to match this function
                    detectedType = _typeResult(typeDetect, allOf(cache[k], settings));
                    // If null, then this type can't apply to this column, so
                    // rather than testing all cells, break out. There is an
                    // exception for the last type which is `html`. We need to
                    // scan all rows since it is possible to mix string and HTML
                    // types
                    if (!detectedType && j !== types.length - 3) {
                        break;
                    }
                    // Only a single match is needed for html type since it is
                    // bottom of the pile and very similar to string - but it
                    // must not be empty
                    if (detectedType === 'html' && !util.is.empty(cache[k])) {
                        break;
                    }
                }
                // Type is valid for all data points in the column - use this
                // type
                if ((oneOf && one && detectedType) ||
                    (!oneOf && detectedType)) {
                    col.type = detectedType;
                    break;
                }
            }
            // Fall back - if no type was detected, always use string
            if (!col.type) {
                col.type = 'string';
            }
        }
        // Set class names for header / footer for auto type classes
        var autoClass = ext.type.className[col.type];
        if (autoClass) {
            _columnAutoClass(settings.header, i, autoClass);
            _columnAutoClass(settings.footer, i, autoClass);
        }
        var renderer = ext.type.render[col.type];
        // This can only happen once! There is no way to remove
        // a renderer. After the first time the renderer has
        // already been set so createTr will run the renderer itself.
        if (renderer && !col.renderer) {
            col.renderer = util.get(renderer);
            _columnAutoRender(settings, i);
        }
    }
    var newTypes = columns.map(c => c.type).join(',');
    if (newTypes !== originalTypes) {
        callbackFire(settings, null, 'columnTypes', [settings], false);
    }
}
/**
 * Apply an auto detected renderer to data which doesn't yet have a renderer
 */
function _columnAutoRender(settings, colIdx) {
    let data = settings.data;
    for (let i = 0; i < data.length; i++) {
        let d = data[i];
        if (d && d.tr) {
            // We have to update the display here since there is no invalidation
            // check for the data
            let display = getCellData(settings, i, colIdx, 'display');
            d.displayData[colIdx] = display;
            writeCell(d.cells[colIdx], display);
            // No need to update sort / filter data since it has been
            // invalidated and will be re-read with the renderer now applied
        }
    }
}
/**
 * Apply a class name to a column's header cells
 *
 * @param container The header / footer structure array
 * @param colIdx Column index
 * @param className Class name to apply
 */
function _columnAutoClass(container, colIdx, className) {
    container.forEach(function (row) {
        if (row[colIdx] && row[colIdx].unique) {
            Dom.s(row[colIdx].cell).classAdd(className);
        }
    });
}
/**
 * Take the column definitions and static columns arrays and calculate how they
 * relate to column indexes. The callback function will then apply the
 * definition found for a column to a suitable configuration object.
 *
 * @param settings DataTables settings object
 * @param aoColDefs The aoColumnDefs array that is to be applied
 * @param aoCols The aoColumns array that defines columns individually
 * @param headerLayout Layout for header as it was loaded
 * @param fn Callback function - takes two parameters, the calculated column
 *    index and the definition for that column.
 */
function applyColumnDefs(settings, aoColDefs, aoCols, headerLayout, fn) {
    var i, iLen, j, jLen, k, kLen;
    var columns = settings.columns;
    if (aoCols) {
        for (i = 0, iLen = aoCols.length; i < iLen; i++) {
            // Compat
            if (aoCols[i] && aoCols[i].name) {
                columns[i].name = aoCols[i].name;
            }
        }
    }
    // Column definitions with aTargets
    if (aoColDefs) {
        // Loop over the definitions array - loop in reverse so first instance
        // has priority
        for (i = aoColDefs.length - 1; i >= 0; i--) {
            let def = aoColDefs[i];
            /* Each definition can target multiple columns, as it is an array */
            let aTargets = def.target !== undefined
                ? def.target
                : def.targets !== undefined
                    ? def.targets
                    : def.aTargets; // legacy
            if (!Array.isArray(aTargets)) {
                aTargets = [aTargets];
            }
            for (j = 0, jLen = aTargets.length; j < jLen; j++) {
                var target = aTargets[j];
                if (typeof target === 'number' && target >= 0) {
                    /* Add columns that we don't yet know about */
                    while (columns.length <= target) {
                        addColumn(settings);
                    }
                    /* Integer, basic index */
                    fn(target, def);
                }
                else if (typeof target === 'number' && target < 0) {
                    /* Negative integer, right to left column counting */
                    fn(columns.length + target, def);
                }
                else if (typeof target === 'string') {
                    for (k = 0, kLen = columns.length; k < kLen; k++) {
                        if (target === '_all') {
                            // Apply to all columns
                            fn(k, def);
                        }
                        else if (target.indexOf(':name') !== -1) {
                            // Column selector
                            if (columns[k].name === target.replace(':name', '')) {
                                fn(k, def);
                            }
                        }
                        else {
                            // Cell selector
                            headerLayout.forEach(function (row) {
                                if (row[k]) {
                                    var cell = row[k].cell;
                                    // Legacy support. Note that it means that
                                    // we don't support an element name selector
                                    // only, since they are treated as class
                                    // names for 1.x compat.
                                    if (target.match(/^[a-z][\w-]*$/i)) {
                                        target = '.' + target;
                                    }
                                    if (cell.matches(target)) {
                                        fn(k, def);
                                    }
                                }
                            });
                        }
                    }
                }
            }
        }
    }
    // Statically defined columns array
    if (aoCols) {
        for (i = 0, iLen = aoCols.length; i < iLen; i++) {
            fn(i, aoCols[i]);
        }
    }
}
/**
 * Get the width for a given set of columns
 *
 * @param settings DataTables settings object
 * @param targets Columns - comma separated string or array of numbers
 * @param original Use the original width (true) or calculated (false)
 * @param incVisible Include visible columns (true) or not (false)
 * @returns Combined CSS value
 */
function columnsSumWidth(settings, targets, original, incVisible) {
    if (!Array.isArray(targets)) {
        targets = columnsFromHeader(targets);
    }
    let sum = 0;
    let unit = 'px';
    let columns = settings.columns;
    for (let i = 0, iLen = targets.length; i < iLen; i++) {
        let column = columns[targets[i]];
        let definedWidth = original ? column.widthOrig : column.width;
        if (column.visible === false) {
            continue;
        }
        if (definedWidth === null || definedWidth === undefined) {
            return null; // can't determine a defined width - browser defined
        }
        else if (typeof definedWidth === 'number') {
            sum += definedWidth;
        }
        else {
            let matched = definedWidth.match(/([\d\.]+)([^\d]*)/);
            if (matched) {
                sum += parseFloat(matched[1]);
                unit = matched.length === 3 ? matched[2] : 'px';
            }
        }
    }
    return sum + unit;
}
/**
 * Determine what columns a header cell covers (can be multiple for colspan
 * cases).
 *
 * @param cell The header cell in question
 * @returns An array of column indexes
 */
function columnsFromHeader(cell) {
    let attr = Dom.s(cell).closest('[data-dt-column]').attr('data-dt-column');
    if (!attr) {
        return [];
    }
    return attr.split(',').map(function (val) {
        return parseInt(val);
    });
}

/**
 * Generate the node required for the processing node
 *
 * @param ctx DataTables settings object
 */
function processingHtml(ctx) {
    var table = ctx.table;
    var scrolling = ctx.scroll.x !== '' || ctx.scroll.y !== '';
    if (ctx.features.processing) {
        var n = Dom
            .c('div')
            .attr('id', ctx.tableId + '_processing')
            .attr('role', 'status')
            .classAdd(ctx.classes.processing.container)
            .html(ctx.language.processing)
            .append(Dom
            .c('div')
            .append(Dom.c('div'))
            .append(Dom.c('div'))
            .append(Dom.c('div'))
            .append(Dom.c('div')));
        // Different positioning depending on if scrolling is enabled or not
        if (scrolling) {
            n.prependTo(Dom.s(ctx.tableWrapper).find('div.dt-scroll').get(0));
        }
        else {
            n.insertBefore(table);
        }
        Dom.s(table).on('processing.dt.DT', (e, s, show) => {
            n.css('display', show ? 'block' : 'none');
        });
    }
}
/**
 * Display or hide the processing indicator
 *
 * @param ctx DataTables settings object
 * @param show Show the processing indicator (true) or not (false)
 */
function processingDisplay(ctx, show) {
    // Ignore cases when we are still redrawing
    if (ctx.doingDraw && show === false) {
        return;
    }
    callbackFire(ctx, null, 'processing', [ctx, show]);
}
/**
 * Show the processing element if an action takes longer than a given time
 *
 * @param ctx DataTables settings object
 * @param enable Do (true) or not (false) async processing (local feature enablement)
 * @param run Function to run
 */
function processingRun(ctx, enable, run) {
    if (!enable) {
        // Immediate execution, synchronous
        run();
    }
    else {
        processingDisplay(ctx, true);
        // Allow the processing display to show if needed
        setTimeout(function () {
            run();
            processingDisplay(ctx, false);
        }, 0);
    }
}

function renderer(ctx, type) {
    var render = ctx.renderer;
    var host = ext.renderer[type];
    if (plainObject(render) && render[type]) {
        // Specific renderer for this type. If available use it, otherwise use
        // the default.
        return host[render[type]] || host._;
    }
    else if (typeof render === 'string') {
        // Common renderer - if there is one available for this type use it,
        // otherwise use the default
        return host[render] || host._;
    }
    // Use the default
    return host._;
}

/**
 * Add the options to the page HTML for the table
 *
 * @param ctx DataTables context
 */
function createLayout(ctx) {
    var classes = ctx.classes;
    // Wrapper div around everything DataTables controls
    var insert = Dom
        .c('div')
        .attr('id', ctx.tableId + '_wrapper')
        .classAdd(classes.container)
        .insertBefore(ctx.table);
    ctx.tableWrapper = insert.get(0);
    if (ctx.dom) {
        // Legacy
        legacyDom(ctx, ctx.dom, insert);
    }
    else {
        var top = convert(ctx, ctx.layout, 'top');
        var bottom = convert(ctx, ctx.layout, 'bottom');
        var render = renderer(ctx, 'layout');
        // Everything above - the renderer will actually insert the contents into the document
        top.forEach(function (item) {
            render(ctx, insert, item);
        });
        // The table - always the center of attention
        render(ctx, insert, {
            full: {
                contents: [featureTable(ctx)],
                items: [],
                table: true
            }
        });
        // Everything below
        bottom.forEach(function (item) {
            render(ctx, insert, item);
        });
    }
    // Processing floats on top, so it isn't an inserted feature
    processingHtml(ctx);
}
/**
 * Expand the layout items into an object for the rendering function
 */
function layoutItems(row, align, items) {
    if (Array.isArray(items)) {
        for (var i = 0; i < items.length; i++) {
            layoutItems(row, align, items[i]);
        }
        return;
    }
    var rowCell = row[align]; // can't be undefined - will have been created by getRow
    // If it is an object, then there can be multiple features contained in it
    if (util.is.plainObject(items)) {
        // Is it an cell object already, with rowId, etc. A feature plugin cannot
        // be named "features" due to this check
        if (items.features) {
            if (items.rowId) {
                row.id = items.rowId;
            }
            if (items.rowClass) {
                row.className = items.rowClass;
            }
            rowCell.id = items.id;
            rowCell.className = items.className;
            layoutItems(row, align, items.features);
        }
        else {
            // An object of features and configuration options - e.g. `{paging: {startEnd: false}}`
            util.object.each(items, (key, val) => {
                rowCell.items.push({
                    feature: key,
                    opts: val
                });
            });
        }
    }
    else {
        // Otherwise, it is a function, node or Dom / jQuery instance and can just get added
        rowCell.items.push(items);
    }
}
/**
 * Find, or create a layout row and setup a target cell in it
 *
 * @param rows Rows array to search for the target row. Is mutated when a row is
 *   added if not found.
 * @param rowNum Row index to get
 * @param align Where the cell position is
 * @returns The row
 */
function getRow(rows, rowNum, align) {
    var row;
    // Find existing rows
    for (var i = 0; i < rows.length; i++) {
        row = rows[i];
        if (row.rowNum === rowNum) {
            // full is on its own, but start and end share a row
            if ((align === 'full' && row.full) ||
                ((align === 'start' || align === 'end') &&
                    (row.start || row.end))) {
                if (!row[align]) {
                    row[align] = {
                        contents: [],
                        items: []
                    };
                }
                return row;
            }
        }
    }
    // If we get this far, then there was no match, create a new row
    row = {
        rowNum: rowNum
    };
    row[align] = {
        contents: [],
        items: []
    };
    rows.push(row);
    return row;
}
/**
 * Convert a `layout` object given by a user to the object structure needed
 * for the renderer. This is done twice, once for above and once for below
 * the table. Ordering must also be considered.
 *
 * @param settings DataTables settings object
 * @param layout Layout object to convert
 * @param side `top` or `bottom`
 * @returns Converted array structure - one item for each row.
 */
function convert(settings, layout, side) {
    var rows = [];
    // Split out into an array
    util.object.each(layout, function (pos, items) {
        var parts = pos.match(/^([a-z]+)([0-9]*)([A-Za-z]*)$/);
        if (items === null || !parts) {
            return;
        }
        var rowNum = parts[2] ? parseInt(parts[2]) : 0;
        var align = parts[3] ? parts[3].toLowerCase() : 'full';
        // Filter out the side we aren't interested in
        if (parts[1] !== side) {
            return;
        }
        // Only really a type check
        if (align !== 'full' && align !== 'start' && align !== 'end') {
            return;
        }
        // Get or create the row we should attach to
        var row = getRow(rows, rowNum, align);
        layoutItems(row, align, items);
    });
    // Order by item identifier
    rows.sort(function (a, b) {
        var order1 = a.rowNum || 0;
        var order2 = b.rowNum || 0;
        // If both in the same row, then the row with `full` comes first
        if (order1 === order2) {
            var ret = a.full && !b.full ? -1 : 1;
            return side === 'bottom' ? ret * -1 : ret;
        }
        return order2 - order1;
    });
    // Invert for below the table
    if (side === 'bottom') {
        rows.reverse();
    }
    for (var row = 0; row < rows.length; row++) {
        delete rows[row].rowNum;
        resolve(settings, rows[row]);
    }
    return rows;
}
/**
 * Convert the contents of a row's layout object to nodes that can be inserted
 * into the document by a renderer. Execute functions, look up plug-ins, etc.
 *
 * @param settings DataTables settings object
 * @param row Layout object for this row
 */
function resolve(settings, row) {
    var getFeature = function (feature, opts) {
        if (!ext.features[feature]) {
            log(settings, 0, 'Unknown feature: ' + feature);
        }
        return ext.features[feature].apply(this, [settings, opts]);
    };
    // Resolve items in the `contents` array from being an identifier, such as
    // the name of a feature, into the node to display.
    var resolve = function (item) {
        if (!row[item]) {
            return;
        }
        row[item].contents = row[item].items
            .filter(item => !!item)
            .map(item => {
            if (typeof item === 'string') {
                return getFeature(item, null);
            }
            else if (util.is.plainObject(item)) {
                // If it's an object, it just has feature and opts properties from
                // the transform in _layoutArray
                return getFeature(item.feature, item.opts);
            }
            else if (typeof item.node === 'function') {
                return item.node(settings);
            }
            else if (typeof item === 'function') {
                var inst = item(settings);
                return typeof inst.node === 'function' ? inst.node() : inst;
            }
            else if (item.nodeName) {
                // An HTML element
                return item;
            }
            else if (item instanceof Dom) {
                return item.get(0);
            }
            else if (item.length) {
                // Possibly jQuery
                return item[0];
            }
        });
    };
    resolve('start');
    resolve('end');
    resolve('full');
}
/**
 * Draw the table with the legacy DOM property
 *
 * @param settings DT settings instance
 * @param layout DOM string
 * @param insert Insert point
 */
function legacyDom(settings, layout, insert) {
    let parts = layout.match(/(".*?")|('.*?')|./g);
    let featureNode, option, newNode, next, attr;
    if (!parts) {
        return;
    }
    for (let i = 0; i < parts.length; i++) {
        featureNode = null;
        option = parts[i];
        if (option == '<') {
            // New container div
            newNode = Dom.c('div');
            // Check to see if we should append an id and/or a class name to the container
            next = parts[i + 1];
            if (next[0] == "'" || next[0] == '"') {
                attr = next.replace(/['"]/g, '');
                let id = '', className;
                /* The attribute can be in the format of "#id.class", "#id" or "class" This logic
                 * breaks the string into parts and applies them as needed
                 */
                if (attr.indexOf('.') != -1) {
                    let split = attr.split('.');
                    id = split[0];
                    className = split[1];
                }
                else if (attr[0] == '#') {
                    id = attr;
                }
                else {
                    className = attr;
                }
                newNode.attr('id', id.substring(1)).classAdd(className);
                i++; // Move along the position array
            }
            insert.append(newNode.get()); // TODO
            insert = newNode;
        }
        else if (option == '>') {
            // End container div
            insert = insert.parent();
        }
        else if (option == 't') {
            // Table
            featureNode = featureTable(settings);
        }
        else {
            ext.feature.forEach(function (feature) {
                if (option == feature.cFeature) {
                    featureNode = feature.fnInit(settings);
                }
            });
        }
        // Add to the display
        if (featureNode) {
            // TODO when doing the full dom update, won't need this check
            insert.append(featureNode instanceof Dom ? featureNode.get() : featureNode);
        }
    }
}

function sortInit(settings) {
    var target = settings.thead;
    var headerRows = target.querySelectorAll('tr');
    var titleRow = settings.titleRow;
    var notSelector = ':not([data-dt-order="disable"]):not([data-dt-order="icon-only"])';
    // Legacy support for `orderCellsTop`
    if (titleRow === true) {
        target = headerRows[0];
    }
    else if (titleRow === false) {
        target = headerRows[headerRows.length - 1];
    }
    else if (titleRow !== null) {
        target = headerRows[titleRow];
    }
    // else - all rows
    if (settings.orderHandler) {
        sortAttachListener(settings, target, target === settings.thead
            ? 'tr' +
                notSelector +
                ' th' +
                notSelector +
                ', tr' +
                notSelector +
                ' td' +
                notSelector
            : 'th' + notSelector + ', td' + notSelector);
    }
    // Need to resolve the user input array into our internal structure
    var order = [];
    sortResolve(settings, order, settings.order);
    settings.order = order;
}
/**
 * Attach event listeners to a node that will trigger ordering on a column
 *
 * @param settings DataTables context
 * @param node Node to attach to
 * @param selector Delegate selector
 * @param column Column index to target
 * @param callback Callback for when done
 */
function sortAttachListener(settings, node, selector, column, callback) {
    bindAction(node, selector, function (e) {
        var run = false;
        var columns = column === undefined
            ? columnsFromHeader(e.target)
            : typeof column === 'function'
                ? column()
                : Array.isArray(column)
                    ? column
                    : [column];
        if (columns.length) {
            for (var i = 0, iLen = columns.length; i < iLen; i++) {
                var ret = sortAdd(settings, columns[i], i, e.shiftKey);
                if (ret !== false) {
                    run = true;
                }
                // If the first entry is no sort, then subsequent
                // sort columns are ignored
                if (settings.order.length === 1 &&
                    settings.order[0][1] === '') {
                    break;
                }
            }
            if (run) {
                processingRun(settings, true, function () {
                    sort(settings);
                    sortDisplay(settings, settings.display);
                    reDraw(settings, false, false);
                    if (callback) {
                        callback();
                    }
                });
            }
        }
    });
}
/**
 * Sort the display array to match the master's order
 *
 * @param settings DataTables context
 * @param display The display array
 */
function sortDisplay(settings, display) {
    if (display.length < 2) {
        return;
    }
    var master = settings.displayMaster;
    var masterMap = {};
    var map = {};
    var i;
    // Rather than needing an `indexOf` on master array, we can create a map
    for (i = 0; i < master.length; i++) {
        masterMap[master[i]] = i;
    }
    // And then cache what would be the indexOf from the display
    for (i = 0; i < display.length; i++) {
        map[display[i]] = masterMap[display[i]];
    }
    display.sort(function (a, b) {
        // Short version of this function is simply `master.indexOf(a) - master.indexOf(b);`
        return map[a] - map[b];
    });
}
/**
 * Convert the API variants that can be used for defining the order into our
 * internal OrderColumn array.
 *
 * @param settings DataTable context object
 * @param nestedSort Array to write the resolve values to
 * @param sortItem Source object / array from user (It is really an `Order`
 *   but due to `aaSorting` being used for input and the internal structure
 *   it is currently any).
 * @todo Split aaSorting into unresolved and resolved parameters (in state.ts as
 *   well)
 */
function sortResolve(settings, nestedSort, sortItem // TODO typing
) {
    var push = function (a) {
        if (plainObject(a)) {
            let orderIdx = a;
            let orderName = a;
            if (orderIdx.idx !== undefined) {
                // Index based ordering
                nestedSort.push([orderIdx.idx, orderIdx.dir]);
            }
            else if (orderName.name) {
                // Name based ordering
                var cols = pluck(settings.columns, 'name');
                var idx = cols.indexOf(orderName.name);
                if (idx !== -1) {
                    nestedSort.push([idx, orderName.dir]);
                }
            }
        }
        else {
            // Plain column index and direction pair
            nestedSort.push(a);
        }
    };
    if (plainObject(sortItem)) {
        // Object
        push(sortItem);
    }
    else if (Array.isArray(sortItem) && typeof sortItem[0] === 'number') {
        // 1D array
        push(sortItem);
    }
    else if (Array.isArray(sortItem)) {
        // 2D array
        for (var z = 0; z < sortItem.length; z++) {
            push(sortItem[z]); // Object or array
        }
    }
}
function sortFlatten(settings) {
    var i, k, kLen, aSort = [], extSort = ext.type.order, aoColumns = settings.columns, dataSort, colIdx, type, srcCol, fixed = settings.orderFixed, fixedObj = plainObject(fixed), nestedSort = [];
    if (!settings.features.ordering) {
        return aSort;
    }
    // Build the sort array, with pre-fix and post-fix options if they have been
    // specified
    if (Array.isArray(fixed)) {
        sortResolve(settings, nestedSort, fixed);
    }
    if (fixedObj && fixed.pre) {
        sortResolve(settings, nestedSort, fixed.pre);
    }
    sortResolve(settings, nestedSort, settings.order);
    if (fixedObj && fixed.post) {
        sortResolve(settings, nestedSort, fixed.post);
    }
    for (i = 0; i < nestedSort.length; i++) {
        srcCol = nestedSort[i][0];
        if (aoColumns[srcCol]) {
            dataSort = aoColumns[srcCol].orderData;
            for (k = 0, kLen = dataSort.length; k < kLen; k++) {
                colIdx = dataSort[k];
                type = aoColumns[colIdx].type || 'string';
                if (nestedSort[i]._idx === undefined) {
                    nestedSort[i]._idx = aoColumns[colIdx].orderSequence.indexOf(nestedSort[i][1]);
                }
                if (nestedSort[i][1]) {
                    aSort.push({
                        src: srcCol,
                        col: colIdx,
                        dir: nestedSort[i][1],
                        index: nestedSort[i]._idx,
                        type: type,
                        formatter: extSort[type + '-pre'],
                        sorter: extSort[type + '-' + nestedSort[i][1]]
                    });
                }
            }
        }
    }
    return aSort;
}
/**
 * Change the order of the table
 *
 * @param ctx DataTables settings object
 * @param col Column to perform sort on
 * @param dir Direction to sort on
 */
function sort(ctx, col, dir) {
    var i, iLen, aiOrig = [], extSort = ext.type.order, data = ctx.data, sortCol, displayMaster = ctx.displayMaster, aSort;
    // Make sure the columns all have types defined
    columnTypes(ctx);
    // Allow a specific column to be sorted, which will _not_ alter the display
    // master
    if (col !== undefined) {
        var srcCol = ctx.columns[col];
        aSort = [
            {
                src: col,
                col: col,
                dir: dir || '',
                index: 0,
                type: srcCol.type,
                formatter: extSort[srcCol.type + '-pre'],
                sorter: extSort[srcCol.type + '-' + dir]
            }
        ];
        displayMaster = displayMaster.slice();
    }
    else {
        aSort = sortFlatten(ctx);
    }
    for (i = 0, iLen = aSort.length; i < iLen; i++) {
        sortCol = aSort[i];
        // Load the data needed for the sort, for each cell
        sortData(ctx, sortCol.col);
    }
    /* No sorting required if server-side or no sorting array */
    if (dataSource(ctx) != 'ssp' && aSort.length !== 0) {
        // Reset the initial positions on each pass so we get a stable sort
        for (i = 0, iLen = displayMaster.length; i < iLen; i++) {
            aiOrig[i] = i;
        }
        // If the first sort is desc, then reverse the array to preserve original
        // order, just in reverse
        if (aSort.length && aSort[0].dir === 'desc' && ctx.orderDescReverse) {
            aiOrig.reverse();
        }
        /* Do the sort - here we want multi-column sorting based on a given data source (column)
         * and sorting function (from oSort) in a certain direction. It's reasonably complex to
         * follow on its own, but this is what we want (example two column sorting):
         *  fnLocalSorting = function(a,b){
         *    var test;
         *    test = oSort['string-asc']('data11', 'data12');
         *      if (test !== 0)
         *        return test;
         *    test = oSort['numeric-desc']('data21', 'data22');
         *    if (test !== 0)
         *      return test;
         *    return oSort['numeric-asc']( aiOrig[a], aiOrig[b] );
         *  }
         * Basically we have a test for each sorting column, if the data in that column is equal,
         * test the next column. If all columns match, then we use a numeric sort on the row
         * positions in the original data array to provide a stable sort.
         */
        displayMaster.sort(function (a, b) {
            var _a, _b;
            var x, y, k, test, sortItem, len = aSort.length, dataA = (_a = data[a]) === null || _a === void 0 ? void 0 : _a.orderCache, dataB = (_b = data[b]) === null || _b === void 0 ? void 0 : _b.orderCache;
            for (k = 0; k < len; k++) {
                sortItem = aSort[k];
                // Data, which may have already been through a `-pre` function
                x = dataA[sortItem.col];
                y = dataB[sortItem.col];
                if (sortItem.sorter) {
                    // If there is a custom sorter (`-asc` or `-desc`) for this
                    // data type, use it
                    test = sortItem.sorter(x, y);
                    if (test !== 0) {
                        return test;
                    }
                }
                else {
                    // Otherwise, use generic sorting
                    test = x < y ? -1 : x > y ? 1 : 0;
                    if (test !== 0) {
                        return sortItem.dir === 'asc' ? test : -test;
                    }
                }
            }
            x = aiOrig[a];
            y = aiOrig[b];
            return x < y ? -1 : x > y ? 1 : 0;
        });
    }
    else if (aSort.length === 0) {
        // Apply index order
        displayMaster.sort(function (x, y) {
            return x < y ? -1 : x > y ? 1 : 0;
        });
    }
    if (col === undefined) {
        // Tell the draw function that we have sorted the data
        ctx.wasOrdered = true;
        ctx.sortDetails = aSort;
        callbackFire(ctx, null, 'order', [ctx, aSort]);
    }
    return displayMaster;
}
/**
 * Function to run on user sort request
 *
 * @param settings dataTables settings object
 * @param colIdx column sorting index
 * @param addIndex Counter
 * @param shift Shift click add
 */
function sortAdd(settings, colIdx, addIndex, shift) {
    var col = settings.columns[colIdx];
    var sorting = settings.order;
    var asSorting = col.orderSequence;
    var nextSortIdx;
    var next = function (a, overflow) {
        var idx = a._idx;
        if (idx === undefined) {
            idx = asSorting.indexOf(a[1]);
        }
        return idx + 1 < asSorting.length ? idx + 1 : overflow ? null : 0;
    };
    if (!col.orderable) {
        return false;
    }
    // Convert to 2D array if needed
    if (typeof sorting[0] === 'number') {
        sorting = settings.order = [sorting];
    }
    // If appending the sort then we are multi-column sorting
    if ((shift || addIndex) && settings.features.orderMulti) {
        // Are we already doing some kind of sort on this column?
        var sortIdx = pluck(sorting, '0').indexOf(colIdx);
        if (sortIdx !== -1) {
            // Yes, modify the sort
            nextSortIdx = next(sorting[sortIdx], true);
            if (nextSortIdx === null && sorting.length === 1) {
                nextSortIdx = 0; // can't remove sorting completely
            }
            if (nextSortIdx === null || asSorting[nextSortIdx] === '') {
                sorting.splice(sortIdx, 1);
            }
            else {
                sorting[sortIdx][1] = asSorting[nextSortIdx];
                sorting[sortIdx]._idx = nextSortIdx;
            }
        }
        else if (shift) {
            // No sort on this column yet, being added by shift click
            // add it as itself
            sorting.push([colIdx, asSorting[0], 0]);
            sorting[sorting.length - 1]._idx = 0;
        }
        else {
            // No sort on this column yet, being added from a colspan
            // so add with same direction as first column
            sorting.push([colIdx, sorting[0][1], 0]);
            sorting[sorting.length - 1]._idx = 0;
        }
    }
    else if (sorting.length && sorting[0][0] == colIdx) {
        // Single column - already sorting on this column, modify the sort
        nextSortIdx = next(sorting[0]);
        if (nextSortIdx) {
            sorting.length = 1;
            sorting[0][1] = asSorting[nextSortIdx];
            sorting[0]._idx = nextSortIdx;
        }
        else {
            sorting.length = 1;
            sorting[0][1] = asSorting[0];
            sorting[0]._idx = 0;
        }
    }
    else {
        // Single column - sort only on this column
        sorting.length = 0;
        sorting.push([colIdx, asSorting[0]]);
        sorting[0]._idx = 0;
    }
}
/**
 * Set the sorting classes on table's body, Note: it is safe to call this function
 * when bSort and bSortClasses are false
 *
 * @param settings DataTables settings object
 */
function sortingClasses(settings) {
    var oldSort = settings.lastOrder;
    var sortClass = settings.classes.order.position;
    var sortFlat = sortFlatten(settings);
    var features = settings.features;
    var i, iLen, colIdx;
    if (features.ordering && features.orderClasses) {
        // Remove old sorting classes
        for (i = 0, iLen = oldSort.length; i < iLen; i++) {
            colIdx = oldSort[i].src;
            // Remove column sorting
            Dom.s(pluck(settings.data, 'cells', colIdx)).classRemove(sortClass + (i < 2 ? i + 1 : 3));
        }
        // Add new column sorting
        for (i = 0, iLen = sortFlat.length; i < iLen; i++) {
            colIdx = sortFlat[i].src;
            Dom.s(pluck(settings.data, 'cells', colIdx)).classAdd(sortClass + (i < 2 ? i + 1 : 3));
        }
    }
    settings.lastOrder = sortFlat;
}
/**
 * Get the data to sort a column, be it from cache, fresh (populating the
 * cache), or from a sort formatter
 *
 * @param settings DataTables settings object
 * @param colIdx Column index
 */
function sortData(settings, colIdx) {
    // Custom sorting function - provided by the sort data type
    var column = settings.columns[colIdx];
    var customSort = ext.order[column.orderDataType];
    var customData;
    if (customSort) {
        customData = customSort.call(settings.instance, settings, colIdx, columnIndexToVisible(settings, colIdx));
    }
    // Use / populate cache
    var row, cellData;
    var formatter = ext.type.order[column.type + '-pre'];
    var data = settings.data;
    for (var rowIdx = 0; rowIdx < data.length; rowIdx++) {
        // Sparse array
        if (!data[rowIdx]) {
            continue;
        }
        row = data[rowIdx];
        if (row && !row.orderCache) {
            row.orderCache = [];
        }
        if (row && (!row.orderCache[colIdx] || customSort)) {
            cellData = customSort
                ? customData[rowIdx] // If there was a custom sort function, use data from there
                : getCellData(settings, rowIdx, colIdx, 'sort');
            row.orderCache[colIdx] = formatter
                ? formatter(cellData, settings)
                : cellData;
        }
    }
}

/**
 * Alter the display settings to change the page
 *
 * @param settings DataTables settings object
 * @param action Paging action to take: "first", "previous", "next" or "last" or
 *   page number to jump to (integer)
 * @param redraw Automatically draw the update or not
 * @returns true page has changed, false - no change
 */
function pageChange(settings, action, redraw) {
    var start = settings.displayStart, len = settings.pageLength, records = recordsDisplay(settings);
    if (records === 0 || len === -1) {
        start = 0;
    }
    else if (typeof action === 'number') {
        start = action * len;
        if (start > records) {
            start = 0;
        }
    }
    else if (action == 'first') {
        start = 0;
    }
    else if (action == 'previous') {
        start = len >= 0 ? start - len : 0;
        if (start < 0) {
            start = 0;
        }
    }
    else if (action == 'next') {
        if (start + len < records) {
            start += len;
        }
    }
    else if (action == 'last') {
        start = Math.floor((records - 1) / len) * len;
    }
    else if (action === 'ellipsis') {
        return;
    }
    else {
        log(settings, 0, 'Unknown paging action: ' + action, 5);
    }
    var changed = settings.displayStart !== start;
    settings.displayStart = start;
    callbackFire(settings, null, changed ? 'page' : 'page-nc', [settings]);
    if (changed && redraw) {
        draw(settings);
    }
    return changed;
}

/**
 * State information for a table
 *
 * @param settings DataTables settings object
 */
function saveState(settings) {
    if (settings.loadingState) {
        return;
    }
    // Sort state saving uses [[idx, order]] structure.
    var sorting = [];
    sortResolve(settings, sorting, settings.order);
    /* Store the interesting variables */
    var columns = settings.columns;
    var state = {
        columns: settings.columns.map(function (col, i) {
            return {
                name: col.name,
                visible: col.visible,
                search: Object.assign({}, settings.searches[i])
            };
        }),
        length: settings.pageLength,
        order: sorting.map(function (sort) {
            // If a column name is available, use it
            return columns[sort[0]] && columns[sort[0]].name
                ? [columns[sort[0]].name, sort[1]]
                : sort.slice();
        }),
        search: Object.assign({}, settings.searches['*']),
        searchGroups: Object.keys(settings.searches)
            .filter(c => c.includes(',')) // Limit to only multi-column subsets
            .map(c => Object.assign({}, settings.searches[c])),
        start: settings.displayStart,
        time: +new Date()
    };
    settings.stateSaved = state;
    callbackFire(settings, 'stateSaveParams', 'stateSaveParams', [
        settings,
        state
    ]);
    if (settings.features.stateSave && !settings.destroying) {
        settings.stateSaveCallback.call(settings.instance, settings, state);
    }
}
/**
 * Attempt to load a saved table state
 *
 * @param settings dataTables settings object
 * @param callback Callback to execute when the state has been loaded
 */
function loadState(settings, callback) {
    if (!settings.features.stateSave) {
        callback();
        return;
    }
    var loaded = function (state, ignoreTime = false) {
        implementState(settings, state, ignoreTime, callback);
    };
    var state = settings.stateLoadCallback.call(settings.instance, settings, loaded);
    if (state !== undefined) {
        implementState(settings, state, false, callback);
    }
    // otherwise, wait for the loaded callback to be executed
    return true;
}
function implementState(settings, s, ignoreTime, callback) {
    var i, iLen;
    var columns = settings.columns;
    var currentNames = pluck(settings.columns, 'name');
    settings.loadingState = true;
    // When StateRestore was introduced the state could now be implemented at
    // any time Not just initialisation. To do this an api instance is required
    // in some places
    var api = settings.initDone ? new Api(settings) : null;
    if (!ignoreTime) {
        if (!s || !s.time) {
            settings.loadingState = false;
            callback();
            return;
        }
        // Reject old data
        var duration = settings.stateDuration;
        if (duration > 0 && s.time < +new Date() - duration * 1000) {
            settings.loadingState = false;
            callback();
            return;
        }
    }
    // Allow custom and plug-in manipulation functions to alter the saved data
    // set and cancelling of loading by returning false
    var abStateLoad = callbackFire(settings, 'stateLoadParams', 'stateLoadParams', [settings, s]);
    if (abStateLoad.indexOf(false) !== -1) {
        settings.loadingState = false;
        callback();
        return;
    }
    // Store the saved state so it might be accessed at any time
    settings.stateLoaded = assignDeep({}, s);
    // This is needed for ColReorder, which has to happen first to allow all
    // the stored indexes to be usable. It is not publicly documented.
    callbackFire(settings, null, 'stateLoadInit', [settings, s], true);
    // Page Length
    if (s.length !== undefined) {
        // If already initialised just set the value directly so that the select
        // element is also updated
        if (api) {
            api.page.len(s.length);
        }
        else {
            settings.pageLength = s.length;
        }
    }
    // Restore key features
    if (s.start !== undefined) {
        if (api === null) {
            settings.displayStart = s.start;
            settings.displayStartInit = s.start;
        }
        else {
            pageChange(settings, s.start / settings.pageLength);
        }
    }
    // Order
    if (s.order !== undefined) {
        settings.order = [];
        for (let i = 0; i < s.order.length; i++) {
            let col = s.order[i];
            let set = [col[0], col[1]];
            // A column name was stored and should be used for restore
            if (typeof col[0] === 'string') {
                // Find the name from the current list of column names
                let idx = currentNames.indexOf(col[0]);
                if (idx < 0) {
                    // If the column was not found ignore it and continue
                    continue;
                }
                set[0] = idx;
            }
            else if (set[0] >= columns.length) {
                // If the column index is out of bounds ignore it and continue
                continue;
            }
            settings.order.push(set);
        }
    }
    // Search
    if (s.search !== undefined) {
        Object.assign(settings.searches['*'], s.search);
    }
    if (s.searchGroups) {
        s.searchGroups.forEach(group => {
            if (group.columns) {
                let index = group.columns.join(',');
                settings.searches[index] = create$2(group);
            }
        });
    }
    // Columns
    if (s.columns) {
        var set = s.columns;
        var incoming = pluck(s.columns, 'name');
        // Check if it is a 2.2 style state object with a `name` property for
        // the columns, and if the name was defined. If so, then create a new
        // array that will map the state object given, to the current columns
        // (don't bother if they are already matching tho).
        if (incoming.join('').length &&
            incoming.join('') !== currentNames.join('')) {
            set = [];
            // For each column, try to find the name in the incoming array
            for (i = 0; i < currentNames.length; i++) {
                if (currentNames[i] != '') {
                    var idx = incoming.indexOf(currentNames[i]);
                    if (idx >= 0) {
                        set.push(s.columns[idx]);
                    }
                    else {
                        // No matching column name in the state's columns, so
                        // this might be a new column and thus can't have a
                        // state already.
                        set.push({});
                    }
                }
                else {
                    // If no name, but other columns did have a name, then there
                    // is no knowing where this one came from originally so it
                    // can't be restored.
                    set.push({});
                }
            }
        }
        // If the number of columns to restore is different from current, then
        // all bets are off.
        if (set.length === columns.length) {
            for (i = 0, iLen = set.length; i < iLen; i++) {
                var col = set[i];
                // Visibility
                if (col.visible !== undefined) {
                    // If the api is defined, the table has been initialised so
                    // we need to use it rather than internal settings
                    if (api) {
                        // Don't redraw the columns on every iteration of this
                        // loop, we will do this at the end instead
                        api.column(i).visible(col.visible, false);
                    }
                    else {
                        columns[i].visible = col.visible;
                    }
                }
                // Search
                if (col.search !== undefined) {
                    Object.assign(settings.searches[i], col.search);
                    // If out of order due to a change in order from named
                    // columns we need to make sure the index is correct
                    settings.searches[i].columns = [i];
                }
            }
            // If the api is defined then we need to adjust the columns once the
            // visibility has been changed
            if (api) {
                api.one('draw', function () {
                    api.columns.adjust();
                });
            }
        }
    }
    settings.loadingState = false;
    callbackFire(settings, 'stateLoaded', 'stateLoaded', [settings, s]);
    callback();
}

/**
 * Draw the table for the first time, adding all required features
 *
 * @param settings DataTables settings object
 */
function initialise(settings) {
    var i;
    var init = settings.init;
    var deferLoading = settings.deferLoading;
    var dataSrc = dataSource(settings);
    // Ensure that the table data is fully initialised
    if (!settings.initialised) {
        setTimeout(function () {
            initialise(settings);
        }, 200);
        return;
    }
    // Build the header / footer for the table
    buildHead(settings, 'header');
    buildHead(settings, 'footer');
    // Load the table's state (if needed) and then render around it and draw
    loadState(settings, function () {
        // Then draw the header / footer
        drawHead(settings, settings.header);
        drawHead(settings, settings.footer);
        // Cache the paging start point, as the first redraw will reset it
        var iAjaxStart = settings.displayStartInit;
        // Local data load
        // Check if there is data passing into the constructor
        if (init && init.data) {
            for (i = 0; i < init.data.length; i++) {
                addData(settings, init.data[i]);
            }
        }
        else if (deferLoading || dataSrc == 'dom') {
            // Grab the data from the page
            addTr(settings, Dom.s(settings.tbody).children('tr'));
        }
        // Filter not yet applied - copy the display master
        settings.display = settings.displayMaster.slice();
        // Enable features
        createLayout(settings);
        sortInit(settings);
        colGroup(settings);
        /* Okay to show that something is going on now */
        processingDisplay(settings, true);
        callbackFire(settings, null, 'preInit', [settings], true);
        // If there is default sorting required - let's do it. The sort function
        // will do the drawing for us. Otherwise we draw the table regardless of
        // the Ajax source - this allows the table to look initialised for Ajax
        // sourcing data (show 'loading' message possibly)
        reDraw(settings);
        // Server-side processing init complete is done by _fnAjaxUpdateDraw
        if (dataSrc != 'ssp' || deferLoading) {
            // if there is an ajax source load the data
            if (dataSrc == 'ajax') {
                buildAjax(settings, {}, function (json) {
                    var aData = ajaxDataSrc(settings, json, false);
                    // Got the data - add it to the table
                    for (i = 0; i < aData.length; i++) {
                        addData(settings, aData[i]);
                    }
                    // Reset the init display for cookie saving. We've already
                    // done a filter, and therefore cleared it before. So we
                    // need to make it appear 'fresh'
                    settings.displayStartInit = iAjaxStart;
                    reDraw(settings);
                    processingDisplay(settings, false);
                    initComplete(settings);
                });
            }
            else {
                initComplete(settings);
                processingDisplay(settings, false);
            }
        }
    });
}
/**
 * Draw the table for the first time, adding all required features
 *
 * @param settings DataTables settings object
 */
function initComplete(settings) {
    if (settings.initDone) {
        return;
    }
    var args = [settings, settings.json];
    settings.initDone = true;
    // If the footer element is empty after initialisation, then remove it
    let tfoot = Dom.s(settings.tfoot);
    if (tfoot.children().count() === 0) {
        tfoot.remove();
    }
    // Table is fully set up and we have data, so calculate the
    // column widths
    adjustColumnSizing(settings);
    callbackFire(settings, null, 'plugin-init', args, true);
    callbackFire(settings, 'init', 'init', args, true);
}

/**
 * Create an Ajax call based on the table's settings, taking into account that
 * parameters can have multiple forms, and backwards compatibility.
 *
 * @param settings DataTables settings object
 * @param data Data to send to the server, required by DataTables - may be
 *   augmented by developer callbacks
 * @param fn Callback function to run when data is obtained
 */
function buildAjax(settings, data, fn) {
    var ajaxData;
    var ajaxConfig = settings.ajax;
    var instance = settings.instance;
    var callback = function (json) {
        var status = settings.jqXHR ? settings.jqXHR.status : null;
        if (json === null || (typeof status === 'number' && status == 204)) {
            json = {};
            ajaxDataSrc(settings, json, []);
        }
        var error = json.error || json.sError;
        if (error) {
            log(settings, 0, error);
        }
        // Microsoft often wrap JSON as a string in another JSON object Let's
        // handle that automatically
        if (json.d && typeof json.d === 'string') {
            try {
                json = JSON.parse(json.d);
            }
            catch (e) {
                // noop
            }
        }
        settings.json = json;
        callbackFire(settings, null, 'xhr', [settings, json, settings.jqXHR], true);
        fn(json);
    };
    if (util.is.plainObject(ajaxConfig) && ajaxConfig.data) {
        ajaxData = ajaxConfig.data;
        var newData = typeof ajaxData === 'function'
            ? ajaxData(data, settings) // fn can manipulate data or return
            : ajaxData; // an object or array to merge
        // If the function returned something, use that alone
        data =
            typeof ajaxData === 'function' && newData
                ? newData
                : util.object.assignDeep(data, newData);
        // Remove the data property as we've resolved it already and don't want
        // jQuery to do it again (it is restored at the end of the function)
        delete ajaxConfig.data;
    }
    var baseAjax = {
        url: typeof ajaxConfig === 'string' ? ajaxConfig : '',
        data: data,
        success: callback,
        dataType: 'json',
        cache: false,
        type: settings.serverMethod,
        error: function (xhr, error) {
            var ret = callbackFire(settings, null, 'xhr', [settings, null, settings.jqXHR], true);
            if (ret.indexOf(false) === -1) {
                if (error == 'parsererror') {
                    log(settings, 0, 'Invalid JSON response', 1);
                }
                else if (xhr.readyState === 4) {
                    log(settings, 0, 'Ajax error', 7);
                }
            }
            processingDisplay(settings, false);
        }
    };
    // If `ajax` option is an object, extend and override our default base
    if (util.is.plainObject(ajaxConfig)) {
        util.object.assign(baseAjax, ajaxConfig);
    }
    // Store the data submitted for the API
    settings.ajaxData = data;
    // Allow plug-ins and external processes to modify the data
    callbackFire(settings, null, 'preXhr', [settings, data, baseAjax], true);
    if (typeof ajaxConfig === 'function') {
        // Is a function - let the caller define what needs to be done
        settings.jqXHR = ajaxConfig.call(instance, data, callback, settings);
    }
    else if (ajaxConfig &&
        typeof ajaxConfig !== 'string' &&
        ajaxConfig.url === '') {
        // No url, so don't load any data. Just apply an empty data array
        // to the object for the callback.
        var empty = {};
        ajaxDataSrc(settings, empty, []);
        callback(empty);
    }
    else {
        // Object to extend the base settings
        settings.jqXHR = util.ajax(baseAjax);
    }
    // Restore for next time around
    if (ajaxData) {
        ajaxConfig.data = ajaxData;
    }
}
/**
 * Update the table using an Ajax call
 *
 * @param settings DataTables settings object
 * @returns Block the table drawing or not
 */
function ajaxUpdate(settings) {
    settings.drawCount++;
    processingDisplay(settings, true);
    buildAjax(settings, ajaxParameters(settings), function (json) {
        ajaxUpdateDraw(settings, json);
    });
}
function functionOrValue(val) {
    return typeof val === 'function' ? 'function' : val.toString();
}
/**
 * Build up the parameters in an object needed for a server-side processing
 * request.
 *
 * @param settings DataTables settings object
 * @returns Block the table drawing or not
 */
function ajaxParameters(settings) {
    var columns = settings.columns, features = settings.features, searches = settings.searches, searchesFixed = settings.searchesFixed, colData = function (idx, prop) {
        return typeof columns[idx][prop] === 'function'
            ? 'function'
            : columns[idx][prop];
    };
    return {
        draw: settings.drawCount,
        columns: columns.map(function (column, i) {
            return {
                data: colData(i, 'data'),
                name: column.name,
                searchable: column.searchable,
                orderable: column.orderable,
                search: {
                    value: searches[i]
                        ? functionOrValue(searches[i].search)
                        : '',
                    regex: searches[i] ? searches[i].regex : false,
                    fixed: searchesFixed[i]
                        ? Object.keys(searchesFixed[i]).map(name => ({
                            name: name,
                            term: functionOrValue(searchesFixed[i][name].search)
                        }))
                        : []
                }
            };
        }),
        order: sortFlatten(settings).map(function (val) {
            return {
                column: val.col,
                dir: val.dir,
                name: colData(val.col, 'name')
            };
        }),
        start: settings.displayStart,
        length: features.paging ? settings.pageLength : -1,
        search: {
            value: functionOrValue(searches['*'].search),
            regex: searches['*'].regex,
            fixed: Object.keys(settings.searchesFixed['*']).map(name => ({
                name: name,
                term: functionOrValue(settings.searchesFixed['*'][name].search)
            })),
            groups: Object.keys(settings.searches)
                .filter(c => c.includes(',')) // Limit to only multi-column subsets
                .map(c => ({
                columns: settings.searches[c].columns || [],
                term: functionOrValue(settings.searches[c].search)
            })),
            groupsFixed: Object.keys(settings.searchesFixed)
                .filter(c => c.includes(',')) // Limit to only multi-column subsets
                .map(c => {
                let searches = settings.searchesFixed[c];
                return Object.keys(searches).map(n => ({
                    columns: searches[n].columns || [],
                    name: n,
                    term: functionOrValue(searches[n].search)
                }));
            })
                .flat()
        }
    };
}
/**
 * Data the data from the server (nuking the old) and redraw the table
 *
 * @param settings DataTables settings object
 * @param json json data return from the server.
 */
function ajaxUpdateDraw(settings, json) {
    var data = ajaxDataSrc(settings, json, false);
    var drawUnique = ajaxDataSrcParam(settings, 'draw', json);
    var recordsTotal = ajaxDataSrcParam(settings, 'recordsTotal', json);
    var recordsFiltered = ajaxDataSrcParam(settings, 'recordsFiltered', json);
    var existingTypes = settings.columns.map(c => c.type).join(',');
    if (drawUnique !== undefined) {
        // Protect against out of sequence returns
        if (drawUnique * 1 < settings.drawCount) {
            return;
        }
        settings.drawCount = drawUnique * 1;
    }
    // No data in returned object, so rather than an array, we show an empty
    // table
    if (!data) {
        data = [];
    }
    clearTable(settings);
    settings.recordsTotal = parseInt(recordsTotal, 10);
    settings.recordsDisplay = parseInt(recordsFiltered, 10);
    for (var i = 0, iLen = data.length; i < iLen; i++) {
        addData(settings, data[i]);
    }
    settings.display = settings.displayMaster.slice();
    columnTypes(settings, existingTypes);
    draw(settings, true);
    initComplete(settings);
    processingDisplay(settings, false);
}
/**
 * Get the data from the JSON data source to use for drawing a table.
 *
 * @param settings DataTables settings object
 * @param json Data source object / array from the server
 * @param write Array or object to write the data to
 * @return Array of data to use
 */
function ajaxDataSrc(settings, json, write) {
    var dataProp = 'data';
    if (util.is.plainObject(settings.ajax) &&
        settings.ajax.dataSrc !== undefined) {
        // Could in inside a `dataSrc` object, or not!
        var dataSrc = settings.ajax.dataSrc;
        // string, function and object are valid types
        if (typeof dataSrc === 'string' || typeof dataSrc === 'function') {
            dataProp = dataSrc;
        }
        else if (dataSrc.data !== undefined) {
            dataProp = dataSrc.data;
        }
    }
    if (!write) {
        if (dataProp === 'data') {
            // If the default, then we still want to support the old style, and
            // safely ignore it if possible
            return json.aaData || json[dataProp];
        }
        return dataProp !== '' ? util.get(dataProp)(json) : json;
    }
    // set
    util.set(dataProp)(json, write);
}
/**
 * Very similar to ajaxDataSrc, but for the other SSP properties
 *
 * @param settings DataTables settings object
 * @param param Target parameter
 * @param json JSON data
 * @returns Resolved value
 */
function ajaxDataSrcParam(settings, param, json) {
    var dataSrc = util.is.plainObject(settings.ajax)
        ? settings.ajax.dataSrc // TODO
        : null;
    if (dataSrc && dataSrc[param]) {
        // Get from custom location
        return util.data.get(dataSrc[param])(json);
    }
    // else - Default behaviour
    var old = '';
    // Legacy support
    if (param === 'draw') {
        old = 'sEcho';
    }
    else if (param === 'recordsTotal') {
        old = 'iTotalRecords';
    }
    else if (param === 'recordsFiltered') {
        old = 'iTotalDisplayRecords';
    }
    return json[old] !== undefined ? json[old] : json[param];
}

const __filter_div = Dom.c('div').get(0);
const __filter_div_textContent = __filter_div.textContent !== undefined;
/**
 * Filter the table using both the global filter and column based filtering
 *
 * @param settings DataTables settings object
 */
function filterComplete(settings) {
    settings.columns;
    // In server-side processing all filtering is done by the server, so no
    // point hanging around here
    if (dataSource(settings) != 'ssp') {
        // Check if any of the rows were invalidated
        filterData(settings);
        // Start from the full data set
        settings.display = settings.displayMaster.slice();
        // Column set filters first
        util.object.each(settings.searches, (key, s) => {
            filter(settings.display, settings, s.search, s);
        });
        // Fixed (named) filters next
        util.object.each(settings.searchesFixed, function (columns) {
            util.object.each(settings.searchesFixed[columns], function (name, s) {
                filter(settings.display, settings, s.search, s);
            });
        });
        // And finally legacy global filtering
        filterCustom(settings);
    }
    // Tell the draw function we have been filtering
    settings.wasFiltered = true;
    callbackFire(settings, null, 'search', [settings]);
}
/**
 * Apply custom filtering functions
 *
 * This is legacy now that we have named functions, but it is widely used
 * from 1.x, so it is not yet deprecated.
 *
 * @param settings DataTables settings object
 */
function filterCustom(settings) {
    let filters = ext.search;
    let displayRows = settings.display;
    let row, rowIdx;
    for (let i = 0, iLen = filters.length; i < iLen; i++) {
        let rows = [];
        // Loop over each row and see if it should be included
        for (let j = 0, jen = displayRows.length; j < jen; j++) {
            rowIdx = displayRows[j];
            row = settings.data[rowIdx];
            if (row &&
                filters[i](settings, row.searchCellCache, rowIdx, row.data, j)) {
                rows.push(rowIdx);
            }
        }
        // So the array reference doesn't break set the results into the
        // existing array
        displayRows.length = 0;
        arrayApply(displayRows, rows);
    }
}
/**
 * Filter the data table based on user input and draw the table
 *
 * @param searchRows
 * @param settings
 * @param input
 * @param options
 * @returns
 */
function filter(searchRows, settings, input, options) {
    if (input === '') {
        return;
    }
    let i = 0;
    let matched = [];
    // Search term can be a function, regex or string - if a string we apply our
    // smart filtering regex (assuming the options require that)
    let searchFunc = typeof input === 'function' ? input : null;
    let rpSearch = input instanceof RegExp
        ? input
        : searchFunc
            ? null
            : filterCreateSearch(input, options);
    let columns = options.columns
        ? options.columns
        : util.array.range(settings.columns.length);
    // Then for each row, does the test pass. If not, lop the row from the array
    for (i = 0; i < searchRows.length; i++) {
        let row = settings.data[searchRows[i]];
        if (row) {
            // Get the data array based on the columns to include in the search
            let data = util.array.selectiveJoin(row.searchCellCache, columns);
            // Run the search action
            if ((searchFunc &&
                searchFunc(data, row.data, searchRows[i], columns.length === 1 ? columns[0] : columns // compat
                )) ||
                (rpSearch && typeof data === 'string' && rpSearch.test(data))) {
                matched.push(searchRows[i]);
            }
        }
    }
    // Mutate the searchRows array
    searchRows.length = matched.length;
    for (i = 0; i < matched.length; i++) {
        searchRows[i] = matched[i];
    }
}
/**
 * Build a regular expression object suitable for searching a table
 */
function filterCreateSearch(searchIn, inOpts) {
    let not = [];
    let options = Object.assign({}, {
        boundary: false,
        caseInsensitive: true,
        exact: false,
        regex: false,
        smart: true
    }, inOpts);
    let search = typeof searchIn !== 'string' ? searchIn.toString() : searchIn;
    // Remove diacritics if normalize is set up to do so
    search = util.diacritics(search);
    if (options.exact) {
        return new RegExp('^' + util.escapeRegex(search) + '$', options.caseInsensitive ? 'i' : '');
    }
    search = options.regex ? search : util.escapeRegex(search);
    if (options.smart) {
        /* For smart filtering we want to allow the search to work regardless of
         * word order. We also want double quoted text to be preserved, so word
         * order is important - a la google. And a negative look around for
         * finding rows which don't contain a given string.
         *
         * So this is the sort of thing we want to generate:
         *
         * ^(?=.*?\bone\b)(?=.*?\btwo three\b)(?=.*?\bfour\b).*$
         */
        let parts = search.match(/!?["\u201C][^"\u201D]+["\u201D]|[^ ]+/g) || [
            ''
        ];
        let a = parts.map(function (word) {
            let negative = false;
            let m;
            // Determine if it is a "does not include"
            if (word.charAt(0) === '!') {
                negative = true;
                word = word.substring(1);
            }
            // Strip the quotes from around matched phrases
            if (word.charAt(0) === '"') {
                m = word.match(/^"(.*)"$/);
                word = m ? m[1] : word;
            }
            else if (word.charAt(0) === '\u201C') {
                // Smart quote match (iPhone users)
                m = word.match(/^\u201C(.*)\u201D$/);
                word = m ? m[1] : word;
            }
            // For our "not" case, we need to modify the string that is
            // allowed to match at the end of the expression.
            if (negative) {
                if (word.length > 1) {
                    not.push('(?!' + word + ')');
                }
                word = '';
            }
            return word.replace(/"/g, '');
        });
        let match = not.length ? not.join('') : '';
        let boundary = options.boundary ? '\\b' : '';
        search =
            '^(?=.*?' +
                boundary +
                a.join(')(?=.*?' + boundary) +
                ')(' +
                match +
                '.)*$';
    }
    return new RegExp(search, options.caseInsensitive ? 'i' : '');
}
// Update the filtering data for each row if needed (by invalidation or first
// run)
function filterData(settings) {
    let columns = settings.columns;
    let data = settings.data;
    let column;
    let j, jen, cellData, row;
    let wasInvalidated = false;
    for (let rowIdx = 0; rowIdx < data.length; rowIdx++) {
        if (!data[rowIdx]) {
            continue;
        }
        row = data[rowIdx];
        if (row && !row.searchCellCache) {
            const rowFilterData = [];
            for (j = 0, jen = columns.length; j < jen; j++) {
                column = columns[j];
                if (column.searchable) {
                    cellData = getCellData(settings, rowIdx, j, 'filter');
                    // Search in DataTables is string based
                    if (cellData === null) {
                        cellData = '';
                    }
                    if (typeof cellData !== 'string' && cellData.toString) {
                        cellData = cellData.toString();
                    }
                }
                else {
                    cellData = '';
                }
                // If it looks like there is an HTML entity in the string,
                // attempt to decode it so sorting works as expected. Note that
                // we could use a single line of jQuery to do this, but the DOM
                // method used here is much faster
                // https://jsperf.com/html-decode
                if (cellData.indexOf && cellData.indexOf('&') !== -1) {
                    __filter_div.innerHTML = cellData;
                    cellData = __filter_div_textContent
                        ? __filter_div.textContent
                        : __filter_div.innerText;
                }
                if (cellData.replace) {
                    cellData = cellData.replace(/[\r\n\u2028]/g, '');
                }
                rowFilterData.push(cellData);
            }
            row.searchCellCache = rowFilterData;
            row.searchRowCache = rowFilterData.join('  ');
            wasInvalidated = true;
        }
    }
    return wasInvalidated;
}

/**
 * Render and cache a row's display data for the columns, if required
 *
 * @param settings DataTables settings object
 * @param rowIdx Row index
 * @returns Array with display information
 */
function getRowDisplay(settings, rowIdx) {
    var rowModal = settings.data[rowIdx];
    var columns = settings.columns;
    if (!rowModal) {
        return [];
    }
    if (!rowModal.displayData) {
        // Need to render and cache
        rowModal.displayData = [];
        for (var colIdx = 0, len = columns.length; colIdx < len; colIdx++) {
            rowModal.displayData.push(getCellData(settings, rowIdx, colIdx, 'display'));
        }
    }
    return rowModal.displayData;
}
/**
 * Create a new TR element (and it's TD children) for a row
 *
 * @param settings DataTables settings object
 * @param rowIdx Row to consider
 * @param trIn TR element to add to the table - optional. If not given,
 *   DataTables will create a row automatically
 * @param tds Array of TD|TH elements for the row - must be given if trIn is.
 */
function createTr(settings, rowIdx, trIn, tds) {
    var row = settings.data[rowIdx], cells = [], tr, td, column, i, iLen, create, trClass = settings.classes.tbody.row;
    if (row && row.tr === null) {
        let rowData = row.data;
        tr = trIn || document.createElement('tr');
        row.tr = tr;
        row.cells = cells;
        Dom.s(tr).classAdd(trClass);
        // Use a private property on the node to allow reserve mapping from the node
        // to the aoData array for fast look up
        tr._DT_RowIndex = rowIdx;
        // Special parameters can be given by the data source to be used on the
        // row
        rowAttributes(settings, row);
        /* Process each column */
        for (i = 0, iLen = settings.columns.length; i < iLen; i++) {
            column = settings.columns[i];
            create = trIn && tds && tds[i] ? false : true;
            td = create
                ? document.createElement(column.cellType)
                : tds[i];
            if (!td) {
                log(settings, 0, 'Incorrect column count', 18);
            }
            td._DT_CellIndex = {
                row: rowIdx,
                column: i
            };
            cells.push(td);
            var display = getRowDisplay(settings, rowIdx);
            // Need to create the HTML if new, or if a rendering function is
            // defined
            if (create ||
                ((column.render || column.data !== i) &&
                    (!util.is.plainObject(column.data) ||
                        (column.data &&
                            column.data._ !== i + '.display')))) {
                writeCell(td, display[i]);
            }
            // column class
            Dom.s(td).classAdd(column.className);
            // Visibility - add or remove as required
            if (column.visible && create) {
                tr.appendChild(td);
            }
            else if (!column.visible && !create) {
                td.parentNode.removeChild(td);
            }
            if (column.createdCell) {
                column.createdCell.call(settings.instance, td, getCellData(settings, rowIdx, i), rowData, rowIdx, i);
            }
        }
        callbackFire(settings, 'rowCreated', 'row-created', [
            tr,
            rowData,
            rowIdx,
            cells
        ]);
    }
    else if (row) {
        Dom.s(row.tr).classAdd(trClass);
    }
}
/**
 * Add attributes to a row based on the special `DT_*` parameters in a data
 * source object.
 *
 * @param settings DataTables settings object
 * @param row Row object for the row to be modified
 */
function rowAttributes(settings, row) {
    var tr = row.tr;
    var data = row.data;
    if (tr) {
        var id = settings.rowIdFn(data);
        if (id) {
            tr.id = id;
        }
        if (data.DT_RowClass) {
            // Remove any classes added by DT_RowClass before
            var a = data.DT_RowClass.split(' ');
            row.addedClasses = row.addedClasses
                ? util.unique(row.addedClasses.concat(a))
                : a;
            Dom.s(tr)
                .classRemove(row.addedClasses.join(' '))
                .classAdd(data.DT_RowClass);
        }
        if (data.DT_RowAttr) {
            Dom.s(tr).attr(data.DT_RowAttr);
        }
        if (data.DT_RowData) {
            Dom.s(tr).data(data.DT_RowData);
        }
    }
}
/**
 * Create the HTML header for the table
 *
 * @param settings DataTable instance
 * @param side If the header or footer should be used
 * @returns
 */
function buildHead(settings, side) {
    let classes = settings.classes;
    let columns = settings.columns;
    let i, iLen, row;
    let target = Dom.s(side === 'header' ? settings.thead : settings.tfoot);
    let titleProp = side === 'header' ? 'title' : side;
    // Footer might be defined
    if (!target) {
        return;
    }
    // If no cells yet and we have content for them, then create
    if (side === 'header' ||
        util.array.pluck(settings.columns, titleProp).join('')) {
        row = target.find('tr');
        // Add a row if needed
        if (!row.count()) {
            row = Dom.c('tr').appendTo(target);
        }
        // Add the number of cells needed to make up to the number of columns
        if (row.count() === 1) {
            let cellCount = 0;
            row.find('td, th').each(el => {
                cellCount += el.colSpan;
            });
            for (i = cellCount, iLen = columns.length; i < iLen; i++) {
                Dom.c('th')
                    .html(columns[i][titleProp] || '')
                    .appendTo(row);
            }
        }
    }
    let detected = detectHeader(settings, target.get(0), true);
    if (side === 'header') {
        settings.header = detected;
        target.find('tr').classAdd(classes.thead.row);
    }
    else {
        settings.footer = detected;
        target.find('tr').classAdd(classes.tfoot.row);
    }
    // Every cell needs to be passed through the renderer
    target
        .children('tr')
        .children('th, td')
        .each(el => {
        // Should just be able to do `renderer(settings, side)` here but
        // Typescript doesn't like it, despite it already being constrained!
        let runner = side === 'header'
            ? renderer(settings, 'header')
            : renderer(settings, 'footer');
        runner(settings, Dom.s(el), classes);
    });
}
/**
 * Build a layout structure for a header or footer
 *
 * @param settings DataTables settings
 * @param source Source layout array
 * @param incColumns What columns should be included
 * @returns Layout array in column index order
 */
function headerLayout(settings, source, incColumns) {
    var row, column, cell;
    var local = [];
    var structure = [];
    var columns = settings.columns;
    var columnCount = columns.length;
    var rowspan, colspan;
    if (!source) {
        return;
    }
    // Default is to work on only visible columns
    if (!incColumns) {
        incColumns = util.array.range(columnCount).filter(function (idx) {
            return columns[idx].visible;
        });
    }
    // Make a copy of the master layout array, but with only the columns we want
    for (row = 0; row < source.length; row++) {
        // Remove any columns we haven't selected
        local[row] = source[row].slice().filter(function (c, i) {
            return incColumns.includes(i);
        });
        // Prep the structure array - it needs an element for each row
        structure.push([]);
    }
    for (row = 0; row < local.length; row++) {
        for (column = 0; column < local[row].length; column++) {
            rowspan = 1;
            colspan = 1;
            // Check to see if there is already a cell (row/colspan) covering
            // our target insert point. If there is, then there is nothing to
            // do.
            if (structure[row][column] === undefined) {
                cell = local[row][column].cell;
                // Expand for rowspan
                while (local[row + rowspan] !== undefined &&
                    local[row][column].cell == local[row + rowspan][column].cell) {
                    structure[row + rowspan][column] = null;
                    rowspan++;
                }
                // And for colspan
                while (local[row][column + colspan] !== undefined &&
                    local[row][column].cell == local[row][column + colspan].cell) {
                    // Which also needs to go over rows
                    for (var k = 0; k < rowspan; k++) {
                        structure[row + k][column + colspan] = null;
                    }
                    colspan++;
                }
                var titleSpan = Dom.s(cell).find('.dt-column-title');
                structure[row][column] = {
                    cell: cell,
                    colspan: colspan,
                    rowspan: rowspan,
                    title: titleSpan.count()
                        ? titleSpan.html()
                        : Dom.s(cell).html()
                };
            }
        }
    }
    return structure;
}
/**
 * Draw the header (or footer) element based on the column visibility states.
 *
 * @param settings DataTables settings object
 * @param source Layout array from detectHeader
 */
function drawHead(settings, source) {
    let layout = headerLayout(settings, source);
    let tr;
    if (!layout) {
        return;
    }
    for (let row = 0; row < source.length; row++) {
        tr = source[row].row;
        // All cells are going to be replaced, so empty out the row
        if (tr) {
            Dom.s(tr).detachChildren();
        }
        for (let column = 0; column < layout[row].length; column++) {
            let point = layout[row][column];
            if (point) {
                Dom.s(point.cell)
                    .appendTo(tr)
                    .attr('rowspan', point.rowspan)
                    .attr('colspan', point.colspan);
            }
        }
    }
}
/**
 * Insert the required TR nodes into the table for display
 *
 * @param settings DataTables settings object
 * @param ajaxComplete true after ajax call to complete rendering
 */
function draw(settings, ajaxComplete) {
    // Allow for state saving and a custom start position
    setStartPosition(settings);
    // Provide a pre-callback function which can be used to cancel the draw is
    // false is returned
    var aPreDraw = callbackFire(settings, 'preDraw', 'preDraw', [settings]);
    if (aPreDraw.indexOf(false) !== -1) {
        processingDisplay(settings, false);
        return;
    }
    var rowEls = [];
    var rowCount = 0;
    var isServerSide = dataSource(settings) == 'ssp';
    var display = settings.display;
    var start = settings.displayStart;
    var end = displayEnd(settings);
    var columns = settings.columns;
    var body = Dom.s(settings.tbody);
    settings.doingDraw = true;
    /* Server-side processing draw intercept */
    if (settings.deferLoading) {
        settings.deferLoading = false;
        settings.drawCount++;
        processingDisplay(settings, false);
    }
    else if (!isServerSide) {
        settings.drawCount++;
    }
    else if (!settings.destroying && !ajaxComplete) {
        // Show loading message for server-side processing
        if (settings.drawCount === 0) {
            body.empty().append(_emptyRow(settings));
        }
        ajaxUpdate(settings);
        return;
    }
    if (display.length !== 0) {
        var iStart = isServerSide ? 0 : start;
        var iEnd = isServerSide ? settings.data.length : end;
        for (var j = iStart; j < iEnd; j++) {
            var dataIdx = display[j];
            var data = settings.data[dataIdx];
            // Row has been deleted - can't be displayed
            if (data === null) {
                continue;
            }
            // Row node hasn't been created yet
            if (data.tr === null) {
                createTr(settings, dataIdx);
            }
            var nRow = data.tr;
            // Add various classes as needed
            for (var i = 0; i < columns.length; i++) {
                var col = columns[i];
                var td = data.cells[i];
                Dom.s(td)
                    .classAdd(col.type ? ext.type.className[col.type] : null) // auto class
                    .classAdd(settings.classes.tbody.cell); // all cells
            }
            // Row callback functions - might want to manipulate the row
            // rowCount and j are not currently documented. Are they at all
            // useful?
            callbackFire(settings, 'row', null, [
                nRow,
                data.data,
                rowCount,
                j,
                dataIdx
            ]);
            rowEls.push(nRow);
            rowCount++;
        }
    }
    else {
        rowEls[0] = _emptyRow(settings);
    }
    /* Header and footer callbacks */
    callbackFire(settings, 'header', 'header', [
        Dom.s(settings.thead).children('tr').get(0),
        getDataMaster(settings),
        start,
        end,
        display
    ]);
    callbackFire(settings, 'footer', 'footer', [
        Dom.s(settings.tfoot).children('tr').get(0),
        getDataMaster(settings),
        start,
        end,
        display
    ]);
    body.detachChildren().append(rowEls);
    // Empty table needs a specific class
    Dom.s(settings.tableWrapper).classToggle('dt-empty-footer', Dom.s(settings.tfoot).find('tr').count() === 0);
    // Call all required callback functions for the end of a draw
    callbackFire(settings, 'draw', 'draw', [settings], true);
    // Draw is complete, sorting and filtering must be as well
    settings.wasOrdered = false;
    settings.wasFiltered = false;
    settings.doingDraw = false;
}
/**
 * Redraw the table - taking account of the various features which are enabled
 *
 * @param settings DataTables settings object
 * @param holdPosition Keep the current paging position. By default the paging
 *    is reset to the first page
 * @param recompute Indicate if a rebuild of sort and filter should happen
 */
function reDraw(settings, holdPosition, recompute) {
    let features = settings.features, doSort = features.ordering, doFilter = features.searching;
    if (recompute === undefined || recompute === true) {
        // Resolve any column types that are unknown due to addition or
        // invalidation
        columnTypes(settings);
        columnWidths(settings);
        if (doSort) {
            sort(settings);
        }
        if (doFilter) {
            filterComplete(settings);
        }
        else {
            // No filtering, so we want to just use the display master
            settings.display = settings.displayMaster.slice();
        }
    }
    if (holdPosition !== true) {
        settings.displayStart = 0;
    }
    else {
        // Keep position, but make sure that there is actually data to display,
        // otherwise we need to rewind a bit (e.g. if rows were deleted)
        lengthOverflow(settings);
    }
    // Let any modules know about the draw hold position state (used by
    // scrolling internally)
    settings.drawHold = holdPosition;
    draw(settings);
    settings.api.one('draw', function () {
        settings.drawHold = false;
    });
}
/**
 * Table is empty - create a row with an empty message in it
 *
 * @param settings DataTables context
 */
function _emptyRow(settings) {
    let lang = settings.language;
    let zero = lang.zeroRecords;
    let dataSrc = dataSource(settings);
    // Make use of the fact that settings.json is only set once the initial data
    // has been loaded. Show loading when that isn't the case
    if ((dataSrc === 'ssp' || dataSrc === 'ajax') && !settings.json) {
        zero = lang.loadingRecords;
    }
    else if (lang.emptyTable && recordsTotal(settings) === 0) {
        zero = lang.emptyTable;
    }
    return Dom
        .c('tr')
        .append(Dom
        .c('td')
        .attr('colSpan', visibleColumns(settings))
        .classAdd(settings.classes.empty.row)
        .html(zero))
        .get(0);
}
/**
 * Use the DOM source to create up an array of header cells. The idea here is to
 * create a layout grid (array) of rows x columns, which contains a reference to
 * the cell at that point in the grid (regardless of col/rowspan), such that any
 * column / row could be removed and the new grid constructed.
 *
 * @param settings DataTables context
 * @param thead thead / tbody element
 * @param write If cells should be written (if required)
 * @returns Calculated layout array
 */
function detectHeader(settings, thead, write) {
    let columns = settings.columns;
    let rows = Dom.s(thead).children('tr');
    let row, loopCell;
    let i, k, l, len, shifted, column, colspan, rowspan;
    let titleRow = settings.titleRow;
    let isHeader = thead && thead.nodeName.toLowerCase() === 'thead';
    let layout = [];
    let isUnique;
    let shift = function (a, b, j) {
        let d = a[b];
        while (d[j]) {
            j++;
        }
        return j;
    };
    // We know how many rows there are in the layout - so prep it
    for (i = 0, len = rows.count(); i < len; i++) {
        layout.push([]);
    }
    for (i = 0, len = rows.count(); i < len; i++) {
        row = rows.get(i);
        column = 0;
        // For every cell in the row..
        loopCell = row.firstChild;
        while (loopCell) {
            if (loopCell.nodeName.toUpperCase() == 'TD' ||
                loopCell.nodeName.toUpperCase() == 'TH') {
                let cell = Dom.s(loopCell);
                let cols = [];
                // Get the col and rowspan attributes from the DOM and sanitise
                // them
                colspan = parseInt(cell.attr('colspan') || '1') || 1;
                rowspan = parseInt(cell.attr('rowspan') || '1') || 1;
                colspan =
                    !colspan || colspan === 0 || colspan === 1 ? 1 : colspan;
                rowspan =
                    !rowspan || rowspan === 0 || rowspan === 1 ? 1 : rowspan;
                // There might be colspan cells already in this row, so shift
                // our target accordingly
                shifted = shift(layout, i, column);
                // Cache calculation for unique columns
                isUnique = colspan === 1 ? true : false;
                // Perform header setup
                if (write) {
                    if (isUnique) {
                        // Allow column options to be set from HTML attributes
                        columnOptions(settings, shifted, escapeObject(cell.data()));
                        // Get the width for the column. This can be defined
                        // from the width attribute, style attribute or
                        // `columns.width` option
                        let columnDef = columns[shifted];
                        let width = cell.attr('width') || null;
                        let t = cell
                            .get(0)
                            .style.width.match(/width:\s*(\d+[pxem%]+)/);
                        if (t) {
                            width = t[1];
                        }
                        columnDef.widthOrig = columnDef.width || width;
                        if (isHeader) {
                            // Column title handling - can be user set, or read
                            // from the DOM This happens before the render, so
                            // the original is still in place
                            if (columnDef.title !== null &&
                                !columnDef.autoTitle) {
                                if ((titleRow === true && i === 0) || // top row
                                    (titleRow === false &&
                                        i === rows.count() - 1) || // bottom row
                                    titleRow === i || // specific row
                                    titleRow === null) {
                                    cell.html(columnDef.title);
                                }
                            }
                            if (!columnDef.title && isUnique) {
                                columnDef.title = util.string.stripHtml(cell.html());
                                columnDef.autoTitle = true;
                            }
                        }
                        else {
                            // Footer specific operations
                            if (columnDef.footer) {
                                cell.html(columnDef.footer);
                            }
                        }
                        // Fall back to the aria-label attribute on the table
                        // header if no ariaTitle is provided.
                        if (!columnDef.ariaTitle) {
                            columnDef.ariaTitle =
                                cell.attr('aria-label') || columnDef.title;
                        }
                        // Column specific class names
                        if (columnDef.className) {
                            cell.classAdd(columnDef.className);
                        }
                    }
                    // Wrap the column title so we can write to it in future
                    if (cell.find('div.dt-column-title').count() === 0) {
                        Dom.c('div')
                            .classAdd('dt-column-title')
                            .append(Array.from(cell.get(0).childNodes))
                            .appendTo(cell);
                    }
                    if (settings.orderIndicators &&
                        isHeader &&
                        cell.filter(':not([data-dt-order=disable])').count() !==
                            0 &&
                        cell.parent(':not([data-dt-order=disable])').count() !==
                            0 &&
                        cell.find('div.dt-column-order').count() === 0) {
                        Dom.c('div')
                            .classAdd('dt-column-order')
                            .appendTo(cell);
                    }
                    // We need to wrap the elements in the header in another
                    // element to use flexbox layout for those elements
                    var headerFooter = isHeader ? 'header' : 'footer';
                    if (cell.find('div.dt-column-' + headerFooter).count() ===
                        0) {
                        Dom.c('div')
                            .classAdd('dt-column-' + headerFooter)
                            .append(Array.from(cell.get(0).childNodes))
                            .appendTo(cell);
                    }
                }
                // If there is col / rowspan, copy the information into the
                // layout grid
                for (l = 0; l < colspan; l++) {
                    for (k = 0; k < rowspan; k++) {
                        layout[i + k][shifted + l] = {
                            cell: cell.get(0),
                            unique: isUnique
                        };
                        layout[i + k].row = row;
                    }
                    cols.push(shifted + l);
                }
                // Assign an attribute so spanning cells can still be identified
                // as belonging to a column
                cell.attr('data-dt-column', util.unique(cols).join(','));
            }
            loopCell = loopCell.nextSibling;
        }
    }
    return layout;
}
/**
 * Set the start position for draw
 *
 * @param settings DataTables settings object
 */
function setStartPosition(settings) {
    var bServerSide = dataSource(settings) == 'ssp';
    var iInitDisplayStart = settings.displayStartInit;
    // Check and see if we have an initial draw position from state saving
    if (iInitDisplayStart !== undefined && iInitDisplayStart !== -1) {
        settings.displayStart = bServerSide
            ? iInitDisplayStart
            : iInitDisplayStart >= recordsDisplay(settings)
                ? 0
                : iInitDisplayStart;
        settings.displayStartInit = -1;
    }
}
/**
 * Get the number of records in the current record set, before filtering
 *
 * @param ctx DataTables settings object
 */
function recordsTotal(ctx) {
    return dataSource(ctx) == 'ssp'
        ? ctx.recordsTotal * 1
        : ctx.displayMaster.length;
}
/**
 * Get the number of records in the current record set, after filtering
 *
 * @param ctx DataTables settings object
 */
function recordsDisplay(ctx) {
    return dataSource(ctx) == 'ssp'
        ? ctx.recordsDisplay * 1
        : ctx.display.length;
}
/**
 * Get the display end point - display index
 *
 * @param ctx DataTables settings object
 */
function displayEnd(ctx) {
    var len = ctx.pageLength, start = ctx.displayStart, calc = start + len, records = ctx.display.length, features = ctx.features, paginate = features.paging;
    if (features.serverSide) {
        return paginate === false || len === -1
            ? start + records
            : Math.min(start + len, ctx.recordsDisplay);
    }
    else {
        return !paginate || calc > records || len === -1 ? records : calc;
    }
}

/**
 * Common run function for selector types
 */
function selectorRun(type, selector, selectFn, settings, opts) {
    var out = [], res, i, iLen, selectorType = typeof selector;
    // If a Dom instance, then get the underlying elements
    if (selector instanceof Dom) {
        selector = selector.get();
    }
    // Can't just check for isArray here, as an API or jQuery instance might be
    // given with their array like look
    if (!selector ||
        selectorType === 'string' ||
        selectorType === 'function' ||
        selector.length === undefined) {
        selector = [selector];
    }
    for (i = 0, iLen = selector.length; i < iLen; i++) {
        res = selectFn(typeof selector[i] === 'string' ? selector[i].trim() : selector[i]);
        // Remove empty items
        res = res.filter(function (item) {
            return item !== null && item !== undefined;
        });
        if (res && res.length) {
            out = out.concat(res);
        }
    }
    // selector extensions
    var extSelectors = ext.selector[type];
    if (extSelectors.length) {
        for (i = 0, iLen = extSelectors.length; i < iLen; i++) {
            out = extSelectors[i](settings, opts, out);
        }
    }
    return unique(out);
}
function selectorOpts(opts) {
    if (!opts) {
        opts = {};
    }
    // Backwards compatibility for 1.9- which used the terminology filter rather
    // than search
    if (opts.filter && opts.search === undefined) {
        opts.search = opts.filter;
    }
    return assign({}, {
        columnOrder: 'implied',
        search: 'none',
        order: 'current',
        page: 'all'
    }, opts);
}
// Reduce the API instance to the first item found
function selectorFirst(old) {
    // Need to specify the target class as singular since `old` has the context
    // of the plural
    var inst = old.inst(old.context[0], null, old._newClass.replace(/s$/, ''));
    // Use a push rather than passing to the constructor, since it will
    // merge arrays down automatically, which isn't what is wanted here
    if (old.length) {
        inst.push(old[0]);
    }
    inst.selector = old.selector;
    // Limit to a single row / column / cell
    if (inst.length && inst[0].length > 1) {
        inst[0].splice(1);
    }
    return inst;
}
function selectorRowIndexes(settings, opts) {
    var i, iLen, tmp, a = [], displayFiltered = settings.display, displayMaster = settings.displayMaster;
    var search = opts.search, // none, applied, removed
    order = opts.order, // applied, current, index (original)
    page = opts.page; // all, current
    if (dataSource(settings) == 'ssp') {
        // In server-side processing mode, most options are irrelevant since
        // rows not shown don't exist and the index order is the applied order
        // Removed is a special case - for consistency just return an empty
        // array
        return search === 'removed' ? [] : range(0, displayMaster.length);
    }
    if (page == 'current') {
        // Current page implies that order=current and filter=applied, since it
        // is fairly senseless otherwise, regardless of what order and search
        // actually are
        for (i = settings.displayStart, iLen = displayEnd(settings); i < iLen; i++) {
            a.push(displayFiltered[i]);
        }
    }
    else if (order == 'current' || order == 'applied') {
        if (search == 'none') {
            a = displayMaster.slice();
        }
        else if (search == 'applied') {
            a = displayFiltered.slice();
        }
        else if (search == 'removed') {
            // O(n+m) solution by creating a hash map
            var displayFilteredMap = {};
            for (i = 0, iLen = displayFiltered.length; i < iLen; i++) {
                displayFilteredMap[displayFiltered[i]] = null;
            }
            displayMaster.forEach(function (item) {
                if (!Object.prototype.hasOwnProperty.call(displayFilteredMap, item)) {
                    a.push(item);
                }
            });
        }
    }
    else if (order == 'index' || order == 'original') {
        for (i = 0, iLen = settings.data.length; i < iLen; i++) {
            if (!settings.data[i]) {
                continue;
            }
            if (search == 'none') {
                a.push(i);
            }
            else {
                // applied | removed
                tmp = displayFiltered.indexOf(i);
                if ((tmp === -1 && search == 'removed') ||
                    (tmp >= 0 && search == 'applied')) {
                    a.push(i);
                }
            }
        }
    }
    else if (typeof order === 'number') {
        // Order the rows by the given column
        var ordered = sort(settings, order, 'asc');
        if (search === 'none') {
            a = ordered;
        }
        else {
            // applied | removed
            for (i = 0; i < ordered.length; i++) {
                tmp = displayFiltered.indexOf(ordered[i]);
                if ((tmp === -1 && search == 'removed') ||
                    (tmp >= 0 && search == 'applied')) {
                    a.push(ordered[i]);
                }
            }
        }
    }
    return a;
}

/**
 * `Array.prototype` reference as methods from it are used in the array-like
 * methods of the API.
 */
const __arrayProto = Array.prototype;
const Api = function (context, data) {
    // Allow the API to be initialised without specifying `new`
    if (!(this instanceof Api)) {
        return new Api(context, data);
    }
    this.context = toContextArray(context);
    // Initial data
    arrayApply(this, data);
    // Add properties which will still execute in this scope
    extendApi(this, 'Api');
};
// And the private parameters
util.object.assign(Api.prototype, {
    _newClass: 'Api',
    isDataTableApi: true,
    any() {
        return this.count() !== 0;
    },
    context: [], // array of table settings objects
    count() {
        return this.flatten().length;
    },
    each(fn) {
        for (var i = 0, iLen = this.length; i < iLen; i++) {
            fn.call(this, this[i], i, this);
        }
        return this;
    },
    eq(idx) {
        var ctx = this.context;
        // Note that `eq` returns an API instance, not a nested class instance
        return ctx.length > idx ? this.inst(ctx[idx], this[idx], 'Api') : null;
    },
    filter(fn) {
        var a = __arrayProto.filter.call(this, fn, this);
        return this.inst(this.context, a);
    },
    flatten() {
        var a = [];
        return this.inst(this.context, a.concat.apply(a, this.toArray()));
    },
    get(idx) {
        return this[idx];
    },
    join: __arrayProto.join,
    includes(find) {
        return this.indexOf(find) === -1 ? false : true;
    },
    indexOf: __arrayProto.indexOf,
    inst(context, data, newClass) {
        let name = newClass || this._newClass;
        let inst = Api;
        if (classes[name]) {
            inst = classes[name];
        }
        return new inst(context, data);
    },
    iterator(flatten, type, fn, alwaysNew) {
        var a = [], ret, i, iLen, j, jen, context = this.context, rows, items, item, selector = this.selector;
        // Argument shifting
        if (typeof flatten === 'string') {
            alwaysNew = fn;
            fn = type;
            type = flatten;
            flatten = false;
        }
        for (i = 0, iLen = context.length; i < iLen; i++) {
            var apiInst = this.inst(context[i]);
            if (type === 'table') {
                ret = fn.call(apiInst, context[i], i);
                if (ret !== undefined) {
                    a.push(ret);
                }
            }
            else if (type === 'columns' || type === 'rows') {
                // this has same length as context - one entry for each table
                ret = fn.call(apiInst, context[i], this[i], i);
                if (ret !== undefined) {
                    a.push(ret);
                }
            }
            else if (type === 'every' ||
                type === 'column' ||
                type === 'column-rows' ||
                type === 'row' ||
                type === 'cell') {
                // columns and rows share the same structure.
                // 'this' is an array of column indexes for each context
                items = this[i];
                if (type === 'column-rows') {
                    rows = selectorRowIndexes(context[i], selector.opts);
                }
                for (j = 0, jen = items.length; j < jen; j++) {
                    item = items[j];
                    if (type === 'cell') {
                        ret = fn.call(apiInst, context[i], item.row, item.column, i, j);
                    }
                    else {
                        ret = fn.call(apiInst, context[i], item, i, j, rows);
                    }
                    if (ret !== undefined) {
                        a.push(ret);
                    }
                }
            }
        }
        if (a.length || alwaysNew) {
            var api = this.inst(context, flatten ? a.concat.apply([], a) : a);
            var apiSelector = api.selector;
            if (apiSelector) {
                apiSelector.rows = selector.rows;
                apiSelector.cols = selector.cols;
                apiSelector.opts = selector.opts;
            }
            return api;
        }
        return this;
    },
    lastIndexOf: __arrayProto.lastIndexOf,
    length: 0,
    map(fn) {
        var a = __arrayProto.map.call(this, fn, this);
        return this.inst(this.context, a);
    },
    pluck(prop) {
        var fn = util.get(prop);
        return this.map((src) => fn(src));
    },
    pop: __arrayProto.pop,
    push: __arrayProto.push,
    reduce: __arrayProto.reduce,
    reduceRight: __arrayProto.reduceRight,
    reverse: __arrayProto.reverse,
    // Object with rows, columns and opts
    selector: {
        rows: undefined,
        cols: undefined,
        opts: undefined
    },
    shift: __arrayProto.shift,
    slice() {
        return this.inst(this.context, this);
    },
    sort: __arrayProto.sort,
    splice: __arrayProto.splice,
    toArray() {
        return __arrayProto.slice.call(this);
    },
    to$() {
        let jq = util.external('jq');
        return jq(this);
    },
    toDom() {
        return new Dom(this.toArray());
    },
    toJQuery: function () {
        let jq = util.external('jq');
        return jq(this);
    },
    unique: function () {
        return this.inst(this.context, util.array.unique(this.toArray()));
    },
    unshift: __arrayProto.unshift
});
function register(name, func) {
    if (Array.isArray(name)) {
        for (let i = 0; i < name.length; i++) {
            Api.register(name[i], func);
        }
        return;
    }
    let names = getPrototypeNames(name);
    // Has the parent already been defined or not?
    if (!classes[names.hostClass]) {
        // Create a new "class"
        createApiClass(names.hostClass);
    }
    if (names.property) {
        if (!properties[names.propertyHost]) {
            properties[names.propertyHost] = [];
        }
        properties[names.propertyHost].push({
            couldReturn: names.couldReturn,
            property: names.property,
            method: names.methodName,
            fn: func
        });
    }
    else {
        let wrapped = function () {
            // If a new instance (.inst) is created while the function is being
            // executed, we want to allow it to return its target class. But we
            // also need to keep hold of our own, so it can be used in the end.
            let previousCould = this._newClass;
            this._newClass = names.couldReturn;
            let result = func.apply(this, arguments);
            this._newClass = previousCould;
            return result;
        };
        // Create the new method on the host class
        classes[names.hostClass].prototype[names.methodName] = wrapped;
        // If the method is on the top level, it needs to be applied to other
        // classes which have already been defined to allow the circular
        // chaining of the API (e.g. `row().data(...).draw())`.
        if (names.hostClass === 'Api') {
            util.object.each(classes, (className, klass) => {
                if (!klass.prototype[names.methodName]) {
                    klass.prototype[names.methodName] = wrapped;
                }
            });
        }
    }
}
function registerPlural(pluralName, singularName, func) {
    Api.register(pluralName, func);
    Api.register(singularName, function () {
        var ret = func.apply(this, arguments);
        if (ret === this) {
            // Returned item is the API instance that was passed in, return it
            return this;
        }
        else if (ret && ret.isDataTableApi) {
            // New API instance returned, want the value from the first item
            // in the returned array for the singular result.
            return ret.length
                ? Array.isArray(ret[0])
                    ? this.inst(ret.context, ret[0]) // Array results are 'enhanced'
                    : ret[0]
                : undefined;
        }
        // Non-API return - just fire it back
        return ret;
    });
}
Api.register = register;
Api.registerPlural = registerPlural;
/** A collection of properties to apply to the classes as they are constructed */
const properties = {};
/** Collection of API classes */
const classes = {
    Api
};
// TODO debug
window.classes = classes;
window.properties = properties;
/**
 * Create a new API "class" (function), used for nested levels of the API - e.g.
 * `ApiRows` and `ApiColumn`.
 *
 * @param name
 */
function createApiClass(name) {
    let newClass = function (context, data) {
        // Same as the main API constructor
        this.context = toContextArray(context);
        arrayApply(this, data);
        // Extend the API with properties that execute in this scope, both for
        // this level and for the top level to allow looped chaining
        extendApi(this, 'Api');
        extendApi(this, this._newClass);
    };
    newClass.prototype = Object.create(Api.prototype);
    Object.defineProperty(newClass, 'name', {
        value: name,
        writable: false
    });
    newClass.prototype._newClass = name;
    classes[name] = newClass;
}
/**
 * When an instance is created it needs to be extended with properties (since
 * these cannot be given a scope from the prototype due to the nesting).
 *
 * @param api API instance to extend
 * @param className The name of the instance to extend
 * @returns void
 */
function extendApi(api, className) {
    let props = properties[className];
    if (!props) {
        return;
    }
    for (let i = 0; i < props.length; i++) {
        let def = props[i];
        if (!api[def.property]) {
            // Instance doesn't yet have this property, so need to create an
            // object to hold the methods.
            api[def.property] = {};
        }
        else if (!api.hasOwnProperty(def.property)) {
            // Its a prototype function, which is a problem since it is shared
            // between all instances, and thus scope is whichever is last setup.
            // As such we need to make it an independent function and wrap it.
            let fn = api[def.property];
            api[def.property] = function () {
                return fn.apply(api, arguments);
            };
        }
        // Wrap the function so we can keep scope and set the return class
        api[def.property][def.method] = function () {
            let previousCould = api._newClass;
            api._newClass = def.couldReturn;
            let result = def.fn.apply(api, arguments);
            api._newClass = previousCould;
            return result;
        };
    }
}
/**
 * Based on an API method name, construct the class, property, etc names that
 * are used to store and construct the API.
 *
 * @param name API function name
 * @returns Name components
 */
function getPrototypeNames(name) {
    let parts = name.split('.');
    let property = null;
    let hostClass = 'Api';
    let returnClass = 'Api';
    let methodName = '';
    let propertyHost = '';
    let lastPart = '';
    for (let i = 0; i < parts.length; i++) {
        let part = parts[i];
        let partNoParen = part.replace('()', '');
        hostClass = returnClass; // from previous loop
        returnClass +=
            partNoParen.charAt(0).toUpperCase() +
                partNoParen.slice(1).toLowerCase();
        if (part.includes('()')) {
            methodName = partNoParen;
            // If the previous part was a method rather than a property, then we
            // remove the property host
            if (lastPart.includes('()')) {
                property = null;
                propertyHost = '';
            }
        }
        else {
            // Is a property
            property = part;
            propertyHost = hostClass;
        }
        lastPart = part;
    }
    return {
        couldReturn: returnClass,
        hostClass,
        property,
        propertyHost,
        methodName
    };
}
/**
 * Abstraction for `context` parameter of the `Api` constructor to allow it to
 * take several different forms for ease of use.
 *
 * Each of the input parameter types will be converted to a DataTables settings
 * object where possible.
 *
 * @param mixedIn DataTable identifier. Can be one of:
 *   * `string` - jQuery selector. Any DataTables' matching the given selector
 *     with be found and used.
 *   * `node` - `TABLE` node which has already been formed into a DataTable.
 *   * `jQuery` - A jQuery object of `TABLE` nodes.
 *   * `object` - DataTables settings object
 *   * `DataTables.Api` - API instance
 * @return Matching DataTables settings objects. `null` or `undefined` is
 *   returned if no matching DataTable is found.
 */
function toContext(mixedIn) {
    var mixed = mixedIn;
    var idx, nodes = null;
    var settings = ext.settings;
    var tables = util.array.pluck(settings, 'table');
    if (!mixed) {
        return [];
    }
    else if (mixed.table && mixed.features) {
        // DataTables settings object
        return [mixed];
    }
    else if (mixed.nodeName && mixed.nodeName.toLowerCase() === 'table') {
        // Table node
        idx = tables.indexOf(mixed);
        return idx !== -1 ? [settings[idx]] : null;
    }
    else if (mixed && typeof mixed.settings === 'function') {
        return mixed.settings().toArray();
    }
    else if (typeof mixed === 'string') {
        // jQuery selector
        nodes = Dom.s(mixed).get();
    }
    else if (util.is.jquery(mixed)) {
        // jQuery object
        nodes = mixed.get();
    }
    else if (util.is.dom(mixed)) {
        // DOM object
        nodes = mixed.get();
    }
    if (nodes) {
        return settings.filter(function (v, i) {
            return nodes.includes(tables[i]);
        });
    }
}
/**
 * Create the context array for an instance
 *
 * @param mixed The passed in options to convert to context
 * @returns Context array
 */
function toContextArray(mixed) {
    var i;
    var settings = [];
    var ctxSettings = function (o) {
        var a = toContext(o);
        if (a) {
            settings.push.apply(settings, a);
        }
    };
    if (Array.isArray(mixed)) {
        for (i = 0; i < mixed.length; i++) {
            ctxSettings(mixed[i]);
        }
    }
    else {
        ctxSettings(mixed);
    }
    // Remove duplicates
    return settings.length > 1 ? util.unique(settings) : settings;
}

register('$()', function (selector, opts) {
    let jq = util.external('jq');
    if (!jq) {
        log(this.context[0], 0, 'No jQuery available. Use `.dom()` or register jQuery');
    }
    let rows = this.rows(opts).nodes(), // Get all rows
    jqRows = jq(rows);
    return jq([].concat(jqRows.filter(selector).toArray(), jqRows.find(selector).toArray()));
});
// jQuery functions to operate on the tables
['on', 'one', 'off'].forEach(key => {
    register(key + '()', function ( /* event, handler */) {
        var args = Array.prototype.slice.call(arguments);
        // Add the `dt` namespace automatically if it isn't already present
        args[0] = args[0]
            .split(/\s/)
            .map(function (e) {
            return !e.match(/\.dt\b/) ? e + '.dt' : e;
        })
            .join(' ');
        var inst = Dom.s(this.tables().nodes());
        inst[key].apply(inst, args);
        return this;
    });
});
register('clear()', function () {
    return this.iterator('table', function (settings) {
        clearTable(settings);
    });
});
register('error()', function (msg) {
    return this.iterator('table', function (settings) {
        log(settings, 0, msg);
    });
});
register('settings()', function () {
    return new Api(this.context, this.context);
});
register('init()', function () {
    var ctx = this.context;
    return ctx.length ? ctx[0].init : null;
});
register('data()', function () {
    return this.iterator('table', function (settings) {
        return util.array.pluck(settings.data, 'data');
    }).flatten();
});
register('trigger()', function (name, args, bubbles) {
    return this.iterator('table', function (settings) {
        return callbackFire(settings, null, name, args, bubbles);
    }).flatten();
});
register('ready()', function (fn) {
    var ctx = this.context;
    // Get status of first table
    if (!fn) {
        return ctx.length ? ctx[0].initDone || false : false;
    }
    // Function to run either once the table becomes ready or
    // immediately if it is already ready.
    return this.tables().every(function () {
        var api = this;
        if (this.context[0].initDone) {
            fn.call(api);
        }
        else {
            this.on('init.dt.DT', function () {
                fn.call(api);
            });
        }
    });
});
register('destroy()', function (remove) {
    remove = remove || false;
    return this.iterator('table', function (settings) {
        var classes = settings.classes;
        var table = settings.table;
        var tbody = settings.tbody;
        var thead = settings.thead;
        var tfoot = settings.tfoot;
        var jqTable = Dom.s(table);
        var jqTbody = Dom.s(tbody);
        var jqWrapper = Dom.s(settings.tableWrapper);
        var rows = settings.data
            .map(function (r) {
            return r ? r.tr : null;
        })
            .filter(r => !!r);
        var orderClasses = classes.order;
        // Flag to note that the table is currently being destroyed - no action
        // should be taken
        settings.destroying = true;
        // Fire off the destroy callbacks for plug-ins etc
        callbackFire(settings, 'destroy', 'destroy', [settings], true);
        // If not being removed from the document, make all columns visible
        if (!remove) {
            new Api(settings).columns().visible();
        }
        // Container width change listener
        if (settings.resizeObserver) {
            settings.resizeObserver.disconnect();
        }
        // Blitz all `DT` namespaced events (these are internal events, the
        // lowercase, `dt` events are user subscribed and they are responsible
        // for removing them
        jqWrapper.off('.DT').find(':not(tbody *)').off('.DT');
        if (settings.windowResizeCb) {
            window.removeEventListener('resize', settings.windowResizeCb);
        }
        // When scrolling we had to break the table up - restore it
        if (table != thead.parentNode) {
            jqTable.children('thead').detach();
            jqTable.append(thead);
        }
        if (tfoot && table != tfoot.parentNode) {
            jqTable.children('tfoot').detach();
            jqTable.append(tfoot);
        }
        // Clean up the header / footer
        cleanHeader(thead, 'header');
        cleanHeader(tfoot, 'footer');
        settings.colgroup.remove();
        settings.order = [];
        settings.orderFixed = [];
        sortingClasses(settings);
        jqTable
            .find('th, td')
            .classRemove(Object.values(ext.type.className).join(' '));
        Dom.s(thead)
            .find('th, td')
            .classRemove(orderClasses.none +
            ' ' +
            orderClasses.canAsc +
            ' ' +
            orderClasses.canDesc +
            ' ' +
            orderClasses.isAsc +
            ' ' +
            orderClasses.isDesc)
            .css('width', '')
            .attrRemove('aria-sort');
        // Add the TR elements back into the table in their original order
        jqTbody.children().detach();
        jqTbody.append(rows);
        var orig = settings.tableWrapper.parentNode;
        var insertBefore = settings.tableWrapper.nextSibling;
        // Remove the DataTables generated nodes, events and classes
        var removedMethod = remove ? 'remove' : 'detach';
        jqTable[removedMethod]();
        jqWrapper[removedMethod]();
        // If we need to reattach the table to the document
        if (!remove && orig) {
            // insertBefore acts like appendChild if !arg[1]
            orig.insertBefore(table, insertBefore);
            // Restore the width of the original table - was read from the style property,
            // so we can restore directly to that
            jqTable.css('width', settings + 'px').classRemove(classes.table);
        }
        /* Remove the settings object from the settings array */
        var idx = ext.settings.indexOf(settings);
        if (idx !== -1) {
            ext.settings.splice(idx, 1);
        }
    });
});
// i18n method for extensions to be able to use the language object from the
// DataTable
register('i18n()', function (token, def, plural) {
    var ctx = this.context[0];
    var resolved = util.get(token)(ctx.language);
    if (resolved === undefined) {
        resolved = def;
    }
    if (util.is.plainObject(resolved)) {
        if (plural !== false) {
            resolved =
                plural !== undefined && resolved[plural] !== undefined
                    ? resolved[plural]
                    : resolved._;
        }
    }
    return typeof resolved === 'string'
        ? resolved.replace('%d', plural) // nb: plural might be undefined,
        : resolved;
});
// Needed for header and footer, so pulled into its own function
function cleanHeader(node, className) {
    let headerCell = Dom.s(node);
    headerCell.find('.dt-column-order').remove();
    headerCell.find('.dt-column-title').each(function (el) {
        let cell = Dom.s(el);
        var title = cell.html();
        cell.parent().parent().html(title);
        cell.remove();
    });
    headerCell.find('div.dt-column-' + className).remove();
    headerCell.find('th, td').attrRemove('data-dt-column');
}

const __reload = function (settings, holdPosition, callback) {
    // Use the draw event to trigger a callback
    if (callback) {
        var api = new Api(settings);
        api.one('draw', function () {
            callback(api.ajax.json());
        });
    }
    if (dataSource(settings) == 'ssp') {
        reDraw(settings, holdPosition);
    }
    else {
        processingDisplay(settings, true);
        // Cancel an existing request
        var xhr = settings.jqXHR;
        if (xhr && xhr.readyState !== 4 && typeof xhr.abort === 'function') {
            xhr.abort();
        }
        // Trigger xhr
        buildAjax(settings, {}, function (json) {
            clearTable(settings);
            var data = ajaxDataSrc(settings, json, false);
            for (var i = 0, iLen = data.length; i < iLen; i++) {
                addData(settings, data[i]);
            }
            reDraw(settings, holdPosition);
            initComplete(settings);
            processingDisplay(settings, false);
        });
    }
};
register('ajax.json()', function () {
    var ctx = this.context;
    if (ctx.length > 0) {
        return ctx[0].json;
    }
    // else return undefined;
});
register('ajax.params()', function () {
    var ctx = this.context;
    if (ctx.length > 0) {
        return ctx[0].ajaxData;
    }
    // else return undefined;
});
register('ajax.reload()', function (callback, resetPaging) {
    return this.iterator('table', function (settings) {
        __reload(settings, resetPaging === false, callback);
    });
});
register('ajax.url()', function (url) {
    var ctx = this.context;
    if (url === undefined) {
        // get
        if (ctx.length === 0) {
            return undefined;
        }
        let context = ctx[0];
        return util.is.plainObject(context.ajax)
            ? context.ajax.url
            : context.ajax;
    }
    // set
    return this.iterator('table', function (settings) {
        if (util.is.plainObject(settings.ajax)) {
            settings.ajax.url = url;
        }
        else {
            settings.ajax = url;
        }
    }, true);
});
register('ajax.url().load()', function (callback, resetPaging) {
    // Same as a reload, but makes sense to present it for easy access after
    // a url change
    return this.iterator('table', function (ctx) {
        __reload(ctx, resetPaging === false, callback);
    });
});

function selectCells(settings, selector, opts) {
    var data = settings.data;
    var rows = selectorRowIndexes(settings, opts);
    var allCells;
    var row;
    var columns = settings.columns.length;
    var a, i, iLen, j, o, host;
    var run = function (s) {
        var fnSelector = typeof s === 'function';
        if (s === null || s === undefined || fnSelector) {
            // All cells and function selectors
            a = [];
            for (i = 0, iLen = rows.length; i < iLen; i++) {
                row = rows[i];
                for (j = 0; j < columns; j++) {
                    o = {
                        row: row,
                        column: j
                    };
                    if (fnSelector) {
                        // Selector - function
                        host = data[row];
                        if (s(o, getCellData(settings, row, j), host && host.cells ? host.cells[j] : null)) {
                            a.push(o);
                        }
                    }
                    else {
                        // Selector - all
                        a.push(o);
                    }
                }
            }
            return a;
        }
        // Selector - index
        if (plainObject(s)) {
            // Valid cell index and its in the array of selectable rows
            return s.column !== undefined &&
                s.row !== undefined &&
                rows.indexOf(s.row) !== -1
                ? [s]
                : [];
        }
        // Only get the nodes if we get these far in the selector and need to
        // actually work with the cell nodes.
        if (!allCells) {
            let cells = removeEmpty(pluckOrder(data, rows, 'cells'));
            allCells = Dom.s(flatten([], cells));
        }
        // Selector - jQuery filtered cells
        let jqResult = allCells.filter(s).mapTo((el) => {
            return {
                // use a new object, in case someone changes the values
                row: el._DT_CellIndex.row,
                column: el._DT_CellIndex.column
            };
        });
        if (jqResult.length || !s.nodeName) {
            return jqResult;
        }
        // Otherwise the selector is a node, and there is one last option - the
        // element might be a child of an element which has dt-row and dt-column
        // data attributes
        let rowHost = Dom.s(s).closest('*[data-dt-row]');
        let columnHost = Dom.s(s).closest('*[data-dt-column]');
        return rowHost.count()
            ? [
                {
                    row: parseInt(rowHost.attr('data-dt-row')),
                    column: parseInt(columnHost.attr('data-dt-column'))
                }
            ]
            : [];
    };
    return selectorRun('cell', selector, run, settings, opts);
}
register('cells()', function (arg1, arg2, arg3) {
    // // Argument shifting
    let rowSelector = null;
    let columnSelector = null;
    let cellSelector;
    let opts;
    // Argument shifting
    if (plainObject(arg1)) {
        if (arg1.row === undefined) {
            // Selector modifier only overload
            opts = arg1;
        }
        else {
            // Cell selector as an index object
            cellSelector = arg1;
            opts = arg2;
        }
    }
    else if (plainObject(arg2) || arg2 === undefined) {
        // Cell selector overload
        cellSelector = arg1;
        opts = arg2;
    }
    else if (arg1 !== undefined) {
        // Row + column selector overload
        rowSelector = arg1;
        columnSelector = arg2;
        opts = arg3;
    }
    // Cell selector (if there is no column selector, then it must be)
    if (columnSelector === null) {
        return this.iterator('table', function (settings) {
            return selectCells(settings, cellSelector, selectorOpts(opts));
        });
    }
    // The default built in options need to apply to row and columns
    let internalOpts = opts
        ? {
            page: opts.page,
            order: opts.order,
            search: opts.search
        }
        : {};
    // Row + column selector
    let columns = this.columns(columnSelector, internalOpts);
    let rows = this.rows(rowSelector, internalOpts);
    let i, iLen, j, jen;
    let cellsNoOpts = this.iterator('table', function (settings, idx) {
        let a = [];
        for (i = 0, iLen = rows[idx].length; i < iLen; i++) {
            for (j = 0, jen = columns[idx].length; j < jen; j++) {
                a.push({
                    row: rows[idx][i],
                    column: columns[idx][j]
                });
            }
        }
        return a;
    }, true);
    // There is currently only one extension which uses a cell selector
    // extension It is a _major_ performance drag to run this if it isn't
    // needed, so this is an extension specific check at the moment
    let cells = opts && opts.selected
        ? this.cells(cellsNoOpts.toArray(), opts)
        : cellsNoOpts;
    assign(cells.selector, {
        cols: columnSelector,
        rows: rowSelector,
        opts: opts
    });
    return cells;
});
register('cells().every()', function (fn) {
    var opts = this.selector.opts;
    var counter = 0;
    return this.iterator('every', (settings, selectedIdx, tableIdx) => {
        let inst = this.cell(selectedIdx, opts);
        fn.call(inst, inst[0][0].row, inst[0][0].column, tableIdx, counter);
        counter++;
    });
});
registerPlural('cells().nodes()', 'cell().node()', function () {
    return this.iterator('cell', function (settings, row, column) {
        var data = settings.data[row];
        return data && data.cells ? data.cells[column] : undefined;
    }, true);
});
register('cells().data()', function () {
    return this.iterator('cell', function (settings, row, column) {
        return getCellData(settings, row, column);
    }, true);
});
registerPlural('cells().render()', 'cell().render()', function (type) {
    return this.iterator('cell', function (settings, row, column) {
        return getCellData(settings, row, column, type);
    }, true);
});
registerPlural('cells().indexes()', 'cell().index()', function () {
    return this.iterator('cell', function (settings, row, column) {
        return {
            row: row,
            column: column,
            columnVisible: columnIndexToVisible(settings, column)
        };
    }, true);
});
registerPlural('cells().invalidate()', 'cell().invalidate()', function (src) {
    return this.iterator('cell', function (settings, row, column) {
        invalidateRow(settings, row, src, column);
    });
});
register('cell()', function (rowSelector, columnSelector, opts) {
    return selectorFirst(this.cells(rowSelector, columnSelector, opts));
});
register('cell().data()', function (data) {
    var ctx = this.context;
    var cell = this[0];
    if (data === undefined) {
        // Get
        return ctx.length && cell.length
            ? getCellData(ctx[0], cell[0].row, cell[0].column)
            : undefined;
    }
    // Set
    setCellData(ctx[0], cell[0].row, cell[0].column, data);
    invalidateRow(ctx[0], cell[0].row, 'data', cell[0].column);
    return this;
});

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Columns
 *
 * {integer}           - column index (>=0 count from left, <0 count from right)
 * "{integer}:visIdx"  - visible column index (i.e. translate to column index)  (>=0 count from left, <0 count from right)
 * "{integer}:visible" - alias for {integer}:visIdx  (>=0 count from left, <0 count from right)
 * "{string}:name"     - column name
 * "{string}"          - jQuery selector on column header nodes
 *
 */
// can be an array of these items, comma separated list, or an array of comma
// separated lists
const __re_column_selector = /^(.*?):(name|title|visIdx|visible)$/;
// r1 and r2 are redundant - but it means that the parameters match for the
// iterator callback in columns().data()
function columnData(settings, column, r1, r2, rows, type) {
    let a = [];
    for (let row = 0, iLen = rows.length; row < iLen; row++) {
        a.push(getCellData(settings, rows[row], column, type));
    }
    return a;
}
function columnHeader(settings, column, row) {
    var header = settings.header;
    var titleRow = settings.titleRow;
    var target = 0;
    if (row !== undefined) {
        target = row;
    }
    else if (titleRow === true) {
        // legacy orderCellsTop support
        target = 0;
    }
    else if (titleRow === false) {
        target = header.length - 1;
    }
    else if (titleRow !== null) {
        target = titleRow;
    }
    else {
        // Automatic - find the _last_ unique cell from the top that is not empty (last for
        // backwards compatibility)
        for (var i = 0; i < header.length; i++) {
            if (header[i][column].unique &&
                Dom
                    .s(header[i][column].cell)
                    .find('.dt-column-title')
                    .text()) {
                target = i;
            }
        }
        if (target === null) {
            target = 0;
        }
    }
    return header[target][column].cell;
}
function columnHeaderCells(header) {
    var out = [];
    for (var i = 0; i < header.length; i++) {
        for (var j = 0; j < header[i].length; j++) {
            var cell = header[i][j].cell;
            if (!out.includes(cell)) {
                out.push(cell);
            }
        }
    }
    return out;
}
function selectColumns(settings, selector, opts) {
    var columns = settings.columns, names, titles, nodes = columnHeaderCells(settings.header);
    var run = function (s) {
        var selInt = intVal(s);
        // Selector - all
        if (s === '') {
            return range(columns.length);
        }
        // Selector - index
        if (selInt !== null) {
            return [
                selInt >= 0
                    ? selInt // Count from left
                    : columns.length + selInt // Count from right (+ because its a negative value)
            ];
        }
        // Selector = function
        if (typeof s === 'function') {
            var rows = selectorRowIndexes(settings, opts);
            return columns.map(function (col, idx) {
                return s(idx, columnData(settings, idx, 0, 0, rows), columnHeader(settings, idx))
                    ? idx
                    : null;
            });
        }
        // String selector
        var match = typeof s === 'string' ? s.match(__re_column_selector) : '';
        if (match) {
            switch (match[2]) {
                case 'visIdx':
                case 'visible':
                    // Selector is a column index
                    if (match[1] && match[1].match(/^\d+$/)) {
                        var idx = parseInt(match[1], 10);
                        // Visible index given, convert to column index
                        if (idx < 0) {
                            // Counting from the right
                            var visColumns = columns.map(function (col, i) {
                                return col.visible ? i : null;
                            });
                            return [visColumns[visColumns.length + idx]];
                        }
                        // Counting from the left
                        return [visibleToColumnIndex(settings, idx)];
                    }
                    return columns.map(function (col, mapIdx) {
                        // Not visible, can't match
                        if (!col.visible) {
                            return null;
                        }
                        if (col.responsiveVisible === false) {
                            return null;
                        }
                        // Selector
                        if (match && match[1]) {
                            return Dom
                                .s(nodes[mapIdx])
                                .filter(match[1])
                                .count() > 0
                                ? mapIdx
                                : null;
                        }
                        // `:visible` on its own
                        return mapIdx;
                    });
                case 'name':
                    // Don't get names, unless needed, and only get once if it is
                    if (!names) {
                        names = pluck(columns, 'name');
                    }
                    // match by name. `names` is column index complete and in
                    // order
                    return names.map(function (name, i) {
                        return match && name === match[1] ? i : null;
                    });
                case 'title':
                    if (!titles) {
                        titles = pluck(columns, 'title');
                    }
                    // match by column title
                    return titles.map(function (title, i) {
                        return match && title === match[1] ? i : null;
                    });
                default:
                    return [];
            }
        }
        // Cell in the table body
        if (s.nodeName && s._DT_CellIndex) {
            return [s._DT_CellIndex.column];
        }
        // Selector on the TH elements for the columns
        var result = Dom
            .s(nodes)
            .filter(s)
            .mapTo(el => {
            return columnsFromHeader(el); // `nodes` is column index complete and in order
        })
            .flat()
            .sort(function (a, b) {
            return a - b;
        });
        if (result.length || !s.nodeName) {
            return result;
        }
        // Otherwise a node which might have a `dt-column` data attribute, or be
        // a child or such an element
        var host = Dom.s(s).closest('*[data-dt-column]');
        return host.count() ? [parseInt(host.attr('data-dt-column'))] : [];
    };
    var selected = selectorRun('column', selector, run, settings, opts);
    return opts.columnOrder && opts.columnOrder === 'index'
        ? selected.sort(function (a, b) {
            return a - b;
        })
        : selected; // implied
}
function setColumnVis(settings, column, vis) {
    var cols = settings.columns, col = cols[column], data = settings.data, cells, i, iLen, tr;
    // Get
    if (vis === undefined) {
        return col.visible;
    }
    // Set
    // No change
    if (col.visible === vis) {
        return false;
    }
    if (vis) {
        // Insert column
        // Need to decide if we should use appendChild or insertBefore
        var insertBefore = pluck(cols, 'visible').indexOf(true, column + 1);
        for (i = 0, iLen = data.length; i < iLen; i++) {
            let row = data[i];
            if (row) {
                tr = row.tr;
                cells = row.cells;
                if (tr) {
                    // insertBefore can act like appendChild if 2nd arg is null
                    tr.insertBefore(cells[column], cells[insertBefore] || null);
                }
            }
        }
    }
    else {
        // Remove column
        Dom.s(removeEmpty(pluck(settings.data, 'cells', column))).detach();
    }
    // Common actions
    col.visible = vis;
    colGroup(settings);
    return true;
}
register('columns()', function (arg1, arg2) {
    let selector;
    let opts;
    // argument shifting
    if (arg1 === undefined) {
        selector = '';
    }
    else if (plainObject(arg1)) {
        selector = '';
        arg2 = arg1;
    }
    else {
        selector = arg1;
    }
    opts = selectorOpts(arg2);
    let inst = this.iterator('table', settings => selectColumns(settings, selector, opts), true);
    // Want argument shifting here and in _row_selector?
    inst.selector.cols = selector;
    inst.selector.opts = opts;
    return inst;
});
register('columns().every()', function (fn) {
    var opts = this.selector.opts;
    var counter = 0;
    return this.iterator('every', (settings, selectedIdx, tableIdx) => {
        let inst = this.column(selectedIdx, opts);
        fn.call(inst, selectedIdx, tableIdx, counter);
        counter++;
    });
});
registerPlural('columns().header()', 'column().header()', function (row) {
    return this.iterator('column', function (settings, column) {
        return columnHeader(settings, column, row);
    }, true);
});
registerPlural('columns().footer()', 'column().footer()', function (row) {
    return this.iterator('column', function (settings, column) {
        var footer = settings.footer;
        if (!footer.length) {
            return null;
        }
        return settings.footer[row !== undefined ? row : 0][column]
            .cell;
    }, true);
});
registerPlural('columns().data()', 'column().data()', function () {
    return this.iterator('column-rows', columnData, true);
});
registerPlural('columns().render()', 'column().render()', function (type) {
    return this.iterator('column-rows', function (settings, column, i, j, rows) {
        return columnData(settings, column, i, j, rows, type);
    }, true);
});
registerPlural('columns().dataSrc()', 'column().dataSrc()', function () {
    return this.iterator('column', function (settings, column) {
        return settings.columns[column].data;
    }, true);
});
registerPlural('columns().init()', 'column().init()', function () {
    return this.iterator('column', function (settings, column) {
        return settings.columns[column];
    }, true);
});
registerPlural('columns().names()', 'column().name()', function () {
    return this.iterator('column', function (settings, column) {
        return settings.columns[column].name;
    }, true);
});
registerPlural('columns().nodes()', 'column().nodes()', function () {
    return this.iterator('column-rows', function (settings, column, i, j, rows) {
        return removeEmpty(pluckOrder(settings.data, rows, 'cells', column));
    }, true);
});
registerPlural('columns().titles()', 'column().title()', function (title, row) {
    return this.iterator('column', function (settings, column) {
        // Argument shifting
        if (typeof title === 'number') {
            row = title;
            title = undefined;
        }
        var span = Dom
            .s(this.column(column).header(row))
            .find('.dt-column-title');
        if (title !== undefined) {
            span.html(title);
            return this;
        }
        return span.html();
    }, true);
});
registerPlural('columns().types()', 'column().type()', function () {
    return this.iterator('column', function (settings, column) {
        var colObj = settings.columns[column];
        var type = colObj.type;
        // If the type was invalidated, then resolve it. This actually
        // does all columns at the moment. Would only happen once if
        // getting all column's data types.
        if (!type) {
            columnTypes(settings);
            type = colObj.type;
        }
        return type;
    }, true);
});
registerPlural('columns().visible()', 'column().visible()', function (vis, calc) {
    var that = this;
    var changed = [];
    var ret = this.iterator('column', function (settings, column) {
        if (vis === undefined) {
            return settings.columns[column].visible;
        } // else
        if (setColumnVis(settings, column, vis)) {
            changed.push(column);
        }
    });
    // Group the column visibility changes
    if (vis !== undefined) {
        this.iterator('table', function (settings) {
            // Redraw the header after changes
            drawHead(settings, settings.header);
            drawHead(settings, settings.footer);
            // Update colspan for no records display. Child rows and
            // extensions will use their own listeners to do this - only
            // need to update the empty table item here
            if (!settings.display.length) {
                Dom.s(settings.tbody)
                    .find('td[colspan]')
                    .attr('colspan', visibleColumns(settings));
            }
            saveState(settings);
            // Second loop once the first is done for events
            that.iterator('column', function (ctx, column) {
                if (changed.includes(column)) {
                    callbackFire(ctx, null, 'column-visibility', [
                        ctx,
                        column,
                        vis,
                        calc
                    ]);
                }
            });
            if (changed.length && (calc === undefined || calc)) {
                that.columns.adjust();
            }
        });
    }
    return ret;
});
registerPlural('columns().widths()', 'column().width()', function () {
    // Injects a fake row into the table for just a moment so the widths can
    // be read, regardless of colspan in the header and rows being present
    // in the body
    var columns = this.columns(':visible');
    var row = Dom
        .c('tr')
        .html('<td>' + Array(columns.count()).join('</td><td>') + '</td>');
    Dom.s(this.table().body()).append(row);
    var widths = [];
    var indexes = columns.indexes();
    row.children().each((el, idx) => {
        widths[indexes[idx]] = Dom.s(el).width('outer');
    });
    row.remove();
    return this.iterator('column', (settings, column) => {
        return widths[column] || 0;
    }, true);
});
registerPlural('columns().indexes()', 'column().index()', function (type) {
    return this.iterator('column', function (settings, column) {
        return type === 'visible'
            ? columnIndexToVisible(settings, column)
            : column;
    }, true);
});
register('columns.adjust()', function () {
    return this.iterator('table', function (settings) {
        // Force a column sizing to happen with a manual call - otherwise it
        // can skip if the size hasn't changed
        settings.containerWidth = -1;
        adjustColumnSizing(settings);
    }, true);
});
register('column.index()', function (type, idx) {
    if (this.context.length !== 0) {
        var ctx = this.context[0];
        if (type === 'fromVisible' || type === 'toData') {
            return visibleToColumnIndex(ctx, idx);
        }
        else if (type === 'fromData' || type === 'toVisible') {
            return columnIndexToVisible(ctx, idx);
        }
    }
    return -1;
});
register('column()', function (selector, opts) {
    return selectorFirst(this.columns(selector, opts));
});

/**
 * Redraw the tables in the current context.
 */
Api.register('draw()', function (paging) {
    return this.iterator('table', function (settings) {
        if (paging === 'page') {
            draw(settings);
        }
        else {
            if (typeof paging === 'string') {
                paging = paging === 'full-hold' ? false : true;
            }
            reDraw(settings, paging === false);
        }
    });
});

register('order()', function (order, dir) {
    let ctx = this.context;
    let args = Array.prototype.slice.call(arguments);
    if (order === undefined) {
        // get
        return ctx.length !== 0 ? ctx[0].order : undefined;
    }
    // set
    if (typeof order === 'number' && typeof dir === 'string') {
        // Simple column / direction passed in
        order = [[order, dir]];
    }
    else if (args.length > 1) {
        // Arguments passed in (list of 1D arrays)
        order = args;
    }
    // otherwise a 2D array was passed in
    return this.iterator('table', function (settings) {
        let resolved = [];
        sortResolve(settings, resolved, order);
        settings.order = resolved;
    });
});
register('order.listener()', function (node, column, callback) {
    return this.iterator('table', function (settings) {
        sortAttachListener(settings, node, '', column, callback);
    });
});
register('order.fixed()', function (set) {
    if (!set) {
        var ctx = this.context;
        var fixed = ctx.length ? ctx[0].orderFixed : undefined;
        return Array.isArray(fixed) ? { pre: fixed } : fixed;
    }
    return this.iterator('table', function (settings) {
        settings.orderFixed = assignDeep({}, set);
    });
});
// Order by the selected column(s)
register(['columns().order()', 'column().order()'], function (dir) {
    var that = this;
    if (!dir) {
        return this.iterator('column', function (settings, idx) {
            var sort = sortFlatten(settings);
            for (var i = 0, iLen = sort.length; i < iLen; i++) {
                if (sort[i].col === idx) {
                    return sort[i].dir;
                }
            }
            return null;
        }, true);
    }
    else {
        return this.iterator('table', function (settings, i) {
            settings.order = that[i].map(function (col) {
                return [col, dir];
            });
        });
    }
});
registerPlural('columns().orderable()', 'column().orderable()', function (directions) {
    return this.iterator('column', function (settings, idx) {
        var col = settings.columns[idx];
        return directions ? col.orderSequence : col.orderable;
    }, true);
});

/**
 * Set the page length
 *
 * @param ctx DataTables context
 * @param val Value to change to
 */
function lengthChange(ctx, val) {
    let len = typeof val === 'string' ? parseInt(val, 10) : val;
    ctx.pageLength = len;
    lengthOverflow(ctx);
    // Fire length change event
    callbackFire(ctx, null, 'length', [ctx, len]);
}

register('page()', function (action) {
    if (action === undefined) {
        return this.page.info().page; // not an expensive call
    }
    // else, have an action to take on all tables
    return this.iterator('table', function (settings) {
        pageChange(settings, action);
    });
});
register('page.info()', function () {
    var settings = this.context[0], start = settings.displayStart, len = settings.features.paging ? settings.pageLength : -1, visRecords = recordsDisplay(settings), all = len === -1;
    return {
        page: all ? 0 : Math.floor(start / len),
        pages: all ? 1 : Math.ceil(visRecords / len),
        start: start,
        end: displayEnd(settings),
        length: len,
        recordsTotal: recordsTotal(settings),
        recordsDisplay: visRecords,
        serverSide: dataSource(settings) === 'ssp'
    };
});
register('page.len()', function (len) {
    // Note that we can't call this function 'length()' because `length` is a
    // JavaScript property of functions which defines how many arguments the
    // function expects.
    if (len === undefined || len === null) {
        return this.context.length !== 0
            ? this.context[0].pageLength
            : undefined;
    }
    // else, set the page length
    return this.iterator('table', function (settings) {
        lengthChange(settings, len);
    });
});

register('processing()', function (show) {
    return this.iterator('table', ctx => processingDisplay(ctx, show));
});

// Add the state event handler in time for the initial draw to save state
Dom.s(document).on('preInit.dt', function (e, context) {
    var api = new Api(context);
    api.on('stateSaveParams.DT', function (ev, settings, d) {
        // This could be more compact with the API, but it is a lot faster as a
        // simple internal loop
        var idFn = settings.rowIdFn;
        var rows = settings.displayMaster;
        var ids = [];
        for (var i = 0; i < rows.length; i++) {
            var rowIdx = rows[i];
            var row = settings.data[rowIdx];
            if (row.detailsShow) {
                ids.push('#' + idFn(row.data));
            }
        }
        d.childRows = ids;
    });
    // For future state loads (e.g. with StateRestore)
    api.on('stateLoaded.DT', function (ev, settings, state) {
        detailsStateLoad(api, state);
    });
});
// But initial details can wait until the end
Dom.s(document).on('plugin-init.dt', function (e, context) {
    var api = context.api;
    // And the initial load state
    detailsStateLoad(api, api.state.loaded());
});
function detailsStateLoad(api, state) {
    if (state && state.childRows) {
        api.rows(state.childRows.map(function (id) {
            // Escape any `:` characters from the row id. Accounts for
            // already escaped characters.
            return id.replace(/([^:\\]*(?:\\.[^:\\]*)*):/g, '$1\\:');
        })).every(function () {
            callbackFire(api.settings()[0], null, 'requestChild', [this]);
        });
    }
}
function detailsAdd(ctx, row, data, klass) {
    if (!row) {
        return;
    }
    // Convert to array of TR elements
    var rows = [];
    var addRow = function (r, k) {
        // Recursion to allow for arrays of jQuery objects
        if (Array.isArray(r) || util.is.jquery(r)) {
            for (var i = 0, iLen = r.length; i < iLen; i++) {
                addRow(r[i], k);
            }
            return;
        }
        // If we get a TR element, then just add it directly - up to the dev
        // to add the correct number of columns etc
        if (r.nodeName && r.nodeName.toLowerCase() === 'tr') {
            r.setAttribute('data-dt-row', row.idx);
            rows.push(r);
        }
        else {
            // Otherwise create a row with a wrapper
            let td = Dom.c('td').classAdd(k);
            let created = Dom
                .c('tr')
                .append(td)
                .attr('data-dt-row', row.idx)
                .classAdd(k);
            if (r.nodeName) {
                td.append(r);
            }
            else {
                td.html(r);
            }
            td.get(0).colSpan = visibleColumns(ctx);
            rows.push(created.get(0));
        }
    };
    addRow(data, klass);
    if (row.details) {
        row.details.detach();
    }
    row.details = Dom.s(rows);
    // If the children were already shown, that state should be retained
    if (row.detailsShow && row.tr) {
        row.details.insertAfter(row.tr);
    }
}
// Make state saving of child row details async to allow them to be batch
// processed
var detailsState = util.throttle(function (ctx) {
    saveState(ctx[0]);
}, 500);
function detailsRemove(api, idx) {
    var ctx = api.context;
    if (ctx.length) {
        var row = ctx[0].data[idx !== undefined ? idx : api[0]];
        if (row && row.details) {
            row.details.detach();
            row.detailsShow = undefined;
            row.details = undefined;
            Dom.s(row.tr).classRemove('dt-hasChild');
            detailsState(ctx);
        }
    }
}
function detailsDisplay(api, show) {
    var ctx = api.context;
    if (ctx.length && api.length) {
        var row = ctx[0].data[api[0]];
        if (row && row.details) {
            row.detailsShow = show;
            if (show && row.tr) {
                row.details.insertAfter(row.tr);
                Dom.s(row.tr).classAdd('dt-hasChild');
            }
            else if (!show) {
                row.details.detach();
                Dom.s(row.tr).classRemove('dt-hasChild');
            }
            callbackFire(ctx[0], null, 'childRow', [show, api.row(api[0])]);
            detailsEvents(ctx[0]);
            detailsState(ctx);
        }
    }
}
function detailsEvents(settings) {
    var api = new Api(settings);
    var namespace = '.dt.DT_details';
    var drawEvent = 'draw' + namespace;
    var colvisEvent = 'column-sizing' + namespace;
    var destroyEvent = 'destroy' + namespace;
    var data = settings.data;
    api.off(drawEvent + ' ' + colvisEvent + ' ' + destroyEvent);
    if (util.array.pluck(data, 'details').length > 0) {
        // On each draw, insert the required elements into the document
        api.on(drawEvent, function (e, ctx) {
            if (settings !== ctx) {
                return;
            }
            api.rows({ page: 'current' })
                .eq(0)
                .each(function (idx) {
                // Internal data grab
                var row = data[idx];
                if (row && row.detailsShow && row.details && row.tr) {
                    row.details.insertAfter(row.tr);
                }
            });
        });
        // Column visibility change - update the colspan
        api.on(colvisEvent, function (e, ctx) {
            if (settings !== ctx) {
                return;
            }
            // Update the colspan for the details rows (note, only if it already
            // has a colspan)
            var row, visible = visibleColumns(ctx);
            for (var i = 0, iLen = data.length; i < iLen; i++) {
                row = data[i];
                if (row && row.details) {
                    row.details.each(function (el) {
                        var td = Dom.s(el).children('td');
                        if (td.count() == 1) {
                            td.attr('colspan', visible);
                        }
                    });
                }
            }
        });
        // Table destroyed - nuke any child rows
        api.on(destroyEvent, function (e, ctx) {
            if (settings !== ctx) {
                return;
            }
            for (var i = 0, iLen = data.length; i < iLen; i++) {
                let d = data[i];
                if (d && d.details) {
                    detailsRemove(api, i);
                }
            }
        });
    }
}
// Strings for the method names to help minification
var _emp = '';
var _child_obj = _emp + 'row().child';
var _child_mth = _child_obj + '()';
// data can be:
//  tr
//  string
//  jQuery or array of any of the above
Api.register(_child_mth, function (data, klass) {
    var _a;
    var ctx = this.context;
    if (data === undefined) {
        // get
        let details = ctx.length && this.length && ctx[0].data[this[0]]
            ? (_a = ctx[0].data[this[0]]) === null || _a === void 0 ? void 0 : _a.details
            : undefined;
        return details;
    }
    else if (data === true) {
        // show
        this.child.show();
    }
    else if (data === false) {
        // remove
        detailsRemove(this);
    }
    else if (ctx.length && this.length) {
        // set
        detailsAdd(ctx[0], ctx[0].data[this[0]], data, klass);
    }
    return this.inst(this.context, this);
});
Api.register([
    _child_obj + '.show()',
    _child_mth + '.show()' // only when `child()` was called with parameters
], function () {
    // it returns an object and this method is not executed)
    detailsDisplay(this, true);
    return this;
});
Api.register([
    _child_obj + '.hide()',
    _child_mth + '.hide()' // only when `child()` was called with parameters
], function () {
    // it returns an object and this method is not executed)
    detailsDisplay(this, false);
    return this;
});
Api.register([
    _child_obj + '.remove()',
    _child_mth + '.remove()' // only when `child()` was called with parameters
], function () {
    // it returns an object and this method is not executed)
    detailsRemove(this);
    return this;
});
Api.register(_child_obj + '.isShown()', function () {
    var ctx = this.context;
    if (ctx.length && this.length && ctx[0].data[this[0]]) {
        // detailsShown as false or undefined will fall through to return false
        return ctx[0].data[this[0]].detailsShow || false;
    }
    return false;
});

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Rows
 *
 * {}          - no selector - use all available rows
 * {integer}   - row data index
 * {node}      - TR node
 * {string}    - jQuery selector to apply to the TR elements
 * {array}     - jQuery array of nodes, or simply an array of TR nodes
 *
 */
function selectRows(settings, selector, opts) {
    var rows;
    var run = function (sel) {
        var selInt = util.conv.intVal(sel);
        var data = settings.data;
        // Short cut - selector is a number and no options provided (default is
        // all records, so no need to check if the index is in there, since it
        // must be - dev error if the index doesn't exist).
        if (selInt !== null && !opts) {
            return [selInt];
        }
        if (!rows) {
            rows = selectorRowIndexes(settings, opts);
        }
        if (selInt !== null && rows.indexOf(selInt) !== -1) {
            // Selector - integer
            return [selInt];
        }
        else if (sel === null || sel === undefined || sel === '') {
            // Selector - none
            return rows;
        }
        // Selector - function
        if (typeof sel === 'function') {
            return rows.map(function (idx) {
                var row = data[idx];
                return row && sel(idx, row.data, row.tr) ? idx : null;
            });
        }
        // Selector - node
        if (sel.nodeName) {
            var rowIdx = sel._DT_RowIndex; // Property added by DT for fast lookup
            var cellIdx = sel._DT_CellIndex;
            var row;
            if (rowIdx !== undefined) {
                // Make sure that the row is actually still present in the table
                row = data[rowIdx];
                return row && row.tr === sel ? [rowIdx] : [];
            }
            else if (cellIdx) {
                row = data[cellIdx.row];
                return row && row.tr === sel.parentNode ? [cellIdx.row] : [];
            }
            else {
                var host = Dom.s(sel).closest('*[data-dt-row]');
                return host.count() ? [parseInt(host.attr('data-dt-row'))] : [];
            }
        }
        // ID selector. Want to always be able to select rows by id, regardless
        // of if the tr element has been created or not, so can't rely upon
        // jQuery here - hence a custom implementation. This does not match
        // Sizzle's fast selector or HTML4 - in HTML5 the ID can be anything,
        // but to select it using a CSS selector engine (like Sizzle or
        // querySelect) it would need to need to be escaped for some characters.
        // DataTables simplifies this for row selectors since you can select
        // only a row. A # indicates an id any anything that follows is the id -
        // unescaped.
        if (typeof sel === 'string') {
            if (sel.charAt(0) === '#') {
                // get row index from id
                var rowObj = settings.ids[sel.replace(/^#/, '')];
                if (rowObj !== undefined) {
                    return [rowObj.idx];
                }
                // need to fall through to selector in case there is DOM id that
                // matches
            }
            else if (sel.match(/^(tr)?:eq\(\d+\)$/)) {
                // :eq() selector to get a row based on its position in the
                // selectable rows.
                let idx = parseInt(sel.replace(/[^\d]/g, ''));
                return rows[idx] !== undefined ? [rows[idx]] : [];
            }
        }
        // Get nodes in the order from the `rows` array with null values removed
        var nodes = util.array.removeEmpty(util.array.pluckOrder(settings.data, rows, 'tr'));
        // Selector - selector string, array of nodes or jQuery object.
        return Dom.s(nodes)
            .filter(sel)
            .mapTo((el) => el._DT_RowIndex);
    };
    var matched = selectorRun('row', selector, run, settings, opts);
    if (opts.order === 'current' || opts.order === 'applied') {
        sortDisplay(settings, matched);
    }
    return matched;
}
register('rows()', function (arg1, arg2) {
    let opts;
    let selector;
    // argument shifting
    if (arg1 === undefined) {
        // All rows - no selector or modifier
        selector = '';
    }
    else if (util.is.plainObject(arg1)) {
        // Arg1 is modifier overload
        selector = '';
        opts = arg1;
    }
    else {
        selector = arg1;
        opts = arg2;
    }
    opts = selectorOpts(opts);
    var inst = this.iterator('table', function (settings) {
        return selectRows(settings, selector, opts);
    }, true);
    // Want argument shifting here and in row_selector?
    inst.selector.rows = selector;
    inst.selector.opts = opts;
    return inst;
});
register('rows().every()', function (fn) {
    var opts = this.selector.opts;
    var counter = 0;
    return this.iterator('every', (settings, selectedIdx, tableIdx) => {
        let inst = this.row(selectedIdx, opts);
        fn.call(inst, selectedIdx, tableIdx, counter);
        counter++;
    });
});
register('rows().nodes()', function () {
    return this.iterator('row', function (settings, row) {
        var _a;
        return ((_a = settings.data[row]) === null || _a === void 0 ? void 0 : _a.tr) || undefined;
    }, true);
});
register('rows().data()', function () {
    return this.iterator(true, 'rows', function (settings, rows) {
        return util.array.pluckOrder(settings.data, rows, 'data');
    }, true);
});
registerPlural('rows().invalidate()', 'row().invalidate()', function (src) {
    return this.iterator('row', function (settings, row) {
        invalidateRow(settings, row, src);
    });
});
registerPlural('rows().indexes()', 'row().index()', function () {
    return this.iterator('row', function (settings, row) {
        return row;
    }, true);
});
registerPlural('rows().ids()', 'row().id()', function (hash) {
    var _a;
    var a = [];
    var context = this.context;
    // `iterator` will drop undefined values, but in this case we want them
    for (var i = 0, iLen = context.length; i < iLen; i++) {
        for (var j = 0, jen = this[i].length; j < jen; j++) {
            var id = context[i].rowIdFn((_a = context[i].data[this[i][j]]) === null || _a === void 0 ? void 0 : _a.data);
            a.push((hash === true ? '#' : '') + id);
        }
    }
    return this.inst(context, a);
});
registerPlural('rows().remove()', 'row().remove()', function () {
    this.iterator('row', function (settings, row) {
        var data = settings.data;
        var rowData = data[row];
        // Delete from the display arrays
        var idx = settings.displayMaster.indexOf(row);
        if (idx !== -1) {
            settings.displayMaster.splice(idx, 1);
        }
        // For server-side processing tables - subtract the deleted row from
        // the count
        if (settings.recordsDisplay > 0) {
            settings.recordsDisplay--;
        }
        // Check for an 'overflow' they case for displaying the table
        lengthOverflow(settings);
        // Remove the row's ID reference if there is one
        var id = settings.rowIdFn(rowData === null || rowData === void 0 ? void 0 : rowData.data);
        if (id !== undefined) {
            delete settings.ids[id];
        }
        data[row] = null;
    });
    return this;
});
register('rows.add()', function (rows) {
    var newRows = this.iterator('table', function (settings) {
        var row, i, iLen;
        var out = [];
        for (i = 0, iLen = rows.length; i < iLen; i++) {
            row = rows[i];
            if (row.nodeName && row.nodeName.toUpperCase() === 'TR') {
                out.push(addTr(settings, Dom.s(row))[0]);
            }
            else {
                out.push(addData(settings, row));
            }
        }
        return out;
    }, true);
    // Return an Api.rows() extended instance, so rows().nodes() etc can be used
    var modRows = this.rows(-1);
    modRows.pop();
    arrayApply(modRows, newRows);
    return modRows;
});
register('row()', function (selector, opts) {
    return selectorFirst(this.rows(selector, opts));
});
register('row().data()', function (data) {
    var _a;
    var ctx = this.context;
    if (data === undefined) {
        // Get
        return ctx.length && this.length && this[0].length
            ? (_a = ctx[0].data[this[0]]) === null || _a === void 0 ? void 0 : _a.data
            : undefined;
    }
    // Set
    var row = ctx[0].data[this[0]];
    row.data = data;
    // If the DOM has an id, and the data source is an array
    if (Array.isArray(data) && row.tr && row.tr.id) {
        util.set(ctx[0].rowId)(data, row.tr.id);
    }
    // Automatically invalidate
    invalidateRow(ctx[0], this[0][0], 'data');
    return this;
});
register('row().node()', function () {
    var ctx = this.context;
    if (ctx.length && this.length && this[0].length) {
        var row = ctx[0].data[this[0]];
        if (row && row.tr) {
            return row.tr;
        }
    }
    return null;
});
register('row.add()', function (row) {
    // Allow an array-like object to be passed in - only a single row is added
    // from it though - the first element in the set
    if (row && row.fn && row.length) {
        row = row[0];
    }
    var rows = this.iterator('table', function (settings) {
        // New column could cause a change in the cached column properties such
        // as type and width.
        invalidColumn(settings);
        if (row.nodeName && row.nodeName.toUpperCase() === 'TR') {
            return addTr(settings, Dom.s(row))[0];
        }
        return addData(settings, row);
    });
    // Return an Api.rows() extended instance, with the newly added row selected
    return this.row(rows[0]);
});

register('search()', function (input, regex, smart, caseInsen) {
    if (input === undefined) {
        let ctx = this.context;
        // get
        if (ctx.length === 0) {
            return;
        }
        return ctx[0].searches['*'].search;
    }
    // set
    return this.iterator('table', function (ctx) {
        if (!ctx.features.searching) {
            return;
        }
        let target = ctx.searches['*'];
        if (!target) {
            target = create$2();
        }
        if (typeof regex === 'object') {
            // New style object of options
            assign(target, regex);
        }
        else {
            // Compat for the old options
            assign(target, {
                regex: regex === null ? false : regex,
                smart: smart === null ? true : smart,
                caseInsensitive: caseInsen === null ? true : caseInsen
            });
        }
        target.search = input;
        ctx.searches['*'] = target;
        filterComplete(ctx);
    });
});
register('search.fixed()', function (name, search, options) {
    var ret = this.iterator(true, 'table', function (settings) {
        var _a;
        var fixed = settings.searchesFixed['*'];
        if (!name) {
            return Object.keys(fixed);
        }
        else if (search === undefined) {
            return (_a = fixed[name]) === null || _a === void 0 ? void 0 : _a.search;
        }
        else if (search === null) {
            delete fixed[name];
        }
        else {
            let target = fixed[name];
            if (!target || !util.is.plainObject(target)) {
                target = create$2();
            }
            if (options) {
                assign(target, options);
            }
            target.search = search;
            fixed[name] = target;
        }
        return this;
    });
    return name !== undefined && search === undefined ? ret[0] : ret;
});
register(['columns().search()', 'column().search()'], function (input, regex, smart, caseInsen) {
    var _a;
    if (input === undefined) {
        let name = this[0].join(',');
        return this.context.length
            ? ((_a = this.context[0].searches[name]) === null || _a === void 0 ? void 0 : _a.search) || ''
            : '';
    }
    return this.iterator('columns', function (ctx, columns) {
        let colIdxs = columns.join(',');
        let target = ctx.searches[colIdxs];
        if (!target) {
            target = create$2();
        }
        // Delete the search for custom grouping types if removing
        if ((input === '' || input === null) && columns.length > 1) {
            delete ctx.searches[colIdxs];
            return;
        }
        if (typeof regex === 'object') {
            // New style object of options
            assign(target, regex);
        }
        else {
            // Compat for the old options
            assign(target, {
                regex: regex === null ? false : regex,
                smart: smart === null ? true : smart,
                caseInsensitive: caseInsen === null ? true : caseInsen
            });
        }
        target.search = input;
        target.columns = columns.slice();
        ctx.searches[colIdxs] = target;
        filterComplete(ctx);
    });
});
register(['columns().search.fixed()', 'column().search.fixed()'], function (name, search, options) {
    // No name, just return the names of the fixed searches applied to these
    // columns
    if (!name) {
        return this.iterator(true, 'columns', function (settings, columns) {
            let colIdxs = columns.join(',');
            let fixed = settings.searchesFixed[colIdxs];
            return fixed ? Object.keys(fixed) : [];
        });
    }
    // Get the value from an existing search
    if (search === undefined) {
        if (!this.context.length) {
            return undefined;
        }
        else {
            let colIdxs = this[0].join(',');
            let fixed = this.context[0].searchesFixed[colIdxs];
            return fixed && fixed[name] ? fixed[name].search : undefined;
        }
    }
    // Set a search, possibly with options
    return this.iterator(true, 'columns', function (settings, columns) {
        let colIdxs = columns.join(',');
        let fixed = settings.searchesFixed[colIdxs];
        if (!fixed) {
            fixed = {};
            settings.searchesFixed[colIdxs] = fixed;
        }
        if (search === null) {
            delete fixed[name];
        }
        else {
            let target = fixed[name];
            if (!target || !util.is.plainObject(target)) {
                target = create$2();
            }
            if (options) {
                assign(target, options);
            }
            target.search = search;
            target.columns = columns;
            fixed[name] = target;
        }
        return this;
    });
});

register('state()', function (set, ignoreTime = true) {
    // getter
    if (!set) {
        return this.context.length ? this.context[0].stateSaved : null;
    }
    let setMutate = assignDeep({}, set);
    // setter
    return this.iterator('table', function (settings) {
        implementState(settings, setMutate, ignoreTime, function () { });
    });
});
register('state.clear()', function () {
    return this.iterator('table', function (settings) {
        // Save an empty object
        settings.stateSaveCallback.call(settings.instance, settings, {});
    });
});
register('state.loaded()', function () {
    return this.context.length ? this.context[0].stateLoaded : null;
});
register('state.save()', function () {
    return this.iterator('table', function (settings) {
        saveState(settings);
    });
});

/**
 * Selector for HTML tables. Apply the given selector to the give array of
 * DataTables settings objects.
 *
 * @param selector Selector string or integer
 * @param a Array of DataTables settings objects to be filtered
 * @return Selected table notes
 */
function table_selector(selector, a) {
    if (Array.isArray(selector)) {
        var result = [];
        selector.forEach(function (sel) {
            var inner = table_selector(sel, a);
            arrayApply(result, inner);
        });
        return result.filter(item => !!item);
    }
    // Integer is used to pick out a table by index
    if (typeof selector === 'number') {
        return [a[selector]];
    }
    // Perform a selector on the table nodes
    var nodes = a.map(function (el) {
        return el.table;
    });
    return Dom
        .s(nodes)
        .filter(selector)
        .mapTo(el => {
        // Need to translate back from the table node to the settings
        var idx = nodes.indexOf(el);
        return a[idx];
    });
}
register('tables()', function (selector) {
    // A new instance is created if there was a selector specified
    return selector !== undefined && selector !== null
        ? this.inst(table_selector(selector, this.context))
        : this.inst(this.context);
});
register('table()', function (selector) {
    return selectorFirst(this.tables(selector));
});
// Common methods, combined to reduce size
[
    ['nodes', 'node', 'table'],
    ['body', 'body', 'tbody'],
    ['header', 'header', 'thead'],
    ['footer', 'footer', 'tfoot']
].forEach(function (item) {
    registerPlural('tables().' + item[0] + '()', 'table().' + item[1] + '()', function () {
        return this.iterator('table', ctx => ctx[item[2]], true);
    });
});
// Structure methods
['header', 'footer'].forEach(function (item) {
    register('table().' + item + '.structure()', function (selector) {
        var indexes = this.columns(selector).indexes().flatten().toArray();
        var ctx = this.context[0];
        var structure = headerLayout(ctx, ctx[item], indexes);
        // The structure is in column index order - but from this method we
        // want the return to be in the columns() selector API order. In
        // order to do that we need to map from one form to the other
        var orderedIndexes = indexes.slice().sort(function (a, b) {
            return a - b;
        });
        return structure.map(function (row) {
            return indexes.map(function (colIdx) {
                return row[orderedIndexes.indexOf(colIdx)];
            });
        });
    });
});
registerPlural('tables().containers()', 'table().container()', function () {
    return this.iterator('table', function (ctx) {
        return ctx.tableWrapper;
    }, true);
});
register('tables().every()', function (fn) {
    return this.iterator('table', (s, i) => {
        fn.call(this.table(i), i);
    });
});
register('caption()', function (value, side) {
    var context = this.context;
    // Getter - return existing node's content
    if (value === undefined) {
        var node = context[0].captionNode;
        return node && context.length ? node.innerHTML : null;
    }
    return this.iterator('table', function (ctx) {
        var table = Dom.s(ctx.table);
        var caption = Dom.s(ctx.captionNode);
        var container = Dom.s(ctx.tableWrapper);
        // Create the node if it doesn't exist yet
        if (!caption.count()) {
            caption = Dom.c('caption').html(value);
            ctx.captionNode = caption.get(0);
            // If side isn't set, we need to insert into the document to let
            // the CSS decide so we can read it back, otherwise there is no
            // way to know if the CSS would put it top or bottom for
            // scrolling
            if (!side) {
                table.prepend(caption);
                side = caption.css('caption-side');
            }
        }
        caption.html(value);
        if (side) {
            caption.css('caption-side', side);
            caption.get(0)._captionSide = side;
        }
        if (container.find('div.dt-scroll').count()) {
            var selector = side === 'top' ? 'head' : 'foot';
            container
                .find('div.dt-scroll-' + selector + ' table')
                .prepend(caption);
        }
        else {
            table.prepend(caption);
        }
    }, true);
});
register('caption.node()', function () {
    var ctx = this.context;
    return ctx.length ? ctx[0].captionNode : null;
});

/**
 * What's this!? "DataTables Plus" is a commercial set of extensions for
 * DataTables, such as Editor, and the functions in this file allow a license
 * key to be provided (`DataTable.key(...)`) to unlock those features.
 *
 * This is the modal that I've selected to make DataTables sustainable, open
 * source core, with some commercial extensions available.
 *
 * Please support DataTables and open source by purchasing a Plus license from
 * https://datatables.net/plus .
 */
let _ready = false;
let _notice;
let _processingKey = false;
let _delayedReleaseDate = null;
let _delayedSoftware = null;
const _licenseInfo = {
    developers: 0,
    type: null,
    expires: null,
    valid: null
};
const _wm = Dom.c('div');
const _publicKey = 'BE1A9w9D9U/4s4/TogY+1sW/dLJ8IquzK1PmV70J93ZTIvXMZ0eV2NAb52ntpgwVFySSB2fOI7geLNO737rQAyo=';
/**
 * Convert a base64 string to a binary array
 *
 * @param b64 Source string
 * @returns Array
 */
function b64ToBuf(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
/**
 * Logic to check the trial and plus license expiry and display messages if
 * needed. There is particular consideration for checking a release date of
 * software, as the license for DataTables Plus is perpetual for the version
 * purchased, and it shouldn't show a message for the purchased version ever.
 *
 * @param releaseDate The date the software was released on.
 * @param software The software name being validated. Can be null for a general
 *   "Plus" check.
 * @returns true if valid, false otherwise
 */
function check(releaseDate, software) {
    let expires = _licenseInfo.expires;
    if (!getSubtle()) {
        noticePrep('Unable to validate license key');
        noticeDisplay();
    }
    else if (_licenseInfo.valid === false) {
        noticePrep('License key invalid');
        noticeDisplay();
    }
    else if (_licenseInfo.type === 'trial') {
        // Trail is for plus, so the software type isn't taken into account
        let remaining = expires
            ? Math.ceil((expires.getTime() - new Date().getTime()) / 86400000)
            : -1;
        if (remaining < 0) {
            // Trial expires
            consoleMsg('Your trial has now expired - https://datatables.net/plus', 'warn');
            noticePrep('Trial expired');
            noticeDisplay();
            return false;
        }
        else {
            // Let the user know when it is going to expire with a console
            // message.
            consoleMsg('Your trial expires in ' +
                remaining +
                ' day' +
                (remaining === 1 ? '' : 's'));
            return true;
        }
    }
    else if (software === null) {
        // Validating the key only - there hasn't been any specific software
        // calling the `plus` parameter yet. The key is good, so carry on.
        return true;
    }
    else if (
    // Checking if the build version can be used with this key
    _licenseInfo.type === 'plus' ||
        (_licenseInfo.type === 'editor' && software === 'editor')) {
        if (!expires || new Date(releaseDate) > expires) {
            noticePrep('Upgrade required for this version');
            noticeDisplay();
            return false;
        }
        return true;
    }
    else if (_licenseInfo.type === 'editor' && software !== 'editor') {
        // Editor specific license
        noticePrep('License for Editor only. Upgrade for Plus');
        noticeDisplay();
        return false;
    }
    noticePrep();
    noticeDisplay();
    return false;
}
/**
 * Common log message handling
 *
 * @param msg Message to show
 * @param level Log level
 */
function consoleMsg(msg, level = 'log') {
    let fn = level === 'log' ? console.log : console.warn;
    fn('%cDataTables Plus%c ' + msg, 'background: #007bff; color: #fff; padding: 2px 5px;', 'color: inherit;');
}
/**
 * Set the DataTables Plus key to use
 *
 * @param key DataTables Plus key - obtain from https://datatables.net/account .
 */
const key = function (key) {
    _processingKey = true;
    // Run the verification of the key
    verify(key)
        .then(result => {
        _processingKey = false;
        check(_delayedReleaseDate, _delayedSoftware);
    })
        .catch(() => {
        _processingKey = false;
        check(_delayedReleaseDate, _delayedSoftware);
    });
};
/**
 * Build the notice
 *
 * @returns
 */
function noticePrep(text) {
    if (!_ready) {
        let shadow = _wm[0].attachShadow({ mode: 'closed' });
        let notice = Dom.c('div').css({
            position: 'fixed',
            bottom: '1em',
            right: '1em',
            border: '1px solid #ffc107',
            background: '#fff3cd',
            color: '#856404',
            padding: '0.5em 1em',
            'font-family': 'sans-serif',
            'font-size': '12px',
            'border-radius': '4px',
            'z-index': '10000',
            'box-shadow': '0 2px 5px rgba(0,0,0,0.2)'
        });
        Dom.c('a')
            .attr('href', 'https://datatables.net/tn/25')
            .attr('target', '_blank')
            .css({
            color: 'inherit',
            'text-decoration': 'none'
        })
            .appendTo(notice);
        if (!text) {
            text = 'License key required';
        }
        shadow.appendChild(notice[0]);
        _notice = notice;
        _ready = true;
    }
    if (text) {
        _notice
            .find('a')
            .html('DataTables Plus: ' + text + ' - learn more &#187;');
    }
}
/**
 * Display the license notice
 */
function noticeDisplay() {
    if (!_processingKey && document.body && !document.body.contains(_wm[0])) {
        document.body.appendChild(_wm[0]);
    }
}
/**
 * Validate the license string, which is in two parts - the first is a payload
 * that provides a small amount of information about the license, and the second
 * which is the license key.
 *
 * @param licenseString Key to validate
 * @returns Promise with validation information
 */
function verify(licenseString) {
    return new Promise(function (resolve) {
        try {
            var parts = licenseString.split(':');
            if (parts.length !== 2) {
                _licenseInfo.valid = false;
                return resolve();
            }
            var payload = parts[0];
            var signatureB64 = parts[1];
            // Extract the payload to be useful
            var payloadParts = payload.match(/(plus|trial|editor)_(\d+)_(\d{4})(\d{2})(\d{2})/);
            if (!payloadParts || payloadParts.length !== 6) {
                _licenseInfo.valid = false;
                return resolve();
            }
            _licenseInfo.type = payloadParts[1];
            _licenseInfo.developers = parseInt(payloadParts[2]);
            _licenseInfo.expires = new Date(payloadParts[3] + '-' + payloadParts[4] + '-' + payloadParts[5]);
            var subtle = getSubtle();
            var rawKey = b64ToBuf(_publicKey);
            var rawSig = b64ToBuf(signatureB64);
            var data = new TextEncoder().encode(payload);
            // Non-secure environments don't have cryptographic verification
            // available.
            if (!subtle) {
                _licenseInfo.valid = false;
                resolve();
                return;
            }
            subtle
                .importKey('raw', rawKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
                .then(function (key) {
                return subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-256' } }, key, rawSig, data);
            })
                .then(function (isValid) {
                _licenseInfo.valid = isValid;
                resolve();
            })
                .catch(function () {
                _licenseInfo.valid = false;
                resolve();
            });
        }
        catch (e) {
            _licenseInfo.valid = false;
            resolve();
        }
    });
}
/**
 * Create the `plus` function on `DataTable` which Plus extensions can call to
 * determine if the license key is valid and in date for the release. The
 * resulting function is called like this: `DataTable.plus('2026-12-25')` and
 * will return `true` or `false` depending on the key that was given (or not).
 *
 * @param DataTable The DataTable host object
 */
function plus (DataTable) {
    Object.defineProperty(DataTable, 'plus', {
        value: function (releaseDate, software = '') {
            // Unsecure sites are only useful for development, so allow there
            // and on the site.
            let host = window.location.hostname;
            let isDev = host === '192.168.234.234' ||
                host.endsWith('.datatables.net') ||
                host === 'datatables.net';
            if (isDev) {
                return true;
            }
            if (_processingKey) {
                // The validation of the key is async, so there is a chance that
                // it could still be happening when this runs. We just queue the
                // last one if that is the case.
                _delayedReleaseDate = releaseDate;
                _delayedSoftware = software;
                return true;
            }
            return check(releaseDate, software);
        },
        configurable: false,
        enumerable: false,
        writable: false
    });
}
function getSubtle() {
    // Backwards compat for old browsers
    let cryptoObj = window.crypto || window.msCrypto;
    let subtle = cryptoObj.subtle || cryptoObj.webkitSubtle;
    return subtle;
}

/**
 * CommonJS factory function pass through. This will check if the arguments
 * given are a window object or a jQuery object. If so they are set accordingly.
 *
 * @param root Window
 * @param jq jQuery
 * @returns Indicator
 */
function factory(root, jq) {
    var is = false;
    // Test if the first parameter is a window object
    if (root && root.document) {
        window = root;
        document = root.document;
    }
    // Test if the second parameter is a jQuery object
    if (jq && jq.fn && jq.fn.jquery) {
        is = true;
    }
    return is;
}
/**
 * Check if a `<table>` node is a DataTable table already or not.
 *
 * @param table Table node or selector for the table to test. Note that if more
 *   than more than one table is passed on, only the first will be checked
 * @returns true the table given is a DataTable, or false otherwise
 */
const isDataTable = function (table) {
    if (table instanceof Api) {
        return true;
    }
    else if (arrayLike(table)) {
        // jQuery compatibility
        table = Array.from(table);
    }
    var t = Dom.s(table).get(0);
    var is = false;
    for (let i = 0; i < ext.settings.length; i++) {
        let ctx = ext.settings[i];
        var head = ctx.scrollHead ? ctx.scrollHead.find('table').get(0) : null;
        var foot = ctx.scrollFoot ? ctx.scrollFoot.find('table').get(0) : null;
        if (ctx.table === t || head === t || foot === t) {
            is = true;
        }
    }
    return is;
};
/**
 * Get all DataTable tables that have been initialised - optionally you can
 * select to get only currently visible tables.
 *
 * @param visible Flag to indicate if you want all (default) or visible tables
 *   only.
 * @returns Array of `table` nodes (not DataTable instances) which are
 *   DataTables
 */
const tables = function (visible) {
    var api = false;
    if (visible && typeof visible !== 'boolean') {
        api = visible.api || false;
        visible = visible.visible || false;
    }
    var a = ext.settings
        .filter(function (o) {
        return !visible || (visible && Dom.s(o.table).isVisible())
            ? true
            : false;
    })
        .map(function (o) {
        return o.table;
    });
    return api ? new Api(a) : a;
};

function _divProp(el, prop, val) {
    if (val) {
        el[prop] = val;
    }
}
register$2('div', function (settings, opts) {
    var n = document.createElement('div');
    if (opts) {
        _divProp(n, 'className', opts.className);
        _divProp(n, 'id', opts.id);
        _divProp(n, 'innerHTML', opts.html);
        _divProp(n, 'textContent', opts.text);
    }
    return n;
});

register$2('info', function (settings, optsIn) {
    // For compatibility with the legacy `info` top level option
    if (!settings.features.info) {
        return null;
    }
    let lang = settings.language, tid = settings.tableId, n = Dom.c('div').classAdd(settings.classes.info.container);
    let opts = Object.assign({
        callback: lang.infoCallback,
        empty: lang.infoEmpty,
        postfix: lang.infoPostFix,
        search: lang.infoFiltered,
        text: lang.info
    }, optsIn);
    // Update display on each draw
    settings.callbacks.draw.push(function (s) {
        updateInfo(s, opts, n);
    });
    // For the first info display in the table, we add a callback and aria
    // information.
    if (!settings.infoEl) {
        n.attr({
            'aria-live': 'polite',
            id: tid + '_info',
            role: 'status'
        });
        // Table is described by our info div
        Dom.s(settings.table).attr('aria-describedby', tid + '_info');
        settings.infoEl = n;
    }
    return n;
}, 'i');
/**
 * Update the information elements in the display
 *  @param settings DataTables settings object
 *  @param opts
 *  @param node
 */
function updateInfo(settings, opts, node) {
    var start = settings.displayStart + 1, end = displayEnd(settings), max = recordsTotal(settings), total = recordsDisplay(settings), out = total ? opts.text : opts.empty;
    if (total !== max) {
        // Record set after filtering
        out += ' ' + opts.search;
    }
    // Convert the macros
    out += opts.postfix;
    out = macros(settings, out);
    if (opts.callback) {
        out = opts.callback.call(settings.instance, settings, start, end, max, total, out);
    }
    node.html(out);
    callbackFire(settings, null, 'info', [settings, node.get(0), out]);
}

// opts
// - type - button configuration
// - buttons - number of buttons to show - must be odd
register$2('paging', function (settings, optsIn) {
    // Don't show the paging input if the table doesn't have paging enabled
    if (!settings.features.paging) {
        return null;
    }
    let opts = Object.assign({
        buttons: ext.pager.numbers_length,
        type: settings.pagingType,
        boundaryNumbers: true,
        firstLast: true,
        previousNext: true,
        numbers: true
    }, optsIn);
    let host = Dom
        .c('div')
        .classAdd(settings.classes.paging.container +
        (opts.type ? ' paging_' + opts.type : ''))
        .append(Dom
        .c('nav')
        .attr('aria-label', 'pagination')
        .classAdd(settings.classes.paging.nav));
    let draw = function () {
        _pagingDraw(settings, host.children(), opts);
    };
    settings.callbacks.draw.push(draw);
    // Responsive redraw of paging control
    Dom.s(settings.table).on('column-sizing.dt.DT', draw);
    return host;
}, 'p');
/**
 * Dynamically create the button type array based on the configuration options.
 * This will only happen if the paging type is not defined.
 */
function _pagingDynamic(opts) {
    let out = [];
    if (opts.numbers) {
        out.push('numbers');
    }
    if (opts.previousNext) {
        out.unshift('previous');
        out.push('next');
    }
    if (opts.firstLast) {
        out.unshift('first');
        out.push('last');
    }
    return out;
}
function _pagingDraw(settings, host, opts) {
    if (!settings.initDone) {
        return;
    }
    let plugin = opts.type ? ext.pager[opts.type] : _pagingDynamic, aria = settings.language.aria.paginate || {}, start = settings.displayStart, len = settings.pageLength, visRecords = recordsDisplay(settings), all = len === -1, page = all ? 0 : Math.ceil(start / len), pages = all ? (visRecords ? 1 : 0) : Math.ceil(visRecords / len), buttons = [], buttonEls = [], buttonsNested = plugin(opts).map(function (val) {
        return val === 'numbers'
            ? pagingNumbers(page, pages, opts.buttons, opts.boundaryNumbers)
            : val;
    });
    // .flat() would be better, but not supported in old Safari
    buttons = buttons.concat.apply(buttons, buttonsNested);
    for (let i = 0; i < buttons.length; i++) {
        let button = buttons[i];
        let btnInfo = _pagingButtonInfo(settings, button, page, pages);
        let btn = renderer(settings, 'pagingButton')(settings, button, btnInfo.display, btnInfo.active, btnInfo.disabled);
        let ariaLabel = typeof button === 'string'
            ? aria[button]
            : aria.number
                ? aria.number + (button + 1)
                : null;
        // Common attributes
        Dom.s(btn.clicker).attr({
            'aria-controls': settings.tableId,
            'aria-disabled': btnInfo.disabled ? 'true' : null,
            'aria-current': btnInfo.active ? 'page' : null,
            'aria-label': ariaLabel,
            'data-dt-idx': button,
            tabIndex: btnInfo.disabled
                ? -1
                : settings.tabIndex &&
                    btn.clicker.nodeName.toLowerCase() !== 'span'
                    ? settings.tabIndex
                    : null // `0` doesn't need a tabIndex since it is the default
        });
        if (typeof button !== 'number') {
            Dom.s(btn.clicker).classAdd(button);
        }
        bindAction(btn.clicker, '', function (e) {
            e.preventDefault();
            pageChange(settings, button, true);
        });
        buttonEls.push(btn.display);
    }
    let wrapped = renderer(settings, 'pagingContainer')(settings, buttonEls);
    let activeEl = host.find(document.activeElement).attr('data-dt-idx');
    host.empty().append(wrapped);
    if (activeEl) {
        host.find('[data-dt-idx="' + activeEl + '"]').trigger('focus');
    }
    // Responsive - check if the buttons are over two lines based on the
    // height of the buttons and the container.
    if (buttonEls.length) {
        let outerHeight = Dom.s(buttonEls[0]).height('withBorder');
        if (opts.buttons > 1 && // prevent infinite
            outerHeight > 0 && // will be 0 if hidden
            host.height() >= outerHeight * 2 - 10) {
            _pagingDraw(settings, host, Object.assign({}, opts, { buttons: opts.buttons - 2 }));
        }
    }
}
/**
 * Get properties for a button based on the current paging state of the table
 *
 * @param settings DT settings object
 * @param button The button type in question
 * @param page Table's current page
 * @param pages Number of pages
 * @returns Info object
 */
function _pagingButtonInfo(settings, button, page, pages) {
    let lang = settings.language.paginate;
    let o = {
        display: '',
        active: false,
        disabled: false
    };
    switch (button) {
        case 'ellipsis':
            o.display = '&#x2026;';
            break;
        case 'first':
            o.display = lang.first;
            if (page === 0) {
                o.disabled = true;
            }
            break;
        case 'previous':
            o.display = lang.previous;
            if (page === 0) {
                o.disabled = true;
            }
            break;
        case 'next':
            o.display = lang.next;
            if (pages === 0 || page === pages - 1) {
                o.disabled = true;
            }
            break;
        case 'last':
            o.display = lang.last;
            if (pages === 0 || page === pages - 1) {
                o.disabled = true;
            }
            break;
        default:
            if (typeof button === 'number') {
                o.display = settings.formatNumber(button + 1, settings);
                if (page === button) {
                    o.active = true;
                }
            }
            break;
    }
    return o;
}

var __lengthCounter = 0;
// opts
// - menu
// - text
register$2('pageLength', function (settings, optsIn) {
    var features = settings.features;
    // For compatibility with the legacy `pageLength` top level option
    if (!features.paging || !features.lengthChange) {
        return null;
    }
    let opts = Object.assign({
        menu: settings.lengthMenu,
        text: settings.language.lengthMenu
    }, optsIn);
    let classes = settings.classes.length, tableId = settings.tableId, menu = opts.menu, lengths = [], language = [], i;
    // Options can be given in a number of ways
    if (Array.isArray(menu[0])) {
        // Old 1.x style - 2D array
        lengths = menu[0];
        language = menu[1];
    }
    else {
        for (i = 0; i < menu.length; i++) {
            // An object with different label and value
            if (plainObject(menu[i])) {
                lengths.push(menu[i].value);
                language.push(menu[i].label);
            }
            else {
                // Or just a number to display and use
                lengths.push(menu[i]);
                language.push(menu[i]);
            }
        }
    }
    // We can put the <select> outside of the label if it is at the start or
    // end which helps improve accessability (not all screen readers like
    // implicit for elements).
    var end = opts.text.match(/_MENU_$/);
    var start = opts.text.match(/^_MENU_/);
    var removed = opts.text.replace(/_MENU_/, '');
    var str = '<label>' + opts.text + '</label>';
    if (start) {
        str = '_MENU_<label>' + removed + '</label>';
    }
    else if (end) {
        str = '<label>' + removed + '</label>_MENU_';
    }
    // Wrapper element - use a span as a holder for where the select will go
    var tmpId = 'tmp-' + +new Date();
    var div = Dom.c('div')
        .classAdd(classes.container)
        .html(str.replace('_MENU_', '<span id="' + tmpId + '"></span>'));
    // Save text node content for macro updating
    var textNodes = [];
    Array.prototype.slice
        .call(div.find('label').get(0).childNodes)
        .forEach(function (el) {
        if (el.nodeType === Node.TEXT_NODE) {
            textNodes.push({
                el: el,
                text: el.textContent
            });
        }
    });
    // Update the label text in case it has an entries value
    var updateEntries = function (len) {
        textNodes.forEach(function (node) {
            node.el.textContent = macros(settings, node.text, len);
        });
    };
    // Next, the select itself, along with the options
    var select = Dom.c('select')
        .attr('aria-controls', tableId)
        .attr('autocomplete', 'off')
        .classAdd(classes.select);
    for (i = 0; i < lengths.length; i++) {
        // Attempt to look up the length from the i18n options
        var label = settings.api.i18n('lengthLabels.' + lengths[i], null);
        if (label === null) {
            // If not present, fallback to old style
            label =
                typeof language[i] === 'number'
                    ? settings.formatNumber(language[i], settings)
                    : language[i];
        }
        select.get(0)[i] = new Option(label, lengths[i]);
    }
    // Swap in the select list
    div.find('#' + tmpId).replaceWith(select);
    // Can't use `select` variable as user might provide their own and the
    // reference is broken by the use of outerHTML
    div.find('select')
        .attr('id', 'dt-length-' + __lengthCounter)
        .val(settings.pageLength)
        .on('change.DT', function () {
        lengthChange(settings, select.val());
        draw(settings);
    });
    // add for and id to label and input
    div.find('label').attr('for', 'dt-length-' + __lengthCounter);
    __lengthCounter++;
    // Update node value whenever anything changes the table's length
    Dom.s(settings.table).on('length.dt.DT', function (e, s, len) {
        if (settings === s) {
            let localSelect = div.find('select');
            // Remove any temporary values
            localSelect.find('option[data-dt-len-tmp]').remove();
            let option = localSelect.find('option[value="' + len + '"]');
            // If the select list doesn't have the target value, then we
            // need to add it for display.
            if (!option.length) {
                let after = findInsertBeforePoint(select, len);
                let tempOption = Dom.c('option')
                    .val(len)
                    .text(len)
                    .attr('data-dt-len-tmp', true);
                if (after && after.length) {
                    tempOption.insertBefore(after);
                }
                else {
                    localSelect.append(tempOption);
                }
            }
            localSelect.val(len);
            // Resolve plurals in the text for the new length
            updateEntries(len);
        }
    });
    updateEntries(settings.pageLength);
    return div;
}, 'l');
/**
 * Find the element to insert the temporary option before to keep the sequence.
 *
 * @param select Select element
 * @param insertValue Page length value
 * @returns Target option or null if not found
 */
function findInsertBeforePoint(select, insertValue) {
    let options = select.find('option');
    let values = options.mapTo(el => parseInt(el.value));
    let idx = values.findIndex(val => val > insertValue);
    return idx < -1 ? null : options.eq(idx);
}

let __searchCounter = 0;
register$2('search', function (settings, optsIn) {
    // Don't show the input if filtering isn't available on the table
    if (!settings.features.searching) {
        return null;
    }
    let classes = settings.classes.search;
    let tableId = settings.tableId;
    let language = settings.language;
    let input = '<input type="search" class="' +
        classes.input +
        '" autocomplete="off"/>';
    let opts = util.object.assignDeep({
        columns: '*',
        placeholder: language.searchPlaceholder,
        processing: false,
        text: language.search
    }, optsIn);
    // The _INPUT_ is optional - is appended if not present
    if (opts.text.indexOf('_INPUT_') === -1) {
        opts.text += '_INPUT_';
    }
    opts.text = macros(settings, opts.text);
    let indexes = settings.api.columns(opts.columns).indexes().toArray();
    let searchName = opts.columns === '*' ? '*' : indexes.join(',');
    let appliedSearch = settings.searches[searchName];
    if (!appliedSearch) {
        appliedSearch = create$2();
        settings.searches[searchName] = appliedSearch;
    }
    appliedSearch.columns = indexes;
    // We can put the <input> outside of the label if it is at the start or
    // end which helps improve accessability (not all screen readers like
    // implicit for elements).
    let end = opts.text.match(/_INPUT_$/);
    let start = opts.text.match(/^_INPUT_/);
    let removed = opts.text.replace(/_INPUT_/, '');
    let str = '<label>' + opts.text + '</label>';
    if (start) {
        str = '_INPUT_<label>' + removed + '</label>';
    }
    else if (end) {
        str = '<label>' + removed + '</label>_INPUT_';
    }
    let filter = Dom.c('div')
        .classAdd(classes.container)
        .html(str.replace(/_INPUT_/, input));
    // add for and id to label and input
    filter.find('label').attr('for', 'dt-search-' + __searchCounter);
    filter.find('input').attr('id', 'dt-search-' + __searchCounter);
    __searchCounter++;
    let searchFn = function (event) {
        let val = this.value;
        if (appliedSearch.return && event.key !== 'Enter') {
            return;
        }
        /* Now do the filter */
        if (val != appliedSearch.search) {
            processingRun(settings, opts.processing, function () {
                appliedSearch.search = val;
                filterComplete(settings);
                // Need to redraw, without resorting
                settings.displayStart = 0;
                draw(settings);
            });
        }
    };
    let searchDelay = settings.searchDelay;
    let filterEl = filter
        .find('input')
        .val(textValue(appliedSearch.search))
        .attr('placeholder', opts.placeholder)
        .on('keyup.DT search.DT input.DT paste.DT cut.DT', searchDelay ? util.debounce(searchFn, searchDelay) : searchFn)
        .on('mouseup.DT', function (e) {
        // Edge fix! Edge 17 does not trigger anything other than mouse
        // events when clicking on the clear icon (Edge bug 17584515).
        // This is safe in other browsers as `searchFn` checks the value
        // to see if it has changed. In other browsers it won't have.
        setTimeout(function () {
            searchFn.call(filterEl.get(0), e);
        }, 10);
    })
        .on('keypress.DT', function (e) {
        /* Prevent form submission */
        if (e.keyCode == 13) {
            return false;
        }
    })
        .attr('aria-controls', tableId);
    // Update the input elements whenever the table is filtered
    Dom.s(settings.table).on('search.dt.DT', function (ev, s) {
        if (settings === s && filterEl.get(0) !== document.activeElement) {
            let host = settings.searches[searchName];
            filterEl.val(textValue(host.search));
        }
    });
    return filter;
}, 'f');
/**
 * Convert a search input into a plain string value for display. This is needed
 * as the value could be a function or regex, which can't be displayed in the
 * input element.
 *
 * @param val Search term
 * @returns String version
 */
function textValue(val) {
    if (val instanceof RegExp) {
        return val.toString();
    }
    else if (typeof val !== 'function') {
        return val;
    }
    return '';
}

const defaults$1 = {
    ajax: null,
    ajaxDataGet: false,
    api: null,
    browser: {
        barWidth: 0,
        scrollbarLeft: false
    },
    callbacks: {
        destroy: [],
        draw: [],
        footer: [],
        header: [],
        init: [],
        preDraw: [],
        row: [],
        rowCreated: [],
        stateLoadParams: [],
        stateLoaded: [],
        stateSaveParams: []
    },
    caption: '',
    captionNode: null,
    classes: {},
    columns: [],
    containerWidth: -1,
    data: [],
    deferLoading: false,
    destroyWidth: 0,
    destroying: false,
    display: [],
    displayMaster: [],
    displayStart: 0,
    displayStartInit: -1,
    doingDraw: false,
    dom: null,
    drawCount: 0,
    drawError: -1,
    drawHold: false,
    features: {
        autoWidth: false,
        deferRender: false,
        info: false,
        lengthChange: false,
        orderClasses: false,
        orderMulti: false,
        ordering: false,
        paging: false,
        processing: false,
        searching: false,
        serverSide: false,
        stateSave: false
    },
    footer: [],
    header: [],
    ids: {},
    init: {},
    initDone: false,
    initialised: false,
    language: {
        ajax: '',
        aria: {
            orderable: '',
            orderableRemove: '',
            orderableReverse: '',
            paginate: {
                first: '',
                last: '',
                next: '',
                number: '',
                previous: ''
            }
        },
        decimal: '',
        emptyTable: '',
        entries: { _: '' },
        info: '',
        infoEmpty: '',
        infoFiltered: '',
        infoPostFix: '',
        lengthMenu: '',
        lengthLabels: {},
        loadingRecords: '',
        paginate: {
            first: '',
            last: '',
            next: '',
            previous: ''
        },
        processing: '',
        search: '',
        searchPlaceholder: '',
        thousands: '',
        url: '',
        zeroRecords: ''
    },
    lastOrder: [],
    layout: {},
    loadingState: false,
    order: [],
    orderCellsTop: null,
    orderDescReverse: false,
    orderFixed: [],
    orderHandler: true,
    orderIndicators: true,
    pageLength: 10,
    pagingControls: 0,
    pagingType: 'two_button',
    searchCols: [],
    recordsDisplay: 0,
    recordsTotal: 0,
    renderer: null,
    resizeObserver: null,
    reszEvt: false,
    rowId: '',
    rowReadObject: false,
    scroll: {
        barWidth: 0,
        collapse: null,
        x: '',
        xInner: '',
        y: ''
    },
    scrollBarVis: false,
    searchDelay: 0,
    searches: {},
    searchesFixed: {
        '*': {}
    },
    serverMethod: null,
    sortDetails: [],
    stateDuration: 0,
    stateLoadCallback: () => {
        return {};
    },
    stateLoaded: null,
    stateSaveCallback: () => { },
    stateSaved: null,
    tabIndex: 0,
    tableId: '',
    titleRow: null,
    typeDetect: true,
    unique: '',
    wasFiltered: false,
    wasOrdered: false,
    windowResizeCb: () => { }
};
/**
 * Create a new context object
 *
 * @param parts Values to assign, otherwise the defaults will be used
 * @returns New object
 */
function create(parts = {}) {
    return util.object.assignDeep({}, defaults$1, parts);
}

var models = {
    Column: Settings,
    Row: create$1,
    Search: create$2,
    Settings: create
};

/**
 * Initialisation options that can be given to DataTables at initialisation
 * time.
 */
const defaults = {
    ajax: null,
    autoWidth: true,
    caption: '',
    classes: {},
    column: defaults$4,
    columnDefs: null,
    columns: null,
    createdRow: null,
    data: null,
    deferLoading: null,
    deferRender: true,
    destroy: false,
    displayStart: 0,
    dom: null,
    drawCallback: null,
    footerCallback: null,
    formatNumber: function (toFormat, ctx) {
        return toFormat
            .toString()
            .replace(/\B(?=(\d{3})+(?!\d))/g, ctx.language.thousands);
    },
    headerCallback: null,
    info: true,
    infoCallback: null,
    initComplete: null,
    language: {
        ajax: '',
        aria: {
            orderable: ': Activate to sort',
            orderableRemove: ': Activate to remove sorting',
            orderableReverse: ': Activate to invert sorting',
            paginate: {
                first: 'First',
                last: 'Last',
                next: 'Next',
                number: '',
                previous: 'Previous'
            }
        },
        decimal: '',
        emptyTable: 'No data available in table',
        entries: {
            _: 'entries',
            1: 'entry'
        },
        info: 'Showing _START_ to _END_ of _TOTAL_ _ENTRIES-TOTAL_',
        infoEmpty: 'Showing 0 to 0 of 0 _ENTRIES-TOTAL_',
        infoFiltered: '(filtered from _MAX_ total _ENTRIES-MAX_)',
        infoPostFix: '',
        lengthLabels: {
            '-1': 'All'
        },
        lengthMenu: '_MENU_ _ENTRIES_ per page',
        loadingRecords: 'Loading...',
        paginate: {
            first: '\u00AB',
            last: '\u00BB',
            next: '\u203A',
            previous: '\u2039'
        },
        processing: '',
        search: 'Search:',
        searchPlaceholder: '',
        thousands: ',',
        url: '',
        zeroRecords: 'No matching records found'
    },
    layout: {
        bottomEnd: 'paging',
        bottomStart: 'info',
        topEnd: 'search',
        topStart: 'pageLength'
    },
    lengthChange: true,
    lengthMenu: [10, 25, 50, 100],
    on: {},
    order: [[0, 'asc']],
    orderCellsTop: null,
    orderClasses: true,
    orderDescReverse: true,
    orderFixed: [],
    orderMulti: true,
    ordering: true,
    pageLength: 10,
    paging: true,
    pagingType: '',
    preDrawCallback: null,
    processing: false,
    renderer: null,
    retrieve: false,
    rowCallback: null,
    rowId: 'DT_RowId',
    scrollCollapse: false,
    scrollX: '',
    scrollY: '',
    search: defaults$3,
    searchCols: [],
    searchDelay: 0,
    searching: true,
    serverMethod: 'GET',
    serverSide: false,
    stateDuration: 7200,
    stateLoadCallback: function (settings) {
        try {
            const state = (settings.stateDuration === -1 ? sessionStorage : localStorage).getItem('DataTables_' + settings.unique + '_' + location.pathname);
            return state ? JSON.parse(state) : {};
        }
        catch (e) {
            return {};
        }
    },
    stateLoadParams: null,
    stateLoaded: null,
    stateSave: false,
    stateSaveCallback: function (settings, data) {
        try {
            (settings.stateDuration === -1
                ? sessionStorage
                : localStorage).setItem('DataTables_' + settings.unique + '_' + location.pathname, JSON.stringify(data));
        }
        catch (e) {
            // noop
        }
    },
    stateSaveParams: null,
    tabIndex: 0,
    titleRow: null,
    typeDetect: true
};

const DataTable = function (selector, options) {
    // Check if called with a window or jQuery object for DOM less applications
    // This is for backwards compatibility
    if (factory(selector, options)) {
        return DataTable;
    }
    // Allow access to the API from the core class
    this.api = () => {
        return new Api(selector);
    };
    // Backwards compatibility with this "class" being exposed as
    // `$().dataTable()`. We can't simply provide that as a wrapper, as there
    // are properties on this class which are expected to be exposed.
    if (typeof this.jquery === 'string') {
        // Typescript doesn't like the `return api` from the constructor, but is
        // it valid Javascript, and allows backwards compatibility, hence the any
        new DataTable(this.toArray(), selector); // note argument shift
        return this;
    }
    var emptyInit = options === undefined;
    let tableEls = Dom.s(selector);
    let len = tableEls.count();
    if (emptyInit) {
        options = {};
    }
    tableEls.each(tableEl => {
        // For each initialisation we want to give it a clean initialisation
        // object that can be bashed around
        var o = {};
        var init = len > 1 // optimisation for single table case
            ? util.object.assignDeepObjects(o, options, true)
            : options;
        var i = 0, iLen;
        var id = tableEl.getAttribute('id');
        var table = Dom.s(tableEl);
        // Sanity check
        if (tableEl.nodeName.toLowerCase() != 'table') {
            log(null, 0, 'Non-table node initialisation (' + tableEl.nodeName + ')', 2);
            return;
        }
        // Special case for options
        if (init.on && init.on.options) {
            listener(table, 'options', init.on.options);
        }
        table.trigger('options.dt', true, [init]);
        // Backwards compatibility parameter mapping
        compatOpts(defaults);
        compatCols(defaults$4);
        // Allow data properties on the table element to be used as
        // initialisation options
        util.object.assign(init, escapeObject(table.data()));
        compatOpts(init);
        /* Check to see if we are re-initialising a table */
        var allSettings = ext.settings;
        for (i = 0, iLen = allSettings.length; i < iLen; i++) {
            var s = allSettings[i];
            /* Base check on table node */
            if (s.table == tableEl ||
                (s.thead && s.thead.parentNode == tableEl) ||
                (s.tfoot && s.tfoot.parentNode == tableEl)) {
                var retrieve = init.retrieve || false;
                var destroy = init.destroy || false;
                if (emptyInit || retrieve) {
                    return s.instance;
                }
                else if (destroy) {
                    new Api(s).destroy();
                    break;
                }
                else {
                    log(s, 0, 'Cannot reinitialise DataTable', 3);
                    return;
                }
            }
            /* If the element we are initialising has the same ID as a table
             * which was previously initialised, but the table nodes don't match
             * (from before) then we destroy the old instance by simply deleting
             * it. This is under the assumption that the table has been
             * destroyed by other methods. Anyone using non-id selectors will
             * need to do this manually
             */
            if (s.tableId == tableEl.id) {
                allSettings.splice(i, 1);
                break;
            }
        }
        /* Ensure the table has an ID - required for accessibility */
        if (id === null || id === '') {
            id = 'DataTables_Table_' + ext._unique++;
            tableEl.id = id;
        }
        // Replacing an existing colgroup with our own. Not ideal, but a merge
        // could take a lot of code
        table.children('colgroup').remove();
        // Create the settings object for this table and set some of the default
        // parameters
        var settings = create({
            destroyWidth: table.width(),
            unique: id,
            tableId: id,
            colgroup: Dom.c('colgroup'),
            fastData: function (row, column, type) {
                return getCellData(settings, row, column, type);
            }
        });
        settings.table = tableEl;
        settings.init = init;
        allSettings.push(settings);
        // Make a single API instance available for internal handling
        settings.api = new Api(settings);
        // Need to add the instance after the instance after the settings object
        // has been added to the settings array, so we can self reference the
        // table instance if more than one
        settings.instance = Dom.s(tableEl); // any until we add the api
        settings.instance.api = () => settings.api;
        // If the length menu is given, but the init display length is not, use
        // the length menu
        if (init.lengthMenu && !init.pageLength) {
            init.pageLength =
                typeof init.lengthMenu[0] === 'number'
                    ? init.lengthMenu[0]
                    : Array.isArray(init.lengthMenu[0])
                        ? init.lengthMenu[0][0]
                        : init.lengthMenu[0].value;
        }
        // Apply the defaults and init options to make a single init object will
        // all options defined from defaults and instance options.
        let config = util.object.assignDeepObjects(util.object.assignDeep({}, defaults), init);
        // Map the initialisation options onto the context object
        map(settings.features, config, [
            'autoWidth',
            'deferRender',
            'info',
            'lengthChange',
            'orderClasses',
            'ordering',
            'orderMulti',
            'paging',
            'processing',
            'searching',
            'serverSide'
        ]);
        map(settings, config, [
            'ajax',
            'formatNumber',
            'serverMethod',
            'order',
            'orderFixed',
            'lengthMenu',
            'pagingType',
            'stateDuration',
            'orderCellsTop',
            'tabIndex',
            'dom',
            'stateLoadCallback',
            'stateSaveCallback',
            'renderer',
            'searchDelay',
            'rowId',
            'caption',
            'layout',
            'orderDescReverse',
            'orderIndicators',
            'orderHandler',
            'titleRow',
            'typeDetect',
            'pageLength',
            'searchCols'
        ]);
        map(settings.scroll, config, [
            ['scrollX', 'x'],
            ['scrollY', 'y'],
            ['scrollCollapse', 'collapse']
        ]);
        map(settings.language, config, 'infoCallback');
        // Setup global search
        settings.searches['*'] = create$2(config.search);
        /* Callback functions which are array driven */
        callbackReg(settings, 'draw', config.drawCallback);
        callbackReg(settings, 'stateSaveParams', config.stateSaveParams);
        callbackReg(settings, 'stateLoadParams', config.stateLoadParams);
        callbackReg(settings, 'stateLoaded', config.stateLoaded);
        callbackReg(settings, 'row', config.rowCallback);
        callbackReg(settings, 'rowCreated', config.createdRow);
        callbackReg(settings, 'header', config.headerCallback);
        callbackReg(settings, 'footer', config.footerCallback);
        callbackReg(settings, 'init', config.initComplete);
        callbackReg(settings, 'preDraw', config.preDrawCallback);
        settings.rowIdFn = util.get(settings.rowId);
        // Add event listeners
        if (config.on) {
            Object.keys(config.on).forEach(function (key) {
                listener(table, key, config.on[key]);
            });
        }
        // Browser support detection
        browserDetect(settings);
        var classes = settings.classes;
        util.object.assignDeep(classes, ext.classes, config.classes);
        table.classAdd(classes.table);
        if (!settings.features.paging) {
            config.displayStart = 0;
        }
        if (settings.displayStartInit === -1) {
            // Display start point, taking into account the save saving
            settings.displayStartInit = config.displayStart;
            settings.displayStart = config.displayStart; // TODO remove !
        }
        var defer = config.deferLoading;
        if (defer !== null) {
            settings.deferLoading = true;
            if (Array.isArray(defer)) {
                settings.recordsDisplay = defer[0];
                settings.recordsTotal = defer[1];
            }
            else {
                settings.recordsDisplay = defer; // TODO remove !
                settings.recordsTotal = defer;
            }
        }
        /*
         * Columns
         * See if we should load columns automatically or use defined ones
         */
        var columnsInit = [];
        var thead = table.children('thead');
        var initHeaderLayout = detectHeader(settings, thead.get(0), false);
        // If we don't have a columns array, then generate one with nulls
        if (config.columns) {
            columnsInit = config.columns;
        }
        else if (initHeaderLayout.length) {
            for (i = 0, iLen = initHeaderLayout[0].length; i < iLen; i++) {
                columnsInit.push(null);
            }
        }
        // Add the columns
        for (i = 0, iLen = columnsInit.length; i < iLen; i++) {
            addColumn(settings);
        }
        // Apply the column definitions
        applyColumnDefs(settings, config.columnDefs, columnsInit, initHeaderLayout, function (idx, def) {
            columnOptions(settings, idx, def);
        });
        /* HTML5 attribute detection - build an mData object automatically if
         * the attributes are found
         */
        var rowOne = table.children('tbody').find('tr:first-child').eq(0);
        if (rowOne.count()) {
            var a = function (cell, name) {
                return cell.getAttribute('data-' + name) !== null ? name : null;
            };
            rowOne
                .eq(0)
                .children('th, td')
                .each(function (cell, loop) {
                var col = settings.columns[loop];
                if (!col) {
                    log(settings, 0, 'Incorrect column count', 18);
                }
                if (col.data === loop) {
                    var sort = a(cell, 'sort') || a(cell, 'order');
                    var filter = a(cell, 'filter') || a(cell, 'search');
                    if (sort !== null || filter !== null) {
                        col.data = {
                            _: loop + '.display',
                            sort: sort !== null
                                ? loop + '.@data-' + sort
                                : undefined,
                            type: sort !== null
                                ? loop + '.@data-' + sort
                                : undefined,
                            filter: filter !== null
                                ? loop + '.@data-' + filter
                                : undefined
                        };
                        col._isArrayHost = true;
                        columnOptions(settings, loop);
                    }
                }
            });
        }
        // Must be done after everything which can be overridden by the state
        // saving!
        callbackReg(settings, 'draw', saveState);
        var features = settings.features;
        if (config.stateSave) {
            features.stateSave = true;
        }
        // If aaSorting is not defined, then we use the first indicator in
        // asSorting in case that has been altered, so the default sort reflects
        // that option
        if (config.order === undefined) {
            var sorting = settings.order;
            for (i = 0, iLen = sorting.length; i < iLen; i++) {
                sorting[i][1] = settings.columns[i].orderSequence[0];
            }
        }
        // Do a first pass on the sorting classes (allows any size changes to be
        // taken into account, and also will apply sorting disabled classes if
        // disabled
        sortingClasses(settings);
        callbackReg(settings, 'draw', function () {
            if (settings.wasOrdered ||
                dataSource(settings) === 'ssp' ||
                features.deferRender) {
                sortingClasses(settings);
            }
        });
        /*
         * Table HTML init Cache the header, body and footer as required,
         * creating them if needed
         */
        var caption = table.children('caption');
        if (settings.caption) {
            if (caption.count() === 0) {
                caption = Dom.c('caption').prependTo(table);
            }
            caption.html(settings.caption);
        }
        // Store the caption side, so we can remove the element from the
        // document when creating the element
        if (caption.count()) {
            caption.get(0)._captionSide = caption.css('caption-side');
            settings.captionNode = caption.get(0);
        }
        // Place the colgroup element in the correct location for the HTML
        // structure
        if (caption.count()) {
            settings.colgroup.insertAfter(caption.get(0));
        }
        else {
            settings.colgroup.prependTo(tableEl);
        }
        if (thead.count() === 0) {
            thead = Dom.c('thead').appendTo(table);
        }
        settings.thead = thead.get(0);
        var tbody = table.children('tbody');
        if (tbody.count() === 0) {
            tbody = Dom.c('tbody').insertAfter(thead.get(0));
        }
        settings.tbody = tbody.get(0);
        var tfoot = table.children('tfoot');
        if (tfoot.count() === 0) {
            // If we are a scrolling table, and no footer has been given, then
            // we need to create a tfoot element for the caption element to be
            // appended to
            tfoot = Dom.c('tfoot').appendTo(tableEl);
        }
        settings.tfoot = tfoot.get(0);
        // Copy the data index array
        settings.display = settings.displayMaster.slice();
        // Initialisation complete - table can be drawn
        settings.initialised = true;
        // Language definitions
        var language = settings.language;
        if (config.language) {
            util.object.assignDeep(language, config.language);
        }
        if (language.ajax) {
            let languageLoaded = function (json) {
                hungarianToCamel(json);
                util.object.assignDeep(language, json, settings.init.language);
                callbackFire(settings, null, 'i18n', [settings], true);
                initialise(settings);
            };
            // Get the language definitions from a remote
            if (typeof language.ajax === 'function') {
                language.ajax(settings, languageLoaded);
            }
            else {
                let ajaxBase = {
                    dataType: 'json',
                    url: '',
                    success: languageLoaded,
                    error: function () {
                        // Error occurred loading language file
                        log(settings, 0, 'i18n file loading error', 21);
                        // Continue on as best we can
                        initialise(settings);
                    }
                };
                if (typeof language.ajax === 'string') {
                    ajaxBase.url = language.ajax;
                }
                else {
                    ajaxBase = util.object.assign(ajaxBase, language.ajax);
                }
                util.ajax(ajaxBase);
            }
        }
        else {
            callbackFire(settings, null, 'i18n', [settings], true);
            initialise(settings);
        }
    });
    // This is unusual, but we want the return from the exposed `DataTable`
    // function to be an API instance, rather than the core, which is not
    // publicly exposed. This is also the reason for the `as unknown` below - TS
    // doesn't like the return with a different object.
    return this.api();
};
DataTable.type = register$1;
DataTable.types = types;
DataTable.render = helpers;
DataTable.ext = ext;
DataTable.use = util.external;
DataTable.factory = factory;
DataTable.versionCheck = util.version.check;
DataTable.version = ext.version;
DataTable.isDataTable = isDataTable;
DataTable.tables = tables;
DataTable.util = util;
DataTable.Api = Api;
DataTable.datetime = datetime;
DataTable.__browser = browser;
DataTable.Dom = Dom;
DataTable.ajax = util.ajax;
DataTable.key = key;
plus(DataTable);
/**
 * Private data store, containing all of the settings objects that are created
 * for the tables on a given page.
 */
DataTable.settings = ext.settings;
/**
 * Object models container, for the various models that DataTables has available
 * to it. These models define the objects that are used to hold the active state
 * and configuration of the table.
 */
DataTable.models = models;
DataTable.defaults = defaults;
DataTable.feature = {
    register: register$2
};
// Register the libraries
util.external(DataTable);
if (window.jQuery) {
    util.external(window.jQuery);
}


return DataTable;
}));


/*! DataTables Bootstrap 5 integration
 * © SpryMedia Ltd - datatables.net/license
 */

(function(factory){
	if (typeof define === 'function' && define.amd) {
		// AMD
		define(['datatables.net'], function (dt) {
			return factory(window, document, dt);
		});
	}
	else if (typeof exports === 'object') {
		// CommonJS
		var cjsRequires = function (root) {
			if (! root.DataTable) {
				require('datatables.net')(root);
			}
		};

		if (typeof window === 'undefined') {
			module.exports = function (root) {
				if (! root) {
					// CommonJS environments without a window global must pass a
					// root. This will give an error otherwise
					root = window;
				}

				cjsRequires(root);
				return factory(root, root.document, root.DataTable);
			};
		}
		else {
			cjsRequires(window);
			module.exports = factory(window, window.document, window.DataTable);
		}
	}
	else {
		// Browser
		factory(window, document, window.DataTable);
	}
}(function(window, document, DataTable) {
'use strict';


/* Set the defaults for DataTables initialisation */
DataTable.util.object.assignDeep(DataTable.defaults, {
    renderer: 'bootstrap'
});
/* Default class modification */
DataTable.util.object.assignDeep(DataTable.ext.classes, {
    container: 'dt-container dt-bootstrap5',
    search: {
        input: 'form-control form-control-sm'
    },
    length: {
        select: 'form-select form-select-sm'
    },
    processing: {
        container: 'dt-processing card'
    },
    layout: {
        row: 'row mt-2 justify-content-between',
        cell: 'd-md-flex justify-content-between align-items-center',
        tableCell: 'col-12',
        start: 'dt-layout-start col-md-auto me-auto',
        end: 'dt-layout-end col-md-auto ms-auto',
        full: 'dt-layout-full col-md'
    }
});
/* Bootstrap paging button renderer */
DataTable.ext.renderer.pagingButton.bootstrap = function (settings, buttonType, content, active, disabled) {
    var btnClasses = ['dt-paging-button', 'page-item'];
    if (active) {
        btnClasses.push('active');
    }
    if (disabled) {
        btnClasses.push('disabled');
    }
    var li = DataTable.Dom.c('li').classAdd(btnClasses.join(' '));
    var a = DataTable.Dom
        .c('button')
        .classAdd('page-link')
        .attr('role', 'link')
        .attr('type', 'button')
        .html(content)
        .appendTo(li);
    return {
        display: li.get(0),
        clicker: a.get(0)
    };
};
DataTable.ext.renderer.pagingContainer.bootstrap = function (settings, buttonEls) {
    return DataTable.Dom
        .c('ul')
        .classAdd('pagination')
        .append(buttonEls)
        .get(0);
};


return DataTable;
}));


