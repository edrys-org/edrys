// deno-fmt-ignore-file
// deno-lint-ignore-file
// This code was bundled using `deno bundle` and it's not recommended to edit it manually

function deferred() {
    let methods;
    let state = "pending";
    const promise = new Promise((resolve, reject)=>{
        methods = {
            async resolve (value) {
                await value;
                state = "fulfilled";
                resolve(value);
            },
            reject (reason) {
                state = "rejected";
                reject(reason);
            }
        };
    });
    Object.defineProperty(promise, "state", {
        get: ()=>state
    });
    return Object.assign(promise, methods);
}
class BytesList {
    #len = 0;
    #chunks = [];
    constructor(){}
    size() {
        return this.#len;
    }
    add(value, start = 0, end = value.byteLength) {
        if (value.byteLength === 0 || end - start === 0) {
            return;
        }
        checkRange(start, end, value.byteLength);
        this.#chunks.push({
            value,
            end,
            start,
            offset: this.#len
        });
        this.#len += end - start;
    }
    shift(n) {
        if (n === 0) {
            return;
        }
        if (this.#len <= n) {
            this.#chunks = [];
            this.#len = 0;
            return;
        }
        const idx = this.getChunkIndex(n);
        this.#chunks.splice(0, idx);
        const [chunk] = this.#chunks;
        if (chunk) {
            const diff = n - chunk.offset;
            chunk.start += diff;
        }
        let offset = 0;
        for (const chunk of this.#chunks){
            chunk.offset = offset;
            offset += chunk.end - chunk.start;
        }
        this.#len = offset;
    }
    getChunkIndex(pos) {
        let max = this.#chunks.length;
        let min = 0;
        while(true){
            const i = min + Math.floor((max - min) / 2);
            if (i < 0 || this.#chunks.length <= i) {
                return -1;
            }
            const { offset , start , end  } = this.#chunks[i];
            const len = end - start;
            if (offset <= pos && pos < offset + len) {
                return i;
            } else if (offset + len <= pos) {
                min = i + 1;
            } else {
                max = i - 1;
            }
        }
    }
    get(i) {
        if (i < 0 || this.#len <= i) {
            throw new Error("out of range");
        }
        const idx = this.getChunkIndex(i);
        const { value , offset , start  } = this.#chunks[idx];
        return value[start + i - offset];
    }
    *iterator(start = 0) {
        const startIdx = this.getChunkIndex(start);
        if (startIdx < 0) return;
        const first = this.#chunks[startIdx];
        let firstOffset = start - first.offset;
        for(let i = startIdx; i < this.#chunks.length; i++){
            const chunk = this.#chunks[i];
            for(let j = chunk.start + firstOffset; j < chunk.end; j++){
                yield chunk.value[j];
            }
            firstOffset = 0;
        }
    }
    slice(start, end = this.#len) {
        if (end === start) {
            return new Uint8Array();
        }
        checkRange(start, end, this.#len);
        const result = new Uint8Array(end - start);
        const startIdx = this.getChunkIndex(start);
        const endIdx = this.getChunkIndex(end - 1);
        let written = 0;
        for(let i = startIdx; i < endIdx; i++){
            const chunk = this.#chunks[i];
            const len = chunk.end - chunk.start;
            result.set(chunk.value.subarray(chunk.start, chunk.end), written);
            written += len;
        }
        const last = this.#chunks[endIdx];
        const rest = end - start - written;
        result.set(last.value.subarray(last.start, last.start + rest), written);
        return result;
    }
    concat() {
        const result = new Uint8Array(this.#len);
        let sum = 0;
        for (const { value , start , end  } of this.#chunks){
            result.set(value.subarray(start, end), sum);
            sum += end - start;
        }
        return result;
    }
}
function checkRange(start, end, len) {
    if (start < 0 || len < start || end < 0 || len < end || end < start) {
        throw new Error("invalid range");
    }
}
function concat(...buf) {
    let length = 0;
    for (const b of buf){
        length += b.length;
    }
    const output = new Uint8Array(length);
    let index = 0;
    for (const b of buf){
        output.set(b, index);
        index += b.length;
    }
    return output;
}
function copy(src, dst, off = 0) {
    off = Math.max(0, Math.min(off, dst.byteLength));
    const dstBytesAvailable = dst.byteLength - off;
    if (src.byteLength > dstBytesAvailable) {
        src = src.subarray(0, dstBytesAvailable);
    }
    dst.set(src, off);
    return src.byteLength;
}
function equalsNaive(a, b) {
    for(let i = 0; i < b.length; i++){
        if (a[i] !== b[i]) return false;
    }
    return true;
}
function equals32Bit(a, b) {
    const len = a.length;
    const compressable = Math.floor(len / 4);
    const compressedA = new Uint32Array(a.buffer, 0, compressable);
    const compressedB = new Uint32Array(b.buffer, 0, compressable);
    for(let i = compressable * 4; i < len; i++){
        if (a[i] !== b[i]) return false;
    }
    for(let i = 0; i < compressedA.length; i++){
        if (compressedA[i] !== compressedB[i]) return false;
    }
    return true;
}
function equals(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    return a.length < 1000 ? equalsNaive(a, b) : equals32Bit(a, b);
}
class DenoStdInternalError extends Error {
    constructor(message){
        super(message);
        this.name = "DenoStdInternalError";
    }
}
function assert(expr, msg = "") {
    if (!expr) {
        throw new DenoStdInternalError(msg);
    }
}
function timingSafeEqual(a, b) {
    if (a.byteLength !== b.byteLength) {
        return false;
    }
    if (!(a instanceof DataView)) {
        a = ArrayBuffer.isView(a) ? new DataView(a.buffer, a.byteOffset, a.byteLength) : new DataView(a);
    }
    if (!(b instanceof DataView)) {
        b = ArrayBuffer.isView(b) ? new DataView(b.buffer, b.byteOffset, b.byteLength) : new DataView(b);
    }
    assert(a instanceof DataView);
    assert(b instanceof DataView);
    const length = a.byteLength;
    let out = 0;
    let i = -1;
    while(++i < length){
        out |= a.getUint8(i) ^ b.getUint8(i);
    }
    return out === 0;
}
const base64abc = [
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "+",
    "/"
];
function encode(data) {
    const uint8 = typeof data === "string" ? new TextEncoder().encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
    let result = "", i;
    const l = uint8.length;
    for(i = 2; i < l; i += 3){
        result += base64abc[uint8[i - 2] >> 2];
        result += base64abc[(uint8[i - 2] & 0x03) << 4 | uint8[i - 1] >> 4];
        result += base64abc[(uint8[i - 1] & 0x0f) << 2 | uint8[i] >> 6];
        result += base64abc[uint8[i] & 0x3f];
    }
    if (i === l + 1) {
        result += base64abc[uint8[i - 2] >> 2];
        result += base64abc[(uint8[i - 2] & 0x03) << 4];
        result += "==";
    }
    if (i === l) {
        result += base64abc[uint8[i - 2] >> 2];
        result += base64abc[(uint8[i - 2] & 0x03) << 4 | uint8[i - 1] >> 4];
        result += base64abc[(uint8[i - 1] & 0x0f) << 2];
        result += "=";
    }
    return result;
}
function decode(b64) {
    const binString = atob(b64);
    const size = binString.length;
    const bytes = new Uint8Array(size);
    for(let i = 0; i < size; i++){
        bytes[i] = binString.charCodeAt(i);
    }
    return bytes;
}
const mod = {
    encode: encode,
    decode: decode
};
function convertBase64ToBase64url(b64) {
    return b64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function encode1(data) {
    return convertBase64ToBase64url(encode(data));
}
const encoder = new TextEncoder();
function importKey(key) {
    if (typeof key === "string") {
        key = encoder.encode(key);
    } else if (Array.isArray(key)) {
        key = new Uint8Array(key);
    }
    return crypto.subtle.importKey("raw", key, {
        name: "HMAC",
        hash: {
            name: "SHA-256"
        }
    }, true, [
        "sign",
        "verify"
    ]);
}
function sign(data, key) {
    if (typeof data === "string") {
        data = encoder.encode(data);
    } else if (Array.isArray(data)) {
        data = Uint8Array.from(data);
    }
    return crypto.subtle.sign("HMAC", key, data);
}
async function compare(a, b) {
    const key = new Uint8Array(32);
    globalThis.crypto.getRandomValues(key);
    const cryptoKey = await importKey(key);
    const ah = await sign(a, cryptoKey);
    const bh = await sign(b, cryptoKey);
    return timingSafeEqual(ah, bh);
}
class KeyStack {
    #cryptoKeys = new Map();
    #keys;
    async #toCryptoKey(key) {
        if (!this.#cryptoKeys.has(key)) {
            this.#cryptoKeys.set(key, await importKey(key));
        }
        return this.#cryptoKeys.get(key);
    }
    get length() {
        return this.#keys.length;
    }
    constructor(keys){
        const values = Array.isArray(keys) ? keys : [
            ...keys
        ];
        if (!values.length) {
            throw new TypeError("keys must contain at least one value");
        }
        this.#keys = values;
    }
    async sign(data) {
        const key = await this.#toCryptoKey(this.#keys[0]);
        return encode1(await sign(data, key));
    }
    async verify(data, digest) {
        return await this.indexOf(data, digest) > -1;
    }
    async indexOf(data, digest) {
        for(let i = 0; i < this.#keys.length; i++){
            const cryptoKey = await this.#toCryptoKey(this.#keys[i]);
            if (await compare(digest, encode1(await sign(data, cryptoKey)))) {
                return i;
            }
        }
        return -1;
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { length  } = this;
        return `${this.constructor.name} ${inspect({
            length
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        const { length  } = this;
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            length
        }, newOptions)}`;
    }
}
const FIELD_CONTENT_REGEXP = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;
const KEY_REGEXP = /(?:^|;) *([^=]*)=[^;]*/g;
const SAME_SITE_REGEXP = /^(?:lax|none|strict)$/i;
const matchCache = {};
function getPattern(name) {
    if (name in matchCache) {
        return matchCache[name];
    }
    return matchCache[name] = new RegExp(`(?:^|;) *${name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&")}=([^;]*)`);
}
function pushCookie(values, cookie) {
    if (cookie.overwrite) {
        for(let i = values.length - 1; i >= 0; i--){
            if (values[i].indexOf(`${cookie.name}=`) === 0) {
                values.splice(i, 1);
            }
        }
    }
    values.push(cookie.toHeaderValue());
}
function validateCookieProperty(key, value) {
    if (value && !FIELD_CONTENT_REGEXP.test(value)) {
        throw new TypeError(`The "${key}" of the cookie (${value}) is invalid.`);
    }
}
class Cookie {
    domain;
    expires;
    httpOnly = true;
    maxAge;
    name;
    overwrite = false;
    path = "/";
    sameSite = false;
    secure = false;
    signed;
    value;
    constructor(name, value, attributes){
        validateCookieProperty("name", name);
        this.name = name;
        validateCookieProperty("value", value);
        this.value = value ?? "";
        Object.assign(this, attributes);
        if (!this.value) {
            this.expires = new Date(0);
            this.maxAge = undefined;
        }
        validateCookieProperty("path", this.path);
        validateCookieProperty("domain", this.domain);
        if (this.sameSite && typeof this.sameSite === "string" && !SAME_SITE_REGEXP.test(this.sameSite)) {
            throw new TypeError(`The "sameSite" of the cookie ("${this.sameSite}") is invalid.`);
        }
    }
    toHeaderValue() {
        let value = this.toString();
        if (this.maxAge) {
            this.expires = new Date(Date.now() + this.maxAge * 1000);
        }
        if (this.path) {
            value += `; path=${this.path}`;
        }
        if (this.expires) {
            value += `; expires=${this.expires.toUTCString()}`;
        }
        if (this.domain) {
            value += `; domain=${this.domain}`;
        }
        if (this.sameSite) {
            value += `; samesite=${this.sameSite === true ? "strict" : this.sameSite.toLowerCase()}`;
        }
        if (this.secure) {
            value += "; secure";
        }
        if (this.httpOnly) {
            value += "; httponly";
        }
        return value;
    }
    toString() {
        return `${this.name}=${this.value}`;
    }
}
const cookieMapHeadersInitSymbol = Symbol.for("Deno.std.cookieMap.headersInit");
const keys = Symbol("#keys");
const requestHeaders = Symbol("#requestHeaders");
const responseHeaders = Symbol("#responseHeaders");
const isSecure = Symbol("#secure");
const requestKeys = Symbol("#requestKeys");
class CookieMapBase {
    [keys];
    [requestHeaders];
    [responseHeaders];
    [isSecure];
    [requestKeys]() {
        if (this[keys]) {
            return this[keys];
        }
        const result = this[keys] = [];
        const header = this[requestHeaders].get("cookie");
        if (!header) {
            return result;
        }
        let matches;
        while(matches = KEY_REGEXP.exec(header)){
            const [, key] = matches;
            result.push(key);
        }
        return result;
    }
    constructor(request, options){
        this[requestHeaders] = "headers" in request ? request.headers : request;
        const { secure =false , response =new Headers()  } = options;
        this[responseHeaders] = "headers" in response ? response.headers : response;
        this[isSecure] = secure;
    }
    [cookieMapHeadersInitSymbol]() {
        const init = [];
        for (const [key, value] of this[responseHeaders]){
            if (key === "set-cookie") {
                init.push([
                    key,
                    value
                ]);
            }
        }
        return init;
    }
    [Symbol.for("Deno.customInspect")]() {
        return `${this.constructor.name} []`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        return `${options.stylize(this.constructor.name, "special")} ${inspect([], newOptions)}`;
    }
}
class CookieMap extends CookieMapBase {
    get size() {
        return [
            ...this
        ].length;
    }
    constructor(request, options = {}){
        super(request, options);
    }
    clear(options = {}) {
        for (const key of this.keys()){
            this.set(key, null, options);
        }
    }
    delete(key, options = {}) {
        this.set(key, null, options);
        return true;
    }
    get(key) {
        const headerValue = this[requestHeaders].get("cookie");
        if (!headerValue) {
            return undefined;
        }
        const match = headerValue.match(getPattern(key));
        if (!match) {
            return undefined;
        }
        const [, value] = match;
        return value;
    }
    has(key) {
        const headerValue = this[requestHeaders].get("cookie");
        if (!headerValue) {
            return false;
        }
        return getPattern(key).test(headerValue);
    }
    set(key, value, options = {}) {
        const resHeaders = this[responseHeaders];
        const values = [];
        for (const [key, value] of resHeaders){
            if (key === "set-cookie") {
                values.push(value);
            }
        }
        const secure = this[isSecure];
        if (!secure && options.secure && !options.ignoreInsecure) {
            throw new TypeError("Cannot send secure cookie over unencrypted connection.");
        }
        const cookie = new Cookie(key, value, options);
        cookie.secure = options.secure ?? secure;
        pushCookie(values, cookie);
        resHeaders.delete("set-cookie");
        for (const value of values){
            resHeaders.append("set-cookie", value);
        }
        return this;
    }
    entries() {
        return this[Symbol.iterator]();
    }
    *keys() {
        for (const [key] of this){
            yield key;
        }
    }
    *values() {
        for (const [, value] of this){
            yield value;
        }
    }
    *[Symbol.iterator]() {
        const keys = this[requestKeys]();
        for (const key of keys){
            const value = this.get(key);
            if (value) {
                yield [
                    key,
                    value
                ];
            }
        }
    }
}
class SecureCookieMap extends CookieMapBase {
    #keyRing;
    get size() {
        return (async ()=>{
            let size = 0;
            for await (const _ of this){
                size++;
            }
            return size;
        })();
    }
    constructor(request, options = {}){
        super(request, options);
        const { keys  } = options;
        this.#keyRing = keys;
    }
    async clear(options) {
        for await (const key of this.keys()){
            await this.set(key, null, options);
        }
    }
    async delete(key, options = {}) {
        await this.set(key, null, options);
        return true;
    }
    async get(key, options = {}) {
        const signed = options.signed ?? !!this.#keyRing;
        const nameSig = `${key}.sig`;
        const header = this[requestHeaders].get("cookie");
        if (!header) {
            return;
        }
        const match = header.match(getPattern(key));
        if (!match) {
            return;
        }
        const [, value] = match;
        if (!signed) {
            return value;
        }
        const digest = await this.get(nameSig, {
            signed: false
        });
        if (!digest) {
            return;
        }
        const data = `${key}=${value}`;
        if (!this.#keyRing) {
            throw new TypeError("key ring required for signed cookies");
        }
        const index = await this.#keyRing.indexOf(data, digest);
        if (index < 0) {
            await this.delete(nameSig, {
                path: "/",
                signed: false
            });
        } else {
            if (index) {
                await this.set(nameSig, await this.#keyRing.sign(data), {
                    signed: false
                });
            }
            return value;
        }
    }
    async has(key, options = {}) {
        const signed = options.signed ?? !!this.#keyRing;
        const nameSig = `${key}.sig`;
        const header = this[requestHeaders].get("cookie");
        if (!header) {
            return false;
        }
        const match = header.match(getPattern(key));
        if (!match) {
            return false;
        }
        if (!signed) {
            return true;
        }
        const digest = await this.get(nameSig, {
            signed: false
        });
        if (!digest) {
            return false;
        }
        const [, value] = match;
        const data = `${key}=${value}`;
        if (!this.#keyRing) {
            throw new TypeError("key ring required for signed cookies");
        }
        const index = await this.#keyRing.indexOf(data, digest);
        if (index < 0) {
            await this.delete(nameSig, {
                path: "/",
                signed: false
            });
            return false;
        } else {
            if (index) {
                await this.set(nameSig, await this.#keyRing.sign(data), {
                    signed: false
                });
            }
            return true;
        }
    }
    async set(key, value, options = {}) {
        const resHeaders = this[responseHeaders];
        const headers = [];
        for (const [key, value] of resHeaders.entries()){
            if (key === "set-cookie") {
                headers.push(value);
            }
        }
        const secure = this[isSecure];
        const signed = options.signed ?? !!this.#keyRing;
        if (!secure && options.secure && !options.ignoreInsecure) {
            throw new TypeError("Cannot send secure cookie over unencrypted connection.");
        }
        const cookie = new Cookie(key, value, options);
        cookie.secure = options.secure ?? secure;
        pushCookie(headers, cookie);
        if (signed) {
            if (!this.#keyRing) {
                throw new TypeError("keys required for signed cookies.");
            }
            cookie.value = await this.#keyRing.sign(cookie.toString());
            cookie.name += ".sig";
            pushCookie(headers, cookie);
        }
        resHeaders.delete("set-cookie");
        for (const header of headers){
            resHeaders.append("set-cookie", header);
        }
        return this;
    }
    entries() {
        return this[Symbol.asyncIterator]();
    }
    async *keys() {
        for await (const [key] of this){
            yield key;
        }
    }
    async *values() {
        for await (const [, value] of this){
            yield value;
        }
    }
    async *[Symbol.asyncIterator]() {
        const keys = this[requestKeys]();
        for (const key of keys){
            const value = await this.get(key);
            if (value) {
                yield [
                    key,
                    value
                ];
            }
        }
    }
}
var Status;
(function(Status) {
    Status[Status["Continue"] = 100] = "Continue";
    Status[Status["SwitchingProtocols"] = 101] = "SwitchingProtocols";
    Status[Status["Processing"] = 102] = "Processing";
    Status[Status["EarlyHints"] = 103] = "EarlyHints";
    Status[Status["OK"] = 200] = "OK";
    Status[Status["Created"] = 201] = "Created";
    Status[Status["Accepted"] = 202] = "Accepted";
    Status[Status["NonAuthoritativeInfo"] = 203] = "NonAuthoritativeInfo";
    Status[Status["NoContent"] = 204] = "NoContent";
    Status[Status["ResetContent"] = 205] = "ResetContent";
    Status[Status["PartialContent"] = 206] = "PartialContent";
    Status[Status["MultiStatus"] = 207] = "MultiStatus";
    Status[Status["AlreadyReported"] = 208] = "AlreadyReported";
    Status[Status["IMUsed"] = 226] = "IMUsed";
    Status[Status["MultipleChoices"] = 300] = "MultipleChoices";
    Status[Status["MovedPermanently"] = 301] = "MovedPermanently";
    Status[Status["Found"] = 302] = "Found";
    Status[Status["SeeOther"] = 303] = "SeeOther";
    Status[Status["NotModified"] = 304] = "NotModified";
    Status[Status["UseProxy"] = 305] = "UseProxy";
    Status[Status["TemporaryRedirect"] = 307] = "TemporaryRedirect";
    Status[Status["PermanentRedirect"] = 308] = "PermanentRedirect";
    Status[Status["BadRequest"] = 400] = "BadRequest";
    Status[Status["Unauthorized"] = 401] = "Unauthorized";
    Status[Status["PaymentRequired"] = 402] = "PaymentRequired";
    Status[Status["Forbidden"] = 403] = "Forbidden";
    Status[Status["NotFound"] = 404] = "NotFound";
    Status[Status["MethodNotAllowed"] = 405] = "MethodNotAllowed";
    Status[Status["NotAcceptable"] = 406] = "NotAcceptable";
    Status[Status["ProxyAuthRequired"] = 407] = "ProxyAuthRequired";
    Status[Status["RequestTimeout"] = 408] = "RequestTimeout";
    Status[Status["Conflict"] = 409] = "Conflict";
    Status[Status["Gone"] = 410] = "Gone";
    Status[Status["LengthRequired"] = 411] = "LengthRequired";
    Status[Status["PreconditionFailed"] = 412] = "PreconditionFailed";
    Status[Status["RequestEntityTooLarge"] = 413] = "RequestEntityTooLarge";
    Status[Status["RequestURITooLong"] = 414] = "RequestURITooLong";
    Status[Status["UnsupportedMediaType"] = 415] = "UnsupportedMediaType";
    Status[Status["RequestedRangeNotSatisfiable"] = 416] = "RequestedRangeNotSatisfiable";
    Status[Status["ExpectationFailed"] = 417] = "ExpectationFailed";
    Status[Status["Teapot"] = 418] = "Teapot";
    Status[Status["MisdirectedRequest"] = 421] = "MisdirectedRequest";
    Status[Status["UnprocessableEntity"] = 422] = "UnprocessableEntity";
    Status[Status["Locked"] = 423] = "Locked";
    Status[Status["FailedDependency"] = 424] = "FailedDependency";
    Status[Status["TooEarly"] = 425] = "TooEarly";
    Status[Status["UpgradeRequired"] = 426] = "UpgradeRequired";
    Status[Status["PreconditionRequired"] = 428] = "PreconditionRequired";
    Status[Status["TooManyRequests"] = 429] = "TooManyRequests";
    Status[Status["RequestHeaderFieldsTooLarge"] = 431] = "RequestHeaderFieldsTooLarge";
    Status[Status["UnavailableForLegalReasons"] = 451] = "UnavailableForLegalReasons";
    Status[Status["InternalServerError"] = 500] = "InternalServerError";
    Status[Status["NotImplemented"] = 501] = "NotImplemented";
    Status[Status["BadGateway"] = 502] = "BadGateway";
    Status[Status["ServiceUnavailable"] = 503] = "ServiceUnavailable";
    Status[Status["GatewayTimeout"] = 504] = "GatewayTimeout";
    Status[Status["HTTPVersionNotSupported"] = 505] = "HTTPVersionNotSupported";
    Status[Status["VariantAlsoNegotiates"] = 506] = "VariantAlsoNegotiates";
    Status[Status["InsufficientStorage"] = 507] = "InsufficientStorage";
    Status[Status["LoopDetected"] = 508] = "LoopDetected";
    Status[Status["NotExtended"] = 510] = "NotExtended";
    Status[Status["NetworkAuthenticationRequired"] = 511] = "NetworkAuthenticationRequired";
})(Status || (Status = {}));
const STATUS_TEXT = {
    [Status.Accepted]: "Accepted",
    [Status.AlreadyReported]: "Already Reported",
    [Status.BadGateway]: "Bad Gateway",
    [Status.BadRequest]: "Bad Request",
    [Status.Conflict]: "Conflict",
    [Status.Continue]: "Continue",
    [Status.Created]: "Created",
    [Status.EarlyHints]: "Early Hints",
    [Status.ExpectationFailed]: "Expectation Failed",
    [Status.FailedDependency]: "Failed Dependency",
    [Status.Forbidden]: "Forbidden",
    [Status.Found]: "Found",
    [Status.GatewayTimeout]: "Gateway Timeout",
    [Status.Gone]: "Gone",
    [Status.HTTPVersionNotSupported]: "HTTP Version Not Supported",
    [Status.IMUsed]: "IM Used",
    [Status.InsufficientStorage]: "Insufficient Storage",
    [Status.InternalServerError]: "Internal Server Error",
    [Status.LengthRequired]: "Length Required",
    [Status.Locked]: "Locked",
    [Status.LoopDetected]: "Loop Detected",
    [Status.MethodNotAllowed]: "Method Not Allowed",
    [Status.MisdirectedRequest]: "Misdirected Request",
    [Status.MovedPermanently]: "Moved Permanently",
    [Status.MultiStatus]: "Multi Status",
    [Status.MultipleChoices]: "Multiple Choices",
    [Status.NetworkAuthenticationRequired]: "Network Authentication Required",
    [Status.NoContent]: "No Content",
    [Status.NonAuthoritativeInfo]: "Non Authoritative Info",
    [Status.NotAcceptable]: "Not Acceptable",
    [Status.NotExtended]: "Not Extended",
    [Status.NotFound]: "Not Found",
    [Status.NotImplemented]: "Not Implemented",
    [Status.NotModified]: "Not Modified",
    [Status.OK]: "OK",
    [Status.PartialContent]: "Partial Content",
    [Status.PaymentRequired]: "Payment Required",
    [Status.PermanentRedirect]: "Permanent Redirect",
    [Status.PreconditionFailed]: "Precondition Failed",
    [Status.PreconditionRequired]: "Precondition Required",
    [Status.Processing]: "Processing",
    [Status.ProxyAuthRequired]: "Proxy Auth Required",
    [Status.RequestEntityTooLarge]: "Request Entity Too Large",
    [Status.RequestHeaderFieldsTooLarge]: "Request Header Fields Too Large",
    [Status.RequestTimeout]: "Request Timeout",
    [Status.RequestURITooLong]: "Request URI Too Long",
    [Status.RequestedRangeNotSatisfiable]: "Requested Range Not Satisfiable",
    [Status.ResetContent]: "Reset Content",
    [Status.SeeOther]: "See Other",
    [Status.ServiceUnavailable]: "Service Unavailable",
    [Status.SwitchingProtocols]: "Switching Protocols",
    [Status.Teapot]: "I'm a teapot",
    [Status.TemporaryRedirect]: "Temporary Redirect",
    [Status.TooEarly]: "Too Early",
    [Status.TooManyRequests]: "Too Many Requests",
    [Status.Unauthorized]: "Unauthorized",
    [Status.UnavailableForLegalReasons]: "Unavailable For Legal Reasons",
    [Status.UnprocessableEntity]: "Unprocessable Entity",
    [Status.UnsupportedMediaType]: "Unsupported Media Type",
    [Status.UpgradeRequired]: "Upgrade Required",
    [Status.UseProxy]: "Use Proxy",
    [Status.VariantAlsoNegotiates]: "Variant Also Negotiates"
};
function isClientErrorStatus(status) {
    return status >= 400 && status < 500;
}
const ERROR_STATUS_MAP = {
    "BadRequest": 400,
    "Unauthorized": 401,
    "PaymentRequired": 402,
    "Forbidden": 403,
    "NotFound": 404,
    "MethodNotAllowed": 405,
    "NotAcceptable": 406,
    "ProxyAuthRequired": 407,
    "RequestTimeout": 408,
    "Conflict": 409,
    "Gone": 410,
    "LengthRequired": 411,
    "PreconditionFailed": 412,
    "RequestEntityTooLarge": 413,
    "RequestURITooLong": 414,
    "UnsupportedMediaType": 415,
    "RequestedRangeNotSatisfiable": 416,
    "ExpectationFailed": 417,
    "Teapot": 418,
    "MisdirectedRequest": 421,
    "UnprocessableEntity": 422,
    "Locked": 423,
    "FailedDependency": 424,
    "UpgradeRequired": 426,
    "PreconditionRequired": 428,
    "TooManyRequests": 429,
    "RequestHeaderFieldsTooLarge": 431,
    "UnavailableForLegalReasons": 451,
    "InternalServerError": 500,
    "NotImplemented": 501,
    "BadGateway": 502,
    "ServiceUnavailable": 503,
    "GatewayTimeout": 504,
    "HTTPVersionNotSupported": 505,
    "VariantAlsoNegotiates": 506,
    "InsufficientStorage": 507,
    "LoopDetected": 508,
    "NotExtended": 510,
    "NetworkAuthenticationRequired": 511
};
class HttpError extends Error {
    #status = Status.InternalServerError;
    #expose;
    #headers;
    constructor(message = "Http Error", options){
        super(message, options);
        this.#expose = options?.expose === undefined ? isClientErrorStatus(this.status) : options.expose;
        if (options?.headers) {
            this.#headers = new Headers(options.headers);
        }
    }
    get expose() {
        return this.#expose;
    }
    get headers() {
        return this.#headers;
    }
    get status() {
        return this.#status;
    }
}
function createHttpErrorConstructor(status) {
    const name = `${Status[status]}Error`;
    const ErrorCtor = class extends HttpError {
        constructor(message = STATUS_TEXT[status], options){
            super(message, options);
            Object.defineProperty(this, "name", {
                configurable: true,
                enumerable: false,
                value: name,
                writable: true
            });
        }
        get status() {
            return status;
        }
    };
    return ErrorCtor;
}
const errors = {};
for (const [key, value] of Object.entries(ERROR_STATUS_MAP)){
    errors[key] = createHttpErrorConstructor(value);
}
function createHttpError(status = Status.InternalServerError, message, options) {
    return new errors[Status[status]](message, options);
}
function isHttpError(value) {
    return value instanceof HttpError;
}
function compareSpecs(a, b) {
    return b.q - a.q || (b.s ?? 0) - (a.s ?? 0) || (a.o ?? 0) - (b.o ?? 0) || a.i - b.i || 0;
}
function isQuality(spec) {
    return spec.q > 0;
}
const simpleEncodingRegExp = /^\s*([^\s;]+)\s*(?:;(.*))?$/;
function parseEncoding(str, i) {
    const match = simpleEncodingRegExp.exec(str);
    if (!match) {
        return undefined;
    }
    const encoding = match[1];
    let q = 1;
    if (match[2]) {
        const params = match[2].split(";");
        for (const param of params){
            const p = param.trim().split("=");
            if (p[0] === "q") {
                q = parseFloat(p[1]);
                break;
            }
        }
    }
    return {
        encoding,
        q,
        i
    };
}
function specify(encoding, spec, i = -1) {
    if (!spec.encoding) {
        return;
    }
    let s = 0;
    if (spec.encoding.toLocaleLowerCase() === encoding.toLocaleLowerCase()) {
        s = 1;
    } else if (spec.encoding !== "*") {
        return;
    }
    return {
        i,
        o: spec.i,
        q: spec.q,
        s
    };
}
function parseAcceptEncoding(accept) {
    const accepts = accept.split(",");
    const parsedAccepts = [];
    let hasIdentity = false;
    let minQuality = 1;
    for(let i = 0; i < accepts.length; i++){
        const encoding = parseEncoding(accepts[i].trim(), i);
        if (encoding) {
            parsedAccepts.push(encoding);
            hasIdentity = hasIdentity || !!specify("identity", encoding);
            minQuality = Math.min(minQuality, encoding.q || 1);
        }
    }
    if (!hasIdentity) {
        parsedAccepts.push({
            encoding: "identity",
            q: minQuality,
            i: accepts.length - 1
        });
    }
    return parsedAccepts;
}
function getEncodingPriority(encoding, accepted, index) {
    let priority = {
        o: -1,
        q: 0,
        s: 0,
        i: 0
    };
    for (const s of accepted){
        const spec = specify(encoding, s, index);
        if (spec && (priority.s - spec.s || priority.q - spec.q || priority.o - spec.o) < 0) {
            priority = spec;
        }
    }
    return priority;
}
function preferredEncodings(accept, provided) {
    const accepts = parseAcceptEncoding(accept);
    if (!provided) {
        return accepts.filter(isQuality).sort(compareSpecs).map((spec)=>spec.encoding);
    }
    const priorities = provided.map((type, index)=>getEncodingPriority(type, accepts, index));
    return priorities.filter(isQuality).sort(compareSpecs).map((priority)=>provided[priorities.indexOf(priority)]);
}
const SIMPLE_LANGUAGE_REGEXP = /^\s*([^\s\-;]+)(?:-([^\s;]+))?\s*(?:;(.*))?$/;
function parseLanguage(str, i) {
    const match = SIMPLE_LANGUAGE_REGEXP.exec(str);
    if (!match) {
        return undefined;
    }
    const [, prefix, suffix] = match;
    const full = suffix ? `${prefix}-${suffix}` : prefix;
    let q = 1;
    if (match[3]) {
        const params = match[3].split(";");
        for (const param of params){
            const [key, value] = param.trim().split("=");
            if (key === "q") {
                q = parseFloat(value);
                break;
            }
        }
    }
    return {
        prefix,
        suffix,
        full,
        q,
        i
    };
}
function parseAcceptLanguage(accept) {
    const accepts = accept.split(",");
    const result = [];
    for(let i = 0; i < accepts.length; i++){
        const language = parseLanguage(accepts[i].trim(), i);
        if (language) {
            result.push(language);
        }
    }
    return result;
}
function specify1(language, spec, i) {
    const p = parseLanguage(language, i);
    if (!p) {
        return undefined;
    }
    let s = 0;
    if (spec.full.toLowerCase() === p.full.toLowerCase()) {
        s |= 4;
    } else if (spec.prefix.toLowerCase() === p.prefix.toLowerCase()) {
        s |= 2;
    } else if (spec.full.toLowerCase() === p.prefix.toLowerCase()) {
        s |= 1;
    } else if (spec.full !== "*") {
        return;
    }
    return {
        i,
        o: spec.i,
        q: spec.q,
        s
    };
}
function getLanguagePriority(language, accepted, index) {
    let priority = {
        i: -1,
        o: -1,
        q: 0,
        s: 0
    };
    for (const accepts of accepted){
        const spec = specify1(language, accepts, index);
        if (spec && ((priority.s ?? 0) - (spec.s ?? 0) || priority.q - spec.q || (priority.o ?? 0) - (spec.o ?? 0)) < 0) {
            priority = spec;
        }
    }
    return priority;
}
function preferredLanguages(accept = "*", provided) {
    const accepts = parseAcceptLanguage(accept);
    if (!provided) {
        return accepts.filter(isQuality).sort(compareSpecs).map((spec)=>spec.full);
    }
    const priorities = provided.map((type, index)=>getLanguagePriority(type, accepts, index));
    return priorities.filter(isQuality).sort(compareSpecs).map((priority)=>provided[priorities.indexOf(priority)]);
}
const simpleMediaTypeRegExp = /^\s*([^\s\/;]+)\/([^;\s]+)\s*(?:;(.*))?$/;
function quoteCount(str) {
    let count = 0;
    let index = 0;
    while((index = str.indexOf(`"`, index)) !== -1){
        count++;
        index++;
    }
    return count;
}
function splitMediaTypes(accept) {
    const accepts = accept.split(",");
    let j = 0;
    for(let i = 1; i < accepts.length; i++){
        if (quoteCount(accepts[j]) % 2 === 0) {
            accepts[++j] = accepts[i];
        } else {
            accepts[j] += `,${accepts[i]}`;
        }
    }
    accepts.length = j + 1;
    return accepts;
}
function splitParameters(str) {
    const parameters = str.split(";");
    let j = 0;
    for(let i = 1; i < parameters.length; i++){
        if (quoteCount(parameters[j]) % 2 === 0) {
            parameters[++j] = parameters[i];
        } else {
            parameters[j] += `;${parameters[i]}`;
        }
    }
    parameters.length = j + 1;
    return parameters.map((p)=>p.trim());
}
function splitKeyValuePair(str) {
    const [key, value] = str.split("=");
    return [
        key.toLowerCase(),
        value
    ];
}
function parseMediaType(str, i) {
    const match = simpleMediaTypeRegExp.exec(str);
    if (!match) {
        return;
    }
    const params = Object.create(null);
    let q = 1;
    const [, type, subtype, parameters] = match;
    if (parameters) {
        const kvps = splitParameters(parameters).map(splitKeyValuePair);
        for (const [key, val] of kvps){
            const value = val && val[0] === `"` && val[val.length - 1] === `"` ? val.slice(1, val.length - 1) : val;
            if (key === "q" && value) {
                q = parseFloat(value);
                break;
            }
            params[key] = value;
        }
    }
    return {
        type,
        subtype,
        params,
        q,
        i
    };
}
function parseAccept(accept) {
    const accepts = splitMediaTypes(accept);
    const mediaTypes = [];
    for(let i = 0; i < accepts.length; i++){
        const mediaType = parseMediaType(accepts[i].trim(), i);
        if (mediaType) {
            mediaTypes.push(mediaType);
        }
    }
    return mediaTypes;
}
function getFullType(spec) {
    return `${spec.type}/${spec.subtype}`;
}
function specify2(type, spec, index) {
    const p = parseMediaType(type, index);
    if (!p) {
        return;
    }
    let s = 0;
    if (spec.type.toLowerCase() === p.type.toLowerCase()) {
        s |= 4;
    } else if (spec.type !== "*") {
        return;
    }
    if (spec.subtype.toLowerCase() === p.subtype.toLowerCase()) {
        s |= 2;
    } else if (spec.subtype !== "*") {
        return;
    }
    const keys = Object.keys(spec.params);
    if (keys.length) {
        if (keys.every((key)=>(spec.params[key] || "").toLowerCase() === (p.params[key] || "").toLowerCase())) {
            s |= 1;
        } else {
            return;
        }
    }
    return {
        i: index,
        o: spec.o,
        q: spec.q,
        s
    };
}
function getMediaTypePriority(type, accepted, index) {
    let priority = {
        o: -1,
        q: 0,
        s: 0,
        i: index
    };
    for (const accepts of accepted){
        const spec = specify2(type, accepts, index);
        if (spec && ((priority.s || 0) - (spec.s || 0) || (priority.q || 0) - (spec.q || 0) || (priority.o || 0) - (spec.o || 0)) < 0) {
            priority = spec;
        }
    }
    return priority;
}
function preferredMediaTypes(accept, provided) {
    const accepts = parseAccept(accept === undefined ? "*/*" : accept || "");
    if (!provided) {
        return accepts.filter(isQuality).sort(compareSpecs).map(getFullType);
    }
    const priorities = provided.map((type, index)=>{
        return getMediaTypePriority(type, accepts, index);
    });
    return priorities.filter(isQuality).sort(compareSpecs).map((priority)=>provided[priorities.indexOf(priority)]);
}
function accepts(request, ...types) {
    const accept = request.headers.get("accept");
    return types.length ? accept ? preferredMediaTypes(accept, types)[0] : types[0] : accept ? preferredMediaTypes(accept) : [
        "*/*"
    ];
}
function acceptsEncodings(request, ...encodings) {
    const acceptEncoding = request.headers.get("accept-encoding");
    return encodings.length ? acceptEncoding ? preferredEncodings(acceptEncoding, encodings)[0] : encodings[0] : acceptEncoding ? preferredEncodings(acceptEncoding) : [
        "*"
    ];
}
function acceptsLanguages(request, ...langs) {
    const acceptLanguage = request.headers.get("accept-language");
    return langs.length ? acceptLanguage ? preferredLanguages(acceptLanguage, langs)[0] : langs[0] : acceptLanguage ? preferredLanguages(acceptLanguage) : [
        "*"
    ];
}
class AbstractBufBase {
    buf;
    usedBufferBytes = 0;
    err = null;
    constructor(buf){
        this.buf = buf;
    }
    size() {
        return this.buf.byteLength;
    }
    available() {
        return this.buf.byteLength - this.usedBufferBytes;
    }
    buffered() {
        return this.usedBufferBytes;
    }
}
class BufWriterSync extends AbstractBufBase {
    #writer;
    static create(writer, size = 4096) {
        return writer instanceof BufWriterSync ? writer : new BufWriterSync(writer, size);
    }
    constructor(writer, size = 4096){
        super(new Uint8Array(size <= 0 ? 4096 : size));
        this.#writer = writer;
    }
    reset(w) {
        this.err = null;
        this.usedBufferBytes = 0;
        this.#writer = w;
    }
    flush() {
        if (this.err !== null) throw this.err;
        if (this.usedBufferBytes === 0) return;
        try {
            const p = this.buf.subarray(0, this.usedBufferBytes);
            let nwritten = 0;
            while(nwritten < p.length){
                nwritten += this.#writer.writeSync(p.subarray(nwritten));
            }
        } catch (e) {
            if (e instanceof Error) {
                this.err = e;
            }
            throw e;
        }
        this.buf = new Uint8Array(this.buf.length);
        this.usedBufferBytes = 0;
    }
    writeSync(data) {
        if (this.err !== null) throw this.err;
        if (data.length === 0) return 0;
        let totalBytesWritten = 0;
        let numBytesWritten = 0;
        while(data.byteLength > this.available()){
            if (this.buffered() === 0) {
                try {
                    numBytesWritten = this.#writer.writeSync(data);
                } catch (e) {
                    if (e instanceof Error) {
                        this.err = e;
                    }
                    throw e;
                }
            } else {
                numBytesWritten = copy(data, this.buf, this.usedBufferBytes);
                this.usedBufferBytes += numBytesWritten;
                this.flush();
            }
            totalBytesWritten += numBytesWritten;
            data = data.subarray(numBytesWritten);
        }
        numBytesWritten = copy(data, this.buf, this.usedBufferBytes);
        this.usedBufferBytes += numBytesWritten;
        totalBytesWritten += numBytesWritten;
        return totalBytesWritten;
    }
}
const MIN_READ = 32 * 1024;
const MAX_SIZE = 2 ** 32 - 2;
class Buffer {
    #buf;
    #off = 0;
    constructor(ab){
        this.#buf = ab === undefined ? new Uint8Array(0) : new Uint8Array(ab);
    }
    bytes(options = {
        copy: true
    }) {
        if (options.copy === false) return this.#buf.subarray(this.#off);
        return this.#buf.slice(this.#off);
    }
    empty() {
        return this.#buf.byteLength <= this.#off;
    }
    get length() {
        return this.#buf.byteLength - this.#off;
    }
    get capacity() {
        return this.#buf.buffer.byteLength;
    }
    truncate(n) {
        if (n === 0) {
            this.reset();
            return;
        }
        if (n < 0 || n > this.length) {
            throw Error("bytes.Buffer: truncation out of range");
        }
        this.#reslice(this.#off + n);
    }
    reset() {
        this.#reslice(0);
        this.#off = 0;
    }
    #tryGrowByReslice(n) {
        const l = this.#buf.byteLength;
        if (n <= this.capacity - l) {
            this.#reslice(l + n);
            return l;
        }
        return -1;
    }
    #reslice(len) {
        assert(len <= this.#buf.buffer.byteLength);
        this.#buf = new Uint8Array(this.#buf.buffer, 0, len);
    }
    readSync(p) {
        if (this.empty()) {
            this.reset();
            if (p.byteLength === 0) {
                return 0;
            }
            return null;
        }
        const nread = copy(this.#buf.subarray(this.#off), p);
        this.#off += nread;
        return nread;
    }
    read(p) {
        const rr = this.readSync(p);
        return Promise.resolve(rr);
    }
    writeSync(p) {
        const m = this.#grow(p.byteLength);
        return copy(p, this.#buf, m);
    }
    write(p) {
        const n = this.writeSync(p);
        return Promise.resolve(n);
    }
    #grow(n1) {
        const m = this.length;
        if (m === 0 && this.#off !== 0) {
            this.reset();
        }
        const i = this.#tryGrowByReslice(n1);
        if (i >= 0) {
            return i;
        }
        const c = this.capacity;
        if (n1 <= Math.floor(c / 2) - m) {
            copy(this.#buf.subarray(this.#off), this.#buf);
        } else if (c + n1 > MAX_SIZE) {
            throw new Error("The buffer cannot be grown beyond the maximum size.");
        } else {
            const buf = new Uint8Array(Math.min(2 * c + n1, MAX_SIZE));
            copy(this.#buf.subarray(this.#off), buf);
            this.#buf = buf;
        }
        this.#off = 0;
        this.#reslice(Math.min(m + n1, MAX_SIZE));
        return m;
    }
    grow(n) {
        if (n < 0) {
            throw Error("Buffer.grow: negative count");
        }
        const m = this.#grow(n);
        this.#reslice(m);
    }
    async readFrom(r) {
        let n = 0;
        const tmp = new Uint8Array(MIN_READ);
        while(true){
            const shouldGrow = this.capacity - this.length < MIN_READ;
            const buf = shouldGrow ? tmp : new Uint8Array(this.#buf.buffer, this.length);
            const nread = await r.read(buf);
            if (nread === null) {
                return n;
            }
            if (shouldGrow) this.writeSync(buf.subarray(0, nread));
            else this.#reslice(this.length + nread);
            n += nread;
        }
    }
    readFromSync(r) {
        let n = 0;
        const tmp = new Uint8Array(MIN_READ);
        while(true){
            const shouldGrow = this.capacity - this.length < MIN_READ;
            const buf = shouldGrow ? tmp : new Uint8Array(this.#buf.buffer, this.length);
            const nread = r.readSync(buf);
            if (nread === null) {
                return n;
            }
            if (shouldGrow) this.writeSync(buf.subarray(0, nread));
            else this.#reslice(this.length + nread);
            n += nread;
        }
    }
}
class LimitedReader {
    constructor(reader, limit){
        this.reader = reader;
        this.limit = limit;
    }
    async read(p) {
        if (this.limit <= 0) {
            return null;
        }
        if (p.length > this.limit) {
            p = p.subarray(0, this.limit);
        }
        const n = await this.reader.read(p);
        if (n == null) {
            return null;
        }
        this.limit -= n;
        return n;
    }
    reader;
    limit;
}
BigInt(Number.MAX_SAFE_INTEGER);
new TextDecoder();
const extensions = new Map();
function consumeToken(v) {
    const notPos = indexOf(v, isNotTokenChar);
    if (notPos == -1) {
        return [
            v,
            ""
        ];
    }
    if (notPos == 0) {
        return [
            "",
            v
        ];
    }
    return [
        v.slice(0, notPos),
        v.slice(notPos)
    ];
}
function consumeValue(v) {
    if (!v) {
        return [
            "",
            v
        ];
    }
    if (v[0] !== `"`) {
        return consumeToken(v);
    }
    let value = "";
    for(let i = 1; i < v.length; i++){
        const r = v[i];
        if (r === `"`) {
            return [
                value,
                v.slice(i + 1)
            ];
        }
        if (r === "\\" && i + 1 < v.length && isTSpecial(v[i + 1])) {
            value += v[i + 1];
            i++;
            continue;
        }
        if (r === "\r" || r === "\n") {
            return [
                "",
                v
            ];
        }
        value += v[i];
    }
    return [
        "",
        v
    ];
}
function consumeMediaParam(v) {
    let rest = v.trimStart();
    if (!rest.startsWith(";")) {
        return [
            "",
            "",
            v
        ];
    }
    rest = rest.slice(1);
    rest = rest.trimStart();
    let param;
    [param, rest] = consumeToken(rest);
    param = param.toLowerCase();
    if (!param) {
        return [
            "",
            "",
            v
        ];
    }
    rest = rest.slice(1);
    rest = rest.trimStart();
    const [value, rest2] = consumeValue(rest);
    if (value == "" && rest2 === rest) {
        return [
            "",
            "",
            v
        ];
    }
    rest = rest2;
    return [
        param,
        value,
        rest
    ];
}
function decode2331Encoding(v) {
    const sv = v.split(`'`, 3);
    if (sv.length !== 3) {
        return undefined;
    }
    const charset = sv[0].toLowerCase();
    if (!charset) {
        return undefined;
    }
    if (charset != "us-ascii" && charset != "utf-8") {
        return undefined;
    }
    const encv = decodeURI(sv[2]);
    if (!encv) {
        return undefined;
    }
    return encv;
}
function indexOf(s, fn) {
    let i = -1;
    for (const v of s){
        i++;
        if (fn(v)) {
            return i;
        }
    }
    return -1;
}
function isIterator(obj) {
    if (obj == null) {
        return false;
    }
    return typeof obj[Symbol.iterator] === "function";
}
function isToken(s) {
    if (!s) {
        return false;
    }
    return indexOf(s, isNotTokenChar) < 0;
}
function isNotTokenChar(r) {
    return !isTokenChar(r);
}
function isTokenChar(r) {
    const code = r.charCodeAt(0);
    return code > 0x20 && code < 0x7f && !isTSpecial(r);
}
function isTSpecial(r) {
    return `()<>@,;:\\"/[]?=`.includes(r[0]);
}
const CHAR_CODE_SPACE = " ".charCodeAt(0);
const CHAR_CODE_TILDE = "~".charCodeAt(0);
function needsEncoding(s) {
    for (const b of s){
        const charCode = b.charCodeAt(0);
        if ((charCode < CHAR_CODE_SPACE || charCode > CHAR_CODE_TILDE) && b !== "\t") {
            return true;
        }
    }
    return false;
}
function parseMediaType1(v) {
    const [base] = v.split(";");
    const mediaType = base.toLowerCase().trim();
    const params = {};
    const continuation = new Map();
    v = v.slice(base.length);
    while(v.length){
        v = v.trimStart();
        if (v.length === 0) {
            break;
        }
        const [key, value, rest] = consumeMediaParam(v);
        if (!key) {
            if (rest.trim() === ";") {
                break;
            }
            throw new TypeError("Invalid media parameter.");
        }
        let pmap = params;
        const [baseName, rest2] = key.split("*");
        if (baseName && rest2 != null) {
            if (!continuation.has(baseName)) {
                continuation.set(baseName, {});
            }
            pmap = continuation.get(baseName);
        }
        if (key in pmap) {
            throw new TypeError("Duplicate key parsed.");
        }
        pmap[key] = value;
        v = rest;
    }
    let str = "";
    for (const [key, pieceMap] of continuation){
        const singlePartKey = `${key}*`;
        const v = pieceMap[singlePartKey];
        if (v) {
            const decv = decode2331Encoding(v);
            if (decv) {
                params[key] = decv;
            }
            continue;
        }
        str = "";
        let valid = false;
        for(let n = 0;; n++){
            const simplePart = `${key}*${n}`;
            let v = pieceMap[simplePart];
            if (v) {
                valid = true;
                str += v;
                continue;
            }
            const encodedPart = `${simplePart}*`;
            v = pieceMap[encodedPart];
            if (!v) {
                break;
            }
            valid = true;
            if (n === 0) {
                const decv = decode2331Encoding(v);
                if (decv) {
                    str += decv;
                }
            } else {
                const decv = decodeURI(v);
                str += decv;
            }
        }
        if (valid) {
            params[key] = str;
        }
    }
    return Object.keys(params).length ? [
        mediaType,
        params
    ] : [
        mediaType,
        undefined
    ];
}
const __default = {
    "application/1d-interleaved-parityfec": {
        "source": "iana"
    },
    "application/3gpdash-qoe-report+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/3gpp-ims+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/3gpphal+json": {
        "source": "iana",
        "compressible": true
    },
    "application/3gpphalforms+json": {
        "source": "iana",
        "compressible": true
    },
    "application/a2l": {
        "source": "iana"
    },
    "application/ace+cbor": {
        "source": "iana"
    },
    "application/activemessage": {
        "source": "iana"
    },
    "application/activity+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-costmap+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-costmapfilter+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-directory+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-endpointcost+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-endpointcostparams+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-endpointprop+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-endpointpropparams+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-error+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-networkmap+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-networkmapfilter+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-updatestreamcontrol+json": {
        "source": "iana",
        "compressible": true
    },
    "application/alto-updatestreamparams+json": {
        "source": "iana",
        "compressible": true
    },
    "application/aml": {
        "source": "iana"
    },
    "application/andrew-inset": {
        "source": "iana",
        "extensions": [
            "ez"
        ]
    },
    "application/applefile": {
        "source": "iana"
    },
    "application/applixware": {
        "source": "apache",
        "extensions": [
            "aw"
        ]
    },
    "application/at+jwt": {
        "source": "iana"
    },
    "application/atf": {
        "source": "iana"
    },
    "application/atfx": {
        "source": "iana"
    },
    "application/atom+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "atom"
        ]
    },
    "application/atomcat+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "atomcat"
        ]
    },
    "application/atomdeleted+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "atomdeleted"
        ]
    },
    "application/atomicmail": {
        "source": "iana"
    },
    "application/atomsvc+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "atomsvc"
        ]
    },
    "application/atsc-dwd+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "dwd"
        ]
    },
    "application/atsc-dynamic-event-message": {
        "source": "iana"
    },
    "application/atsc-held+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "held"
        ]
    },
    "application/atsc-rdt+json": {
        "source": "iana",
        "compressible": true
    },
    "application/atsc-rsat+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rsat"
        ]
    },
    "application/atxml": {
        "source": "iana"
    },
    "application/auth-policy+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/bacnet-xdd+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/batch-smtp": {
        "source": "iana"
    },
    "application/bdoc": {
        "compressible": false,
        "extensions": [
            "bdoc"
        ]
    },
    "application/beep+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/calendar+json": {
        "source": "iana",
        "compressible": true
    },
    "application/calendar+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xcs"
        ]
    },
    "application/call-completion": {
        "source": "iana"
    },
    "application/cals-1840": {
        "source": "iana"
    },
    "application/captive+json": {
        "source": "iana",
        "compressible": true
    },
    "application/cbor": {
        "source": "iana"
    },
    "application/cbor-seq": {
        "source": "iana"
    },
    "application/cccex": {
        "source": "iana"
    },
    "application/ccmp+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/ccxml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ccxml"
        ]
    },
    "application/cdfx+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "cdfx"
        ]
    },
    "application/cdmi-capability": {
        "source": "iana",
        "extensions": [
            "cdmia"
        ]
    },
    "application/cdmi-container": {
        "source": "iana",
        "extensions": [
            "cdmic"
        ]
    },
    "application/cdmi-domain": {
        "source": "iana",
        "extensions": [
            "cdmid"
        ]
    },
    "application/cdmi-object": {
        "source": "iana",
        "extensions": [
            "cdmio"
        ]
    },
    "application/cdmi-queue": {
        "source": "iana",
        "extensions": [
            "cdmiq"
        ]
    },
    "application/cdni": {
        "source": "iana"
    },
    "application/cea": {
        "source": "iana"
    },
    "application/cea-2018+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/cellml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/cfw": {
        "source": "iana"
    },
    "application/city+json": {
        "source": "iana",
        "compressible": true
    },
    "application/clr": {
        "source": "iana"
    },
    "application/clue+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/clue_info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/cms": {
        "source": "iana"
    },
    "application/cnrp+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/coap-group+json": {
        "source": "iana",
        "compressible": true
    },
    "application/coap-payload": {
        "source": "iana"
    },
    "application/commonground": {
        "source": "iana"
    },
    "application/conference-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/cose": {
        "source": "iana"
    },
    "application/cose-key": {
        "source": "iana"
    },
    "application/cose-key-set": {
        "source": "iana"
    },
    "application/cpl+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "cpl"
        ]
    },
    "application/csrattrs": {
        "source": "iana"
    },
    "application/csta+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/cstadata+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/csvm+json": {
        "source": "iana",
        "compressible": true
    },
    "application/cu-seeme": {
        "source": "apache",
        "extensions": [
            "cu"
        ]
    },
    "application/cwt": {
        "source": "iana"
    },
    "application/cybercash": {
        "source": "iana"
    },
    "application/dart": {
        "compressible": true
    },
    "application/dash+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mpd"
        ]
    },
    "application/dash-patch+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mpp"
        ]
    },
    "application/dashdelta": {
        "source": "iana"
    },
    "application/davmount+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "davmount"
        ]
    },
    "application/dca-rft": {
        "source": "iana"
    },
    "application/dcd": {
        "source": "iana"
    },
    "application/dec-dx": {
        "source": "iana"
    },
    "application/dialog-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/dicom": {
        "source": "iana"
    },
    "application/dicom+json": {
        "source": "iana",
        "compressible": true
    },
    "application/dicom+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/dii": {
        "source": "iana"
    },
    "application/dit": {
        "source": "iana"
    },
    "application/dns": {
        "source": "iana"
    },
    "application/dns+json": {
        "source": "iana",
        "compressible": true
    },
    "application/dns-message": {
        "source": "iana"
    },
    "application/docbook+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "dbk"
        ]
    },
    "application/dots+cbor": {
        "source": "iana"
    },
    "application/dskpp+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/dssc+der": {
        "source": "iana",
        "extensions": [
            "dssc"
        ]
    },
    "application/dssc+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xdssc"
        ]
    },
    "application/dvcs": {
        "source": "iana"
    },
    "application/ecmascript": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "es",
            "ecma"
        ]
    },
    "application/edi-consent": {
        "source": "iana"
    },
    "application/edi-x12": {
        "source": "iana",
        "compressible": false
    },
    "application/edifact": {
        "source": "iana",
        "compressible": false
    },
    "application/efi": {
        "source": "iana"
    },
    "application/elm+json": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/elm+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emergencycalldata.cap+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/emergencycalldata.comment+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emergencycalldata.control+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emergencycalldata.deviceinfo+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emergencycalldata.ecall.msd": {
        "source": "iana"
    },
    "application/emergencycalldata.providerinfo+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emergencycalldata.serviceinfo+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emergencycalldata.subscriberinfo+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emergencycalldata.veds+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/emma+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "emma"
        ]
    },
    "application/emotionml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "emotionml"
        ]
    },
    "application/encaprtp": {
        "source": "iana"
    },
    "application/epp+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/epub+zip": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "epub"
        ]
    },
    "application/eshop": {
        "source": "iana"
    },
    "application/exi": {
        "source": "iana",
        "extensions": [
            "exi"
        ]
    },
    "application/expect-ct-report+json": {
        "source": "iana",
        "compressible": true
    },
    "application/express": {
        "source": "iana",
        "extensions": [
            "exp"
        ]
    },
    "application/fastinfoset": {
        "source": "iana"
    },
    "application/fastsoap": {
        "source": "iana"
    },
    "application/fdt+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "fdt"
        ]
    },
    "application/fhir+json": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/fhir+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/fido.trusted-apps+json": {
        "compressible": true
    },
    "application/fits": {
        "source": "iana"
    },
    "application/flexfec": {
        "source": "iana"
    },
    "application/font-sfnt": {
        "source": "iana"
    },
    "application/font-tdpfr": {
        "source": "iana",
        "extensions": [
            "pfr"
        ]
    },
    "application/font-woff": {
        "source": "iana",
        "compressible": false
    },
    "application/framework-attributes+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/geo+json": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "geojson"
        ]
    },
    "application/geo+json-seq": {
        "source": "iana"
    },
    "application/geopackage+sqlite3": {
        "source": "iana"
    },
    "application/geoxacml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/gltf-buffer": {
        "source": "iana"
    },
    "application/gml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "gml"
        ]
    },
    "application/gpx+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "gpx"
        ]
    },
    "application/gxf": {
        "source": "apache",
        "extensions": [
            "gxf"
        ]
    },
    "application/gzip": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "gz"
        ]
    },
    "application/h224": {
        "source": "iana"
    },
    "application/held+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/hjson": {
        "extensions": [
            "hjson"
        ]
    },
    "application/http": {
        "source": "iana"
    },
    "application/hyperstudio": {
        "source": "iana",
        "extensions": [
            "stk"
        ]
    },
    "application/ibe-key-request+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/ibe-pkg-reply+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/ibe-pp-data": {
        "source": "iana"
    },
    "application/iges": {
        "source": "iana"
    },
    "application/im-iscomposing+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/index": {
        "source": "iana"
    },
    "application/index.cmd": {
        "source": "iana"
    },
    "application/index.obj": {
        "source": "iana"
    },
    "application/index.response": {
        "source": "iana"
    },
    "application/index.vnd": {
        "source": "iana"
    },
    "application/inkml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ink",
            "inkml"
        ]
    },
    "application/iotp": {
        "source": "iana"
    },
    "application/ipfix": {
        "source": "iana",
        "extensions": [
            "ipfix"
        ]
    },
    "application/ipp": {
        "source": "iana"
    },
    "application/isup": {
        "source": "iana"
    },
    "application/its+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "its"
        ]
    },
    "application/java-archive": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "jar",
            "war",
            "ear"
        ]
    },
    "application/java-serialized-object": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "ser"
        ]
    },
    "application/java-vm": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "class"
        ]
    },
    "application/javascript": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "js",
            "mjs"
        ]
    },
    "application/jf2feed+json": {
        "source": "iana",
        "compressible": true
    },
    "application/jose": {
        "source": "iana"
    },
    "application/jose+json": {
        "source": "iana",
        "compressible": true
    },
    "application/jrd+json": {
        "source": "iana",
        "compressible": true
    },
    "application/jscalendar+json": {
        "source": "iana",
        "compressible": true
    },
    "application/json": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "json",
            "map"
        ]
    },
    "application/json-patch+json": {
        "source": "iana",
        "compressible": true
    },
    "application/json-seq": {
        "source": "iana"
    },
    "application/json5": {
        "extensions": [
            "json5"
        ]
    },
    "application/jsonml+json": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "jsonml"
        ]
    },
    "application/jwk+json": {
        "source": "iana",
        "compressible": true
    },
    "application/jwk-set+json": {
        "source": "iana",
        "compressible": true
    },
    "application/jwt": {
        "source": "iana"
    },
    "application/kpml-request+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/kpml-response+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/ld+json": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "jsonld"
        ]
    },
    "application/lgr+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "lgr"
        ]
    },
    "application/link-format": {
        "source": "iana"
    },
    "application/load-control+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/lost+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "lostxml"
        ]
    },
    "application/lostsync+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/lpf+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/lxf": {
        "source": "iana"
    },
    "application/mac-binhex40": {
        "source": "iana",
        "extensions": [
            "hqx"
        ]
    },
    "application/mac-compactpro": {
        "source": "apache",
        "extensions": [
            "cpt"
        ]
    },
    "application/macwriteii": {
        "source": "iana"
    },
    "application/mads+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mads"
        ]
    },
    "application/manifest+json": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "webmanifest"
        ]
    },
    "application/marc": {
        "source": "iana",
        "extensions": [
            "mrc"
        ]
    },
    "application/marcxml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mrcx"
        ]
    },
    "application/mathematica": {
        "source": "iana",
        "extensions": [
            "ma",
            "nb",
            "mb"
        ]
    },
    "application/mathml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mathml"
        ]
    },
    "application/mathml-content+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mathml-presentation+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-associated-procedure-description+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-deregister+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-envelope+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-msk+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-msk-response+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-protection-description+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-reception-report+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-register+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-register-response+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-schedule+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbms-user-service-description+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mbox": {
        "source": "iana",
        "extensions": [
            "mbox"
        ]
    },
    "application/media-policy-dataset+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mpf"
        ]
    },
    "application/media_control+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mediaservercontrol+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mscml"
        ]
    },
    "application/merge-patch+json": {
        "source": "iana",
        "compressible": true
    },
    "application/metalink+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "metalink"
        ]
    },
    "application/metalink4+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "meta4"
        ]
    },
    "application/mets+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mets"
        ]
    },
    "application/mf4": {
        "source": "iana"
    },
    "application/mikey": {
        "source": "iana"
    },
    "application/mipc": {
        "source": "iana"
    },
    "application/missing-blocks+cbor-seq": {
        "source": "iana"
    },
    "application/mmt-aei+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "maei"
        ]
    },
    "application/mmt-usd+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "musd"
        ]
    },
    "application/mods+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mods"
        ]
    },
    "application/moss-keys": {
        "source": "iana"
    },
    "application/moss-signature": {
        "source": "iana"
    },
    "application/mosskey-data": {
        "source": "iana"
    },
    "application/mosskey-request": {
        "source": "iana"
    },
    "application/mp21": {
        "source": "iana",
        "extensions": [
            "m21",
            "mp21"
        ]
    },
    "application/mp4": {
        "source": "iana",
        "extensions": [
            "mp4s",
            "m4p"
        ]
    },
    "application/mpeg4-generic": {
        "source": "iana"
    },
    "application/mpeg4-iod": {
        "source": "iana"
    },
    "application/mpeg4-iod-xmt": {
        "source": "iana"
    },
    "application/mrb-consumer+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/mrb-publish+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/msc-ivr+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/msc-mixer+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/msword": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "doc",
            "dot"
        ]
    },
    "application/mud+json": {
        "source": "iana",
        "compressible": true
    },
    "application/multipart-core": {
        "source": "iana"
    },
    "application/mxf": {
        "source": "iana",
        "extensions": [
            "mxf"
        ]
    },
    "application/n-quads": {
        "source": "iana",
        "extensions": [
            "nq"
        ]
    },
    "application/n-triples": {
        "source": "iana",
        "extensions": [
            "nt"
        ]
    },
    "application/nasdata": {
        "source": "iana"
    },
    "application/news-checkgroups": {
        "source": "iana",
        "charset": "US-ASCII"
    },
    "application/news-groupinfo": {
        "source": "iana",
        "charset": "US-ASCII"
    },
    "application/news-transmission": {
        "source": "iana"
    },
    "application/nlsml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/node": {
        "source": "iana",
        "extensions": [
            "cjs"
        ]
    },
    "application/nss": {
        "source": "iana"
    },
    "application/oauth-authz-req+jwt": {
        "source": "iana"
    },
    "application/oblivious-dns-message": {
        "source": "iana"
    },
    "application/ocsp-request": {
        "source": "iana"
    },
    "application/ocsp-response": {
        "source": "iana"
    },
    "application/octet-stream": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "bin",
            "dms",
            "lrf",
            "mar",
            "so",
            "dist",
            "distz",
            "pkg",
            "bpk",
            "dump",
            "elc",
            "deploy",
            "exe",
            "dll",
            "deb",
            "dmg",
            "iso",
            "img",
            "msi",
            "msp",
            "msm",
            "buffer"
        ]
    },
    "application/oda": {
        "source": "iana",
        "extensions": [
            "oda"
        ]
    },
    "application/odm+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/odx": {
        "source": "iana"
    },
    "application/oebps-package+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "opf"
        ]
    },
    "application/ogg": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "ogx"
        ]
    },
    "application/omdoc+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "omdoc"
        ]
    },
    "application/onenote": {
        "source": "apache",
        "extensions": [
            "onetoc",
            "onetoc2",
            "onetmp",
            "onepkg"
        ]
    },
    "application/opc-nodeset+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/oscore": {
        "source": "iana"
    },
    "application/oxps": {
        "source": "iana",
        "extensions": [
            "oxps"
        ]
    },
    "application/p21": {
        "source": "iana"
    },
    "application/p21+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/p2p-overlay+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "relo"
        ]
    },
    "application/parityfec": {
        "source": "iana"
    },
    "application/passport": {
        "source": "iana"
    },
    "application/patch-ops-error+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xer"
        ]
    },
    "application/pdf": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "pdf"
        ]
    },
    "application/pdx": {
        "source": "iana"
    },
    "application/pem-certificate-chain": {
        "source": "iana"
    },
    "application/pgp-encrypted": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "pgp"
        ]
    },
    "application/pgp-keys": {
        "source": "iana",
        "extensions": [
            "asc"
        ]
    },
    "application/pgp-signature": {
        "source": "iana",
        "extensions": [
            "asc",
            "sig"
        ]
    },
    "application/pics-rules": {
        "source": "apache",
        "extensions": [
            "prf"
        ]
    },
    "application/pidf+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/pidf-diff+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/pkcs10": {
        "source": "iana",
        "extensions": [
            "p10"
        ]
    },
    "application/pkcs12": {
        "source": "iana"
    },
    "application/pkcs7-mime": {
        "source": "iana",
        "extensions": [
            "p7m",
            "p7c"
        ]
    },
    "application/pkcs7-signature": {
        "source": "iana",
        "extensions": [
            "p7s"
        ]
    },
    "application/pkcs8": {
        "source": "iana",
        "extensions": [
            "p8"
        ]
    },
    "application/pkcs8-encrypted": {
        "source": "iana"
    },
    "application/pkix-attr-cert": {
        "source": "iana",
        "extensions": [
            "ac"
        ]
    },
    "application/pkix-cert": {
        "source": "iana",
        "extensions": [
            "cer"
        ]
    },
    "application/pkix-crl": {
        "source": "iana",
        "extensions": [
            "crl"
        ]
    },
    "application/pkix-pkipath": {
        "source": "iana",
        "extensions": [
            "pkipath"
        ]
    },
    "application/pkixcmp": {
        "source": "iana",
        "extensions": [
            "pki"
        ]
    },
    "application/pls+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "pls"
        ]
    },
    "application/poc-settings+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/postscript": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ai",
            "eps",
            "ps"
        ]
    },
    "application/ppsp-tracker+json": {
        "source": "iana",
        "compressible": true
    },
    "application/problem+json": {
        "source": "iana",
        "compressible": true
    },
    "application/problem+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/provenance+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "provx"
        ]
    },
    "application/prs.alvestrand.titrax-sheet": {
        "source": "iana"
    },
    "application/prs.cww": {
        "source": "iana",
        "extensions": [
            "cww"
        ]
    },
    "application/prs.cyn": {
        "source": "iana",
        "charset": "7-BIT"
    },
    "application/prs.hpub+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/prs.nprend": {
        "source": "iana"
    },
    "application/prs.plucker": {
        "source": "iana"
    },
    "application/prs.rdf-xml-crypt": {
        "source": "iana"
    },
    "application/prs.xsf+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/pskc+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "pskcxml"
        ]
    },
    "application/pvd+json": {
        "source": "iana",
        "compressible": true
    },
    "application/qsig": {
        "source": "iana"
    },
    "application/raml+yaml": {
        "compressible": true,
        "extensions": [
            "raml"
        ]
    },
    "application/raptorfec": {
        "source": "iana"
    },
    "application/rdap+json": {
        "source": "iana",
        "compressible": true
    },
    "application/rdf+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rdf",
            "owl"
        ]
    },
    "application/reginfo+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rif"
        ]
    },
    "application/relax-ng-compact-syntax": {
        "source": "iana",
        "extensions": [
            "rnc"
        ]
    },
    "application/remote-printing": {
        "source": "iana"
    },
    "application/reputon+json": {
        "source": "iana",
        "compressible": true
    },
    "application/resource-lists+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rl"
        ]
    },
    "application/resource-lists-diff+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rld"
        ]
    },
    "application/rfc+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/riscos": {
        "source": "iana"
    },
    "application/rlmi+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/rls-services+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rs"
        ]
    },
    "application/route-apd+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rapd"
        ]
    },
    "application/route-s-tsid+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "sls"
        ]
    },
    "application/route-usd+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rusd"
        ]
    },
    "application/rpki-ghostbusters": {
        "source": "iana",
        "extensions": [
            "gbr"
        ]
    },
    "application/rpki-manifest": {
        "source": "iana",
        "extensions": [
            "mft"
        ]
    },
    "application/rpki-publication": {
        "source": "iana"
    },
    "application/rpki-roa": {
        "source": "iana",
        "extensions": [
            "roa"
        ]
    },
    "application/rpki-updown": {
        "source": "iana"
    },
    "application/rsd+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "rsd"
        ]
    },
    "application/rss+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "rss"
        ]
    },
    "application/rtf": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rtf"
        ]
    },
    "application/rtploopback": {
        "source": "iana"
    },
    "application/rtx": {
        "source": "iana"
    },
    "application/samlassertion+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/samlmetadata+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/sarif+json": {
        "source": "iana",
        "compressible": true
    },
    "application/sarif-external-properties+json": {
        "source": "iana",
        "compressible": true
    },
    "application/sbe": {
        "source": "iana"
    },
    "application/sbml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "sbml"
        ]
    },
    "application/scaip+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/scim+json": {
        "source": "iana",
        "compressible": true
    },
    "application/scvp-cv-request": {
        "source": "iana",
        "extensions": [
            "scq"
        ]
    },
    "application/scvp-cv-response": {
        "source": "iana",
        "extensions": [
            "scs"
        ]
    },
    "application/scvp-vp-request": {
        "source": "iana",
        "extensions": [
            "spq"
        ]
    },
    "application/scvp-vp-response": {
        "source": "iana",
        "extensions": [
            "spp"
        ]
    },
    "application/sdp": {
        "source": "iana",
        "extensions": [
            "sdp"
        ]
    },
    "application/secevent+jwt": {
        "source": "iana"
    },
    "application/senml+cbor": {
        "source": "iana"
    },
    "application/senml+json": {
        "source": "iana",
        "compressible": true
    },
    "application/senml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "senmlx"
        ]
    },
    "application/senml-etch+cbor": {
        "source": "iana"
    },
    "application/senml-etch+json": {
        "source": "iana",
        "compressible": true
    },
    "application/senml-exi": {
        "source": "iana"
    },
    "application/sensml+cbor": {
        "source": "iana"
    },
    "application/sensml+json": {
        "source": "iana",
        "compressible": true
    },
    "application/sensml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "sensmlx"
        ]
    },
    "application/sensml-exi": {
        "source": "iana"
    },
    "application/sep+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/sep-exi": {
        "source": "iana"
    },
    "application/session-info": {
        "source": "iana"
    },
    "application/set-payment": {
        "source": "iana"
    },
    "application/set-payment-initiation": {
        "source": "iana",
        "extensions": [
            "setpay"
        ]
    },
    "application/set-registration": {
        "source": "iana"
    },
    "application/set-registration-initiation": {
        "source": "iana",
        "extensions": [
            "setreg"
        ]
    },
    "application/sgml": {
        "source": "iana"
    },
    "application/sgml-open-catalog": {
        "source": "iana"
    },
    "application/shf+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "shf"
        ]
    },
    "application/sieve": {
        "source": "iana",
        "extensions": [
            "siv",
            "sieve"
        ]
    },
    "application/simple-filter+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/simple-message-summary": {
        "source": "iana"
    },
    "application/simplesymbolcontainer": {
        "source": "iana"
    },
    "application/sipc": {
        "source": "iana"
    },
    "application/slate": {
        "source": "iana"
    },
    "application/smil": {
        "source": "iana"
    },
    "application/smil+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "smi",
            "smil"
        ]
    },
    "application/smpte336m": {
        "source": "iana"
    },
    "application/soap+fastinfoset": {
        "source": "iana"
    },
    "application/soap+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/sparql-query": {
        "source": "iana",
        "extensions": [
            "rq"
        ]
    },
    "application/sparql-results+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "srx"
        ]
    },
    "application/spdx+json": {
        "source": "iana",
        "compressible": true
    },
    "application/spirits-event+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/sql": {
        "source": "iana"
    },
    "application/srgs": {
        "source": "iana",
        "extensions": [
            "gram"
        ]
    },
    "application/srgs+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "grxml"
        ]
    },
    "application/sru+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "sru"
        ]
    },
    "application/ssdl+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "ssdl"
        ]
    },
    "application/ssml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ssml"
        ]
    },
    "application/stix+json": {
        "source": "iana",
        "compressible": true
    },
    "application/swid+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "swidtag"
        ]
    },
    "application/tamp-apex-update": {
        "source": "iana"
    },
    "application/tamp-apex-update-confirm": {
        "source": "iana"
    },
    "application/tamp-community-update": {
        "source": "iana"
    },
    "application/tamp-community-update-confirm": {
        "source": "iana"
    },
    "application/tamp-error": {
        "source": "iana"
    },
    "application/tamp-sequence-adjust": {
        "source": "iana"
    },
    "application/tamp-sequence-adjust-confirm": {
        "source": "iana"
    },
    "application/tamp-status-query": {
        "source": "iana"
    },
    "application/tamp-status-response": {
        "source": "iana"
    },
    "application/tamp-update": {
        "source": "iana"
    },
    "application/tamp-update-confirm": {
        "source": "iana"
    },
    "application/tar": {
        "compressible": true
    },
    "application/taxii+json": {
        "source": "iana",
        "compressible": true
    },
    "application/td+json": {
        "source": "iana",
        "compressible": true
    },
    "application/tei+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "tei",
            "teicorpus"
        ]
    },
    "application/tetra_isi": {
        "source": "iana"
    },
    "application/thraud+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "tfi"
        ]
    },
    "application/timestamp-query": {
        "source": "iana"
    },
    "application/timestamp-reply": {
        "source": "iana"
    },
    "application/timestamped-data": {
        "source": "iana",
        "extensions": [
            "tsd"
        ]
    },
    "application/tlsrpt+gzip": {
        "source": "iana"
    },
    "application/tlsrpt+json": {
        "source": "iana",
        "compressible": true
    },
    "application/tnauthlist": {
        "source": "iana"
    },
    "application/token-introspection+jwt": {
        "source": "iana"
    },
    "application/toml": {
        "compressible": true,
        "extensions": [
            "toml"
        ]
    },
    "application/trickle-ice-sdpfrag": {
        "source": "iana"
    },
    "application/trig": {
        "source": "iana",
        "extensions": [
            "trig"
        ]
    },
    "application/ttml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ttml"
        ]
    },
    "application/tve-trigger": {
        "source": "iana"
    },
    "application/tzif": {
        "source": "iana"
    },
    "application/tzif-leap": {
        "source": "iana"
    },
    "application/ubjson": {
        "compressible": false,
        "extensions": [
            "ubj"
        ]
    },
    "application/ulpfec": {
        "source": "iana"
    },
    "application/urc-grpsheet+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/urc-ressheet+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rsheet"
        ]
    },
    "application/urc-targetdesc+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "td"
        ]
    },
    "application/urc-uisocketdesc+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vcard+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vcard+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vemmi": {
        "source": "iana"
    },
    "application/vividence.scriptfile": {
        "source": "apache"
    },
    "application/vnd.1000minds.decision-model+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "1km"
        ]
    },
    "application/vnd.3gpp-prose+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp-prose-pc3ch+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp-v2x-local-service-information": {
        "source": "iana"
    },
    "application/vnd.3gpp.5gnas": {
        "source": "iana"
    },
    "application/vnd.3gpp.access-transfer-events+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.bsf+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.gmop+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.gtpc": {
        "source": "iana"
    },
    "application/vnd.3gpp.interworking-data": {
        "source": "iana"
    },
    "application/vnd.3gpp.lpp": {
        "source": "iana"
    },
    "application/vnd.3gpp.mc-signalling-ear": {
        "source": "iana"
    },
    "application/vnd.3gpp.mcdata-affiliation-command+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcdata-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcdata-payload": {
        "source": "iana"
    },
    "application/vnd.3gpp.mcdata-service-config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcdata-signalling": {
        "source": "iana"
    },
    "application/vnd.3gpp.mcdata-ue-config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcdata-user-profile+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-affiliation-command+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-floor-request+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-location-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-mbms-usage-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-service-config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-signed+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-ue-config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-ue-init-config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcptt-user-profile+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-affiliation-command+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-affiliation-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-location-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-mbms-usage-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-service-config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-transmission-request+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-ue-config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mcvideo-user-profile+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.mid-call+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.ngap": {
        "source": "iana"
    },
    "application/vnd.3gpp.pfcp": {
        "source": "iana"
    },
    "application/vnd.3gpp.pic-bw-large": {
        "source": "iana",
        "extensions": [
            "plb"
        ]
    },
    "application/vnd.3gpp.pic-bw-small": {
        "source": "iana",
        "extensions": [
            "psb"
        ]
    },
    "application/vnd.3gpp.pic-bw-var": {
        "source": "iana",
        "extensions": [
            "pvb"
        ]
    },
    "application/vnd.3gpp.s1ap": {
        "source": "iana"
    },
    "application/vnd.3gpp.sms": {
        "source": "iana"
    },
    "application/vnd.3gpp.sms+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.srvcc-ext+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.srvcc-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.state-and-event-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp.ussd+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp2.bcmcsinfo+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.3gpp2.sms": {
        "source": "iana"
    },
    "application/vnd.3gpp2.tcap": {
        "source": "iana",
        "extensions": [
            "tcap"
        ]
    },
    "application/vnd.3lightssoftware.imagescal": {
        "source": "iana"
    },
    "application/vnd.3m.post-it-notes": {
        "source": "iana",
        "extensions": [
            "pwn"
        ]
    },
    "application/vnd.accpac.simply.aso": {
        "source": "iana",
        "extensions": [
            "aso"
        ]
    },
    "application/vnd.accpac.simply.imp": {
        "source": "iana",
        "extensions": [
            "imp"
        ]
    },
    "application/vnd.acucobol": {
        "source": "iana",
        "extensions": [
            "acu"
        ]
    },
    "application/vnd.acucorp": {
        "source": "iana",
        "extensions": [
            "atc",
            "acutc"
        ]
    },
    "application/vnd.adobe.air-application-installer-package+zip": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "air"
        ]
    },
    "application/vnd.adobe.flash.movie": {
        "source": "iana"
    },
    "application/vnd.adobe.formscentral.fcdt": {
        "source": "iana",
        "extensions": [
            "fcdt"
        ]
    },
    "application/vnd.adobe.fxp": {
        "source": "iana",
        "extensions": [
            "fxp",
            "fxpl"
        ]
    },
    "application/vnd.adobe.partial-upload": {
        "source": "iana"
    },
    "application/vnd.adobe.xdp+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xdp"
        ]
    },
    "application/vnd.adobe.xfdf": {
        "source": "iana",
        "extensions": [
            "xfdf"
        ]
    },
    "application/vnd.aether.imp": {
        "source": "iana"
    },
    "application/vnd.afpc.afplinedata": {
        "source": "iana"
    },
    "application/vnd.afpc.afplinedata-pagedef": {
        "source": "iana"
    },
    "application/vnd.afpc.cmoca-cmresource": {
        "source": "iana"
    },
    "application/vnd.afpc.foca-charset": {
        "source": "iana"
    },
    "application/vnd.afpc.foca-codedfont": {
        "source": "iana"
    },
    "application/vnd.afpc.foca-codepage": {
        "source": "iana"
    },
    "application/vnd.afpc.modca": {
        "source": "iana"
    },
    "application/vnd.afpc.modca-cmtable": {
        "source": "iana"
    },
    "application/vnd.afpc.modca-formdef": {
        "source": "iana"
    },
    "application/vnd.afpc.modca-mediummap": {
        "source": "iana"
    },
    "application/vnd.afpc.modca-objectcontainer": {
        "source": "iana"
    },
    "application/vnd.afpc.modca-overlay": {
        "source": "iana"
    },
    "application/vnd.afpc.modca-pagesegment": {
        "source": "iana"
    },
    "application/vnd.age": {
        "source": "iana",
        "extensions": [
            "age"
        ]
    },
    "application/vnd.ah-barcode": {
        "source": "iana"
    },
    "application/vnd.ahead.space": {
        "source": "iana",
        "extensions": [
            "ahead"
        ]
    },
    "application/vnd.airzip.filesecure.azf": {
        "source": "iana",
        "extensions": [
            "azf"
        ]
    },
    "application/vnd.airzip.filesecure.azs": {
        "source": "iana",
        "extensions": [
            "azs"
        ]
    },
    "application/vnd.amadeus+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.amazon.ebook": {
        "source": "apache",
        "extensions": [
            "azw"
        ]
    },
    "application/vnd.amazon.mobi8-ebook": {
        "source": "iana"
    },
    "application/vnd.americandynamics.acc": {
        "source": "iana",
        "extensions": [
            "acc"
        ]
    },
    "application/vnd.amiga.ami": {
        "source": "iana",
        "extensions": [
            "ami"
        ]
    },
    "application/vnd.amundsen.maze+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.android.ota": {
        "source": "iana"
    },
    "application/vnd.android.package-archive": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "apk"
        ]
    },
    "application/vnd.anki": {
        "source": "iana"
    },
    "application/vnd.anser-web-certificate-issue-initiation": {
        "source": "iana",
        "extensions": [
            "cii"
        ]
    },
    "application/vnd.anser-web-funds-transfer-initiation": {
        "source": "apache",
        "extensions": [
            "fti"
        ]
    },
    "application/vnd.antix.game-component": {
        "source": "iana",
        "extensions": [
            "atx"
        ]
    },
    "application/vnd.apache.arrow.file": {
        "source": "iana"
    },
    "application/vnd.apache.arrow.stream": {
        "source": "iana"
    },
    "application/vnd.apache.thrift.binary": {
        "source": "iana"
    },
    "application/vnd.apache.thrift.compact": {
        "source": "iana"
    },
    "application/vnd.apache.thrift.json": {
        "source": "iana"
    },
    "application/vnd.api+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.aplextor.warrp+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.apothekende.reservation+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.apple.installer+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mpkg"
        ]
    },
    "application/vnd.apple.keynote": {
        "source": "iana",
        "extensions": [
            "key"
        ]
    },
    "application/vnd.apple.mpegurl": {
        "source": "iana",
        "extensions": [
            "m3u8"
        ]
    },
    "application/vnd.apple.numbers": {
        "source": "iana",
        "extensions": [
            "numbers"
        ]
    },
    "application/vnd.apple.pages": {
        "source": "iana",
        "extensions": [
            "pages"
        ]
    },
    "application/vnd.apple.pkpass": {
        "compressible": false,
        "extensions": [
            "pkpass"
        ]
    },
    "application/vnd.arastra.swi": {
        "source": "iana"
    },
    "application/vnd.aristanetworks.swi": {
        "source": "iana",
        "extensions": [
            "swi"
        ]
    },
    "application/vnd.artisan+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.artsquare": {
        "source": "iana"
    },
    "application/vnd.astraea-software.iota": {
        "source": "iana",
        "extensions": [
            "iota"
        ]
    },
    "application/vnd.audiograph": {
        "source": "iana",
        "extensions": [
            "aep"
        ]
    },
    "application/vnd.autopackage": {
        "source": "iana"
    },
    "application/vnd.avalon+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.avistar+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.balsamiq.bmml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "bmml"
        ]
    },
    "application/vnd.balsamiq.bmpr": {
        "source": "iana"
    },
    "application/vnd.banana-accounting": {
        "source": "iana"
    },
    "application/vnd.bbf.usp.error": {
        "source": "iana"
    },
    "application/vnd.bbf.usp.msg": {
        "source": "iana"
    },
    "application/vnd.bbf.usp.msg+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.bekitzur-stech+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.bint.med-content": {
        "source": "iana"
    },
    "application/vnd.biopax.rdf+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.blink-idb-value-wrapper": {
        "source": "iana"
    },
    "application/vnd.blueice.multipass": {
        "source": "iana",
        "extensions": [
            "mpm"
        ]
    },
    "application/vnd.bluetooth.ep.oob": {
        "source": "iana"
    },
    "application/vnd.bluetooth.le.oob": {
        "source": "iana"
    },
    "application/vnd.bmi": {
        "source": "iana",
        "extensions": [
            "bmi"
        ]
    },
    "application/vnd.bpf": {
        "source": "iana"
    },
    "application/vnd.bpf3": {
        "source": "iana"
    },
    "application/vnd.businessobjects": {
        "source": "iana",
        "extensions": [
            "rep"
        ]
    },
    "application/vnd.byu.uapi+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.cab-jscript": {
        "source": "iana"
    },
    "application/vnd.canon-cpdl": {
        "source": "iana"
    },
    "application/vnd.canon-lips": {
        "source": "iana"
    },
    "application/vnd.capasystems-pg+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.cendio.thinlinc.clientconf": {
        "source": "iana"
    },
    "application/vnd.century-systems.tcp_stream": {
        "source": "iana"
    },
    "application/vnd.chemdraw+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "cdxml"
        ]
    },
    "application/vnd.chess-pgn": {
        "source": "iana"
    },
    "application/vnd.chipnuts.karaoke-mmd": {
        "source": "iana",
        "extensions": [
            "mmd"
        ]
    },
    "application/vnd.ciedi": {
        "source": "iana"
    },
    "application/vnd.cinderella": {
        "source": "iana",
        "extensions": [
            "cdy"
        ]
    },
    "application/vnd.cirpack.isdn-ext": {
        "source": "iana"
    },
    "application/vnd.citationstyles.style+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "csl"
        ]
    },
    "application/vnd.claymore": {
        "source": "iana",
        "extensions": [
            "cla"
        ]
    },
    "application/vnd.cloanto.rp9": {
        "source": "iana",
        "extensions": [
            "rp9"
        ]
    },
    "application/vnd.clonk.c4group": {
        "source": "iana",
        "extensions": [
            "c4g",
            "c4d",
            "c4f",
            "c4p",
            "c4u"
        ]
    },
    "application/vnd.cluetrust.cartomobile-config": {
        "source": "iana",
        "extensions": [
            "c11amc"
        ]
    },
    "application/vnd.cluetrust.cartomobile-config-pkg": {
        "source": "iana",
        "extensions": [
            "c11amz"
        ]
    },
    "application/vnd.coffeescript": {
        "source": "iana"
    },
    "application/vnd.collabio.xodocuments.document": {
        "source": "iana"
    },
    "application/vnd.collabio.xodocuments.document-template": {
        "source": "iana"
    },
    "application/vnd.collabio.xodocuments.presentation": {
        "source": "iana"
    },
    "application/vnd.collabio.xodocuments.presentation-template": {
        "source": "iana"
    },
    "application/vnd.collabio.xodocuments.spreadsheet": {
        "source": "iana"
    },
    "application/vnd.collabio.xodocuments.spreadsheet-template": {
        "source": "iana"
    },
    "application/vnd.collection+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.collection.doc+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.collection.next+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.comicbook+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.comicbook-rar": {
        "source": "iana"
    },
    "application/vnd.commerce-battelle": {
        "source": "iana"
    },
    "application/vnd.commonspace": {
        "source": "iana",
        "extensions": [
            "csp"
        ]
    },
    "application/vnd.contact.cmsg": {
        "source": "iana",
        "extensions": [
            "cdbcmsg"
        ]
    },
    "application/vnd.coreos.ignition+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.cosmocaller": {
        "source": "iana",
        "extensions": [
            "cmc"
        ]
    },
    "application/vnd.crick.clicker": {
        "source": "iana",
        "extensions": [
            "clkx"
        ]
    },
    "application/vnd.crick.clicker.keyboard": {
        "source": "iana",
        "extensions": [
            "clkk"
        ]
    },
    "application/vnd.crick.clicker.palette": {
        "source": "iana",
        "extensions": [
            "clkp"
        ]
    },
    "application/vnd.crick.clicker.template": {
        "source": "iana",
        "extensions": [
            "clkt"
        ]
    },
    "application/vnd.crick.clicker.wordbank": {
        "source": "iana",
        "extensions": [
            "clkw"
        ]
    },
    "application/vnd.criticaltools.wbs+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "wbs"
        ]
    },
    "application/vnd.cryptii.pipe+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.crypto-shade-file": {
        "source": "iana"
    },
    "application/vnd.cryptomator.encrypted": {
        "source": "iana"
    },
    "application/vnd.cryptomator.vault": {
        "source": "iana"
    },
    "application/vnd.ctc-posml": {
        "source": "iana",
        "extensions": [
            "pml"
        ]
    },
    "application/vnd.ctct.ws+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.cups-pdf": {
        "source": "iana"
    },
    "application/vnd.cups-postscript": {
        "source": "iana"
    },
    "application/vnd.cups-ppd": {
        "source": "iana",
        "extensions": [
            "ppd"
        ]
    },
    "application/vnd.cups-raster": {
        "source": "iana"
    },
    "application/vnd.cups-raw": {
        "source": "iana"
    },
    "application/vnd.curl": {
        "source": "iana"
    },
    "application/vnd.curl.car": {
        "source": "apache",
        "extensions": [
            "car"
        ]
    },
    "application/vnd.curl.pcurl": {
        "source": "apache",
        "extensions": [
            "pcurl"
        ]
    },
    "application/vnd.cyan.dean.root+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.cybank": {
        "source": "iana"
    },
    "application/vnd.cyclonedx+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.cyclonedx+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.d2l.coursepackage1p0+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.d3m-dataset": {
        "source": "iana"
    },
    "application/vnd.d3m-problem": {
        "source": "iana"
    },
    "application/vnd.dart": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "dart"
        ]
    },
    "application/vnd.data-vision.rdz": {
        "source": "iana",
        "extensions": [
            "rdz"
        ]
    },
    "application/vnd.datapackage+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dataresource+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dbf": {
        "source": "iana",
        "extensions": [
            "dbf"
        ]
    },
    "application/vnd.debian.binary-package": {
        "source": "iana"
    },
    "application/vnd.dece.data": {
        "source": "iana",
        "extensions": [
            "uvf",
            "uvvf",
            "uvd",
            "uvvd"
        ]
    },
    "application/vnd.dece.ttml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "uvt",
            "uvvt"
        ]
    },
    "application/vnd.dece.unspecified": {
        "source": "iana",
        "extensions": [
            "uvx",
            "uvvx"
        ]
    },
    "application/vnd.dece.zip": {
        "source": "iana",
        "extensions": [
            "uvz",
            "uvvz"
        ]
    },
    "application/vnd.denovo.fcselayout-link": {
        "source": "iana",
        "extensions": [
            "fe_launch"
        ]
    },
    "application/vnd.desmume.movie": {
        "source": "iana"
    },
    "application/vnd.dir-bi.plate-dl-nosuffix": {
        "source": "iana"
    },
    "application/vnd.dm.delegation+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dna": {
        "source": "iana",
        "extensions": [
            "dna"
        ]
    },
    "application/vnd.document+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dolby.mlp": {
        "source": "apache",
        "extensions": [
            "mlp"
        ]
    },
    "application/vnd.dolby.mobile.1": {
        "source": "iana"
    },
    "application/vnd.dolby.mobile.2": {
        "source": "iana"
    },
    "application/vnd.doremir.scorecloud-binary-document": {
        "source": "iana"
    },
    "application/vnd.dpgraph": {
        "source": "iana",
        "extensions": [
            "dpg"
        ]
    },
    "application/vnd.dreamfactory": {
        "source": "iana",
        "extensions": [
            "dfac"
        ]
    },
    "application/vnd.drive+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ds-keypoint": {
        "source": "apache",
        "extensions": [
            "kpxx"
        ]
    },
    "application/vnd.dtg.local": {
        "source": "iana"
    },
    "application/vnd.dtg.local.flash": {
        "source": "iana"
    },
    "application/vnd.dtg.local.html": {
        "source": "iana"
    },
    "application/vnd.dvb.ait": {
        "source": "iana",
        "extensions": [
            "ait"
        ]
    },
    "application/vnd.dvb.dvbisl+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.dvbj": {
        "source": "iana"
    },
    "application/vnd.dvb.esgcontainer": {
        "source": "iana"
    },
    "application/vnd.dvb.ipdcdftnotifaccess": {
        "source": "iana"
    },
    "application/vnd.dvb.ipdcesgaccess": {
        "source": "iana"
    },
    "application/vnd.dvb.ipdcesgaccess2": {
        "source": "iana"
    },
    "application/vnd.dvb.ipdcesgpdd": {
        "source": "iana"
    },
    "application/vnd.dvb.ipdcroaming": {
        "source": "iana"
    },
    "application/vnd.dvb.iptv.alfec-base": {
        "source": "iana"
    },
    "application/vnd.dvb.iptv.alfec-enhancement": {
        "source": "iana"
    },
    "application/vnd.dvb.notif-aggregate-root+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.notif-container+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.notif-generic+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.notif-ia-msglist+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.notif-ia-registration-request+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.notif-ia-registration-response+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.notif-init+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.dvb.pfr": {
        "source": "iana"
    },
    "application/vnd.dvb.service": {
        "source": "iana",
        "extensions": [
            "svc"
        ]
    },
    "application/vnd.dxr": {
        "source": "iana"
    },
    "application/vnd.dynageo": {
        "source": "iana",
        "extensions": [
            "geo"
        ]
    },
    "application/vnd.dzr": {
        "source": "iana"
    },
    "application/vnd.easykaraoke.cdgdownload": {
        "source": "iana"
    },
    "application/vnd.ecdis-update": {
        "source": "iana"
    },
    "application/vnd.ecip.rlp": {
        "source": "iana"
    },
    "application/vnd.eclipse.ditto+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ecowin.chart": {
        "source": "iana",
        "extensions": [
            "mag"
        ]
    },
    "application/vnd.ecowin.filerequest": {
        "source": "iana"
    },
    "application/vnd.ecowin.fileupdate": {
        "source": "iana"
    },
    "application/vnd.ecowin.series": {
        "source": "iana"
    },
    "application/vnd.ecowin.seriesrequest": {
        "source": "iana"
    },
    "application/vnd.ecowin.seriesupdate": {
        "source": "iana"
    },
    "application/vnd.efi.img": {
        "source": "iana"
    },
    "application/vnd.efi.iso": {
        "source": "iana"
    },
    "application/vnd.emclient.accessrequest+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.enliven": {
        "source": "iana",
        "extensions": [
            "nml"
        ]
    },
    "application/vnd.enphase.envoy": {
        "source": "iana"
    },
    "application/vnd.eprints.data+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.epson.esf": {
        "source": "iana",
        "extensions": [
            "esf"
        ]
    },
    "application/vnd.epson.msf": {
        "source": "iana",
        "extensions": [
            "msf"
        ]
    },
    "application/vnd.epson.quickanime": {
        "source": "iana",
        "extensions": [
            "qam"
        ]
    },
    "application/vnd.epson.salt": {
        "source": "iana",
        "extensions": [
            "slt"
        ]
    },
    "application/vnd.epson.ssf": {
        "source": "iana",
        "extensions": [
            "ssf"
        ]
    },
    "application/vnd.ericsson.quickcall": {
        "source": "iana"
    },
    "application/vnd.espass-espass+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.eszigno3+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "es3",
            "et3"
        ]
    },
    "application/vnd.etsi.aoc+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.asic-e+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.etsi.asic-s+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.etsi.cug+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvcommand+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvdiscovery+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvprofile+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvsad-bc+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvsad-cod+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvsad-npvr+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvservice+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvsync+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.iptvueprofile+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.mcid+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.mheg5": {
        "source": "iana"
    },
    "application/vnd.etsi.overload-control-policy-dataset+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.pstn+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.sci+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.simservs+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.timestamp-token": {
        "source": "iana"
    },
    "application/vnd.etsi.tsl+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.etsi.tsl.der": {
        "source": "iana"
    },
    "application/vnd.eu.kasparian.car+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.eudora.data": {
        "source": "iana"
    },
    "application/vnd.evolv.ecig.profile": {
        "source": "iana"
    },
    "application/vnd.evolv.ecig.settings": {
        "source": "iana"
    },
    "application/vnd.evolv.ecig.theme": {
        "source": "iana"
    },
    "application/vnd.exstream-empower+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.exstream-package": {
        "source": "iana"
    },
    "application/vnd.ezpix-album": {
        "source": "iana",
        "extensions": [
            "ez2"
        ]
    },
    "application/vnd.ezpix-package": {
        "source": "iana",
        "extensions": [
            "ez3"
        ]
    },
    "application/vnd.f-secure.mobile": {
        "source": "iana"
    },
    "application/vnd.familysearch.gedcom+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.fastcopy-disk-image": {
        "source": "iana"
    },
    "application/vnd.fdf": {
        "source": "iana",
        "extensions": [
            "fdf"
        ]
    },
    "application/vnd.fdsn.mseed": {
        "source": "iana",
        "extensions": [
            "mseed"
        ]
    },
    "application/vnd.fdsn.seed": {
        "source": "iana",
        "extensions": [
            "seed",
            "dataless"
        ]
    },
    "application/vnd.ffsns": {
        "source": "iana"
    },
    "application/vnd.ficlab.flb+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.filmit.zfc": {
        "source": "iana"
    },
    "application/vnd.fints": {
        "source": "iana"
    },
    "application/vnd.firemonkeys.cloudcell": {
        "source": "iana"
    },
    "application/vnd.flographit": {
        "source": "iana",
        "extensions": [
            "gph"
        ]
    },
    "application/vnd.fluxtime.clip": {
        "source": "iana",
        "extensions": [
            "ftc"
        ]
    },
    "application/vnd.font-fontforge-sfd": {
        "source": "iana"
    },
    "application/vnd.framemaker": {
        "source": "iana",
        "extensions": [
            "fm",
            "frame",
            "maker",
            "book"
        ]
    },
    "application/vnd.frogans.fnc": {
        "source": "iana",
        "extensions": [
            "fnc"
        ]
    },
    "application/vnd.frogans.ltf": {
        "source": "iana",
        "extensions": [
            "ltf"
        ]
    },
    "application/vnd.fsc.weblaunch": {
        "source": "iana",
        "extensions": [
            "fsc"
        ]
    },
    "application/vnd.fujifilm.fb.docuworks": {
        "source": "iana"
    },
    "application/vnd.fujifilm.fb.docuworks.binder": {
        "source": "iana"
    },
    "application/vnd.fujifilm.fb.docuworks.container": {
        "source": "iana"
    },
    "application/vnd.fujifilm.fb.jfi+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.fujitsu.oasys": {
        "source": "iana",
        "extensions": [
            "oas"
        ]
    },
    "application/vnd.fujitsu.oasys2": {
        "source": "iana",
        "extensions": [
            "oa2"
        ]
    },
    "application/vnd.fujitsu.oasys3": {
        "source": "iana",
        "extensions": [
            "oa3"
        ]
    },
    "application/vnd.fujitsu.oasysgp": {
        "source": "iana",
        "extensions": [
            "fg5"
        ]
    },
    "application/vnd.fujitsu.oasysprs": {
        "source": "iana",
        "extensions": [
            "bh2"
        ]
    },
    "application/vnd.fujixerox.art-ex": {
        "source": "iana"
    },
    "application/vnd.fujixerox.art4": {
        "source": "iana"
    },
    "application/vnd.fujixerox.ddd": {
        "source": "iana",
        "extensions": [
            "ddd"
        ]
    },
    "application/vnd.fujixerox.docuworks": {
        "source": "iana",
        "extensions": [
            "xdw"
        ]
    },
    "application/vnd.fujixerox.docuworks.binder": {
        "source": "iana",
        "extensions": [
            "xbd"
        ]
    },
    "application/vnd.fujixerox.docuworks.container": {
        "source": "iana"
    },
    "application/vnd.fujixerox.hbpl": {
        "source": "iana"
    },
    "application/vnd.fut-misnet": {
        "source": "iana"
    },
    "application/vnd.futoin+cbor": {
        "source": "iana"
    },
    "application/vnd.futoin+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.fuzzysheet": {
        "source": "iana",
        "extensions": [
            "fzs"
        ]
    },
    "application/vnd.genomatix.tuxedo": {
        "source": "iana",
        "extensions": [
            "txd"
        ]
    },
    "application/vnd.gentics.grd+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.geo+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.geocube+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.geogebra.file": {
        "source": "iana",
        "extensions": [
            "ggb"
        ]
    },
    "application/vnd.geogebra.slides": {
        "source": "iana"
    },
    "application/vnd.geogebra.tool": {
        "source": "iana",
        "extensions": [
            "ggt"
        ]
    },
    "application/vnd.geometry-explorer": {
        "source": "iana",
        "extensions": [
            "gex",
            "gre"
        ]
    },
    "application/vnd.geonext": {
        "source": "iana",
        "extensions": [
            "gxt"
        ]
    },
    "application/vnd.geoplan": {
        "source": "iana",
        "extensions": [
            "g2w"
        ]
    },
    "application/vnd.geospace": {
        "source": "iana",
        "extensions": [
            "g3w"
        ]
    },
    "application/vnd.gerber": {
        "source": "iana"
    },
    "application/vnd.globalplatform.card-content-mgt": {
        "source": "iana"
    },
    "application/vnd.globalplatform.card-content-mgt-response": {
        "source": "iana"
    },
    "application/vnd.gmx": {
        "source": "iana",
        "extensions": [
            "gmx"
        ]
    },
    "application/vnd.google-apps.document": {
        "compressible": false,
        "extensions": [
            "gdoc"
        ]
    },
    "application/vnd.google-apps.presentation": {
        "compressible": false,
        "extensions": [
            "gslides"
        ]
    },
    "application/vnd.google-apps.spreadsheet": {
        "compressible": false,
        "extensions": [
            "gsheet"
        ]
    },
    "application/vnd.google-earth.kml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "kml"
        ]
    },
    "application/vnd.google-earth.kmz": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "kmz"
        ]
    },
    "application/vnd.gov.sk.e-form+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.gov.sk.e-form+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.gov.sk.xmldatacontainer+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.grafeq": {
        "source": "iana",
        "extensions": [
            "gqf",
            "gqs"
        ]
    },
    "application/vnd.gridmp": {
        "source": "iana"
    },
    "application/vnd.groove-account": {
        "source": "iana",
        "extensions": [
            "gac"
        ]
    },
    "application/vnd.groove-help": {
        "source": "iana",
        "extensions": [
            "ghf"
        ]
    },
    "application/vnd.groove-identity-message": {
        "source": "iana",
        "extensions": [
            "gim"
        ]
    },
    "application/vnd.groove-injector": {
        "source": "iana",
        "extensions": [
            "grv"
        ]
    },
    "application/vnd.groove-tool-message": {
        "source": "iana",
        "extensions": [
            "gtm"
        ]
    },
    "application/vnd.groove-tool-template": {
        "source": "iana",
        "extensions": [
            "tpl"
        ]
    },
    "application/vnd.groove-vcard": {
        "source": "iana",
        "extensions": [
            "vcg"
        ]
    },
    "application/vnd.hal+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.hal+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "hal"
        ]
    },
    "application/vnd.handheld-entertainment+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "zmm"
        ]
    },
    "application/vnd.hbci": {
        "source": "iana",
        "extensions": [
            "hbci"
        ]
    },
    "application/vnd.hc+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.hcl-bireports": {
        "source": "iana"
    },
    "application/vnd.hdt": {
        "source": "iana"
    },
    "application/vnd.heroku+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.hhe.lesson-player": {
        "source": "iana",
        "extensions": [
            "les"
        ]
    },
    "application/vnd.hl7cda+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/vnd.hl7v2+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/vnd.hp-hpgl": {
        "source": "iana",
        "extensions": [
            "hpgl"
        ]
    },
    "application/vnd.hp-hpid": {
        "source": "iana",
        "extensions": [
            "hpid"
        ]
    },
    "application/vnd.hp-hps": {
        "source": "iana",
        "extensions": [
            "hps"
        ]
    },
    "application/vnd.hp-jlyt": {
        "source": "iana",
        "extensions": [
            "jlt"
        ]
    },
    "application/vnd.hp-pcl": {
        "source": "iana",
        "extensions": [
            "pcl"
        ]
    },
    "application/vnd.hp-pclxl": {
        "source": "iana",
        "extensions": [
            "pclxl"
        ]
    },
    "application/vnd.httphone": {
        "source": "iana"
    },
    "application/vnd.hydrostatix.sof-data": {
        "source": "iana",
        "extensions": [
            "sfd-hdstx"
        ]
    },
    "application/vnd.hyper+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.hyper-item+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.hyperdrive+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.hzn-3d-crossword": {
        "source": "iana"
    },
    "application/vnd.ibm.afplinedata": {
        "source": "iana"
    },
    "application/vnd.ibm.electronic-media": {
        "source": "iana"
    },
    "application/vnd.ibm.minipay": {
        "source": "iana",
        "extensions": [
            "mpy"
        ]
    },
    "application/vnd.ibm.modcap": {
        "source": "iana",
        "extensions": [
            "afp",
            "listafp",
            "list3820"
        ]
    },
    "application/vnd.ibm.rights-management": {
        "source": "iana",
        "extensions": [
            "irm"
        ]
    },
    "application/vnd.ibm.secure-container": {
        "source": "iana",
        "extensions": [
            "sc"
        ]
    },
    "application/vnd.iccprofile": {
        "source": "iana",
        "extensions": [
            "icc",
            "icm"
        ]
    },
    "application/vnd.ieee.1905": {
        "source": "iana"
    },
    "application/vnd.igloader": {
        "source": "iana",
        "extensions": [
            "igl"
        ]
    },
    "application/vnd.imagemeter.folder+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.imagemeter.image+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.immervision-ivp": {
        "source": "iana",
        "extensions": [
            "ivp"
        ]
    },
    "application/vnd.immervision-ivu": {
        "source": "iana",
        "extensions": [
            "ivu"
        ]
    },
    "application/vnd.ims.imsccv1p1": {
        "source": "iana"
    },
    "application/vnd.ims.imsccv1p2": {
        "source": "iana"
    },
    "application/vnd.ims.imsccv1p3": {
        "source": "iana"
    },
    "application/vnd.ims.lis.v2.result+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ims.lti.v2.toolconsumerprofile+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ims.lti.v2.toolproxy+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ims.lti.v2.toolproxy.id+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ims.lti.v2.toolsettings+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ims.lti.v2.toolsettings.simple+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.informedcontrol.rms+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.informix-visionary": {
        "source": "iana"
    },
    "application/vnd.infotech.project": {
        "source": "iana"
    },
    "application/vnd.infotech.project+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.innopath.wamp.notification": {
        "source": "iana"
    },
    "application/vnd.insors.igm": {
        "source": "iana",
        "extensions": [
            "igm"
        ]
    },
    "application/vnd.intercon.formnet": {
        "source": "iana",
        "extensions": [
            "xpw",
            "xpx"
        ]
    },
    "application/vnd.intergeo": {
        "source": "iana",
        "extensions": [
            "i2g"
        ]
    },
    "application/vnd.intertrust.digibox": {
        "source": "iana"
    },
    "application/vnd.intertrust.nncp": {
        "source": "iana"
    },
    "application/vnd.intu.qbo": {
        "source": "iana",
        "extensions": [
            "qbo"
        ]
    },
    "application/vnd.intu.qfx": {
        "source": "iana",
        "extensions": [
            "qfx"
        ]
    },
    "application/vnd.iptc.g2.catalogitem+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.iptc.g2.conceptitem+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.iptc.g2.knowledgeitem+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.iptc.g2.newsitem+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.iptc.g2.newsmessage+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.iptc.g2.packageitem+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.iptc.g2.planningitem+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ipunplugged.rcprofile": {
        "source": "iana",
        "extensions": [
            "rcprofile"
        ]
    },
    "application/vnd.irepository.package+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "irp"
        ]
    },
    "application/vnd.is-xpr": {
        "source": "iana",
        "extensions": [
            "xpr"
        ]
    },
    "application/vnd.isac.fcs": {
        "source": "iana",
        "extensions": [
            "fcs"
        ]
    },
    "application/vnd.iso11783-10+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.jam": {
        "source": "iana",
        "extensions": [
            "jam"
        ]
    },
    "application/vnd.japannet-directory-service": {
        "source": "iana"
    },
    "application/vnd.japannet-jpnstore-wakeup": {
        "source": "iana"
    },
    "application/vnd.japannet-payment-wakeup": {
        "source": "iana"
    },
    "application/vnd.japannet-registration": {
        "source": "iana"
    },
    "application/vnd.japannet-registration-wakeup": {
        "source": "iana"
    },
    "application/vnd.japannet-setstore-wakeup": {
        "source": "iana"
    },
    "application/vnd.japannet-verification": {
        "source": "iana"
    },
    "application/vnd.japannet-verification-wakeup": {
        "source": "iana"
    },
    "application/vnd.jcp.javame.midlet-rms": {
        "source": "iana",
        "extensions": [
            "rms"
        ]
    },
    "application/vnd.jisp": {
        "source": "iana",
        "extensions": [
            "jisp"
        ]
    },
    "application/vnd.joost.joda-archive": {
        "source": "iana",
        "extensions": [
            "joda"
        ]
    },
    "application/vnd.jsk.isdn-ngn": {
        "source": "iana"
    },
    "application/vnd.kahootz": {
        "source": "iana",
        "extensions": [
            "ktz",
            "ktr"
        ]
    },
    "application/vnd.kde.karbon": {
        "source": "iana",
        "extensions": [
            "karbon"
        ]
    },
    "application/vnd.kde.kchart": {
        "source": "iana",
        "extensions": [
            "chrt"
        ]
    },
    "application/vnd.kde.kformula": {
        "source": "iana",
        "extensions": [
            "kfo"
        ]
    },
    "application/vnd.kde.kivio": {
        "source": "iana",
        "extensions": [
            "flw"
        ]
    },
    "application/vnd.kde.kontour": {
        "source": "iana",
        "extensions": [
            "kon"
        ]
    },
    "application/vnd.kde.kpresenter": {
        "source": "iana",
        "extensions": [
            "kpr",
            "kpt"
        ]
    },
    "application/vnd.kde.kspread": {
        "source": "iana",
        "extensions": [
            "ksp"
        ]
    },
    "application/vnd.kde.kword": {
        "source": "iana",
        "extensions": [
            "kwd",
            "kwt"
        ]
    },
    "application/vnd.kenameaapp": {
        "source": "iana",
        "extensions": [
            "htke"
        ]
    },
    "application/vnd.kidspiration": {
        "source": "iana",
        "extensions": [
            "kia"
        ]
    },
    "application/vnd.kinar": {
        "source": "iana",
        "extensions": [
            "kne",
            "knp"
        ]
    },
    "application/vnd.koan": {
        "source": "iana",
        "extensions": [
            "skp",
            "skd",
            "skt",
            "skm"
        ]
    },
    "application/vnd.kodak-descriptor": {
        "source": "iana",
        "extensions": [
            "sse"
        ]
    },
    "application/vnd.las": {
        "source": "iana"
    },
    "application/vnd.las.las+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.las.las+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "lasxml"
        ]
    },
    "application/vnd.laszip": {
        "source": "iana"
    },
    "application/vnd.leap+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.liberty-request+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.llamagraphics.life-balance.desktop": {
        "source": "iana",
        "extensions": [
            "lbd"
        ]
    },
    "application/vnd.llamagraphics.life-balance.exchange+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "lbe"
        ]
    },
    "application/vnd.logipipe.circuit+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.loom": {
        "source": "iana"
    },
    "application/vnd.lotus-1-2-3": {
        "source": "iana",
        "extensions": [
            "123"
        ]
    },
    "application/vnd.lotus-approach": {
        "source": "iana",
        "extensions": [
            "apr"
        ]
    },
    "application/vnd.lotus-freelance": {
        "source": "iana",
        "extensions": [
            "pre"
        ]
    },
    "application/vnd.lotus-notes": {
        "source": "iana",
        "extensions": [
            "nsf"
        ]
    },
    "application/vnd.lotus-organizer": {
        "source": "iana",
        "extensions": [
            "org"
        ]
    },
    "application/vnd.lotus-screencam": {
        "source": "iana",
        "extensions": [
            "scm"
        ]
    },
    "application/vnd.lotus-wordpro": {
        "source": "iana",
        "extensions": [
            "lwp"
        ]
    },
    "application/vnd.macports.portpkg": {
        "source": "iana",
        "extensions": [
            "portpkg"
        ]
    },
    "application/vnd.mapbox-vector-tile": {
        "source": "iana",
        "extensions": [
            "mvt"
        ]
    },
    "application/vnd.marlin.drm.actiontoken+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.marlin.drm.conftoken+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.marlin.drm.license+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.marlin.drm.mdcf": {
        "source": "iana"
    },
    "application/vnd.mason+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.maxar.archive.3tz+zip": {
        "source": "iana",
        "compressible": false
    },
    "application/vnd.maxmind.maxmind-db": {
        "source": "iana"
    },
    "application/vnd.mcd": {
        "source": "iana",
        "extensions": [
            "mcd"
        ]
    },
    "application/vnd.medcalcdata": {
        "source": "iana",
        "extensions": [
            "mc1"
        ]
    },
    "application/vnd.mediastation.cdkey": {
        "source": "iana",
        "extensions": [
            "cdkey"
        ]
    },
    "application/vnd.meridian-slingshot": {
        "source": "iana"
    },
    "application/vnd.mfer": {
        "source": "iana",
        "extensions": [
            "mwf"
        ]
    },
    "application/vnd.mfmp": {
        "source": "iana",
        "extensions": [
            "mfm"
        ]
    },
    "application/vnd.micro+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.micrografx.flo": {
        "source": "iana",
        "extensions": [
            "flo"
        ]
    },
    "application/vnd.micrografx.igx": {
        "source": "iana",
        "extensions": [
            "igx"
        ]
    },
    "application/vnd.microsoft.portable-executable": {
        "source": "iana"
    },
    "application/vnd.microsoft.windows.thumbnail-cache": {
        "source": "iana"
    },
    "application/vnd.miele+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.mif": {
        "source": "iana",
        "extensions": [
            "mif"
        ]
    },
    "application/vnd.minisoft-hp3000-save": {
        "source": "iana"
    },
    "application/vnd.mitsubishi.misty-guard.trustweb": {
        "source": "iana"
    },
    "application/vnd.mobius.daf": {
        "source": "iana",
        "extensions": [
            "daf"
        ]
    },
    "application/vnd.mobius.dis": {
        "source": "iana",
        "extensions": [
            "dis"
        ]
    },
    "application/vnd.mobius.mbk": {
        "source": "iana",
        "extensions": [
            "mbk"
        ]
    },
    "application/vnd.mobius.mqy": {
        "source": "iana",
        "extensions": [
            "mqy"
        ]
    },
    "application/vnd.mobius.msl": {
        "source": "iana",
        "extensions": [
            "msl"
        ]
    },
    "application/vnd.mobius.plc": {
        "source": "iana",
        "extensions": [
            "plc"
        ]
    },
    "application/vnd.mobius.txf": {
        "source": "iana",
        "extensions": [
            "txf"
        ]
    },
    "application/vnd.mophun.application": {
        "source": "iana",
        "extensions": [
            "mpn"
        ]
    },
    "application/vnd.mophun.certificate": {
        "source": "iana",
        "extensions": [
            "mpc"
        ]
    },
    "application/vnd.motorola.flexsuite": {
        "source": "iana"
    },
    "application/vnd.motorola.flexsuite.adsi": {
        "source": "iana"
    },
    "application/vnd.motorola.flexsuite.fis": {
        "source": "iana"
    },
    "application/vnd.motorola.flexsuite.gotap": {
        "source": "iana"
    },
    "application/vnd.motorola.flexsuite.kmr": {
        "source": "iana"
    },
    "application/vnd.motorola.flexsuite.ttc": {
        "source": "iana"
    },
    "application/vnd.motorola.flexsuite.wem": {
        "source": "iana"
    },
    "application/vnd.motorola.iprm": {
        "source": "iana"
    },
    "application/vnd.mozilla.xul+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xul"
        ]
    },
    "application/vnd.ms-3mfdocument": {
        "source": "iana"
    },
    "application/vnd.ms-artgalry": {
        "source": "iana",
        "extensions": [
            "cil"
        ]
    },
    "application/vnd.ms-asf": {
        "source": "iana"
    },
    "application/vnd.ms-cab-compressed": {
        "source": "iana",
        "extensions": [
            "cab"
        ]
    },
    "application/vnd.ms-color.iccprofile": {
        "source": "apache"
    },
    "application/vnd.ms-excel": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "xls",
            "xlm",
            "xla",
            "xlc",
            "xlt",
            "xlw"
        ]
    },
    "application/vnd.ms-excel.addin.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "xlam"
        ]
    },
    "application/vnd.ms-excel.sheet.binary.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "xlsb"
        ]
    },
    "application/vnd.ms-excel.sheet.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "xlsm"
        ]
    },
    "application/vnd.ms-excel.template.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "xltm"
        ]
    },
    "application/vnd.ms-fontobject": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "eot"
        ]
    },
    "application/vnd.ms-htmlhelp": {
        "source": "iana",
        "extensions": [
            "chm"
        ]
    },
    "application/vnd.ms-ims": {
        "source": "iana",
        "extensions": [
            "ims"
        ]
    },
    "application/vnd.ms-lrm": {
        "source": "iana",
        "extensions": [
            "lrm"
        ]
    },
    "application/vnd.ms-office.activex+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ms-officetheme": {
        "source": "iana",
        "extensions": [
            "thmx"
        ]
    },
    "application/vnd.ms-opentype": {
        "source": "apache",
        "compressible": true
    },
    "application/vnd.ms-outlook": {
        "compressible": false,
        "extensions": [
            "msg"
        ]
    },
    "application/vnd.ms-package.obfuscated-opentype": {
        "source": "apache"
    },
    "application/vnd.ms-pki.seccat": {
        "source": "apache",
        "extensions": [
            "cat"
        ]
    },
    "application/vnd.ms-pki.stl": {
        "source": "apache",
        "extensions": [
            "stl"
        ]
    },
    "application/vnd.ms-playready.initiator+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ms-powerpoint": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "ppt",
            "pps",
            "pot"
        ]
    },
    "application/vnd.ms-powerpoint.addin.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "ppam"
        ]
    },
    "application/vnd.ms-powerpoint.presentation.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "pptm"
        ]
    },
    "application/vnd.ms-powerpoint.slide.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "sldm"
        ]
    },
    "application/vnd.ms-powerpoint.slideshow.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "ppsm"
        ]
    },
    "application/vnd.ms-powerpoint.template.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "potm"
        ]
    },
    "application/vnd.ms-printdevicecapabilities+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ms-printing.printticket+xml": {
        "source": "apache",
        "compressible": true
    },
    "application/vnd.ms-printschematicket+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ms-project": {
        "source": "iana",
        "extensions": [
            "mpp",
            "mpt"
        ]
    },
    "application/vnd.ms-tnef": {
        "source": "iana"
    },
    "application/vnd.ms-windows.devicepairing": {
        "source": "iana"
    },
    "application/vnd.ms-windows.nwprinting.oob": {
        "source": "iana"
    },
    "application/vnd.ms-windows.printerpairing": {
        "source": "iana"
    },
    "application/vnd.ms-windows.wsd.oob": {
        "source": "iana"
    },
    "application/vnd.ms-wmdrm.lic-chlg-req": {
        "source": "iana"
    },
    "application/vnd.ms-wmdrm.lic-resp": {
        "source": "iana"
    },
    "application/vnd.ms-wmdrm.meter-chlg-req": {
        "source": "iana"
    },
    "application/vnd.ms-wmdrm.meter-resp": {
        "source": "iana"
    },
    "application/vnd.ms-word.document.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "docm"
        ]
    },
    "application/vnd.ms-word.template.macroenabled.12": {
        "source": "iana",
        "extensions": [
            "dotm"
        ]
    },
    "application/vnd.ms-works": {
        "source": "iana",
        "extensions": [
            "wps",
            "wks",
            "wcm",
            "wdb"
        ]
    },
    "application/vnd.ms-wpl": {
        "source": "iana",
        "extensions": [
            "wpl"
        ]
    },
    "application/vnd.ms-xpsdocument": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "xps"
        ]
    },
    "application/vnd.msa-disk-image": {
        "source": "iana"
    },
    "application/vnd.mseq": {
        "source": "iana",
        "extensions": [
            "mseq"
        ]
    },
    "application/vnd.msign": {
        "source": "iana"
    },
    "application/vnd.multiad.creator": {
        "source": "iana"
    },
    "application/vnd.multiad.creator.cif": {
        "source": "iana"
    },
    "application/vnd.music-niff": {
        "source": "iana"
    },
    "application/vnd.musician": {
        "source": "iana",
        "extensions": [
            "mus"
        ]
    },
    "application/vnd.muvee.style": {
        "source": "iana",
        "extensions": [
            "msty"
        ]
    },
    "application/vnd.mynfc": {
        "source": "iana",
        "extensions": [
            "taglet"
        ]
    },
    "application/vnd.nacamar.ybrid+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.ncd.control": {
        "source": "iana"
    },
    "application/vnd.ncd.reference": {
        "source": "iana"
    },
    "application/vnd.nearst.inv+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.nebumind.line": {
        "source": "iana"
    },
    "application/vnd.nervana": {
        "source": "iana"
    },
    "application/vnd.netfpx": {
        "source": "iana"
    },
    "application/vnd.neurolanguage.nlu": {
        "source": "iana",
        "extensions": [
            "nlu"
        ]
    },
    "application/vnd.nimn": {
        "source": "iana"
    },
    "application/vnd.nintendo.nitro.rom": {
        "source": "iana"
    },
    "application/vnd.nintendo.snes.rom": {
        "source": "iana"
    },
    "application/vnd.nitf": {
        "source": "iana",
        "extensions": [
            "ntf",
            "nitf"
        ]
    },
    "application/vnd.noblenet-directory": {
        "source": "iana",
        "extensions": [
            "nnd"
        ]
    },
    "application/vnd.noblenet-sealer": {
        "source": "iana",
        "extensions": [
            "nns"
        ]
    },
    "application/vnd.noblenet-web": {
        "source": "iana",
        "extensions": [
            "nnw"
        ]
    },
    "application/vnd.nokia.catalogs": {
        "source": "iana"
    },
    "application/vnd.nokia.conml+wbxml": {
        "source": "iana"
    },
    "application/vnd.nokia.conml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.nokia.iptv.config+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.nokia.isds-radio-presets": {
        "source": "iana"
    },
    "application/vnd.nokia.landmark+wbxml": {
        "source": "iana"
    },
    "application/vnd.nokia.landmark+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.nokia.landmarkcollection+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.nokia.n-gage.ac+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ac"
        ]
    },
    "application/vnd.nokia.n-gage.data": {
        "source": "iana",
        "extensions": [
            "ngdat"
        ]
    },
    "application/vnd.nokia.n-gage.symbian.install": {
        "source": "iana",
        "extensions": [
            "n-gage"
        ]
    },
    "application/vnd.nokia.ncd": {
        "source": "iana"
    },
    "application/vnd.nokia.pcd+wbxml": {
        "source": "iana"
    },
    "application/vnd.nokia.pcd+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.nokia.radio-preset": {
        "source": "iana",
        "extensions": [
            "rpst"
        ]
    },
    "application/vnd.nokia.radio-presets": {
        "source": "iana",
        "extensions": [
            "rpss"
        ]
    },
    "application/vnd.novadigm.edm": {
        "source": "iana",
        "extensions": [
            "edm"
        ]
    },
    "application/vnd.novadigm.edx": {
        "source": "iana",
        "extensions": [
            "edx"
        ]
    },
    "application/vnd.novadigm.ext": {
        "source": "iana",
        "extensions": [
            "ext"
        ]
    },
    "application/vnd.ntt-local.content-share": {
        "source": "iana"
    },
    "application/vnd.ntt-local.file-transfer": {
        "source": "iana"
    },
    "application/vnd.ntt-local.ogw_remote-access": {
        "source": "iana"
    },
    "application/vnd.ntt-local.sip-ta_remote": {
        "source": "iana"
    },
    "application/vnd.ntt-local.sip-ta_tcp_stream": {
        "source": "iana"
    },
    "application/vnd.oasis.opendocument.chart": {
        "source": "iana",
        "extensions": [
            "odc"
        ]
    },
    "application/vnd.oasis.opendocument.chart-template": {
        "source": "iana",
        "extensions": [
            "otc"
        ]
    },
    "application/vnd.oasis.opendocument.database": {
        "source": "iana",
        "extensions": [
            "odb"
        ]
    },
    "application/vnd.oasis.opendocument.formula": {
        "source": "iana",
        "extensions": [
            "odf"
        ]
    },
    "application/vnd.oasis.opendocument.formula-template": {
        "source": "iana",
        "extensions": [
            "odft"
        ]
    },
    "application/vnd.oasis.opendocument.graphics": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "odg"
        ]
    },
    "application/vnd.oasis.opendocument.graphics-template": {
        "source": "iana",
        "extensions": [
            "otg"
        ]
    },
    "application/vnd.oasis.opendocument.image": {
        "source": "iana",
        "extensions": [
            "odi"
        ]
    },
    "application/vnd.oasis.opendocument.image-template": {
        "source": "iana",
        "extensions": [
            "oti"
        ]
    },
    "application/vnd.oasis.opendocument.presentation": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "odp"
        ]
    },
    "application/vnd.oasis.opendocument.presentation-template": {
        "source": "iana",
        "extensions": [
            "otp"
        ]
    },
    "application/vnd.oasis.opendocument.spreadsheet": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "ods"
        ]
    },
    "application/vnd.oasis.opendocument.spreadsheet-template": {
        "source": "iana",
        "extensions": [
            "ots"
        ]
    },
    "application/vnd.oasis.opendocument.text": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "odt"
        ]
    },
    "application/vnd.oasis.opendocument.text-master": {
        "source": "iana",
        "extensions": [
            "odm"
        ]
    },
    "application/vnd.oasis.opendocument.text-template": {
        "source": "iana",
        "extensions": [
            "ott"
        ]
    },
    "application/vnd.oasis.opendocument.text-web": {
        "source": "iana",
        "extensions": [
            "oth"
        ]
    },
    "application/vnd.obn": {
        "source": "iana"
    },
    "application/vnd.ocf+cbor": {
        "source": "iana"
    },
    "application/vnd.oci.image.manifest.v1+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oftn.l10n+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.contentaccessdownload+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.contentaccessstreaming+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.cspg-hexbinary": {
        "source": "iana"
    },
    "application/vnd.oipf.dae.svg+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.dae.xhtml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.mippvcontrolmessage+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.pae.gem": {
        "source": "iana"
    },
    "application/vnd.oipf.spdiscovery+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.spdlist+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.ueprofile+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oipf.userprofile+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.olpc-sugar": {
        "source": "iana",
        "extensions": [
            "xo"
        ]
    },
    "application/vnd.oma-scws-config": {
        "source": "iana"
    },
    "application/vnd.oma-scws-http-request": {
        "source": "iana"
    },
    "application/vnd.oma-scws-http-response": {
        "source": "iana"
    },
    "application/vnd.oma.bcast.associated-procedure-parameter+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.bcast.drm-trigger+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.bcast.imd+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.bcast.ltkm": {
        "source": "iana"
    },
    "application/vnd.oma.bcast.notification+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.bcast.provisioningtrigger": {
        "source": "iana"
    },
    "application/vnd.oma.bcast.sgboot": {
        "source": "iana"
    },
    "application/vnd.oma.bcast.sgdd+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.bcast.sgdu": {
        "source": "iana"
    },
    "application/vnd.oma.bcast.simple-symbol-container": {
        "source": "iana"
    },
    "application/vnd.oma.bcast.smartcard-trigger+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.bcast.sprov+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.bcast.stkm": {
        "source": "iana"
    },
    "application/vnd.oma.cab-address-book+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.cab-feature-handler+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.cab-pcc+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.cab-subs-invite+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.cab-user-prefs+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.dcd": {
        "source": "iana"
    },
    "application/vnd.oma.dcdc": {
        "source": "iana"
    },
    "application/vnd.oma.dd2+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "dd2"
        ]
    },
    "application/vnd.oma.drm.risd+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.group-usage-list+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.lwm2m+cbor": {
        "source": "iana"
    },
    "application/vnd.oma.lwm2m+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.lwm2m+tlv": {
        "source": "iana"
    },
    "application/vnd.oma.pal+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.poc.detailed-progress-report+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.poc.final-report+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.poc.groups+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.poc.invocation-descriptor+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.poc.optimized-progress-report+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.push": {
        "source": "iana"
    },
    "application/vnd.oma.scidm.messages+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oma.xcap-directory+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.omads-email+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/vnd.omads-file+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/vnd.omads-folder+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/vnd.omaloc-supl-init": {
        "source": "iana"
    },
    "application/vnd.onepager": {
        "source": "iana"
    },
    "application/vnd.onepagertamp": {
        "source": "iana"
    },
    "application/vnd.onepagertamx": {
        "source": "iana"
    },
    "application/vnd.onepagertat": {
        "source": "iana"
    },
    "application/vnd.onepagertatp": {
        "source": "iana"
    },
    "application/vnd.onepagertatx": {
        "source": "iana"
    },
    "application/vnd.openblox.game+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "obgx"
        ]
    },
    "application/vnd.openblox.game-binary": {
        "source": "iana"
    },
    "application/vnd.openeye.oeb": {
        "source": "iana"
    },
    "application/vnd.openofficeorg.extension": {
        "source": "apache",
        "extensions": [
            "oxt"
        ]
    },
    "application/vnd.openstreetmap.data+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "osm"
        ]
    },
    "application/vnd.opentimestamps.ots": {
        "source": "iana"
    },
    "application/vnd.openxmlformats-officedocument.custom-properties+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.customxmlproperties+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.drawing+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.drawingml.chart+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.drawingml.chartshapes+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.drawingml.diagramcolors+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.drawingml.diagramdata+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.drawingml.diagramlayout+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.drawingml.diagramstyle+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.extended-properties+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.commentauthors+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.comments+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.handoutmaster+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.notesmaster+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.notesslide+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "pptx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.presprops+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slide": {
        "source": "iana",
        "extensions": [
            "sldx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slide+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slidelayout+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slidemaster+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow": {
        "source": "iana",
        "extensions": [
            "ppsx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slideupdateinfo+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.tablestyles+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.tags+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.template": {
        "source": "iana",
        "extensions": [
            "potx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.presentationml.viewprops+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.calcchain+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.chartsheet+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.connections+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.dialogsheet+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.externallink+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotcachedefinition+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotcacherecords+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.pivottable+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.querytable+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.revisionheaders+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.revisionlog+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedstrings+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "xlsx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheetmetadata+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.tablesinglecells+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template": {
        "source": "iana",
        "extensions": [
            "xltx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.usernames+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.volatiledependencies+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.theme+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.themeoverride+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.vmldrawing": {
        "source": "iana"
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "docx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.glossary+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.fonttable+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template": {
        "source": "iana",
        "extensions": [
            "dotx"
        ]
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.websettings+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-package.core-properties+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.openxmlformats-package.relationships+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oracle.resource+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.orange.indata": {
        "source": "iana"
    },
    "application/vnd.osa.netdeploy": {
        "source": "iana"
    },
    "application/vnd.osgeo.mapguide.package": {
        "source": "iana",
        "extensions": [
            "mgp"
        ]
    },
    "application/vnd.osgi.bundle": {
        "source": "iana"
    },
    "application/vnd.osgi.dp": {
        "source": "iana",
        "extensions": [
            "dp"
        ]
    },
    "application/vnd.osgi.subsystem": {
        "source": "iana",
        "extensions": [
            "esa"
        ]
    },
    "application/vnd.otps.ct-kip+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.oxli.countgraph": {
        "source": "iana"
    },
    "application/vnd.pagerduty+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.palm": {
        "source": "iana",
        "extensions": [
            "pdb",
            "pqa",
            "oprc"
        ]
    },
    "application/vnd.panoply": {
        "source": "iana"
    },
    "application/vnd.paos.xml": {
        "source": "iana"
    },
    "application/vnd.patentdive": {
        "source": "iana"
    },
    "application/vnd.patientecommsdoc": {
        "source": "iana"
    },
    "application/vnd.pawaafile": {
        "source": "iana",
        "extensions": [
            "paw"
        ]
    },
    "application/vnd.pcos": {
        "source": "iana"
    },
    "application/vnd.pg.format": {
        "source": "iana",
        "extensions": [
            "str"
        ]
    },
    "application/vnd.pg.osasli": {
        "source": "iana",
        "extensions": [
            "ei6"
        ]
    },
    "application/vnd.piaccess.application-licence": {
        "source": "iana"
    },
    "application/vnd.picsel": {
        "source": "iana",
        "extensions": [
            "efif"
        ]
    },
    "application/vnd.pmi.widget": {
        "source": "iana",
        "extensions": [
            "wg"
        ]
    },
    "application/vnd.poc.group-advertisement+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.pocketlearn": {
        "source": "iana",
        "extensions": [
            "plf"
        ]
    },
    "application/vnd.powerbuilder6": {
        "source": "iana",
        "extensions": [
            "pbd"
        ]
    },
    "application/vnd.powerbuilder6-s": {
        "source": "iana"
    },
    "application/vnd.powerbuilder7": {
        "source": "iana"
    },
    "application/vnd.powerbuilder7-s": {
        "source": "iana"
    },
    "application/vnd.powerbuilder75": {
        "source": "iana"
    },
    "application/vnd.powerbuilder75-s": {
        "source": "iana"
    },
    "application/vnd.preminet": {
        "source": "iana"
    },
    "application/vnd.previewsystems.box": {
        "source": "iana",
        "extensions": [
            "box"
        ]
    },
    "application/vnd.proteus.magazine": {
        "source": "iana",
        "extensions": [
            "mgz"
        ]
    },
    "application/vnd.psfs": {
        "source": "iana"
    },
    "application/vnd.publishare-delta-tree": {
        "source": "iana",
        "extensions": [
            "qps"
        ]
    },
    "application/vnd.pvi.ptid1": {
        "source": "iana",
        "extensions": [
            "ptid"
        ]
    },
    "application/vnd.pwg-multiplexed": {
        "source": "iana"
    },
    "application/vnd.pwg-xhtml-print+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.qualcomm.brew-app-res": {
        "source": "iana"
    },
    "application/vnd.quarantainenet": {
        "source": "iana"
    },
    "application/vnd.quark.quarkxpress": {
        "source": "iana",
        "extensions": [
            "qxd",
            "qxt",
            "qwd",
            "qwt",
            "qxl",
            "qxb"
        ]
    },
    "application/vnd.quobject-quoxdocument": {
        "source": "iana"
    },
    "application/vnd.radisys.moml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-audit+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-audit-conf+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-audit-conn+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-audit-dialog+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-audit-stream+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-conf+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-dialog+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-dialog-base+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-dialog-fax-detect+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-dialog-fax-sendrecv+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-dialog-group+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-dialog-speech+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.radisys.msml-dialog-transform+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.rainstor.data": {
        "source": "iana"
    },
    "application/vnd.rapid": {
        "source": "iana"
    },
    "application/vnd.rar": {
        "source": "iana",
        "extensions": [
            "rar"
        ]
    },
    "application/vnd.realvnc.bed": {
        "source": "iana",
        "extensions": [
            "bed"
        ]
    },
    "application/vnd.recordare.musicxml": {
        "source": "iana",
        "extensions": [
            "mxl"
        ]
    },
    "application/vnd.recordare.musicxml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "musicxml"
        ]
    },
    "application/vnd.renlearn.rlprint": {
        "source": "iana"
    },
    "application/vnd.resilient.logic": {
        "source": "iana"
    },
    "application/vnd.restful+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.rig.cryptonote": {
        "source": "iana",
        "extensions": [
            "cryptonote"
        ]
    },
    "application/vnd.rim.cod": {
        "source": "apache",
        "extensions": [
            "cod"
        ]
    },
    "application/vnd.rn-realmedia": {
        "source": "apache",
        "extensions": [
            "rm"
        ]
    },
    "application/vnd.rn-realmedia-vbr": {
        "source": "apache",
        "extensions": [
            "rmvb"
        ]
    },
    "application/vnd.route66.link66+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "link66"
        ]
    },
    "application/vnd.rs-274x": {
        "source": "iana"
    },
    "application/vnd.ruckus.download": {
        "source": "iana"
    },
    "application/vnd.s3sms": {
        "source": "iana"
    },
    "application/vnd.sailingtracker.track": {
        "source": "iana",
        "extensions": [
            "st"
        ]
    },
    "application/vnd.sar": {
        "source": "iana"
    },
    "application/vnd.sbm.cid": {
        "source": "iana"
    },
    "application/vnd.sbm.mid2": {
        "source": "iana"
    },
    "application/vnd.scribus": {
        "source": "iana"
    },
    "application/vnd.sealed.3df": {
        "source": "iana"
    },
    "application/vnd.sealed.csf": {
        "source": "iana"
    },
    "application/vnd.sealed.doc": {
        "source": "iana"
    },
    "application/vnd.sealed.eml": {
        "source": "iana"
    },
    "application/vnd.sealed.mht": {
        "source": "iana"
    },
    "application/vnd.sealed.net": {
        "source": "iana"
    },
    "application/vnd.sealed.ppt": {
        "source": "iana"
    },
    "application/vnd.sealed.tiff": {
        "source": "iana"
    },
    "application/vnd.sealed.xls": {
        "source": "iana"
    },
    "application/vnd.sealedmedia.softseal.html": {
        "source": "iana"
    },
    "application/vnd.sealedmedia.softseal.pdf": {
        "source": "iana"
    },
    "application/vnd.seemail": {
        "source": "iana",
        "extensions": [
            "see"
        ]
    },
    "application/vnd.seis+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.sema": {
        "source": "iana",
        "extensions": [
            "sema"
        ]
    },
    "application/vnd.semd": {
        "source": "iana",
        "extensions": [
            "semd"
        ]
    },
    "application/vnd.semf": {
        "source": "iana",
        "extensions": [
            "semf"
        ]
    },
    "application/vnd.shade-save-file": {
        "source": "iana"
    },
    "application/vnd.shana.informed.formdata": {
        "source": "iana",
        "extensions": [
            "ifm"
        ]
    },
    "application/vnd.shana.informed.formtemplate": {
        "source": "iana",
        "extensions": [
            "itp"
        ]
    },
    "application/vnd.shana.informed.interchange": {
        "source": "iana",
        "extensions": [
            "iif"
        ]
    },
    "application/vnd.shana.informed.package": {
        "source": "iana",
        "extensions": [
            "ipk"
        ]
    },
    "application/vnd.shootproof+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.shopkick+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.shp": {
        "source": "iana"
    },
    "application/vnd.shx": {
        "source": "iana"
    },
    "application/vnd.sigrok.session": {
        "source": "iana"
    },
    "application/vnd.simtech-mindmapper": {
        "source": "iana",
        "extensions": [
            "twd",
            "twds"
        ]
    },
    "application/vnd.siren+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.smaf": {
        "source": "iana",
        "extensions": [
            "mmf"
        ]
    },
    "application/vnd.smart.notebook": {
        "source": "iana"
    },
    "application/vnd.smart.teacher": {
        "source": "iana",
        "extensions": [
            "teacher"
        ]
    },
    "application/vnd.snesdev-page-table": {
        "source": "iana"
    },
    "application/vnd.software602.filler.form+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "fo"
        ]
    },
    "application/vnd.software602.filler.form-xml-zip": {
        "source": "iana"
    },
    "application/vnd.solent.sdkm+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "sdkm",
            "sdkd"
        ]
    },
    "application/vnd.spotfire.dxp": {
        "source": "iana",
        "extensions": [
            "dxp"
        ]
    },
    "application/vnd.spotfire.sfs": {
        "source": "iana",
        "extensions": [
            "sfs"
        ]
    },
    "application/vnd.sqlite3": {
        "source": "iana"
    },
    "application/vnd.sss-cod": {
        "source": "iana"
    },
    "application/vnd.sss-dtf": {
        "source": "iana"
    },
    "application/vnd.sss-ntf": {
        "source": "iana"
    },
    "application/vnd.stardivision.calc": {
        "source": "apache",
        "extensions": [
            "sdc"
        ]
    },
    "application/vnd.stardivision.draw": {
        "source": "apache",
        "extensions": [
            "sda"
        ]
    },
    "application/vnd.stardivision.impress": {
        "source": "apache",
        "extensions": [
            "sdd"
        ]
    },
    "application/vnd.stardivision.math": {
        "source": "apache",
        "extensions": [
            "smf"
        ]
    },
    "application/vnd.stardivision.writer": {
        "source": "apache",
        "extensions": [
            "sdw",
            "vor"
        ]
    },
    "application/vnd.stardivision.writer-global": {
        "source": "apache",
        "extensions": [
            "sgl"
        ]
    },
    "application/vnd.stepmania.package": {
        "source": "iana",
        "extensions": [
            "smzip"
        ]
    },
    "application/vnd.stepmania.stepchart": {
        "source": "iana",
        "extensions": [
            "sm"
        ]
    },
    "application/vnd.street-stream": {
        "source": "iana"
    },
    "application/vnd.sun.wadl+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "wadl"
        ]
    },
    "application/vnd.sun.xml.calc": {
        "source": "apache",
        "extensions": [
            "sxc"
        ]
    },
    "application/vnd.sun.xml.calc.template": {
        "source": "apache",
        "extensions": [
            "stc"
        ]
    },
    "application/vnd.sun.xml.draw": {
        "source": "apache",
        "extensions": [
            "sxd"
        ]
    },
    "application/vnd.sun.xml.draw.template": {
        "source": "apache",
        "extensions": [
            "std"
        ]
    },
    "application/vnd.sun.xml.impress": {
        "source": "apache",
        "extensions": [
            "sxi"
        ]
    },
    "application/vnd.sun.xml.impress.template": {
        "source": "apache",
        "extensions": [
            "sti"
        ]
    },
    "application/vnd.sun.xml.math": {
        "source": "apache",
        "extensions": [
            "sxm"
        ]
    },
    "application/vnd.sun.xml.writer": {
        "source": "apache",
        "extensions": [
            "sxw"
        ]
    },
    "application/vnd.sun.xml.writer.global": {
        "source": "apache",
        "extensions": [
            "sxg"
        ]
    },
    "application/vnd.sun.xml.writer.template": {
        "source": "apache",
        "extensions": [
            "stw"
        ]
    },
    "application/vnd.sus-calendar": {
        "source": "iana",
        "extensions": [
            "sus",
            "susp"
        ]
    },
    "application/vnd.svd": {
        "source": "iana",
        "extensions": [
            "svd"
        ]
    },
    "application/vnd.swiftview-ics": {
        "source": "iana"
    },
    "application/vnd.sycle+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.syft+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.symbian.install": {
        "source": "apache",
        "extensions": [
            "sis",
            "sisx"
        ]
    },
    "application/vnd.syncml+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "xsm"
        ]
    },
    "application/vnd.syncml.dm+wbxml": {
        "source": "iana",
        "charset": "UTF-8",
        "extensions": [
            "bdm"
        ]
    },
    "application/vnd.syncml.dm+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "xdm"
        ]
    },
    "application/vnd.syncml.dm.notification": {
        "source": "iana"
    },
    "application/vnd.syncml.dmddf+wbxml": {
        "source": "iana"
    },
    "application/vnd.syncml.dmddf+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "ddf"
        ]
    },
    "application/vnd.syncml.dmtnds+wbxml": {
        "source": "iana"
    },
    "application/vnd.syncml.dmtnds+xml": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true
    },
    "application/vnd.syncml.ds.notification": {
        "source": "iana"
    },
    "application/vnd.tableschema+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.tao.intent-module-archive": {
        "source": "iana",
        "extensions": [
            "tao"
        ]
    },
    "application/vnd.tcpdump.pcap": {
        "source": "iana",
        "extensions": [
            "pcap",
            "cap",
            "dmp"
        ]
    },
    "application/vnd.think-cell.ppttc+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.tmd.mediaflex.api+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.tml": {
        "source": "iana"
    },
    "application/vnd.tmobile-livetv": {
        "source": "iana",
        "extensions": [
            "tmo"
        ]
    },
    "application/vnd.tri.onesource": {
        "source": "iana"
    },
    "application/vnd.trid.tpt": {
        "source": "iana",
        "extensions": [
            "tpt"
        ]
    },
    "application/vnd.triscape.mxs": {
        "source": "iana",
        "extensions": [
            "mxs"
        ]
    },
    "application/vnd.trueapp": {
        "source": "iana",
        "extensions": [
            "tra"
        ]
    },
    "application/vnd.truedoc": {
        "source": "iana"
    },
    "application/vnd.ubisoft.webplayer": {
        "source": "iana"
    },
    "application/vnd.ufdl": {
        "source": "iana",
        "extensions": [
            "ufd",
            "ufdl"
        ]
    },
    "application/vnd.uiq.theme": {
        "source": "iana",
        "extensions": [
            "utz"
        ]
    },
    "application/vnd.umajin": {
        "source": "iana",
        "extensions": [
            "umj"
        ]
    },
    "application/vnd.unity": {
        "source": "iana",
        "extensions": [
            "unityweb"
        ]
    },
    "application/vnd.uoml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "uoml"
        ]
    },
    "application/vnd.uplanet.alert": {
        "source": "iana"
    },
    "application/vnd.uplanet.alert-wbxml": {
        "source": "iana"
    },
    "application/vnd.uplanet.bearer-choice": {
        "source": "iana"
    },
    "application/vnd.uplanet.bearer-choice-wbxml": {
        "source": "iana"
    },
    "application/vnd.uplanet.cacheop": {
        "source": "iana"
    },
    "application/vnd.uplanet.cacheop-wbxml": {
        "source": "iana"
    },
    "application/vnd.uplanet.channel": {
        "source": "iana"
    },
    "application/vnd.uplanet.channel-wbxml": {
        "source": "iana"
    },
    "application/vnd.uplanet.list": {
        "source": "iana"
    },
    "application/vnd.uplanet.list-wbxml": {
        "source": "iana"
    },
    "application/vnd.uplanet.listcmd": {
        "source": "iana"
    },
    "application/vnd.uplanet.listcmd-wbxml": {
        "source": "iana"
    },
    "application/vnd.uplanet.signal": {
        "source": "iana"
    },
    "application/vnd.uri-map": {
        "source": "iana"
    },
    "application/vnd.valve.source.material": {
        "source": "iana"
    },
    "application/vnd.vcx": {
        "source": "iana",
        "extensions": [
            "vcx"
        ]
    },
    "application/vnd.vd-study": {
        "source": "iana"
    },
    "application/vnd.vectorworks": {
        "source": "iana"
    },
    "application/vnd.vel+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.verimatrix.vcas": {
        "source": "iana"
    },
    "application/vnd.veritone.aion+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.veryant.thin": {
        "source": "iana"
    },
    "application/vnd.ves.encrypted": {
        "source": "iana"
    },
    "application/vnd.vidsoft.vidconference": {
        "source": "iana"
    },
    "application/vnd.visio": {
        "source": "iana",
        "extensions": [
            "vsd",
            "vst",
            "vss",
            "vsw"
        ]
    },
    "application/vnd.visionary": {
        "source": "iana",
        "extensions": [
            "vis"
        ]
    },
    "application/vnd.vividence.scriptfile": {
        "source": "iana"
    },
    "application/vnd.vsf": {
        "source": "iana",
        "extensions": [
            "vsf"
        ]
    },
    "application/vnd.wap.sic": {
        "source": "iana"
    },
    "application/vnd.wap.slc": {
        "source": "iana"
    },
    "application/vnd.wap.wbxml": {
        "source": "iana",
        "charset": "UTF-8",
        "extensions": [
            "wbxml"
        ]
    },
    "application/vnd.wap.wmlc": {
        "source": "iana",
        "extensions": [
            "wmlc"
        ]
    },
    "application/vnd.wap.wmlscriptc": {
        "source": "iana",
        "extensions": [
            "wmlsc"
        ]
    },
    "application/vnd.webturbo": {
        "source": "iana",
        "extensions": [
            "wtb"
        ]
    },
    "application/vnd.wfa.dpp": {
        "source": "iana"
    },
    "application/vnd.wfa.p2p": {
        "source": "iana"
    },
    "application/vnd.wfa.wsc": {
        "source": "iana"
    },
    "application/vnd.windows.devicepairing": {
        "source": "iana"
    },
    "application/vnd.wmc": {
        "source": "iana"
    },
    "application/vnd.wmf.bootstrap": {
        "source": "iana"
    },
    "application/vnd.wolfram.mathematica": {
        "source": "iana"
    },
    "application/vnd.wolfram.mathematica.package": {
        "source": "iana"
    },
    "application/vnd.wolfram.player": {
        "source": "iana",
        "extensions": [
            "nbp"
        ]
    },
    "application/vnd.wordperfect": {
        "source": "iana",
        "extensions": [
            "wpd"
        ]
    },
    "application/vnd.wqd": {
        "source": "iana",
        "extensions": [
            "wqd"
        ]
    },
    "application/vnd.wrq-hp3000-labelled": {
        "source": "iana"
    },
    "application/vnd.wt.stf": {
        "source": "iana",
        "extensions": [
            "stf"
        ]
    },
    "application/vnd.wv.csp+wbxml": {
        "source": "iana"
    },
    "application/vnd.wv.csp+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.wv.ssp+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.xacml+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.xara": {
        "source": "iana",
        "extensions": [
            "xar"
        ]
    },
    "application/vnd.xfdl": {
        "source": "iana",
        "extensions": [
            "xfdl"
        ]
    },
    "application/vnd.xfdl.webform": {
        "source": "iana"
    },
    "application/vnd.xmi+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/vnd.xmpie.cpkg": {
        "source": "iana"
    },
    "application/vnd.xmpie.dpkg": {
        "source": "iana"
    },
    "application/vnd.xmpie.plan": {
        "source": "iana"
    },
    "application/vnd.xmpie.ppkg": {
        "source": "iana"
    },
    "application/vnd.xmpie.xlim": {
        "source": "iana"
    },
    "application/vnd.yamaha.hv-dic": {
        "source": "iana",
        "extensions": [
            "hvd"
        ]
    },
    "application/vnd.yamaha.hv-script": {
        "source": "iana",
        "extensions": [
            "hvs"
        ]
    },
    "application/vnd.yamaha.hv-voice": {
        "source": "iana",
        "extensions": [
            "hvp"
        ]
    },
    "application/vnd.yamaha.openscoreformat": {
        "source": "iana",
        "extensions": [
            "osf"
        ]
    },
    "application/vnd.yamaha.openscoreformat.osfpvg+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "osfpvg"
        ]
    },
    "application/vnd.yamaha.remote-setup": {
        "source": "iana"
    },
    "application/vnd.yamaha.smaf-audio": {
        "source": "iana",
        "extensions": [
            "saf"
        ]
    },
    "application/vnd.yamaha.smaf-phrase": {
        "source": "iana",
        "extensions": [
            "spf"
        ]
    },
    "application/vnd.yamaha.through-ngn": {
        "source": "iana"
    },
    "application/vnd.yamaha.tunnel-udpencap": {
        "source": "iana"
    },
    "application/vnd.yaoweme": {
        "source": "iana"
    },
    "application/vnd.yellowriver-custom-menu": {
        "source": "iana",
        "extensions": [
            "cmp"
        ]
    },
    "application/vnd.youtube.yt": {
        "source": "iana"
    },
    "application/vnd.zul": {
        "source": "iana",
        "extensions": [
            "zir",
            "zirz"
        ]
    },
    "application/vnd.zzazz.deck+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "zaz"
        ]
    },
    "application/voicexml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "vxml"
        ]
    },
    "application/voucher-cms+json": {
        "source": "iana",
        "compressible": true
    },
    "application/vq-rtcpxr": {
        "source": "iana"
    },
    "application/wasm": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "wasm"
        ]
    },
    "application/watcherinfo+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "wif"
        ]
    },
    "application/webpush-options+json": {
        "source": "iana",
        "compressible": true
    },
    "application/whoispp-query": {
        "source": "iana"
    },
    "application/whoispp-response": {
        "source": "iana"
    },
    "application/widget": {
        "source": "iana",
        "extensions": [
            "wgt"
        ]
    },
    "application/winhlp": {
        "source": "apache",
        "extensions": [
            "hlp"
        ]
    },
    "application/wita": {
        "source": "iana"
    },
    "application/wordperfect5.1": {
        "source": "iana"
    },
    "application/wsdl+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "wsdl"
        ]
    },
    "application/wspolicy+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "wspolicy"
        ]
    },
    "application/x-7z-compressed": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "7z"
        ]
    },
    "application/x-abiword": {
        "source": "apache",
        "extensions": [
            "abw"
        ]
    },
    "application/x-ace-compressed": {
        "source": "apache",
        "extensions": [
            "ace"
        ]
    },
    "application/x-amf": {
        "source": "apache"
    },
    "application/x-apple-diskimage": {
        "source": "apache",
        "extensions": [
            "dmg"
        ]
    },
    "application/x-arj": {
        "compressible": false,
        "extensions": [
            "arj"
        ]
    },
    "application/x-authorware-bin": {
        "source": "apache",
        "extensions": [
            "aab",
            "x32",
            "u32",
            "vox"
        ]
    },
    "application/x-authorware-map": {
        "source": "apache",
        "extensions": [
            "aam"
        ]
    },
    "application/x-authorware-seg": {
        "source": "apache",
        "extensions": [
            "aas"
        ]
    },
    "application/x-bcpio": {
        "source": "apache",
        "extensions": [
            "bcpio"
        ]
    },
    "application/x-bdoc": {
        "compressible": false,
        "extensions": [
            "bdoc"
        ]
    },
    "application/x-bittorrent": {
        "source": "apache",
        "extensions": [
            "torrent"
        ]
    },
    "application/x-blorb": {
        "source": "apache",
        "extensions": [
            "blb",
            "blorb"
        ]
    },
    "application/x-bzip": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "bz"
        ]
    },
    "application/x-bzip2": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "bz2",
            "boz"
        ]
    },
    "application/x-cbr": {
        "source": "apache",
        "extensions": [
            "cbr",
            "cba",
            "cbt",
            "cbz",
            "cb7"
        ]
    },
    "application/x-cdlink": {
        "source": "apache",
        "extensions": [
            "vcd"
        ]
    },
    "application/x-cfs-compressed": {
        "source": "apache",
        "extensions": [
            "cfs"
        ]
    },
    "application/x-chat": {
        "source": "apache",
        "extensions": [
            "chat"
        ]
    },
    "application/x-chess-pgn": {
        "source": "apache",
        "extensions": [
            "pgn"
        ]
    },
    "application/x-chrome-extension": {
        "extensions": [
            "crx"
        ]
    },
    "application/x-cocoa": {
        "source": "nginx",
        "extensions": [
            "cco"
        ]
    },
    "application/x-compress": {
        "source": "apache"
    },
    "application/x-conference": {
        "source": "apache",
        "extensions": [
            "nsc"
        ]
    },
    "application/x-cpio": {
        "source": "apache",
        "extensions": [
            "cpio"
        ]
    },
    "application/x-csh": {
        "source": "apache",
        "extensions": [
            "csh"
        ]
    },
    "application/x-deb": {
        "compressible": false
    },
    "application/x-debian-package": {
        "source": "apache",
        "extensions": [
            "deb",
            "udeb"
        ]
    },
    "application/x-dgc-compressed": {
        "source": "apache",
        "extensions": [
            "dgc"
        ]
    },
    "application/x-director": {
        "source": "apache",
        "extensions": [
            "dir",
            "dcr",
            "dxr",
            "cst",
            "cct",
            "cxt",
            "w3d",
            "fgd",
            "swa"
        ]
    },
    "application/x-doom": {
        "source": "apache",
        "extensions": [
            "wad"
        ]
    },
    "application/x-dtbncx+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "ncx"
        ]
    },
    "application/x-dtbook+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "dtb"
        ]
    },
    "application/x-dtbresource+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "res"
        ]
    },
    "application/x-dvi": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "dvi"
        ]
    },
    "application/x-envoy": {
        "source": "apache",
        "extensions": [
            "evy"
        ]
    },
    "application/x-eva": {
        "source": "apache",
        "extensions": [
            "eva"
        ]
    },
    "application/x-font-bdf": {
        "source": "apache",
        "extensions": [
            "bdf"
        ]
    },
    "application/x-font-dos": {
        "source": "apache"
    },
    "application/x-font-framemaker": {
        "source": "apache"
    },
    "application/x-font-ghostscript": {
        "source": "apache",
        "extensions": [
            "gsf"
        ]
    },
    "application/x-font-libgrx": {
        "source": "apache"
    },
    "application/x-font-linux-psf": {
        "source": "apache",
        "extensions": [
            "psf"
        ]
    },
    "application/x-font-pcf": {
        "source": "apache",
        "extensions": [
            "pcf"
        ]
    },
    "application/x-font-snf": {
        "source": "apache",
        "extensions": [
            "snf"
        ]
    },
    "application/x-font-speedo": {
        "source": "apache"
    },
    "application/x-font-sunos-news": {
        "source": "apache"
    },
    "application/x-font-type1": {
        "source": "apache",
        "extensions": [
            "pfa",
            "pfb",
            "pfm",
            "afm"
        ]
    },
    "application/x-font-vfont": {
        "source": "apache"
    },
    "application/x-freearc": {
        "source": "apache",
        "extensions": [
            "arc"
        ]
    },
    "application/x-futuresplash": {
        "source": "apache",
        "extensions": [
            "spl"
        ]
    },
    "application/x-gca-compressed": {
        "source": "apache",
        "extensions": [
            "gca"
        ]
    },
    "application/x-glulx": {
        "source": "apache",
        "extensions": [
            "ulx"
        ]
    },
    "application/x-gnumeric": {
        "source": "apache",
        "extensions": [
            "gnumeric"
        ]
    },
    "application/x-gramps-xml": {
        "source": "apache",
        "extensions": [
            "gramps"
        ]
    },
    "application/x-gtar": {
        "source": "apache",
        "extensions": [
            "gtar"
        ]
    },
    "application/x-gzip": {
        "source": "apache"
    },
    "application/x-hdf": {
        "source": "apache",
        "extensions": [
            "hdf"
        ]
    },
    "application/x-httpd-php": {
        "compressible": true,
        "extensions": [
            "php"
        ]
    },
    "application/x-install-instructions": {
        "source": "apache",
        "extensions": [
            "install"
        ]
    },
    "application/x-iso9660-image": {
        "source": "apache",
        "extensions": [
            "iso"
        ]
    },
    "application/x-iwork-keynote-sffkey": {
        "extensions": [
            "key"
        ]
    },
    "application/x-iwork-numbers-sffnumbers": {
        "extensions": [
            "numbers"
        ]
    },
    "application/x-iwork-pages-sffpages": {
        "extensions": [
            "pages"
        ]
    },
    "application/x-java-archive-diff": {
        "source": "nginx",
        "extensions": [
            "jardiff"
        ]
    },
    "application/x-java-jnlp-file": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "jnlp"
        ]
    },
    "application/x-javascript": {
        "compressible": true
    },
    "application/x-keepass2": {
        "extensions": [
            "kdbx"
        ]
    },
    "application/x-latex": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "latex"
        ]
    },
    "application/x-lua-bytecode": {
        "extensions": [
            "luac"
        ]
    },
    "application/x-lzh-compressed": {
        "source": "apache",
        "extensions": [
            "lzh",
            "lha"
        ]
    },
    "application/x-makeself": {
        "source": "nginx",
        "extensions": [
            "run"
        ]
    },
    "application/x-mie": {
        "source": "apache",
        "extensions": [
            "mie"
        ]
    },
    "application/x-mobipocket-ebook": {
        "source": "apache",
        "extensions": [
            "prc",
            "mobi"
        ]
    },
    "application/x-mpegurl": {
        "compressible": false
    },
    "application/x-ms-application": {
        "source": "apache",
        "extensions": [
            "application"
        ]
    },
    "application/x-ms-shortcut": {
        "source": "apache",
        "extensions": [
            "lnk"
        ]
    },
    "application/x-ms-wmd": {
        "source": "apache",
        "extensions": [
            "wmd"
        ]
    },
    "application/x-ms-wmz": {
        "source": "apache",
        "extensions": [
            "wmz"
        ]
    },
    "application/x-ms-xbap": {
        "source": "apache",
        "extensions": [
            "xbap"
        ]
    },
    "application/x-msaccess": {
        "source": "apache",
        "extensions": [
            "mdb"
        ]
    },
    "application/x-msbinder": {
        "source": "apache",
        "extensions": [
            "obd"
        ]
    },
    "application/x-mscardfile": {
        "source": "apache",
        "extensions": [
            "crd"
        ]
    },
    "application/x-msclip": {
        "source": "apache",
        "extensions": [
            "clp"
        ]
    },
    "application/x-msdos-program": {
        "extensions": [
            "exe"
        ]
    },
    "application/x-msdownload": {
        "source": "apache",
        "extensions": [
            "exe",
            "dll",
            "com",
            "bat",
            "msi"
        ]
    },
    "application/x-msmediaview": {
        "source": "apache",
        "extensions": [
            "mvb",
            "m13",
            "m14"
        ]
    },
    "application/x-msmetafile": {
        "source": "apache",
        "extensions": [
            "wmf",
            "wmz",
            "emf",
            "emz"
        ]
    },
    "application/x-msmoney": {
        "source": "apache",
        "extensions": [
            "mny"
        ]
    },
    "application/x-mspublisher": {
        "source": "apache",
        "extensions": [
            "pub"
        ]
    },
    "application/x-msschedule": {
        "source": "apache",
        "extensions": [
            "scd"
        ]
    },
    "application/x-msterminal": {
        "source": "apache",
        "extensions": [
            "trm"
        ]
    },
    "application/x-mswrite": {
        "source": "apache",
        "extensions": [
            "wri"
        ]
    },
    "application/x-netcdf": {
        "source": "apache",
        "extensions": [
            "nc",
            "cdf"
        ]
    },
    "application/x-ns-proxy-autoconfig": {
        "compressible": true,
        "extensions": [
            "pac"
        ]
    },
    "application/x-nzb": {
        "source": "apache",
        "extensions": [
            "nzb"
        ]
    },
    "application/x-perl": {
        "source": "nginx",
        "extensions": [
            "pl",
            "pm"
        ]
    },
    "application/x-pilot": {
        "source": "nginx",
        "extensions": [
            "prc",
            "pdb"
        ]
    },
    "application/x-pkcs12": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "p12",
            "pfx"
        ]
    },
    "application/x-pkcs7-certificates": {
        "source": "apache",
        "extensions": [
            "p7b",
            "spc"
        ]
    },
    "application/x-pkcs7-certreqresp": {
        "source": "apache",
        "extensions": [
            "p7r"
        ]
    },
    "application/x-pki-message": {
        "source": "iana"
    },
    "application/x-rar-compressed": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "rar"
        ]
    },
    "application/x-redhat-package-manager": {
        "source": "nginx",
        "extensions": [
            "rpm"
        ]
    },
    "application/x-research-info-systems": {
        "source": "apache",
        "extensions": [
            "ris"
        ]
    },
    "application/x-sea": {
        "source": "nginx",
        "extensions": [
            "sea"
        ]
    },
    "application/x-sh": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "sh"
        ]
    },
    "application/x-shar": {
        "source": "apache",
        "extensions": [
            "shar"
        ]
    },
    "application/x-shockwave-flash": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "swf"
        ]
    },
    "application/x-silverlight-app": {
        "source": "apache",
        "extensions": [
            "xap"
        ]
    },
    "application/x-sql": {
        "source": "apache",
        "extensions": [
            "sql"
        ]
    },
    "application/x-stuffit": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "sit"
        ]
    },
    "application/x-stuffitx": {
        "source": "apache",
        "extensions": [
            "sitx"
        ]
    },
    "application/x-subrip": {
        "source": "apache",
        "extensions": [
            "srt"
        ]
    },
    "application/x-sv4cpio": {
        "source": "apache",
        "extensions": [
            "sv4cpio"
        ]
    },
    "application/x-sv4crc": {
        "source": "apache",
        "extensions": [
            "sv4crc"
        ]
    },
    "application/x-t3vm-image": {
        "source": "apache",
        "extensions": [
            "t3"
        ]
    },
    "application/x-tads": {
        "source": "apache",
        "extensions": [
            "gam"
        ]
    },
    "application/x-tar": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "tar"
        ]
    },
    "application/x-tcl": {
        "source": "apache",
        "extensions": [
            "tcl",
            "tk"
        ]
    },
    "application/x-tex": {
        "source": "apache",
        "extensions": [
            "tex"
        ]
    },
    "application/x-tex-tfm": {
        "source": "apache",
        "extensions": [
            "tfm"
        ]
    },
    "application/x-texinfo": {
        "source": "apache",
        "extensions": [
            "texinfo",
            "texi"
        ]
    },
    "application/x-tgif": {
        "source": "apache",
        "extensions": [
            "obj"
        ]
    },
    "application/x-ustar": {
        "source": "apache",
        "extensions": [
            "ustar"
        ]
    },
    "application/x-virtualbox-hdd": {
        "compressible": true,
        "extensions": [
            "hdd"
        ]
    },
    "application/x-virtualbox-ova": {
        "compressible": true,
        "extensions": [
            "ova"
        ]
    },
    "application/x-virtualbox-ovf": {
        "compressible": true,
        "extensions": [
            "ovf"
        ]
    },
    "application/x-virtualbox-vbox": {
        "compressible": true,
        "extensions": [
            "vbox"
        ]
    },
    "application/x-virtualbox-vbox-extpack": {
        "compressible": false,
        "extensions": [
            "vbox-extpack"
        ]
    },
    "application/x-virtualbox-vdi": {
        "compressible": true,
        "extensions": [
            "vdi"
        ]
    },
    "application/x-virtualbox-vhd": {
        "compressible": true,
        "extensions": [
            "vhd"
        ]
    },
    "application/x-virtualbox-vmdk": {
        "compressible": true,
        "extensions": [
            "vmdk"
        ]
    },
    "application/x-wais-source": {
        "source": "apache",
        "extensions": [
            "src"
        ]
    },
    "application/x-web-app-manifest+json": {
        "compressible": true,
        "extensions": [
            "webapp"
        ]
    },
    "application/x-www-form-urlencoded": {
        "source": "iana",
        "compressible": true
    },
    "application/x-x509-ca-cert": {
        "source": "iana",
        "extensions": [
            "der",
            "crt",
            "pem"
        ]
    },
    "application/x-x509-ca-ra-cert": {
        "source": "iana"
    },
    "application/x-x509-next-ca-cert": {
        "source": "iana"
    },
    "application/x-xfig": {
        "source": "apache",
        "extensions": [
            "fig"
        ]
    },
    "application/x-xliff+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "xlf"
        ]
    },
    "application/x-xpinstall": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "xpi"
        ]
    },
    "application/x-xz": {
        "source": "apache",
        "extensions": [
            "xz"
        ]
    },
    "application/x-zmachine": {
        "source": "apache",
        "extensions": [
            "z1",
            "z2",
            "z3",
            "z4",
            "z5",
            "z6",
            "z7",
            "z8"
        ]
    },
    "application/x400-bp": {
        "source": "iana"
    },
    "application/xacml+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/xaml+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "xaml"
        ]
    },
    "application/xcap-att+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xav"
        ]
    },
    "application/xcap-caps+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xca"
        ]
    },
    "application/xcap-diff+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xdf"
        ]
    },
    "application/xcap-el+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xel"
        ]
    },
    "application/xcap-error+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/xcap-ns+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xns"
        ]
    },
    "application/xcon-conference-info+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/xcon-conference-info-diff+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/xenc+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xenc"
        ]
    },
    "application/xhtml+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xhtml",
            "xht"
        ]
    },
    "application/xhtml-voice+xml": {
        "source": "apache",
        "compressible": true
    },
    "application/xliff+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xlf"
        ]
    },
    "application/xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xml",
            "xsl",
            "xsd",
            "rng"
        ]
    },
    "application/xml-dtd": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "dtd"
        ]
    },
    "application/xml-external-parsed-entity": {
        "source": "iana"
    },
    "application/xml-patch+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/xmpp+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/xop+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xop"
        ]
    },
    "application/xproc+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "xpl"
        ]
    },
    "application/xslt+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xsl",
            "xslt"
        ]
    },
    "application/xspf+xml": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "xspf"
        ]
    },
    "application/xv+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "mxml",
            "xhvml",
            "xvml",
            "xvm"
        ]
    },
    "application/yang": {
        "source": "iana",
        "extensions": [
            "yang"
        ]
    },
    "application/yang-data+json": {
        "source": "iana",
        "compressible": true
    },
    "application/yang-data+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/yang-patch+json": {
        "source": "iana",
        "compressible": true
    },
    "application/yang-patch+xml": {
        "source": "iana",
        "compressible": true
    },
    "application/yin+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "yin"
        ]
    },
    "application/zip": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "zip"
        ]
    },
    "application/zlib": {
        "source": "iana"
    },
    "application/zstd": {
        "source": "iana"
    },
    "audio/1d-interleaved-parityfec": {
        "source": "iana"
    },
    "audio/32kadpcm": {
        "source": "iana"
    },
    "audio/3gpp": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "3gpp"
        ]
    },
    "audio/3gpp2": {
        "source": "iana"
    },
    "audio/aac": {
        "source": "iana"
    },
    "audio/ac3": {
        "source": "iana"
    },
    "audio/adpcm": {
        "source": "apache",
        "extensions": [
            "adp"
        ]
    },
    "audio/amr": {
        "source": "iana",
        "extensions": [
            "amr"
        ]
    },
    "audio/amr-wb": {
        "source": "iana"
    },
    "audio/amr-wb+": {
        "source": "iana"
    },
    "audio/aptx": {
        "source": "iana"
    },
    "audio/asc": {
        "source": "iana"
    },
    "audio/atrac-advanced-lossless": {
        "source": "iana"
    },
    "audio/atrac-x": {
        "source": "iana"
    },
    "audio/atrac3": {
        "source": "iana"
    },
    "audio/basic": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "au",
            "snd"
        ]
    },
    "audio/bv16": {
        "source": "iana"
    },
    "audio/bv32": {
        "source": "iana"
    },
    "audio/clearmode": {
        "source": "iana"
    },
    "audio/cn": {
        "source": "iana"
    },
    "audio/dat12": {
        "source": "iana"
    },
    "audio/dls": {
        "source": "iana"
    },
    "audio/dsr-es201108": {
        "source": "iana"
    },
    "audio/dsr-es202050": {
        "source": "iana"
    },
    "audio/dsr-es202211": {
        "source": "iana"
    },
    "audio/dsr-es202212": {
        "source": "iana"
    },
    "audio/dv": {
        "source": "iana"
    },
    "audio/dvi4": {
        "source": "iana"
    },
    "audio/eac3": {
        "source": "iana"
    },
    "audio/encaprtp": {
        "source": "iana"
    },
    "audio/evrc": {
        "source": "iana"
    },
    "audio/evrc-qcp": {
        "source": "iana"
    },
    "audio/evrc0": {
        "source": "iana"
    },
    "audio/evrc1": {
        "source": "iana"
    },
    "audio/evrcb": {
        "source": "iana"
    },
    "audio/evrcb0": {
        "source": "iana"
    },
    "audio/evrcb1": {
        "source": "iana"
    },
    "audio/evrcnw": {
        "source": "iana"
    },
    "audio/evrcnw0": {
        "source": "iana"
    },
    "audio/evrcnw1": {
        "source": "iana"
    },
    "audio/evrcwb": {
        "source": "iana"
    },
    "audio/evrcwb0": {
        "source": "iana"
    },
    "audio/evrcwb1": {
        "source": "iana"
    },
    "audio/evs": {
        "source": "iana"
    },
    "audio/flexfec": {
        "source": "iana"
    },
    "audio/fwdred": {
        "source": "iana"
    },
    "audio/g711-0": {
        "source": "iana"
    },
    "audio/g719": {
        "source": "iana"
    },
    "audio/g722": {
        "source": "iana"
    },
    "audio/g7221": {
        "source": "iana"
    },
    "audio/g723": {
        "source": "iana"
    },
    "audio/g726-16": {
        "source": "iana"
    },
    "audio/g726-24": {
        "source": "iana"
    },
    "audio/g726-32": {
        "source": "iana"
    },
    "audio/g726-40": {
        "source": "iana"
    },
    "audio/g728": {
        "source": "iana"
    },
    "audio/g729": {
        "source": "iana"
    },
    "audio/g7291": {
        "source": "iana"
    },
    "audio/g729d": {
        "source": "iana"
    },
    "audio/g729e": {
        "source": "iana"
    },
    "audio/gsm": {
        "source": "iana"
    },
    "audio/gsm-efr": {
        "source": "iana"
    },
    "audio/gsm-hr-08": {
        "source": "iana"
    },
    "audio/ilbc": {
        "source": "iana"
    },
    "audio/ip-mr_v2.5": {
        "source": "iana"
    },
    "audio/isac": {
        "source": "apache"
    },
    "audio/l16": {
        "source": "iana"
    },
    "audio/l20": {
        "source": "iana"
    },
    "audio/l24": {
        "source": "iana",
        "compressible": false
    },
    "audio/l8": {
        "source": "iana"
    },
    "audio/lpc": {
        "source": "iana"
    },
    "audio/melp": {
        "source": "iana"
    },
    "audio/melp1200": {
        "source": "iana"
    },
    "audio/melp2400": {
        "source": "iana"
    },
    "audio/melp600": {
        "source": "iana"
    },
    "audio/mhas": {
        "source": "iana"
    },
    "audio/midi": {
        "source": "apache",
        "extensions": [
            "mid",
            "midi",
            "kar",
            "rmi"
        ]
    },
    "audio/mobile-xmf": {
        "source": "iana",
        "extensions": [
            "mxmf"
        ]
    },
    "audio/mp3": {
        "compressible": false,
        "extensions": [
            "mp3"
        ]
    },
    "audio/mp4": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "m4a",
            "mp4a"
        ]
    },
    "audio/mp4a-latm": {
        "source": "iana"
    },
    "audio/mpa": {
        "source": "iana"
    },
    "audio/mpa-robust": {
        "source": "iana"
    },
    "audio/mpeg": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "mpga",
            "mp2",
            "mp2a",
            "mp3",
            "m2a",
            "m3a"
        ]
    },
    "audio/mpeg4-generic": {
        "source": "iana"
    },
    "audio/musepack": {
        "source": "apache"
    },
    "audio/ogg": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "oga",
            "ogg",
            "spx",
            "opus"
        ]
    },
    "audio/opus": {
        "source": "iana"
    },
    "audio/parityfec": {
        "source": "iana"
    },
    "audio/pcma": {
        "source": "iana"
    },
    "audio/pcma-wb": {
        "source": "iana"
    },
    "audio/pcmu": {
        "source": "iana"
    },
    "audio/pcmu-wb": {
        "source": "iana"
    },
    "audio/prs.sid": {
        "source": "iana"
    },
    "audio/qcelp": {
        "source": "iana"
    },
    "audio/raptorfec": {
        "source": "iana"
    },
    "audio/red": {
        "source": "iana"
    },
    "audio/rtp-enc-aescm128": {
        "source": "iana"
    },
    "audio/rtp-midi": {
        "source": "iana"
    },
    "audio/rtploopback": {
        "source": "iana"
    },
    "audio/rtx": {
        "source": "iana"
    },
    "audio/s3m": {
        "source": "apache",
        "extensions": [
            "s3m"
        ]
    },
    "audio/scip": {
        "source": "iana"
    },
    "audio/silk": {
        "source": "apache",
        "extensions": [
            "sil"
        ]
    },
    "audio/smv": {
        "source": "iana"
    },
    "audio/smv-qcp": {
        "source": "iana"
    },
    "audio/smv0": {
        "source": "iana"
    },
    "audio/sofa": {
        "source": "iana"
    },
    "audio/sp-midi": {
        "source": "iana"
    },
    "audio/speex": {
        "source": "iana"
    },
    "audio/t140c": {
        "source": "iana"
    },
    "audio/t38": {
        "source": "iana"
    },
    "audio/telephone-event": {
        "source": "iana"
    },
    "audio/tetra_acelp": {
        "source": "iana"
    },
    "audio/tetra_acelp_bb": {
        "source": "iana"
    },
    "audio/tone": {
        "source": "iana"
    },
    "audio/tsvcis": {
        "source": "iana"
    },
    "audio/uemclip": {
        "source": "iana"
    },
    "audio/ulpfec": {
        "source": "iana"
    },
    "audio/usac": {
        "source": "iana"
    },
    "audio/vdvi": {
        "source": "iana"
    },
    "audio/vmr-wb": {
        "source": "iana"
    },
    "audio/vnd.3gpp.iufp": {
        "source": "iana"
    },
    "audio/vnd.4sb": {
        "source": "iana"
    },
    "audio/vnd.audiokoz": {
        "source": "iana"
    },
    "audio/vnd.celp": {
        "source": "iana"
    },
    "audio/vnd.cisco.nse": {
        "source": "iana"
    },
    "audio/vnd.cmles.radio-events": {
        "source": "iana"
    },
    "audio/vnd.cns.anp1": {
        "source": "iana"
    },
    "audio/vnd.cns.inf1": {
        "source": "iana"
    },
    "audio/vnd.dece.audio": {
        "source": "iana",
        "extensions": [
            "uva",
            "uvva"
        ]
    },
    "audio/vnd.digital-winds": {
        "source": "iana",
        "extensions": [
            "eol"
        ]
    },
    "audio/vnd.dlna.adts": {
        "source": "iana"
    },
    "audio/vnd.dolby.heaac.1": {
        "source": "iana"
    },
    "audio/vnd.dolby.heaac.2": {
        "source": "iana"
    },
    "audio/vnd.dolby.mlp": {
        "source": "iana"
    },
    "audio/vnd.dolby.mps": {
        "source": "iana"
    },
    "audio/vnd.dolby.pl2": {
        "source": "iana"
    },
    "audio/vnd.dolby.pl2x": {
        "source": "iana"
    },
    "audio/vnd.dolby.pl2z": {
        "source": "iana"
    },
    "audio/vnd.dolby.pulse.1": {
        "source": "iana"
    },
    "audio/vnd.dra": {
        "source": "iana",
        "extensions": [
            "dra"
        ]
    },
    "audio/vnd.dts": {
        "source": "iana",
        "extensions": [
            "dts"
        ]
    },
    "audio/vnd.dts.hd": {
        "source": "iana",
        "extensions": [
            "dtshd"
        ]
    },
    "audio/vnd.dts.uhd": {
        "source": "iana"
    },
    "audio/vnd.dvb.file": {
        "source": "iana"
    },
    "audio/vnd.everad.plj": {
        "source": "iana"
    },
    "audio/vnd.hns.audio": {
        "source": "iana"
    },
    "audio/vnd.lucent.voice": {
        "source": "iana",
        "extensions": [
            "lvp"
        ]
    },
    "audio/vnd.ms-playready.media.pya": {
        "source": "iana",
        "extensions": [
            "pya"
        ]
    },
    "audio/vnd.nokia.mobile-xmf": {
        "source": "iana"
    },
    "audio/vnd.nortel.vbk": {
        "source": "iana"
    },
    "audio/vnd.nuera.ecelp4800": {
        "source": "iana",
        "extensions": [
            "ecelp4800"
        ]
    },
    "audio/vnd.nuera.ecelp7470": {
        "source": "iana",
        "extensions": [
            "ecelp7470"
        ]
    },
    "audio/vnd.nuera.ecelp9600": {
        "source": "iana",
        "extensions": [
            "ecelp9600"
        ]
    },
    "audio/vnd.octel.sbc": {
        "source": "iana"
    },
    "audio/vnd.presonus.multitrack": {
        "source": "iana"
    },
    "audio/vnd.qcelp": {
        "source": "iana"
    },
    "audio/vnd.rhetorex.32kadpcm": {
        "source": "iana"
    },
    "audio/vnd.rip": {
        "source": "iana",
        "extensions": [
            "rip"
        ]
    },
    "audio/vnd.rn-realaudio": {
        "compressible": false
    },
    "audio/vnd.sealedmedia.softseal.mpeg": {
        "source": "iana"
    },
    "audio/vnd.vmx.cvsd": {
        "source": "iana"
    },
    "audio/vnd.wave": {
        "compressible": false
    },
    "audio/vorbis": {
        "source": "iana",
        "compressible": false
    },
    "audio/vorbis-config": {
        "source": "iana"
    },
    "audio/wav": {
        "compressible": false,
        "extensions": [
            "wav"
        ]
    },
    "audio/wave": {
        "compressible": false,
        "extensions": [
            "wav"
        ]
    },
    "audio/webm": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "weba"
        ]
    },
    "audio/x-aac": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "aac"
        ]
    },
    "audio/x-aiff": {
        "source": "apache",
        "extensions": [
            "aif",
            "aiff",
            "aifc"
        ]
    },
    "audio/x-caf": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "caf"
        ]
    },
    "audio/x-flac": {
        "source": "apache",
        "extensions": [
            "flac"
        ]
    },
    "audio/x-m4a": {
        "source": "nginx",
        "extensions": [
            "m4a"
        ]
    },
    "audio/x-matroska": {
        "source": "apache",
        "extensions": [
            "mka"
        ]
    },
    "audio/x-mpegurl": {
        "source": "apache",
        "extensions": [
            "m3u"
        ]
    },
    "audio/x-ms-wax": {
        "source": "apache",
        "extensions": [
            "wax"
        ]
    },
    "audio/x-ms-wma": {
        "source": "apache",
        "extensions": [
            "wma"
        ]
    },
    "audio/x-pn-realaudio": {
        "source": "apache",
        "extensions": [
            "ram",
            "ra"
        ]
    },
    "audio/x-pn-realaudio-plugin": {
        "source": "apache",
        "extensions": [
            "rmp"
        ]
    },
    "audio/x-realaudio": {
        "source": "nginx",
        "extensions": [
            "ra"
        ]
    },
    "audio/x-tta": {
        "source": "apache"
    },
    "audio/x-wav": {
        "source": "apache",
        "extensions": [
            "wav"
        ]
    },
    "audio/xm": {
        "source": "apache",
        "extensions": [
            "xm"
        ]
    },
    "chemical/x-cdx": {
        "source": "apache",
        "extensions": [
            "cdx"
        ]
    },
    "chemical/x-cif": {
        "source": "apache",
        "extensions": [
            "cif"
        ]
    },
    "chemical/x-cmdf": {
        "source": "apache",
        "extensions": [
            "cmdf"
        ]
    },
    "chemical/x-cml": {
        "source": "apache",
        "extensions": [
            "cml"
        ]
    },
    "chemical/x-csml": {
        "source": "apache",
        "extensions": [
            "csml"
        ]
    },
    "chemical/x-pdb": {
        "source": "apache"
    },
    "chemical/x-xyz": {
        "source": "apache",
        "extensions": [
            "xyz"
        ]
    },
    "font/collection": {
        "source": "iana",
        "extensions": [
            "ttc"
        ]
    },
    "font/otf": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "otf"
        ]
    },
    "font/sfnt": {
        "source": "iana"
    },
    "font/ttf": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ttf"
        ]
    },
    "font/woff": {
        "source": "iana",
        "extensions": [
            "woff"
        ]
    },
    "font/woff2": {
        "source": "iana",
        "extensions": [
            "woff2"
        ]
    },
    "image/aces": {
        "source": "iana",
        "extensions": [
            "exr"
        ]
    },
    "image/apng": {
        "compressible": false,
        "extensions": [
            "apng"
        ]
    },
    "image/avci": {
        "source": "iana",
        "extensions": [
            "avci"
        ]
    },
    "image/avcs": {
        "source": "iana",
        "extensions": [
            "avcs"
        ]
    },
    "image/avif": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "avif"
        ]
    },
    "image/bmp": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "bmp"
        ]
    },
    "image/cgm": {
        "source": "iana",
        "extensions": [
            "cgm"
        ]
    },
    "image/dicom-rle": {
        "source": "iana",
        "extensions": [
            "drle"
        ]
    },
    "image/emf": {
        "source": "iana",
        "extensions": [
            "emf"
        ]
    },
    "image/fits": {
        "source": "iana",
        "extensions": [
            "fits"
        ]
    },
    "image/g3fax": {
        "source": "iana",
        "extensions": [
            "g3"
        ]
    },
    "image/gif": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "gif"
        ]
    },
    "image/heic": {
        "source": "iana",
        "extensions": [
            "heic"
        ]
    },
    "image/heic-sequence": {
        "source": "iana",
        "extensions": [
            "heics"
        ]
    },
    "image/heif": {
        "source": "iana",
        "extensions": [
            "heif"
        ]
    },
    "image/heif-sequence": {
        "source": "iana",
        "extensions": [
            "heifs"
        ]
    },
    "image/hej2k": {
        "source": "iana",
        "extensions": [
            "hej2"
        ]
    },
    "image/hsj2": {
        "source": "iana",
        "extensions": [
            "hsj2"
        ]
    },
    "image/ief": {
        "source": "iana",
        "extensions": [
            "ief"
        ]
    },
    "image/jls": {
        "source": "iana",
        "extensions": [
            "jls"
        ]
    },
    "image/jp2": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "jp2",
            "jpg2"
        ]
    },
    "image/jpeg": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "jpeg",
            "jpg",
            "jpe"
        ]
    },
    "image/jph": {
        "source": "iana",
        "extensions": [
            "jph"
        ]
    },
    "image/jphc": {
        "source": "iana",
        "extensions": [
            "jhc"
        ]
    },
    "image/jpm": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "jpm"
        ]
    },
    "image/jpx": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "jpx",
            "jpf"
        ]
    },
    "image/jxr": {
        "source": "iana",
        "extensions": [
            "jxr"
        ]
    },
    "image/jxra": {
        "source": "iana",
        "extensions": [
            "jxra"
        ]
    },
    "image/jxrs": {
        "source": "iana",
        "extensions": [
            "jxrs"
        ]
    },
    "image/jxs": {
        "source": "iana",
        "extensions": [
            "jxs"
        ]
    },
    "image/jxsc": {
        "source": "iana",
        "extensions": [
            "jxsc"
        ]
    },
    "image/jxsi": {
        "source": "iana",
        "extensions": [
            "jxsi"
        ]
    },
    "image/jxss": {
        "source": "iana",
        "extensions": [
            "jxss"
        ]
    },
    "image/ktx": {
        "source": "iana",
        "extensions": [
            "ktx"
        ]
    },
    "image/ktx2": {
        "source": "iana",
        "extensions": [
            "ktx2"
        ]
    },
    "image/naplps": {
        "source": "iana"
    },
    "image/pjpeg": {
        "compressible": false
    },
    "image/png": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "png"
        ]
    },
    "image/prs.btif": {
        "source": "iana",
        "extensions": [
            "btif"
        ]
    },
    "image/prs.pti": {
        "source": "iana",
        "extensions": [
            "pti"
        ]
    },
    "image/pwg-raster": {
        "source": "iana"
    },
    "image/sgi": {
        "source": "apache",
        "extensions": [
            "sgi"
        ]
    },
    "image/svg+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "svg",
            "svgz"
        ]
    },
    "image/t38": {
        "source": "iana",
        "extensions": [
            "t38"
        ]
    },
    "image/tiff": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "tif",
            "tiff"
        ]
    },
    "image/tiff-fx": {
        "source": "iana",
        "extensions": [
            "tfx"
        ]
    },
    "image/vnd.adobe.photoshop": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "psd"
        ]
    },
    "image/vnd.airzip.accelerator.azv": {
        "source": "iana",
        "extensions": [
            "azv"
        ]
    },
    "image/vnd.cns.inf2": {
        "source": "iana"
    },
    "image/vnd.dece.graphic": {
        "source": "iana",
        "extensions": [
            "uvi",
            "uvvi",
            "uvg",
            "uvvg"
        ]
    },
    "image/vnd.djvu": {
        "source": "iana",
        "extensions": [
            "djvu",
            "djv"
        ]
    },
    "image/vnd.dvb.subtitle": {
        "source": "iana",
        "extensions": [
            "sub"
        ]
    },
    "image/vnd.dwg": {
        "source": "iana",
        "extensions": [
            "dwg"
        ]
    },
    "image/vnd.dxf": {
        "source": "iana",
        "extensions": [
            "dxf"
        ]
    },
    "image/vnd.fastbidsheet": {
        "source": "iana",
        "extensions": [
            "fbs"
        ]
    },
    "image/vnd.fpx": {
        "source": "iana",
        "extensions": [
            "fpx"
        ]
    },
    "image/vnd.fst": {
        "source": "iana",
        "extensions": [
            "fst"
        ]
    },
    "image/vnd.fujixerox.edmics-mmr": {
        "source": "iana",
        "extensions": [
            "mmr"
        ]
    },
    "image/vnd.fujixerox.edmics-rlc": {
        "source": "iana",
        "extensions": [
            "rlc"
        ]
    },
    "image/vnd.globalgraphics.pgb": {
        "source": "iana"
    },
    "image/vnd.microsoft.icon": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "ico"
        ]
    },
    "image/vnd.mix": {
        "source": "iana"
    },
    "image/vnd.mozilla.apng": {
        "source": "iana"
    },
    "image/vnd.ms-dds": {
        "compressible": true,
        "extensions": [
            "dds"
        ]
    },
    "image/vnd.ms-modi": {
        "source": "iana",
        "extensions": [
            "mdi"
        ]
    },
    "image/vnd.ms-photo": {
        "source": "apache",
        "extensions": [
            "wdp"
        ]
    },
    "image/vnd.net-fpx": {
        "source": "iana",
        "extensions": [
            "npx"
        ]
    },
    "image/vnd.pco.b16": {
        "source": "iana",
        "extensions": [
            "b16"
        ]
    },
    "image/vnd.radiance": {
        "source": "iana"
    },
    "image/vnd.sealed.png": {
        "source": "iana"
    },
    "image/vnd.sealedmedia.softseal.gif": {
        "source": "iana"
    },
    "image/vnd.sealedmedia.softseal.jpg": {
        "source": "iana"
    },
    "image/vnd.svf": {
        "source": "iana"
    },
    "image/vnd.tencent.tap": {
        "source": "iana",
        "extensions": [
            "tap"
        ]
    },
    "image/vnd.valve.source.texture": {
        "source": "iana",
        "extensions": [
            "vtf"
        ]
    },
    "image/vnd.wap.wbmp": {
        "source": "iana",
        "extensions": [
            "wbmp"
        ]
    },
    "image/vnd.xiff": {
        "source": "iana",
        "extensions": [
            "xif"
        ]
    },
    "image/vnd.zbrush.pcx": {
        "source": "iana",
        "extensions": [
            "pcx"
        ]
    },
    "image/webp": {
        "source": "apache",
        "extensions": [
            "webp"
        ]
    },
    "image/wmf": {
        "source": "iana",
        "extensions": [
            "wmf"
        ]
    },
    "image/x-3ds": {
        "source": "apache",
        "extensions": [
            "3ds"
        ]
    },
    "image/x-cmu-raster": {
        "source": "apache",
        "extensions": [
            "ras"
        ]
    },
    "image/x-cmx": {
        "source": "apache",
        "extensions": [
            "cmx"
        ]
    },
    "image/x-freehand": {
        "source": "apache",
        "extensions": [
            "fh",
            "fhc",
            "fh4",
            "fh5",
            "fh7"
        ]
    },
    "image/x-icon": {
        "source": "apache",
        "compressible": true,
        "extensions": [
            "ico"
        ]
    },
    "image/x-jng": {
        "source": "nginx",
        "extensions": [
            "jng"
        ]
    },
    "image/x-mrsid-image": {
        "source": "apache",
        "extensions": [
            "sid"
        ]
    },
    "image/x-ms-bmp": {
        "source": "nginx",
        "compressible": true,
        "extensions": [
            "bmp"
        ]
    },
    "image/x-pcx": {
        "source": "apache",
        "extensions": [
            "pcx"
        ]
    },
    "image/x-pict": {
        "source": "apache",
        "extensions": [
            "pic",
            "pct"
        ]
    },
    "image/x-portable-anymap": {
        "source": "apache",
        "extensions": [
            "pnm"
        ]
    },
    "image/x-portable-bitmap": {
        "source": "apache",
        "extensions": [
            "pbm"
        ]
    },
    "image/x-portable-graymap": {
        "source": "apache",
        "extensions": [
            "pgm"
        ]
    },
    "image/x-portable-pixmap": {
        "source": "apache",
        "extensions": [
            "ppm"
        ]
    },
    "image/x-rgb": {
        "source": "apache",
        "extensions": [
            "rgb"
        ]
    },
    "image/x-tga": {
        "source": "apache",
        "extensions": [
            "tga"
        ]
    },
    "image/x-xbitmap": {
        "source": "apache",
        "extensions": [
            "xbm"
        ]
    },
    "image/x-xcf": {
        "compressible": false
    },
    "image/x-xpixmap": {
        "source": "apache",
        "extensions": [
            "xpm"
        ]
    },
    "image/x-xwindowdump": {
        "source": "apache",
        "extensions": [
            "xwd"
        ]
    },
    "message/cpim": {
        "source": "iana"
    },
    "message/delivery-status": {
        "source": "iana"
    },
    "message/disposition-notification": {
        "source": "iana",
        "extensions": [
            "disposition-notification"
        ]
    },
    "message/external-body": {
        "source": "iana"
    },
    "message/feedback-report": {
        "source": "iana"
    },
    "message/global": {
        "source": "iana",
        "extensions": [
            "u8msg"
        ]
    },
    "message/global-delivery-status": {
        "source": "iana",
        "extensions": [
            "u8dsn"
        ]
    },
    "message/global-disposition-notification": {
        "source": "iana",
        "extensions": [
            "u8mdn"
        ]
    },
    "message/global-headers": {
        "source": "iana",
        "extensions": [
            "u8hdr"
        ]
    },
    "message/http": {
        "source": "iana",
        "compressible": false
    },
    "message/imdn+xml": {
        "source": "iana",
        "compressible": true
    },
    "message/news": {
        "source": "iana"
    },
    "message/partial": {
        "source": "iana",
        "compressible": false
    },
    "message/rfc822": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "eml",
            "mime"
        ]
    },
    "message/s-http": {
        "source": "iana"
    },
    "message/sip": {
        "source": "iana"
    },
    "message/sipfrag": {
        "source": "iana"
    },
    "message/tracking-status": {
        "source": "iana"
    },
    "message/vnd.si.simp": {
        "source": "iana"
    },
    "message/vnd.wfa.wsc": {
        "source": "iana",
        "extensions": [
            "wsc"
        ]
    },
    "model/3mf": {
        "source": "iana",
        "extensions": [
            "3mf"
        ]
    },
    "model/e57": {
        "source": "iana"
    },
    "model/gltf+json": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "gltf"
        ]
    },
    "model/gltf-binary": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "glb"
        ]
    },
    "model/iges": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "igs",
            "iges"
        ]
    },
    "model/mesh": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "msh",
            "mesh",
            "silo"
        ]
    },
    "model/mtl": {
        "source": "iana",
        "extensions": [
            "mtl"
        ]
    },
    "model/obj": {
        "source": "iana",
        "extensions": [
            "obj"
        ]
    },
    "model/step": {
        "source": "iana"
    },
    "model/step+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "stpx"
        ]
    },
    "model/step+zip": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "stpz"
        ]
    },
    "model/step-xml+zip": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "stpxz"
        ]
    },
    "model/stl": {
        "source": "iana",
        "extensions": [
            "stl"
        ]
    },
    "model/vnd.collada+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "dae"
        ]
    },
    "model/vnd.dwf": {
        "source": "iana",
        "extensions": [
            "dwf"
        ]
    },
    "model/vnd.flatland.3dml": {
        "source": "iana"
    },
    "model/vnd.gdl": {
        "source": "iana",
        "extensions": [
            "gdl"
        ]
    },
    "model/vnd.gs-gdl": {
        "source": "apache"
    },
    "model/vnd.gs.gdl": {
        "source": "iana"
    },
    "model/vnd.gtw": {
        "source": "iana",
        "extensions": [
            "gtw"
        ]
    },
    "model/vnd.moml+xml": {
        "source": "iana",
        "compressible": true
    },
    "model/vnd.mts": {
        "source": "iana",
        "extensions": [
            "mts"
        ]
    },
    "model/vnd.opengex": {
        "source": "iana",
        "extensions": [
            "ogex"
        ]
    },
    "model/vnd.parasolid.transmit.binary": {
        "source": "iana",
        "extensions": [
            "x_b"
        ]
    },
    "model/vnd.parasolid.transmit.text": {
        "source": "iana",
        "extensions": [
            "x_t"
        ]
    },
    "model/vnd.pytha.pyox": {
        "source": "iana"
    },
    "model/vnd.rosette.annotated-data-model": {
        "source": "iana"
    },
    "model/vnd.sap.vds": {
        "source": "iana",
        "extensions": [
            "vds"
        ]
    },
    "model/vnd.usdz+zip": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "usdz"
        ]
    },
    "model/vnd.valve.source.compiled-map": {
        "source": "iana",
        "extensions": [
            "bsp"
        ]
    },
    "model/vnd.vtu": {
        "source": "iana",
        "extensions": [
            "vtu"
        ]
    },
    "model/vrml": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "wrl",
            "vrml"
        ]
    },
    "model/x3d+binary": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "x3db",
            "x3dbz"
        ]
    },
    "model/x3d+fastinfoset": {
        "source": "iana",
        "extensions": [
            "x3db"
        ]
    },
    "model/x3d+vrml": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "x3dv",
            "x3dvz"
        ]
    },
    "model/x3d+xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "x3d",
            "x3dz"
        ]
    },
    "model/x3d-vrml": {
        "source": "iana",
        "extensions": [
            "x3dv"
        ]
    },
    "multipart/alternative": {
        "source": "iana",
        "compressible": false
    },
    "multipart/appledouble": {
        "source": "iana"
    },
    "multipart/byteranges": {
        "source": "iana"
    },
    "multipart/digest": {
        "source": "iana"
    },
    "multipart/encrypted": {
        "source": "iana",
        "compressible": false
    },
    "multipart/form-data": {
        "source": "iana",
        "compressible": false
    },
    "multipart/header-set": {
        "source": "iana"
    },
    "multipart/mixed": {
        "source": "iana"
    },
    "multipart/multilingual": {
        "source": "iana"
    },
    "multipart/parallel": {
        "source": "iana"
    },
    "multipart/related": {
        "source": "iana",
        "compressible": false
    },
    "multipart/report": {
        "source": "iana"
    },
    "multipart/signed": {
        "source": "iana",
        "compressible": false
    },
    "multipart/vnd.bint.med-plus": {
        "source": "iana"
    },
    "multipart/voice-message": {
        "source": "iana"
    },
    "multipart/x-mixed-replace": {
        "source": "iana"
    },
    "text/1d-interleaved-parityfec": {
        "source": "iana"
    },
    "text/cache-manifest": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "appcache",
            "manifest"
        ]
    },
    "text/calendar": {
        "source": "iana",
        "extensions": [
            "ics",
            "ifb"
        ]
    },
    "text/calender": {
        "compressible": true
    },
    "text/cmd": {
        "compressible": true
    },
    "text/coffeescript": {
        "extensions": [
            "coffee",
            "litcoffee"
        ]
    },
    "text/cql": {
        "source": "iana"
    },
    "text/cql-expression": {
        "source": "iana"
    },
    "text/cql-identifier": {
        "source": "iana"
    },
    "text/css": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "css"
        ]
    },
    "text/csv": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "csv"
        ]
    },
    "text/csv-schema": {
        "source": "iana"
    },
    "text/directory": {
        "source": "iana"
    },
    "text/dns": {
        "source": "iana"
    },
    "text/ecmascript": {
        "source": "iana"
    },
    "text/encaprtp": {
        "source": "iana"
    },
    "text/enriched": {
        "source": "iana"
    },
    "text/fhirpath": {
        "source": "iana"
    },
    "text/flexfec": {
        "source": "iana"
    },
    "text/fwdred": {
        "source": "iana"
    },
    "text/gff3": {
        "source": "iana"
    },
    "text/grammar-ref-list": {
        "source": "iana"
    },
    "text/html": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "html",
            "htm",
            "shtml"
        ]
    },
    "text/jade": {
        "extensions": [
            "jade"
        ]
    },
    "text/javascript": {
        "source": "iana",
        "compressible": true
    },
    "text/jcr-cnd": {
        "source": "iana"
    },
    "text/jsx": {
        "compressible": true,
        "extensions": [
            "jsx"
        ]
    },
    "text/less": {
        "compressible": true,
        "extensions": [
            "less"
        ]
    },
    "text/markdown": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "markdown",
            "md"
        ]
    },
    "text/mathml": {
        "source": "nginx",
        "extensions": [
            "mml"
        ]
    },
    "text/mdx": {
        "compressible": true,
        "extensions": [
            "mdx"
        ]
    },
    "text/mizar": {
        "source": "iana"
    },
    "text/n3": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "n3"
        ]
    },
    "text/parameters": {
        "source": "iana",
        "charset": "UTF-8"
    },
    "text/parityfec": {
        "source": "iana"
    },
    "text/plain": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "txt",
            "text",
            "conf",
            "def",
            "list",
            "log",
            "in",
            "ini"
        ]
    },
    "text/provenance-notation": {
        "source": "iana",
        "charset": "UTF-8"
    },
    "text/prs.fallenstein.rst": {
        "source": "iana"
    },
    "text/prs.lines.tag": {
        "source": "iana",
        "extensions": [
            "dsc"
        ]
    },
    "text/prs.prop.logic": {
        "source": "iana"
    },
    "text/raptorfec": {
        "source": "iana"
    },
    "text/red": {
        "source": "iana"
    },
    "text/rfc822-headers": {
        "source": "iana"
    },
    "text/richtext": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rtx"
        ]
    },
    "text/rtf": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "rtf"
        ]
    },
    "text/rtp-enc-aescm128": {
        "source": "iana"
    },
    "text/rtploopback": {
        "source": "iana"
    },
    "text/rtx": {
        "source": "iana"
    },
    "text/sgml": {
        "source": "iana",
        "extensions": [
            "sgml",
            "sgm"
        ]
    },
    "text/shaclc": {
        "source": "iana"
    },
    "text/shex": {
        "source": "iana",
        "extensions": [
            "shex"
        ]
    },
    "text/slim": {
        "extensions": [
            "slim",
            "slm"
        ]
    },
    "text/spdx": {
        "source": "iana",
        "extensions": [
            "spdx"
        ]
    },
    "text/strings": {
        "source": "iana"
    },
    "text/stylus": {
        "extensions": [
            "stylus",
            "styl"
        ]
    },
    "text/t140": {
        "source": "iana"
    },
    "text/tab-separated-values": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "tsv"
        ]
    },
    "text/troff": {
        "source": "iana",
        "extensions": [
            "t",
            "tr",
            "roff",
            "man",
            "me",
            "ms"
        ]
    },
    "text/turtle": {
        "source": "iana",
        "charset": "UTF-8",
        "extensions": [
            "ttl"
        ]
    },
    "text/ulpfec": {
        "source": "iana"
    },
    "text/uri-list": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "uri",
            "uris",
            "urls"
        ]
    },
    "text/vcard": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "vcard"
        ]
    },
    "text/vnd.a": {
        "source": "iana"
    },
    "text/vnd.abc": {
        "source": "iana"
    },
    "text/vnd.ascii-art": {
        "source": "iana"
    },
    "text/vnd.curl": {
        "source": "iana",
        "extensions": [
            "curl"
        ]
    },
    "text/vnd.curl.dcurl": {
        "source": "apache",
        "extensions": [
            "dcurl"
        ]
    },
    "text/vnd.curl.mcurl": {
        "source": "apache",
        "extensions": [
            "mcurl"
        ]
    },
    "text/vnd.curl.scurl": {
        "source": "apache",
        "extensions": [
            "scurl"
        ]
    },
    "text/vnd.debian.copyright": {
        "source": "iana",
        "charset": "UTF-8"
    },
    "text/vnd.dmclientscript": {
        "source": "iana"
    },
    "text/vnd.dvb.subtitle": {
        "source": "iana",
        "extensions": [
            "sub"
        ]
    },
    "text/vnd.esmertec.theme-descriptor": {
        "source": "iana",
        "charset": "UTF-8"
    },
    "text/vnd.familysearch.gedcom": {
        "source": "iana",
        "extensions": [
            "ged"
        ]
    },
    "text/vnd.ficlab.flt": {
        "source": "iana"
    },
    "text/vnd.fly": {
        "source": "iana",
        "extensions": [
            "fly"
        ]
    },
    "text/vnd.fmi.flexstor": {
        "source": "iana",
        "extensions": [
            "flx"
        ]
    },
    "text/vnd.gml": {
        "source": "iana"
    },
    "text/vnd.graphviz": {
        "source": "iana",
        "extensions": [
            "gv"
        ]
    },
    "text/vnd.hans": {
        "source": "iana"
    },
    "text/vnd.hgl": {
        "source": "iana"
    },
    "text/vnd.in3d.3dml": {
        "source": "iana",
        "extensions": [
            "3dml"
        ]
    },
    "text/vnd.in3d.spot": {
        "source": "iana",
        "extensions": [
            "spot"
        ]
    },
    "text/vnd.iptc.newsml": {
        "source": "iana"
    },
    "text/vnd.iptc.nitf": {
        "source": "iana"
    },
    "text/vnd.latex-z": {
        "source": "iana"
    },
    "text/vnd.motorola.reflex": {
        "source": "iana"
    },
    "text/vnd.ms-mediapackage": {
        "source": "iana"
    },
    "text/vnd.net2phone.commcenter.command": {
        "source": "iana"
    },
    "text/vnd.radisys.msml-basic-layout": {
        "source": "iana"
    },
    "text/vnd.senx.warpscript": {
        "source": "iana"
    },
    "text/vnd.si.uricatalogue": {
        "source": "iana"
    },
    "text/vnd.sosi": {
        "source": "iana"
    },
    "text/vnd.sun.j2me.app-descriptor": {
        "source": "iana",
        "charset": "UTF-8",
        "extensions": [
            "jad"
        ]
    },
    "text/vnd.trolltech.linguist": {
        "source": "iana",
        "charset": "UTF-8"
    },
    "text/vnd.wap.si": {
        "source": "iana"
    },
    "text/vnd.wap.sl": {
        "source": "iana"
    },
    "text/vnd.wap.wml": {
        "source": "iana",
        "extensions": [
            "wml"
        ]
    },
    "text/vnd.wap.wmlscript": {
        "source": "iana",
        "extensions": [
            "wmls"
        ]
    },
    "text/vtt": {
        "source": "iana",
        "charset": "UTF-8",
        "compressible": true,
        "extensions": [
            "vtt"
        ]
    },
    "text/x-asm": {
        "source": "apache",
        "extensions": [
            "s",
            "asm"
        ]
    },
    "text/x-c": {
        "source": "apache",
        "extensions": [
            "c",
            "cc",
            "cxx",
            "cpp",
            "h",
            "hh",
            "dic"
        ]
    },
    "text/x-component": {
        "source": "nginx",
        "extensions": [
            "htc"
        ]
    },
    "text/x-fortran": {
        "source": "apache",
        "extensions": [
            "f",
            "for",
            "f77",
            "f90"
        ]
    },
    "text/x-gwt-rpc": {
        "compressible": true
    },
    "text/x-handlebars-template": {
        "extensions": [
            "hbs"
        ]
    },
    "text/x-java-source": {
        "source": "apache",
        "extensions": [
            "java"
        ]
    },
    "text/x-jquery-tmpl": {
        "compressible": true
    },
    "text/x-lua": {
        "extensions": [
            "lua"
        ]
    },
    "text/x-markdown": {
        "compressible": true,
        "extensions": [
            "mkd"
        ]
    },
    "text/x-nfo": {
        "source": "apache",
        "extensions": [
            "nfo"
        ]
    },
    "text/x-opml": {
        "source": "apache",
        "extensions": [
            "opml"
        ]
    },
    "text/x-org": {
        "compressible": true,
        "extensions": [
            "org"
        ]
    },
    "text/x-pascal": {
        "source": "apache",
        "extensions": [
            "p",
            "pas"
        ]
    },
    "text/x-processing": {
        "compressible": true,
        "extensions": [
            "pde"
        ]
    },
    "text/x-sass": {
        "extensions": [
            "sass"
        ]
    },
    "text/x-scss": {
        "extensions": [
            "scss"
        ]
    },
    "text/x-setext": {
        "source": "apache",
        "extensions": [
            "etx"
        ]
    },
    "text/x-sfv": {
        "source": "apache",
        "extensions": [
            "sfv"
        ]
    },
    "text/x-suse-ymp": {
        "compressible": true,
        "extensions": [
            "ymp"
        ]
    },
    "text/x-uuencode": {
        "source": "apache",
        "extensions": [
            "uu"
        ]
    },
    "text/x-vcalendar": {
        "source": "apache",
        "extensions": [
            "vcs"
        ]
    },
    "text/x-vcard": {
        "source": "apache",
        "extensions": [
            "vcf"
        ]
    },
    "text/xml": {
        "source": "iana",
        "compressible": true,
        "extensions": [
            "xml"
        ]
    },
    "text/xml-external-parsed-entity": {
        "source": "iana"
    },
    "text/yaml": {
        "compressible": true,
        "extensions": [
            "yaml",
            "yml"
        ]
    },
    "video/1d-interleaved-parityfec": {
        "source": "iana"
    },
    "video/3gpp": {
        "source": "iana",
        "extensions": [
            "3gp",
            "3gpp"
        ]
    },
    "video/3gpp-tt": {
        "source": "iana"
    },
    "video/3gpp2": {
        "source": "iana",
        "extensions": [
            "3g2"
        ]
    },
    "video/av1": {
        "source": "iana"
    },
    "video/bmpeg": {
        "source": "iana"
    },
    "video/bt656": {
        "source": "iana"
    },
    "video/celb": {
        "source": "iana"
    },
    "video/dv": {
        "source": "iana"
    },
    "video/encaprtp": {
        "source": "iana"
    },
    "video/ffv1": {
        "source": "iana"
    },
    "video/flexfec": {
        "source": "iana"
    },
    "video/h261": {
        "source": "iana",
        "extensions": [
            "h261"
        ]
    },
    "video/h263": {
        "source": "iana",
        "extensions": [
            "h263"
        ]
    },
    "video/h263-1998": {
        "source": "iana"
    },
    "video/h263-2000": {
        "source": "iana"
    },
    "video/h264": {
        "source": "iana",
        "extensions": [
            "h264"
        ]
    },
    "video/h264-rcdo": {
        "source": "iana"
    },
    "video/h264-svc": {
        "source": "iana"
    },
    "video/h265": {
        "source": "iana"
    },
    "video/iso.segment": {
        "source": "iana",
        "extensions": [
            "m4s"
        ]
    },
    "video/jpeg": {
        "source": "iana",
        "extensions": [
            "jpgv"
        ]
    },
    "video/jpeg2000": {
        "source": "iana"
    },
    "video/jpm": {
        "source": "apache",
        "extensions": [
            "jpm",
            "jpgm"
        ]
    },
    "video/jxsv": {
        "source": "iana"
    },
    "video/mj2": {
        "source": "iana",
        "extensions": [
            "mj2",
            "mjp2"
        ]
    },
    "video/mp1s": {
        "source": "iana"
    },
    "video/mp2p": {
        "source": "iana"
    },
    "video/mp2t": {
        "source": "iana",
        "extensions": [
            "ts"
        ]
    },
    "video/mp4": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "mp4",
            "mp4v",
            "mpg4"
        ]
    },
    "video/mp4v-es": {
        "source": "iana"
    },
    "video/mpeg": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "mpeg",
            "mpg",
            "mpe",
            "m1v",
            "m2v"
        ]
    },
    "video/mpeg4-generic": {
        "source": "iana"
    },
    "video/mpv": {
        "source": "iana"
    },
    "video/nv": {
        "source": "iana"
    },
    "video/ogg": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "ogv"
        ]
    },
    "video/parityfec": {
        "source": "iana"
    },
    "video/pointer": {
        "source": "iana"
    },
    "video/quicktime": {
        "source": "iana",
        "compressible": false,
        "extensions": [
            "qt",
            "mov"
        ]
    },
    "video/raptorfec": {
        "source": "iana"
    },
    "video/raw": {
        "source": "iana"
    },
    "video/rtp-enc-aescm128": {
        "source": "iana"
    },
    "video/rtploopback": {
        "source": "iana"
    },
    "video/rtx": {
        "source": "iana"
    },
    "video/scip": {
        "source": "iana"
    },
    "video/smpte291": {
        "source": "iana"
    },
    "video/smpte292m": {
        "source": "iana"
    },
    "video/ulpfec": {
        "source": "iana"
    },
    "video/vc1": {
        "source": "iana"
    },
    "video/vc2": {
        "source": "iana"
    },
    "video/vnd.cctv": {
        "source": "iana"
    },
    "video/vnd.dece.hd": {
        "source": "iana",
        "extensions": [
            "uvh",
            "uvvh"
        ]
    },
    "video/vnd.dece.mobile": {
        "source": "iana",
        "extensions": [
            "uvm",
            "uvvm"
        ]
    },
    "video/vnd.dece.mp4": {
        "source": "iana"
    },
    "video/vnd.dece.pd": {
        "source": "iana",
        "extensions": [
            "uvp",
            "uvvp"
        ]
    },
    "video/vnd.dece.sd": {
        "source": "iana",
        "extensions": [
            "uvs",
            "uvvs"
        ]
    },
    "video/vnd.dece.video": {
        "source": "iana",
        "extensions": [
            "uvv",
            "uvvv"
        ]
    },
    "video/vnd.directv.mpeg": {
        "source": "iana"
    },
    "video/vnd.directv.mpeg-tts": {
        "source": "iana"
    },
    "video/vnd.dlna.mpeg-tts": {
        "source": "iana"
    },
    "video/vnd.dvb.file": {
        "source": "iana",
        "extensions": [
            "dvb"
        ]
    },
    "video/vnd.fvt": {
        "source": "iana",
        "extensions": [
            "fvt"
        ]
    },
    "video/vnd.hns.video": {
        "source": "iana"
    },
    "video/vnd.iptvforum.1dparityfec-1010": {
        "source": "iana"
    },
    "video/vnd.iptvforum.1dparityfec-2005": {
        "source": "iana"
    },
    "video/vnd.iptvforum.2dparityfec-1010": {
        "source": "iana"
    },
    "video/vnd.iptvforum.2dparityfec-2005": {
        "source": "iana"
    },
    "video/vnd.iptvforum.ttsavc": {
        "source": "iana"
    },
    "video/vnd.iptvforum.ttsmpeg2": {
        "source": "iana"
    },
    "video/vnd.motorola.video": {
        "source": "iana"
    },
    "video/vnd.motorola.videop": {
        "source": "iana"
    },
    "video/vnd.mpegurl": {
        "source": "iana",
        "extensions": [
            "mxu",
            "m4u"
        ]
    },
    "video/vnd.ms-playready.media.pyv": {
        "source": "iana",
        "extensions": [
            "pyv"
        ]
    },
    "video/vnd.nokia.interleaved-multimedia": {
        "source": "iana"
    },
    "video/vnd.nokia.mp4vr": {
        "source": "iana"
    },
    "video/vnd.nokia.videovoip": {
        "source": "iana"
    },
    "video/vnd.objectvideo": {
        "source": "iana"
    },
    "video/vnd.radgamettools.bink": {
        "source": "iana"
    },
    "video/vnd.radgamettools.smacker": {
        "source": "iana"
    },
    "video/vnd.sealed.mpeg1": {
        "source": "iana"
    },
    "video/vnd.sealed.mpeg4": {
        "source": "iana"
    },
    "video/vnd.sealed.swf": {
        "source": "iana"
    },
    "video/vnd.sealedmedia.softseal.mov": {
        "source": "iana"
    },
    "video/vnd.uvvu.mp4": {
        "source": "iana",
        "extensions": [
            "uvu",
            "uvvu"
        ]
    },
    "video/vnd.vivo": {
        "source": "iana",
        "extensions": [
            "viv"
        ]
    },
    "video/vnd.youtube.yt": {
        "source": "iana"
    },
    "video/vp8": {
        "source": "iana"
    },
    "video/vp9": {
        "source": "iana"
    },
    "video/webm": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "webm"
        ]
    },
    "video/x-f4v": {
        "source": "apache",
        "extensions": [
            "f4v"
        ]
    },
    "video/x-fli": {
        "source": "apache",
        "extensions": [
            "fli"
        ]
    },
    "video/x-flv": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "flv"
        ]
    },
    "video/x-m4v": {
        "source": "apache",
        "extensions": [
            "m4v"
        ]
    },
    "video/x-matroska": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "mkv",
            "mk3d",
            "mks"
        ]
    },
    "video/x-mng": {
        "source": "apache",
        "extensions": [
            "mng"
        ]
    },
    "video/x-ms-asf": {
        "source": "apache",
        "extensions": [
            "asf",
            "asx"
        ]
    },
    "video/x-ms-vob": {
        "source": "apache",
        "extensions": [
            "vob"
        ]
    },
    "video/x-ms-wm": {
        "source": "apache",
        "extensions": [
            "wm"
        ]
    },
    "video/x-ms-wmv": {
        "source": "apache",
        "compressible": false,
        "extensions": [
            "wmv"
        ]
    },
    "video/x-ms-wmx": {
        "source": "apache",
        "extensions": [
            "wmx"
        ]
    },
    "video/x-ms-wvx": {
        "source": "apache",
        "extensions": [
            "wvx"
        ]
    },
    "video/x-msvideo": {
        "source": "apache",
        "extensions": [
            "avi"
        ]
    },
    "video/x-sgi-movie": {
        "source": "apache",
        "extensions": [
            "movie"
        ]
    },
    "video/x-smv": {
        "source": "apache",
        "extensions": [
            "smv"
        ]
    },
    "x-conference/x-cooltalk": {
        "source": "apache",
        "extensions": [
            "ice"
        ]
    },
    "x-shader/x-fragment": {
        "compressible": true
    },
    "x-shader/x-vertex": {
        "compressible": true
    }
};
const types = new Map();
(function populateMaps() {
    const preference = [
        "nginx",
        "apache",
        undefined,
        "iana"
    ];
    for (const type of Object.keys(__default)){
        const mime = __default[type];
        const exts = mime.extensions;
        if (!exts || !exts.length) {
            continue;
        }
        extensions.set(type, exts);
        for (const ext of exts){
            const current = types.get(ext);
            if (current) {
                const from = preference.indexOf(__default[current].source);
                const to = preference.indexOf(mime.source);
                if (current !== "application/octet-stream" && (from > to || from === to && current.startsWith("application/"))) {
                    continue;
                }
            }
            types.set(ext, type);
        }
    }
})();
function typeByExtension(extension) {
    extension = extension.startsWith(".") ? extension.slice(1) : extension;
    return types.get(extension.toLowerCase());
}
function getCharset(type) {
    try {
        const [mediaType, params] = parseMediaType1(type);
        if (params && params["charset"]) {
            return params["charset"];
        }
        const entry = __default[mediaType];
        if (entry && entry.charset) {
            return entry.charset;
        }
        if (mediaType.startsWith("text/")) {
            return "UTF-8";
        }
    } catch  {}
    return undefined;
}
function formatMediaType(type, param) {
    let b = "";
    const [major, sub] = type.split("/");
    if (!sub) {
        if (!isToken(type)) {
            return "";
        }
        b += type.toLowerCase();
    } else {
        if (!isToken(major) || !isToken(sub)) {
            return "";
        }
        b += `${major.toLowerCase()}/${sub.toLowerCase()}`;
    }
    if (param) {
        param = isIterator(param) ? Object.fromEntries(param) : param;
        const attrs = Object.keys(param);
        attrs.sort();
        for (const attribute of attrs){
            if (!isToken(attribute)) {
                return "";
            }
            const value = param[attribute];
            b += `; ${attribute.toLowerCase()}`;
            const needEnc = needsEncoding(value);
            if (needEnc) {
                b += "*";
            }
            b += "=";
            if (needEnc) {
                b += `utf-8''${encodeURIComponent(value)}`;
                continue;
            }
            if (isToken(value)) {
                b += value;
                continue;
            }
            b += `"${value.replace(/["\\]/gi, (m)=>`\\${m}`)}"`;
        }
    }
    return b;
}
function contentType(extensionOrType) {
    try {
        const [mediaType, params = {}] = extensionOrType.includes("/") ? parseMediaType1(extensionOrType) : [
            typeByExtension(extensionOrType),
            undefined
        ];
        if (!mediaType) {
            return undefined;
        }
        if (!("charset" in params)) {
            const charset = getCharset(mediaType);
            if (charset) {
                params.charset = charset;
            }
        }
        return formatMediaType(mediaType, params);
    } catch  {}
    return undefined;
}
function extensionsByType(type) {
    try {
        const [mediaType] = parseMediaType1(type);
        return extensions.get(mediaType);
    } catch  {}
}
function extension(type) {
    const exts = extensionsByType(type);
    if (exts) {
        return exts[0];
    }
    return undefined;
}
const MAX_SIZE1 = 2 ** 32 - 2;
class Buffer1 {
    #buf;
    #off = 0;
    #readable = new ReadableStream({
        type: "bytes",
        pull: (controller)=>{
            const view = new Uint8Array(controller.byobRequest.view.buffer);
            if (this.empty()) {
                this.reset();
                controller.close();
                controller.byobRequest.respond(0);
                return;
            }
            const nread = copy(this.#buf.subarray(this.#off), view);
            this.#off += nread;
            controller.byobRequest.respond(nread);
        },
        autoAllocateChunkSize: 16_640
    });
    get readable() {
        return this.#readable;
    }
    #writable = new WritableStream({
        write: (chunk)=>{
            const m = this.#grow(chunk.byteLength);
            copy(chunk, this.#buf, m);
        }
    });
    get writable() {
        return this.#writable;
    }
    constructor(ab){
        this.#buf = ab === undefined ? new Uint8Array(0) : new Uint8Array(ab);
    }
    bytes(options = {
        copy: true
    }) {
        if (options.copy === false) return this.#buf.subarray(this.#off);
        return this.#buf.slice(this.#off);
    }
    empty() {
        return this.#buf.byteLength <= this.#off;
    }
    get length() {
        return this.#buf.byteLength - this.#off;
    }
    get capacity() {
        return this.#buf.buffer.byteLength;
    }
    truncate(n) {
        if (n === 0) {
            this.reset();
            return;
        }
        if (n < 0 || n > this.length) {
            throw Error("bytes.Buffer: truncation out of range");
        }
        this.#reslice(this.#off + n);
    }
    reset() {
        this.#reslice(0);
        this.#off = 0;
    }
    #tryGrowByReslice(n2) {
        const l = this.#buf.byteLength;
        if (n2 <= this.capacity - l) {
            this.#reslice(l + n2);
            return l;
        }
        return -1;
    }
    #reslice(len1) {
        assert(len1 <= this.#buf.buffer.byteLength);
        this.#buf = new Uint8Array(this.#buf.buffer, 0, len1);
    }
    #grow(n11) {
        const m = this.length;
        if (m === 0 && this.#off !== 0) {
            this.reset();
        }
        const i = this.#tryGrowByReslice(n11);
        if (i >= 0) {
            return i;
        }
        const c = this.capacity;
        if (n11 <= Math.floor(c / 2) - m) {
            copy(this.#buf.subarray(this.#off), this.#buf);
        } else if (c + n11 > MAX_SIZE1) {
            throw new Error("The buffer cannot be grown beyond the maximum size.");
        } else {
            const buf = new Uint8Array(Math.min(2 * c + n11, MAX_SIZE1));
            copy(this.#buf.subarray(this.#off), buf);
            this.#buf = buf;
        }
        this.#off = 0;
        this.#reslice(Math.min(m + n11, MAX_SIZE1));
        return m;
    }
    grow(n) {
        if (n < 0) {
            throw Error("Buffer.grow: negative count");
        }
        const m = this.#grow(n);
        this.#reslice(m);
    }
}
function createLPS(pat) {
    const lps = new Uint8Array(pat.length);
    lps[0] = 0;
    let prefixEnd = 0;
    let i = 1;
    while(i < lps.length){
        if (pat[i] == pat[prefixEnd]) {
            prefixEnd++;
            lps[i] = prefixEnd;
            i++;
        } else if (prefixEnd === 0) {
            lps[i] = 0;
            i++;
        } else {
            prefixEnd = lps[prefixEnd - 1];
        }
    }
    return lps;
}
class DelimiterStream extends TransformStream {
    #bufs = new BytesList();
    #delimiter;
    #inspectIndex = 0;
    #matchIndex = 0;
    #delimLen;
    #delimLPS;
    #disp;
    constructor(delimiter, options){
        super({
            transform: (chunk, controller)=>{
                this.#handle(chunk, controller);
            },
            flush: (controller)=>{
                controller.enqueue(this.#bufs.concat());
            }
        });
        this.#delimiter = delimiter;
        this.#delimLen = delimiter.length;
        this.#delimLPS = createLPS(delimiter);
        this.#disp = options?.disposition ?? "discard";
    }
    #handle(chunk, controller) {
        this.#bufs.add(chunk);
        let localIndex = 0;
        while(this.#inspectIndex < this.#bufs.size()){
            if (chunk[localIndex] === this.#delimiter[this.#matchIndex]) {
                this.#inspectIndex++;
                localIndex++;
                this.#matchIndex++;
                if (this.#matchIndex === this.#delimLen) {
                    const start = this.#inspectIndex - this.#delimLen;
                    const end = this.#disp == "suffix" ? this.#inspectIndex : start;
                    const copy = this.#bufs.slice(0, end);
                    controller.enqueue(copy);
                    const shift = this.#disp == "prefix" ? start : this.#inspectIndex;
                    this.#bufs.shift(shift);
                    this.#inspectIndex = this.#disp == "prefix" ? this.#delimLen : 0;
                    this.#matchIndex = 0;
                }
            } else {
                if (this.#matchIndex === 0) {
                    this.#inspectIndex++;
                    localIndex++;
                } else {
                    this.#matchIndex = this.#delimLPS[this.#matchIndex - 1];
                }
            }
        }
    }
}
async function readAll(r) {
    const buf = new Buffer();
    await buf.readFrom(r);
    return buf.bytes();
}
async function writeAll(w, arr) {
    let nwritten = 0;
    while(nwritten < arr.length){
        nwritten += await w.write(arr.subarray(nwritten));
    }
}
function readerFromStreamReader(streamReader) {
    const buffer = new Buffer();
    return {
        async read (p) {
            if (buffer.empty()) {
                const res = await streamReader.read();
                if (res.done) {
                    return null;
                }
                await writeAll(buffer, res.value);
            }
            return buffer.read(p);
        }
    };
}
const osType = (()=>{
    const { Deno: Deno1  } = globalThis;
    if (typeof Deno1?.build?.os === "string") {
        return Deno1.build.os;
    }
    const { navigator  } = globalThis;
    if (navigator?.appVersion?.includes?.("Win")) {
        return "windows";
    }
    return "linux";
})();
const isWindows = osType === "windows";
const CHAR_FORWARD_SLASH = 47;
function assertPath(path) {
    if (typeof path !== "string") {
        throw new TypeError(`Path must be a string. Received ${JSON.stringify(path)}`);
    }
}
function isPosixPathSeparator(code) {
    return code === 47;
}
function isPathSeparator(code) {
    return isPosixPathSeparator(code) || code === 92;
}
function isWindowsDeviceRoot(code) {
    return code >= 97 && code <= 122 || code >= 65 && code <= 90;
}
function normalizeString(path, allowAboveRoot, separator, isPathSeparator) {
    let res = "";
    let lastSegmentLength = 0;
    let lastSlash = -1;
    let dots = 0;
    let code;
    for(let i = 0, len = path.length; i <= len; ++i){
        if (i < len) code = path.charCodeAt(i);
        else if (isPathSeparator(code)) break;
        else code = CHAR_FORWARD_SLASH;
        if (isPathSeparator(code)) {
            if (lastSlash === i - 1 || dots === 1) {} else if (lastSlash !== i - 1 && dots === 2) {
                if (res.length < 2 || lastSegmentLength !== 2 || res.charCodeAt(res.length - 1) !== 46 || res.charCodeAt(res.length - 2) !== 46) {
                    if (res.length > 2) {
                        const lastSlashIndex = res.lastIndexOf(separator);
                        if (lastSlashIndex === -1) {
                            res = "";
                            lastSegmentLength = 0;
                        } else {
                            res = res.slice(0, lastSlashIndex);
                            lastSegmentLength = res.length - 1 - res.lastIndexOf(separator);
                        }
                        lastSlash = i;
                        dots = 0;
                        continue;
                    } else if (res.length === 2 || res.length === 1) {
                        res = "";
                        lastSegmentLength = 0;
                        lastSlash = i;
                        dots = 0;
                        continue;
                    }
                }
                if (allowAboveRoot) {
                    if (res.length > 0) res += `${separator}..`;
                    else res = "..";
                    lastSegmentLength = 2;
                }
            } else {
                if (res.length > 0) res += separator + path.slice(lastSlash + 1, i);
                else res = path.slice(lastSlash + 1, i);
                lastSegmentLength = i - lastSlash - 1;
            }
            lastSlash = i;
            dots = 0;
        } else if (code === 46 && dots !== -1) {
            ++dots;
        } else {
            dots = -1;
        }
    }
    return res;
}
function _format(sep, pathObject) {
    const dir = pathObject.dir || pathObject.root;
    const base = pathObject.base || (pathObject.name || "") + (pathObject.ext || "");
    if (!dir) return base;
    if (base === sep) return dir;
    if (dir === pathObject.root) return dir + base;
    return dir + sep + base;
}
const WHITESPACE_ENCODINGS = {
    "\u0009": "%09",
    "\u000A": "%0A",
    "\u000B": "%0B",
    "\u000C": "%0C",
    "\u000D": "%0D",
    "\u0020": "%20"
};
function encodeWhitespace(string) {
    return string.replaceAll(/[\s]/g, (c)=>{
        return WHITESPACE_ENCODINGS[c] ?? c;
    });
}
function lastPathSegment(path, isSep, start = 0) {
    let matchedNonSeparator = false;
    let end = path.length;
    for(let i = path.length - 1; i >= start; --i){
        if (isSep(path.charCodeAt(i))) {
            if (matchedNonSeparator) {
                start = i + 1;
                break;
            }
        } else if (!matchedNonSeparator) {
            matchedNonSeparator = true;
            end = i + 1;
        }
    }
    return path.slice(start, end);
}
function stripTrailingSeparators(segment, isSep) {
    if (segment.length <= 1) {
        return segment;
    }
    let end = segment.length;
    for(let i = segment.length - 1; i > 0; i--){
        if (isSep(segment.charCodeAt(i))) {
            end = i;
        } else {
            break;
        }
    }
    return segment.slice(0, end);
}
function stripSuffix(name, suffix) {
    if (suffix.length >= name.length) {
        return name;
    }
    const lenDiff = name.length - suffix.length;
    for(let i = suffix.length - 1; i >= 0; --i){
        if (name.charCodeAt(lenDiff + i) !== suffix.charCodeAt(i)) {
            return name;
        }
    }
    return name.slice(0, -suffix.length);
}
const sep = "\\";
const delimiter = ";";
function resolve(...pathSegments) {
    let resolvedDevice = "";
    let resolvedTail = "";
    let resolvedAbsolute = false;
    for(let i = pathSegments.length - 1; i >= -1; i--){
        let path;
        const { Deno: Deno1  } = globalThis;
        if (i >= 0) {
            path = pathSegments[i];
        } else if (!resolvedDevice) {
            if (typeof Deno1?.cwd !== "function") {
                throw new TypeError("Resolved a drive-letter-less path without a CWD.");
            }
            path = Deno1.cwd();
        } else {
            if (typeof Deno1?.env?.get !== "function" || typeof Deno1?.cwd !== "function") {
                throw new TypeError("Resolved a relative path without a CWD.");
            }
            path = Deno1.cwd();
            if (path === undefined || path.slice(0, 3).toLowerCase() !== `${resolvedDevice.toLowerCase()}\\`) {
                path = `${resolvedDevice}\\`;
            }
        }
        assertPath(path);
        const len = path.length;
        if (len === 0) continue;
        let rootEnd = 0;
        let device = "";
        let isAbsolute = false;
        const code = path.charCodeAt(0);
        if (len > 1) {
            if (isPathSeparator(code)) {
                isAbsolute = true;
                if (isPathSeparator(path.charCodeAt(1))) {
                    let j = 2;
                    let last = j;
                    for(; j < len; ++j){
                        if (isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        const firstPart = path.slice(last, j);
                        last = j;
                        for(; j < len; ++j){
                            if (!isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j < len && j !== last) {
                            last = j;
                            for(; j < len; ++j){
                                if (isPathSeparator(path.charCodeAt(j))) break;
                            }
                            if (j === len) {
                                device = `\\\\${firstPart}\\${path.slice(last)}`;
                                rootEnd = j;
                            } else if (j !== last) {
                                device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                                rootEnd = j;
                            }
                        }
                    }
                } else {
                    rootEnd = 1;
                }
            } else if (isWindowsDeviceRoot(code)) {
                if (path.charCodeAt(1) === 58) {
                    device = path.slice(0, 2);
                    rootEnd = 2;
                    if (len > 2) {
                        if (isPathSeparator(path.charCodeAt(2))) {
                            isAbsolute = true;
                            rootEnd = 3;
                        }
                    }
                }
            }
        } else if (isPathSeparator(code)) {
            rootEnd = 1;
            isAbsolute = true;
        }
        if (device.length > 0 && resolvedDevice.length > 0 && device.toLowerCase() !== resolvedDevice.toLowerCase()) {
            continue;
        }
        if (resolvedDevice.length === 0 && device.length > 0) {
            resolvedDevice = device;
        }
        if (!resolvedAbsolute) {
            resolvedTail = `${path.slice(rootEnd)}\\${resolvedTail}`;
            resolvedAbsolute = isAbsolute;
        }
        if (resolvedAbsolute && resolvedDevice.length > 0) break;
    }
    resolvedTail = normalizeString(resolvedTail, !resolvedAbsolute, "\\", isPathSeparator);
    return resolvedDevice + (resolvedAbsolute ? "\\" : "") + resolvedTail || ".";
}
function normalize(path) {
    assertPath(path);
    const len = path.length;
    if (len === 0) return ".";
    let rootEnd = 0;
    let device;
    let isAbsolute = false;
    const code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator(code)) {
            isAbsolute = true;
            if (isPathSeparator(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    const firstPart = path.slice(last, j);
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            return `\\\\${firstPart}\\${path.slice(last)}\\`;
                        } else if (j !== last) {
                            device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                            rootEnd = j;
                        }
                    }
                }
            } else {
                rootEnd = 1;
            }
        } else if (isWindowsDeviceRoot(code)) {
            if (path.charCodeAt(1) === 58) {
                device = path.slice(0, 2);
                rootEnd = 2;
                if (len > 2) {
                    if (isPathSeparator(path.charCodeAt(2))) {
                        isAbsolute = true;
                        rootEnd = 3;
                    }
                }
            }
        }
    } else if (isPathSeparator(code)) {
        return "\\";
    }
    let tail;
    if (rootEnd < len) {
        tail = normalizeString(path.slice(rootEnd), !isAbsolute, "\\", isPathSeparator);
    } else {
        tail = "";
    }
    if (tail.length === 0 && !isAbsolute) tail = ".";
    if (tail.length > 0 && isPathSeparator(path.charCodeAt(len - 1))) {
        tail += "\\";
    }
    if (device === undefined) {
        if (isAbsolute) {
            if (tail.length > 0) return `\\${tail}`;
            else return "\\";
        } else if (tail.length > 0) {
            return tail;
        } else {
            return "";
        }
    } else if (isAbsolute) {
        if (tail.length > 0) return `${device}\\${tail}`;
        else return `${device}\\`;
    } else if (tail.length > 0) {
        return device + tail;
    } else {
        return device;
    }
}
function isAbsolute(path) {
    assertPath(path);
    const len = path.length;
    if (len === 0) return false;
    const code = path.charCodeAt(0);
    if (isPathSeparator(code)) {
        return true;
    } else if (isWindowsDeviceRoot(code)) {
        if (len > 2 && path.charCodeAt(1) === 58) {
            if (isPathSeparator(path.charCodeAt(2))) return true;
        }
    }
    return false;
}
function join(...paths) {
    const pathsCount = paths.length;
    if (pathsCount === 0) return ".";
    let joined;
    let firstPart = null;
    for(let i = 0; i < pathsCount; ++i){
        const path = paths[i];
        assertPath(path);
        if (path.length > 0) {
            if (joined === undefined) joined = firstPart = path;
            else joined += `\\${path}`;
        }
    }
    if (joined === undefined) return ".";
    let needsReplace = true;
    let slashCount = 0;
    assert(firstPart != null);
    if (isPathSeparator(firstPart.charCodeAt(0))) {
        ++slashCount;
        const firstLen = firstPart.length;
        if (firstLen > 1) {
            if (isPathSeparator(firstPart.charCodeAt(1))) {
                ++slashCount;
                if (firstLen > 2) {
                    if (isPathSeparator(firstPart.charCodeAt(2))) ++slashCount;
                    else {
                        needsReplace = false;
                    }
                }
            }
        }
    }
    if (needsReplace) {
        for(; slashCount < joined.length; ++slashCount){
            if (!isPathSeparator(joined.charCodeAt(slashCount))) break;
        }
        if (slashCount >= 2) joined = `\\${joined.slice(slashCount)}`;
    }
    return normalize(joined);
}
function relative(from, to) {
    assertPath(from);
    assertPath(to);
    if (from === to) return "";
    const fromOrig = resolve(from);
    const toOrig = resolve(to);
    if (fromOrig === toOrig) return "";
    from = fromOrig.toLowerCase();
    to = toOrig.toLowerCase();
    if (from === to) return "";
    let fromStart = 0;
    let fromEnd = from.length;
    for(; fromStart < fromEnd; ++fromStart){
        if (from.charCodeAt(fromStart) !== 92) break;
    }
    for(; fromEnd - 1 > fromStart; --fromEnd){
        if (from.charCodeAt(fromEnd - 1) !== 92) break;
    }
    const fromLen = fromEnd - fromStart;
    let toStart = 0;
    let toEnd = to.length;
    for(; toStart < toEnd; ++toStart){
        if (to.charCodeAt(toStart) !== 92) break;
    }
    for(; toEnd - 1 > toStart; --toEnd){
        if (to.charCodeAt(toEnd - 1) !== 92) break;
    }
    const toLen = toEnd - toStart;
    const length = fromLen < toLen ? fromLen : toLen;
    let lastCommonSep = -1;
    let i = 0;
    for(; i <= length; ++i){
        if (i === length) {
            if (toLen > length) {
                if (to.charCodeAt(toStart + i) === 92) {
                    return toOrig.slice(toStart + i + 1);
                } else if (i === 2) {
                    return toOrig.slice(toStart + i);
                }
            }
            if (fromLen > length) {
                if (from.charCodeAt(fromStart + i) === 92) {
                    lastCommonSep = i;
                } else if (i === 2) {
                    lastCommonSep = 3;
                }
            }
            break;
        }
        const fromCode = from.charCodeAt(fromStart + i);
        const toCode = to.charCodeAt(toStart + i);
        if (fromCode !== toCode) break;
        else if (fromCode === 92) lastCommonSep = i;
    }
    if (i !== length && lastCommonSep === -1) {
        return toOrig;
    }
    let out = "";
    if (lastCommonSep === -1) lastCommonSep = 0;
    for(i = fromStart + lastCommonSep + 1; i <= fromEnd; ++i){
        if (i === fromEnd || from.charCodeAt(i) === 92) {
            if (out.length === 0) out += "..";
            else out += "\\..";
        }
    }
    if (out.length > 0) {
        return out + toOrig.slice(toStart + lastCommonSep, toEnd);
    } else {
        toStart += lastCommonSep;
        if (toOrig.charCodeAt(toStart) === 92) ++toStart;
        return toOrig.slice(toStart, toEnd);
    }
}
function toNamespacedPath(path) {
    if (typeof path !== "string") return path;
    if (path.length === 0) return "";
    const resolvedPath = resolve(path);
    if (resolvedPath.length >= 3) {
        if (resolvedPath.charCodeAt(0) === 92) {
            if (resolvedPath.charCodeAt(1) === 92) {
                const code = resolvedPath.charCodeAt(2);
                if (code !== 63 && code !== 46) {
                    return `\\\\?\\UNC\\${resolvedPath.slice(2)}`;
                }
            }
        } else if (isWindowsDeviceRoot(resolvedPath.charCodeAt(0))) {
            if (resolvedPath.charCodeAt(1) === 58 && resolvedPath.charCodeAt(2) === 92) {
                return `\\\\?\\${resolvedPath}`;
            }
        }
    }
    return path;
}
function dirname(path) {
    assertPath(path);
    const len = path.length;
    if (len === 0) return ".";
    let rootEnd = -1;
    let end = -1;
    let matchedSlash = true;
    let offset = 0;
    const code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator(code)) {
            rootEnd = offset = 1;
            if (isPathSeparator(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            return path;
                        }
                        if (j !== last) {
                            rootEnd = offset = j + 1;
                        }
                    }
                }
            }
        } else if (isWindowsDeviceRoot(code)) {
            if (path.charCodeAt(1) === 58) {
                rootEnd = offset = 2;
                if (len > 2) {
                    if (isPathSeparator(path.charCodeAt(2))) rootEnd = offset = 3;
                }
            }
        }
    } else if (isPathSeparator(code)) {
        return path;
    }
    for(let i = len - 1; i >= offset; --i){
        if (isPathSeparator(path.charCodeAt(i))) {
            if (!matchedSlash) {
                end = i;
                break;
            }
        } else {
            matchedSlash = false;
        }
    }
    if (end === -1) {
        if (rootEnd === -1) return ".";
        else end = rootEnd;
    }
    return stripTrailingSeparators(path.slice(0, end), isPosixPathSeparator);
}
function basename(path, suffix = "") {
    assertPath(path);
    if (path.length === 0) return path;
    if (typeof suffix !== "string") {
        throw new TypeError(`Suffix must be a string. Received ${JSON.stringify(suffix)}`);
    }
    let start = 0;
    if (path.length >= 2) {
        const drive = path.charCodeAt(0);
        if (isWindowsDeviceRoot(drive)) {
            if (path.charCodeAt(1) === 58) start = 2;
        }
    }
    const lastSegment = lastPathSegment(path, isPathSeparator, start);
    const strippedSegment = stripTrailingSeparators(lastSegment, isPathSeparator);
    return suffix ? stripSuffix(strippedSegment, suffix) : strippedSegment;
}
function extname(path) {
    assertPath(path);
    let start = 0;
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let preDotState = 0;
    if (path.length >= 2 && path.charCodeAt(1) === 58 && isWindowsDeviceRoot(path.charCodeAt(0))) {
        start = startPart = 2;
    }
    for(let i = path.length - 1; i >= start; --i){
        const code = path.charCodeAt(i);
        if (isPathSeparator(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        return "";
    }
    return path.slice(startDot, end);
}
function format(pathObject) {
    if (pathObject === null || typeof pathObject !== "object") {
        throw new TypeError(`The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`);
    }
    return _format("\\", pathObject);
}
function parse(path) {
    assertPath(path);
    const ret = {
        root: "",
        dir: "",
        base: "",
        ext: "",
        name: ""
    };
    const len = path.length;
    if (len === 0) return ret;
    let rootEnd = 0;
    let code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator(code)) {
            rootEnd = 1;
            if (isPathSeparator(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            rootEnd = j;
                        } else if (j !== last) {
                            rootEnd = j + 1;
                        }
                    }
                }
            }
        } else if (isWindowsDeviceRoot(code)) {
            if (path.charCodeAt(1) === 58) {
                rootEnd = 2;
                if (len > 2) {
                    if (isPathSeparator(path.charCodeAt(2))) {
                        if (len === 3) {
                            ret.root = ret.dir = path;
                            ret.base = "\\";
                            return ret;
                        }
                        rootEnd = 3;
                    }
                } else {
                    ret.root = ret.dir = path;
                    return ret;
                }
            }
        }
    } else if (isPathSeparator(code)) {
        ret.root = ret.dir = path;
        ret.base = "\\";
        return ret;
    }
    if (rootEnd > 0) ret.root = path.slice(0, rootEnd);
    let startDot = -1;
    let startPart = rootEnd;
    let end = -1;
    let matchedSlash = true;
    let i = path.length - 1;
    let preDotState = 0;
    for(; i >= rootEnd; --i){
        code = path.charCodeAt(i);
        if (isPathSeparator(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        if (end !== -1) {
            ret.base = ret.name = path.slice(startPart, end);
        }
    } else {
        ret.name = path.slice(startPart, startDot);
        ret.base = path.slice(startPart, end);
        ret.ext = path.slice(startDot, end);
    }
    ret.base = ret.base || "\\";
    if (startPart > 0 && startPart !== rootEnd) {
        ret.dir = path.slice(0, startPart - 1);
    } else ret.dir = ret.root;
    return ret;
}
function fromFileUrl(url) {
    url = url instanceof URL ? url : new URL(url);
    if (url.protocol != "file:") {
        throw new TypeError("Must be a file URL.");
    }
    let path = decodeURIComponent(url.pathname.replace(/\//g, "\\").replace(/%(?![0-9A-Fa-f]{2})/g, "%25")).replace(/^\\*([A-Za-z]:)(\\|$)/, "$1\\");
    if (url.hostname != "") {
        path = `\\\\${url.hostname}${path}`;
    }
    return path;
}
function toFileUrl(path) {
    if (!isAbsolute(path)) {
        throw new TypeError("Must be an absolute path.");
    }
    const [, hostname, pathname] = path.match(/^(?:[/\\]{2}([^/\\]+)(?=[/\\](?:[^/\\]|$)))?(.*)/);
    const url = new URL("file:///");
    url.pathname = encodeWhitespace(pathname.replace(/%/g, "%25"));
    if (hostname != null && hostname != "localhost") {
        url.hostname = hostname;
        if (!url.hostname) {
            throw new TypeError("Invalid hostname.");
        }
    }
    return url;
}
const mod1 = {
    sep: sep,
    delimiter: delimiter,
    resolve: resolve,
    normalize: normalize,
    isAbsolute: isAbsolute,
    join: join,
    relative: relative,
    toNamespacedPath: toNamespacedPath,
    dirname: dirname,
    basename: basename,
    extname: extname,
    format: format,
    parse: parse,
    fromFileUrl: fromFileUrl,
    toFileUrl: toFileUrl
};
const sep1 = "/";
const delimiter1 = ":";
function resolve1(...pathSegments) {
    let resolvedPath = "";
    let resolvedAbsolute = false;
    for(let i = pathSegments.length - 1; i >= -1 && !resolvedAbsolute; i--){
        let path;
        if (i >= 0) path = pathSegments[i];
        else {
            const { Deno: Deno1  } = globalThis;
            if (typeof Deno1?.cwd !== "function") {
                throw new TypeError("Resolved a relative path without a CWD.");
            }
            path = Deno1.cwd();
        }
        assertPath(path);
        if (path.length === 0) {
            continue;
        }
        resolvedPath = `${path}/${resolvedPath}`;
        resolvedAbsolute = isPosixPathSeparator(path.charCodeAt(0));
    }
    resolvedPath = normalizeString(resolvedPath, !resolvedAbsolute, "/", isPosixPathSeparator);
    if (resolvedAbsolute) {
        if (resolvedPath.length > 0) return `/${resolvedPath}`;
        else return "/";
    } else if (resolvedPath.length > 0) return resolvedPath;
    else return ".";
}
function normalize1(path) {
    assertPath(path);
    if (path.length === 0) return ".";
    const isAbsolute = isPosixPathSeparator(path.charCodeAt(0));
    const trailingSeparator = isPosixPathSeparator(path.charCodeAt(path.length - 1));
    path = normalizeString(path, !isAbsolute, "/", isPosixPathSeparator);
    if (path.length === 0 && !isAbsolute) path = ".";
    if (path.length > 0 && trailingSeparator) path += "/";
    if (isAbsolute) return `/${path}`;
    return path;
}
function isAbsolute1(path) {
    assertPath(path);
    return path.length > 0 && isPosixPathSeparator(path.charCodeAt(0));
}
function join1(...paths) {
    if (paths.length === 0) return ".";
    let joined;
    for(let i = 0, len = paths.length; i < len; ++i){
        const path = paths[i];
        assertPath(path);
        if (path.length > 0) {
            if (!joined) joined = path;
            else joined += `/${path}`;
        }
    }
    if (!joined) return ".";
    return normalize1(joined);
}
function relative1(from, to) {
    assertPath(from);
    assertPath(to);
    if (from === to) return "";
    from = resolve1(from);
    to = resolve1(to);
    if (from === to) return "";
    let fromStart = 1;
    const fromEnd = from.length;
    for(; fromStart < fromEnd; ++fromStart){
        if (!isPosixPathSeparator(from.charCodeAt(fromStart))) break;
    }
    const fromLen = fromEnd - fromStart;
    let toStart = 1;
    const toEnd = to.length;
    for(; toStart < toEnd; ++toStart){
        if (!isPosixPathSeparator(to.charCodeAt(toStart))) break;
    }
    const toLen = toEnd - toStart;
    const length = fromLen < toLen ? fromLen : toLen;
    let lastCommonSep = -1;
    let i = 0;
    for(; i <= length; ++i){
        if (i === length) {
            if (toLen > length) {
                if (isPosixPathSeparator(to.charCodeAt(toStart + i))) {
                    return to.slice(toStart + i + 1);
                } else if (i === 0) {
                    return to.slice(toStart + i);
                }
            } else if (fromLen > length) {
                if (isPosixPathSeparator(from.charCodeAt(fromStart + i))) {
                    lastCommonSep = i;
                } else if (i === 0) {
                    lastCommonSep = 0;
                }
            }
            break;
        }
        const fromCode = from.charCodeAt(fromStart + i);
        const toCode = to.charCodeAt(toStart + i);
        if (fromCode !== toCode) break;
        else if (isPosixPathSeparator(fromCode)) lastCommonSep = i;
    }
    let out = "";
    for(i = fromStart + lastCommonSep + 1; i <= fromEnd; ++i){
        if (i === fromEnd || isPosixPathSeparator(from.charCodeAt(i))) {
            if (out.length === 0) out += "..";
            else out += "/..";
        }
    }
    if (out.length > 0) return out + to.slice(toStart + lastCommonSep);
    else {
        toStart += lastCommonSep;
        if (isPosixPathSeparator(to.charCodeAt(toStart))) ++toStart;
        return to.slice(toStart);
    }
}
function toNamespacedPath1(path) {
    return path;
}
function dirname1(path) {
    if (path.length === 0) return ".";
    let end = -1;
    let matchedNonSeparator = false;
    for(let i = path.length - 1; i >= 1; --i){
        if (isPosixPathSeparator(path.charCodeAt(i))) {
            if (matchedNonSeparator) {
                end = i;
                break;
            }
        } else {
            matchedNonSeparator = true;
        }
    }
    if (end === -1) {
        return isPosixPathSeparator(path.charCodeAt(0)) ? "/" : ".";
    }
    return stripTrailingSeparators(path.slice(0, end), isPosixPathSeparator);
}
function basename1(path, suffix = "") {
    assertPath(path);
    if (path.length === 0) return path;
    if (typeof suffix !== "string") {
        throw new TypeError(`Suffix must be a string. Received ${JSON.stringify(suffix)}`);
    }
    const lastSegment = lastPathSegment(path, isPosixPathSeparator);
    const strippedSegment = stripTrailingSeparators(lastSegment, isPosixPathSeparator);
    return suffix ? stripSuffix(strippedSegment, suffix) : strippedSegment;
}
function extname1(path) {
    assertPath(path);
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let preDotState = 0;
    for(let i = path.length - 1; i >= 0; --i){
        const code = path.charCodeAt(i);
        if (isPosixPathSeparator(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        return "";
    }
    return path.slice(startDot, end);
}
function format1(pathObject) {
    if (pathObject === null || typeof pathObject !== "object") {
        throw new TypeError(`The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`);
    }
    return _format("/", pathObject);
}
function parse1(path) {
    assertPath(path);
    const ret = {
        root: "",
        dir: "",
        base: "",
        ext: "",
        name: ""
    };
    if (path.length === 0) return ret;
    const isAbsolute = isPosixPathSeparator(path.charCodeAt(0));
    let start;
    if (isAbsolute) {
        ret.root = "/";
        start = 1;
    } else {
        start = 0;
    }
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let i = path.length - 1;
    let preDotState = 0;
    for(; i >= start; --i){
        const code = path.charCodeAt(i);
        if (isPosixPathSeparator(code)) {
            if (!matchedSlash) {
                startPart = i + 1;
                break;
            }
            continue;
        }
        if (end === -1) {
            matchedSlash = false;
            end = i + 1;
        }
        if (code === 46) {
            if (startDot === -1) startDot = i;
            else if (preDotState !== 1) preDotState = 1;
        } else if (startDot !== -1) {
            preDotState = -1;
        }
    }
    if (startDot === -1 || end === -1 || preDotState === 0 || preDotState === 1 && startDot === end - 1 && startDot === startPart + 1) {
        if (end !== -1) {
            if (startPart === 0 && isAbsolute) {
                ret.base = ret.name = path.slice(1, end);
            } else {
                ret.base = ret.name = path.slice(startPart, end);
            }
        }
        ret.base = ret.base || "/";
    } else {
        if (startPart === 0 && isAbsolute) {
            ret.name = path.slice(1, startDot);
            ret.base = path.slice(1, end);
        } else {
            ret.name = path.slice(startPart, startDot);
            ret.base = path.slice(startPart, end);
        }
        ret.ext = path.slice(startDot, end);
    }
    if (startPart > 0) {
        ret.dir = stripTrailingSeparators(path.slice(0, startPart - 1), isPosixPathSeparator);
    } else if (isAbsolute) ret.dir = "/";
    return ret;
}
function fromFileUrl1(url) {
    url = url instanceof URL ? url : new URL(url);
    if (url.protocol != "file:") {
        throw new TypeError("Must be a file URL.");
    }
    return decodeURIComponent(url.pathname.replace(/%(?![0-9A-Fa-f]{2})/g, "%25"));
}
function toFileUrl1(path) {
    if (!isAbsolute1(path)) {
        throw new TypeError("Must be an absolute path.");
    }
    const url = new URL("file:///");
    url.pathname = encodeWhitespace(path.replace(/%/g, "%25").replace(/\\/g, "%5C"));
    return url;
}
const mod2 = {
    sep: sep1,
    delimiter: delimiter1,
    resolve: resolve1,
    normalize: normalize1,
    isAbsolute: isAbsolute1,
    join: join1,
    relative: relative1,
    toNamespacedPath: toNamespacedPath1,
    dirname: dirname1,
    basename: basename1,
    extname: extname1,
    format: format1,
    parse: parse1,
    fromFileUrl: fromFileUrl1,
    toFileUrl: toFileUrl1
};
const SEP = isWindows ? "\\" : "/";
const SEP_PATTERN = isWindows ? /[\\/]+/ : /\/+/;
const path = isWindows ? mod1 : mod2;
const { join: join2 , normalize: normalize2  } = path;
const regExpEscapeChars = [
    "!",
    "$",
    "(",
    ")",
    "*",
    "+",
    ".",
    "=",
    "?",
    "[",
    "\\",
    "^",
    "{",
    "|"
];
const rangeEscapeChars = [
    "-",
    "\\",
    "]"
];
function globToRegExp(glob, { extended =true , globstar: globstarOption = true , os =osType , caseInsensitive =false  } = {}) {
    if (glob == "") {
        return /(?!)/;
    }
    const sep = os == "windows" ? "(?:\\\\|/)+" : "/+";
    const sepMaybe = os == "windows" ? "(?:\\\\|/)*" : "/*";
    const seps = os == "windows" ? [
        "\\",
        "/"
    ] : [
        "/"
    ];
    const globstar = os == "windows" ? "(?:[^\\\\/]*(?:\\\\|/|$)+)*" : "(?:[^/]*(?:/|$)+)*";
    const wildcard = os == "windows" ? "[^\\\\/]*" : "[^/]*";
    const escapePrefix = os == "windows" ? "`" : "\\";
    let newLength = glob.length;
    for(; newLength > 1 && seps.includes(glob[newLength - 1]); newLength--);
    glob = glob.slice(0, newLength);
    let regExpString = "";
    for(let j = 0; j < glob.length;){
        let segment = "";
        const groupStack = [];
        let inRange = false;
        let inEscape = false;
        let endsWithSep = false;
        let i = j;
        for(; i < glob.length && !seps.includes(glob[i]); i++){
            if (inEscape) {
                inEscape = false;
                const escapeChars = inRange ? rangeEscapeChars : regExpEscapeChars;
                segment += escapeChars.includes(glob[i]) ? `\\${glob[i]}` : glob[i];
                continue;
            }
            if (glob[i] == escapePrefix) {
                inEscape = true;
                continue;
            }
            if (glob[i] == "[") {
                if (!inRange) {
                    inRange = true;
                    segment += "[";
                    if (glob[i + 1] == "!") {
                        i++;
                        segment += "^";
                    } else if (glob[i + 1] == "^") {
                        i++;
                        segment += "\\^";
                    }
                    continue;
                } else if (glob[i + 1] == ":") {
                    let k = i + 1;
                    let value = "";
                    while(glob[k + 1] != null && glob[k + 1] != ":"){
                        value += glob[k + 1];
                        k++;
                    }
                    if (glob[k + 1] == ":" && glob[k + 2] == "]") {
                        i = k + 2;
                        if (value == "alnum") segment += "\\dA-Za-z";
                        else if (value == "alpha") segment += "A-Za-z";
                        else if (value == "ascii") segment += "\x00-\x7F";
                        else if (value == "blank") segment += "\t ";
                        else if (value == "cntrl") segment += "\x00-\x1F\x7F";
                        else if (value == "digit") segment += "\\d";
                        else if (value == "graph") segment += "\x21-\x7E";
                        else if (value == "lower") segment += "a-z";
                        else if (value == "print") segment += "\x20-\x7E";
                        else if (value == "punct") {
                            segment += "!\"#$%&'()*+,\\-./:;<=>?@[\\\\\\]^_‘{|}~";
                        } else if (value == "space") segment += "\\s\v";
                        else if (value == "upper") segment += "A-Z";
                        else if (value == "word") segment += "\\w";
                        else if (value == "xdigit") segment += "\\dA-Fa-f";
                        continue;
                    }
                }
            }
            if (glob[i] == "]" && inRange) {
                inRange = false;
                segment += "]";
                continue;
            }
            if (inRange) {
                if (glob[i] == "\\") {
                    segment += `\\\\`;
                } else {
                    segment += glob[i];
                }
                continue;
            }
            if (glob[i] == ")" && groupStack.length > 0 && groupStack[groupStack.length - 1] != "BRACE") {
                segment += ")";
                const type = groupStack.pop();
                if (type == "!") {
                    segment += wildcard;
                } else if (type != "@") {
                    segment += type;
                }
                continue;
            }
            if (glob[i] == "|" && groupStack.length > 0 && groupStack[groupStack.length - 1] != "BRACE") {
                segment += "|";
                continue;
            }
            if (glob[i] == "+" && extended && glob[i + 1] == "(") {
                i++;
                groupStack.push("+");
                segment += "(?:";
                continue;
            }
            if (glob[i] == "@" && extended && glob[i + 1] == "(") {
                i++;
                groupStack.push("@");
                segment += "(?:";
                continue;
            }
            if (glob[i] == "?") {
                if (extended && glob[i + 1] == "(") {
                    i++;
                    groupStack.push("?");
                    segment += "(?:";
                } else {
                    segment += ".";
                }
                continue;
            }
            if (glob[i] == "!" && extended && glob[i + 1] == "(") {
                i++;
                groupStack.push("!");
                segment += "(?!";
                continue;
            }
            if (glob[i] == "{") {
                groupStack.push("BRACE");
                segment += "(?:";
                continue;
            }
            if (glob[i] == "}" && groupStack[groupStack.length - 1] == "BRACE") {
                groupStack.pop();
                segment += ")";
                continue;
            }
            if (glob[i] == "," && groupStack[groupStack.length - 1] == "BRACE") {
                segment += "|";
                continue;
            }
            if (glob[i] == "*") {
                if (extended && glob[i + 1] == "(") {
                    i++;
                    groupStack.push("*");
                    segment += "(?:";
                } else {
                    const prevChar = glob[i - 1];
                    let numStars = 1;
                    while(glob[i + 1] == "*"){
                        i++;
                        numStars++;
                    }
                    const nextChar = glob[i + 1];
                    if (globstarOption && numStars == 2 && [
                        ...seps,
                        undefined
                    ].includes(prevChar) && [
                        ...seps,
                        undefined
                    ].includes(nextChar)) {
                        segment += globstar;
                        endsWithSep = true;
                    } else {
                        segment += wildcard;
                    }
                }
                continue;
            }
            segment += regExpEscapeChars.includes(glob[i]) ? `\\${glob[i]}` : glob[i];
        }
        if (groupStack.length > 0 || inRange || inEscape) {
            segment = "";
            for (const c of glob.slice(j, i)){
                segment += regExpEscapeChars.includes(c) ? `\\${c}` : c;
                endsWithSep = false;
            }
        }
        regExpString += segment;
        if (!endsWithSep) {
            regExpString += i < glob.length ? sep : sepMaybe;
            endsWithSep = true;
        }
        while(seps.includes(glob[i]))i++;
        if (!(i > j)) {
            throw new Error("Assertion failure: i > j (potential infinite loop)");
        }
        j = i;
    }
    regExpString = `^${regExpString}$`;
    return new RegExp(regExpString, caseInsensitive ? "i" : "");
}
function isGlob(str) {
    const chars = {
        "{": "}",
        "(": ")",
        "[": "]"
    };
    const regex = /\\(.)|(^!|\*|\?|[\].+)]\?|\[[^\\\]]+\]|\{[^\\}]+\}|\(\?[:!=][^\\)]+\)|\([^|]+\|[^\\)]+\))/;
    if (str === "") {
        return false;
    }
    let match;
    while(match = regex.exec(str)){
        if (match[2]) return true;
        let idx = match.index + match[0].length;
        const open = match[1];
        const close = open ? chars[open] : null;
        if (open && close) {
            const n = str.indexOf(close, idx);
            if (n !== -1) {
                idx = n + 1;
            }
        }
        str = str.slice(idx);
    }
    return false;
}
function normalizeGlob(glob, { globstar =false  } = {}) {
    if (glob.match(/\0/g)) {
        throw new Error(`Glob contains invalid characters: "${glob}"`);
    }
    if (!globstar) {
        return normalize2(glob);
    }
    const s = SEP_PATTERN.source;
    const badParentPattern = new RegExp(`(?<=(${s}|^)\\*\\*${s})\\.\\.(?=${s}|$)`, "g");
    return normalize2(glob.replace(badParentPattern, "\0")).replace(/\0/g, "..");
}
function joinGlobs(globs, { extended =true , globstar =false  } = {}) {
    if (!globstar || globs.length == 0) {
        return join2(...globs);
    }
    if (globs.length === 0) return ".";
    let joined;
    for (const glob of globs){
        const path = glob;
        if (path.length > 0) {
            if (!joined) joined = path;
            else joined += `${SEP}${path}`;
        }
    }
    if (!joined) return ".";
    return normalizeGlob(joined, {
        extended,
        globstar
    });
}
const path1 = isWindows ? mod1 : mod2;
const { basename: basename2 , delimiter: delimiter2 , dirname: dirname2 , extname: extname2 , format: format2 , fromFileUrl: fromFileUrl2 , isAbsolute: isAbsolute2 , join: join3 , normalize: normalize3 , parse: parse2 , relative: relative2 , resolve: resolve2 , sep: sep2 , toFileUrl: toFileUrl2 , toNamespacedPath: toNamespacedPath2  } = path1;
function lexer(str) {
    const tokens = [];
    let i = 0;
    while(i < str.length){
        const __char = str[i];
        if (__char === "*" || __char === "+" || __char === "?") {
            tokens.push({
                type: "MODIFIER",
                index: i,
                value: str[i++]
            });
            continue;
        }
        if (__char === "\\") {
            tokens.push({
                type: "ESCAPED_CHAR",
                index: i++,
                value: str[i++]
            });
            continue;
        }
        if (__char === "{") {
            tokens.push({
                type: "OPEN",
                index: i,
                value: str[i++]
            });
            continue;
        }
        if (__char === "}") {
            tokens.push({
                type: "CLOSE",
                index: i,
                value: str[i++]
            });
            continue;
        }
        if (__char === ":") {
            let name = "";
            let j = i + 1;
            while(j < str.length){
                const code = str.charCodeAt(j);
                if (code >= 48 && code <= 57 || code >= 65 && code <= 90 || code >= 97 && code <= 122 || code === 95) {
                    name += str[j++];
                    continue;
                }
                break;
            }
            if (!name) throw new TypeError(`Missing parameter name at ${i}`);
            tokens.push({
                type: "NAME",
                index: i,
                value: name
            });
            i = j;
            continue;
        }
        if (__char === "(") {
            let count = 1;
            let pattern = "";
            let j = i + 1;
            if (str[j] === "?") {
                throw new TypeError(`Pattern cannot start with "?" at ${j}`);
            }
            while(j < str.length){
                if (str[j] === "\\") {
                    pattern += str[j++] + str[j++];
                    continue;
                }
                if (str[j] === ")") {
                    count--;
                    if (count === 0) {
                        j++;
                        break;
                    }
                } else if (str[j] === "(") {
                    count++;
                    if (str[j + 1] !== "?") {
                        throw new TypeError(`Capturing groups are not allowed at ${j}`);
                    }
                }
                pattern += str[j++];
            }
            if (count) throw new TypeError(`Unbalanced pattern at ${i}`);
            if (!pattern) throw new TypeError(`Missing pattern at ${i}`);
            tokens.push({
                type: "PATTERN",
                index: i,
                value: pattern
            });
            i = j;
            continue;
        }
        tokens.push({
            type: "CHAR",
            index: i,
            value: str[i++]
        });
    }
    tokens.push({
        type: "END",
        index: i,
        value: ""
    });
    return tokens;
}
function parse3(str, options = {}) {
    const tokens = lexer(str);
    const { prefixes ="./"  } = options;
    const defaultPattern = `[^${escapeString(options.delimiter || "/#?")}]+?`;
    const result = [];
    let key = 0;
    let i = 0;
    let path = "";
    const tryConsume = (type)=>{
        if (i < tokens.length && tokens[i].type === type) return tokens[i++].value;
    };
    const mustConsume = (type)=>{
        const value = tryConsume(type);
        if (value !== undefined) return value;
        const { type: nextType , index  } = tokens[i];
        throw new TypeError(`Unexpected ${nextType} at ${index}, expected ${type}`);
    };
    const consumeText = ()=>{
        let result = "";
        let value;
        while(value = tryConsume("CHAR") || tryConsume("ESCAPED_CHAR")){
            result += value;
        }
        return result;
    };
    while(i < tokens.length){
        const __char = tryConsume("CHAR");
        const name = tryConsume("NAME");
        const pattern = tryConsume("PATTERN");
        if (name || pattern) {
            let prefix = __char || "";
            if (prefixes.indexOf(prefix) === -1) {
                path += prefix;
                prefix = "";
            }
            if (path) {
                result.push(path);
                path = "";
            }
            result.push({
                name: name || key++,
                prefix,
                suffix: "",
                pattern: pattern || defaultPattern,
                modifier: tryConsume("MODIFIER") || ""
            });
            continue;
        }
        const value = __char || tryConsume("ESCAPED_CHAR");
        if (value) {
            path += value;
            continue;
        }
        if (path) {
            result.push(path);
            path = "";
        }
        const open = tryConsume("OPEN");
        if (open) {
            const prefix = consumeText();
            const name = tryConsume("NAME") || "";
            const pattern = tryConsume("PATTERN") || "";
            const suffix = consumeText();
            mustConsume("CLOSE");
            result.push({
                name: name || (pattern ? key++ : ""),
                pattern: name && !pattern ? defaultPattern : pattern,
                prefix,
                suffix,
                modifier: tryConsume("MODIFIER") || ""
            });
            continue;
        }
        mustConsume("END");
    }
    return result;
}
function compile(str, options) {
    return tokensToFunction(parse3(str, options), options);
}
function tokensToFunction(tokens, options = {}) {
    const reFlags = flags(options);
    const { encode =(x)=>x , validate =true  } = options;
    const matches = tokens.map((token)=>{
        if (typeof token === "object") {
            return new RegExp(`^(?:${token.pattern})$`, reFlags);
        }
    });
    return (data)=>{
        let path = "";
        for(let i = 0; i < tokens.length; i++){
            const token = tokens[i];
            if (typeof token === "string") {
                path += token;
                continue;
            }
            const value = data ? data[token.name] : undefined;
            const optional = token.modifier === "?" || token.modifier === "*";
            const repeat = token.modifier === "*" || token.modifier === "+";
            if (Array.isArray(value)) {
                if (!repeat) {
                    throw new TypeError(`Expected "${token.name}" to not repeat, but got an array`);
                }
                if (value.length === 0) {
                    if (optional) continue;
                    throw new TypeError(`Expected "${token.name}" to not be empty`);
                }
                for(let j = 0; j < value.length; j++){
                    const segment = encode(value[j], token);
                    if (validate && !matches[i].test(segment)) {
                        throw new TypeError(`Expected all "${token.name}" to match "${token.pattern}", but got "${segment}"`);
                    }
                    path += token.prefix + segment + token.suffix;
                }
                continue;
            }
            if (typeof value === "string" || typeof value === "number") {
                const segment = encode(String(value), token);
                if (validate && !matches[i].test(segment)) {
                    throw new TypeError(`Expected "${token.name}" to match "${token.pattern}", but got "${segment}"`);
                }
                path += token.prefix + segment + token.suffix;
                continue;
            }
            if (optional) continue;
            const typeOfMessage = repeat ? "an array" : "a string";
            throw new TypeError(`Expected "${token.name}" to be ${typeOfMessage}`);
        }
        return path;
    };
}
function escapeString(str) {
    return str.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
}
function flags(options) {
    return options && options.sensitive ? "" : "i";
}
function regexpToRegexp(path, keys) {
    if (!keys) return path;
    const groupsRegex = /\((?:\?<(.*?)>)?(?!\?)/g;
    let index = 0;
    let execResult = groupsRegex.exec(path.source);
    while(execResult){
        keys.push({
            name: execResult[1] || index++,
            prefix: "",
            suffix: "",
            modifier: "",
            pattern: ""
        });
        execResult = groupsRegex.exec(path.source);
    }
    return path;
}
function arrayToRegexp(paths, keys, options) {
    const parts = paths.map((path)=>pathToRegexp(path, keys, options).source);
    return new RegExp(`(?:${parts.join("|")})`, flags(options));
}
function stringToRegexp(path, keys, options) {
    return tokensToRegexp(parse3(path, options), keys, options);
}
function tokensToRegexp(tokens, keys, options = {}) {
    const { strict =false , start =true , end =true , encode =(x)=>x , delimiter ="/#?" , endsWith =""  } = options;
    const endsWithRe = `[${escapeString(endsWith)}]|$`;
    const delimiterRe = `[${escapeString(delimiter)}]`;
    let route = start ? "^" : "";
    for (const token of tokens){
        if (typeof token === "string") {
            route += escapeString(encode(token));
        } else {
            const prefix = escapeString(encode(token.prefix));
            const suffix = escapeString(encode(token.suffix));
            if (token.pattern) {
                if (keys) keys.push(token);
                if (prefix || suffix) {
                    if (token.modifier === "+" || token.modifier === "*") {
                        const mod = token.modifier === "*" ? "?" : "";
                        route += `(?:${prefix}((?:${token.pattern})(?:${suffix}${prefix}(?:${token.pattern}))*)${suffix})${mod}`;
                    } else {
                        route += `(?:${prefix}(${token.pattern})${suffix})${token.modifier}`;
                    }
                } else {
                    if (token.modifier === "+" || token.modifier === "*") {
                        route += `((?:${token.pattern})${token.modifier})`;
                    } else {
                        route += `(${token.pattern})${token.modifier}`;
                    }
                }
            } else {
                route += `(?:${prefix}${suffix})${token.modifier}`;
            }
        }
    }
    if (end) {
        if (!strict) route += `${delimiterRe}?`;
        route += !options.endsWith ? "$" : `(?=${endsWithRe})`;
    } else {
        const endToken = tokens[tokens.length - 1];
        const isEndDelimited = typeof endToken === "string" ? delimiterRe.indexOf(endToken[endToken.length - 1]) > -1 : endToken === undefined;
        if (!strict) {
            route += `(?:${delimiterRe}(?=${endsWithRe}))?`;
        }
        if (!isEndDelimited) {
            route += `(?=${delimiterRe}|${endsWithRe})`;
        }
    }
    return new RegExp(route, flags(options));
}
function pathToRegexp(path, keys, options) {
    if (path instanceof RegExp) return regexpToRegexp(path, keys);
    if (Array.isArray(path)) return arrayToRegexp(path, keys, options);
    return stringToRegexp(path, keys, options);
}
const SUBTYPE_NAME_REGEXP = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.-]{0,126}$/;
const TYPE_NAME_REGEXP = /^[A-Za-z0-9][A-Za-z0-9!#$&^_-]{0,126}$/;
const TYPE_REGEXP = /^ *([A-Za-z0-9][A-Za-z0-9!#$&^_-]{0,126})\/([A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}) *$/;
class MediaType {
    constructor(type, subtype, suffix){
        this.type = type;
        this.subtype = subtype;
        this.suffix = suffix;
    }
    type;
    subtype;
    suffix;
}
function format3(obj) {
    const { subtype , suffix , type  } = obj;
    if (!TYPE_NAME_REGEXP.test(type)) {
        throw new TypeError("Invalid type.");
    }
    if (!SUBTYPE_NAME_REGEXP.test(subtype)) {
        throw new TypeError("Invalid subtype.");
    }
    let str = `${type}/${subtype}`;
    if (suffix) {
        if (!TYPE_NAME_REGEXP.test(suffix)) {
            throw new TypeError("Invalid suffix.");
        }
        str += `+${suffix}`;
    }
    return str;
}
function parse4(str) {
    const match = TYPE_REGEXP.exec(str.toLowerCase());
    if (!match) {
        throw new TypeError("Invalid media type.");
    }
    let [, type, subtype] = match;
    let suffix;
    const idx = subtype.lastIndexOf("+");
    if (idx !== -1) {
        suffix = subtype.substr(idx + 1);
        subtype = subtype.substr(0, idx);
    }
    return new MediaType(type, subtype, suffix);
}
function mimeMatch(expected, actual) {
    if (expected === undefined) {
        return false;
    }
    const actualParts = actual.split("/");
    const expectedParts = expected.split("/");
    if (actualParts.length !== 2 || expectedParts.length !== 2) {
        return false;
    }
    const [actualType, actualSubtype] = actualParts;
    const [expectedType, expectedSubtype] = expectedParts;
    if (expectedType !== "*" && expectedType !== actualType) {
        return false;
    }
    if (expectedSubtype.substr(0, 2) === "*+") {
        return expectedSubtype.length <= actualSubtype.length + 1 && expectedSubtype.substr(1) === actualSubtype.substr(1 - expectedSubtype.length);
    }
    if (expectedSubtype !== "*" && expectedSubtype !== actualSubtype) {
        return false;
    }
    return true;
}
function normalize4(type) {
    if (type === "urlencoded") {
        return "application/x-www-form-urlencoded";
    } else if (type === "multipart") {
        return "multipart/*";
    } else if (type[0] === "+") {
        return `*/*${type}`;
    }
    return type.includes("/") ? type : typeByExtension(type);
}
function normalizeType(value) {
    try {
        const val = value.split(";");
        const type = parse4(val[0]);
        return format3(type);
    } catch  {
        return;
    }
}
function isMediaType(value, types) {
    const val = normalizeType(value);
    if (!val) {
        return false;
    }
    if (!types.length) {
        return val;
    }
    for (const type of types){
        if (mimeMatch(normalize4(type), val)) {
            return type[0] === "+" || type.includes("*") ? val : type;
        }
    }
    return false;
}
const ENCODE_CHARS_REGEXP = /(?:[^\x21\x25\x26-\x3B\x3D\x3F-\x5B\x5D\x5F\x61-\x7A\x7E]|%(?:[^0-9A-Fa-f]|[0-9A-Fa-f][^0-9A-Fa-f]|$))+/g;
const HTAB = "\t".charCodeAt(0);
const SPACE = " ".charCodeAt(0);
const CR = "\r".charCodeAt(0);
const LF = "\n".charCodeAt(0);
const UNMATCHED_SURROGATE_PAIR_REGEXP = /(^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]|[\uD800-\uDBFF]([^\uDC00-\uDFFF]|$)/g;
const UNMATCHED_SURROGATE_PAIR_REPLACE = "$1\uFFFD$2";
const BODY_TYPES = [
    "string",
    "number",
    "bigint",
    "boolean",
    "symbol"
];
function assert1(cond, msg = "Assertion failed") {
    if (!cond) {
        throw new Error(msg);
    }
}
function decodeComponent(text) {
    try {
        return decodeURIComponent(text);
    } catch  {
        return text;
    }
}
function encodeUrl(url) {
    return String(url).replace(UNMATCHED_SURROGATE_PAIR_REGEXP, UNMATCHED_SURROGATE_PAIR_REPLACE).replace(ENCODE_CHARS_REGEXP, encodeURI);
}
function bufferToHex(buffer) {
    const arr = Array.from(new Uint8Array(buffer));
    return arr.map((b)=>b.toString(16).padStart(2, "0")).join("");
}
async function getRandomFilename(prefix = "", extension = "") {
    const buffer = await crypto.subtle.digest("SHA-1", crypto.getRandomValues(new Uint8Array(256)));
    return `${prefix}${bufferToHex(buffer)}${extension ? `.${extension}` : ""}`;
}
async function getBoundary() {
    const buffer = await crypto.subtle.digest("SHA-1", crypto.getRandomValues(new Uint8Array(256)));
    return `oak_${bufferToHex(buffer)}`;
}
function isAsyncIterable(value) {
    return typeof value === "object" && value !== null && Symbol.asyncIterator in value && typeof value[Symbol.asyncIterator] === "function";
}
function isRouterContext(value) {
    return "params" in value;
}
function isReader(value) {
    return typeof value === "object" && value !== null && "read" in value && typeof value.read === "function";
}
function isCloser(value) {
    return typeof value === "object" && value != null && "close" in value && typeof value["close"] === "function";
}
function isConn(value) {
    return typeof value === "object" && value != null && "rid" in value && typeof value.rid === "number" && "localAddr" in value && "remoteAddr" in value;
}
function isListenTlsOptions(value) {
    return typeof value === "object" && value !== null && ("cert" in value || "certFile" in value) && ("key" in value || "keyFile" in value) && "port" in value;
}
function readableStreamFromAsyncIterable(source) {
    return new ReadableStream({
        async start (controller) {
            for await (const chunk of source){
                if (BODY_TYPES.includes(typeof chunk)) {
                    controller.enqueue(encoder1.encode(String(chunk)));
                } else if (chunk instanceof Uint8Array) {
                    controller.enqueue(chunk);
                } else if (ArrayBuffer.isView(chunk)) {
                    controller.enqueue(new Uint8Array(chunk.buffer));
                } else if (chunk instanceof ArrayBuffer) {
                    controller.enqueue(new Uint8Array(chunk));
                } else {
                    try {
                        controller.enqueue(encoder1.encode(JSON.stringify(chunk)));
                    } catch  {}
                }
            }
            controller.close();
        }
    });
}
function readableStreamFromReader(reader, options = {}) {
    const { autoClose =true , chunkSize =16_640 , strategy  } = options;
    return new ReadableStream({
        async pull (controller) {
            const chunk = new Uint8Array(chunkSize);
            try {
                const read = await reader.read(chunk);
                if (read === null) {
                    if (isCloser(reader) && autoClose) {
                        reader.close();
                    }
                    controller.close();
                    return;
                }
                controller.enqueue(chunk.subarray(0, read));
            } catch (e) {
                controller.error(e);
                if (isCloser(reader)) {
                    reader.close();
                }
            }
        },
        cancel () {
            if (isCloser(reader) && autoClose) {
                reader.close();
            }
        }
    }, strategy);
}
function isErrorStatus(value) {
    return [
        Status.BadRequest,
        Status.Unauthorized,
        Status.PaymentRequired,
        Status.Forbidden,
        Status.NotFound,
        Status.MethodNotAllowed,
        Status.NotAcceptable,
        Status.ProxyAuthRequired,
        Status.RequestTimeout,
        Status.Conflict,
        Status.Gone,
        Status.LengthRequired,
        Status.PreconditionFailed,
        Status.RequestEntityTooLarge,
        Status.RequestURITooLong,
        Status.UnsupportedMediaType,
        Status.RequestedRangeNotSatisfiable,
        Status.ExpectationFailed,
        Status.Teapot,
        Status.MisdirectedRequest,
        Status.UnprocessableEntity,
        Status.Locked,
        Status.FailedDependency,
        Status.UpgradeRequired,
        Status.PreconditionRequired,
        Status.TooManyRequests,
        Status.RequestHeaderFieldsTooLarge,
        Status.UnavailableForLegalReasons,
        Status.InternalServerError,
        Status.NotImplemented,
        Status.BadGateway,
        Status.ServiceUnavailable,
        Status.GatewayTimeout,
        Status.HTTPVersionNotSupported,
        Status.VariantAlsoNegotiates,
        Status.InsufficientStorage,
        Status.LoopDetected,
        Status.NotExtended,
        Status.NetworkAuthenticationRequired
    ].includes(value);
}
function isRedirectStatus(value) {
    return [
        Status.MultipleChoices,
        Status.MovedPermanently,
        Status.Found,
        Status.SeeOther,
        Status.UseProxy,
        Status.TemporaryRedirect,
        Status.PermanentRedirect
    ].includes(value);
}
function isHtml(value) {
    return /^\s*<(?:!DOCTYPE|html|body)/i.test(value);
}
function skipLWSPChar(u8) {
    const result = new Uint8Array(u8.length);
    let j = 0;
    for(let i = 0; i < u8.length; i++){
        if (u8[i] === SPACE || u8[i] === HTAB) continue;
        result[j++] = u8[i];
    }
    return result.slice(0, j);
}
function stripEol(value) {
    if (value[value.byteLength - 1] == LF) {
        let drop = 1;
        if (value.byteLength > 1 && value[value.byteLength - 2] === CR) {
            drop = 2;
        }
        return value.subarray(0, value.byteLength - drop);
    }
    return value;
}
const UP_PATH_REGEXP = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
function resolvePath(rootPath, relativePath) {
    let path = relativePath;
    let root = rootPath;
    if (relativePath === undefined) {
        path = rootPath;
        root = ".";
    }
    if (path == null) {
        throw new TypeError("Argument relativePath is required.");
    }
    if (path.includes("\0")) {
        throw createHttpError(400, "Malicious Path");
    }
    if (isAbsolute2(path)) {
        throw createHttpError(400, "Malicious Path");
    }
    if (UP_PATH_REGEXP.test(normalize3("." + sep2 + path))) {
        throw createHttpError(403);
    }
    return normalize3(join3(root, path));
}
class Uint8ArrayTransformStream extends TransformStream {
    constructor(){
        const init = {
            async transform (chunk, controller) {
                chunk = await chunk;
                switch(typeof chunk){
                    case "object":
                        if (chunk === null) {
                            controller.terminate();
                        } else if (ArrayBuffer.isView(chunk)) {
                            controller.enqueue(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
                        } else if (Array.isArray(chunk) && chunk.every((value)=>typeof value === "number")) {
                            controller.enqueue(new Uint8Array(chunk));
                        } else if (typeof chunk.valueOf === "function" && chunk.valueOf() !== chunk) {
                            this.transform(chunk.valueOf(), controller);
                        } else if ("toJSON" in chunk) {
                            this.transform(JSON.stringify(chunk), controller);
                        }
                        break;
                    case "symbol":
                        controller.error(new TypeError("Cannot transform a symbol to a Uint8Array"));
                        break;
                    case "undefined":
                        controller.error(new TypeError("Cannot transform undefined to a Uint8Array"));
                        break;
                    default:
                        controller.enqueue(this.encoder.encode(String(chunk)));
                }
            },
            encoder: new TextEncoder()
        };
        super(init);
    }
}
const encoder1 = new TextEncoder();
const MIN_BUF_SIZE = 16;
const CR1 = "\r".charCodeAt(0);
const LF1 = "\n".charCodeAt(0);
class BufferFullError extends Error {
    name;
    constructor(partial){
        super("Buffer full");
        this.partial = partial;
        this.name = "BufferFullError";
    }
    partial;
}
class BufReader {
    #buffer;
    #reader;
    #posRead = 0;
    #posWrite = 0;
    #eof = false;
    async #fill() {
        if (this.#posRead > 0) {
            this.#buffer.copyWithin(0, this.#posRead, this.#posWrite);
            this.#posWrite -= this.#posRead;
            this.#posRead = 0;
        }
        if (this.#posWrite >= this.#buffer.byteLength) {
            throw Error("bufio: tried to fill full buffer");
        }
        for(let i = 100; i > 0; i--){
            const rr = await this.#reader.read(this.#buffer.subarray(this.#posWrite));
            if (rr === null) {
                this.#eof = true;
                return;
            }
            assert1(rr >= 0, "negative read");
            this.#posWrite += rr;
            if (rr > 0) {
                return;
            }
        }
        throw new Error(`No progress after ${100} read() calls`);
    }
    #reset(buffer, reader) {
        this.#buffer = buffer;
        this.#reader = reader;
        this.#eof = false;
    }
    constructor(rd, size = 4096){
        if (size < 16) {
            size = MIN_BUF_SIZE;
        }
        this.#reset(new Uint8Array(size), rd);
    }
    buffered() {
        return this.#posWrite - this.#posRead;
    }
    async readLine(strip = true) {
        let line;
        try {
            line = await this.readSlice(LF1);
        } catch (err) {
            assert1(err instanceof Error);
            let { partial  } = err;
            assert1(partial instanceof Uint8Array, "Caught error from `readSlice()` without `partial` property");
            if (!(err instanceof BufferFullError)) {
                throw err;
            }
            if (!this.#eof && partial.byteLength > 0 && partial[partial.byteLength - 1] === CR1) {
                assert1(this.#posRead > 0, "Tried to rewind past start of buffer");
                this.#posRead--;
                partial = partial.subarray(0, partial.byteLength - 1);
            }
            return {
                bytes: partial,
                eol: this.#eof
            };
        }
        if (line === null) {
            return null;
        }
        if (line.byteLength === 0) {
            return {
                bytes: line,
                eol: true
            };
        }
        if (strip) {
            line = stripEol(line);
        }
        return {
            bytes: line,
            eol: true
        };
    }
    async readSlice(delim) {
        let s = 0;
        let slice;
        while(true){
            let i = this.#buffer.subarray(this.#posRead + s, this.#posWrite).indexOf(delim);
            if (i >= 0) {
                i += s;
                slice = this.#buffer.subarray(this.#posRead, this.#posRead + i + 1);
                this.#posRead += i + 1;
                break;
            }
            if (this.#eof) {
                if (this.#posRead === this.#posWrite) {
                    return null;
                }
                slice = this.#buffer.subarray(this.#posRead, this.#posWrite);
                this.#posRead = this.#posWrite;
                break;
            }
            if (this.buffered() >= this.#buffer.byteLength) {
                this.#posRead = this.#posWrite;
                const oldbuf = this.#buffer;
                const newbuf = this.#buffer.slice(0);
                this.#buffer = newbuf;
                throw new BufferFullError(oldbuf);
            }
            s = this.#posWrite - this.#posRead;
            try {
                await this.#fill();
            } catch (err) {
                const e = err instanceof Error ? err : new Error("[non-object thrown]");
                e.partial = slice;
                throw err;
            }
        }
        return slice;
    }
}
const COLON = ":".charCodeAt(0);
const HTAB1 = "\t".charCodeAt(0);
const SPACE1 = " ".charCodeAt(0);
const decoder = new TextDecoder();
function toParamRegExp(attributePattern, flags) {
    return new RegExp(`(?:^|;)\\s*${attributePattern}\\s*=\\s*` + `(` + `[^";\\s][^;\\s]*` + `|` + `"(?:[^"\\\\]|\\\\"?)+"?` + `)`, flags);
}
async function readHeaders(body) {
    const headers = {};
    let readResult = await body.readLine();
    while(readResult){
        const { bytes  } = readResult;
        if (!bytes.length) {
            return headers;
        }
        let i = bytes.indexOf(COLON);
        if (i === -1) {
            throw new errors.BadRequest(`Malformed header: ${decoder.decode(bytes)}`);
        }
        const key = decoder.decode(bytes.subarray(0, i)).trim().toLowerCase();
        if (key === "") {
            throw new errors.BadRequest("Invalid header key.");
        }
        i++;
        while(i < bytes.byteLength && (bytes[i] === SPACE1 || bytes[i] === HTAB1)){
            i++;
        }
        const value = decoder.decode(bytes.subarray(i)).trim();
        headers[key] = value;
        readResult = await body.readLine();
    }
    throw new errors.BadRequest("Unexpected end of body reached.");
}
function unquote(value) {
    if (value.startsWith(`"`)) {
        const parts = value.slice(1).split(`\\"`);
        for(let i = 0; i < parts.length; ++i){
            const quoteIndex = parts[i].indexOf(`"`);
            if (quoteIndex !== -1) {
                parts[i] = parts[i].slice(0, quoteIndex);
                parts.length = i + 1;
            }
            parts[i] = parts[i].replace(/\\(.)/g, "$1");
        }
        value = parts.join(`"`);
    }
    return value;
}
let needsEncodingFixup = false;
function fixupEncoding(value) {
    if (needsEncodingFixup && /[\x80-\xff]/.test(value)) {
        value = textDecode("utf-8", value);
        if (needsEncodingFixup) {
            value = textDecode("iso-8859-1", value);
        }
    }
    return value;
}
const FILENAME_STAR_REGEX = toParamRegExp("filename\\*", "i");
const FILENAME_START_ITER_REGEX = toParamRegExp("filename\\*((?!0\\d)\\d+)(\\*?)", "ig");
const FILENAME_REGEX = toParamRegExp("filename", "i");
function rfc2047decode(value) {
    if (!value.startsWith("=?") || /[\x00-\x19\x80-\xff]/.test(value)) {
        return value;
    }
    return value.replace(/=\?([\w-]*)\?([QqBb])\?((?:[^?]|\?(?!=))*)\?=/g, (_, charset, encoding, text)=>{
        if (encoding === "q" || encoding === "Q") {
            text = text.replace(/_/g, " ");
            text = text.replace(/=([0-9a-fA-F]{2})/g, (_, hex)=>String.fromCharCode(parseInt(hex, 16)));
            return textDecode(charset, text);
        }
        try {
            text = atob(text);
        } catch  {}
        return textDecode(charset, text);
    });
}
function rfc2231getParam(header) {
    const matches = [];
    let match;
    while(match = FILENAME_START_ITER_REGEX.exec(header)){
        const [, ns, quote, part] = match;
        const n = parseInt(ns, 10);
        if (n in matches) {
            if (n === 0) {
                break;
            }
            continue;
        }
        matches[n] = [
            quote,
            part
        ];
    }
    const parts = [];
    for(let n = 0; n < matches.length; ++n){
        if (!(n in matches)) {
            break;
        }
        let [quote, part] = matches[n];
        part = unquote(part);
        if (quote) {
            part = unescape(part);
            if (n === 0) {
                part = rfc5987decode(part);
            }
        }
        parts.push(part);
    }
    return parts.join("");
}
function rfc5987decode(value) {
    const encodingEnd = value.indexOf(`'`);
    if (encodingEnd === -1) {
        return value;
    }
    const encoding = value.slice(0, encodingEnd);
    const langValue = value.slice(encodingEnd + 1);
    return textDecode(encoding, langValue.replace(/^[^']*'/, ""));
}
function textDecode(encoding, value) {
    if (encoding) {
        try {
            const decoder = new TextDecoder(encoding, {
                fatal: true
            });
            const bytes = Array.from(value, (c)=>c.charCodeAt(0));
            if (bytes.every((code)=>code <= 0xFF)) {
                value = decoder.decode(new Uint8Array(bytes));
                needsEncodingFixup = false;
            }
        } catch  {}
    }
    return value;
}
function getFilename(header) {
    needsEncodingFixup = true;
    let matches = FILENAME_STAR_REGEX.exec(header);
    if (matches) {
        const [, filename] = matches;
        return fixupEncoding(rfc2047decode(rfc5987decode(unescape(unquote(filename)))));
    }
    const filename = rfc2231getParam(header);
    if (filename) {
        return fixupEncoding(rfc2047decode(filename));
    }
    matches = FILENAME_REGEX.exec(header);
    if (matches) {
        const [, filename] = matches;
        return fixupEncoding(rfc2047decode(unquote(filename)));
    }
    return "";
}
const decoder1 = new TextDecoder();
const encoder2 = new TextEncoder();
const BOUNDARY_PARAM_REGEX = toParamRegExp("boundary", "i");
const NAME_PARAM_REGEX = toParamRegExp("name", "i");
function append(a, b) {
    const ab = new Uint8Array(a.length + b.length);
    ab.set(a, 0);
    ab.set(b, a.length);
    return ab;
}
function isEqual(a, b) {
    return equals(skipLWSPChar(a), b);
}
async function readToStartOrEnd(body, start, end) {
    let lineResult;
    while(lineResult = await body.readLine()){
        if (isEqual(lineResult.bytes, start)) {
            return true;
        }
        if (isEqual(lineResult.bytes, end)) {
            return false;
        }
    }
    throw new errors.BadRequest("Unable to find multi-part boundary.");
}
async function* parts({ body , customContentTypes ={} , final: __final , part , maxFileSize , maxSize , outPath , prefix  }) {
    async function getFile(contentType) {
        const ext = customContentTypes[contentType.toLowerCase()] ?? extension(contentType);
        if (!ext) {
            throw new errors.BadRequest(`The form contained content type "${contentType}" which is not supported by the server.`);
        }
        if (!outPath) {
            outPath = await Deno.makeTempDir();
        }
        const filename = `${outPath}/${await getRandomFilename(prefix, ext)}`;
        const file = await Deno.open(filename, {
            write: true,
            createNew: true
        });
        return [
            filename,
            file
        ];
    }
    while(true){
        const headers = await readHeaders(body);
        const contentType = headers["content-type"];
        const contentDisposition = headers["content-disposition"];
        if (!contentDisposition) {
            throw new errors.BadRequest("Form data part missing content-disposition header");
        }
        if (!contentDisposition.match(/^form-data;/i)) {
            throw new errors.BadRequest(`Unexpected content-disposition header: "${contentDisposition}"`);
        }
        const matches = NAME_PARAM_REGEX.exec(contentDisposition);
        if (!matches) {
            throw new errors.BadRequest(`Unable to determine name of form body part`);
        }
        let [, name] = matches;
        name = unquote(name);
        if (contentType) {
            const originalName = getFilename(contentDisposition);
            let byteLength = 0;
            let file;
            let filename;
            let buf;
            if (maxSize) {
                buf = new Uint8Array();
            } else {
                const result = await getFile(contentType);
                filename = result[0];
                file = result[1];
            }
            while(true){
                const readResult = await body.readLine(false);
                if (!readResult) {
                    throw new errors.BadRequest("Unexpected EOF reached");
                }
                const { bytes  } = readResult;
                const strippedBytes = stripEol(bytes);
                if (isEqual(strippedBytes, part) || isEqual(strippedBytes, __final)) {
                    if (file) {
                        const bytesDiff = bytes.length - strippedBytes.length;
                        if (bytesDiff) {
                            const originalBytesSize = await file.seek(-bytesDiff, Deno.SeekMode.Current);
                            await file.truncate(originalBytesSize);
                        }
                        file.close();
                    }
                    yield [
                        name,
                        {
                            content: buf,
                            contentType,
                            name,
                            filename,
                            originalName
                        }
                    ];
                    if (isEqual(strippedBytes, __final)) {
                        return;
                    }
                    break;
                }
                byteLength += bytes.byteLength;
                if (byteLength > maxFileSize) {
                    if (file) {
                        file.close();
                    }
                    throw new errors.RequestEntityTooLarge(`File size exceeds limit of ${maxFileSize} bytes.`);
                }
                if (buf) {
                    if (byteLength > maxSize) {
                        const result = await getFile(contentType);
                        filename = result[0];
                        file = result[1];
                        await writeAll(file, buf);
                        buf = undefined;
                    } else {
                        buf = append(buf, bytes);
                    }
                }
                if (file) {
                    await writeAll(file, bytes);
                }
            }
        } else {
            const lines = [];
            while(true){
                const readResult = await body.readLine();
                if (!readResult) {
                    throw new errors.BadRequest("Unexpected EOF reached");
                }
                const { bytes  } = readResult;
                if (isEqual(bytes, part) || isEqual(bytes, __final)) {
                    yield [
                        name,
                        lines.join("\n")
                    ];
                    if (isEqual(bytes, __final)) {
                        return;
                    }
                    break;
                }
                lines.push(decoder1.decode(bytes));
            }
        }
    }
}
class FormDataReader {
    #body;
    #boundaryFinal;
    #boundaryPart;
    #reading = false;
    constructor(contentType, body){
        const matches = contentType.match(BOUNDARY_PARAM_REGEX);
        if (!matches) {
            throw new errors.BadRequest(`Content type "${contentType}" does not contain a valid boundary.`);
        }
        let [, boundary] = matches;
        boundary = unquote(boundary);
        this.#boundaryPart = encoder2.encode(`--${boundary}`);
        this.#boundaryFinal = encoder2.encode(`--${boundary}--`);
        this.#body = body;
    }
    async read(options = {}) {
        if (this.#reading) {
            throw new Error("Body is already being read.");
        }
        this.#reading = true;
        const { outPath , maxFileSize =10_485_760 , maxSize =0 , bufferSize =1_048_576 , customContentTypes  } = options;
        const body = new BufReader(this.#body, bufferSize);
        const result = {
            fields: {}
        };
        if (!await readToStartOrEnd(body, this.#boundaryPart, this.#boundaryFinal)) {
            return result;
        }
        try {
            for await (const part of parts({
                body,
                customContentTypes,
                part: this.#boundaryPart,
                final: this.#boundaryFinal,
                maxFileSize,
                maxSize,
                outPath
            })){
                const [key, value] = part;
                if (typeof value === "string") {
                    result.fields[key] = value;
                } else {
                    if (!result.files) {
                        result.files = [];
                    }
                    result.files.push(value);
                }
            }
        } catch (err) {
            if (err instanceof Deno.errors.PermissionDenied) {
                console.error(err.stack ? err.stack : `${err.name}: ${err.message}`);
            } else {
                throw err;
            }
        }
        return result;
    }
    async *stream(options = {}) {
        if (this.#reading) {
            throw new Error("Body is already being read.");
        }
        this.#reading = true;
        const { outPath , customContentTypes , maxFileSize =10_485_760 , maxSize =0 , bufferSize =32000  } = options;
        const body = new BufReader(this.#body, bufferSize);
        if (!await readToStartOrEnd(body, this.#boundaryPart, this.#boundaryFinal)) {
            return;
        }
        try {
            for await (const part of parts({
                body,
                customContentTypes,
                part: this.#boundaryPart,
                final: this.#boundaryFinal,
                maxFileSize,
                maxSize,
                outPath
            })){
                yield part;
            }
        } catch (err) {
            if (err instanceof Deno.errors.PermissionDenied) {
                console.error(err.stack ? err.stack : `${err.name}: ${err.message}`);
            } else {
                throw err;
            }
        }
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect({})}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        return `${options.stylize(this.constructor.name, "special")} ${inspect({}, newOptions)}`;
    }
}
const defaultBodyContentTypes = {
    json: [
        "json",
        "application/*+json",
        "application/csp-report"
    ],
    form: [
        "urlencoded"
    ],
    formData: [
        "multipart"
    ],
    text: [
        "text"
    ]
};
function resolveType(contentType, contentTypes) {
    const contentTypesJson = [
        ...defaultBodyContentTypes.json,
        ...contentTypes.json ?? []
    ];
    const contentTypesForm = [
        ...defaultBodyContentTypes.form,
        ...contentTypes.form ?? []
    ];
    const contentTypesFormData = [
        ...defaultBodyContentTypes.formData,
        ...contentTypes.formData ?? []
    ];
    const contentTypesText = [
        ...defaultBodyContentTypes.text,
        ...contentTypes.text ?? []
    ];
    if (contentTypes.bytes && isMediaType(contentType, contentTypes.bytes)) {
        return "bytes";
    } else if (isMediaType(contentType, contentTypesJson)) {
        return "json";
    } else if (isMediaType(contentType, contentTypesForm)) {
        return "form";
    } else if (isMediaType(contentType, contentTypesFormData)) {
        return "form-data";
    } else if (isMediaType(contentType, contentTypesText)) {
        return "text";
    }
    return "bytes";
}
const decoder2 = new TextDecoder();
class RequestBody {
    #body;
    #formDataReader;
    #headers;
    #jsonBodyReviver;
    #stream;
    #readAllBody;
    #readBody;
    #type;
    #exceedsLimit(limit) {
        if (!limit || limit === Infinity) {
            return false;
        }
        if (!this.#body) {
            return false;
        }
        const contentLength = this.#headers.get("content-length") ?? "0";
        const parsed = parseInt(contentLength, 10);
        if (isNaN(parsed)) {
            return true;
        }
        return parsed > limit;
    }
    #parse(type, limit1) {
        switch(type){
            case "form":
                this.#type = "bytes";
                if (this.#exceedsLimit(limit1)) {
                    return ()=>Promise.reject(new RangeError(`Body exceeds a limit of ${limit1}.`));
                }
                return async ()=>new URLSearchParams(decoder2.decode(await this.#valuePromise()).replace(/\+/g, " "));
            case "form-data":
                this.#type = "form-data";
                return ()=>{
                    const contentType = this.#headers.get("content-type");
                    assert1(contentType);
                    const readableStream = this.#body ?? new ReadableStream();
                    return this.#formDataReader ?? (this.#formDataReader = new FormDataReader(contentType, readerFromStreamReader(readableStream.getReader())));
                };
            case "json":
                this.#type = "bytes";
                if (this.#exceedsLimit(limit1)) {
                    return ()=>Promise.reject(new RangeError(`Body exceeds a limit of ${limit1}.`));
                }
                return async ()=>{
                    const value = await this.#valuePromise();
                    return value.length ? JSON.parse(decoder2.decode(await this.#valuePromise()), this.#jsonBodyReviver) : null;
                };
            case "bytes":
                this.#type = "bytes";
                if (this.#exceedsLimit(limit1)) {
                    return ()=>Promise.reject(new RangeError(`Body exceeds a limit of ${limit1}.`));
                }
                return ()=>this.#valuePromise();
            case "text":
                this.#type = "bytes";
                if (this.#exceedsLimit(limit1)) {
                    return ()=>Promise.reject(new RangeError(`Body exceeds a limit of ${limit1}.`));
                }
                return async ()=>decoder2.decode(await this.#valuePromise());
            default:
                throw new TypeError(`Invalid body type: "${type}"`);
        }
    }
    #validateGetArgs(type1, contentTypes) {
        if (type1 === "reader" && this.#type && this.#type !== "reader") {
            throw new TypeError(`Body already consumed as "${this.#type}" and cannot be returned as a reader.`);
        }
        if (type1 === "stream" && this.#type && this.#type !== "stream") {
            throw new TypeError(`Body already consumed as "${this.#type}" and cannot be returned as a stream.`);
        }
        if (type1 === "form-data" && this.#type && this.#type !== "form-data") {
            throw new TypeError(`Body already consumed as "${this.#type}" and cannot be returned as a stream.`);
        }
        if (this.#type === "reader" && type1 !== "reader") {
            throw new TypeError("Body already consumed as a reader and can only be returned as a reader.");
        }
        if (this.#type === "stream" && type1 !== "stream") {
            throw new TypeError("Body already consumed as a stream and can only be returned as a stream.");
        }
        if (this.#type === "form-data" && type1 !== "form-data") {
            throw new TypeError("Body already consumed as form data and can only be returned as form data.");
        }
        if (type1 && Object.keys(contentTypes).length) {
            throw new TypeError(`"type" and "contentTypes" cannot be specified at the same time`);
        }
    }
    #valuePromise() {
        return this.#readAllBody ?? (this.#readAllBody = this.#readBody());
    }
    constructor({ body , readBody  }, headers, jsonBodyReviver){
        this.#body = body;
        this.#headers = headers;
        this.#jsonBodyReviver = jsonBodyReviver;
        this.#readBody = readBody;
    }
    get({ limit =10_485_760 , type , contentTypes ={}  } = {}) {
        this.#validateGetArgs(type, contentTypes);
        if (type === "reader") {
            if (!this.#body) {
                this.#type = "undefined";
                throw new TypeError(`Body is undefined and cannot be returned as "reader".`);
            }
            this.#type = "reader";
            return {
                type,
                value: readerFromStreamReader(this.#body.getReader())
            };
        }
        if (type === "stream") {
            if (!this.#body) {
                this.#type = "undefined";
                throw new TypeError(`Body is undefined and cannot be returned as "stream".`);
            }
            this.#type = "stream";
            const streams = (this.#stream ?? this.#body).tee();
            this.#stream = streams[1];
            return {
                type,
                value: streams[0]
            };
        }
        if (!this.has()) {
            this.#type = "undefined";
        } else if (!this.#type) {
            const encoding = this.#headers.get("content-encoding") ?? "identity";
            if (encoding !== "identity") {
                throw new errors.UnsupportedMediaType(`Unsupported content-encoding: ${encoding}`);
            }
        }
        if (this.#type === "undefined" && (!type || type === "undefined")) {
            return {
                type: "undefined",
                value: undefined
            };
        }
        if (!type) {
            const contentType = this.#headers.get("content-type");
            assert1(contentType, "The Content-Type header is missing from the request");
            type = resolveType(contentType, contentTypes);
        }
        assert1(type);
        const body = Object.create(null);
        Object.defineProperties(body, {
            type: {
                value: type,
                configurable: true,
                enumerable: true
            },
            value: {
                get: this.#parse(type, limit),
                configurable: true,
                enumerable: true
            }
        });
        return body;
    }
    has() {
        return this.#body != null;
    }
}
class Request1 {
    #body;
    #proxy;
    #secure;
    #serverRequest;
    #url;
    #getRemoteAddr() {
        return this.#serverRequest.remoteAddr ?? "";
    }
    get hasBody() {
        return this.#body.has();
    }
    get headers() {
        return this.#serverRequest.headers;
    }
    get ip() {
        return (this.#proxy ? this.ips[0] : this.#getRemoteAddr()) ?? "";
    }
    get ips() {
        return this.#proxy ? (this.#serverRequest.headers.get("x-forwarded-for") ?? this.#getRemoteAddr()).split(/\s*,\s*/) : [];
    }
    get method() {
        return this.#serverRequest.method;
    }
    get secure() {
        return this.#secure;
    }
    get originalRequest() {
        return this.#serverRequest;
    }
    get url() {
        if (!this.#url) {
            const serverRequest = this.#serverRequest;
            if (!this.#proxy) {
                try {
                    if (serverRequest.rawUrl) {
                        this.#url = new URL(serverRequest.rawUrl);
                        return this.#url;
                    }
                } catch  {}
            }
            let proto;
            let host;
            if (this.#proxy) {
                proto = serverRequest.headers.get("x-forwarded-proto")?.split(/\s*,\s*/, 1)[0] ?? "http";
                host = serverRequest.headers.get("x-forwarded-host") ?? serverRequest.headers.get("host") ?? "";
            } else {
                proto = this.#secure ? "https" : "http";
                host = serverRequest.headers.get("host") ?? "";
            }
            try {
                this.#url = new URL(`${proto}://${host}${serverRequest.url}`);
            } catch  {
                throw new TypeError(`The server request URL of "${proto}://${host}${serverRequest.url}" is invalid.`);
            }
        }
        return this.#url;
    }
    constructor(serverRequest, { proxy =false , secure =false , jsonBodyReviver  } = {}){
        this.#proxy = proxy;
        this.#secure = secure;
        this.#serverRequest = serverRequest;
        this.#body = new RequestBody(serverRequest.getBody(), serverRequest.headers, jsonBodyReviver);
    }
    accepts(...types) {
        if (!this.#serverRequest.headers.has("Accept")) {
            return types.length ? types[0] : [
                "*/*"
            ];
        }
        if (types.length) {
            return accepts(this.#serverRequest, ...types);
        }
        return accepts(this.#serverRequest);
    }
    acceptsEncodings(...encodings) {
        if (!this.#serverRequest.headers.has("Accept-Encoding")) {
            return encodings.length ? encodings[0] : [
                "*"
            ];
        }
        if (encodings.length) {
            return acceptsEncodings(this.#serverRequest, ...encodings);
        }
        return acceptsEncodings(this.#serverRequest);
    }
    acceptsLanguages(...langs) {
        if (!this.#serverRequest.headers.get("Accept-Language")) {
            return langs.length ? langs[0] : [
                "*"
            ];
        }
        if (langs.length) {
            return acceptsLanguages(this.#serverRequest, ...langs);
        }
        return acceptsLanguages(this.#serverRequest);
    }
    body(options = {}) {
        return this.#body.get(options);
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { hasBody , headers , ip , ips , method , secure , url  } = this;
        return `${this.constructor.name} ${inspect({
            hasBody,
            headers,
            ip,
            ips,
            method,
            secure,
            url: url.toString()
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        const { hasBody , headers , ip , ips , method , secure , url  } = this;
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            hasBody,
            headers,
            ip,
            ips,
            method,
            secure,
            url
        }, newOptions)}`;
    }
}
const DomResponse = globalThis.Response ?? class MockResponse {
};
const maybeUpgradeWebSocket = "upgradeWebSocket" in Deno ? Deno.upgradeWebSocket.bind(Deno) : undefined;
class NativeRequest {
    #conn;
    #reject;
    #request;
    #requestPromise;
    #resolve;
    #resolved = false;
    #upgradeWebSocket;
    constructor(requestEvent, options = {}){
        const { conn  } = options;
        this.#conn = conn;
        this.#upgradeWebSocket = "upgradeWebSocket" in options ? options["upgradeWebSocket"] : maybeUpgradeWebSocket;
        this.#request = requestEvent.request;
        const p = new Promise((resolve, reject)=>{
            this.#resolve = resolve;
            this.#reject = reject;
        });
        this.#requestPromise = requestEvent.respondWith(p);
    }
    get body() {
        return this.#request.body;
    }
    get donePromise() {
        return this.#requestPromise;
    }
    get headers() {
        return this.#request.headers;
    }
    get method() {
        return this.#request.method;
    }
    get remoteAddr() {
        return (this.#conn?.remoteAddr)?.hostname;
    }
    get request() {
        return this.#request;
    }
    get url() {
        try {
            const url = new URL(this.#request.url);
            return this.#request.url.replace(url.origin, "");
        } catch  {}
        return this.#request.url;
    }
    get rawUrl() {
        return this.#request.url;
    }
    error(reason) {
        if (this.#resolved) {
            throw new Error("Request already responded to.");
        }
        this.#reject(reason);
        this.#resolved = true;
    }
    getBody() {
        return {
            body: this.#request.body,
            readBody: async ()=>{
                const ab = await this.#request.arrayBuffer();
                return new Uint8Array(ab);
            }
        };
    }
    respond(response) {
        if (this.#resolved) {
            throw new Error("Request already responded to.");
        }
        this.#resolve(response);
        this.#resolved = true;
        return this.#requestPromise;
    }
    upgrade(options) {
        if (this.#resolved) {
            throw new Error("Request already responded to.");
        }
        if (!this.#upgradeWebSocket) {
            throw new TypeError("Upgrading web sockets not supported.");
        }
        const { response , socket  } = this.#upgradeWebSocket(this.#request, options);
        this.#resolve(response);
        this.#resolved = true;
        return socket;
    }
}
const REDIRECT_BACK = Symbol("redirect backwards");
async function convertBodyToBodyInit(body, type, jsonBodyReplacer) {
    let result;
    if (BODY_TYPES.includes(typeof body)) {
        result = String(body);
        type = type ?? (isHtml(result) ? "html" : "text/plain");
    } else if (isReader(body)) {
        result = readableStreamFromReader(body);
    } else if (ArrayBuffer.isView(body) || body instanceof ArrayBuffer || body instanceof Blob || body instanceof URLSearchParams) {
        result = body;
    } else if (body instanceof ReadableStream) {
        result = body.pipeThrough(new Uint8ArrayTransformStream());
    } else if (body instanceof FormData) {
        result = body;
        type = "multipart/form-data";
    } else if (isAsyncIterable(body)) {
        result = readableStreamFromAsyncIterable(body);
    } else if (body && typeof body === "object") {
        result = JSON.stringify(body, jsonBodyReplacer);
        type = type ?? "json";
    } else if (typeof body === "function") {
        const result = body.call(null);
        return convertBodyToBodyInit(await result, type, jsonBodyReplacer);
    } else if (body) {
        throw new TypeError("Response body was set but could not be converted.");
    }
    return [
        result,
        type
    ];
}
class Response1 {
    #body;
    #bodySet = false;
    #domResponse;
    #headers = new Headers();
    #jsonBodyReplacer;
    #request;
    #resources = [];
    #status;
    #type;
    #writable = true;
    async #getBodyInit() {
        const [body, type] = await convertBodyToBodyInit(this.body, this.type, this.#jsonBodyReplacer);
        this.type = type;
        return body;
    }
    #setContentType() {
        if (this.type) {
            const contentTypeString = contentType(this.type);
            if (contentTypeString && !this.headers.has("Content-Type")) {
                this.headers.append("Content-Type", contentTypeString);
            }
        }
    }
    get body() {
        return this.#body;
    }
    set body(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#bodySet = true;
        this.#body = value;
    }
    get headers() {
        return this.#headers;
    }
    set headers(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#headers = value;
    }
    get status() {
        if (this.#status) {
            return this.#status;
        }
        return this.body != null ? Status.OK : this.#bodySet ? Status.NoContent : Status.NotFound;
    }
    set status(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#status = value;
    }
    get type() {
        return this.#type;
    }
    set type(value) {
        if (!this.#writable) {
            throw new Error("The response is not writable.");
        }
        this.#type = value;
    }
    get writable() {
        return this.#writable;
    }
    constructor(request, jsonBodyReplacer){
        this.#request = request;
        this.#jsonBodyReplacer = jsonBodyReplacer;
    }
    addResource(rid) {
        this.#resources.push(rid);
    }
    destroy(closeResources = true) {
        this.#writable = false;
        this.#body = undefined;
        this.#domResponse = undefined;
        if (closeResources) {
            for (const rid of this.#resources){
                try {
                    Deno.close(rid);
                } catch  {}
            }
        }
    }
    redirect(url, alt = "/") {
        if (url === REDIRECT_BACK) {
            url = this.#request.headers.get("Referer") ?? String(alt);
        } else if (typeof url === "object") {
            url = String(url);
        }
        this.headers.set("Location", encodeUrl(url));
        if (!this.status || !isRedirectStatus(this.status)) {
            this.status = Status.Found;
        }
        if (this.#request.accepts("html")) {
            url = encodeURI(url);
            this.type = "text/html; charset=UTF-8";
            this.body = `Redirecting to <a href="${url}">${url}</a>.`;
            return;
        }
        this.type = "text/plain; charset=UTF-8";
        this.body = `Redirecting to ${url}.`;
    }
    async toDomResponse() {
        if (this.#domResponse) {
            return this.#domResponse;
        }
        const bodyInit = await this.#getBodyInit();
        this.#setContentType();
        const { headers  } = this;
        if (!(bodyInit || headers.has("Content-Type") || headers.has("Content-Length"))) {
            headers.append("Content-Length", "0");
        }
        this.#writable = false;
        const status = this.status;
        const responseInit = {
            headers,
            status,
            statusText: STATUS_TEXT[status]
        };
        return this.#domResponse = new DomResponse(bodyInit, responseInit);
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { body , headers , status , type , writable  } = this;
        return `${this.constructor.name} ${inspect({
            body,
            headers,
            status,
            type,
            writable
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        const { body , headers , status , type , writable  } = this;
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            body,
            headers,
            status,
            type,
            writable
        }, newOptions)}`;
    }
}
function isFileInfo(value) {
    return Boolean(value && typeof value === "object" && "mtime" in value && "size" in value);
}
function calcStatTag(entity) {
    const mtime = entity.mtime?.getTime().toString(16) ?? "0";
    const size = entity.size.toString(16);
    return `"${size}-${mtime}"`;
}
const encoder3 = new TextEncoder();
async function calcEntityTag(entity) {
    if (entity.length === 0) {
        return `"0-2jmj7l5rSw0yVb/vlWAYkK/YBwk="`;
    }
    if (typeof entity === "string") {
        entity = encoder3.encode(entity);
    }
    const hash = mod.encode(await crypto.subtle.digest("SHA-1", entity)).substring(0, 27);
    return `"${entity.length.toString(16)}-${hash}"`;
}
function fstat(file) {
    if ("fstat" in Deno) {
        return Deno.fstat(file.rid);
    }
    return Promise.resolve(undefined);
}
function getEntity(context) {
    const { body  } = context.response;
    if (body instanceof Deno.FsFile) {
        return fstat(body);
    }
    if (body instanceof Uint8Array) {
        return Promise.resolve(body);
    }
    if (BODY_TYPES.includes(typeof body)) {
        return Promise.resolve(String(body));
    }
    if (isAsyncIterable(body) || isReader(body)) {
        return Promise.resolve(undefined);
    }
    if (typeof body === "object" && body !== null) {
        try {
            const bodyText = JSON.stringify(body);
            return Promise.resolve(bodyText);
        } catch  {}
    }
    return Promise.resolve(undefined);
}
async function calculate(entity, options = {}) {
    const weak = options.weak ?? isFileInfo(entity);
    const tag = isFileInfo(entity) ? calcStatTag(entity) : await calcEntityTag(entity);
    return weak ? `W/${tag}` : tag;
}
function factory(options) {
    return async function etag(context, next) {
        await next();
        if (!context.response.headers.has("ETag")) {
            const entity = await getEntity(context);
            if (entity) {
                context.response.headers.set("ETag", await calculate(entity, options));
            }
        }
    };
}
async function ifMatch(value, entity, options = {}) {
    const etag = await calculate(entity, options);
    if (etag.startsWith("W/")) {
        return false;
    }
    if (value.trim() === "*") {
        return true;
    }
    const tags = value.split(/\s*,\s*/);
    return tags.includes(etag);
}
async function ifNoneMatch(value, entity, options = {}) {
    if (value.trim() === "*") {
        return false;
    }
    const etag = await calculate(entity, options);
    const tags = value.split(/\s*,\s*/);
    return !tags.includes(etag);
}
const mod3 = {
    getEntity: getEntity,
    calculate: calculate,
    factory: factory,
    ifMatch: ifMatch,
    ifNoneMatch: ifNoneMatch
};
const ETAG_RE = /(?:W\/)?"[ !#-\x7E\x80-\xFF]+"/;
async function ifRange(value, mtime, entity) {
    if (value) {
        const matches = value.match(ETAG_RE);
        if (matches) {
            const [match] = matches;
            if (await calculate(entity) === match) {
                return true;
            }
        } else {
            return new Date(value).getTime() >= mtime;
        }
    }
    return false;
}
function parseRange(value, size) {
    const ranges = [];
    const [unit, rangesStr] = value.split("=");
    if (unit !== "bytes") {
        throw createHttpError(Status.RequestedRangeNotSatisfiable);
    }
    for (const range of rangesStr.split(/\s*,\s+/)){
        const item = range.split("-");
        if (item.length !== 2) {
            throw createHttpError(Status.RequestedRangeNotSatisfiable);
        }
        const [startStr, endStr] = item;
        let start;
        let end;
        try {
            if (startStr === "") {
                start = size - parseInt(endStr, 10) - 1;
                end = size - 1;
            } else if (endStr === "") {
                start = parseInt(startStr, 10);
                end = size - 1;
            } else {
                start = parseInt(startStr, 10);
                end = parseInt(endStr, 10);
            }
        } catch  {
            throw createHttpError();
        }
        if (start < 0 || start >= size || end < 0 || end >= size || start > end) {
            throw createHttpError(Status.RequestedRangeNotSatisfiable);
        }
        ranges.push({
            start,
            end
        });
    }
    return ranges;
}
async function readRange(file, range) {
    let length = range.end - range.start + 1;
    assert1(length);
    await file.seek(range.start, Deno.SeekMode.Start);
    const result = new Uint8Array(length);
    let off = 0;
    while(length){
        const p = new Uint8Array(Math.min(length, 16_640));
        const nread = await file.read(p);
        assert1(nread !== null, "Unexpected EOF encountered when reading a range.");
        assert1(nread > 0, "Unexpected read of 0 bytes while reading a range.");
        copy(p, result, off);
        off += nread;
        length -= nread;
        assert1(length >= 0, "Unexpected length remaining.");
    }
    return result;
}
const encoder4 = new TextEncoder();
class MultiPartStream extends ReadableStream {
    #contentLength;
    #postscript;
    #preamble;
    constructor(file, type, ranges, size, boundary){
        super({
            pull: async (controller)=>{
                const range = ranges.shift();
                if (!range) {
                    controller.enqueue(this.#postscript);
                    controller.close();
                    if (!(file instanceof Uint8Array)) {
                        file.close();
                    }
                    return;
                }
                let bytes;
                if (file instanceof Uint8Array) {
                    bytes = file.subarray(range.start, range.end + 1);
                } else {
                    bytes = await readRange(file, range);
                }
                const rangeHeader = encoder4.encode(`Content-Range: ${range.start}-${range.end}/${size}\n\n`);
                controller.enqueue(concat(this.#preamble, rangeHeader, bytes));
            }
        });
        const resolvedType = contentType(type);
        if (!resolvedType) {
            throw new TypeError(`Could not resolve media type for "${type}"`);
        }
        this.#preamble = encoder4.encode(`\n--${boundary}\nContent-Type: ${resolvedType}\n`);
        this.#postscript = encoder4.encode(`\n--${boundary}--\n`);
        this.#contentLength = ranges.reduce((prev, { start , end  })=>{
            return prev + this.#preamble.length + String(start).length + String(end).length + String(size).length + 20 + (end - start);
        }, this.#postscript.length);
    }
    contentLength() {
        return this.#contentLength;
    }
}
let boundary;
function isHidden(path) {
    const pathArr = path.split("/");
    for (const segment of pathArr){
        if (segment[0] === "." && segment !== "." && segment !== "..") {
            return true;
        }
        return false;
    }
}
async function exists(path) {
    try {
        return (await Deno.stat(path)).isFile;
    } catch  {
        return false;
    }
}
async function getEntity1(path, mtime, stats, maxbuffer, response) {
    let body;
    let entity;
    const file = await Deno.open(path, {
        read: true
    });
    if (stats.size < maxbuffer) {
        const buffer = await readAll(file);
        file.close();
        body = entity = buffer;
    } else {
        response.addResource(file.rid);
        body = file;
        entity = {
            mtime: new Date(mtime),
            size: stats.size
        };
    }
    return [
        body,
        entity
    ];
}
async function sendRange(response, body, range, size) {
    const ranges = parseRange(range, size);
    if (ranges.length === 0) {
        throw createHttpError(Status.RequestedRangeNotSatisfiable);
    }
    response.status = Status.PartialContent;
    if (ranges.length === 1) {
        const [byteRange] = ranges;
        response.headers.set("Content-Range", `bytes ${byteRange.start}-${byteRange.end}/${size}`);
        if (body instanceof Uint8Array) {
            response.body = body.slice(byteRange.start, byteRange.end + 1);
        } else {
            await body.seek(byteRange.start, Deno.SeekMode.Start);
            response.body = new LimitedReader(body, byteRange.end - byteRange.start + 1);
        }
    } else {
        assert1(response.type);
        if (!boundary) {
            boundary = await getBoundary();
        }
        response.headers.set("content-type", `multipart/byteranges; boundary=${boundary}`);
        const multipartBody = new MultiPartStream(body, response.type, ranges, size, boundary);
        response.body = multipartBody;
    }
}
async function send({ request , response  }, path, options = {
    root: ""
}) {
    const { brotli =true , contentTypes ={} , extensions , format =true , gzip =true , hidden =false , immutable =false , index , maxbuffer =1_048_576 , maxage =0 , root  } = options;
    const trailingSlash = path[path.length - 1] === "/";
    path = decodeComponent(path.substr(parse2(path).root.length));
    if (index && trailingSlash) {
        path += index;
    }
    if (!hidden && isHidden(path)) {
        throw createHttpError(403);
    }
    path = resolvePath(root, path);
    let encodingExt = "";
    if (brotli && request.acceptsEncodings("br", "identity") === "br" && await exists(`${path}.br`)) {
        path = `${path}.br`;
        response.headers.set("Content-Encoding", "br");
        response.headers.delete("Content-Length");
        encodingExt = ".br";
    } else if (gzip && request.acceptsEncodings("gzip", "identity") === "gzip" && await exists(`${path}.gz`)) {
        path = `${path}.gz`;
        response.headers.set("Content-Encoding", "gzip");
        response.headers.delete("Content-Length");
        encodingExt = ".gz";
    }
    if (extensions && !/\.[^/]*$/.exec(path)) {
        for (let ext of extensions){
            if (!/^\./.exec(ext)) {
                ext = `.${ext}`;
            }
            if (await exists(`${path}${ext}`)) {
                path += ext;
                break;
            }
        }
    }
    let stats;
    try {
        stats = await Deno.stat(path);
        if (stats.isDirectory) {
            if (format && index) {
                path += `/${index}`;
                stats = await Deno.stat(path);
            } else {
                return;
            }
        }
    } catch (err) {
        if (err instanceof Deno.errors.NotFound) {
            throw createHttpError(404, err.message);
        }
        if (err instanceof Error && err.message.startsWith("ENOENT:")) {
            throw createHttpError(404, err.message);
        }
        throw createHttpError(500, err instanceof Error ? err.message : "[non-error thrown]");
    }
    let mtime = null;
    if (response.headers.has("Last-Modified")) {
        mtime = new Date(response.headers.get("Last-Modified")).getTime();
    } else if (stats.mtime) {
        mtime = stats.mtime.getTime();
        mtime -= mtime % 1000;
        response.headers.set("Last-Modified", new Date(mtime).toUTCString());
    }
    if (!response.headers.has("Cache-Control")) {
        const directives = [
            `max-age=${maxage / 1000 | 0}`
        ];
        if (immutable) {
            directives.push("immutable");
        }
        response.headers.set("Cache-Control", directives.join(","));
    }
    if (!response.type) {
        response.type = encodingExt !== "" ? extname2(basename2(path, encodingExt)) : contentTypes[extname2(path)] ?? extname2(path);
    }
    let entity = null;
    let body = null;
    if (request.headers.has("If-None-Match") && mtime) {
        [body, entity] = await getEntity1(path, mtime, stats, maxbuffer, response);
        if (!await ifNoneMatch(request.headers.get("If-None-Match"), entity)) {
            response.headers.set("ETag", await calculate(entity));
            response.status = 304;
            return path;
        }
    }
    if (request.headers.has("If-Modified-Since") && mtime) {
        const ifModifiedSince = new Date(request.headers.get("If-Modified-Since"));
        if (ifModifiedSince.getTime() >= mtime) {
            response.status = 304;
            return path;
        }
    }
    if (!body || !entity) {
        [body, entity] = await getEntity1(path, mtime ?? 0, stats, maxbuffer, response);
    }
    if (request.headers.has("If-Range") && mtime && await ifRange(request.headers.get("If-Range"), mtime, entity) && request.headers.has("Range")) {
        await sendRange(response, body, request.headers.get("Range"), stats.size);
        return path;
    }
    if (request.headers.has("Range")) {
        await sendRange(response, body, request.headers.get("Range"), stats.size);
        return path;
    }
    response.body = body;
    if (!response.headers.has("ETag")) {
        response.headers.set("ETag", await calculate(entity));
    }
    if (!response.headers.has("Accept-Ranges")) {
        response.headers.set("Accept-Ranges", "bytes");
    }
    return path;
}
const encoder5 = new TextEncoder();
class CloseEvent extends Event {
    constructor(eventInit){
        super("close", eventInit);
    }
}
class ServerSentEvent extends Event {
    #data;
    #id;
    #type;
    constructor(type, data, eventInit = {}){
        super(type, eventInit);
        const { replacer , space  } = eventInit;
        this.#type = type;
        try {
            this.#data = typeof data === "string" ? data : JSON.stringify(data, replacer, space);
        } catch (e) {
            assert1(e instanceof Error);
            throw new TypeError(`data could not be coerced into a serialized string.\n  ${e.message}`);
        }
        const { id  } = eventInit;
        this.#id = id;
    }
    get data() {
        return this.#data;
    }
    get id() {
        return this.#id;
    }
    toString() {
        const data = `data: ${this.#data.split("\n").join("\ndata: ")}\n`;
        return `${this.#type === "__message" ? "" : `event: ${this.#type}\n`}${this.#id ? `id: ${String(this.#id)}\n` : ""}${data}\n`;
    }
}
const RESPONSE_HEADERS = [
    [
        "Connection",
        "Keep-Alive"
    ],
    [
        "Content-Type",
        "text/event-stream"
    ],
    [
        "Cache-Control",
        "no-cache"
    ],
    [
        "Keep-Alive",
        `timeout=${Number.MAX_SAFE_INTEGER}`
    ]
];
class SSEStreamTarget extends EventTarget {
    #closed = false;
    #context;
    #controller;
    #keepAliveId;
    #error(error) {
        console.log("error", error);
        this.dispatchEvent(new CloseEvent({
            cancelable: false
        }));
        const errorEvent = new ErrorEvent("error", {
            error
        });
        this.dispatchEvent(errorEvent);
        this.#context.app.dispatchEvent(errorEvent);
    }
    #push(payload) {
        if (!this.#controller) {
            this.#error(new Error("The controller has not been set."));
            return;
        }
        if (this.#closed) {
            return;
        }
        this.#controller.enqueue(encoder5.encode(payload));
    }
    get closed() {
        return this.#closed;
    }
    constructor(context, { headers , keepAlive =false  } = {}){
        super();
        this.#context = context;
        context.response.body = new ReadableStream({
            start: (controller)=>{
                this.#controller = controller;
            },
            cancel: (error)=>{
                if (error instanceof Error && error.message.includes("connection closed")) {
                    this.close();
                } else {
                    this.#error(error);
                }
            }
        });
        if (headers) {
            for (const [key, value] of headers){
                context.response.headers.set(key, value);
            }
        }
        for (const [key, value] of RESPONSE_HEADERS){
            context.response.headers.set(key, value);
        }
        this.addEventListener("close", ()=>{
            this.#closed = true;
            if (this.#keepAliveId != null) {
                clearInterval(this.#keepAliveId);
                this.#keepAliveId = undefined;
            }
            if (this.#controller) {
                try {
                    this.#controller.close();
                } catch  {}
            }
        });
        if (keepAlive) {
            const interval = typeof keepAlive === "number" ? keepAlive : 30_000;
            this.#keepAliveId = setInterval(()=>{
                this.dispatchComment("keep-alive comment");
            }, interval);
        }
    }
    close() {
        this.dispatchEvent(new CloseEvent({
            cancelable: false
        }));
        return Promise.resolve();
    }
    dispatchComment(comment) {
        this.#push(`: ${comment.split("\n").join("\n: ")}\n\n`);
        return true;
    }
    dispatchMessage(data) {
        const event = new ServerSentEvent("__message", data);
        return this.dispatchEvent(event);
    }
    dispatchEvent(event) {
        const dispatched = super.dispatchEvent(event);
        if (dispatched && event instanceof ServerSentEvent) {
            this.#push(String(event));
        }
        return dispatched;
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect({
            "#closed": this.#closed,
            "#context": this.#context
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            "#closed": this.#closed,
            "#context": this.#context
        }, newOptions)}`;
    }
}
class Context {
    #socket;
    #sse;
    #wrapReviverReplacer(reviver) {
        return reviver ? (key, value)=>reviver(key, value, this) : undefined;
    }
    app;
    cookies;
    get isUpgradable() {
        const upgrade = this.request.headers.get("upgrade");
        if (!upgrade || upgrade.toLowerCase() !== "websocket") {
            return false;
        }
        const secKey = this.request.headers.get("sec-websocket-key");
        return typeof secKey === "string" && secKey != "";
    }
    respond;
    request;
    response;
    get socket() {
        return this.#socket;
    }
    state;
    constructor(app, serverRequest, state, { secure =false , jsonBodyReplacer , jsonBodyReviver  } = {}){
        this.app = app;
        this.state = state;
        const { proxy  } = app;
        this.request = new Request1(serverRequest, {
            proxy,
            secure,
            jsonBodyReviver: this.#wrapReviverReplacer(jsonBodyReviver)
        });
        this.respond = true;
        this.response = new Response1(this.request, this.#wrapReviverReplacer(jsonBodyReplacer));
        this.cookies = new SecureCookieMap(serverRequest, {
            keys: this.app.keys,
            response: this.response,
            secure: this.request.secure
        });
    }
    assert(condition, errorStatus = 500, message, props) {
        if (condition) {
            return;
        }
        const err = createHttpError(errorStatus, message);
        if (props) {
            Object.assign(err, props);
        }
        throw err;
    }
    send(options) {
        const { path =this.request.url.pathname , ...sendOptions } = options;
        return send(this, path, sendOptions);
    }
    sendEvents(options) {
        if (!this.#sse) {
            this.#sse = new SSEStreamTarget(this, options);
        }
        return this.#sse;
    }
    throw(errorStatus, message, props) {
        const err = createHttpError(errorStatus, message);
        if (props) {
            Object.assign(err, props);
        }
        throw err;
    }
    upgrade(options) {
        if (this.#socket) {
            return this.#socket;
        }
        if (!this.request.originalRequest.upgrade) {
            throw new TypeError("Web socket upgrades not currently supported for this type of server.");
        }
        this.#socket = this.request.originalRequest.upgrade(options);
        this.respond = false;
        return this.#socket;
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { app , cookies , isUpgradable , respond , request , response , socket , state  } = this;
        return `${this.constructor.name} ${inspect({
            app,
            cookies,
            isUpgradable,
            respond,
            request,
            response,
            socket,
            state
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        const { app , cookies , isUpgradable , respond , request , response , socket , state  } = this;
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            app,
            cookies,
            isUpgradable,
            respond,
            request,
            response,
            socket,
            state
        }, newOptions)}`;
    }
}
const maybeUpgradeWebSocket1 = "upgradeWebSocket" in Deno ? Deno.upgradeWebSocket.bind(Deno) : undefined;
class HttpRequest {
    #deferred;
    #request;
    #resolved = false;
    #upgradeWebSocket;
    get remoteAddr() {
        return undefined;
    }
    get headers() {
        return this.#request.headers;
    }
    get method() {
        return this.#request.method;
    }
    get url() {
        try {
            const url = new URL(this.#request.url);
            return this.#request.url.replace(url.origin, "");
        } catch  {}
        return this.#request.url;
    }
    constructor(request, deferred, upgradeWebSocket){
        this.#deferred = deferred;
        this.#request = request;
        this.#upgradeWebSocket = upgradeWebSocket ?? maybeUpgradeWebSocket1;
    }
    error(reason) {
        if (this.#resolved) {
            throw new Error("Request already responded to.");
        }
        this.#deferred.reject(reason);
        this.#resolved = true;
    }
    getBody() {
        return {
            body: this.#request.body,
            readBody: async ()=>{
                const ab = await this.#request.arrayBuffer();
                return new Uint8Array(ab);
            }
        };
    }
    respond(response) {
        if (this.#resolved) {
            throw new Error("Request already responded to.");
        }
        this.#deferred.resolve(response);
        this.#resolved = true;
        return Promise.resolve();
    }
    upgrade(options) {
        if (this.#resolved) {
            throw new Error("Request already responded to.");
        }
        if (!this.#upgradeWebSocket) {
            throw new TypeError("Upgrading web sockets not supported.");
        }
        const { response , socket  } = this.#upgradeWebSocket(this.#request, options);
        this.#deferred.resolve(response);
        return socket;
    }
}
const serve = "serve" in Deno ? Deno.serve.bind(Deno) : undefined;
function hasFlash() {
    return Boolean(serve);
}
class FlashServer {
    #app;
    #closed = false;
    #controller;
    #abortController = new AbortController();
    #options;
    #servePromise;
    #stream;
    constructor(app, options){
        if (!serve) {
            throw new Error("The flash bindings for serving HTTP are not available.");
        }
        this.#app = app;
        this.#options = options;
    }
    async close() {
        if (this.#closed) {
            return;
        }
        this.#closed = true;
        try {
            this.#controller?.close();
            this.#controller = undefined;
            this.#stream = undefined;
            this.#abortController.abort();
            if (this.#servePromise) {
                await this.#servePromise;
                this.#servePromise = undefined;
            }
        } catch  {}
    }
    listen() {
        const p = deferred();
        const start = (controller)=>{
            this.#controller = controller;
            const options = {
                ...this.#options,
                signal: this.#abortController.signal,
                onListen: (addr)=>p.resolve({
                        addr
                    }),
                onError: (error)=>{
                    this.#app.dispatchEvent(new ErrorEvent("error", {
                        error
                    }));
                    return new Response("Internal server error", {
                        status: Status.InternalServerError,
                        statusText: STATUS_TEXT[Status.InternalServerError]
                    });
                }
            };
            const handler = (request)=>{
                const resolve = deferred();
                const flashRequest = new HttpRequest(request, resolve);
                controller.enqueue(flashRequest);
                return resolve;
            };
            this.#servePromise = serve(handler, options);
        };
        this.#stream = new ReadableStream({
            start
        });
        return p;
    }
    [Symbol.asyncIterator]() {
        assert1(this.#stream, ".listen() was not called before iterating or server is closed.");
        return this.#stream[Symbol.asyncIterator]();
    }
}
const serveHttp = "serveHttp" in Deno ? Deno.serveHttp.bind(Deno) : undefined;
class HttpServer {
    #app;
    #closed = false;
    #listener;
    #httpConnections = new Set();
    #options;
    constructor(app, options){
        if (!("serveHttp" in Deno)) {
            throw new Error("The native bindings for serving HTTP are not available.");
        }
        this.#app = app;
        this.#options = options;
    }
    get app() {
        return this.#app;
    }
    get closed() {
        return this.#closed;
    }
    close() {
        this.#closed = true;
        if (this.#listener) {
            this.#listener.close();
            this.#listener = undefined;
        }
        for (const httpConn of this.#httpConnections){
            try {
                httpConn.close();
            } catch (error) {
                if (!(error instanceof Deno.errors.BadResource)) {
                    throw error;
                }
            }
        }
        this.#httpConnections.clear();
    }
    listen() {
        return this.#listener = isListenTlsOptions(this.#options) ? Deno.listenTls(this.#options) : Deno.listen(this.#options);
    }
    #trackHttpConnection(httpConn) {
        this.#httpConnections.add(httpConn);
    }
    #untrackHttpConnection(httpConn1) {
        this.#httpConnections.delete(httpConn1);
    }
    [Symbol.asyncIterator]() {
        const start = (controller)=>{
            const server = this;
            async function serve(conn) {
                const httpConn = serveHttp(conn);
                server.#trackHttpConnection(httpConn);
                while(true){
                    try {
                        const requestEvent = await httpConn.nextRequest();
                        if (requestEvent === null) {
                            return;
                        }
                        const nativeRequest = new NativeRequest(requestEvent, {
                            conn
                        });
                        controller.enqueue(nativeRequest);
                        nativeRequest.donePromise.catch((error)=>{
                            server.app.dispatchEvent(new ErrorEvent("error", {
                                error
                            }));
                        });
                    } catch (error) {
                        server.app.dispatchEvent(new ErrorEvent("error", {
                            error
                        }));
                    }
                    if (server.closed) {
                        server.#untrackHttpConnection(httpConn);
                        httpConn.close();
                        controller.close();
                    }
                }
            }
            const listener = this.#listener;
            assert1(listener);
            async function accept() {
                while(true){
                    try {
                        const conn = await listener.accept();
                        serve(conn);
                    } catch (error) {
                        if (!server.closed) {
                            server.app.dispatchEvent(new ErrorEvent("error", {
                                error
                            }));
                        }
                    }
                    if (server.closed) {
                        controller.close();
                        return;
                    }
                }
            }
            accept();
        };
        const stream = new ReadableStream({
            start
        });
        return stream[Symbol.asyncIterator]();
    }
}
function compose(middleware) {
    return function composedMiddleware(context, next) {
        let index = -1;
        async function dispatch(i) {
            if (i <= index) {
                throw new Error("next() called multiple times.");
            }
            index = i;
            let fn = middleware[i];
            if (i === middleware.length) {
                fn = next;
            }
            if (!fn) {
                return;
            }
            await fn(context, dispatch.bind(null, i + 1));
        }
        return dispatch(0);
    };
}
const objectCloneMemo = new WeakMap();
function cloneArrayBuffer(srcBuffer, srcByteOffset, srcLength, _cloneConstructor) {
    return srcBuffer.slice(srcByteOffset, srcByteOffset + srcLength);
}
function cloneValue(value) {
    switch(typeof value){
        case "number":
        case "string":
        case "boolean":
        case "undefined":
        case "bigint":
            return value;
        case "object":
            {
                if (objectCloneMemo.has(value)) {
                    return objectCloneMemo.get(value);
                }
                if (value === null) {
                    return value;
                }
                if (value instanceof Date) {
                    return new Date(value.valueOf());
                }
                if (value instanceof RegExp) {
                    return new RegExp(value);
                }
                if (value instanceof SharedArrayBuffer) {
                    return value;
                }
                if (value instanceof ArrayBuffer) {
                    const cloned = cloneArrayBuffer(value, 0, value.byteLength, ArrayBuffer);
                    objectCloneMemo.set(value, cloned);
                    return cloned;
                }
                if (ArrayBuffer.isView(value)) {
                    const clonedBuffer = cloneValue(value.buffer);
                    let length;
                    if (value instanceof DataView) {
                        length = value.byteLength;
                    } else {
                        length = value.length;
                    }
                    return new value.constructor(clonedBuffer, value.byteOffset, length);
                }
                if (value instanceof Map) {
                    const clonedMap = new Map();
                    objectCloneMemo.set(value, clonedMap);
                    value.forEach((v, k)=>{
                        clonedMap.set(cloneValue(k), cloneValue(v));
                    });
                    return clonedMap;
                }
                if (value instanceof Set) {
                    const clonedSet = new Set([
                        ...value
                    ].map(cloneValue));
                    objectCloneMemo.set(value, clonedSet);
                    return clonedSet;
                }
                const clonedObj = {};
                objectCloneMemo.set(value, clonedObj);
                const sourceKeys = Object.getOwnPropertyNames(value);
                for (const key of sourceKeys){
                    clonedObj[key] = cloneValue(value[key]);
                }
                Reflect.setPrototypeOf(clonedObj, Reflect.getPrototypeOf(value));
                return clonedObj;
            }
        case "symbol":
        case "function":
        default:
            throw new DOMException("Uncloneable value in stream", "DataCloneError");
    }
}
const core = Deno?.core;
const structuredClone = globalThis.structuredClone;
function sc(value) {
    return structuredClone ? structuredClone(value) : core ? core.deserialize(core.serialize(value)) : cloneValue(value);
}
function cloneState(state) {
    const clone = {};
    for (const [key, value] of Object.entries(state)){
        try {
            const clonedValue = sc(value);
            clone[key] = clonedValue;
        } catch  {}
    }
    return clone;
}
const ADDR_REGEXP = /^\[?([^\]]*)\]?:([0-9]{1,5})$/;
class ApplicationErrorEvent extends ErrorEvent {
    context;
    constructor(eventInitDict){
        super("error", eventInitDict);
        this.context = eventInitDict.context;
    }
}
function logErrorListener({ error , context  }) {
    if (error instanceof Error) {
        console.error(`[uncaught application error]: ${error.name} - ${error.message}`);
    } else {
        console.error(`[uncaught application error]\n`, error);
    }
    if (context) {
        let url;
        try {
            url = context.request.url.toString();
        } catch  {
            url = "[malformed url]";
        }
        console.error(`\nrequest:`, {
            url,
            method: context.request.method,
            hasBody: context.request.hasBody
        });
        console.error(`response:`, {
            status: context.response.status,
            type: context.response.type,
            hasBody: !!context.response.body,
            writable: context.response.writable
        });
    }
    if (error instanceof Error && error.stack) {
        console.error(`\n${error.stack.split("\n").slice(1).join("\n")}`);
    }
}
class ApplicationListenEvent extends Event {
    hostname;
    listener;
    port;
    secure;
    serverType;
    constructor(eventInitDict){
        super("listen", eventInitDict);
        this.hostname = eventInitDict.hostname;
        this.listener = eventInitDict.listener;
        this.port = eventInitDict.port;
        this.secure = eventInitDict.secure;
        this.serverType = eventInitDict.serverType;
    }
}
class Application extends EventTarget {
    #composedMiddleware;
    #contextOptions;
    #contextState;
    #keys;
    #middleware = [];
    #serverConstructor;
    get keys() {
        return this.#keys;
    }
    set keys(keys) {
        if (!keys) {
            this.#keys = undefined;
            return;
        } else if (Array.isArray(keys)) {
            this.#keys = new KeyStack(keys);
        } else {
            this.#keys = keys;
        }
    }
    proxy;
    state;
    constructor(options = {}){
        super();
        const { state , keys , proxy , serverConstructor =HttpServer , contextState ="clone" , logErrors =true , ...contextOptions } = options;
        this.proxy = proxy ?? false;
        this.keys = keys;
        this.state = state ?? {};
        this.#serverConstructor = serverConstructor;
        this.#contextOptions = contextOptions;
        this.#contextState = contextState;
        if (logErrors) {
            this.addEventListener("error", logErrorListener);
        }
    }
    #getComposed() {
        if (!this.#composedMiddleware) {
            this.#composedMiddleware = compose(this.#middleware);
        }
        return this.#composedMiddleware;
    }
    #getContextState() {
        switch(this.#contextState){
            case "alias":
                return this.state;
            case "clone":
                return cloneState(this.state);
            case "empty":
                return {};
            case "prototype":
                return Object.create(this.state);
        }
    }
    #handleError(context, error1) {
        if (!(error1 instanceof Error)) {
            error1 = new Error(`non-error thrown: ${JSON.stringify(error1)}`);
        }
        const { message  } = error1;
        this.dispatchEvent(new ApplicationErrorEvent({
            context,
            message,
            error: error1
        }));
        if (!context.response.writable) {
            return;
        }
        for (const key of [
            ...context.response.headers.keys()
        ]){
            context.response.headers.delete(key);
        }
        if (error1.headers && error1.headers instanceof Headers) {
            for (const [key, value] of error1.headers){
                context.response.headers.set(key, value);
            }
        }
        context.response.type = "text";
        const status = context.response.status = Deno.errors && error1 instanceof Deno.errors.NotFound ? 404 : error1.status && typeof error1.status === "number" ? error1.status : 500;
        context.response.body = error1.expose ? error1.message : STATUS_TEXT[status];
    }
    async #handleRequest(request, secure, state) {
        let context;
        try {
            context = new Context(this, request, this.#getContextState(), {
                secure,
                ...this.#contextOptions
            });
        } catch (e) {
            const error = e instanceof Error ? e : new Error(`non-error thrown: ${JSON.stringify(e)}`);
            const { message  } = error;
            this.dispatchEvent(new ApplicationErrorEvent({
                message,
                error
            }));
            return;
        }
        assert1(context, "Context was not created.");
        let resolve;
        const handlingPromise = new Promise((res)=>resolve = res);
        state.handling.add(handlingPromise);
        if (!state.closing && !state.closed) {
            try {
                await this.#getComposed()(context);
            } catch (err) {
                this.#handleError(context, err);
            }
        }
        if (context.respond === false) {
            context.response.destroy();
            resolve();
            state.handling.delete(handlingPromise);
            return;
        }
        let closeResources = true;
        let response;
        try {
            closeResources = false;
            response = await context.response.toDomResponse();
        } catch (err) {
            this.#handleError(context, err);
            response = await context.response.toDomResponse();
        }
        assert1(response);
        try {
            await request.respond(response);
        } catch (err) {
            this.#handleError(context, err);
        } finally{
            context.response.destroy(closeResources);
            resolve();
            state.handling.delete(handlingPromise);
            if (state.closing) {
                await state.server.close();
                state.closed = true;
            }
        }
    }
    addEventListener(type, listener, options) {
        super.addEventListener(type, listener, options);
    }
    handle = async (request, secureOrConn, secure = false)=>{
        if (!this.#middleware.length) {
            throw new TypeError("There is no middleware to process requests.");
        }
        assert1(isConn(secureOrConn) || typeof secureOrConn === "undefined");
        const contextRequest = new NativeRequest({
            request,
            respondWith () {
                return Promise.resolve(undefined);
            }
        }, {
            conn: secureOrConn
        });
        const context = new Context(this, contextRequest, this.#getContextState(), {
            secure,
            ...this.#contextOptions
        });
        try {
            await this.#getComposed()(context);
        } catch (err) {
            this.#handleError(context, err);
        }
        if (context.respond === false) {
            context.response.destroy();
            return;
        }
        try {
            const response = await context.response.toDomResponse();
            context.response.destroy(false);
            return response;
        } catch (err) {
            this.#handleError(context, err);
            throw err;
        }
    };
    async listen(options = {
        port: 0
    }) {
        if (!this.#middleware.length) {
            throw new TypeError("There is no middleware to process requests.");
        }
        if (typeof options === "string") {
            const match = ADDR_REGEXP.exec(options);
            if (!match) {
                throw TypeError(`Invalid address passed: "${options}"`);
            }
            const [, hostname, portStr] = match;
            options = {
                hostname,
                port: parseInt(portStr, 10)
            };
        }
        options = Object.assign({
            port: 0
        }, options);
        const server = new this.#serverConstructor(this, options);
        const { signal  } = options;
        const state = {
            closed: false,
            closing: false,
            handling: new Set(),
            server
        };
        if (signal) {
            signal.addEventListener("abort", ()=>{
                if (!state.handling.size) {
                    server.close();
                    state.closed = true;
                }
                state.closing = true;
            });
        }
        const { secure =false  } = options;
        const serverType = server instanceof HttpServer ? "native" : server instanceof FlashServer ? "flash" : "custom";
        const listener = await server.listen();
        const { hostname , port  } = listener.addr;
        this.dispatchEvent(new ApplicationListenEvent({
            hostname,
            listener,
            port,
            secure,
            serverType
        }));
        try {
            for await (const request of server){
                this.#handleRequest(request, secure, state);
            }
            await Promise.all(state.handling);
        } catch (error) {
            const message = error instanceof Error ? error.message : "Application Error";
            this.dispatchEvent(new ApplicationErrorEvent({
                message,
                error
            }));
        }
    }
    use(...middleware) {
        this.#middleware.push(...middleware);
        this.#composedMiddleware = undefined;
        return this;
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { keys , proxy , state  } = this;
        return `${this.constructor.name} ${inspect({
            "#middleware": this.#middleware,
            keys,
            proxy,
            state
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        const { keys , proxy , state  } = this;
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            "#middleware": this.#middleware,
            keys,
            proxy,
            state
        }, newOptions)}`;
    }
}
function getQuery(ctx, { mergeParams , asMap  } = {}) {
    const result = {};
    if (mergeParams && isRouterContext(ctx)) {
        Object.assign(result, ctx.params);
    }
    for (const [key, value] of ctx.request.url.searchParams){
        result[key] = value;
    }
    return asMap ? new Map(Object.entries(result)) : result;
}
const mod4 = {
    getQuery: getQuery
};
const FORWARDED_RE = /^(,[ \\t]*)*([!#$%&'*+.^_`|~0-9A-Za-z-]+=([!#$%&'*+.^_`|~0-9A-Za-z-]+|\"([\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]|\\\\[\\t \\x21-\\x7E\\x80-\\xFF])*\"))?(;([!#$%&'*+.^_`|~0-9A-Za-z-]+=([!#$%&'*+.^_`|~0-9A-Za-z-]+|\"([\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]|\\\\[\\t \\x21-\\x7E\\x80-\\xFF])*\"))?)*([ \\t]*,([ \\t]*([!#$%&'*+.^_`|~0-9A-Za-z-]+=([!#$%&'*+.^_`|~0-9A-Za-z-]+|\"([\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]|\\\\[\\t \\x21-\\x7E\\x80-\\xFF])*\"))?(;([!#$%&'*+.^_`|~0-9A-Za-z-]+=([!#$%&'*+.^_`|~0-9A-Za-z-]+|\"([\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]|\\\\[\\t \\x21-\\x7E\\x80-\\xFF])*\"))?)*)?)*$/;
function createMatcher({ match  }) {
    return function matches(ctx) {
        if (!match) {
            return true;
        }
        if (typeof match === "string") {
            return ctx.request.url.pathname.startsWith(match);
        }
        if (match instanceof RegExp) {
            return match.test(ctx.request.url.pathname);
        }
        return match(ctx);
    };
}
async function createRequest(target, ctx, { headers: optHeaders , map , proxyHeaders =true , request: reqFn  }) {
    let path = ctx.request.url.pathname;
    let params;
    if (isRouterContext(ctx)) {
        params = ctx.params;
    }
    if (map && typeof map === "function") {
        path = map(path, params);
    } else if (map) {
        path = map[path] ?? path;
    }
    const url = new URL(String(target));
    if (url.pathname.endsWith("/") && path.startsWith("/")) {
        url.pathname = `${url.pathname}${path.slice(1)}`;
    } else if (!url.pathname.endsWith("/") && !path.startsWith("/")) {
        url.pathname = `${url.pathname}/${path}`;
    } else {
        url.pathname = `${url.pathname}${path}`;
    }
    url.search = ctx.request.url.search;
    const body = getBodyInit(ctx);
    const headers = new Headers(ctx.request.headers);
    if (optHeaders) {
        if (typeof optHeaders === "function") {
            optHeaders = await optHeaders(ctx);
        }
        for (const [key, value] of iterableHeaders(optHeaders)){
            headers.set(key, value);
        }
    }
    if (proxyHeaders) {
        const maybeForwarded = headers.get("forwarded");
        const ip = ctx.request.ip.startsWith("[") ? `"${ctx.request.ip}"` : ctx.request.ip;
        const host = headers.get("host");
        if (maybeForwarded && FORWARDED_RE.test(maybeForwarded)) {
            let value = `for=${ip}`;
            if (host) {
                value += `;host=${host}`;
            }
            headers.append("forwarded", value);
        } else {
            headers.append("x-forwarded-for", ip);
            if (host) {
                headers.append("x-forwarded-host", host);
            }
        }
    }
    const init = {
        body,
        headers,
        method: ctx.request.method,
        redirect: "follow"
    };
    let request = new Request(url.toString(), init);
    if (reqFn) {
        request = await reqFn(request);
    }
    return request;
}
function getBodyInit(ctx) {
    if (!ctx.request.hasBody) {
        return null;
    }
    return ctx.request.body({
        type: "stream"
    }).value;
}
function iterableHeaders(headers) {
    if (headers instanceof Headers) {
        return headers.entries();
    } else if (Array.isArray(headers)) {
        return headers.values();
    } else {
        return Object.entries(headers).values();
    }
}
async function processResponse(response, ctx, { contentType: contentTypeFn , response: resFn  }) {
    if (resFn) {
        response = await resFn(response);
    }
    if (response.body) {
        ctx.response.body = response.body;
    } else {
        ctx.response.body = null;
    }
    ctx.response.status = response.status;
    for (const [key, value] of response.headers){
        ctx.response.headers.append(key, value);
    }
    if (contentTypeFn) {
        const value = await contentTypeFn(response.url, ctx.response.headers.get("content-type") ?? undefined);
        if (value != null) {
            ctx.response.headers.set("content-type", value);
        }
    }
}
function proxy(target, options = {}) {
    const matches = createMatcher(options);
    return async function proxy(ctx, next) {
        if (!matches(ctx)) {
            return next();
        }
        const request = await createRequest(target, ctx, options);
        const { fetch: fetch1 = globalThis.fetch  } = options;
        const response = await fetch1(request);
        await processResponse(response, ctx, options);
        return next();
    };
}
function toUrl(url, params = {}, options) {
    const tokens = parse3(url);
    let replace = {};
    if (tokens.some((token)=>typeof token === "object")) {
        replace = params;
    } else {
        options = params;
    }
    const toPath = compile(url, options);
    const replaced = toPath(replace);
    if (options && options.query) {
        const url = new URL(replaced, "http://oak");
        if (typeof options.query === "string") {
            url.search = options.query;
        } else {
            url.search = String(options.query instanceof URLSearchParams ? options.query : new URLSearchParams(options.query));
        }
        return `${url.pathname}${url.search}${url.hash}`;
    }
    return replaced;
}
class Layer {
    #opts;
    #paramNames = [];
    #regexp;
    methods;
    name;
    path;
    stack;
    constructor(path, methods, middleware, { name , ...opts } = {}){
        this.#opts = opts;
        this.name = name;
        this.methods = [
            ...methods
        ];
        if (this.methods.includes("GET")) {
            this.methods.unshift("HEAD");
        }
        this.stack = Array.isArray(middleware) ? middleware.slice() : [
            middleware
        ];
        this.path = path;
        this.#regexp = pathToRegexp(path, this.#paramNames, this.#opts);
    }
    clone() {
        return new Layer(this.path, this.methods, this.stack, {
            name: this.name,
            ...this.#opts
        });
    }
    match(path) {
        return this.#regexp.test(path);
    }
    params(captures, existingParams = {}) {
        const params = existingParams;
        for(let i = 0; i < captures.length; i++){
            if (this.#paramNames[i]) {
                const c = captures[i];
                params[this.#paramNames[i].name] = c ? decodeComponent(c) : c;
            }
        }
        return params;
    }
    captures(path) {
        if (this.#opts.ignoreCaptures) {
            return [];
        }
        return path.match(this.#regexp)?.slice(1) ?? [];
    }
    url(params = {}, options) {
        const url = this.path.replace(/\(\.\*\)/g, "");
        return toUrl(url, params, options);
    }
    param(param, fn) {
        const stack = this.stack;
        const params = this.#paramNames;
        const middleware = function(ctx, next) {
            const p = ctx.params[param];
            assert1(p);
            return fn.call(this, p, ctx, next);
        };
        middleware.param = param;
        const names = params.map((p)=>p.name);
        const x = names.indexOf(param);
        if (x >= 0) {
            for(let i = 0; i < stack.length; i++){
                const fn = stack[i];
                if (!fn.param || names.indexOf(fn.param) > x) {
                    stack.splice(i, 0, middleware);
                    break;
                }
            }
        }
        return this;
    }
    setPrefix(prefix) {
        if (this.path) {
            this.path = this.path !== "/" || this.#opts.strict === true ? `${prefix}${this.path}` : prefix;
            this.#paramNames = [];
            this.#regexp = pathToRegexp(this.path, this.#paramNames, this.#opts);
        }
        return this;
    }
    toJSON() {
        return {
            methods: [
                ...this.methods
            ],
            middleware: [
                ...this.stack
            ],
            paramNames: this.#paramNames.map((key)=>key.name),
            path: this.path,
            regexp: this.#regexp,
            options: {
                ...this.#opts
            }
        };
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect({
            methods: this.methods,
            middleware: this.stack,
            options: this.#opts,
            paramNames: this.#paramNames.map((key)=>key.name),
            path: this.path,
            regexp: this.#regexp
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            methods: this.methods,
            middleware: this.stack,
            options: this.#opts,
            paramNames: this.#paramNames.map((key)=>key.name),
            path: this.path,
            regexp: this.#regexp
        }, newOptions)}`;
    }
}
class Router {
    #opts;
    #methods;
    #params = {};
    #stack = [];
    #match(path2, method) {
        const matches = {
            path: [],
            pathAndMethod: [],
            route: false
        };
        for (const route of this.#stack){
            if (route.match(path2)) {
                matches.path.push(route);
                if (route.methods.length === 0 || route.methods.includes(method)) {
                    matches.pathAndMethod.push(route);
                    if (route.methods.length) {
                        matches.route = true;
                        matches.name = route.name;
                    }
                }
            }
        }
        return matches;
    }
    #register(path11, middlewares, methods, options = {}) {
        if (Array.isArray(path11)) {
            for (const p of path11){
                this.#register(p, middlewares, methods, options);
            }
            return;
        }
        let layerMiddlewares = [];
        for (const middleware of middlewares){
            if (!middleware.router) {
                layerMiddlewares.push(middleware);
                continue;
            }
            if (layerMiddlewares.length) {
                this.#addLayer(path11, layerMiddlewares, methods, options);
                layerMiddlewares = [];
            }
            const router = middleware.router.#clone();
            for (const layer of router.#stack){
                if (!options.ignorePrefix) {
                    layer.setPrefix(path11);
                }
                if (this.#opts.prefix) {
                    layer.setPrefix(this.#opts.prefix);
                }
                this.#stack.push(layer);
            }
            for (const [param, mw] of Object.entries(this.#params)){
                router.param(param, mw);
            }
        }
        if (layerMiddlewares.length) {
            this.#addLayer(path11, layerMiddlewares, methods, options);
        }
    }
    #addLayer(path21, middlewares1, methods1, options1 = {}) {
        const { end , name , sensitive =this.#opts.sensitive , strict =this.#opts.strict , ignoreCaptures  } = options1;
        const route = new Layer(path21, methods1, middlewares1, {
            end,
            name,
            sensitive,
            strict,
            ignoreCaptures
        });
        if (this.#opts.prefix) {
            route.setPrefix(this.#opts.prefix);
        }
        for (const [param, mw] of Object.entries(this.#params)){
            route.param(param, mw);
        }
        this.#stack.push(route);
    }
    #route(name) {
        for (const route of this.#stack){
            if (route.name === name) {
                return route;
            }
        }
    }
    #useVerb(nameOrPath, pathOrMiddleware, middleware, methods2) {
        let name = undefined;
        let path;
        if (typeof pathOrMiddleware === "string") {
            name = nameOrPath;
            path = pathOrMiddleware;
        } else {
            path = nameOrPath;
            middleware.unshift(pathOrMiddleware);
        }
        this.#register(path, middleware, methods2, {
            name
        });
    }
    #clone() {
        const router = new Router(this.#opts);
        router.#methods = router.#methods.slice();
        router.#params = {
            ...this.#params
        };
        router.#stack = this.#stack.map((layer)=>layer.clone());
        return router;
    }
    constructor(opts = {}){
        this.#opts = opts;
        this.#methods = opts.methods ?? [
            "DELETE",
            "GET",
            "HEAD",
            "OPTIONS",
            "PATCH",
            "POST",
            "PUT"
        ];
    }
    all(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, this.#methods.filter((method)=>method !== "OPTIONS"));
        return this;
    }
    allowedMethods(options = {}) {
        const implemented = this.#methods;
        const allowedMethods = async (context, next)=>{
            const ctx = context;
            await next();
            if (!ctx.response.status || ctx.response.status === Status.NotFound) {
                assert1(ctx.matched);
                const allowed = new Set();
                for (const route of ctx.matched){
                    for (const method of route.methods){
                        allowed.add(method);
                    }
                }
                const allowedStr = [
                    ...allowed
                ].join(", ");
                if (!implemented.includes(ctx.request.method)) {
                    if (options.throw) {
                        throw options.notImplemented ? options.notImplemented() : new errors.NotImplemented();
                    } else {
                        ctx.response.status = Status.NotImplemented;
                        ctx.response.headers.set("Allow", allowedStr);
                    }
                } else if (allowed.size) {
                    if (ctx.request.method === "OPTIONS") {
                        ctx.response.status = Status.OK;
                        ctx.response.headers.set("Allow", allowedStr);
                    } else if (!allowed.has(ctx.request.method)) {
                        if (options.throw) {
                            throw options.methodNotAllowed ? options.methodNotAllowed() : new errors.MethodNotAllowed();
                        } else {
                            ctx.response.status = Status.MethodNotAllowed;
                            ctx.response.headers.set("Allow", allowedStr);
                        }
                    }
                }
            }
        };
        return allowedMethods;
    }
    delete(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "DELETE"
        ]);
        return this;
    }
    *entries() {
        for (const route of this.#stack){
            const value = route.toJSON();
            yield [
                value,
                value
            ];
        }
    }
    forEach(callback, thisArg = null) {
        for (const route of this.#stack){
            const value = route.toJSON();
            callback.call(thisArg, value, value, this);
        }
    }
    get(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "GET"
        ]);
        return this;
    }
    head(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "HEAD"
        ]);
        return this;
    }
    *keys() {
        for (const route of this.#stack){
            yield route.toJSON();
        }
    }
    options(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "OPTIONS"
        ]);
        return this;
    }
    param(param, middleware) {
        this.#params[param] = middleware;
        for (const route of this.#stack){
            route.param(param, middleware);
        }
        return this;
    }
    patch(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "PATCH"
        ]);
        return this;
    }
    post(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "POST"
        ]);
        return this;
    }
    prefix(prefix) {
        prefix = prefix.replace(/\/$/, "");
        this.#opts.prefix = prefix;
        for (const route of this.#stack){
            route.setPrefix(prefix);
        }
        return this;
    }
    put(nameOrPath, pathOrMiddleware, ...middleware) {
        this.#useVerb(nameOrPath, pathOrMiddleware, middleware, [
            "PUT"
        ]);
        return this;
    }
    redirect(source, destination, status = Status.Found) {
        if (source[0] !== "/") {
            const s = this.url(source);
            if (!s) {
                throw new RangeError(`Could not resolve named route: "${source}"`);
            }
            source = s;
        }
        if (typeof destination === "string") {
            if (destination[0] !== "/") {
                const d = this.url(destination);
                if (!d) {
                    try {
                        const url = new URL(destination);
                        destination = url;
                    } catch  {
                        throw new RangeError(`Could not resolve named route: "${source}"`);
                    }
                } else {
                    destination = d;
                }
            }
        }
        this.all(source, async (ctx, next)=>{
            await next();
            ctx.response.redirect(destination);
            ctx.response.status = status;
        });
        return this;
    }
    routes() {
        const dispatch = (context, next)=>{
            const ctx = context;
            let pathname;
            let method;
            try {
                const { url: { pathname: p  } , method: m  } = ctx.request;
                pathname = p;
                method = m;
            } catch (e) {
                return Promise.reject(e);
            }
            const path = this.#opts.routerPath ?? ctx.routerPath ?? decodeURI(pathname);
            const matches = this.#match(path, method);
            if (ctx.matched) {
                ctx.matched.push(...matches.path);
            } else {
                ctx.matched = [
                    ...matches.path
                ];
            }
            ctx.router = this;
            if (!matches.route) return next();
            ctx.routeName = matches.name;
            const { pathAndMethod: matchedRoutes  } = matches;
            const chain = matchedRoutes.reduce((prev, route)=>[
                    ...prev,
                    (ctx, next)=>{
                        ctx.captures = route.captures(path);
                        ctx.params = route.params(ctx.captures, ctx.params);
                        return next();
                    },
                    ...route.stack
                ], []);
            return compose(chain)(ctx, next);
        };
        dispatch.router = this;
        return dispatch;
    }
    url(name, params, options) {
        const route = this.#route(name);
        if (route) {
            return route.url(params, options);
        }
    }
    use(pathOrMiddleware, ...middleware) {
        let path;
        if (typeof pathOrMiddleware === "string" || Array.isArray(pathOrMiddleware)) {
            path = pathOrMiddleware;
        } else {
            middleware.unshift(pathOrMiddleware);
        }
        this.#register(path ?? "(.*)", middleware, [], {
            end: false,
            ignoreCaptures: !path,
            ignorePrefix: !path
        });
        return this;
    }
    *values() {
        for (const route of this.#stack){
            yield route.toJSON();
        }
    }
    *[Symbol.iterator]() {
        for (const route of this.#stack){
            yield route.toJSON();
        }
    }
    static url(path, params, options) {
        return toUrl(path, params, options);
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        return `${this.constructor.name} ${inspect({
            "#params": this.#params,
            "#stack": this.#stack
        })}`;
    }
    [Symbol.for("nodejs.util.inspect.custom")](depth, options, inspect) {
        if (depth < 0) {
            return options.stylize(`[${this.constructor.name}]`, "special");
        }
        const newOptions = Object.assign({}, options, {
            depth: options.depth === null ? null : options.depth - 1
        });
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            "#params": this.#params,
            "#stack": this.#stack
        }, newOptions)}`;
    }
}
function createMockApp(state = {}) {
    const app = {
        state,
        use () {
            return app;
        },
        [Symbol.for("Deno.customInspect")] () {
            return "MockApplication {}";
        },
        [Symbol.for("nodejs.util.inspect.custom")] (depth, options, inspect) {
            if (depth < 0) {
                return options.stylize(`[MockApplication]`, "special");
            }
            const newOptions = Object.assign({}, options, {
                depth: options.depth === null ? null : options.depth - 1
            });
            return `${options.stylize("MockApplication", "special")} ${inspect({}, newOptions)}`;
        }
    };
    return app;
}
const mockContextState = {
    encodingsAccepted: "identity"
};
function createMockContext({ ip ="127.0.0.1" , method ="GET" , params , path ="/" , state , app =createMockApp(state) , headers: requestHeaders  } = {}) {
    function createMockRequest() {
        const headers = new Headers(requestHeaders);
        return {
            accepts (...types) {
                if (!headers.has("Accept")) {
                    return;
                }
                if (types.length) {
                    return accepts({
                        headers
                    }, ...types);
                }
                return accepts({
                    headers
                });
            },
            acceptsEncodings () {
                return mockContextState.encodingsAccepted;
            },
            headers,
            ip,
            method,
            path,
            search: undefined,
            searchParams: new URLSearchParams(),
            url: new URL(path, "http://localhost/")
        };
    }
    const request = createMockRequest();
    const response = new Response1(request);
    const cookies = new SecureCookieMap(request, {
        response
    });
    return {
        app,
        params,
        request,
        cookies,
        response,
        state: Object.assign({}, app.state),
        assert (condition, errorStatus = 500, message, props) {
            if (condition) {
                return;
            }
            const err = createHttpError(errorStatus, message);
            if (props) {
                Object.assign(err, props);
            }
            throw err;
        },
        throw (errorStatus, message, props) {
            const err = createHttpError(errorStatus, message);
            if (props) {
                Object.assign(err, props);
            }
            throw err;
        },
        [Symbol.for("Deno.customInspect")] () {
            return `MockContext {}`;
        },
        [Symbol.for("nodejs.util.inspect.custom")] (depth, options, inspect) {
            if (depth < 0) {
                return options.stylize(`[MockContext]`, "special");
            }
            const newOptions = Object.assign({}, options, {
                depth: options.depth === null ? null : options.depth - 1
            });
            return `${options.stylize("MockContext", "special")} ${inspect({}, newOptions)}`;
        }
    };
}
function createMockNext() {
    return async function next() {};
}
const mod5 = {
    createMockApp: createMockApp,
    mockContextState: mockContextState,
    createMockContext: createMockContext,
    createMockNext: createMockNext
};
const mod6 = {
    Application: Application,
    Context: Context,
    HttpRequest: HttpRequest,
    FlashServer: FlashServer,
    hasFlash: hasFlash,
    HttpServerNative: HttpServer,
    proxy: proxy,
    composeMiddleware: compose,
    FormDataReader: FormDataReader,
    ifRange: ifRange,
    MultiPartStream: MultiPartStream,
    parseRange: parseRange,
    Request: Request1,
    REDIRECT_BACK: REDIRECT_BACK,
    Response: Response1,
    Router: Router,
    send: send,
    ServerSentEvent: ServerSentEvent,
    isErrorStatus: isErrorStatus,
    isRedirectStatus: isRedirectStatus,
    createHttpError: createHttpError,
    httpErrors: errors,
    HttpError: HttpError,
    isHttpError: isHttpError,
    Cookies: SecureCookieMap,
    Status: Status,
    STATUS_TEXT: STATUS_TEXT,
    helpers: mod4,
    etag: mod3,
    testing: mod5
};
const uintToBuf = (num)=>{
    const buf = new ArrayBuffer(8);
    const arr = new Uint8Array(buf);
    let acc = num;
    for(let i = 7; i >= 0; i--){
        if (acc === 0) break;
        arr[i] = acc & 255;
        acc -= arr[i];
        acc /= 256;
    }
    return buf;
};
const createHmac = undefined;
const randomBytes$1 = undefined;
const timingSafeEqual$1 = undefined;
var crypto1 = Object.freeze({
    __proto__: null,
    createHmac: createHmac,
    randomBytes: randomBytes$1,
    timingSafeEqual: timingSafeEqual$1
});
const t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function n3(t, n, e, r) {
    let i, s, o;
    const h = n || [
        0
    ], u = (e = e || 0) >>> 3, w = -1 === r ? 3 : 0;
    for(i = 0; i < t.length; i += 1)o = i + u, s = o >>> 2, h.length <= s && h.push(0), h[s] |= t[i] << 8 * (w + r * (o % 4));
    return {
        value: h,
        binLen: 8 * t.length + e
    };
}
function e(e, r, i) {
    switch(r){
        case "UTF8":
        case "UTF16BE":
        case "UTF16LE":
            break;
        default:
            throw new Error("encoding must be UTF8, UTF16BE, or UTF16LE");
    }
    switch(e){
        case "HEX":
            return function(t, n, e) {
                return function(t, n, e, r) {
                    let i, s, o, h;
                    if (0 != t.length % 2) throw new Error("String of HEX type must be in byte increments");
                    const u = n || [
                        0
                    ], w = (e = e || 0) >>> 3, c = -1 === r ? 3 : 0;
                    for(i = 0; i < t.length; i += 2){
                        if (s = parseInt(t.substr(i, 2), 16), isNaN(s)) throw new Error("String of HEX type contains invalid characters");
                        for(h = (i >>> 1) + w, o = h >>> 2; u.length <= o;)u.push(0);
                        u[o] |= s << 8 * (c + r * (h % 4));
                    }
                    return {
                        value: u,
                        binLen: 4 * t.length + e
                    };
                }(t, n, e, i);
            };
        case "TEXT":
            return function(t, n, e) {
                return function(t, n, e, r, i) {
                    let s, o, h, u, w, c, f, a, l = 0;
                    const A = e || [
                        0
                    ], E = (r = r || 0) >>> 3;
                    if ("UTF8" === n) for(f = -1 === i ? 3 : 0, h = 0; h < t.length; h += 1)for(s = t.charCodeAt(h), o = [], 128 > s ? o.push(s) : 2048 > s ? (o.push(192 | s >>> 6), o.push(128 | 63 & s)) : 55296 > s || 57344 <= s ? o.push(224 | s >>> 12, 128 | s >>> 6 & 63, 128 | 63 & s) : (h += 1, s = 65536 + ((1023 & s) << 10 | 1023 & t.charCodeAt(h)), o.push(240 | s >>> 18, 128 | s >>> 12 & 63, 128 | s >>> 6 & 63, 128 | 63 & s)), u = 0; u < o.length; u += 1){
                        for(c = l + E, w = c >>> 2; A.length <= w;)A.push(0);
                        A[w] |= o[u] << 8 * (f + i * (c % 4)), l += 1;
                    }
                    else for(f = -1 === i ? 2 : 0, a = "UTF16LE" === n && 1 !== i || "UTF16LE" !== n && 1 === i, h = 0; h < t.length; h += 1){
                        for(s = t.charCodeAt(h), !0 === a && (u = 255 & s, s = u << 8 | s >>> 8), c = l + E, w = c >>> 2; A.length <= w;)A.push(0);
                        A[w] |= s << 8 * (f + i * (c % 4)), l += 2;
                    }
                    return {
                        value: A,
                        binLen: 8 * l + r
                    };
                }(t, r, n, e, i);
            };
        case "B64":
            return function(n, e, r) {
                return function(n, e, r, i) {
                    let s, o, h, u, w, c, f, a = 0;
                    const l = e || [
                        0
                    ], A = (r = r || 0) >>> 3, E = -1 === i ? 3 : 0, H = n.indexOf("=");
                    if (-1 === n.search(/^[a-zA-Z0-9=+/]+$/)) throw new Error("Invalid character in base-64 string");
                    if (n = n.replace(/=/g, ""), -1 !== H && H < n.length) throw new Error("Invalid '=' found in base-64 string");
                    for(o = 0; o < n.length; o += 4){
                        for(w = n.substr(o, 4), u = 0, h = 0; h < w.length; h += 1)s = t.indexOf(w.charAt(h)), u |= s << 18 - 6 * h;
                        for(h = 0; h < w.length - 1; h += 1){
                            for(f = a + A, c = f >>> 2; l.length <= c;)l.push(0);
                            l[c] |= (u >>> 16 - 8 * h & 255) << 8 * (E + i * (f % 4)), a += 1;
                        }
                    }
                    return {
                        value: l,
                        binLen: 8 * a + r
                    };
                }(n, e, r, i);
            };
        case "BYTES":
            return function(t, n, e) {
                return function(t, n, e, r) {
                    let i, s, o, h;
                    const u = n || [
                        0
                    ], w = (e = e || 0) >>> 3, c = -1 === r ? 3 : 0;
                    for(s = 0; s < t.length; s += 1)i = t.charCodeAt(s), h = s + w, o = h >>> 2, u.length <= o && u.push(0), u[o] |= i << 8 * (c + r * (h % 4));
                    return {
                        value: u,
                        binLen: 8 * t.length + e
                    };
                }(t, n, e, i);
            };
        case "ARRAYBUFFER":
            try {
                new ArrayBuffer(0);
            } catch (t) {
                throw new Error("ARRAYBUFFER not supported by this environment");
            }
            return function(t, e, r) {
                return function(t, e, r, i) {
                    return n3(new Uint8Array(t), e, r, i);
                }(t, e, r, i);
            };
        case "UINT8ARRAY":
            try {
                new Uint8Array(0);
            } catch (t) {
                throw new Error("UINT8ARRAY not supported by this environment");
            }
            return function(t, e, r) {
                return n3(t, e, r, i);
            };
        default:
            throw new Error("format must be HEX, TEXT, B64, BYTES, ARRAYBUFFER, or UINT8ARRAY");
    }
}
function r(n, e, r, i) {
    switch(n){
        case "HEX":
            return function(t) {
                return function(t, n, e, r) {
                    const i = "0123456789abcdef";
                    let s, o, h = "";
                    const u = n / 8, w = -1 === e ? 3 : 0;
                    for(s = 0; s < u; s += 1)o = t[s >>> 2] >>> 8 * (w + e * (s % 4)), h += i.charAt(o >>> 4 & 15) + i.charAt(15 & o);
                    return r.outputUpper ? h.toUpperCase() : h;
                }(t, e, r, i);
            };
        case "B64":
            return function(n) {
                return function(n, e, r, i) {
                    let s, o, h, u, w, c = "";
                    const f = e / 8, a = -1 === r ? 3 : 0;
                    for(s = 0; s < f; s += 3)for(u = s + 1 < f ? n[s + 1 >>> 2] : 0, w = s + 2 < f ? n[s + 2 >>> 2] : 0, h = (n[s >>> 2] >>> 8 * (a + r * (s % 4)) & 255) << 16 | (u >>> 8 * (a + r * ((s + 1) % 4)) & 255) << 8 | w >>> 8 * (a + r * ((s + 2) % 4)) & 255, o = 0; o < 4; o += 1)c += 8 * s + 6 * o <= e ? t.charAt(h >>> 6 * (3 - o) & 63) : i.b64Pad;
                    return c;
                }(n, e, r, i);
            };
        case "BYTES":
            return function(t) {
                return function(t, n, e) {
                    let r, i, s = "";
                    const o = n / 8, h = -1 === e ? 3 : 0;
                    for(r = 0; r < o; r += 1)i = t[r >>> 2] >>> 8 * (h + e * (r % 4)) & 255, s += String.fromCharCode(i);
                    return s;
                }(t, e, r);
            };
        case "ARRAYBUFFER":
            try {
                new ArrayBuffer(0);
            } catch (t) {
                throw new Error("ARRAYBUFFER not supported by this environment");
            }
            return function(t) {
                return function(t, n, e) {
                    let r;
                    const i = n / 8, s = new ArrayBuffer(i), o = new Uint8Array(s), h = -1 === e ? 3 : 0;
                    for(r = 0; r < i; r += 1)o[r] = t[r >>> 2] >>> 8 * (h + e * (r % 4)) & 255;
                    return s;
                }(t, e, r);
            };
        case "UINT8ARRAY":
            try {
                new Uint8Array(0);
            } catch (t) {
                throw new Error("UINT8ARRAY not supported by this environment");
            }
            return function(t) {
                return function(t, n, e) {
                    let r;
                    const i = n / 8, s = -1 === e ? 3 : 0, o = new Uint8Array(i);
                    for(r = 0; r < i; r += 1)o[r] = t[r >>> 2] >>> 8 * (s + e * (r % 4)) & 255;
                    return o;
                }(t, e, r);
            };
        default:
            throw new Error("format must be HEX, B64, BYTES, ARRAYBUFFER, or UINT8ARRAY");
    }
}
const i = [
    1116352408,
    1899447441,
    3049323471,
    3921009573,
    961987163,
    1508970993,
    2453635748,
    2870763221,
    3624381080,
    310598401,
    607225278,
    1426881987,
    1925078388,
    2162078206,
    2614888103,
    3248222580,
    3835390401,
    4022224774,
    264347078,
    604807628,
    770255983,
    1249150122,
    1555081692,
    1996064986,
    2554220882,
    2821834349,
    2952996808,
    3210313671,
    3336571891,
    3584528711,
    113926993,
    338241895,
    666307205,
    773529912,
    1294757372,
    1396182291,
    1695183700,
    1986661051,
    2177026350,
    2456956037,
    2730485921,
    2820302411,
    3259730800,
    3345764771,
    3516065817,
    3600352804,
    4094571909,
    275423344,
    430227734,
    506948616,
    659060556,
    883997877,
    958139571,
    1322822218,
    1537002063,
    1747873779,
    1955562222,
    2024104815,
    2227730452,
    2361852424,
    2428436474,
    2756734187,
    3204031479,
    3329325298
], s = [
    3238371032,
    914150663,
    812702999,
    4144912697,
    4290775857,
    1750603025,
    1694076839,
    3204075428
], o = [
    1779033703,
    3144134277,
    1013904242,
    2773480762,
    1359893119,
    2600822924,
    528734635,
    1541459225
], h = "Chosen SHA variant is not supported";
function u(t, n) {
    let e, r;
    const i = t.binLen >>> 3, s = n.binLen >>> 3, o = i << 3, h = 4 - i << 3;
    if (i % 4 != 0) {
        for(e = 0; e < s; e += 4)r = i + e >>> 2, t.value[r] |= n.value[e >>> 2] << o, t.value.push(0), t.value[r + 1] |= n.value[e >>> 2] >>> h;
        return (t.value.length << 2) - 4 >= s + i && t.value.pop(), {
            value: t.value,
            binLen: t.binLen + n.binLen
        };
    }
    return {
        value: t.value.concat(n.value),
        binLen: t.binLen + n.binLen
    };
}
function w(t) {
    const n = {
        outputUpper: !1,
        b64Pad: "=",
        outputLen: -1
    }, e = t || {}, r = "Output length must be a multiple of 8";
    if (n.outputUpper = e.outputUpper || !1, e.b64Pad && (n.b64Pad = e.b64Pad), e.outputLen) {
        if (e.outputLen % 8 != 0) throw new Error(r);
        n.outputLen = e.outputLen;
    } else if (e.shakeLen) {
        if (e.shakeLen % 8 != 0) throw new Error(r);
        n.outputLen = e.shakeLen;
    }
    if ("boolean" != typeof n.outputUpper) throw new Error("Invalid outputUpper formatting option");
    if ("string" != typeof n.b64Pad) throw new Error("Invalid b64Pad formatting option");
    return n;
}
function c(t, n, r, i) {
    const s = t + " must include a value and format";
    if (!n) {
        if (!i) throw new Error(s);
        return i;
    }
    if (void 0 === n.value || !n.format) throw new Error(s);
    return e(n.format, n.encoding || "UTF8", r)(n.value);
}
class f {
    constructor(t, n, e){
        const r = e || {};
        if (this.t = n, this.i = r.encoding || "UTF8", this.numRounds = r.numRounds || 1, isNaN(this.numRounds) || this.numRounds !== parseInt(this.numRounds, 10) || 1 > this.numRounds) throw new Error("numRounds must a integer >= 1");
        this.o = t, this.h = [], this.u = 0, this.l = !1, this.A = 0, this.H = !1, this.S = [], this.p = [];
    }
    update(t) {
        let n, e = 0;
        const r = this.m >>> 5, i = this.C(t, this.h, this.u), s = i.binLen, o = i.value, h = s >>> 5;
        for(n = 0; n < h; n += r)e + this.m <= s && (this.R = this.U(o.slice(n, n + r), this.R), e += this.m);
        return this.A += e, this.h = o.slice(e >>> 5), this.u = s % this.m, this.l = !0, this;
    }
    getHash(t, n) {
        let e, i, s = this.v;
        const o = w(n);
        if (this.K) {
            if (-1 === o.outputLen) throw new Error("Output length must be specified in options");
            s = o.outputLen;
        }
        const h = r(t, s, this.T, o);
        if (this.H && this.F) return h(this.F(o));
        for(i = this.g(this.h.slice(), this.u, this.A, this.B(this.R), s), e = 1; e < this.numRounds; e += 1)this.K && s % 32 != 0 && (i[i.length - 1] &= 16777215 >>> 24 - s % 32), i = this.g(i, s, 0, this.L(this.o), s);
        return h(i);
    }
    setHMACKey(t, n, r) {
        if (!this.M) throw new Error("Variant does not support HMAC");
        if (this.l) throw new Error("Cannot set MAC key after calling update");
        const i = e(n, (r || {}).encoding || "UTF8", this.T);
        this.k(i(t));
    }
    k(t) {
        const n = this.m >>> 3, e = n / 4 - 1;
        let r;
        if (1 !== this.numRounds) throw new Error("Cannot set numRounds with MAC");
        if (this.H) throw new Error("MAC key already set");
        for(n < t.binLen / 8 && (t.value = this.g(t.value, t.binLen, 0, this.L(this.o), this.v)); t.value.length <= e;)t.value.push(0);
        for(r = 0; r <= e; r += 1)this.S[r] = 909522486 ^ t.value[r], this.p[r] = 1549556828 ^ t.value[r];
        this.R = this.U(this.S, this.R), this.A = this.m, this.H = !0;
    }
    getHMAC(t, n) {
        const e = w(n);
        return r(t, this.v, this.T, e)(this.Y());
    }
    Y() {
        let t;
        if (!this.H) throw new Error("Cannot call getHMAC without first setting MAC key");
        const n = this.g(this.h.slice(), this.u, this.A, this.B(this.R), this.v);
        return t = this.U(this.p, this.L(this.o)), t = this.g(n, this.v, this.m, t, this.v), t;
    }
}
function a(t, n) {
    return t << n | t >>> 32 - n;
}
function l(t, n) {
    return t >>> n | t << 32 - n;
}
function A(t, n) {
    return t >>> n;
}
function E(t, n, e) {
    return t ^ n ^ e;
}
function H(t, n, e) {
    return t & n ^ ~t & e;
}
function S(t, n, e) {
    return t & n ^ t & e ^ n & e;
}
function b(t) {
    return l(t, 2) ^ l(t, 13) ^ l(t, 22);
}
function p(t, n) {
    const e = (65535 & t) + (65535 & n);
    return (65535 & (t >>> 16) + (n >>> 16) + (e >>> 16)) << 16 | 65535 & e;
}
function d(t, n, e, r) {
    const i = (65535 & t) + (65535 & n) + (65535 & e) + (65535 & r);
    return (65535 & (t >>> 16) + (n >>> 16) + (e >>> 16) + (r >>> 16) + (i >>> 16)) << 16 | 65535 & i;
}
function m(t, n, e, r, i) {
    const s = (65535 & t) + (65535 & n) + (65535 & e) + (65535 & r) + (65535 & i);
    return (65535 & (t >>> 16) + (n >>> 16) + (e >>> 16) + (r >>> 16) + (i >>> 16) + (s >>> 16)) << 16 | 65535 & s;
}
function C(t) {
    return l(t, 7) ^ l(t, 18) ^ A(t, 3);
}
function y(t) {
    return l(t, 6) ^ l(t, 11) ^ l(t, 25);
}
function R(t) {
    return [
        1732584193,
        4023233417,
        2562383102,
        271733878,
        3285377520
    ];
}
function U(t, n) {
    let e, r, i, s, o, h, u;
    const w = [];
    for(e = n[0], r = n[1], i = n[2], s = n[3], o = n[4], u = 0; u < 80; u += 1)w[u] = u < 16 ? t[u] : a(w[u - 3] ^ w[u - 8] ^ w[u - 14] ^ w[u - 16], 1), h = u < 20 ? m(a(e, 5), H(r, i, s), o, 1518500249, w[u]) : u < 40 ? m(a(e, 5), E(r, i, s), o, 1859775393, w[u]) : u < 60 ? m(a(e, 5), S(r, i, s), o, 2400959708, w[u]) : m(a(e, 5), E(r, i, s), o, 3395469782, w[u]), o = s, s = i, i = a(r, 30), r = e, e = h;
    return n[0] = p(e, n[0]), n[1] = p(r, n[1]), n[2] = p(i, n[2]), n[3] = p(s, n[3]), n[4] = p(o, n[4]), n;
}
function v(t, n, e, r) {
    let i;
    const s = 15 + (n + 65 >>> 9 << 4), o = n + e;
    for(; t.length <= s;)t.push(0);
    for(t[n >>> 5] |= 128 << 24 - n % 32, t[s] = 4294967295 & o, t[s - 1] = o / 4294967296 | 0, i = 0; i < t.length; i += 16)r = U(t.slice(i, i + 16), r);
    return r;
}
class K extends f {
    constructor(t, n, r){
        if ("SHA-1" !== t) throw new Error(h);
        super(t, n, r);
        const i = r || {};
        this.M = !0, this.F = this.Y, this.T = -1, this.C = e(this.t, this.i, this.T), this.U = U, this.B = function(t) {
            return t.slice();
        }, this.L = R, this.g = v, this.R = [
            1732584193,
            4023233417,
            2562383102,
            271733878,
            3285377520
        ], this.m = 512, this.v = 160, this.K = !1, i.hmacKey && this.k(c("hmacKey", i.hmacKey, this.T));
    }
}
function T(t) {
    let n;
    return n = "SHA-224" == t ? s.slice() : o.slice(), n;
}
function F(t, n) {
    let e, r, s, o, h, u, w, c, f, a, E;
    const R = [];
    for(e = n[0], r = n[1], s = n[2], o = n[3], h = n[4], u = n[5], w = n[6], c = n[7], E = 0; E < 64; E += 1)R[E] = E < 16 ? t[E] : d(l(U = R[E - 2], 17) ^ l(U, 19) ^ A(U, 10), R[E - 7], C(R[E - 15]), R[E - 16]), f = m(c, y(h), H(h, u, w), i[E], R[E]), a = p(b(e), S(e, r, s)), c = w, w = u, u = h, h = p(o, f), o = s, s = r, r = e, e = p(f, a);
    var U;
    return n[0] = p(e, n[0]), n[1] = p(r, n[1]), n[2] = p(s, n[2]), n[3] = p(o, n[3]), n[4] = p(h, n[4]), n[5] = p(u, n[5]), n[6] = p(w, n[6]), n[7] = p(c, n[7]), n;
}
class g extends f {
    constructor(t, n, r){
        if ("SHA-224" !== t && "SHA-256" !== t) throw new Error(h);
        super(t, n, r);
        const i = r || {};
        this.F = this.Y, this.M = !0, this.T = -1, this.C = e(this.t, this.i, this.T), this.U = F, this.B = function(t) {
            return t.slice();
        }, this.L = T, this.g = function(n, e, r, i) {
            return function(t, n, e, r, i) {
                let s, o;
                const h = 15 + (n + 65 >>> 9 << 4), u = n + e;
                for(; t.length <= h;)t.push(0);
                for(t[n >>> 5] |= 128 << 24 - n % 32, t[h] = 4294967295 & u, t[h - 1] = u / 4294967296 | 0, s = 0; s < t.length; s += 16)r = F(t.slice(s, s + 16), r);
                return o = "SHA-224" === i ? [
                    r[0],
                    r[1],
                    r[2],
                    r[3],
                    r[4],
                    r[5],
                    r[6]
                ] : r, o;
            }(n, e, r, i, t);
        }, this.R = T(t), this.m = 512, this.v = "SHA-224" === t ? 224 : 256, this.K = !1, i.hmacKey && this.k(c("hmacKey", i.hmacKey, this.T));
    }
}
class B {
    constructor(t, n){
        this.N = t, this.I = n;
    }
}
function L(t, n) {
    let e;
    return n > 32 ? (e = 64 - n, new B(t.I << n | t.N >>> e, t.N << n | t.I >>> e)) : 0 !== n ? (e = 32 - n, new B(t.N << n | t.I >>> e, t.I << n | t.N >>> e)) : t;
}
function M(t, n) {
    let e;
    return n < 32 ? (e = 32 - n, new B(t.N >>> n | t.I << e, t.I >>> n | t.N << e)) : (e = 64 - n, new B(t.I >>> n | t.N << e, t.N >>> n | t.I << e));
}
function k(t, n) {
    return new B(t.N >>> n, t.I >>> n | t.N << 32 - n);
}
function Y(t, n, e) {
    return new B(t.N & n.N ^ t.N & e.N ^ n.N & e.N, t.I & n.I ^ t.I & e.I ^ n.I & e.I);
}
function N(t) {
    const n = M(t, 28), e = M(t, 34), r = M(t, 39);
    return new B(n.N ^ e.N ^ r.N, n.I ^ e.I ^ r.I);
}
function I(t, n) {
    let e, r;
    e = (65535 & t.I) + (65535 & n.I), r = (t.I >>> 16) + (n.I >>> 16) + (e >>> 16);
    const i = (65535 & r) << 16 | 65535 & e;
    e = (65535 & t.N) + (65535 & n.N) + (r >>> 16), r = (t.N >>> 16) + (n.N >>> 16) + (e >>> 16);
    return new B((65535 & r) << 16 | 65535 & e, i);
}
function X(t, n, e, r) {
    let i, s;
    i = (65535 & t.I) + (65535 & n.I) + (65535 & e.I) + (65535 & r.I), s = (t.I >>> 16) + (n.I >>> 16) + (e.I >>> 16) + (r.I >>> 16) + (i >>> 16);
    const o = (65535 & s) << 16 | 65535 & i;
    i = (65535 & t.N) + (65535 & n.N) + (65535 & e.N) + (65535 & r.N) + (s >>> 16), s = (t.N >>> 16) + (n.N >>> 16) + (e.N >>> 16) + (r.N >>> 16) + (i >>> 16);
    return new B((65535 & s) << 16 | 65535 & i, o);
}
function z(t, n, e, r, i) {
    let s, o;
    s = (65535 & t.I) + (65535 & n.I) + (65535 & e.I) + (65535 & r.I) + (65535 & i.I), o = (t.I >>> 16) + (n.I >>> 16) + (e.I >>> 16) + (r.I >>> 16) + (i.I >>> 16) + (s >>> 16);
    const h = (65535 & o) << 16 | 65535 & s;
    s = (65535 & t.N) + (65535 & n.N) + (65535 & e.N) + (65535 & r.N) + (65535 & i.N) + (o >>> 16), o = (t.N >>> 16) + (n.N >>> 16) + (e.N >>> 16) + (r.N >>> 16) + (i.N >>> 16) + (s >>> 16);
    return new B((65535 & o) << 16 | 65535 & s, h);
}
function x(t, n) {
    return new B(t.N ^ n.N, t.I ^ n.I);
}
function _(t) {
    const n = M(t, 19), e = M(t, 61), r = k(t, 6);
    return new B(n.N ^ e.N ^ r.N, n.I ^ e.I ^ r.I);
}
function O(t) {
    const n = M(t, 1), e = M(t, 8), r = k(t, 7);
    return new B(n.N ^ e.N ^ r.N, n.I ^ e.I ^ r.I);
}
function P(t) {
    const n = M(t, 14), e = M(t, 18), r = M(t, 41);
    return new B(n.N ^ e.N ^ r.N, n.I ^ e.I ^ r.I);
}
const V = [
    new B(i[0], 3609767458),
    new B(i[1], 602891725),
    new B(i[2], 3964484399),
    new B(i[3], 2173295548),
    new B(i[4], 4081628472),
    new B(i[5], 3053834265),
    new B(i[6], 2937671579),
    new B(i[7], 3664609560),
    new B(i[8], 2734883394),
    new B(i[9], 1164996542),
    new B(i[10], 1323610764),
    new B(i[11], 3590304994),
    new B(i[12], 4068182383),
    new B(i[13], 991336113),
    new B(i[14], 633803317),
    new B(i[15], 3479774868),
    new B(i[16], 2666613458),
    new B(i[17], 944711139),
    new B(i[18], 2341262773),
    new B(i[19], 2007800933),
    new B(i[20], 1495990901),
    new B(i[21], 1856431235),
    new B(i[22], 3175218132),
    new B(i[23], 2198950837),
    new B(i[24], 3999719339),
    new B(i[25], 766784016),
    new B(i[26], 2566594879),
    new B(i[27], 3203337956),
    new B(i[28], 1034457026),
    new B(i[29], 2466948901),
    new B(i[30], 3758326383),
    new B(i[31], 168717936),
    new B(i[32], 1188179964),
    new B(i[33], 1546045734),
    new B(i[34], 1522805485),
    new B(i[35], 2643833823),
    new B(i[36], 2343527390),
    new B(i[37], 1014477480),
    new B(i[38], 1206759142),
    new B(i[39], 344077627),
    new B(i[40], 1290863460),
    new B(i[41], 3158454273),
    new B(i[42], 3505952657),
    new B(i[43], 106217008),
    new B(i[44], 3606008344),
    new B(i[45], 1432725776),
    new B(i[46], 1467031594),
    new B(i[47], 851169720),
    new B(i[48], 3100823752),
    new B(i[49], 1363258195),
    new B(i[50], 3750685593),
    new B(i[51], 3785050280),
    new B(i[52], 3318307427),
    new B(i[53], 3812723403),
    new B(i[54], 2003034995),
    new B(i[55], 3602036899),
    new B(i[56], 1575990012),
    new B(i[57], 1125592928),
    new B(i[58], 2716904306),
    new B(i[59], 442776044),
    new B(i[60], 593698344),
    new B(i[61], 3733110249),
    new B(i[62], 2999351573),
    new B(i[63], 3815920427),
    new B(3391569614, 3928383900),
    new B(3515267271, 566280711),
    new B(3940187606, 3454069534),
    new B(4118630271, 4000239992),
    new B(116418474, 1914138554),
    new B(174292421, 2731055270),
    new B(289380356, 3203993006),
    new B(460393269, 320620315),
    new B(685471733, 587496836),
    new B(852142971, 1086792851),
    new B(1017036298, 365543100),
    new B(1126000580, 2618297676),
    new B(1288033470, 3409855158),
    new B(1501505948, 4234509866),
    new B(1607167915, 987167468),
    new B(1816402316, 1246189591)
];
function Z(t) {
    return "SHA-384" === t ? [
        new B(3418070365, s[0]),
        new B(1654270250, s[1]),
        new B(2438529370, s[2]),
        new B(355462360, s[3]),
        new B(1731405415, s[4]),
        new B(41048885895, s[5]),
        new B(3675008525, s[6]),
        new B(1203062813, s[7])
    ] : [
        new B(o[0], 4089235720),
        new B(o[1], 2227873595),
        new B(o[2], 4271175723),
        new B(o[3], 1595750129),
        new B(o[4], 2917565137),
        new B(o[5], 725511199),
        new B(o[6], 4215389547),
        new B(o[7], 327033209)
    ];
}
function j(t, n) {
    let e, r, i, s, o, h, u, w, c, f, a, l;
    const A = [];
    for(e = n[0], r = n[1], i = n[2], s = n[3], o = n[4], h = n[5], u = n[6], w = n[7], a = 0; a < 80; a += 1)a < 16 ? (l = 2 * a, A[a] = new B(t[l], t[l + 1])) : A[a] = X(_(A[a - 2]), A[a - 7], O(A[a - 15]), A[a - 16]), c = z(w, P(o), (H = h, S = u, new B((E = o).N & H.N ^ ~E.N & S.N, E.I & H.I ^ ~E.I & S.I)), V[a], A[a]), f = I(N(e), Y(e, r, i)), w = u, u = h, h = o, o = I(s, c), s = i, i = r, r = e, e = I(c, f);
    var E, H, S;
    return n[0] = I(e, n[0]), n[1] = I(r, n[1]), n[2] = I(i, n[2]), n[3] = I(s, n[3]), n[4] = I(o, n[4]), n[5] = I(h, n[5]), n[6] = I(u, n[6]), n[7] = I(w, n[7]), n;
}
class q extends f {
    constructor(t, n, r){
        if ("SHA-384" !== t && "SHA-512" !== t) throw new Error(h);
        super(t, n, r);
        const i = r || {};
        this.F = this.Y, this.M = !0, this.T = -1, this.C = e(this.t, this.i, this.T), this.U = j, this.B = function(t) {
            return t.slice();
        }, this.L = Z, this.g = function(n, e, r, i) {
            return function(t, n, e, r, i) {
                let s, o;
                const h = 31 + (n + 129 >>> 10 << 5), u = n + e;
                for(; t.length <= h;)t.push(0);
                for(t[n >>> 5] |= 128 << 24 - n % 32, t[h] = 4294967295 & u, t[h - 1] = u / 4294967296 | 0, s = 0; s < t.length; s += 32)r = j(t.slice(s, s + 32), r);
                return o = "SHA-384" === i ? [
                    r[0].N,
                    r[0].I,
                    r[1].N,
                    r[1].I,
                    r[2].N,
                    r[2].I,
                    r[3].N,
                    r[3].I,
                    r[4].N,
                    r[4].I,
                    r[5].N,
                    r[5].I
                ] : [
                    r[0].N,
                    r[0].I,
                    r[1].N,
                    r[1].I,
                    r[2].N,
                    r[2].I,
                    r[3].N,
                    r[3].I,
                    r[4].N,
                    r[4].I,
                    r[5].N,
                    r[5].I,
                    r[6].N,
                    r[6].I,
                    r[7].N,
                    r[7].I
                ], o;
            }(n, e, r, i, t);
        }, this.R = Z(t), this.m = 1024, this.v = "SHA-384" === t ? 384 : 512, this.K = !1, i.hmacKey && this.k(c("hmacKey", i.hmacKey, this.T));
    }
}
const D = [
    new B(0, 1),
    new B(0, 32898),
    new B(2147483648, 32906),
    new B(2147483648, 2147516416),
    new B(0, 32907),
    new B(0, 2147483649),
    new B(2147483648, 2147516545),
    new B(2147483648, 32777),
    new B(0, 138),
    new B(0, 136),
    new B(0, 2147516425),
    new B(0, 2147483658),
    new B(0, 2147516555),
    new B(2147483648, 139),
    new B(2147483648, 32905),
    new B(2147483648, 32771),
    new B(2147483648, 32770),
    new B(2147483648, 128),
    new B(0, 32778),
    new B(2147483648, 2147483658),
    new B(2147483648, 2147516545),
    new B(2147483648, 32896),
    new B(0, 2147483649),
    new B(2147483648, 2147516424)
], G = [
    [
        0,
        36,
        3,
        41,
        18
    ],
    [
        1,
        44,
        10,
        45,
        2
    ],
    [
        62,
        6,
        43,
        15,
        61
    ],
    [
        28,
        55,
        25,
        21,
        56
    ],
    [
        27,
        20,
        39,
        8,
        14
    ]
];
function J(t) {
    let n;
    const e = [];
    for(n = 0; n < 5; n += 1)e[n] = [
        new B(0, 0),
        new B(0, 0),
        new B(0, 0),
        new B(0, 0),
        new B(0, 0)
    ];
    return e;
}
function Q(t) {
    let n;
    const e = [];
    for(n = 0; n < 5; n += 1)e[n] = t[n].slice();
    return e;
}
function W(t, n) {
    let e, r, i, s;
    const o = [], h = [];
    if (null !== t) for(r = 0; r < t.length; r += 2)n[(r >>> 1) % 5][(r >>> 1) / 5 | 0] = x(n[(r >>> 1) % 5][(r >>> 1) / 5 | 0], new B(t[r + 1], t[r]));
    for(e = 0; e < 24; e += 1){
        for(s = J(), r = 0; r < 5; r += 1)o[r] = (u = n[r][0], w = n[r][1], c = n[r][2], f = n[r][3], a = n[r][4], new B(u.N ^ w.N ^ c.N ^ f.N ^ a.N, u.I ^ w.I ^ c.I ^ f.I ^ a.I));
        for(r = 0; r < 5; r += 1)h[r] = x(o[(r + 4) % 5], L(o[(r + 1) % 5], 1));
        for(r = 0; r < 5; r += 1)for(i = 0; i < 5; i += 1)n[r][i] = x(n[r][i], h[r]);
        for(r = 0; r < 5; r += 1)for(i = 0; i < 5; i += 1)s[i][(2 * r + 3 * i) % 5] = L(n[r][i], G[r][i]);
        for(r = 0; r < 5; r += 1)for(i = 0; i < 5; i += 1)n[r][i] = x(s[r][i], new B(~s[(r + 1) % 5][i].N & s[(r + 2) % 5][i].N, ~s[(r + 1) % 5][i].I & s[(r + 2) % 5][i].I));
        n[0][0] = x(n[0][0], D[e]);
    }
    var u, w, c, f, a;
    return n;
}
function $(t) {
    let n, e, r = 0;
    const i = [
        0,
        0
    ], s = [
        4294967295 & t,
        t / 4294967296 & 2097151
    ];
    for(n = 6; n >= 0; n--)e = s[n >> 2] >>> 8 * n & 255, 0 === e && 0 === r || (i[r + 1 >> 2] |= e << 8 * (r + 1), r += 1);
    return r = 0 !== r ? r : 1, i[0] |= r, {
        value: r + 1 > 4 ? i : [
            i[0]
        ],
        binLen: 8 + 8 * r
    };
}
function tt(t) {
    return u($(t.binLen), t);
}
function nt(t, n) {
    let e, r = $(n);
    r = u(r, t);
    const i = n >>> 2, s = (i - r.value.length % i) % i;
    for(e = 0; e < s; e++)r.value.push(0);
    return r.value;
}
class et extends f {
    constructor(t, n, r){
        let i = 6, s = 0;
        super(t, n, r);
        const o = r || {};
        if (1 !== this.numRounds) {
            if (o.kmacKey || o.hmacKey) throw new Error("Cannot set numRounds with MAC");
            if ("CSHAKE128" === this.o || "CSHAKE256" === this.o) throw new Error("Cannot set numRounds for CSHAKE variants");
        }
        switch(this.T = 1, this.C = e(this.t, this.i, this.T), this.U = W, this.B = Q, this.L = J, this.R = J(), this.K = !1, t){
            case "SHA3-224":
                this.m = s = 1152, this.v = 224, this.M = !0, this.F = this.Y;
                break;
            case "SHA3-256":
                this.m = s = 1088, this.v = 256, this.M = !0, this.F = this.Y;
                break;
            case "SHA3-384":
                this.m = s = 832, this.v = 384, this.M = !0, this.F = this.Y;
                break;
            case "SHA3-512":
                this.m = s = 576, this.v = 512, this.M = !0, this.F = this.Y;
                break;
            case "SHAKE128":
                i = 31, this.m = s = 1344, this.v = -1, this.K = !0, this.M = !1, this.F = null;
                break;
            case "SHAKE256":
                i = 31, this.m = s = 1088, this.v = -1, this.K = !0, this.M = !1, this.F = null;
                break;
            case "KMAC128":
                i = 4, this.m = s = 1344, this.X(r), this.v = -1, this.K = !0, this.M = !1, this.F = this._;
                break;
            case "KMAC256":
                i = 4, this.m = s = 1088, this.X(r), this.v = -1, this.K = !0, this.M = !1, this.F = this._;
                break;
            case "CSHAKE128":
                this.m = s = 1344, i = this.O(r), this.v = -1, this.K = !0, this.M = !1, this.F = null;
                break;
            case "CSHAKE256":
                this.m = s = 1088, i = this.O(r), this.v = -1, this.K = !0, this.M = !1, this.F = null;
                break;
            default:
                throw new Error(h);
        }
        this.g = function(t, n, e, r, o) {
            return function(t, n, e, r, i, s, o) {
                let h, u, w = 0;
                const c = [], f = i >>> 5, a = n >>> 5;
                for(h = 0; h < a && n >= i; h += f)r = W(t.slice(h, h + f), r), n -= i;
                for(t = t.slice(h), n %= i; t.length < f;)t.push(0);
                for(h = n >>> 3, t[h >> 2] ^= s << h % 4 * 8, t[f - 1] ^= 2147483648, r = W(t, r); 32 * c.length < o && (u = r[w % 5][w / 5 | 0], c.push(u.I), !(32 * c.length >= o));)c.push(u.N), w += 1, 0 == 64 * w % i && (W(null, r), w = 0);
                return c;
            }(t, n, 0, r, s, i, o);
        }, o.hmacKey && this.k(c("hmacKey", o.hmacKey, this.T));
    }
    O(t, n) {
        const e = function(t) {
            const n = t || {};
            return {
                funcName: c("funcName", n.funcName, 1, {
                    value: [],
                    binLen: 0
                }),
                customization: c("Customization", n.customization, 1, {
                    value: [],
                    binLen: 0
                })
            };
        }(t || {});
        n && (e.funcName = n);
        const r = u(tt(e.funcName), tt(e.customization));
        if (0 !== e.customization.binLen || 0 !== e.funcName.binLen) {
            const t = nt(r, this.m >>> 3);
            for(let n = 0; n < t.length; n += this.m >>> 5)this.R = this.U(t.slice(n, n + (this.m >>> 5)), this.R), this.A += this.m;
            return 4;
        }
        return 31;
    }
    X(t) {
        const n = function(t) {
            const n = t || {};
            return {
                kmacKey: c("kmacKey", n.kmacKey, 1),
                funcName: {
                    value: [
                        1128353099
                    ],
                    binLen: 32
                },
                customization: c("Customization", n.customization, 1, {
                    value: [],
                    binLen: 0
                })
            };
        }(t || {});
        this.O(t, n.funcName);
        const e = nt(tt(n.kmacKey), this.m >>> 3);
        for(let t = 0; t < e.length; t += this.m >>> 5)this.R = this.U(e.slice(t, t + (this.m >>> 5)), this.R), this.A += this.m;
        this.H = !0;
    }
    _(t) {
        const n = u({
            value: this.h.slice(),
            binLen: this.u
        }, function(t) {
            let n, e, r = 0;
            const i = [
                0,
                0
            ], s = [
                4294967295 & t,
                t / 4294967296 & 2097151
            ];
            for(n = 6; n >= 0; n--)e = s[n >> 2] >>> 8 * n & 255, 0 === e && 0 === r || (i[r >> 2] |= e << 8 * r, r += 1);
            return r = 0 !== r ? r : 1, i[r >> 2] |= r << 8 * r, {
                value: r + 1 > 4 ? i : [
                    i[0]
                ],
                binLen: 8 + 8 * r
            };
        }(t.outputLen));
        return this.g(n.value, n.binLen, this.A, this.B(this.R), t.outputLen);
    }
}
class rt {
    constructor(t, n, e){
        if ("SHA-1" == t) this.P = new K(t, n, e);
        else if ("SHA-224" == t || "SHA-256" == t) this.P = new g(t, n, e);
        else if ("SHA-384" == t || "SHA-512" == t) this.P = new q(t, n, e);
        else {
            if ("SHA3-224" != t && "SHA3-256" != t && "SHA3-384" != t && "SHA3-512" != t && "SHAKE128" != t && "SHAKE256" != t && "CSHAKE128" != t && "CSHAKE256" != t && "KMAC128" != t && "KMAC256" != t) throw new Error(h);
            this.P = new et(t, n, e);
        }
    }
    update(t) {
        return this.P.update(t), this;
    }
    getHash(t, n) {
        return this.P.getHash(t, n);
    }
    setHMACKey(t, n, e) {
        this.P.setHMACKey(t, n, e);
    }
    getHMAC(t, n) {
        return this.P.getHMAC(t, n);
    }
}
const globalScope = (()=>{
    if (typeof globalThis === "object") return globalThis;
    else {
        Object.defineProperty(Object.prototype, "__GLOBALTHIS__", {
            get () {
                return this;
            },
            configurable: true
        });
        try {
            if (typeof __GLOBALTHIS__ !== "undefined") return __GLOBALTHIS__;
        } finally{
            delete Object.prototype.__GLOBALTHIS__;
        }
    }
    if (typeof self !== "undefined") return self;
    else if (typeof window !== "undefined") return window;
    else if (typeof global !== "undefined") return global;
    return undefined;
})();
const OPENSSL_JSSHA_ALGO_MAP = {
    SHA1: "SHA-1",
    SHA224: "SHA-224",
    SHA256: "SHA-256",
    SHA384: "SHA-384",
    SHA512: "SHA-512",
    "SHA3-224": "SHA3-224",
    "SHA3-256": "SHA3-256",
    "SHA3-384": "SHA3-384",
    "SHA3-512": "SHA3-512"
};
const hmacDigest = (algorithm, key, message)=>{
    if (crypto1 !== null && crypto1 !== void 0 && createHmac) {
        const hmac = createHmac(algorithm, globalScope.Buffer.from(key));
        hmac.update(globalScope.Buffer.from(message));
        return hmac.digest().buffer;
    } else {
        const variant = OPENSSL_JSSHA_ALGO_MAP[algorithm.toUpperCase()];
        if (typeof variant === "undefined") {
            throw new TypeError("Unknown hash function");
        }
        const hmac = new rt(variant, "ARRAYBUFFER");
        hmac.setHMACKey(key, "ARRAYBUFFER");
        hmac.update(message);
        return hmac.getHMAC("ARRAYBUFFER");
    }
};
const pad = (num, digits)=>{
    let prefix = "";
    let repeat = digits - String(num).length;
    while(repeat-- > 0)prefix += "0";
    return `${prefix}${num}`;
};
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const base32ToBuf = (str)=>{
    let end = str.length;
    while(str[end - 1] === "=")--end;
    const cstr = (end < str.length ? str.substring(0, end) : str).toUpperCase();
    const buf = new ArrayBuffer(cstr.length * 5 / 8 | 0);
    const arr = new Uint8Array(buf);
    let bits = 0;
    let value = 0;
    let index = 0;
    for(let i = 0; i < cstr.length; i++){
        const idx = ALPHABET.indexOf(cstr[i]);
        if (idx === -1) throw new TypeError(`Invalid character found: ${cstr[i]}`);
        value = value << 5 | idx;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            arr[index++] = value >>> bits;
        }
    }
    return buf;
};
const base32FromBuf = (buf)=>{
    const arr = new Uint8Array(buf);
    let bits = 0;
    let value = 0;
    let str = "";
    for(let i = 0; i < arr.length; i++){
        value = value << 8 | arr[i];
        bits += 8;
        while(bits >= 5){
            str += ALPHABET[value >>> bits - 5 & 31];
            bits -= 5;
        }
    }
    if (bits > 0) {
        str += ALPHABET[value << 5 - bits & 31];
    }
    return str;
};
const hexToBuf = (str)=>{
    const buf = new ArrayBuffer(str.length / 2);
    const arr = new Uint8Array(buf);
    for(let i = 0; i < str.length; i += 2){
        arr[i / 2] = parseInt(str.substring(i, i + 2), 16);
    }
    return buf;
};
const hexFromBuf = (buf)=>{
    const arr = new Uint8Array(buf);
    let str = "";
    for(let i = 0; i < arr.length; i++){
        const hex = arr[i].toString(16);
        if (hex.length === 1) str += "0";
        str += hex;
    }
    return str.toUpperCase();
};
const latin1ToBuf = (str)=>{
    const buf = new ArrayBuffer(str.length);
    const arr = new Uint8Array(buf);
    for(let i = 0; i < str.length; i++){
        arr[i] = str.charCodeAt(i) & 0xff;
    }
    return buf;
};
const latin1FromBuf = (buf)=>{
    const arr = new Uint8Array(buf);
    let str = "";
    for(let i = 0; i < arr.length; i++){
        str += String.fromCharCode(arr[i]);
    }
    return str;
};
const ENCODER = globalScope.TextEncoder ? new globalScope.TextEncoder("utf-8") : null;
const DECODER = globalScope.TextDecoder ? new globalScope.TextDecoder("utf-8") : null;
const utf8ToBuf = (str)=>{
    if (!ENCODER) {
        throw new Error("Encoding API not available");
    }
    return ENCODER.encode(str).buffer;
};
const utf8FromBuf = (buf)=>{
    if (!DECODER) {
        throw new Error("Encoding API not available");
    }
    return DECODER.decode(buf);
};
const randomBytes = (size)=>{
    if (crypto1 !== null && crypto1 !== void 0 && randomBytes$1) {
        return randomBytes$1(size).buffer;
    } else {
        if (!globalScope.crypto || !globalScope.crypto.getRandomValues) {
            throw new Error("Cryptography API not available");
        }
        return globalScope.crypto.getRandomValues(new Uint8Array(size)).buffer;
    }
};
class Secret {
    constructor(){
        let { buffer , size =20  } = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
        this.buffer = typeof buffer === "undefined" ? randomBytes(size) : buffer;
    }
    static fromLatin1(str) {
        return new Secret({
            buffer: latin1ToBuf(str)
        });
    }
    static fromUTF8(str) {
        return new Secret({
            buffer: utf8ToBuf(str)
        });
    }
    static fromBase32(str) {
        return new Secret({
            buffer: base32ToBuf(str)
        });
    }
    static fromHex(str) {
        return new Secret({
            buffer: hexToBuf(str)
        });
    }
    get latin1() {
        Object.defineProperty(this, "latin1", {
            enumerable: true,
            value: latin1FromBuf(this.buffer)
        });
        return this.latin1;
    }
    get utf8() {
        Object.defineProperty(this, "utf8", {
            enumerable: true,
            value: utf8FromBuf(this.buffer)
        });
        return this.utf8;
    }
    get base32() {
        Object.defineProperty(this, "base32", {
            enumerable: true,
            value: base32FromBuf(this.buffer)
        });
        return this.base32;
    }
    get hex() {
        Object.defineProperty(this, "hex", {
            enumerable: true,
            value: hexFromBuf(this.buffer)
        });
        return this.hex;
    }
}
const timingSafeEqual1 = (a, b)=>{
    if (crypto1 !== null && crypto1 !== void 0 && timingSafeEqual$1) {
        return timingSafeEqual$1(globalScope.Buffer.from(a), globalScope.Buffer.from(b));
    } else {
        if (a.length !== b.length) {
            throw new TypeError("Input strings must have the same length");
        }
        let i = -1;
        let out = 0;
        while(++i < a.length){
            out |= a.charCodeAt(i) ^ b.charCodeAt(i);
        }
        return out === 0;
    }
};
class HOTP {
    static get defaults() {
        return {
            issuer: "",
            label: "OTPAuth",
            algorithm: "SHA1",
            digits: 6,
            counter: 0,
            window: 1
        };
    }
    constructor(){
        let { issuer =HOTP.defaults.issuer , label =HOTP.defaults.label , secret =new Secret() , algorithm =HOTP.defaults.algorithm , digits =HOTP.defaults.digits , counter =HOTP.defaults.counter  } = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
        this.issuer = issuer;
        this.label = label;
        this.secret = typeof secret === "string" ? Secret.fromBase32(secret) : secret;
        this.algorithm = algorithm.toUpperCase();
        this.digits = digits;
        this.counter = counter;
    }
    static generate(_ref) {
        let { secret , algorithm =HOTP.defaults.algorithm , digits =HOTP.defaults.digits , counter =HOTP.defaults.counter  } = _ref;
        const digest = new Uint8Array(hmacDigest(algorithm, secret.buffer, uintToBuf(counter)));
        const offset = digest[digest.byteLength - 1] & 15;
        const otp = ((digest[offset] & 127) << 24 | (digest[offset + 1] & 255) << 16 | (digest[offset + 2] & 255) << 8 | digest[offset + 3] & 255) % 10 ** digits;
        return pad(otp, digits);
    }
    generate() {
        let { counter =this.counter++  } = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
        return HOTP.generate({
            secret: this.secret,
            algorithm: this.algorithm,
            digits: this.digits,
            counter
        });
    }
    static validate(_ref2) {
        let { token , secret , algorithm , digits , counter =HOTP.defaults.counter , window: window1 = HOTP.defaults.window  } = _ref2;
        if (token.length !== digits) return null;
        let delta = null;
        for(let i = counter - window1; i <= counter + window1; ++i){
            const generatedToken = HOTP.generate({
                secret,
                algorithm,
                digits,
                counter: i
            });
            if (timingSafeEqual1(token, generatedToken)) {
                delta = i - counter;
            }
        }
        return delta;
    }
    validate(_ref3) {
        let { token , counter =this.counter , window: window1  } = _ref3;
        return HOTP.validate({
            token,
            secret: this.secret,
            algorithm: this.algorithm,
            digits: this.digits,
            counter,
            window: window1
        });
    }
    toString() {
        const e = encodeURIComponent;
        return "otpauth://hotp/" + `${this.issuer.length > 0 ? `${e(this.issuer)}:${e(this.label)}?issuer=${e(this.issuer)}&` : `${e(this.label)}?`}` + `secret=${e(this.secret.base32)}&` + `algorithm=${e(this.algorithm)}&` + `digits=${e(this.digits)}&` + `counter=${e(this.counter)}`;
    }
}
class TOTP {
    static get defaults() {
        return {
            issuer: "",
            label: "OTPAuth",
            algorithm: "SHA1",
            digits: 6,
            period: 30,
            window: 1
        };
    }
    constructor(){
        let { issuer =TOTP.defaults.issuer , label =TOTP.defaults.label , secret =new Secret() , algorithm =TOTP.defaults.algorithm , digits =TOTP.defaults.digits , period =TOTP.defaults.period  } = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
        this.issuer = issuer;
        this.label = label;
        this.secret = typeof secret === "string" ? Secret.fromBase32(secret) : secret;
        this.algorithm = algorithm.toUpperCase();
        this.digits = digits;
        this.period = period;
    }
    static generate(_ref) {
        let { secret , algorithm , digits , period =TOTP.defaults.period , timestamp =Date.now()  } = _ref;
        return HOTP.generate({
            secret,
            algorithm,
            digits,
            counter: Math.floor(timestamp / 1000 / period)
        });
    }
    generate() {
        let { timestamp =Date.now()  } = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
        return TOTP.generate({
            secret: this.secret,
            algorithm: this.algorithm,
            digits: this.digits,
            period: this.period,
            timestamp
        });
    }
    static validate(_ref2) {
        let { token , secret , algorithm , digits , period =TOTP.defaults.period , timestamp =Date.now() , window: window1  } = _ref2;
        return HOTP.validate({
            token,
            secret,
            algorithm,
            digits,
            counter: Math.floor(timestamp / 1000 / period),
            window: window1
        });
    }
    validate(_ref3) {
        let { token , timestamp , window: window1  } = _ref3;
        return TOTP.validate({
            token,
            secret: this.secret,
            algorithm: this.algorithm,
            digits: this.digits,
            period: this.period,
            timestamp,
            window: window1
        });
    }
    toString() {
        const e = encodeURIComponent;
        return "otpauth://totp/" + `${this.issuer.length > 0 ? `${e(this.issuer)}:${e(this.label)}?issuer=${e(this.issuer)}&` : `${e(this.label)}?`}` + `secret=${e(this.secret.base32)}&` + `algorithm=${e(this.algorithm)}&` + `digits=${e(this.digits)}&` + `period=${e(this.period)}`;
    }
}
const OTPURI_REGEX = /^otpauth:\/\/([ht]otp)\/(.+)\?([A-Z0-9.~_-]+=[^?&]*(?:&[A-Z0-9.~_-]+=[^?&]*)*)$/i;
const SECRET_REGEX = /^[2-7A-Z]+=*$/i;
const ALGORITHM_REGEX = /^SHA(?:1|224|256|384|512|3-224|3-256|3-384|3-512)$/i;
const INTEGER_REGEX = /^[+-]?\d+$/;
const POSITIVE_INTEGER_REGEX = /^\+?[1-9]\d*$/;
class URI {
    static parse(uri) {
        let uriGroups;
        try {
            uriGroups = uri.match(OTPURI_REGEX);
        } catch (error) {}
        if (!Array.isArray(uriGroups)) {
            throw new URIError("Invalid URI format");
        }
        const uriType = uriGroups[1].toLowerCase();
        const uriLabel = uriGroups[2].split(/(?::|%3A) *(.+)/i, 2).map(decodeURIComponent);
        const uriParams = uriGroups[3].split("&").reduce((acc, cur)=>{
            const pairArr = cur.split(/=(.*)/, 2).map(decodeURIComponent);
            const pairKey = pairArr[0].toLowerCase();
            const pairVal = pairArr[1];
            const pairAcc = acc;
            pairAcc[pairKey] = pairVal;
            return pairAcc;
        }, {});
        let OTP;
        const config = {};
        if (uriType === "hotp") {
            OTP = HOTP;
            if (typeof uriParams.counter !== "undefined" && INTEGER_REGEX.test(uriParams.counter)) {
                config.counter = parseInt(uriParams.counter, 10);
            } else {
                throw new TypeError("Missing or invalid 'counter' parameter");
            }
        } else if (uriType === "totp") {
            OTP = TOTP;
            if (typeof uriParams.period !== "undefined") {
                if (POSITIVE_INTEGER_REGEX.test(uriParams.period)) {
                    config.period = parseInt(uriParams.period, 10);
                } else {
                    throw new TypeError("Invalid 'period' parameter");
                }
            }
        } else {
            throw new TypeError("Unknown OTP type");
        }
        if (uriLabel.length === 2) {
            config.label = uriLabel[1];
            config.issuer = uriLabel[0];
        } else {
            config.label = uriLabel[0];
            if (typeof uriParams.issuer !== "undefined") {
                config.issuer = uriParams.issuer;
            }
        }
        if (typeof uriParams.secret !== "undefined" && SECRET_REGEX.test(uriParams.secret)) {
            config.secret = uriParams.secret;
        } else {
            throw new TypeError("Missing or invalid 'secret' parameter");
        }
        if (typeof uriParams.algorithm !== "undefined") {
            if (ALGORITHM_REGEX.test(uriParams.algorithm)) {
                config.algorithm = uriParams.algorithm;
            } else {
                throw new TypeError("Invalid 'algorithm' parameter");
            }
        }
        if (typeof uriParams.digits !== "undefined") {
            if (POSITIVE_INTEGER_REGEX.test(uriParams.digits)) {
                config.digits = parseInt(uriParams.digits, 10);
            } else {
                throw new TypeError("Invalid 'digits' parameter");
            }
        }
        return new OTP(config);
    }
    static stringify(otp) {
        if (otp instanceof HOTP || otp instanceof TOTP) {
            return otp.toString();
        }
        throw new TypeError("Invalid 'HOTP/TOTP' object");
    }
}
const version = "9.0.2";
const mod7 = {
    HOTP: HOTP,
    Secret: Secret,
    TOTP: TOTP,
    URI: URI,
    version: version
};
const importMeta = {
    url: "https://deno.land/x/denomailer@1.6.0/client/worker/worker.ts",
    main: false
};
class SMTPWorker {
    id = 1;
    #timeout;
    constructor(config){
        this.#config = config;
        this.#timeout = config.pool.timeout;
    }
    #w;
    #idleTO = null;
    #idleMode2 = false;
    #noCon = true;
    #config;
    #resolver = new Map();
    #startup() {
        this.#w = new Worker(new URL("./worker-file.ts", importMeta.url), {
            type: "module",
            deno: {
                permissions: {
                    net: "inherit",
                    read: true
                },
                namespace: true
            }
        });
        this.#w.addEventListener("message", (ev)=>{
            if (typeof ev.data === "object") {
                if ("err" in ev.data) {
                    this.#resolver.get(ev.data.__ret)?.rej(ev.data.err);
                }
                if ("res" in ev.data) {
                    this.#resolver.get(ev.data.__ret)?.res(ev.data.res);
                }
                this.#resolver.delete(ev.data.__ret);
                return;
            }
            if (ev.data) {
                this.#stopIdle();
            } else {
                if (this.#idleMode2) {
                    this.#cleanup();
                } else {
                    this.#startIdle();
                }
            }
        });
        this.#w.postMessage({
            __setup: {
                ...this.#config,
                client: {
                    ...this.#config.client,
                    preprocessors: []
                }
            }
        });
        this.#noCon = false;
    }
    #startIdle() {
        console.log("started idle");
        if (this.#idleTO) {
            return;
        }
        this.#idleTO = setTimeout(()=>{
            console.log("idle mod 2");
            this.#idleMode2 = true;
            this.#w.postMessage({
                __check_idle: true
            });
        }, this.#timeout);
    }
    #stopIdle() {
        if (this.#idleTO) {
            clearTimeout(this.#idleTO);
        }
        this.#idleMode2 = false;
        this.#idleTO = null;
    }
    #cleanup() {
        console.log("killed");
        this.#w.terminate();
        this.#stopIdle();
    }
    send(mail) {
        const myID = this.id;
        this.id++;
        this.#stopIdle();
        if (this.#noCon) {
            this.#startup();
        }
        this.#w.postMessage({
            __mail: myID,
            mail
        });
        return new Promise((res, rej)=>{
            this.#resolver.set(myID, {
                res,
                rej
            });
        });
    }
    close() {
        if (this.#w) this.#w.terminate();
        if (this.#idleTO) {
            clearTimeout(this.#idleTO);
        }
    }
}
class SMTPWorkerPool {
    pool = [];
    constructor(config){
        for(let i = 0; i < config.pool.size; i++){
            this.pool.push(new SMTPWorker(config));
        }
    }
    #lastUsed = -1;
    send(mail) {
        this.#lastUsed = (this.#lastUsed + 1) % this.pool.length;
        return this.pool[this.#lastUsed].send(mail);
    }
    close() {
        this.pool.forEach((v)=>v.close());
    }
}
class QUE {
    running = false;
    #que = [];
    idle = Promise.resolve();
    #idbleCB;
    que() {
        if (!this.running) {
            this.running = true;
            this.idle = new Promise((res)=>{
                this.#idbleCB = res;
            });
            return Promise.resolve();
        }
        return new Promise((res)=>{
            this.#que.push(res);
        });
    }
    next() {
        if (this.#que.length === 0) {
            this.running = false;
            if (this.#idbleCB) {
                this.#idbleCB();
            }
            return;
        }
        this.#que[0]();
        this.#que.splice(0, 1);
    }
}
class TextEncoderOrIntArrayStream {
    #encoder = new TextEncoder();
    #transform = new TransformStream({
        transform: (chunk, ctx)=>{
            if (typeof chunk === "string") {
                ctx.enqueue(this.#encoder.encode(chunk));
                return;
            }
            ctx.enqueue(chunk);
        }
    });
    get readable() {
        return this.#transform.readable;
    }
    get writable() {
        return this.#transform.writable;
    }
}
class TextLineStream {
    #buf = "";
    #transform = new TransformStream({
        transform: (chunk, controller)=>this.#handle(chunk, controller),
        flush: (controler)=>this.#handle("\r\n", controler)
    });
    get readable() {
        return this.#transform.readable;
    }
    get writable() {
        return this.#transform.writable;
    }
    #handle(chunk1, controller1) {
        chunk1 = this.#buf + chunk1;
        const chunks = chunk1.split("\r\n");
        if (chunks.length > 1) {
            for(let i = 0; i < chunks.length - 1; i++){
                controller1.enqueue(chunks[i]);
            }
        }
        this.#buf = chunks.at(-1) ?? "";
    }
}
class TextDecoderStream {
    #decoder;
    #transform;
    constructor(label = "utf-8", options = {}){
        this.#decoder = new TextDecoder(label, options);
        this.#transform = new TransformStream({
            transform: (chunk, controller)=>{
                const decoded = this.#decoder.decode(chunk, {
                    stream: true
                });
                if (decoded) {
                    controller.enqueue(decoded);
                }
            },
            flush: (controller)=>{
                const __final = this.#decoder.decode();
                if (__final) {
                    controller.enqueue(__final);
                }
            }
        });
    }
    get readable() {
        return this.#transform.readable;
    }
    get writable() {
        return this.#transform.writable;
    }
    close() {
        this.#decoder.decode();
    }
}
class SMTPConnection {
    #outTransform;
    #decoder;
    #lineStream;
    #writableTransformStream;
    #readableStream;
    #reader;
    #writer;
    #que;
    constructor(conn, config){
        this.conn = conn;
        this.config = config;
        this.#outTransform = new TextEncoderOrIntArrayStream();
        this.#decoder = new TextDecoderStream();
        this.#lineStream = new TextLineStream();
        this.#writableTransformStream = new TransformStream();
        this.#que = new QUE();
        this.#writableTransformStream.readable.pipeThrough(this.#outTransform).pipeTo(this.conn.writable);
        this.#readableStream = this.conn.readable.pipeThrough(this.#decoder).pipeThrough(this.#lineStream);
        this.#reader = this.#readableStream.getReader();
        this.#writer = this.#writableTransformStream.writable.getWriter();
    }
    async cleanupForStartTLS() {
        await this.#reader.cancel();
        await this.#writer.close();
    }
    async readLine() {
        const ret = await this.#reader.read();
        return ret.value ?? null;
    }
    async write(chunks) {
        if (chunks.length === 0) return;
        await this.#que.que();
        for (const chunk of chunks){
            await this.#writer.write(chunk);
        }
        this.#que.next();
    }
    close() {
        try {
            this.conn.close();
        } catch (_ex) {}
        try {
            this.#decoder.close();
        } catch (_ex) {}
    }
    assertCode(cmd, code, msg) {
        if (!cmd) {
            throw new Error(`invalid cmd`);
        }
        if (cmd.code !== code) {
            throw new Error(msg || cmd.code + ": " + cmd.args);
        }
    }
    async readCmd() {
        const result = [];
        while(result.length === 0 || result.at(-1) && result.at(-1).at(3) === "-"){
            result.push(await this.readLine());
        }
        const nonNullResult = result.filter((v)=>v !== null);
        if (nonNullResult.length === 0) return null;
        const code = parseInt(nonNullResult[0].slice(0, 3));
        const data = nonNullResult.map((v)=>v.slice(4).trim());
        if (this.config.debug.log) {
            nonNullResult.forEach((v)=>console.log(v));
        }
        return {
            code,
            args: data
        };
    }
    writeCmd(...args) {
        if (this.config.debug.log) {
            console.table(args);
        }
        return this.write([
            args.join(" ") + "\r\n"
        ]);
    }
    writeCmdBinary(...args) {
        if (this.config.debug.log) {
            console.table(args.map(()=>"Uint8Array"));
        }
        return this.write(args);
    }
    async writeCmdAndRead(...args) {
        await this.writeCmd(...args);
        return this.readCmd();
    }
    async writeCmdAndAssert(code, ...args) {
        const res = await this.writeCmdAndRead(...args);
        this.assertCode(res, code);
        return res;
    }
    conn;
    config;
}
const CommandCode = {
    READY: 220,
    AUTHO_NEXT: 334,
    AUTHO_SUCCESS: 235,
    OK: 250,
    BEGIN_DATA: 354,
    FAIL: 554
};
class SMTPClient {
    secure;
    #connection;
    #que;
    constructor(config){
        this.config = config;
        this.secure = false;
        this.#que = new QUE();
        this.#supportedFeatures = new Set();
        this.#ready = (async ()=>{
            let conn;
            if (this.config.connection.tls) {
                conn = await Deno.connectTls({
                    hostname: this.config.connection.hostname,
                    port: this.config.connection.port
                });
                this.secure = true;
            } else {
                conn = await Deno.connect({
                    hostname: this.config.connection.hostname,
                    port: this.config.connection.port
                });
            }
            this.#connection = new SMTPConnection(conn, config);
            await this.#prepareConnection();
        })();
    }
    #ready;
    close() {
        return this.#connection.close();
    }
    get isSending() {
        return this.#que.running;
    }
    get idle() {
        return this.#que.idle;
    }
    async send(config) {
        await this.#ready;
        let dataMode = false;
        try {
            await this.#que.que();
            await this.#connection.writeCmdAndAssert(CommandCode.OK, "MAIL", "FROM:", `<${config.from.mail}>`);
            for(let i = 0; i < config.to.length; i++){
                await this.#connection.writeCmdAndAssert(CommandCode.OK, "RCPT", "TO:", `<${config.to[i].mail}>`);
            }
            for(let i = 0; i < config.cc.length; i++){
                await this.#connection.writeCmdAndAssert(CommandCode.OK, "RCPT", "TO:", `<${config.cc[i].mail}>`);
            }
            for(let i = 0; i < config.bcc.length; i++){
                await this.#connection.writeCmdAndAssert(CommandCode.OK, "RCPT", "TO:", `<${config.bcc[i].mail}>`);
            }
            dataMode = true;
            await this.#connection.writeCmdAndAssert(CommandCode.BEGIN_DATA, "DATA");
            this.#connection.writeCmd("Subject: ", config.subject);
            this.#connection.writeCmd("From: ", `${config.from.name} <${config.from.mail}>`);
            if (config.to.length > 0) {
                this.#connection.writeCmd("To: ", config.to.map((m)=>`${m.name} <${m.mail}>`).join(";"));
            }
            if (config.cc.length > 0) {
                this.#connection.writeCmd("Cc: ", config.cc.map((m)=>`${m.name} <${m.mail}>`).join(";"));
            }
            this.#connection.writeCmd("Date: ", config.date);
            const obj = Object.entries(config.headers);
            for(let i = 0; i < obj.length; i++){
                const [name, value] = obj[i];
                this.#connection.writeCmd(name + ": ", value);
            }
            if (config.inReplyTo) {
                this.#connection.writeCmd("InReplyTo: ", config.inReplyTo);
            }
            if (config.references) {
                this.#connection.writeCmd("References: ", config.references);
            }
            if (config.replyTo) {
                this.#connection.writeCmd("Reply-To: ", `${config.replyTo.name} <${config.replyTo.mail}>`);
            }
            if (config.priority) {
                this.#connection.writeCmd("Priority:", config.priority);
            }
            this.#connection.writeCmd("MIME-Version: 1.0");
            let boundaryAdditionAtt = 100;
            config.mimeContent.map((v)=>v.content).join("\n").replace(new RegExp("--attachment([0-9]+)", "g"), (_, numb)=>{
                boundaryAdditionAtt += parseInt(numb, 10);
                return "";
            });
            config.attachments.map((v)=>{
                return v.content;
            }).join("\n").replace(new RegExp("--attachment([0-9]+)", "g"), (_, numb)=>{
                boundaryAdditionAtt += parseInt(numb, 10);
                return "";
            });
            const attachmentBoundary = `attachment${boundaryAdditionAtt}`;
            this.#connection.writeCmd(`Content-Type: multipart/mixed; boundary=${attachmentBoundary}`, "\r\n");
            this.#connection.writeCmd(`--${attachmentBoundary}`);
            let boundaryAddition = 100;
            config.mimeContent.map((v)=>v.content).join("\n").replace(new RegExp("--message([0-9]+)", "g"), (_, numb)=>{
                boundaryAddition += parseInt(numb, 10);
                return "";
            });
            const messageBoundary = `message${boundaryAddition}`;
            this.#connection.writeCmd(`Content-Type: multipart/alternative; boundary=${messageBoundary}`, "\r\n");
            for(let i = 0; i < config.mimeContent.length; i++){
                this.#connection.writeCmd(`--${messageBoundary}`);
                this.#connection.writeCmd("Content-Type: " + config.mimeContent[i].mimeType);
                if (config.mimeContent[i].transferEncoding) {
                    this.#connection.writeCmd(`Content-Transfer-Encoding: ${config.mimeContent[i].transferEncoding}` + "\r\n");
                } else {
                    this.#connection.writeCmd("");
                }
                this.#connection.writeCmd(config.mimeContent[i].content, "\r\n");
            }
            this.#connection.writeCmd(`--${messageBoundary}--\r\n`);
            for(let i = 0; i < config.attachments.length; i++){
                const attachment = config.attachments[i];
                this.#connection.writeCmd(`--${attachmentBoundary}`);
                this.#connection.writeCmd("Content-Type:", attachment.contentType + ";", "name=" + attachment.filename);
                if (attachment.contentID) {
                    this.#connection.writeCmd(`Content-ID: <${attachment.contentID}>`);
                }
                this.#connection.writeCmd("Content-Disposition: attachment; filename=" + attachment.filename);
                if (attachment.encoding === "base64") {
                    this.#connection.writeCmd("Content-Transfer-Encoding: base64\r\n");
                    for(let line = 0; line < Math.ceil(attachment.content.length / 75); line++){
                        const lineOfBase64 = attachment.content.slice(line * 75, (line + 1) * 75);
                        this.#connection.writeCmd(lineOfBase64);
                    }
                    this.#connection.writeCmd("\r\n");
                } else if (attachment.encoding === "text") {
                    this.#connection.writeCmd("Content-Transfer-Encoding: quoted-printable", "\r\n");
                    this.#connection.writeCmd(attachment.content, "\r\n");
                }
            }
            this.#connection.writeCmd(`--${attachmentBoundary}--\r\n`);
            await this.#connection.writeCmdAndAssert(CommandCode.OK, ".\r\n");
            dataMode = false;
            await this.#cleanup();
            this.#que.next();
        } catch (ex) {
            if (dataMode) {
                console.error("Error while in datamode - connection not recoverable");
                queueMicrotask(()=>{
                    this.#connection.conn?.close();
                });
                throw ex;
            }
            await this.#cleanup();
            this.#que.next();
            throw ex;
        }
    }
    async #prepareConnection() {
        this.#connection.assertCode(await this.#connection.readCmd(), CommandCode.READY);
        await this.#connection.writeCmd("EHLO", this.config.connection.hostname);
        const cmd = await this.#connection.readCmd();
        if (!cmd) throw new Error("Unexpected empty response");
        if (typeof cmd.args === "string") {
            this.#supportedFeatures.add(cmd.args);
        } else {
            cmd.args.forEach((cmd)=>{
                this.#supportedFeatures.add(cmd);
            });
        }
        if (!this.secure && this.#supportedFeatures.has("STARTTLS") && !this.config.debug.noStartTLS) {
            this.#connection.writeCmdAndAssert(CommandCode.READY, "STARTTLS");
            await this.#connection.cleanupForStartTLS();
            const conn = await Deno.startTls(this.#connection.conn, {
                hostname: this.config.connection.hostname
            });
            this.#connection = new SMTPConnection(conn, this.config);
            this.secure = true;
            this.#connection.writeCmdAndRead("EHLO", this.config.connection.hostname);
        }
        if (!this.config.debug.allowUnsecure && !this.secure) {
            this.#connection.close();
            this.#connection = null;
            throw new Error("Connection is not secure! Don't send authentication over non secure connection!");
        }
        if (this.config.connection.auth) {
            await this.#connection.writeCmdAndAssert(CommandCode.AUTHO_NEXT, "AUTH", "LOGIN");
            await this.#connection.writeCmdAndAssert(CommandCode.AUTHO_NEXT, btoa(this.config.connection.auth.username));
            await this.#connection.writeCmdAndAssert(CommandCode.AUTHO_SUCCESS, btoa(this.config.connection.auth.password));
        }
        await this.#cleanup();
    }
    #supportedFeatures;
    async #cleanup() {
        this.#connection.writeCmd("NOOP");
        while(true){
            const cmd = await this.#connection.readCmd();
            if (cmd && cmd.code === 250) return;
        }
    }
    config;
}
function resolveClientOptions(config) {
    return {
        debug: {
            log: config.debug?.log ?? false,
            allowUnsecure: config.debug?.allowUnsecure ?? false,
            encodeLB: config.debug?.encodeLB ?? false,
            noStartTLS: config.debug?.noStartTLS ?? false
        },
        connection: {
            hostname: config.connection.hostname,
            port: config.connection.port ?? (config.connection.tls ? 465 : 25),
            tls: config.connection.tls ?? false,
            auth: config.connection.auth
        },
        pool: config.pool ? config.pool === true ? {
            size: 2,
            timeout: 60000
        } : {
            size: config.pool.size ?? 2,
            timeout: config.pool.timeout ?? 60000
        } : undefined,
        client: {
            warning: config.client?.warning ?? "log",
            preprocessors: config.client?.preprocessors ?? []
        }
    };
}
const base64abc1 = [
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "+",
    "/"
];
function encode2(data) {
    const uint8 = typeof data === "string" ? new TextEncoder().encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
    let result = "", i;
    const l = uint8.length;
    for(i = 2; i < l; i += 3){
        result += base64abc1[uint8[i - 2] >> 2];
        result += base64abc1[(uint8[i - 2] & 0x03) << 4 | uint8[i - 1] >> 4];
        result += base64abc1[(uint8[i - 1] & 0x0f) << 2 | uint8[i] >> 6];
        result += base64abc1[uint8[i] & 0x3f];
    }
    if (i === l + 1) {
        result += base64abc1[uint8[i - 2] >> 2];
        result += base64abc1[(uint8[i - 2] & 0x03) << 4];
        result += "==";
    }
    if (i === l) {
        result += base64abc1[uint8[i - 2] >> 2];
        result += base64abc1[(uint8[i - 2] & 0x03) << 4 | uint8[i - 1] >> 4];
        result += base64abc1[(uint8[i - 1] & 0x0f) << 2];
        result += "=";
    }
    return result;
}
const encoder6 = new TextEncoder();
function quotedPrintableEncode(data, encLB = false) {
    data.replaceAll("=", "=3D");
    if (!encLB) {
        data = data.replaceAll(" \r\n", "=20\r\n").replaceAll(" \n", "=20\n");
    }
    const encodedData = Array.from(data).map((ch)=>{
        const encodedChar = encoder6.encode(ch);
        if (encodedChar.length === 1) {
            const code = encodedChar[0];
            if (code >= 32 && code <= 126 && code !== 61) return ch;
            if (!encLB && (code === 10 || code === 13)) return ch;
            if (code === 9) return ch;
        }
        let enc = "";
        encodedChar.forEach((i)=>{
            let c = i.toString(16);
            if (c.length === 1) c = "0" + c;
            enc += `=${c}`;
        });
        return enc;
    }).join("");
    let ret = "";
    const lines = Math.ceil(encodedData.length / 74) - 1;
    let offset = 0;
    for(let i = 0; i < lines; i++){
        let old = encodedData.slice(i * 74 + offset, (i + 1) * 74);
        offset = 0;
        if (old.at(-1) === "=") {
            old = old.slice(0, old.length - 1);
            offset = -1;
        }
        if (old.at(-2) === "=") {
            old = old.slice(0, old.length - 2);
            offset = -2;
        }
        if (old.endsWith("\r") || old.endsWith("\n")) {
            ret += old;
        } else {
            ret += `${old}=\r\n`;
        }
    }
    ret += encodedData.slice(lines * 74);
    return ret;
}
function hasNonAsciiCharacters(str) {
    return /[^\u0000-\u007f]/.test(str);
}
function quotedPrintableEncodeInline(data) {
    if (hasNonAsciiCharacters(data) || data.startsWith("=?")) {
        return `=?utf-8?Q?${quotedPrintableEncode(data)}?=`;
    }
    return data;
}
function resolveAttachment(attachment) {
    if (attachment.encoding === "binary") {
        return {
            filename: attachment.filename,
            contentType: attachment.contentType,
            encoding: "base64",
            content: encode2(attachment.content)
        };
    } else {
        return attachment;
    }
}
function resolveContent({ text , html , mimeContent  }) {
    const newContent = [
        ...mimeContent ?? []
    ];
    if (text === "auto" && html) {
        text = html.replace(/<head((.|\n|\r)*?)<\/head>/g, "").replace(/<style((.|\n|\r)*?)<\/style>/g, "").replace(/<[^>]+>/g, "");
    }
    if (text) {
        newContent.push({
            mimeType: 'text/plain; charset="utf-8"',
            content: quotedPrintableEncode(text),
            transferEncoding: "quoted-printable"
        });
    }
    if (html) {
        newContent.push({
            mimeType: 'text/html; charset="utf-8"',
            content: quotedPrintableEncode(html),
            transferEncoding: "quoted-printable"
        });
    }
    return newContent;
}
function isSingleMail(mail) {
    return /^(([^<>()\[\]\\,;:\s@"]+@[a-zA-Z0-9\-]+\.([a-zA-Z0-9\-]+\.)*[a-zA-Z]{2,})|(<[^<>()\[\]\\,;:\s@"]+@[a-zA-Z0-9]+\.([a-zA-Z0-9\-]+\.)*[a-zA-Z]{2,}>)|([^<>]+ <[^<>()\[\]\\,;:\s@"]+@[a-zA-Z0-9]+\.([a-zA-Z0-9\-]+\.)*[a-zA-Z]{2,}>))$/.test(mail);
}
function parseSingleEmail(mail) {
    if (typeof mail !== "string") {
        return {
            mail: mail.mail,
            name: quotedPrintableEncodeInline(mail.name ?? "")
        };
    }
    const mailSplitRe = /^([^<]*)<([^>]+)>\s*$/;
    const res = mailSplitRe.exec(mail);
    if (!res) {
        return {
            mail,
            name: ""
        };
    }
    const [_, name, email] = res;
    return {
        name: quotedPrintableEncodeInline(name.trim()),
        mail: email.trim()
    };
}
function parseMailList(list) {
    if (typeof list === "string") return [
        parseSingleEmail(list)
    ];
    if (Array.isArray(list)) return list.map((v)=>parseSingleEmail(v));
    if ("mail" in list) {
        return [
            {
                mail: list.mail,
                name: quotedPrintableEncodeInline(list.name ?? "")
            }
        ];
    }
    return Object.entries(list).map(([name, mail])=>({
            name: quotedPrintableEncodeInline(name),
            mail
        }));
}
function validateEmailList(list) {
    const ok = [];
    const bad = [];
    list.forEach((mail)=>{
        if (isSingleMail(mail.mail)) {
            ok.push(mail);
        } else {
            bad.push(mail);
        }
    });
    return {
        ok,
        bad
    };
}
function validateHeaders(headers) {
    return !(Object.keys(headers).some((v)=>v.includes("\n") || v.includes("\r")) || Object.values(headers).some((v)=>v.includes("\n") || v.includes("\r")));
}
function resolveSendConfig(config) {
    const { to , cc =[] , bcc =[] , from , date =new Date().toUTCString().split(",")[1].slice(1) , subject , content , mimeContent , html , inReplyTo , replyTo , references , priority , attachments , internalTag , headers  } = config;
    return {
        to: parseMailList(to),
        cc: parseMailList(cc),
        bcc: parseMailList(bcc),
        from: parseSingleEmail(from),
        date,
        mimeContent: resolveContent({
            mimeContent,
            html,
            text: content
        }),
        replyTo: replyTo ? parseSingleEmail(replyTo) : undefined,
        inReplyTo,
        subject: quotedPrintableEncodeInline(subject),
        attachments: attachments ? attachments.map((attachment)=>resolveAttachment(attachment)) : [],
        references,
        priority,
        internalTag,
        headers: headers ?? {}
    };
}
function validateConfig(config, client) {
    const errors = [];
    const warn = [];
    if (!isSingleMail(config.from.mail)) {
        errors.push(`The specified from adress is not a valid email adress.`);
    }
    if (config.replyTo && !isSingleMail(config.replyTo.mail)) {
        errors.push(`The specified replyTo adress is not a valid email adress.`);
    }
    const valTo = validateEmailList(config.to);
    if (valTo.bad.length > 0) {
        config.to = valTo.ok;
        valTo.bad.forEach((m)=>{
            warn.push(`TO Email ${m.mail} is not valid!`);
        });
    }
    const valCc = validateEmailList(config.cc);
    if (valCc.bad.length > 0) {
        config.to = valCc.ok;
        valCc.bad.forEach((m)=>{
            warn.push(`CC Email ${m.mail} is not valid!`);
        });
    }
    const valBcc = validateEmailList(config.bcc);
    if (valBcc.bad.length > 0) {
        config.to = valBcc.ok;
        valBcc.bad.forEach((m)=>{
            warn.push(`BCC Email ${m.mail} is not valid!`);
        });
    }
    if (config.to.length + config.cc.length + config.bcc.length === 0) {
        errors.push(`No valid emails provided!`);
    }
    if (config.mimeContent.length === 0) {
        errors.push(`No content provided!`);
    }
    if (!config.mimeContent.some((v)=>v.mimeType.includes("text/html") || v.mimeType.includes("text/plain"))) {
        warn.push("You should provide at least html or text content!");
    }
    if (!validateHeaders(config.headers)) {
        errors.push(`Headers are not allowed to include linebreaks!`);
    }
    if (client.client.warning === "log" && warn.length > 0) {
        console.warn(warn.join("\n"));
    }
    if (client.client.warning === "error") {
        errors.push(...warn);
    }
    if (errors.length > 0) {
        throw new Error(errors.join("\n"));
    }
    return config;
}
class SMTPHandler {
    #internalClient;
    #clientConfig;
    constructor(config){
        const resolvedConfig = resolveClientOptions(config);
        resolvedConfig.client.preprocessors.push(validateConfig);
        this.#clientConfig = resolvedConfig;
        if (resolvedConfig.debug.log) {
            console.log("used resolved config");
            console.log(".debug");
            console.table(resolvedConfig.debug);
            console.log(".connection");
            console.table({
                ...resolvedConfig.connection,
                ...resolvedConfig.connection.auth ? {
                    auth: JSON.stringify(resolvedConfig.connection.auth)
                } : {}
            });
            console.log(".pool");
            console.table(resolvedConfig.pool);
        }
        const Client = resolvedConfig.pool ? resolvedConfig.pool.size > 1 ? SMTPWorkerPool : SMTPWorker : SMTPClient;
        this.#internalClient = new Client(resolvedConfig);
    }
    send(config) {
        let resolvedConfig = resolveSendConfig(config);
        for(let i = 0; i < this.#clientConfig.client.preprocessors.length; i++){
            const cb = this.#clientConfig.client.preprocessors[i];
            resolvedConfig = cb(resolvedConfig, this.#clientConfig);
        }
        return this.#internalClient.send(resolvedConfig);
    }
    close() {
        return this.#internalClient.close();
    }
}
var LogLevels;
(function(LogLevels) {
    LogLevels[LogLevels["NOTSET"] = 0] = "NOTSET";
    LogLevels[LogLevels["DEBUG"] = 10] = "DEBUG";
    LogLevels[LogLevels["INFO"] = 20] = "INFO";
    LogLevels[LogLevels["WARNING"] = 30] = "WARNING";
    LogLevels[LogLevels["ERROR"] = 40] = "ERROR";
    LogLevels[LogLevels["CRITICAL"] = 50] = "CRITICAL";
})(LogLevels || (LogLevels = {}));
Object.keys(LogLevels).filter((key)=>isNaN(Number(key)));
const byLevel = {
    [String(LogLevels.NOTSET)]: "NOTSET",
    [String(LogLevels.DEBUG)]: "DEBUG",
    [String(LogLevels.INFO)]: "INFO",
    [String(LogLevels.WARNING)]: "WARNING",
    [String(LogLevels.ERROR)]: "ERROR",
    [String(LogLevels.CRITICAL)]: "CRITICAL"
};
function getLevelByName(name) {
    switch(name){
        case "NOTSET":
            return LogLevels.NOTSET;
        case "DEBUG":
            return LogLevels.DEBUG;
        case "INFO":
            return LogLevels.INFO;
        case "WARNING":
            return LogLevels.WARNING;
        case "ERROR":
            return LogLevels.ERROR;
        case "CRITICAL":
            return LogLevels.CRITICAL;
        default:
            throw new Error(`no log level found for "${name}"`);
    }
}
function getLevelName(level) {
    const levelName = byLevel[level];
    if (levelName) {
        return levelName;
    }
    throw new Error(`no level name found for level: ${level}`);
}
class LogRecord {
    msg;
    #args;
    #datetime;
    level;
    levelName;
    loggerName;
    constructor(options){
        this.msg = options.msg;
        this.#args = [
            ...options.args
        ];
        this.level = options.level;
        this.loggerName = options.loggerName;
        this.#datetime = new Date();
        this.levelName = getLevelName(options.level);
    }
    get args() {
        return [
            ...this.#args
        ];
    }
    get datetime() {
        return new Date(this.#datetime.getTime());
    }
}
class Logger {
    #level;
    #handlers;
    #loggerName;
    constructor(loggerName, levelName, options = {}){
        this.#loggerName = loggerName;
        this.#level = getLevelByName(levelName);
        this.#handlers = options.handlers || [];
    }
    get level() {
        return this.#level;
    }
    set level(level) {
        this.#level = level;
    }
    get levelName() {
        return getLevelName(this.#level);
    }
    set levelName(levelName) {
        this.#level = getLevelByName(levelName);
    }
    get loggerName() {
        return this.#loggerName;
    }
    set handlers(hndls) {
        this.#handlers = hndls;
    }
    get handlers() {
        return this.#handlers;
    }
    #_log(level, msg, ...args) {
        if (this.level > level) {
            return msg instanceof Function ? undefined : msg;
        }
        let fnResult;
        let logMessage;
        if (msg instanceof Function) {
            fnResult = msg();
            logMessage = this.asString(fnResult);
        } else {
            logMessage = this.asString(msg);
        }
        const record = new LogRecord({
            msg: logMessage,
            args: args,
            level: level,
            loggerName: this.loggerName
        });
        this.#handlers.forEach((handler)=>{
            handler.handle(record);
        });
        return msg instanceof Function ? fnResult : msg;
    }
    asString(data) {
        if (typeof data === "string") {
            return data;
        } else if (data === null || typeof data === "number" || typeof data === "bigint" || typeof data === "boolean" || typeof data === "undefined" || typeof data === "symbol") {
            return String(data);
        } else if (data instanceof Error) {
            return data.stack;
        } else if (typeof data === "object") {
            return JSON.stringify(data);
        }
        return "undefined";
    }
    debug(msg, ...args) {
        return this.#_log(LogLevels.DEBUG, msg, ...args);
    }
    info(msg, ...args) {
        return this.#_log(LogLevels.INFO, msg, ...args);
    }
    warning(msg, ...args) {
        return this.#_log(LogLevels.WARNING, msg, ...args);
    }
    error(msg, ...args) {
        return this.#_log(LogLevels.ERROR, msg, ...args);
    }
    critical(msg, ...args) {
        return this.#_log(LogLevels.CRITICAL, msg, ...args);
    }
}
const { Deno: Deno1  } = globalThis;
const noColor = typeof Deno1?.noColor === "boolean" ? Deno1.noColor : true;
let enabled = !noColor;
function code(open, close) {
    return {
        open: `\x1b[${open.join(";")}m`,
        close: `\x1b[${close}m`,
        regexp: new RegExp(`\\x1b\\[${close}m`, "g")
    };
}
function run(str, code) {
    return enabled ? `${code.open}${str.replace(code.regexp, code.open)}${code.close}` : str;
}
function bold(str) {
    return run(str, code([
        1
    ], 22));
}
function red(str) {
    return run(str, code([
        31
    ], 39));
}
function yellow(str) {
    return run(str, code([
        33
    ], 39));
}
function blue(str) {
    return run(str, code([
        34
    ], 39));
}
new RegExp([
    "[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]+)*|[a-zA-Z\\d]+(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)",
    "(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-nq-uy=><~]))"
].join("|"), "g");
async function exists1(filePath) {
    try {
        await Deno.lstat(filePath);
        return true;
    } catch (error) {
        if (error instanceof Deno.errors.NotFound) {
            return false;
        }
        throw error;
    }
}
function existsSync(filePath) {
    try {
        Deno.lstatSync(filePath);
        return true;
    } catch (error) {
        if (error instanceof Deno.errors.NotFound) {
            return false;
        }
        throw error;
    }
}
const DEFAULT_FORMATTER = "{levelName} {msg}";
class BaseHandler {
    level;
    levelName;
    formatter;
    constructor(levelName, options = {}){
        this.level = getLevelByName(levelName);
        this.levelName = levelName;
        this.formatter = options.formatter || DEFAULT_FORMATTER;
    }
    handle(logRecord) {
        if (this.level > logRecord.level) return;
        const msg = this.format(logRecord);
        return this.log(msg);
    }
    format(logRecord) {
        if (this.formatter instanceof Function) {
            return this.formatter(logRecord);
        }
        return this.formatter.replace(/{([^\s}]+)}/g, (match, p1)=>{
            const value = logRecord[p1];
            if (value == null) {
                return match;
            }
            return String(value);
        });
    }
    log(_msg) {}
    setup() {}
    destroy() {}
}
class ConsoleHandler extends BaseHandler {
    format(logRecord) {
        let msg = super.format(logRecord);
        switch(logRecord.level){
            case LogLevels.INFO:
                msg = blue(msg);
                break;
            case LogLevels.WARNING:
                msg = yellow(msg);
                break;
            case LogLevels.ERROR:
                msg = red(msg);
                break;
            case LogLevels.CRITICAL:
                msg = bold(red(msg));
                break;
            default:
                break;
        }
        return msg;
    }
    log(msg) {
        console.log(msg);
    }
}
class WriterHandler extends BaseHandler {
    _writer;
    #encoder = new TextEncoder();
}
class FileHandler extends WriterHandler {
    _file;
    _buf;
    _filename;
    _mode;
    _openOptions;
    _encoder = new TextEncoder();
    #unloadCallback = (()=>{
        this.destroy();
    }).bind(this);
    constructor(levelName, options){
        super(levelName, options);
        this._filename = options.filename;
        this._mode = options.mode ? options.mode : "a";
        this._openOptions = {
            createNew: this._mode === "x",
            create: this._mode !== "x",
            append: this._mode === "a",
            truncate: this._mode !== "a",
            write: true
        };
    }
    setup() {
        this._file = Deno.openSync(this._filename, this._openOptions);
        this._writer = this._file;
        this._buf = new BufWriterSync(this._file);
        addEventListener("unload", this.#unloadCallback);
    }
    handle(logRecord) {
        super.handle(logRecord);
        if (logRecord.level > LogLevels.ERROR) {
            this.flush();
        }
    }
    log(msg) {
        if (this._encoder.encode(msg).byteLength + 1 > this._buf.available()) {
            this.flush();
        }
        this._buf.writeSync(this._encoder.encode(msg + "\n"));
    }
    flush() {
        if (this._buf?.buffered() > 0) {
            this._buf.flush();
        }
    }
    destroy() {
        this.flush();
        this._file?.close();
        this._file = undefined;
        removeEventListener("unload", this.#unloadCallback);
    }
}
class RotatingFileHandler extends FileHandler {
    #maxBytes;
    #maxBackupCount;
    #currentFileSize = 0;
    constructor(levelName, options){
        super(levelName, options);
        this.#maxBytes = options.maxBytes;
        this.#maxBackupCount = options.maxBackupCount;
    }
    async setup() {
        if (this.#maxBytes < 1) {
            this.destroy();
            throw new Error("maxBytes cannot be less than 1");
        }
        if (this.#maxBackupCount < 1) {
            this.destroy();
            throw new Error("maxBackupCount cannot be less than 1");
        }
        await super.setup();
        if (this._mode === "w") {
            for(let i = 1; i <= this.#maxBackupCount; i++){
                try {
                    await Deno.remove(this._filename + "." + i);
                } catch (error) {
                    if (!(error instanceof Deno.errors.NotFound)) {
                        throw error;
                    }
                }
            }
        } else if (this._mode === "x") {
            for(let i = 1; i <= this.#maxBackupCount; i++){
                if (await exists1(this._filename + "." + i)) {
                    this.destroy();
                    throw new Deno.errors.AlreadyExists("Backup log file " + this._filename + "." + i + " already exists");
                }
            }
        } else {
            this.#currentFileSize = (await Deno.stat(this._filename)).size;
        }
    }
    log(msg) {
        const msgByteLength = this._encoder.encode(msg).byteLength + 1;
        if (this.#currentFileSize + msgByteLength > this.#maxBytes) {
            this.rotateLogFiles();
            this.#currentFileSize = 0;
        }
        super.log(msg);
        this.#currentFileSize += msgByteLength;
    }
    rotateLogFiles() {
        this._buf.flush();
        this._file.close();
        for(let i = this.#maxBackupCount - 1; i >= 0; i--){
            const source = this._filename + (i === 0 ? "" : "." + i);
            const dest = this._filename + "." + (i + 1);
            if (existsSync(source)) {
                Deno.renameSync(source, dest);
            }
        }
        this._file = Deno.openSync(this._filename, this._openOptions);
        this._writer = this._file;
        this._buf = new BufWriterSync(this._file);
    }
}
class LoggerConfig {
    level;
    handlers;
}
const DEFAULT_LEVEL = "INFO";
const DEFAULT_CONFIG = {
    handlers: {
        default: new ConsoleHandler(DEFAULT_LEVEL)
    },
    loggers: {
        default: {
            level: DEFAULT_LEVEL,
            handlers: [
                "default"
            ]
        }
    }
};
const state1 = {
    handlers: new Map(),
    loggers: new Map(),
    config: DEFAULT_CONFIG
};
const handlers = {
    BaseHandler,
    ConsoleHandler,
    WriterHandler,
    FileHandler,
    RotatingFileHandler
};
function getLogger(name) {
    if (!name) {
        const d = state1.loggers.get("default");
        assert(d != null, `"default" logger must be set for getting logger without name`);
        return d;
    }
    const result = state1.loggers.get(name);
    if (!result) {
        const logger = new Logger(name, "NOTSET", {
            handlers: []
        });
        state1.loggers.set(name, logger);
        return logger;
    }
    return result;
}
function debug(msg, ...args) {
    if (msg instanceof Function) {
        return getLogger("default").debug(msg, ...args);
    }
    return getLogger("default").debug(msg, ...args);
}
function info(msg, ...args) {
    if (msg instanceof Function) {
        return getLogger("default").info(msg, ...args);
    }
    return getLogger("default").info(msg, ...args);
}
function warning(msg, ...args) {
    if (msg instanceof Function) {
        return getLogger("default").warning(msg, ...args);
    }
    return getLogger("default").warning(msg, ...args);
}
function error2(msg, ...args) {
    if (msg instanceof Function) {
        return getLogger("default").error(msg, ...args);
    }
    return getLogger("default").error(msg, ...args);
}
function critical(msg, ...args) {
    if (msg instanceof Function) {
        return getLogger("default").critical(msg, ...args);
    }
    return getLogger("default").critical(msg, ...args);
}
function setup(config) {
    state1.config = {
        handlers: {
            ...DEFAULT_CONFIG.handlers,
            ...config.handlers
        },
        loggers: {
            ...DEFAULT_CONFIG.loggers,
            ...config.loggers
        }
    };
    state1.handlers.forEach((handler)=>{
        handler.destroy();
    });
    state1.handlers.clear();
    const handlers = state1.config.handlers || {};
    for(const handlerName in handlers){
        const handler = handlers[handlerName];
        handler.setup();
        state1.handlers.set(handlerName, handler);
    }
    state1.loggers.clear();
    const loggers = state1.config.loggers || {};
    for(const loggerName in loggers){
        const loggerConfig = loggers[loggerName];
        const handlerNames = loggerConfig.handlers || [];
        const handlers = [];
        handlerNames.forEach((handlerName)=>{
            const handler = state1.handlers.get(handlerName);
            if (handler) {
                handlers.push(handler);
            }
        });
        const levelName = loggerConfig.level || DEFAULT_LEVEL;
        const logger = new Logger(loggerName, levelName, {
            handlers: handlers
        });
        state1.loggers.set(loggerName, logger);
    }
}
setup(DEFAULT_CONFIG);
const mod8 = {
    LogLevels: LogLevels,
    Logger: Logger,
    LoggerConfig: LoggerConfig,
    handlers: handlers,
    getLogger: getLogger,
    debug: debug,
    info: info,
    warning: warning,
    error: error2,
    critical: critical,
    setup: setup
};
let wasm;
const heap = new Array(32).fill(undefined);
heap.push(undefined, null, true, false);
function getObject(idx) {
    return heap[idx];
}
let heap_next = heap.length;
function dropObject(idx) {
    if (idx < 36) return;
    heap[idx] = heap_next;
    heap_next = idx;
}
function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}
function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];
    heap[idx] = obj;
    return idx;
}
const cachedTextDecoder = new TextDecoder("utf-8", {
    ignoreBOM: true,
    fatal: true
});
cachedTextDecoder.decode();
let cachedUint8Memory0 = new Uint8Array();
function getUint8Memory0() {
    if (cachedUint8Memory0.byteLength === 0) {
        cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8Memory0;
}
function getStringFromWasm0(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}
let WASM_VECTOR_LEN = 0;
const cachedTextEncoder = new TextEncoder("utf-8");
const encodeString = function(arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
};
function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length);
        getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }
    let len = arg.length;
    let ptr = malloc(len);
    const mem = getUint8Memory0();
    let offset = 0;
    for(; offset < len; offset++){
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3);
        const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);
        offset += ret.written;
    }
    WASM_VECTOR_LEN = offset;
    return ptr;
}
function isLikeNone(x) {
    return x === undefined || x === null;
}
let cachedInt32Memory0 = new Int32Array();
function getInt32Memory0() {
    if (cachedInt32Memory0.byteLength === 0) {
        cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachedInt32Memory0;
}
function getArrayU8FromWasm0(ptr, len) {
    return getUint8Memory0().subarray(ptr / 1, ptr / 1 + len);
}
function digest(algorithm, data, length) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(algorithm, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.digest(retptr, ptr0, len0, addHeapObject(data), !isLikeNone(length), isLikeNone(length) ? 0 : length);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        var r3 = getInt32Memory0()[retptr / 4 + 3];
        if (r3) {
            throw takeObject(r2);
        }
        var v1 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v1;
    } finally{
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}
const DigestContextFinalization = new FinalizationRegistry((ptr)=>wasm.__wbg_digestcontext_free(ptr));
class DigestContext {
    static __wrap(ptr) {
        const obj = Object.create(DigestContext.prototype);
        obj.ptr = ptr;
        DigestContextFinalization.register(obj, obj.ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;
        DigestContextFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_digestcontext_free(ptr);
    }
    constructor(algorithm){
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(algorithm, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.digestcontext_new(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return DigestContext.__wrap(r0);
        } finally{
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    update(data) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.digestcontext_update(retptr, this.ptr, addHeapObject(data));
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            if (r1) {
                throw takeObject(r0);
            }
        } finally{
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    digest(length) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.digestcontext_digest(retptr, this.ptr, !isLikeNone(length), isLikeNone(length) ? 0 : length);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            var r3 = getInt32Memory0()[retptr / 4 + 3];
            if (r3) {
                throw takeObject(r2);
            }
            var v0 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1);
            return v0;
        } finally{
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    digestAndReset(length) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.digestcontext_digestAndReset(retptr, this.ptr, !isLikeNone(length), isLikeNone(length) ? 0 : length);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            var r3 = getInt32Memory0()[retptr / 4 + 3];
            if (r3) {
                throw takeObject(r2);
            }
            var v0 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1);
            return v0;
        } finally{
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    digestAndDrop(length) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.digestcontext_digestAndDrop(retptr, ptr, !isLikeNone(length), isLikeNone(length) ? 0 : length);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            var r3 = getInt32Memory0()[retptr / 4 + 3];
            if (r3) {
                throw takeObject(r2);
            }
            var v0 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1);
            return v0;
        } finally{
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    reset() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.digestcontext_reset(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            if (r1) {
                throw takeObject(r0);
            }
        } finally{
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    clone() {
        const ret = wasm.digestcontext_clone(this.ptr);
        return DigestContext.__wrap(ret);
    }
}
const imports = {
    __wbindgen_placeholder__: {
        __wbg_new_db254ae0a1bb0ff5: function(arg0, arg1) {
            const ret = new TypeError(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        },
        __wbindgen_object_drop_ref: function(arg0) {
            takeObject(arg0);
        },
        __wbg_byteLength_87a0436a74adc26c: function(arg0) {
            const ret = getObject(arg0).byteLength;
            return ret;
        },
        __wbg_byteOffset_4477d54710af6f9b: function(arg0) {
            const ret = getObject(arg0).byteOffset;
            return ret;
        },
        __wbg_buffer_21310ea17257b0b4: function(arg0) {
            const ret = getObject(arg0).buffer;
            return addHeapObject(ret);
        },
        __wbg_newwithbyteoffsetandlength_d9aa266703cb98be: function(arg0, arg1, arg2) {
            const ret = new Uint8Array(getObject(arg0), arg1 >>> 0, arg2 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_length_9e1ae1900cb0fbd5: function(arg0) {
            const ret = getObject(arg0).length;
            return ret;
        },
        __wbindgen_memory: function() {
            const ret = wasm.memory;
            return addHeapObject(ret);
        },
        __wbg_buffer_3f3d764d4747d564: function(arg0) {
            const ret = getObject(arg0).buffer;
            return addHeapObject(ret);
        },
        __wbg_new_8c3f0052272a457a: function(arg0) {
            const ret = new Uint8Array(getObject(arg0));
            return addHeapObject(ret);
        },
        __wbg_set_83db9690f9353e79: function(arg0, arg1, arg2) {
            getObject(arg0).set(getObject(arg1), arg2 >>> 0);
        },
        __wbindgen_throw: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        }
    }
};
function instantiate() {
    return instantiateWithInstance().exports;
}
let instanceWithExports;
function instantiateWithInstance() {
    if (instanceWithExports == null) {
        const instance = instantiateInstance();
        wasm = instance.exports;
        cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
        cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
        instanceWithExports = {
            instance,
            exports: {
                digest,
                DigestContext
            }
        };
    }
    return instanceWithExports;
}
function instantiateInstance() {
    const wasmBytes = base64decode("\
AGFzbQEAAAABrIGAgAAZYAAAYAABf2ABfwBgAX8Bf2ABfwF+YAJ/fwBgAn9/AX9gA39/fwBgA39/fw\
F/YAR/f39/AGAEf39/fwF/YAV/f39/fwBgBX9/f39/AX9gBn9/f39/fwBgBn9/f39/fwF/YAV/f39+\
fwBgB39/f35/f38Bf2ADf39+AGAFf39+f38AYAV/f31/fwBgBX9/fH9/AGACf34AYAR/fn9/AGAEf3\
1/fwBgBH98f38AAqSFgIAADBhfX3diaW5kZ2VuX3BsYWNlaG9sZGVyX18aX193YmdfbmV3X2RiMjU0\
YWUwYTFiYjBmZjUABhhfX3diaW5kZ2VuX3BsYWNlaG9sZGVyX18aX193YmluZGdlbl9vYmplY3RfZH\
JvcF9yZWYAAhhfX3diaW5kZ2VuX3BsYWNlaG9sZGVyX18hX193YmdfYnl0ZUxlbmd0aF84N2EwNDM2\
YTc0YWRjMjZjAAMYX193YmluZGdlbl9wbGFjZWhvbGRlcl9fIV9fd2JnX2J5dGVPZmZzZXRfNDQ3N2\
Q1NDcxMGFmNmY5YgADGF9fd2JpbmRnZW5fcGxhY2Vob2xkZXJfXx1fX3diZ19idWZmZXJfMjEzMTBl\
YTE3MjU3YjBiNAADGF9fd2JpbmRnZW5fcGxhY2Vob2xkZXJfXzFfX3diZ19uZXd3aXRoYnl0ZW9mZn\
NldGFuZGxlbmd0aF9kOWFhMjY2NzAzY2I5OGJlAAgYX193YmluZGdlbl9wbGFjZWhvbGRlcl9fHV9f\
d2JnX2xlbmd0aF85ZTFhZTE5MDBjYjBmYmQ1AAMYX193YmluZGdlbl9wbGFjZWhvbGRlcl9fEV9fd2\
JpbmRnZW5fbWVtb3J5AAEYX193YmluZGdlbl9wbGFjZWhvbGRlcl9fHV9fd2JnX2J1ZmZlcl8zZjNk\
NzY0ZDQ3NDdkNTY0AAMYX193YmluZGdlbl9wbGFjZWhvbGRlcl9fGl9fd2JnX25ld184YzNmMDA1Mj\
I3MmE0NTdhAAMYX193YmluZGdlbl9wbGFjZWhvbGRlcl9fGl9fd2JnX3NldF84M2RiOTY5MGY5MzUz\
ZTc5AAcYX193YmluZGdlbl9wbGFjZWhvbGRlcl9fEF9fd2JpbmRnZW5fdGhyb3cABQOPgYCAAI0BCw\
cLBwMJEQUHBwUHDwMHBQgFEAUHBQIHBQIGBwYHFQgHDgcHBwYBAQEBBwgHBwcBBwcHAQgHBwcHBwUC\
BwcHBwcBAQcHBQ0IBwkHCQEBAQEBBQkNCwkFBQUFBQUGBgcHBwcCAggHBwUCCgAFAgMCAg4MCwwLCx\
MUEgkICAYGBQcHAAYDAAAFCAgIBAACBIWAgIAAAXABFRUFg4CAgAABABEGiYCAgAABfwFBgIDAAAsH\
uYKAgAAOBm1lbW9yeQIABmRpZ2VzdABSGF9fd2JnX2RpZ2VzdGNvbnRleHRfZnJlZQBuEWRpZ2VzdG\
NvbnRleHRfbmV3AFYUZGlnZXN0Y29udGV4dF91cGRhdGUAcRRkaWdlc3Rjb250ZXh0X2RpZ2VzdABV\
HGRpZ2VzdGNvbnRleHRfZGlnZXN0QW5kUmVzZXQAVxtkaWdlc3Rjb250ZXh0X2RpZ2VzdEFuZERyb3\
AAXhNkaWdlc3Rjb250ZXh0X3Jlc2V0ACETZGlnZXN0Y29udGV4dF9jbG9uZQAQH19fd2JpbmRnZW5f\
YWRkX3RvX3N0YWNrX3BvaW50ZXIAjwERX193YmluZGdlbl9tYWxsb2MAeRJfX3diaW5kZ2VuX3JlYW\
xsb2MAhgEPX193YmluZGdlbl9mcmVlAIoBCaaAgIAAAQBBAQsUiAGJASiOAX1ffn98hwGFAYABgQGC\
AYMBhAGYAWlolgEK//KIgACNAYZ2AhF/An4jAEHAKGsiBSQAAkACQAJAAkACQAJAAkACQAJAAkACQA\
JAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQCABDhgAAQIDBAUGBwgJCgsMDQ4PEBES\
ExQVFhcAC0HQARAZIgZFDRggBUHQE2pBOGogAkE4aikDADcDACAFQdATakEwaiACQTBqKQMANwMAIA\
VB0BNqQShqIAJBKGopAwA3AwAgBUHQE2pBIGogAkEgaikDADcDACAFQdATakEYaiACQRhqKQMANwMA\
IAVB0BNqQRBqIAJBEGopAwA3AwAgBUHQE2pBCGogAkEIaikDADcDACAFIAIpAwA3A9ATIAIpA0AhFi\
AFQdATakHIAGogAkHIAGoQYiAFIBY3A5AUIAYgBUHQE2pB0AEQlAEaDBcLQdABEBkiBkUNFyAFQdAT\
akE4aiACQThqKQMANwMAIAVB0BNqQTBqIAJBMGopAwA3AwAgBUHQE2pBKGogAkEoaikDADcDACAFQd\
ATakEgaiACQSBqKQMANwMAIAVB0BNqQRhqIAJBGGopAwA3AwAgBUHQE2pBEGogAkEQaikDADcDACAF\
QdATakEIaiACQQhqKQMANwMAIAUgAikDADcD0BMgAikDQCEWIAVB0BNqQcgAaiACQcgAahBiIAUgFj\
cDkBQgBiAFQdATakHQARCUARoMFgtB0AEQGSIGRQ0WIAVB0BNqQThqIAJBOGopAwA3AwAgBUHQE2pB\
MGogAkEwaikDADcDACAFQdATakEoaiACQShqKQMANwMAIAVB0BNqQSBqIAJBIGopAwA3AwAgBUHQE2\
pBGGogAkEYaikDADcDACAFQdATakEQaiACQRBqKQMANwMAIAVB0BNqQQhqIAJBCGopAwA3AwAgBSAC\
KQMANwPQEyACKQNAIRYgBUHQE2pByABqIAJByABqEGIgBSAWNwOQFCAGIAVB0BNqQdABEJQBGgwVC0\
HwABAZIgZFDRUgBUHQE2pBIGogAkEgaikDADcDACAFQdATakEYaiACQRhqKQMANwMAIAVB0BNqQRBq\
IAJBEGopAwA3AwAgBSACKQMINwPYEyACKQMAIRYgBUHQE2pBKGogAkEoahBRIAUgFjcD0BMgBiAFQd\
ATakHwABCUARoMFAtB+A4QGSIGRQ0UIAVB0BNqQYgBaiACQYgBaikDADcDACAFQdATakGAAWogAkGA\
AWopAwA3AwAgBUHQE2pB+ABqIAJB+ABqKQMANwMAIAVB0BNqQRBqIAJBEGopAwA3AwAgBUHQE2pBGG\
ogAkEYaikDADcDACAFQdATakEgaiACQSBqKQMANwMAIAVB0BNqQTBqIAJBMGopAwA3AwAgBUHQE2pB\
OGogAkE4aikDADcDACAFQdATakHAAGogAkHAAGopAwA3AwAgBUHQE2pByABqIAJByABqKQMANwMAIA\
VB0BNqQdAAaiACQdAAaikDADcDACAFQdATakHYAGogAkHYAGopAwA3AwAgBUHQE2pB4ABqIAJB4ABq\
KQMANwMAIAUgAikDcDcDwBQgBSACKQMINwPYEyAFIAIpAyg3A/gTIAIpAwAhFkEAIQcgBUEANgLgFC\
ACKAKQASIIQf///z9xIglBNyAJQTdJGyEKIAJBlAFqIgkgCEEFdCILaiEMIAVBxCJqIQ0gAi0AaiEO\
IAItAGkhDyACLQBoIRACQANAIAsgB0YNASAFQdATaiAHakGUAWoiAiAJKQAANwAAIAJBGGogCUEYai\
kAADcAACACQRBqIAlBEGopAAA3AAAgAkEIaiAJQQhqKQAANwAAIAlBIGoiCCAMRg0BIAJBIGogCCkA\
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\
GGoiDCAEQdATakEcaikCADcDACAEQfgmakEQaiILIARB0BNqQRRqKQIANwMAIARB+CZqQQhqIg0gBE\
HQE2pBDGopAgA3AwAgBCAEKQLUEzcD+CYgBEHQE2ogBEHQARCUARogBCAEKQOQFCAEQZgVai0AACIC\
rXw3A5AUIARBmBRqIQECQCACQYABRg0AIAEgAmpBAEGAASACaxCTARoLIARBADoAmBUgBEHQE2ogAU\
J/EBIgBEH4DmpBCGoiAiAEQdATakEIaikDADcDACAEQfgOakEQaiIBIARB0BNqQRBqKQMANwMAIARB\
+A5qQRhqIgogBEHQE2pBGGopAwA3AwAgBEH4DmpBIGoiDiAEKQPwEzcDACAEQfgOakEoaiIPIARB0B\
NqQShqKQMANwMAIARB+A5qQTBqIhAgBEHQE2pBMGopAwA3AwAgBEH4DmpBOGoiESAEQdATakE4aikD\
ADcDACAEIAQpA9ATNwP4DiANIAIpAwA3AwAgCyABKQMANwMAIAwgCikDADcDACAHIA4pAwA3AwAgCC\
APKQMANwMAIAMgECkDADcDACAJIBEpAwA3AwAgBCAEKQP4DjcD+CZBwAAQGSICRQ0cIAIgBCkD+CY3\
AAAgAkE4aiAEQfgmakE4aikDADcAACACQTBqIARB+CZqQTBqKQMANwAAIAJBKGogBEH4JmpBKGopAw\
A3AAAgAkEgaiAEQfgmakEgaikDADcAACACQRhqIARB+CZqQRhqKQMANwAAIAJBEGogBEH4JmpBEGop\
AwA3AAAgAkEIaiAEQfgmakEIaikDADcAACAGECJBwAAhBAweCyAFIAZB0AEQlAEiBEH4DmpBDGpCAD\
cCACAEQfgOakEUakIANwIAIARB+A5qQRxqQgA3AgAgBEIANwL8DiAEQQA2AvgOIARB+A5qIARB+A5q\
QQRyQX9zakEkakEHSRogBEEgNgL4DiAEQdATakEQaiIHIARB+A5qQRBqIgIpAwA3AwAgBEHQE2pBCG\
oiDCAEQfgOakEIaiIBKQMANwMAIARB0BNqQRhqIgsgBEH4DmpBGGoiCSkDADcDACAEQdATakEgaiAE\
QfgOakEgaiINKAIANgIAIARB+CZqQQhqIgogBEHQE2pBDGopAgA3AwAgBEH4JmpBEGoiDiAEQdATak\
EUaikCADcDACAEQfgmakEYaiIPIARB0BNqQRxqKQIANwMAIAQgBCkD+A43A9ATIAQgBCkC1BM3A/gm\
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\
AgAgAUGUD2pBADYCACABQgA3AvwOIAFBADYC+A5BBCECIAFB+A5qIAFB+A5qQQRyQX9zakEgaiEEA0\
AgAkF/aiICDQALAkAgBEEHSQ0AQRghAgNAIAJBeGoiAg0ACwtBHCEEIAFBHDYC+A4gAUHQE2pBEGog\
AUH4DmpBEGopAwA3AwAgAUHQE2pBCGogAUH4DmpBCGopAwA3AwAgAUHQE2pBGGogAUH4DmpBGGopAw\
A3AwAgAUH4JmpBCGoiCSABQdwTaikCADcDACABQfgmakEQaiIDIAFB5BNqKQIANwMAIAFB+CZqQRhq\
IgggAUHQE2pBHGooAgA2AgAgASABKQP4DjcD0BMgASABKQLUEzcD+CYgAUHQE2ogAUHgAhCUARogAU\
HQE2ogAUGYFWogAUH4JmoQOEEcEBkiAkUNFyACIAEpA/gmNwAAIAJBGGogCCgCADYAACACQRBqIAMp\
AwA3AAAgAkEIaiAJKQMANwAADBYLIAUgBkHYAhCUASIBQfgOakEMakIANwIAIAFB+A5qQRRqQgA3Ag\
AgAUH4DmpBHGpCADcCACABQgA3AvwOIAFBADYC+A4gAUH4DmogAUH4DmpBBHJBf3NqQSRqQQdJGkEg\
IQQgAUEgNgL4DiABQdATakEQaiABQfgOakEQaikDADcDACABQdATakEIaiABQfgOakEIaikDADcDAC\
ABQdATakEYaiABQfgOakEYaikDADcDACABQdATakEgaiABQfgOakEgaigCADYCACABQfgmakEIaiIJ\
IAFB0BNqQQxqKQIANwMAIAFB+CZqQRBqIgMgAUHQE2pBFGopAgA3AwAgAUH4JmpBGGoiCCABQdATak\
EcaikCADcDACABIAEpA/gONwPQEyABIAEpAtQTNwP4JiABQdATaiABQdgCEJQBGiABQdATaiABQZgV\
aiABQfgmahBBQSAQGSICRQ0WIAIgASkD+CY3AAAgAkEYaiAIKQMANwAAIAJBEGogAykDADcAACACQQ\
hqIAkpAwA3AAAMFQsgBSAGQbgCEJQBIgFB+A5qQQxqQgA3AgAgAUH4DmpBFGpCADcCACABQfgOakEc\
akIANwIAIAFB+A5qQSRqQgA3AgAgAUH4DmpBLGpCADcCACABQgA3AvwOIAFBADYC+A4gAUH4DmogAU\
H4DmpBBHJBf3NqQTRqQQdJGkEwIQQgAUEwNgL4DiABQdATakEQaiABQfgOakEQaikDADcDACABQdAT\
akEIaiABQfgOakEIaikDADcDACABQdATakEYaiABQfgOakEYaikDADcDACABQdATakEgaiABQfgOak\
EgaikDADcDACABQdATakEoaiABQfgOakEoaikDADcDACABQdATakEwaiABQfgOakEwaigCADYCACAB\
QfgmakEIaiIJIAFB0BNqQQxqKQIANwMAIAFB+CZqQRBqIgMgAUHQE2pBFGopAgA3AwAgAUH4JmpBGG\
oiCCABQdATakEcaikCADcDACABQfgmakEgaiIHIAFB0BNqQSRqKQIANwMAIAFB+CZqQShqIgwgAUHQ\
E2pBLGopAgA3AwAgASABKQP4DjcD0BMgASABKQLUEzcD+CYgAUHQE2ogAUG4AhCUARogAUHQE2ogAU\
GYFWogAUH4JmoQSUEwEBkiAkUNFSACIAEpA/gmNwAAIAJBKGogDCkDADcAACACQSBqIAcpAwA3AAAg\
AkEYaiAIKQMANwAAIAJBEGogAykDADcAACACQQhqIAkpAwA3AAAMFAsgBSAGQZgCEJQBIgFB+A5qQQ\
xqQgA3AgAgAUH4DmpBFGpCADcCACABQfgOakEcakIANwIAIAFB+A5qQSRqQgA3AgAgAUH4DmpBLGpC\
ADcCACABQfgOakE0akIANwIAIAFB+A5qQTxqQgA3AgAgAUIANwL8DiABQQA2AvgOIAFB+A5qIAFB+A\
5qQQRyQX9zakHEAGpBB0kaQcAAIQQgAUHAADYC+A4gAUHQE2ogAUH4DmpBxAAQlAEaIAFB+CZqQThq\
IgkgAUHQE2pBPGopAgA3AwAgAUH4JmpBMGoiAyABQdATakE0aikCADcDACABQfgmakEoaiIIIAFB0B\
NqQSxqKQIANwMAIAFB+CZqQSBqIgcgAUHQE2pBJGopAgA3AwAgAUH4JmpBGGoiDCABQdATakEcaikC\
ADcDACABQfgmakEQaiILIAFB0BNqQRRqKQIANwMAIAFB+CZqQQhqIg0gAUHQE2pBDGopAgA3AwAgAS\
ABKQLUEzcD+CYgAUHQE2ogAUGYAhCUARogAUHQE2ogAUGYFWogAUH4JmoQS0HAABAZIgJFDRQgAiAB\
KQP4JjcAACACQThqIAkpAwA3AAAgAkEwaiADKQMANwAAIAJBKGogCCkDADcAACACQSBqIAcpAwA3AA\
AgAkEYaiAMKQMANwAAIAJBEGogCykDADcAACACQQhqIA0pAwA3AAAMEwsgBSAGQeAAEJQBIgFB+A5q\
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\
aiABQfgmahBCQSAQGSICRQ0OIAIgASkD+CY3AAAgAkEYaiAIKQMANwAAIAJBEGogAykDADcAACACQQ\
hqIAkpAwA3AAAMDQsgBSAGQbgCEJQBIgFB+A5qQQxqQgA3AgAgAUH4DmpBFGpCADcCACABQfgOakEc\
akIANwIAIAFB+A5qQSRqQgA3AgAgAUH4DmpBLGpCADcCACABQgA3AvwOIAFBADYC+A4gAUH4DmogAU\
H4DmpBBHJBf3NqQTRqQQdJGkEwIQQgAUEwNgL4DiABQdATakEQaiABQfgOakEQaikDADcDACABQdAT\
akEIaiABQfgOakEIaikDADcDACABQdATakEYaiABQfgOakEYaikDADcDACABQdATakEgaiABQfgOak\
EgaikDADcDACABQdATakEoaiABQfgOakEoaikDADcDACABQdATakEwaiABQfgOakEwaigCADYCACAB\
QfgmakEIaiIJIAFB0BNqQQxqKQIANwMAIAFB+CZqQRBqIgMgAUHQE2pBFGopAgA3AwAgAUH4JmpBGG\
oiCCABQdATakEcaikCADcDACABQfgmakEgaiIHIAFB0BNqQSRqKQIANwMAIAFB+CZqQShqIgwgAUHQ\
E2pBLGopAgA3AwAgASABKQP4DjcD0BMgASABKQLUEzcD+CYgAUHQE2ogAUG4AhCUARogAUHQE2ogAU\
GYFWogAUH4JmoQSkEwEBkiAkUNDSACIAEpA/gmNwAAIAJBKGogDCkDADcAACACQSBqIAcpAwA3AAAg\
AkEYaiAIKQMANwAAIAJBEGogAykDADcAACACQQhqIAkpAwA3AAAMDAsgBSAGQZgCEJQBIgFB+A5qQQ\
xqQgA3AgAgAUH4DmpBFGpCADcCACABQfgOakEcakIANwIAIAFB+A5qQSRqQgA3AgAgAUH4DmpBLGpC\
ADcCACABQfgOakE0akIANwIAIAFB+A5qQTxqQgA3AgAgAUIANwL8DiABQQA2AvgOIAFB+A5qIAFB+A\
5qQQRyQX9zakHEAGpBB0kaQcAAIQQgAUHAADYC+A4gAUHQE2ogAUH4DmpBxAAQlAEaIAFB+CZqQThq\
IgkgAUHQE2pBPGopAgA3AwAgAUH4JmpBMGoiAyABQdATakE0aikCADcDACABQfgmakEoaiIIIAFB0B\
NqQSxqKQIANwMAIAFB+CZqQSBqIgcgAUHQE2pBJGopAgA3AwAgAUH4JmpBGGoiDCABQdATakEcaikC\
ADcDACABQfgmakEQaiILIAFB0BNqQRRqKQIANwMAIAFB+CZqQQhqIg0gAUHQE2pBDGopAgA3AwAgAS\
ABKQLUEzcD+CYgAUHQE2ogAUGYAhCUARogAUHQE2ogAUGYFWogAUH4JmoQTEHAABAZIgJFDQwgAiAB\
KQP4JjcAACACQThqIAkpAwA3AAAgAkEwaiADKQMANwAAIAJBKGogCCkDADcAACACQSBqIAcpAwA3AA\
AgAkEYaiAMKQMANwAAIAJBEGogCykDADcAACACQQhqIA0pAwA3AAAMCwsgBSAGQfAAEJQBIQRBBCEC\
A0AgAkF/aiICDQALAkBBG0EHSQ0AQRghAgNAIAJBeGoiAg0ACwsgBEHQE2ogBEHwABCUARogBEH4Jm\
pBDGpCADcCACAEQfgmakEUakIANwIAIARB+CZqQRxqQgA3AgAgBEIANwL8JiAEQQA2AvgmIARB+CZq\
IARB+CZqQQRyQX9zakEkakEHSRogBEEgNgL4JiAEQfgOakEQaiIBIARB+CZqQRBqKQMANwMAIARB+A\
5qQQhqIgkgBEH4JmpBCGopAwA3AwAgBEH4DmpBGGoiAyAEQfgmakEYaikDADcDACAEQfgOakEgaiAE\
QfgmakEgaigCADYCACAEQcglakEIaiICIARB+A5qQQxqKQIANwMAIARByCVqQRBqIgggBEH4DmpBFG\
opAgA3AwAgBEHIJWpBGGoiByAEQfgOakEcaikCADcDACAEIAQpA/gmNwP4DiAEIAQpAvwONwPIJSAE\
QdATaiAEQfgTaiAEQcglahAnIAMgBygCADYCACABIAgpAwA3AwAgCSACKQMANwMAIAQgBCkDyCU3A/\
gOQRwQGSICRQ0LIAIgBCkD+A43AAAgAkEYaiADKAIANgAAIAJBEGogASkDADcAACACQQhqIAkpAwA3\
AAAgBhAiQRwhBAwNCyAFIAZB8AAQlAEiAUHQE2ogAUHwABCUARogAUH4JmpBDGpCADcCACABQfgmak\
EUakIANwIAIAFB+CZqQRxqQgA3AgAgAUIANwL8JiABQQA2AvgmIAFB+CZqIAFB+CZqQQRyQX9zakEk\
akEHSRpBICEEIAFBIDYC+CYgAUH4DmpBEGoiCSABQfgmakEQaikDADcDACABQfgOakEIaiIDIAFB+C\
ZqQQhqKQMANwMAIAFB+A5qQRhqIgggAUH4JmpBGGopAwA3AwAgAUH4DmpBIGogAUH4JmpBIGooAgA2\
AgAgAUHIJWpBCGoiAiABQfgOakEMaikCADcDACABQcglakEQaiIHIAFB+A5qQRRqKQIANwMAIAFByC\
VqQRhqIgwgAUH4DmpBHGopAgA3AwAgASABKQP4JjcD+A4gASABKQL8DjcDyCUgAUHQE2ogAUH4E2og\
AUHIJWoQJyAIIAwpAwA3AwAgCSAHKQMANwMAIAMgAikDADcDACABIAEpA8glNwP4DkEgEBkiAkUNCi\
ACIAEpA/gONwAAIAJBGGogCCkDADcAACACQRBqIAkpAwA3AAAgAkEIaiADKQMANwAADAkLIAUgBkHY\
ARCUASIBQdATaiABQdgBEJQBGiABQfgmakEMakIANwIAIAFB+CZqQRRqQgA3AgAgAUH4JmpBHGpCAD\
cCACABQfgmakEkakIANwIAIAFB+CZqQSxqQgA3AgAgAUH4JmpBNGpCADcCACABQfgmakE8akIANwIA\
IAFCADcC/CYgAUEANgL4JiABQfgmaiABQfgmakEEckF/c2pBxABqQQdJGiABQcAANgL4JiABQfgOai\
ABQfgmakHEABCUARogAUGAJmogAUH4DmpBPGopAgA3AwBBMCEEIAFByCVqQTBqIAFB+A5qQTRqKQIA\
NwMAIAFByCVqQShqIgIgAUH4DmpBLGopAgA3AwAgAUHIJWpBIGoiCSABQfgOakEkaikCADcDACABQc\
glakEYaiIDIAFB+A5qQRxqKQIANwMAIAFByCVqQRBqIgggAUH4DmpBFGopAgA3AwAgAUHIJWpBCGoi\
ByABQfgOakEMaikCADcDACABIAEpAvwONwPIJSABQdATaiABQaAUaiABQcglahAjIAFB+A5qQShqIg\
wgAikDADcDACABQfgOakEgaiILIAkpAwA3AwAgAUH4DmpBGGoiCSADKQMANwMAIAFB+A5qQRBqIgMg\
CCkDADcDACABQfgOakEIaiIIIAcpAwA3AwAgASABKQPIJTcD+A5BMBAZIgJFDQkgAiABKQP4DjcAAC\
ACQShqIAwpAwA3AAAgAkEgaiALKQMANwAAIAJBGGogCSkDADcAACACQRBqIAMpAwA3AAAgAkEIaiAI\
KQMANwAADAgLIAUgBkHYARCUASIBQdATaiABQdgBEJQBGiABQfgmakEMakIANwIAIAFB+CZqQRRqQg\
A3AgAgAUH4JmpBHGpCADcCACABQfgmakEkakIANwIAIAFB+CZqQSxqQgA3AgAgAUH4JmpBNGpCADcC\
ACABQfgmakE8akIANwIAIAFCADcC/CYgAUEANgL4JiABQfgmaiABQfgmakEEckF/c2pBxABqQQdJGk\
HAACEEIAFBwAA2AvgmIAFB+A5qIAFB+CZqQcQAEJQBGiABQcglakE4aiICIAFB+A5qQTxqKQIANwMA\
IAFByCVqQTBqIgkgAUH4DmpBNGopAgA3AwAgAUHIJWpBKGoiAyABQfgOakEsaikCADcDACABQcglak\
EgaiIIIAFB+A5qQSRqKQIANwMAIAFByCVqQRhqIgcgAUH4DmpBHGopAgA3AwAgAUHIJWpBEGoiDCAB\
QfgOakEUaikCADcDACABQcglakEIaiILIAFB+A5qQQxqKQIANwMAIAEgASkC/A43A8glIAFB0BNqIA\
FBoBRqIAFByCVqECMgAUH4DmpBOGoiDSACKQMANwMAIAFB+A5qQTBqIgogCSkDADcDACABQfgOakEo\
aiIJIAMpAwA3AwAgAUH4DmpBIGoiAyAIKQMANwMAIAFB+A5qQRhqIgggBykDADcDACABQfgOakEQai\
IHIAwpAwA3AwAgAUH4DmpBCGoiDCALKQMANwMAIAEgASkDyCU3A/gOQcAAEBkiAkUNCCACIAEpA/gO\
NwAAIAJBOGogDSkDADcAACACQTBqIAopAwA3AAAgAkEoaiAJKQMANwAAIAJBIGogAykDADcAACACQR\
hqIAgpAwA3AAAgAkEQaiAHKQMANwAAIAJBCGogDCkDADcAAAwHCyAFQfgOaiAGQfgCEJQBGgJAAkAg\
BA0AQQEhAgwBCyAEQX9MDQIgBBAZIgJFDQggAkF8ai0AAEEDcUUNACACQQAgBBCTARoLIAVB0BNqIA\
VB+A5qQfgCEJQBGiAFQcgBaiAFQdATakHIAWoiAUGpARCUASEJIAVB+CZqIAVB+A5qQcgBEJQBGiAF\
QegiaiAJQakBEJQBGiAFIAVB+CZqIAVB6CJqEDYgBUEANgKYJCAFQZgkaiAFQZgkakEEckEAQagBEJ\
MBQX9zakGsAWpBB0kaIAVBqAE2ApgkIAVByCVqIAVBmCRqQawBEJQBGiABIAVByCVqQQRyQagBEJQB\
GiAFQcAWakEAOgAAIAVB0BNqIAVByAEQlAEaIAVB0BNqIAIgBBA8DAYLIAVB+A5qIAZB2AIQlAEaAk\
AgBA0AQQEhAkEAIQQMBAsgBEF/Sg0CCxB2AAsgBUH4DmogBkHYAhCUARpBwAAhBAsgBBAZIgJFDQMg\
AkF8ai0AAEEDcUUNACACQQAgBBCTARoLIAVB0BNqIAVB+A5qQdgCEJQBGiAFQcgBaiAFQdATakHIAW\
oiAUGJARCUASEJIAVB+CZqIAVB+A5qQcgBEJQBGiAFQegiaiAJQYkBEJQBGiAFIAVB+CZqIAVB6CJq\
EEUgBUEANgKYJCAFQZgkaiAFQZgkakEEckEAQYgBEJMBQX9zakGMAWpBB0kaIAVBiAE2ApgkIAVByC\
VqIAVBmCRqQYwBEJQBGiABIAVByCVqQQRyQYgBEJQBGiAFQaAWakEAOgAAIAVB0BNqIAVByAEQlAEa\
IAVB0BNqIAIgBBA9DAELIAUgBkHoABCUASIBQfgOakEMakIANwIAIAFB+A5qQRRqQgA3AgAgAUIANw\
L8DiABQQA2AvgOIAFB+A5qIAFB+A5qQQRyQX9zakEcakEHSRpBGCEEIAFBGDYC+A4gAUHQE2pBEGog\
AUH4DmpBEGopAwA3AwAgAUHQE2pBCGogAUH4DmpBCGopAwA3AwAgAUHQE2pBGGogAUH4DmpBGGooAg\
A2AgAgAUH4JmpBCGoiCSABQdATakEMaikCADcDACABQfgmakEQaiIDIAFB0BNqQRRqKQIANwMAIAEg\
ASkD+A43A9ATIAEgASkC1BM3A/gmIAFB0BNqIAFB6AAQlAEaIAFB0BNqIAFB8BNqIAFB+CZqEDBBGB\
AZIgJFDQEgAiABKQP4JjcAACACQRBqIAMpAwA3AAAgAkEIaiAJKQMANwAACyAGECIMAgsACyAGECJB\
ICEECyAAIAI2AgQgAEEANgIAIABBCGogBDYCAAsgBUHAKGokAAvcWQIBfyJ+IwBBgAFrIgMkACADQQ\
BBgAEQkwEhAyAAKQM4IQQgACkDMCEFIAApAyghBiAAKQMgIQcgACkDGCEIIAApAxAhCSAAKQMIIQog\
ACkDACELAkAgAkUNACABIAJBB3RqIQIDQCADIAEpAAAiDEI4hiAMQiiGQoCAgICAgMD/AIOEIAxCGI\
ZCgICAgIDgP4MgDEIIhkKAgICA8B+DhIQgDEIIiEKAgID4D4MgDEIYiEKAgPwHg4QgDEIoiEKA/gOD\
IAxCOIiEhIQ3AwAgAyABKQAIIgxCOIYgDEIohkKAgICAgIDA/wCDhCAMQhiGQoCAgICA4D+DIAxCCI\
ZCgICAgPAfg4SEIAxCCIhCgICA+A+DIAxCGIhCgID8B4OEIAxCKIhCgP4DgyAMQjiIhISENwMIIAMg\
ASkAECIMQjiGIAxCKIZCgICAgICAwP8Ag4QgDEIYhkKAgICAgOA/gyAMQgiGQoCAgIDwH4OEhCAMQg\
iIQoCAgPgPgyAMQhiIQoCA/AeDhCAMQiiIQoD+A4MgDEI4iISEhDcDECADIAEpABgiDEI4hiAMQiiG\
QoCAgICAgMD/AIOEIAxCGIZCgICAgIDgP4MgDEIIhkKAgICA8B+DhIQgDEIIiEKAgID4D4MgDEIYiE\
KAgPwHg4QgDEIoiEKA/gODIAxCOIiEhIQ3AxggAyABKQAgIgxCOIYgDEIohkKAgICAgIDA/wCDhCAM\
QhiGQoCAgICA4D+DIAxCCIZCgICAgPAfg4SEIAxCCIhCgICA+A+DIAxCGIhCgID8B4OEIAxCKIhCgP\
4DgyAMQjiIhISENwMgIAMgASkAKCIMQjiGIAxCKIZCgICAgICAwP8Ag4QgDEIYhkKAgICAgOA/gyAM\
QgiGQoCAgIDwH4OEhCAMQgiIQoCAgPgPgyAMQhiIQoCA/AeDhCAMQiiIQoD+A4MgDEI4iISEhDcDKC\
ADIAEpAEAiDEI4hiAMQiiGQoCAgICAgMD/AIOEIAxCGIZCgICAgIDgP4MgDEIIhkKAgICA8B+DhIQg\
DEIIiEKAgID4D4MgDEIYiEKAgPwHg4QgDEIoiEKA/gODIAxCOIiEhIQiDTcDQCADIAEpADgiDEI4hi\
AMQiiGQoCAgICAgMD/AIOEIAxCGIZCgICAgIDgP4MgDEIIhkKAgICA8B+DhIQgDEIIiEKAgID4D4Mg\
DEIYiEKAgPwHg4QgDEIoiEKA/gODIAxCOIiEhIQiDjcDOCADIAEpADAiDEI4hiAMQiiGQoCAgICAgM\
D/AIOEIAxCGIZCgICAgIDgP4MgDEIIhkKAgICA8B+DhIQgDEIIiEKAgID4D4MgDEIYiEKAgPwHg4Qg\
DEIoiEKA/gODIAxCOIiEhIQiDzcDMCADKQMAIRAgAykDCCERIAMpAxAhEiADKQMYIRMgAykDICEUIA\
MpAyghFSADIAEpAEgiDEI4hiAMQiiGQoCAgICAgMD/AIOEIAxCGIZCgICAgIDgP4MgDEIIhkKAgICA\
8B+DhIQgDEIIiEKAgID4D4MgDEIYiEKAgPwHg4QgDEIoiEKA/gODIAxCOIiEhIQiFjcDSCADIAEpAF\
AiDEI4hiAMQiiGQoCAgICAgMD/AIOEIAxCGIZCgICAgIDgP4MgDEIIhkKAgICA8B+DhIQgDEIIiEKA\
gID4D4MgDEIYiEKAgPwHg4QgDEIoiEKA/gODIAxCOIiEhIQiFzcDUCADIAEpAFgiDEI4hiAMQiiGQo\
CAgICAgMD/AIOEIAxCGIZCgICAgIDgP4MgDEIIhkKAgICA8B+DhIQgDEIIiEKAgID4D4MgDEIYiEKA\
gPwHg4QgDEIoiEKA/gODIAxCOIiEhIQiGDcDWCADIAEpAGAiDEI4hiAMQiiGQoCAgICAgMD/AIOEIA\
xCGIZCgICAgIDgP4MgDEIIhkKAgICA8B+DhIQgDEIIiEKAgID4D4MgDEIYiEKAgPwHg4QgDEIoiEKA\
/gODIAxCOIiEhIQiGTcDYCADIAEpAGgiDEI4hiAMQiiGQoCAgICAgMD/AIOEIAxCGIZCgICAgIDgP4\
MgDEIIhkKAgICA8B+DhIQgDEIIiEKAgID4D4MgDEIYiEKAgPwHg4QgDEIoiEKA/gODIAxCOIiEhIQi\
GjcDaCADIAEpAHAiDEI4hiAMQiiGQoCAgICAgMD/AIOEIAxCGIZCgICAgIDgP4MgDEIIhkKAgICA8B\
+DhIQgDEIIiEKAgID4D4MgDEIYiEKAgPwHg4QgDEIoiEKA/gODIAxCOIiEhIQiDDcDcCADIAEpAHgi\
G0I4hiAbQiiGQoCAgICAgMD/AIOEIBtCGIZCgICAgIDgP4MgG0IIhkKAgICA8B+DhIQgG0IIiEKAgI\
D4D4MgG0IYiEKAgPwHg4QgG0IoiEKA/gODIBtCOIiEhIQiGzcDeCALQiSJIAtCHomFIAtCGYmFIAog\
CYUgC4MgCiAJg4V8IBAgBCAGIAWFIAeDIAWFfCAHQjKJIAdCLomFIAdCF4mFfHxCotyiuY3zi8XCAH\
wiHHwiHUIkiSAdQh6JhSAdQhmJhSAdIAsgCoWDIAsgCoOFfCAFIBF8IBwgCHwiHiAHIAaFgyAGhXwg\
HkIyiSAeQi6JhSAeQheJhXxCzcu9n5KS0ZvxAHwiH3wiHEIkiSAcQh6JhSAcQhmJhSAcIB0gC4WDIB\
0gC4OFfCAGIBJ8IB8gCXwiICAeIAeFgyAHhXwgIEIyiSAgQi6JhSAgQheJhXxCr/a04v75vuC1f3wi\
IXwiH0IkiSAfQh6JhSAfQhmJhSAfIBwgHYWDIBwgHYOFfCAHIBN8ICEgCnwiIiAgIB6FgyAehXwgIk\
IyiSAiQi6JhSAiQheJhXxCvLenjNj09tppfCIjfCIhQiSJICFCHomFICFCGYmFICEgHyAchYMgHyAc\
g4V8IB4gFHwgIyALfCIjICIgIIWDICCFfCAjQjKJICNCLomFICNCF4mFfEK46qKav8uwqzl8IiR8Ih\
5CJIkgHkIeiYUgHkIZiYUgHiAhIB+FgyAhIB+DhXwgFSAgfCAkIB18IiAgIyAihYMgIoV8ICBCMokg\
IEIuiYUgIEIXiYV8Qpmgl7CbvsT42QB8IiR8Ih1CJIkgHUIeiYUgHUIZiYUgHSAeICGFgyAeICGDhX\
wgDyAifCAkIBx8IiIgICAjhYMgI4V8ICJCMokgIkIuiYUgIkIXiYV8Qpuf5fjK1OCfkn98IiR8IhxC\
JIkgHEIeiYUgHEIZiYUgHCAdIB6FgyAdIB6DhXwgDiAjfCAkIB98IiMgIiAghYMgIIV8ICNCMokgI0\
IuiYUgI0IXiYV8QpiCttPd2peOq398IiR8Ih9CJIkgH0IeiYUgH0IZiYUgHyAcIB2FgyAcIB2DhXwg\
DSAgfCAkICF8IiAgIyAihYMgIoV8ICBCMokgIEIuiYUgIEIXiYV8QsKEjJiK0+qDWHwiJHwiIUIkiS\
AhQh6JhSAhQhmJhSAhIB8gHIWDIB8gHIOFfCAWICJ8ICQgHnwiIiAgICOFgyAjhXwgIkIyiSAiQi6J\
hSAiQheJhXxCvt/Bq5Tg1sESfCIkfCIeQiSJIB5CHomFIB5CGYmFIB4gISAfhYMgISAfg4V8IBcgI3\
wgJCAdfCIjICIgIIWDICCFfCAjQjKJICNCLomFICNCF4mFfEKM5ZL35LfhmCR8IiR8Ih1CJIkgHUIe\
iYUgHUIZiYUgHSAeICGFgyAeICGDhXwgGCAgfCAkIBx8IiAgIyAihYMgIoV8ICBCMokgIEIuiYUgIE\
IXiYV8QuLp/q+9uJ+G1QB8IiR8IhxCJIkgHEIeiYUgHEIZiYUgHCAdIB6FgyAdIB6DhXwgGSAifCAk\
IB98IiIgICAjhYMgI4V8ICJCMokgIkIuiYUgIkIXiYV8Qu+S7pPPrpff8gB8IiR8Ih9CJIkgH0IeiY\
UgH0IZiYUgHyAcIB2FgyAcIB2DhXwgGiAjfCAkICF8IiMgIiAghYMgIIV8ICNCMokgI0IuiYUgI0IX\
iYV8QrGt2tjjv6zvgH98IiR8IiFCJIkgIUIeiYUgIUIZiYUgISAfIByFgyAfIByDhXwgDCAgfCAkIB\
58IiQgIyAihYMgIoV8ICRCMokgJEIuiYUgJEIXiYV8QrWknK7y1IHum398IiB8Ih5CJIkgHkIeiYUg\
HkIZiYUgHiAhIB+FgyAhIB+DhXwgGyAifCAgIB18IiUgJCAjhYMgI4V8ICVCMokgJUIuiYUgJUIXiY\
V8QpTNpPvMrvzNQXwiInwiHUIkiSAdQh6JhSAdQhmJhSAdIB4gIYWDIB4gIYOFfCAQIBFCP4kgEUI4\
iYUgEUIHiIV8IBZ8IAxCLYkgDEIDiYUgDEIGiIV8IiAgI3wgIiAcfCIQICUgJIWDICSFfCAQQjKJIB\
BCLomFIBBCF4mFfELSlcX3mbjazWR8IiN8IhxCJIkgHEIeiYUgHEIZiYUgHCAdIB6FgyAdIB6DhXwg\
ESASQj+JIBJCOImFIBJCB4iFfCAXfCAbQi2JIBtCA4mFIBtCBoiFfCIiICR8ICMgH3wiESAQICWFgy\
AlhXwgEUIyiSARQi6JhSARQheJhXxC48u8wuPwkd9vfCIkfCIfQiSJIB9CHomFIB9CGYmFIB8gHCAd\
hYMgHCAdg4V8IBIgE0I/iSATQjiJhSATQgeIhXwgGHwgIEItiSAgQgOJhSAgQgaIhXwiIyAlfCAkIC\
F8IhIgESAQhYMgEIV8IBJCMokgEkIuiYUgEkIXiYV8QrWrs9zouOfgD3wiJXwiIUIkiSAhQh6JhSAh\
QhmJhSAhIB8gHIWDIB8gHIOFfCATIBRCP4kgFEI4iYUgFEIHiIV8IBl8ICJCLYkgIkIDiYUgIkIGiI\
V8IiQgEHwgJSAefCITIBIgEYWDIBGFfCATQjKJIBNCLomFIBNCF4mFfELluLK9x7mohiR8IhB8Ih5C\
JIkgHkIeiYUgHkIZiYUgHiAhIB+FgyAhIB+DhXwgFCAVQj+JIBVCOImFIBVCB4iFfCAafCAjQi2JIC\
NCA4mFICNCBoiFfCIlIBF8IBAgHXwiFCATIBKFgyAShXwgFEIyiSAUQi6JhSAUQheJhXxC9YSsyfWN\
y/QtfCIRfCIdQiSJIB1CHomFIB1CGYmFIB0gHiAhhYMgHiAhg4V8IBUgD0I/iSAPQjiJhSAPQgeIhX\
wgDHwgJEItiSAkQgOJhSAkQgaIhXwiECASfCARIBx8IhUgFCAThYMgE4V8IBVCMokgFUIuiYUgFUIX\
iYV8QoPJm/WmlaG6ygB8IhJ8IhxCJIkgHEIeiYUgHEIZiYUgHCAdIB6FgyAdIB6DhXwgDkI/iSAOQj\
iJhSAOQgeIhSAPfCAbfCAlQi2JICVCA4mFICVCBoiFfCIRIBN8IBIgH3wiDyAVIBSFgyAUhXwgD0Iy\
iSAPQi6JhSAPQheJhXxC1PeH6su7qtjcAHwiE3wiH0IkiSAfQh6JhSAfQhmJhSAfIBwgHYWDIBwgHY\
OFfCANQj+JIA1COImFIA1CB4iFIA58ICB8IBBCLYkgEEIDiYUgEEIGiIV8IhIgFHwgEyAhfCIOIA8g\
FYWDIBWFfCAOQjKJIA5CLomFIA5CF4mFfEK1p8WYqJvi/PYAfCIUfCIhQiSJICFCHomFICFCGYmFIC\
EgHyAchYMgHyAcg4V8IBZCP4kgFkI4iYUgFkIHiIUgDXwgInwgEUItiSARQgOJhSARQgaIhXwiEyAV\
fCAUIB58Ig0gDiAPhYMgD4V8IA1CMokgDUIuiYUgDUIXiYV8Qqu/m/OuqpSfmH98IhV8Ih5CJIkgHk\
IeiYUgHkIZiYUgHiAhIB+FgyAhIB+DhXwgF0I/iSAXQjiJhSAXQgeIhSAWfCAjfCASQi2JIBJCA4mF\
IBJCBoiFfCIUIA98IBUgHXwiFiANIA6FgyAOhXwgFkIyiSAWQi6JhSAWQheJhXxCkOTQ7dLN8Ziof3\
wiD3wiHUIkiSAdQh6JhSAdQhmJhSAdIB4gIYWDIB4gIYOFfCAYQj+JIBhCOImFIBhCB4iFIBd8ICR8\
IBNCLYkgE0IDiYUgE0IGiIV8IhUgDnwgDyAcfCIXIBYgDYWDIA2FfCAXQjKJIBdCLomFIBdCF4mFfE\
K/wuzHifnJgbB/fCIOfCIcQiSJIBxCHomFIBxCGYmFIBwgHSAehYMgHSAeg4V8IBlCP4kgGUI4iYUg\
GUIHiIUgGHwgJXwgFEItiSAUQgOJhSAUQgaIhXwiDyANfCAOIB98IhggFyAWhYMgFoV8IBhCMokgGE\
IuiYUgGEIXiYV8QuSdvPf7+N+sv398Ig18Ih9CJIkgH0IeiYUgH0IZiYUgHyAcIB2FgyAcIB2DhXwg\
GkI/iSAaQjiJhSAaQgeIhSAZfCAQfCAVQi2JIBVCA4mFIBVCBoiFfCIOIBZ8IA0gIXwiFiAYIBeFgy\
AXhXwgFkIyiSAWQi6JhSAWQheJhXxCwp+i7bP+gvBGfCIZfCIhQiSJICFCHomFICFCGYmFICEgHyAc\
hYMgHyAcg4V8IAxCP4kgDEI4iYUgDEIHiIUgGnwgEXwgD0ItiSAPQgOJhSAPQgaIhXwiDSAXfCAZIB\
58IhcgFiAYhYMgGIV8IBdCMokgF0IuiYUgF0IXiYV8QqXOqpj5qOTTVXwiGXwiHkIkiSAeQh6JhSAe\
QhmJhSAeICEgH4WDICEgH4OFfCAbQj+JIBtCOImFIBtCB4iFIAx8IBJ8IA5CLYkgDkIDiYUgDkIGiI\
V8IgwgGHwgGSAdfCIYIBcgFoWDIBaFfCAYQjKJIBhCLomFIBhCF4mFfELvhI6AnuqY5QZ8Ihl8Ih1C\
JIkgHUIeiYUgHUIZiYUgHSAeICGFgyAeICGDhXwgIEI/iSAgQjiJhSAgQgeIhSAbfCATfCANQi2JIA\
1CA4mFIA1CBoiFfCIbIBZ8IBkgHHwiFiAYIBeFgyAXhXwgFkIyiSAWQi6JhSAWQheJhXxC8Ny50PCs\
ypQUfCIZfCIcQiSJIBxCHomFIBxCGYmFIBwgHSAehYMgHSAeg4V8ICJCP4kgIkI4iYUgIkIHiIUgIH\
wgFHwgDEItiSAMQgOJhSAMQgaIhXwiICAXfCAZIB98IhcgFiAYhYMgGIV8IBdCMokgF0IuiYUgF0IX\
iYV8QvzfyLbU0MLbJ3wiGXwiH0IkiSAfQh6JhSAfQhmJhSAfIBwgHYWDIBwgHYOFfCAjQj+JICNCOI\
mFICNCB4iFICJ8IBV8IBtCLYkgG0IDiYUgG0IGiIV8IiIgGHwgGSAhfCIYIBcgFoWDIBaFfCAYQjKJ\
IBhCLomFIBhCF4mFfEKmkpvhhafIjS58Ihl8IiFCJIkgIUIeiYUgIUIZiYUgISAfIByFgyAfIByDhX\
wgJEI/iSAkQjiJhSAkQgeIhSAjfCAPfCAgQi2JICBCA4mFICBCBoiFfCIjIBZ8IBkgHnwiFiAYIBeF\
gyAXhXwgFkIyiSAWQi6JhSAWQheJhXxC7dWQ1sW/m5bNAHwiGXwiHkIkiSAeQh6JhSAeQhmJhSAeIC\
EgH4WDICEgH4OFfCAlQj+JICVCOImFICVCB4iFICR8IA58ICJCLYkgIkIDiYUgIkIGiIV8IiQgF3wg\
GSAdfCIXIBYgGIWDIBiFfCAXQjKJIBdCLomFIBdCF4mFfELf59bsuaKDnNMAfCIZfCIdQiSJIB1CHo\
mFIB1CGYmFIB0gHiAhhYMgHiAhg4V8IBBCP4kgEEI4iYUgEEIHiIUgJXwgDXwgI0ItiSAjQgOJhSAj\
QgaIhXwiJSAYfCAZIBx8IhggFyAWhYMgFoV8IBhCMokgGEIuiYUgGEIXiYV8Qt7Hvd3I6pyF5QB8Ih\
l8IhxCJIkgHEIeiYUgHEIZiYUgHCAdIB6FgyAdIB6DhXwgEUI/iSARQjiJhSARQgeIhSAQfCAMfCAk\
Qi2JICRCA4mFICRCBoiFfCIQIBZ8IBkgH3wiFiAYIBeFgyAXhXwgFkIyiSAWQi6JhSAWQheJhXxCqO\
Xe47PXgrX2AHwiGXwiH0IkiSAfQh6JhSAfQhmJhSAfIBwgHYWDIBwgHYOFfCASQj+JIBJCOImFIBJC\
B4iFIBF8IBt8ICVCLYkgJUIDiYUgJUIGiIV8IhEgF3wgGSAhfCIXIBYgGIWDIBiFfCAXQjKJIBdCLo\
mFIBdCF4mFfELm3ba/5KWy4YF/fCIZfCIhQiSJICFCHomFICFCGYmFICEgHyAchYMgHyAcg4V8IBNC\
P4kgE0I4iYUgE0IHiIUgEnwgIHwgEEItiSAQQgOJhSAQQgaIhXwiEiAYfCAZIB58IhggFyAWhYMgFo\
V8IBhCMokgGEIuiYUgGEIXiYV8QrvqiKTRkIu5kn98Ihl8Ih5CJIkgHkIeiYUgHkIZiYUgHiAhIB+F\
gyAhIB+DhXwgFEI/iSAUQjiJhSAUQgeIhSATfCAifCARQi2JIBFCA4mFIBFCBoiFfCITIBZ8IBkgHX\
wiFiAYIBeFgyAXhXwgFkIyiSAWQi6JhSAWQheJhXxC5IbE55SU+t+if3wiGXwiHUIkiSAdQh6JhSAd\
QhmJhSAdIB4gIYWDIB4gIYOFfCAVQj+JIBVCOImFIBVCB4iFIBR8ICN8IBJCLYkgEkIDiYUgEkIGiI\
V8IhQgF3wgGSAcfCIXIBYgGIWDIBiFfCAXQjKJIBdCLomFIBdCF4mFfEKB4Ijiu8mZjah/fCIZfCIc\
QiSJIBxCHomFIBxCGYmFIBwgHSAehYMgHSAeg4V8IA9CP4kgD0I4iYUgD0IHiIUgFXwgJHwgE0ItiS\
ATQgOJhSATQgaIhXwiFSAYfCAZIB98IhggFyAWhYMgFoV8IBhCMokgGEIuiYUgGEIXiYV8QpGv4oeN\
7uKlQnwiGXwiH0IkiSAfQh6JhSAfQhmJhSAfIBwgHYWDIBwgHYOFfCAOQj+JIA5COImFIA5CB4iFIA\
98ICV8IBRCLYkgFEIDiYUgFEIGiIV8Ig8gFnwgGSAhfCIWIBggF4WDIBeFfCAWQjKJIBZCLomFIBZC\
F4mFfEKw/NKysLSUtkd8Ihl8IiFCJIkgIUIeiYUgIUIZiYUgISAfIByFgyAfIByDhXwgDUI/iSANQj\
iJhSANQgeIhSAOfCAQfCAVQi2JIBVCA4mFIBVCBoiFfCIOIBd8IBkgHnwiFyAWIBiFgyAYhXwgF0Iy\
iSAXQi6JhSAXQheJhXxCmKS9t52DuslRfCIZfCIeQiSJIB5CHomFIB5CGYmFIB4gISAfhYMgISAfg4\
V8IAxCP4kgDEI4iYUgDEIHiIUgDXwgEXwgD0ItiSAPQgOJhSAPQgaIhXwiDSAYfCAZIB18IhggFyAW\
hYMgFoV8IBhCMokgGEIuiYUgGEIXiYV8QpDSlqvFxMHMVnwiGXwiHUIkiSAdQh6JhSAdQhmJhSAdIB\
4gIYWDIB4gIYOFfCAbQj+JIBtCOImFIBtCB4iFIAx8IBJ8IA5CLYkgDkIDiYUgDkIGiIV8IgwgFnwg\
GSAcfCIWIBggF4WDIBeFfCAWQjKJIBZCLomFIBZCF4mFfEKqwMS71bCNh3R8Ihl8IhxCJIkgHEIeiY\
UgHEIZiYUgHCAdIB6FgyAdIB6DhXwgIEI/iSAgQjiJhSAgQgeIhSAbfCATfCANQi2JIA1CA4mFIA1C\
BoiFfCIbIBd8IBkgH3wiFyAWIBiFgyAYhXwgF0IyiSAXQi6JhSAXQheJhXxCuKPvlYOOqLUQfCIZfC\
IfQiSJIB9CHomFIB9CGYmFIB8gHCAdhYMgHCAdg4V8ICJCP4kgIkI4iYUgIkIHiIUgIHwgFHwgDEIt\
iSAMQgOJhSAMQgaIhXwiICAYfCAZICF8IhggFyAWhYMgFoV8IBhCMokgGEIuiYUgGEIXiYV8Qsihy8\
brorDSGXwiGXwiIUIkiSAhQh6JhSAhQhmJhSAhIB8gHIWDIB8gHIOFfCAjQj+JICNCOImFICNCB4iF\
ICJ8IBV8IBtCLYkgG0IDiYUgG0IGiIV8IiIgFnwgGSAefCIWIBggF4WDIBeFfCAWQjKJIBZCLomFIB\
ZCF4mFfELT1oaKhYHbmx58Ihl8Ih5CJIkgHkIeiYUgHkIZiYUgHiAhIB+FgyAhIB+DhXwgJEI/iSAk\
QjiJhSAkQgeIhSAjfCAPfCAgQi2JICBCA4mFICBCBoiFfCIjIBd8IBkgHXwiFyAWIBiFgyAYhXwgF0\
IyiSAXQi6JhSAXQheJhXxCmde7/M3pnaQnfCIZfCIdQiSJIB1CHomFIB1CGYmFIB0gHiAhhYMgHiAh\
g4V8ICVCP4kgJUI4iYUgJUIHiIUgJHwgDnwgIkItiSAiQgOJhSAiQgaIhXwiJCAYfCAZIBx8IhggFy\
AWhYMgFoV8IBhCMokgGEIuiYUgGEIXiYV8QqiR7Yzelq/YNHwiGXwiHEIkiSAcQh6JhSAcQhmJhSAc\
IB0gHoWDIB0gHoOFfCAQQj+JIBBCOImFIBBCB4iFICV8IA18ICNCLYkgI0IDiYUgI0IGiIV8IiUgFn\
wgGSAffCIWIBggF4WDIBeFfCAWQjKJIBZCLomFIBZCF4mFfELjtKWuvJaDjjl8Ihl8Ih9CJIkgH0Ie\
iYUgH0IZiYUgHyAcIB2FgyAcIB2DhXwgEUI/iSARQjiJhSARQgeIhSAQfCAMfCAkQi2JICRCA4mFIC\
RCBoiFfCIQIBd8IBkgIXwiFyAWIBiFgyAYhXwgF0IyiSAXQi6JhSAXQheJhXxCy5WGmq7JquzOAHwi\
GXwiIUIkiSAhQh6JhSAhQhmJhSAhIB8gHIWDIB8gHIOFfCASQj+JIBJCOImFIBJCB4iFIBF8IBt8IC\
VCLYkgJUIDiYUgJUIGiIV8IhEgGHwgGSAefCIYIBcgFoWDIBaFfCAYQjKJIBhCLomFIBhCF4mFfELz\
xo+798myztsAfCIZfCIeQiSJIB5CHomFIB5CGYmFIB4gISAfhYMgISAfg4V8IBNCP4kgE0I4iYUgE0\
IHiIUgEnwgIHwgEEItiSAQQgOJhSAQQgaIhXwiEiAWfCAZIB18IhYgGCAXhYMgF4V8IBZCMokgFkIu\
iYUgFkIXiYV8QqPxyrW9/puX6AB8Ihl8Ih1CJIkgHUIeiYUgHUIZiYUgHSAeICGFgyAeICGDhXwgFE\
I/iSAUQjiJhSAUQgeIhSATfCAifCARQi2JIBFCA4mFIBFCBoiFfCITIBd8IBkgHHwiFyAWIBiFgyAY\
hXwgF0IyiSAXQi6JhSAXQheJhXxC/OW+7+Xd4Mf0AHwiGXwiHEIkiSAcQh6JhSAcQhmJhSAcIB0gHo\
WDIB0gHoOFfCAVQj+JIBVCOImFIBVCB4iFIBR8ICN8IBJCLYkgEkIDiYUgEkIGiIV8IhQgGHwgGSAf\
fCIYIBcgFoWDIBaFfCAYQjKJIBhCLomFIBhCF4mFfELg3tyY9O3Y0vgAfCIZfCIfQiSJIB9CHomFIB\
9CGYmFIB8gHCAdhYMgHCAdg4V8IA9CP4kgD0I4iYUgD0IHiIUgFXwgJHwgE0ItiSATQgOJhSATQgaI\
hXwiFSAWfCAZICF8IhYgGCAXhYMgF4V8IBZCMokgFkIuiYUgFkIXiYV8QvLWwo/Kgp7khH98Ihl8Ii\
FCJIkgIUIeiYUgIUIZiYUgISAfIByFgyAfIByDhXwgDkI/iSAOQjiJhSAOQgeIhSAPfCAlfCAUQi2J\
IBRCA4mFIBRCBoiFfCIPIBd8IBkgHnwiFyAWIBiFgyAYhXwgF0IyiSAXQi6JhSAXQheJhXxC7POQ04\
HBwOOMf3wiGXwiHkIkiSAeQh6JhSAeQhmJhSAeICEgH4WDICEgH4OFfCANQj+JIA1COImFIA1CB4iF\
IA58IBB8IBVCLYkgFUIDiYUgFUIGiIV8Ig4gGHwgGSAdfCIYIBcgFoWDIBaFfCAYQjKJIBhCLomFIB\
hCF4mFfEKovIybov+/35B/fCIZfCIdQiSJIB1CHomFIB1CGYmFIB0gHiAhhYMgHiAhg4V8IAxCP4kg\
DEI4iYUgDEIHiIUgDXwgEXwgD0ItiSAPQgOJhSAPQgaIhXwiDSAWfCAZIBx8IhYgGCAXhYMgF4V8IB\
ZCMokgFkIuiYUgFkIXiYV8Qun7ivS9nZuopH98Ihl8IhxCJIkgHEIeiYUgHEIZiYUgHCAdIB6FgyAd\
IB6DhXwgG0I/iSAbQjiJhSAbQgeIhSAMfCASfCAOQi2JIA5CA4mFIA5CBoiFfCIMIBd8IBkgH3wiFy\
AWIBiFgyAYhXwgF0IyiSAXQi6JhSAXQheJhXxClfKZlvv+6Py+f3wiGXwiH0IkiSAfQh6JhSAfQhmJ\
hSAfIBwgHYWDIBwgHYOFfCAgQj+JICBCOImFICBCB4iFIBt8IBN8IA1CLYkgDUIDiYUgDUIGiIV8Ih\
sgGHwgGSAhfCIYIBcgFoWDIBaFfCAYQjKJIBhCLomFIBhCF4mFfEKrpsmbrp7euEZ8Ihl8IiFCJIkg\
IUIeiYUgIUIZiYUgISAfIByFgyAfIByDhXwgIkI/iSAiQjiJhSAiQgeIhSAgfCAUfCAMQi2JIAxCA4\
mFIAxCBoiFfCIgIBZ8IBkgHnwiFiAYIBeFgyAXhXwgFkIyiSAWQi6JhSAWQheJhXxCnMOZ0e7Zz5NK\
fCIafCIeQiSJIB5CHomFIB5CGYmFIB4gISAfhYMgISAfg4V8ICNCP4kgI0I4iYUgI0IHiIUgInwgFX\
wgG0ItiSAbQgOJhSAbQgaIhXwiGSAXfCAaIB18IiIgFiAYhYMgGIV8ICJCMokgIkIuiYUgIkIXiYV8\
QoeEg47ymK7DUXwiGnwiHUIkiSAdQh6JhSAdQhmJhSAdIB4gIYWDIB4gIYOFfCAkQj+JICRCOImFIC\
RCB4iFICN8IA98ICBCLYkgIEIDiYUgIEIGiIV8IhcgGHwgGiAcfCIjICIgFoWDIBaFfCAjQjKJICNC\
LomFICNCF4mFfEKe1oPv7Lqf7Wp8Ihp8IhxCJIkgHEIeiYUgHEIZiYUgHCAdIB6FgyAdIB6DhXwgJU\
I/iSAlQjiJhSAlQgeIhSAkfCAOfCAZQi2JIBlCA4mFIBlCBoiFfCIYIBZ8IBogH3wiJCAjICKFgyAi\
hXwgJEIyiSAkQi6JhSAkQheJhXxC+KK78/7v0751fCIWfCIfQiSJIB9CHomFIB9CGYmFIB8gHCAdhY\
MgHCAdg4V8IBBCP4kgEEI4iYUgEEIHiIUgJXwgDXwgF0ItiSAXQgOJhSAXQgaIhXwiJSAifCAWICF8\
IiIgJCAjhYMgI4V8ICJCMokgIkIuiYUgIkIXiYV8Qrrf3ZCn9Zn4BnwiFnwiIUIkiSAhQh6JhSAhQh\
mJhSAhIB8gHIWDIB8gHIOFfCARQj+JIBFCOImFIBFCB4iFIBB8IAx8IBhCLYkgGEIDiYUgGEIGiIV8\
IhAgI3wgFiAefCIjICIgJIWDICSFfCAjQjKJICNCLomFICNCF4mFfEKmsaKW2rjfsQp8IhZ8Ih5CJI\
kgHkIeiYUgHkIZiYUgHiAhIB+FgyAhIB+DhXwgEkI/iSASQjiJhSASQgeIhSARfCAbfCAlQi2JICVC\
A4mFICVCBoiFfCIRICR8IBYgHXwiJCAjICKFgyAihXwgJEIyiSAkQi6JhSAkQheJhXxCrpvk98uA5p\
8RfCIWfCIdQiSJIB1CHomFIB1CGYmFIB0gHiAhhYMgHiAhg4V8IBNCP4kgE0I4iYUgE0IHiIUgEnwg\
IHwgEEItiSAQQgOJhSAQQgaIhXwiEiAifCAWIBx8IiIgJCAjhYMgI4V8ICJCMokgIkIuiYUgIkIXiY\
V8QpuO8ZjR5sK4G3wiFnwiHEIkiSAcQh6JhSAcQhmJhSAcIB0gHoWDIB0gHoOFfCAUQj+JIBRCOImF\
IBRCB4iFIBN8IBl8IBFCLYkgEUIDiYUgEUIGiIV8IhMgI3wgFiAffCIjICIgJIWDICSFfCAjQjKJIC\
NCLomFICNCF4mFfEKE+5GY0v7d7Sh8IhZ8Ih9CJIkgH0IeiYUgH0IZiYUgHyAcIB2FgyAcIB2DhXwg\
FUI/iSAVQjiJhSAVQgeIhSAUfCAXfCASQi2JIBJCA4mFIBJCBoiFfCIUICR8IBYgIXwiJCAjICKFgy\
AihXwgJEIyiSAkQi6JhSAkQheJhXxCk8mchrTvquUyfCIWfCIhQiSJICFCHomFICFCGYmFICEgHyAc\
hYMgHyAcg4V8IA9CP4kgD0I4iYUgD0IHiIUgFXwgGHwgE0ItiSATQgOJhSATQgaIhXwiFSAifCAWIB\
58IiIgJCAjhYMgI4V8ICJCMokgIkIuiYUgIkIXiYV8Qrz9pq6hwa/PPHwiFnwiHkIkiSAeQh6JhSAe\
QhmJhSAeICEgH4WDICEgH4OFfCAOQj+JIA5COImFIA5CB4iFIA98ICV8IBRCLYkgFEIDiYUgFEIGiI\
V8IiUgI3wgFiAdfCIjICIgJIWDICSFfCAjQjKJICNCLomFICNCF4mFfELMmsDgyfjZjsMAfCIUfCId\
QiSJIB1CHomFIB1CGYmFIB0gHiAhhYMgHiAhg4V8IA1CP4kgDUI4iYUgDUIHiIUgDnwgEHwgFUItiS\
AVQgOJhSAVQgaIhXwiECAkfCAUIBx8IiQgIyAihYMgIoV8ICRCMokgJEIuiYUgJEIXiYV8QraF+dns\
l/XizAB8IhR8IhxCJIkgHEIeiYUgHEIZiYUgHCAdIB6FgyAdIB6DhXwgDEI/iSAMQjiJhSAMQgeIhS\
ANfCARfCAlQi2JICVCA4mFICVCBoiFfCIlICJ8IBQgH3wiHyAkICOFgyAjhXwgH0IyiSAfQi6JhSAf\
QheJhXxCqvyV48+zyr/ZAHwiEXwiIkIkiSAiQh6JhSAiQhmJhSAiIBwgHYWDIBwgHYOFfCAMIBtCP4\
kgG0I4iYUgG0IHiIV8IBJ8IBBCLYkgEEIDiYUgEEIGiIV8ICN8IBEgIXwiDCAfICSFgyAkhXwgDEIy\
iSAMQi6JhSAMQheJhXxC7PXb1rP12+XfAHwiI3wiISAiIByFgyAiIByDhSALfCAhQiSJICFCHomFIC\
FCGYmFfCAbICBCP4kgIEI4iYUgIEIHiIV8IBN8ICVCLYkgJUIDiYUgJUIGiIV8ICR8ICMgHnwiGyAM\
IB+FgyAfhXwgG0IyiSAbQi6JhSAbQheJhXxCl7Cd0sSxhqLsAHwiHnwhCyAhIAp8IQogHSAHfCAefC\
EHICIgCXwhCSAbIAZ8IQYgHCAIfCEIIAwgBXwhBSAfIAR8IQQgAUGAAWoiASACRw0ACwsgACAENwM4\
IAAgBTcDMCAAIAY3AyggACAHNwMgIAAgCDcDGCAAIAk3AxAgACAKNwMIIAAgCzcDACADQYABaiQAC9\
xbAgp/BX4jAEGgCWsiBSQAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJA\
AkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAIANBAUcNAEHAACEDAkACQAJAAkACQA\
JAAkACQAJAAkACQAJAAkACQAJAAkAgAQ4YDwABAhYDBAUPBgYHBwgJCg8LDA0PKi4ODwtBICEDDA4L\
QTAhAwwNC0EgIQMMDAtBHCEDDAsLQSAhAwwKC0EwIQMMCQtBECEDDAgLQRQhAwwHC0EcIQMMBgtBIC\
EDDAULQTAhAwwEC0EcIQMMAwtBICEDDAILQTAhAwwBC0EYIQMLIAMgBEYNASAAQa2BwAA2AgQgAEEI\
akE5NgIAQQEhAgwmCyABDhgBAgMEBgkKCwwNDg8QERITFBUWFxgaHiEBCyABDhgAAQIDBAgJCgsMDQ\
4PEBESExQVFhcYHCAACyAFQdgHakEMakIANwIAIAVB2AdqQRRqQgA3AgAgBUHYB2pBHGpCADcCACAF\
QdgHakEkakIANwIAIAVB2AdqQSxqQgA3AgAgBUHYB2pBNGpCADcCACAFQdgHakE8akIANwIAIAVCAD\
cC3AcgBUEANgLYByAFQdgHaiAFQdgHakEEckF/c2pBxABqQQdJGiAFQcAANgLYByAFQYACaiAFQdgH\
akHEABCUARogBUGoBmpBOGoiAyAFQYACakE8aikCADcDACAFQagGakEwaiIGIAVBgAJqQTRqKQIANw\
MAIAVBqAZqQShqIgcgBUGAAmpBLGopAgA3AwAgBUGoBmpBIGoiCCAFQYACakEkaikCADcDACAFQagG\
akEYaiIJIAVBgAJqQRxqKQIANwMAIAVBqAZqQRBqIgogBUGAAmpBFGopAgA3AwAgBUGoBmpBCGoiCy\
AFQYACakEMaikCADcDACAFIAUpAoQCNwOoBiACIAIpA0AgAkHIAWotAAAiAa18NwNAIAJByABqIQQC\
QCABQYABRg0AIAQgAWpBAEGAASABaxCTARoLIAJBADoAyAEgAiAEQn8QEiAFQYACakEIaiIBIAJBCG\
opAwAiDzcDACAFQYACakEQaiACQRBqKQMAIhA3AwAgBUGAAmpBGGogAkEYaikDACIRNwMAIAVBgAJq\
QSBqIAIpAyAiEjcDACAFQYACakEoaiACQShqKQMAIhM3AwAgCyAPNwMAIAogEDcDACAJIBE3AwAgCC\
ASNwMAIAcgEzcDACAGIAJBMGopAwA3AwAgAyACQThqKQMANwMAIAUgAikDACIPNwOAAiAFIA83A6gG\
IAFBwAAQcyACIAFByAAQlAFBADoAyAFBwAAQGSIBRQ0hIAEgBSkDqAY3AAAgAUE4aiAFQagGakE4ai\
kDADcAACABQTBqIAVBqAZqQTBqKQMANwAAIAFBKGogBUGoBmpBKGopAwA3AAAgAUEgaiAFQagGakEg\
aikDADcAACABQRhqIAVBqAZqQRhqKQMANwAAIAFBEGogBUGoBmpBEGopAwA3AAAgAUEIaiAFQagGak\
EIaikDADcAAEHAACEEDCALIAVB2AdqQQxqQgA3AgAgBUHYB2pBFGpCADcCACAFQdgHakEcakIANwIA\
IAVCADcC3AcgBUEANgLYByAFQdgHaiAFQdgHakEEckF/c2pBJGpBB0kaIAVBIDYC2AcgBUGAAmpBEG\
oiBiAFQdgHakEQaikDADcDACAFQYACakEIaiIBIAVB2AdqQQhqKQMANwMAIAVBgAJqQRhqIgcgBUHY\
B2pBGGopAwA3AwAgBUGAAmpBIGoiCCAFQdgHakEgaigCADYCACAFQagGakEIaiIJIAVBgAJqQQxqKQ\
IANwMAIAVBqAZqQRBqIgogBUGAAmpBFGopAgA3AwAgBUGoBmpBGGoiCyAFQYACakEcaikCADcDACAF\
IAUpA9gHNwOAAiAFIAUpAoQCNwOoBiACIAIpA0AgAkHIAWotAAAiBK18NwNAIAJByABqIQMCQCAEQY\
ABRg0AIAMgBGpBAEGAASAEaxCTARoLIAJBADoAyAEgAiADQn8QEiABIAJBCGopAwAiDzcDACAGIAJB\
EGopAwAiEDcDACAHIAJBGGopAwAiETcDACAIIAIpAyA3AwAgBUGAAmpBKGogAkEoaikDADcDACAJIA\
83AwAgCiAQNwMAIAsgETcDACAFIAIpAwAiDzcDgAIgBSAPNwOoBiABQSAQcyACIAFByAAQlAFBADoA\
yAFBIBAZIgFFDSAgASAFKQOoBjcAACABQRhqIAVBqAZqQRhqKQMANwAAIAFBEGogBUGoBmpBEGopAw\
A3AAAgAUEIaiAFQagGakEIaikDADcAAEEgIQQMHwsgBUHYB2pBDGpCADcCACAFQdgHakEUakIANwIA\
IAVB2AdqQRxqQgA3AgAgBUHYB2pBJGpCADcCACAFQdgHakEsakIANwIAIAVCADcC3AcgBUEANgLYBy\
AFQdgHaiAFQdgHakEEckF/c2pBNGpBB0kaIAVBMDYC2AcgBUGAAmpBEGoiBiAFQdgHakEQaikDADcD\
ACAFQYACakEIaiIBIAVB2AdqQQhqKQMANwMAIAVBgAJqQRhqIgcgBUHYB2pBGGopAwA3AwAgBUGAAm\
pBIGoiCCAFQdgHakEgaikDADcDACAFQYACakEoaiIJIAVB2AdqQShqKQMANwMAIAVBgAJqQTBqIAVB\
2AdqQTBqKAIANgIAIAVBqAZqQQhqIgogBUGAAmpBDGopAgA3AwAgBUGoBmpBEGoiCyAFQYACakEUai\
kCADcDACAFQagGakEYaiIMIAVBgAJqQRxqKQIANwMAIAVBqAZqQSBqIg0gBUGAAmpBJGopAgA3AwAg\
BUGoBmpBKGoiDiAFQYACakEsaikCADcDACAFIAUpA9gHNwOAAiAFIAUpAoQCNwOoBiACIAIpA0AgAk\
HIAWotAAAiBK18NwNAIAJByABqIQMCQCAEQYABRg0AIAMgBGpBAEGAASAEaxCTARoLIAJBADoAyAEg\
AiADQn8QEiABIAJBCGopAwAiDzcDACAGIAJBEGopAwAiEDcDACAHIAJBGGopAwAiETcDACAIIAIpAy\
AiEjcDACAJIAJBKGopAwAiEzcDACAKIA83AwAgCyAQNwMAIAwgETcDACANIBI3AwAgDiATNwMAIAUg\
AikDACIPNwOAAiAFIA83A6gGIAFBMBBzIAIgAUHIABCUAUEAOgDIAUEwEBkiAUUNHyABIAUpA6gGNw\
AAIAFBKGogBUGoBmpBKGopAwA3AAAgAUEgaiAFQagGakEgaikDADcAACABQRhqIAVBqAZqQRhqKQMA\
NwAAIAFBEGogBUGoBmpBEGopAwA3AAAgAUEIaiAFQagGakEIaikDADcAAEEwIQQMHgsgBUHYB2pBDG\
pCADcCACAFQdgHakEUakIANwIAIAVB2AdqQRxqQgA3AgAgBUIANwLcByAFQQA2AtgHIAVB2AdqIAVB\
2AdqQQRyQX9zakEkakEHSRogBUEgNgLYByAFQYACakEQaiIGIAVB2AdqQRBqKQMANwMAIAVBgAJqQQ\
hqIgEgBUHYB2pBCGopAwA3AwAgBUGAAmpBGGoiByAFQdgHakEYaikDADcDACAFQYACakEgaiIIIAVB\
2AdqQSBqKAIANgIAIAVBqAZqQQhqIgkgBUGAAmpBDGopAgA3AwAgBUGoBmpBEGoiCiAFQYACakEUai\
kCADcDACAFQagGakEYaiILIAVBgAJqQRxqKQIANwMAIAUgBSkD2Ac3A4ACIAUgBSkChAI3A6gGIAIg\
AikDACACQegAai0AACIErXw3AwAgAkEoaiEDAkAgBEHAAEYNACADIARqQQBBwAAgBGsQkwEaCyACQQ\
A6AGggAiADQX8QFCABIAJBEGoiBCkCACIPNwMAIAkgDzcDACAKIAJBGGoiAykCADcDACALIAJBIGoi\
CSkCADcDACAFIAJBCGoiCikCACIPNwOAAiAFIA83A6gGIAEQeiAJIAVBgAJqQShqKQMANwMAIAMgCC\
kDADcDACAEIAcpAwA3AwAgCiAGKQMANwMAIAIgBSkDiAI3AwAgAkEAOgBoQSAQGSIBRQ0eIAEgBSkD\
qAY3AAAgAUEYaiAFQagGakEYaikDADcAACABQRBqIAVBqAZqQRBqKQMANwAAIAFBCGogBUGoBmpBCG\
opAwA3AABBICEEDB0LAkAgBA0AQQEhAUEAIQQMAwsgBEF/Sg0BDB4LQSAhBAsgBBAZIgFFDRsgAUF8\
ai0AAEEDcUUNACABQQAgBBCTARoLIAVBgAJqIAIQHyACQgA3AwAgAkEgaiACQYgBaikDADcDACACQR\
hqIAJBgAFqKQMANwMAIAJBEGogAkH4AGopAwA3AwAgAiACKQNwNwMIIAJBKGpBAEHCABCTARoCQCAC\
KAKQAUUNACACQQA2ApABCyAFQYACaiABIAQQFwwZCyAFQeQHakIANwIAIAVB7AdqQgA3AgAgBUH0B2\
pBADYCACAFQgA3AtwHIAVBADYC2AdBBCEBIAVB2AdqIAVB2AdqQQRyQX9zakEgaiEEA0AgAUF/aiIB\
DQALAkAgBEEHSQ0AQRghAQNAIAFBeGoiAQ0ACwtBHCEEIAVBHDYC2AcgBUGAAmpBEGogBUHYB2pBEG\
opAwA3AwAgBUGAAmpBCGogBUHYB2pBCGopAwA3AwAgBUGAAmpBGGogBUHYB2pBGGopAwA3AwAgBUGo\
BmpBCGoiAyAFQYwCaikCADcDACAFQagGakEQaiIGIAVBlAJqKQIANwMAIAVBqAZqQRhqIgcgBUGAAm\
pBHGooAgA2AgAgBSAFKQPYBzcDgAIgBSAFKQKEAjcDqAYgAiACQcgBaiAFQagGahA4IAJBAEHIARCT\
AUHYAmpBADoAAEEcEBkiAUUNGSABIAUpA6gGNwAAIAFBGGogBygCADYAACABQRBqIAYpAwA3AAAgAU\
EIaiADKQMANwAADBgLIAVB2AdqQQxqQgA3AgAgBUHYB2pBFGpCADcCACAFQdgHakEcakIANwIAIAVC\
ADcC3AcgBUEANgLYByAFQdgHaiAFQdgHakEEckF/c2pBJGpBB0kaQSAhBCAFQSA2AtgHIAVBgAJqQR\
BqIAVB2AdqQRBqKQMANwMAIAVBgAJqQQhqIAVB2AdqQQhqKQMANwMAIAVBgAJqQRhqIAVB2AdqQRhq\
KQMANwMAIAVBgAJqQSBqIAVB2AdqQSBqKAIANgIAIAVBqAZqQQhqIgMgBUGAAmpBDGopAgA3AwAgBU\
GoBmpBEGoiBiAFQYACakEUaikCADcDACAFQagGakEYaiIHIAVBgAJqQRxqKQIANwMAIAUgBSkD2Ac3\
A4ACIAUgBSkChAI3A6gGIAIgAkHIAWogBUGoBmoQQSACQQBByAEQkwFB0AJqQQA6AABBIBAZIgFFDR\
ggASAFKQOoBjcAACABQRhqIAcpAwA3AAAgAUEQaiAGKQMANwAAIAFBCGogAykDADcAAAwXCyAFQdgH\
akEMakIANwIAIAVB2AdqQRRqQgA3AgAgBUHYB2pBHGpCADcCACAFQdgHakEkakIANwIAIAVB2AdqQS\
xqQgA3AgAgBUIANwLcByAFQQA2AtgHIAVB2AdqIAVB2AdqQQRyQX9zakE0akEHSRpBMCEEIAVBMDYC\
2AcgBUGAAmpBEGogBUHYB2pBEGopAwA3AwAgBUGAAmpBCGogBUHYB2pBCGopAwA3AwAgBUGAAmpBGG\
ogBUHYB2pBGGopAwA3AwAgBUGAAmpBIGogBUHYB2pBIGopAwA3AwAgBUGAAmpBKGogBUHYB2pBKGop\
AwA3AwAgBUGAAmpBMGogBUHYB2pBMGooAgA2AgAgBUGoBmpBCGoiAyAFQYACakEMaikCADcDACAFQa\
gGakEQaiIGIAVBgAJqQRRqKQIANwMAIAVBqAZqQRhqIgcgBUGAAmpBHGopAgA3AwAgBUGoBmpBIGoi\
CCAFQYACakEkaikCADcDACAFQagGakEoaiIJIAVBgAJqQSxqKQIANwMAIAUgBSkD2Ac3A4ACIAUgBS\
kChAI3A6gGIAIgAkHIAWogBUGoBmoQSSACQQBByAEQkwFBsAJqQQA6AABBMBAZIgFFDRcgASAFKQOo\
BjcAACABQShqIAkpAwA3AAAgAUEgaiAIKQMANwAAIAFBGGogBykDADcAACABQRBqIAYpAwA3AAAgAU\
EIaiADKQMANwAADBYLIAVB2AdqQQxqQgA3AgAgBUHYB2pBFGpCADcCACAFQdgHakEcakIANwIAIAVB\
2AdqQSRqQgA3AgAgBUHYB2pBLGpCADcCACAFQdgHakE0akIANwIAIAVB2AdqQTxqQgA3AgAgBUIANw\
LcByAFQQA2AtgHIAVB2AdqIAVB2AdqQQRyQX9zakHEAGpBB0kaQcAAIQQgBUHAADYC2AcgBUGAAmog\
BUHYB2pBxAAQlAEaIAVBqAZqQThqIgMgBUGAAmpBPGopAgA3AwAgBUGoBmpBMGoiBiAFQYACakE0ai\
kCADcDACAFQagGakEoaiIHIAVBgAJqQSxqKQIANwMAIAVBqAZqQSBqIgggBUGAAmpBJGopAgA3AwAg\
BUGoBmpBGGoiCSAFQYACakEcaikCADcDACAFQagGakEQaiIKIAVBgAJqQRRqKQIANwMAIAVBqAZqQQ\
hqIgsgBUGAAmpBDGopAgA3AwAgBSAFKQKEAjcDqAYgAiACQcgBaiAFQagGahBLIAJBAEHIARCTAUGQ\
AmpBADoAAEHAABAZIgFFDRYgASAFKQOoBjcAACABQThqIAMpAwA3AAAgAUEwaiAGKQMANwAAIAFBKG\
ogBykDADcAACABQSBqIAgpAwA3AAAgAUEYaiAJKQMANwAAIAFBEGogCikDADcAACABQQhqIAspAwA3\
AAAMFQsgBUHYB2pBDGpCADcCACAFQgA3AtwHIAVBADYC2AcgBUHYB2ogBUHYB2pBBHJBf3NqQRRqQQ\
dJGkEQIQQgBUEQNgLYByAFQYACakEQaiAFQdgHakEQaigCADYCACAFQYACakEIaiAFQdgHakEIaikD\
ADcDACAFQagGakEIaiIDIAVBgAJqQQxqKQIANwMAIAUgBSkD2Ac3A4ACIAUgBSkChAI3A6gGIAIgAk\
EYaiAFQagGahAuIAJB2ABqQQA6AAAgAkL+uevF6Y6VmRA3AxAgAkKBxpS6lvHq5m83AwggAkIANwMA\
QRAQGSIBRQ0VIAEgBSkDqAY3AAAgAUEIaiADKQMANwAADBQLIAVB2AdqQQxqQgA3AgAgBUIANwLcBy\
AFQQA2AtgHIAVB2AdqIAVB2AdqQQRyQX9zakEUakEHSRpBECEEIAVBEDYC2AcgBUGAAmpBEGogBUHY\
B2pBEGooAgA2AgAgBUGAAmpBCGogBUHYB2pBCGopAwA3AwAgBUGoBmpBCGoiAyAFQYACakEMaikCAD\
cDACAFIAUpA9gHNwOAAiAFIAUpAoQCNwOoBiACIAJBGGogBUGoBmoQLyACQdgAakEAOgAAIAJC/rnr\
xemOlZkQNwMQIAJCgcaUupbx6uZvNwMIIAJCADcDAEEQEBkiAUUNFCABIAUpA6gGNwAAIAFBCGogAy\
kDADcAAAwTCyAFQeQHakIANwIAIAVB7AdqQQA2AgAgBUIANwLcByAFQQA2AtgHQQQhASAFQdgHaiAF\
QdgHakEEckF/c2pBGGohBANAIAFBf2oiAQ0ACwJAIARBB0kNAEEQIQEDQCABQXhqIgENAAsLQRQhBC\
AFQRQ2AtgHIAVBgAJqQRBqIAVB2AdqQRBqKQMANwMAIAVBgAJqQQhqIAVB2AdqQQhqKQMANwMAIAVB\
qAZqQQhqIgMgBUGMAmopAgA3AwAgBUGoBmpBEGoiBiAFQYACakEUaigCADYCACAFIAUpA9gHNwOAAi\
AFIAUpAoQCNwOoBiACIAJBIGogBUGoBmoQLCACQgA3AwAgAkHgAGpBADoAACACQQApA9iMQDcDCCAC\
QRBqQQApA+CMQDcDACACQRhqQQAoAuiMQDYCAEEUEBkiAUUNEyABIAUpA6gGNwAAIAFBEGogBigCAD\
YAACABQQhqIAMpAwA3AAAMEgsgBUHkB2pCADcCACAFQewHakEANgIAIAVCADcC3AcgBUEANgLYB0EE\
IQEgBUHYB2ogBUHYB2pBBHJBf3NqQRhqIQQDQCABQX9qIgENAAsCQCAEQQdJDQBBECEBA0AgAUF4ai\
IBDQALC0EUIQQgBUEUNgLYByAFQYACakEQaiAFQdgHakEQaikDADcDACAFQYACakEIaiAFQdgHakEI\
aikDADcDACAFQagGakEIaiIDIAVBjAJqKQIANwMAIAVBqAZqQRBqIgYgBUGAAmpBFGooAgA2AgAgBS\
AFKQPYBzcDgAIgBSAFKQKEAjcDqAYgAiACQSBqIAVBqAZqECkgAkHgAGpBADoAACACQfDDy558NgIY\
IAJC/rnrxemOlZkQNwMQIAJCgcaUupbx6uZvNwMIIAJCADcDAEEUEBkiAUUNEiABIAUpA6gGNwAAIA\
FBEGogBigCADYAACABQQhqIAMpAwA3AAAMEQsgBUHkB2pCADcCACAFQewHakIANwIAIAVB9AdqQQA2\
AgAgBUIANwLcByAFQQA2AtgHQQQhASAFQdgHaiAFQdgHakEEckF/c2pBIGohBANAIAFBf2oiAQ0ACw\
JAIARBB0kNAEEYIQEDQCABQXhqIgENAAsLQRwhBCAFQRw2AtgHIAVBgAJqQRBqIAVB2AdqQRBqKQMA\
NwMAIAVBgAJqQQhqIAVB2AdqQQhqKQMANwMAIAVBgAJqQRhqIAVB2AdqQRhqKQMANwMAIAVBqAZqQQ\
hqIgMgBUGMAmopAgA3AwAgBUGoBmpBEGoiBiAFQZQCaikCADcDACAFQagGakEYaiIHIAVBgAJqQRxq\
KAIANgIAIAUgBSkD2Ac3A4ACIAUgBSkChAI3A6gGIAIgAkHIAWogBUGoBmoQOSACQQBByAEQkwFB2A\
JqQQA6AABBHBAZIgFFDREgASAFKQOoBjcAACABQRhqIAcoAgA2AAAgAUEQaiAGKQMANwAAIAFBCGog\
AykDADcAAAwQCyAFQdgHakEMakIANwIAIAVB2AdqQRRqQgA3AgAgBUHYB2pBHGpCADcCACAFQgA3At\
wHIAVBADYC2AcgBUHYB2ogBUHYB2pBBHJBf3NqQSRqQQdJGkEgIQQgBUEgNgLYByAFQYACakEQaiAF\
QdgHakEQaikDADcDACAFQYACakEIaiAFQdgHakEIaikDADcDACAFQYACakEYaiAFQdgHakEYaikDAD\
cDACAFQYACakEgaiAFQdgHakEgaigCADYCACAFQagGakEIaiIDIAVBgAJqQQxqKQIANwMAIAVBqAZq\
QRBqIgYgBUGAAmpBFGopAgA3AwAgBUGoBmpBGGoiByAFQYACakEcaikCADcDACAFIAUpA9gHNwOAAi\
AFIAUpAoQCNwOoBiACIAJByAFqIAVBqAZqEEIgAkEAQcgBEJMBQdACakEAOgAAQSAQGSIBRQ0QIAEg\
BSkDqAY3AAAgAUEYaiAHKQMANwAAIAFBEGogBikDADcAACABQQhqIAMpAwA3AAAMDwsgBUHYB2pBDG\
pCADcCACAFQdgHakEUakIANwIAIAVB2AdqQRxqQgA3AgAgBUHYB2pBJGpCADcCACAFQdgHakEsakIA\
NwIAIAVCADcC3AcgBUEANgLYByAFQdgHaiAFQdgHakEEckF/c2pBNGpBB0kaQTAhBCAFQTA2AtgHIA\
VBgAJqQRBqIAVB2AdqQRBqKQMANwMAIAVBgAJqQQhqIAVB2AdqQQhqKQMANwMAIAVBgAJqQRhqIAVB\
2AdqQRhqKQMANwMAIAVBgAJqQSBqIAVB2AdqQSBqKQMANwMAIAVBgAJqQShqIAVB2AdqQShqKQMANw\
MAIAVBgAJqQTBqIAVB2AdqQTBqKAIANgIAIAVBqAZqQQhqIgMgBUGAAmpBDGopAgA3AwAgBUGoBmpB\
EGoiBiAFQYACakEUaikCADcDACAFQagGakEYaiIHIAVBgAJqQRxqKQIANwMAIAVBqAZqQSBqIgggBU\
GAAmpBJGopAgA3AwAgBUGoBmpBKGoiCSAFQYACakEsaikCADcDACAFIAUpA9gHNwOAAiAFIAUpAoQC\
NwOoBiACIAJByAFqIAVBqAZqEEogAkEAQcgBEJMBQbACakEAOgAAQTAQGSIBRQ0PIAEgBSkDqAY3AA\
AgAUEoaiAJKQMANwAAIAFBIGogCCkDADcAACABQRhqIAcpAwA3AAAgAUEQaiAGKQMANwAAIAFBCGog\
AykDADcAAAwOCyAFQdgHakEMakIANwIAIAVB2AdqQRRqQgA3AgAgBUHYB2pBHGpCADcCACAFQdgHak\
EkakIANwIAIAVB2AdqQSxqQgA3AgAgBUHYB2pBNGpCADcCACAFQdgHakE8akIANwIAIAVCADcC3Acg\
BUEANgLYByAFQdgHaiAFQdgHakEEckF/c2pBxABqQQdJGkHAACEEIAVBwAA2AtgHIAVBgAJqIAVB2A\
dqQcQAEJQBGiAFQagGakE4aiIDIAVBgAJqQTxqKQIANwMAIAVBqAZqQTBqIgYgBUGAAmpBNGopAgA3\
AwAgBUGoBmpBKGoiByAFQYACakEsaikCADcDACAFQagGakEgaiIIIAVBgAJqQSRqKQIANwMAIAVBqA\
ZqQRhqIgkgBUGAAmpBHGopAgA3AwAgBUGoBmpBEGoiCiAFQYACakEUaikCADcDACAFQagGakEIaiIL\
IAVBgAJqQQxqKQIANwMAIAUgBSkChAI3A6gGIAIgAkHIAWogBUGoBmoQTCACQQBByAEQkwFBkAJqQQ\
A6AABBwAAQGSIBRQ0OIAEgBSkDqAY3AAAgAUE4aiADKQMANwAAIAFBMGogBikDADcAACABQShqIAcp\
AwA3AAAgAUEgaiAIKQMANwAAIAFBGGogCSkDADcAACABQRBqIAopAwA3AAAgAUEIaiALKQMANwAADA\
0LQQQhAQNAIAFBf2oiAQ0ACwJAQRtBB0kNAEEYIQEDQCABQXhqIgENAAsLIAVB2AdqQQxqQgA3AgAg\
BUHYB2pBFGpCADcCACAFQdgHakEcakIANwIAIAVCADcC3AcgBUEANgLYByAFQdgHaiAFQdgHakEEck\
F/c2pBJGpBB0kaIAVBIDYC2AcgBUGAAmpBEGoiBCAFQdgHakEQaikDADcDACAFQYACakEIaiIDIAVB\
2AdqQQhqKQMANwMAIAVBgAJqQRhqIgYgBUHYB2pBGGopAwA3AwAgBUGAAmpBIGogBUHYB2pBIGooAg\
A2AgAgBUGoBmpBCGoiASAFQYACakEMaikCADcDACAFQagGakEQaiIHIAVBgAJqQRRqKQIANwMAIAVB\
qAZqQRhqIgggBUGAAmpBHGopAgA3AwAgBSAFKQPYBzcDgAIgBSAFKQKEAjcDqAYgAiACQShqIAVBqA\
ZqECcgBiAIKAIANgIAIAQgBykDADcDACADIAEpAwA3AwAgBSAFKQOoBjcDgAIgAkIANwMAIAJBACkD\
kI1ANwMIIAJBEGpBACkDmI1ANwMAIAJBGGpBACkDoI1ANwMAIAJBIGpBACkDqI1ANwMAIAJB6ABqQQ\
A6AABBHBAZIgFFDQ0gASAFKQOAAjcAACABQRhqIAYoAgA2AAAgAUEQaiAEKQMANwAAIAFBCGogAykD\
ADcAAEEcIQQMDAsgBUHYB2pBDGpCADcCACAFQdgHakEUakIANwIAIAVB2AdqQRxqQgA3AgAgBUIANw\
LcByAFQQA2AtgHIAVB2AdqIAVB2AdqQQRyQX9zakEkakEHSRpBICEEIAVBIDYC2AcgBUGAAmpBEGoi\
AyAFQdgHakEQaikDADcDACAFQYACakEIaiIGIAVB2AdqQQhqKQMANwMAIAVBgAJqQRhqIgcgBUHYB2\
pBGGopAwA3AwAgBUGAAmpBIGogBUHYB2pBIGooAgA2AgAgBUGoBmpBCGoiASAFQYACakEMaikCADcD\
ACAFQagGakEQaiIIIAVBgAJqQRRqKQIANwMAIAVBqAZqQRhqIgkgBUGAAmpBHGopAgA3AwAgBSAFKQ\
PYBzcDgAIgBSAFKQKEAjcDqAYgAiACQShqIAVBqAZqECcgByAJKQMANwMAIAMgCCkDADcDACAGIAEp\
AwA3AwAgBSAFKQOoBjcDgAIgAkIANwMAIAJBACkD8IxANwMIIAJBEGpBACkD+IxANwMAIAJBGGpBAC\
kDgI1ANwMAIAJBIGpBACkDiI1ANwMAIAJB6ABqQQA6AABBIBAZIgFFDQwgASAFKQOAAjcAACABQRhq\
IAcpAwA3AAAgAUEQaiADKQMANwAAIAFBCGogBikDADcAAAwLCyAFQdgHakEMakIANwIAIAVB2AdqQR\
RqQgA3AgAgBUHYB2pBHGpCADcCACAFQdgHakEkakIANwIAIAVB2AdqQSxqQgA3AgAgBUHYB2pBNGpC\
ADcCACAFQdgHakE8akIANwIAIAVCADcC3AcgBUEANgLYByAFQdgHaiAFQdgHakEEckF/c2pBxABqQQ\
dJGiAFQcAANgLYByAFQYACaiAFQdgHakHEABCUARogBUGoBmpBOGogBUGAAmpBPGopAgA3AwBBMCEE\
IAVBqAZqQTBqIAVBgAJqQTRqKQIANwMAIAVBqAZqQShqIgEgBUGAAmpBLGopAgA3AwAgBUGoBmpBIG\
oiAyAFQYACakEkaikCADcDACAFQagGakEYaiIGIAVBgAJqQRxqKQIANwMAIAVBqAZqQRBqIgcgBUGA\
AmpBFGopAgA3AwAgBUGoBmpBCGoiCCAFQYACakEMaikCADcDACAFIAUpAoQCNwOoBiACIAJB0ABqIA\
VBqAZqECMgBUGAAmpBKGoiCSABKQMANwMAIAVBgAJqQSBqIgogAykDADcDACAFQYACakEYaiIDIAYp\
AwA3AwAgBUGAAmpBEGoiBiAHKQMANwMAIAVBgAJqQQhqIgcgCCkDADcDACAFIAUpA6gGNwOAAiACQc\
gAakIANwMAIAJCADcDQCACQThqQQApA6iOQDcDACACQTBqQQApA6COQDcDACACQShqQQApA5iOQDcD\
ACACQSBqQQApA5COQDcDACACQRhqQQApA4iOQDcDACACQRBqQQApA4COQDcDACACQQhqQQApA/iNQD\
cDACACQQApA/CNQDcDACACQdABakEAOgAAQTAQGSIBRQ0LIAEgBSkDgAI3AAAgAUEoaiAJKQMANwAA\
IAFBIGogCikDADcAACABQRhqIAMpAwA3AAAgAUEQaiAGKQMANwAAIAFBCGogBykDADcAAAwKCyAFQd\
gHakEMakIANwIAIAVB2AdqQRRqQgA3AgAgBUHYB2pBHGpCADcCACAFQdgHakEkakIANwIAIAVB2Adq\
QSxqQgA3AgAgBUHYB2pBNGpCADcCACAFQdgHakE8akIANwIAIAVCADcC3AcgBUEANgLYByAFQdgHai\
AFQdgHakEEckF/c2pBxABqQQdJGkHAACEEIAVBwAA2AtgHIAVBgAJqIAVB2AdqQcQAEJQBGiAFQagG\
akE4aiIBIAVBgAJqQTxqKQIANwMAIAVBqAZqQTBqIgMgBUGAAmpBNGopAgA3AwAgBUGoBmpBKGoiBi\
AFQYACakEsaikCADcDACAFQagGakEgaiIHIAVBgAJqQSRqKQIANwMAIAVBqAZqQRhqIgggBUGAAmpB\
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\
cyAjQR53ICNBE3dzICNBCndzaiACIBtBGXcgG0EOd3MgG0EDdnNqIBlqIBJBD3cgEkENd3MgEkEKdn\
NqICJqIBAgHGoiAiAhIB5zcSAec2ogAkEadyACQRV3cyACQQd3c2pB98fm93tqIiJqIhwgIyAgc3Eg\
E3MgC2ogHEEedyAcQRN3cyAcQQp3c2ogGyAfQRl3IB9BDndzIB9BA3ZzaiARaiAkQQ93ICRBDXdzIC\
RBCnZzaiAeaiAiICVqIhsgAiAhc3EgIXNqIBtBGncgG0EVd3MgG0EHd3NqQfLxxbN8aiIeaiELIBwg\
CmohCiAjIAlqIQkgICAIaiEIIB0gB2ogHmohByAbIAZqIQYgAiAFaiEFICEgBGohBCABQcAAaiIBIA\
xHDQALCyAAIAQ2AhwgACAFNgIYIAAgBjYCFCAAIAc2AhAgACAINgIMIAAgCTYCCCAAIAo2AgQgACAL\
NgIAC71AAgp/BH4jAEGAD2siASQAAkACQAJAAkAgAEUNACAAKAIAIgJBf0YNASAAIAJBAWo2AgAgAE\
EIaigCACECAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkAg\
AEEEaigCACIDDhgAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcAC0HQARAZIgRFDRogAUEIakE4aiACQT\
hqKQMANwMAIAFBCGpBMGogAkEwaikDADcDACABQQhqQShqIAJBKGopAwA3AwAgAUEIakEgaiACQSBq\
KQMANwMAIAFBCGpBGGogAkEYaikDADcDACABQQhqQRBqIAJBEGopAwA3AwAgAUEIakEIaiACQQhqKQ\
MANwMAIAEgAikDADcDCCACKQNAIQsgAUEIakHIAGogAkHIAGoQYiABIAs3A0ggBCABQQhqQdABEJQB\
GgwXC0HQARAZIgRFDRkgAUEIakE4aiACQThqKQMANwMAIAFBCGpBMGogAkEwaikDADcDACABQQhqQS\
hqIAJBKGopAwA3AwAgAUEIakEgaiACQSBqKQMANwMAIAFBCGpBGGogAkEYaikDADcDACABQQhqQRBq\
IAJBEGopAwA3AwAgAUEIakEIaiACQQhqKQMANwMAIAEgAikDADcDCCACKQNAIQsgAUEIakHIAGogAk\
HIAGoQYiABIAs3A0ggBCABQQhqQdABEJQBGgwWC0HQARAZIgRFDRggAUEIakE4aiACQThqKQMANwMA\
IAFBCGpBMGogAkEwaikDADcDACABQQhqQShqIAJBKGopAwA3AwAgAUEIakEgaiACQSBqKQMANwMAIA\
FBCGpBGGogAkEYaikDADcDACABQQhqQRBqIAJBEGopAwA3AwAgAUEIakEIaiACQQhqKQMANwMAIAEg\
AikDADcDCCACKQNAIQsgAUEIakHIAGogAkHIAGoQYiABIAs3A0ggBCABQQhqQdABEJQBGgwVC0HwAB\
AZIgRFDRcgAUEIakEgaiACQSBqKQMANwMAIAFBCGpBGGogAkEYaikDADcDACABQQhqQRBqIAJBEGop\
AwA3AwAgASACKQMINwMQIAIpAwAhCyABQQhqQShqIAJBKGoQUSABIAs3AwggBCABQQhqQfAAEJQBGg\
wUC0H4DhAZIgRFDRYgAUEIakGIAWogAkGIAWopAwA3AwAgAUEIakGAAWogAkGAAWopAwA3AwAgAUEI\
akH4AGogAkH4AGopAwA3AwAgASACKQNwNwN4IAFBCGpBEGogAkEQaikDADcDACABQQhqQRhqIAJBGG\
opAwA3AwAgAUEIakEgaiACQSBqKQMANwMAIAEgAikDCDcDECACKQMAIQsgAUEIakHgAGogAkHgAGop\
AwA3AwAgAUEIakHYAGogAkHYAGopAwA3AwAgAUEIakHQAGogAkHQAGopAwA3AwAgAUEIakHIAGogAk\
HIAGopAwA3AwAgAUEIakHAAGogAkHAAGopAwA3AwAgAUEIakE4aiACQThqKQMANwMAIAFBCGpBMGog\
AkEwaikDADcDACABIAIpAyg3AzAgAi0AaiEFIAItAGkhBiACLQBoIQcgAUEANgKYAQJAIAIoApABIg\
hFDQAgAkGUAWoiCUEIaikAACEMIAlBEGopAAAhDSAJKQAAIQ4gAUG0AWogCUEYaikAADcCACABQawB\
aiANNwIAIAFBpAFqIAw3AgAgAUEIakGUAWogDjcCACACQbQBaiIKIAkgCEEFdGoiCUYNACAKQQhqKQ\
AAIQwgCkEQaikAACENIAopAAAhDiABQdQBaiAKQRhqKQAANwIAIAFBzAFqIA03AgAgAUHEAWogDDcC\
ACABQQhqQbQBaiAONwIAIAJB1AFqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQf\
QBaiAKQRhqKQAANwIAIAFB7AFqIA03AgAgAUHkAWogDDcCACABQQhqQdQBaiAONwIAIAJB9AFqIgog\
CUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQZQCaiAKQRhqKQAANwIAIAFBjAJqIA03Ag\
AgAUGEAmogDDcCACABQQhqQfQBaiAONwIAIAJBlAJqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACEN\
IAopAAAhDiABQbQCaiAKQRhqKQAANwIAIAFBrAJqIA03AgAgAUGkAmogDDcCACABQQhqQZQCaiAONw\
IAIAJBtAJqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQdQCaiAKQRhqKQAANwIA\
IAFBzAJqIA03AgAgAUHEAmogDDcCACABQQhqQbQCaiAONwIAIAJB1AJqIgogCUYNACAKQQhqKQAAIQ\
wgCkEQaikAACENIAopAAAhDiABQfQCaiAKQRhqKQAANwIAIAFB7AJqIA03AgAgAUHkAmogDDcCACAB\
QQhqQdQCaiAONwIAIAJB9AJqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQZQDai\
AKQRhqKQAANwIAIAFBjANqIA03AgAgAUGEA2ogDDcCACABQQhqQfQCaiAONwIAIAJBlANqIgogCUYN\
ACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQbQDaiAKQRhqKQAANwIAIAFBrANqIA03AgAgAU\
GkA2ogDDcCACABQQhqQZQDaiAONwIAIAJBtANqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAop\
AAAhDiABQdQDaiAKQRhqKQAANwIAIAFBzANqIA03AgAgAUHEA2ogDDcCACABQQhqQbQDaiAONwIAIA\
JB1ANqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQfQDaiAKQRhqKQAANwIAIAFB\
7ANqIA03AgAgAUHkA2ogDDcCACABQQhqQdQDaiAONwIAIAJB9ANqIgogCUYNACAKQQhqKQAAIQwgCk\
EQaikAACENIAopAAAhDiABQZQEaiAKQRhqKQAANwIAIAFBjARqIA03AgAgAUGEBGogDDcCACABQQhq\
QfQDaiAONwIAIAJBlARqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQbQEaiAKQR\
hqKQAANwIAIAFBrARqIA03AgAgAUGkBGogDDcCACABQQhqQZQEaiAONwIAIAJBtARqIgogCUYNACAK\
QQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQdQEaiAKQRhqKQAANwIAIAFBzARqIA03AgAgAUHEBG\
ogDDcCACABQQhqQbQEaiAONwIAIAJB1ARqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAh\
DiABQfQEaiAKQRhqKQAANwIAIAFB7ARqIA03AgAgAUHkBGogDDcCACABQQhqQdQEaiAONwIAIAJB9A\
RqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQZQFaiAKQRhqKQAANwIAIAFBjAVq\
IA03AgAgAUGEBWogDDcCACABQQhqQfQEaiAONwIAIAJBlAVqIgogCUYNACAKQQhqKQAAIQwgCkEQai\
kAACENIAopAAAhDiABQbQFaiAKQRhqKQAANwIAIAFBrAVqIA03AgAgAUGkBWogDDcCACABQQhqQZQF\
aiAONwIAIAJBtAVqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQdQFaiAKQRhqKQ\
AANwIAIAFBzAVqIA03AgAgAUHEBWogDDcCACABQQhqQbQFaiAONwIAIAJB1AVqIgogCUYNACAKQQhq\
KQAAIQwgCkEQaikAACENIAopAAAhDiABQfQFaiAKQRhqKQAANwIAIAFB7AVqIA03AgAgAUHkBWogDD\
cCACABQQhqQdQFaiAONwIAIAJB9AVqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiAB\
QZQGaiAKQRhqKQAANwIAIAFBjAZqIA03AgAgAUGEBmogDDcCACABQQhqQfQFaiAONwIAIAJBlAZqIg\
ogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQbQGaiAKQRhqKQAANwIAIAFBrAZqIA03\
AgAgAUGkBmogDDcCACABQQhqQZQGaiAONwIAIAJBtAZqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAAC\
ENIAopAAAhDiABQdQGaiAKQRhqKQAANwIAIAFBzAZqIA03AgAgAUHEBmogDDcCACABQQhqQbQGaiAO\
NwIAIAJB1AZqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQfQGaiAKQRhqKQAANw\
IAIAFB7AZqIA03AgAgAUHkBmogDDcCACABQQhqQdQGaiAONwIAIAJB9AZqIgogCUYNACAKQQhqKQAA\
IQwgCkEQaikAACENIAopAAAhDiABQZQHaiAKQRhqKQAANwIAIAFBjAdqIA03AgAgAUGEB2ogDDcCAC\
ABQQhqQfQGaiAONwIAIAJBlAdqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQbQH\
aiAKQRhqKQAANwIAIAFBrAdqIA03AgAgAUGkB2ogDDcCACABQQhqQZQHaiAONwIAIAJBtAdqIgogCU\
YNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQdQHaiAKQRhqKQAANwIAIAFBzAdqIA03AgAg\
AUHEB2ogDDcCACABQQhqQbQHaiAONwIAIAJB1AdqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIA\
opAAAhDiABQfQHaiAKQRhqKQAANwIAIAFB7AdqIA03AgAgAUHkB2ogDDcCACABQQhqQdQHaiAONwIA\
IAJB9AdqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQZQIaiAKQRhqKQAANwIAIA\
FBjAhqIA03AgAgAUGECGogDDcCACABQQhqQfQHaiAONwIAIAJBlAhqIgogCUYNACAKQQhqKQAAIQwg\
CkEQaikAACENIAopAAAhDiABQbQIaiAKQRhqKQAANwIAIAFBrAhqIA03AgAgAUGkCGogDDcCACABQQ\
hqQZQIaiAONwIAIAJBtAhqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQdQIaiAK\
QRhqKQAANwIAIAFBzAhqIA03AgAgAUHECGogDDcCACABQQhqQbQIaiAONwIAIAJB1AhqIgogCUYNAC\
AKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQfQIaiAKQRhqKQAANwIAIAFB7AhqIA03AgAgAUHk\
CGogDDcCACABQQhqQdQIaiAONwIAIAJB9AhqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAA\
AhDiABQZQJaiAKQRhqKQAANwIAIAFBjAlqIA03AgAgAUGECWogDDcCACABQQhqQfQIaiAONwIAIAJB\
lAlqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQbQJaiAKQRhqKQAANwIAIAFBrA\
lqIA03AgAgAUGkCWogDDcCACABQQhqQZQJaiAONwIAIAJBtAlqIgogCUYNACAKQQhqKQAAIQwgCkEQ\
aikAACENIAopAAAhDiABQdQJaiAKQRhqKQAANwIAIAFBzAlqIA03AgAgAUHECWogDDcCACABQQhqQb\
QJaiAONwIAIAJB1AlqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQfQJaiAKQRhq\
KQAANwIAIAFB7AlqIA03AgAgAUHkCWogDDcCACABQQhqQdQJaiAONwIAIAJB9AlqIgogCUYNACAKQQ\
hqKQAAIQwgCkEQaikAACENIAopAAAhDiABQZQKaiAKQRhqKQAANwIAIAFBjApqIA03AgAgAUGECmog\
DDcCACABQQhqQfQJaiAONwIAIAJBlApqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDi\
ABQbQKaiAKQRhqKQAANwIAIAFBrApqIA03AgAgAUGkCmogDDcCACABQQhqQZQKaiAONwIAIAJBtApq\
IgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQdQKaiAKQRhqKQAANwIAIAFBzApqIA\
03AgAgAUHECmogDDcCACABQQhqQbQKaiAONwIAIAJB1ApqIgogCUYNACAKQQhqKQAAIQwgCkEQaikA\
ACENIAopAAAhDiABQfQKaiAKQRhqKQAANwIAIAFB7ApqIA03AgAgAUHkCmogDDcCACABQQhqQdQKai\
AONwIAIAJB9ApqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQZQLaiAKQRhqKQAA\
NwIAIAFBjAtqIA03AgAgAUGEC2ogDDcCACABQQhqQfQKaiAONwIAIAJBlAtqIgogCUYNACAKQQhqKQ\
AAIQwgCkEQaikAACENIAopAAAhDiABQbQLaiAKQRhqKQAANwIAIAFBrAtqIA03AgAgAUGkC2ogDDcC\
ACABQQhqQZQLaiAONwIAIAJBtAtqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQd\
QLaiAKQRhqKQAANwIAIAFBzAtqIA03AgAgAUHEC2ogDDcCACABQQhqQbQLaiAONwIAIAJB1AtqIgog\
CUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQfQLaiAKQRhqKQAANwIAIAFB7AtqIA03Ag\
AgAUHkC2ogDDcCACABQQhqQdQLaiAONwIAIAJB9AtqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACEN\
IAopAAAhDiABQZQMaiAKQRhqKQAANwIAIAFBjAxqIA03AgAgAUGEDGogDDcCACABQQhqQfQLaiAONw\
IAIAJBlAxqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQbQMaiAKQRhqKQAANwIA\
IAFBrAxqIA03AgAgAUGkDGogDDcCACABQQhqQZQMaiAONwIAIAJBtAxqIgogCUYNACAKQQhqKQAAIQ\
wgCkEQaikAACENIAopAAAhDiABQdQMaiAKQRhqKQAANwIAIAFBzAxqIA03AgAgAUHEDGogDDcCACAB\
QQhqQbQMaiAONwIAIAJB1AxqIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQfQMai\
AKQRhqKQAANwIAIAFB7AxqIA03AgAgAUHkDGogDDcCACABQQhqQdQMaiAONwIAIAJB9AxqIgogCUYN\
ACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQZQNaiAKQRhqKQAANwIAIAFBjA1qIA03AgAgAU\
GEDWogDDcCACABQQhqQfQMaiAONwIAIAJBlA1qIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAop\
AAAhDiABQbQNaiAKQRhqKQAANwIAIAFBrA1qIA03AgAgAUGkDWogDDcCACABQQhqQZQNaiAONwIAIA\
JBtA1qIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQdQNaiAKQRhqKQAANwIAIAFB\
zA1qIA03AgAgAUHEDWogDDcCACABQQhqQbQNaiAONwIAIAJB1A1qIgogCUYNACAKQQhqKQAAIQwgCk\
EQaikAACENIAopAAAhDiABQfQNaiAKQRhqKQAANwIAIAFB7A1qIA03AgAgAUHkDWogDDcCACABQQhq\
QdQNaiAONwIAIAJB9A1qIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQZQOaiAKQR\
hqKQAANwIAIAFBjA5qIA03AgAgAUGEDmogDDcCACABQQhqQfQNaiAONwIAIAJBlA5qIgogCUYNACAK\
QQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQbQOaiAKQRhqKQAANwIAIAFBrA5qIA03AgAgAUGkDm\
ogDDcCACABQQhqQZQOaiAONwIAIAJBtA5qIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAh\
DiABQdQOaiAKQRhqKQAANwIAIAFBzA5qIA03AgAgAUHEDmogDDcCACABQQhqQbQOaiAONwIAIAJB1A\
5qIgogCUYNACAKQQhqKQAAIQwgCkEQaikAACENIAopAAAhDiABQfQOaiAKQRhqKQAANwIAIAFB7A5q\
IA03AgAgAUHkDmogDDcCACABQQhqQdQOaiAONwIAIAJB9A5qIAlHDRgLIAEgBToAciABIAY6AHEgAS\
AHOgBwIAEgCzcDCCABIAhB////P3EiAkE3IAJBN0kbNgKYASAEIAFBCGpB+A4QlAEaDBMLQeACEBki\
BEUNFSABQQhqIAJByAEQlAEaIAFBCGpByAFqIAJByAFqEGMgBCABQQhqQeACEJQBGgwSC0HYAhAZIg\
RFDRQgAUEIaiACQcgBEJQBGiABQQhqQcgBaiACQcgBahBkIAQgAUEIakHYAhCUARoMEQtBuAIQGSIE\
RQ0TIAFBCGogAkHIARCUARogAUEIakHIAWogAkHIAWoQZSAEIAFBCGpBuAIQlAEaDBALQZgCEBkiBE\
UNEiABQQhqIAJByAEQlAEaIAFBCGpByAFqIAJByAFqEGYgBCABQQhqQZgCEJQBGgwPC0HgABAZIgRF\
DREgAUEIakEQaiACQRBqKQMANwMAIAEgAikDCDcDECACKQMAIQsgAUEIakEYaiACQRhqEFEgASALNw\
MIIAQgAUEIakHgABCUARoMDgtB4AAQGSIERQ0QIAFBCGpBEGogAkEQaikDADcDACABIAIpAwg3AxAg\
AikDACELIAFBCGpBGGogAkEYahBRIAEgCzcDCCAEIAFBCGpB4AAQlAEaDA0LQegAEBkiBEUNDyABQQ\
hqQRhqIAJBGGooAgA2AgAgAUEIakEQaiACQRBqKQMANwMAIAEgAikDCDcDECACKQMAIQsgAUEIakEg\
aiACQSBqEFEgASALNwMIIAQgAUEIakHoABCUARoMDAtB6AAQGSIERQ0OIAFBCGpBGGogAkEYaigCAD\
YCACABQQhqQRBqIAJBEGopAwA3AwAgASACKQMINwMQIAIpAwAhCyABQQhqQSBqIAJBIGoQUSABIAs3\
AwggBCABQQhqQegAEJQBGgwLC0HgAhAZIgRFDQ0gAUEIaiACQcgBEJQBGiABQQhqQcgBaiACQcgBah\
BjIAQgAUEIakHgAhCUARoMCgtB2AIQGSIERQ0MIAFBCGogAkHIARCUARogAUEIakHIAWogAkHIAWoQ\
ZCAEIAFBCGpB2AIQlAEaDAkLQbgCEBkiBEUNCyABQQhqIAJByAEQlAEaIAFBCGpByAFqIAJByAFqEG\
UgBCABQQhqQbgCEJQBGgwIC0GYAhAZIgRFDQogAUEIaiACQcgBEJQBGiABQQhqQcgBaiACQcgBahBm\
IAQgAUEIakGYAhCUARoMBwtB8AAQGSIERQ0JIAFBCGpBIGogAkEgaikDADcDACABQQhqQRhqIAJBGG\
opAwA3AwAgAUEIakEQaiACQRBqKQMANwMAIAEgAikDCDcDECACKQMAIQsgAUEIakEoaiACQShqEFEg\
ASALNwMIIAQgAUEIakHwABCUARoMBgtB8AAQGSIERQ0IIAFBCGpBIGogAkEgaikDADcDACABQQhqQR\
hqIAJBGGopAwA3AwAgAUEIakEQaiACQRBqKQMANwMAIAEgAikDCDcDECACKQMAIQsgAUEIakEoaiAC\
QShqEFEgASALNwMIIAQgAUEIakHwABCUARoMBQtB2AEQGSIERQ0HIAFBCGpBOGogAkE4aikDADcDAC\
ABQQhqQTBqIAJBMGopAwA3AwAgAUEIakEoaiACQShqKQMANwMAIAFBCGpBIGogAkEgaikDADcDACAB\
QQhqQRhqIAJBGGopAwA3AwAgAUEIakEQaiACQRBqKQMANwMAIAFBCGpBCGogAkEIaikDADcDACABIA\
IpAwA3AwggAkHIAGopAwAhCyACKQNAIQwgAUEIakHQAGogAkHQAGoQYiABQQhqQcgAaiALNwMAIAEg\
DDcDSCAEIAFBCGpB2AEQlAEaDAQLQdgBEBkiBEUNBiABQQhqQThqIAJBOGopAwA3AwAgAUEIakEwai\
ACQTBqKQMANwMAIAFBCGpBKGogAkEoaikDADcDACABQQhqQSBqIAJBIGopAwA3AwAgAUEIakEYaiAC\
QRhqKQMANwMAIAFBCGpBEGogAkEQaikDADcDACABQQhqQQhqIAJBCGopAwA3AwAgASACKQMANwMIIA\
JByABqKQMAIQsgAikDQCEMIAFBCGpB0ABqIAJB0ABqEGIgAUEIakHIAGogCzcDACABIAw3A0ggBCAB\
QQhqQdgBEJQBGgwDC0H4AhAZIgRFDQUgAUEIaiACQcgBEJQBGiABQQhqQcgBaiACQcgBahBnIAQgAU\
EIakH4AhCUARoMAgtB2AIQGSIERQ0EIAFBCGogAkHIARCUARogAUEIakHIAWogAkHIAWoQZCAEIAFB\
CGpB2AIQlAEaDAELQegAEBkiBEUNAyABQQhqQRBqIAJBEGopAwA3AwAgAUEIakEYaiACQRhqKQMANw\
MAIAEgAikDCDcDECACKQMAIQsgAUEIakEgaiACQSBqEFEgASALNwMIIAQgAUEIakHoABCUARoLIAAg\
ACgCAEF/ajYCAEEMEBkiAEUNAiAAIAQ2AgggACADNgIEIABBADYCACABQYAPaiQAIAAPCxCQAQALEJ\
EBAAsACxCNAQAL1TwCE38CfiMAQYACayIEJAACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkAC\
QAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAk\
ACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJA\
IAAOGAABAgMEBQYHCAkKCwwNDg8QERITFBUWFwALIAFByABqIQVBgAEgAUHIAWotAAAiAGsiBiADTw\
0XAkAgAEUNACAFIABqIAIgBhCUARogASABKQNAQoABfDcDQCABIAVCABASIAMgBmshAyACIAZqIQIL\
IAMgA0EHdiADQQBHIANB/wBxRXFrIgBBB3QiB2shAyAARQ1GIAchBiACIQADQCABIAEpA0BCgAF8Nw\
NAIAEgAEIAEBIgAEGAAWohACAGQYB/aiIGDQAMRwsLIAFByABqIQVBgAEgAUHIAWotAAAiAGsiBiAD\
Tw0XAkAgAEUNACAFIABqIAIgBhCUARogASABKQNAQoABfDcDQCABIAVCABASIAMgBmshAyACIAZqIQ\
ILIAMgA0EHdiADQQBHIANB/wBxRXFrIgBBB3QiB2shAyAARQ1EIAchBiACIQADQCABIAEpA0BCgAF8\
NwNAIAEgAEIAEBIgAEGAAWohACAGQYB/aiIGDQAMRQsLIAFByABqIQVBgAEgAUHIAWotAAAiAGsiBi\
ADTw0XAkAgAEUNACAFIABqIAIgBhCUARogASABKQNAQoABfDcDQCABIAVCABASIAMgBmshAyACIAZq\
IQILIAMgA0EHdiADQQBHIANB/wBxRXFrIgBBB3QiB2shAyAARQ1CIAchBiACIQADQCABIAEpA0BCgA\
F8NwNAIAEgAEIAEBIgAEGAAWohACAGQYB/aiIGDQAMQwsLIAFBKGohBUHAACABQegAai0AACIAayIG\
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\
OgDIAQwtCyAFIABqIAIgAxCUARogASAAIANqOgBoDCwLIAQgCzYCjAEgBCAJNgKIASAEIAw2AoQBIA\
QgCDYCgAEgBCANNgJ8IAQgCjYCeCAEIA42AnQgBCAPNgJwQfiQwAAgBEHwAGpBkIfAAEHwhsAAEGEA\
CyAGIABqIAIgAxCUARogASAAIANqOgDYAgwqCyAGIABqIAIgAxCUARogASAAIANqOgDQAgwpCyAGIA\
BqIAIgAxCUARogASAAIANqOgCwAgwoCyAGIABqIAIgAxCUARogASAAIANqOgCQAgwnCyAFIABqIAIg\
AxCUARogASAAIANqOgBYDCYLIAYgAGogAiADEJQBGiABIAAgA2o6AFgMJQsgBSAAaiACIAMQlAEaIA\
EgACADajoAYAwkCyAGIABqIAIgAxCUARogASAAIANqOgBgDCMLIAYgAGogAiADEJQBGiABIAAgA2o6\
ANgCDCILIAYgAGogAiADEJQBGiABIAAgA2o6ANACDCELIAYgAGogAiADEJQBGiABIAAgA2o6ALACDC\
ALIAYgAGogAiADEJQBGiABIAAgA2o6AJACDB8LIAYgAGogAiADEJQBGiABIAAgA2o6AGgMHgsgBiAA\
aiACIAMQlAEaIAEgACADajoAaAwdCyAGIABqIAIgAxCUARogASAAIANqOgDQAQwcCyAGIABqIAIgAx\
CUARogASAAIANqOgDQAQwbCyAGIABqIAIgAxCUARogASAAIANqOgDwAgwaCyAGIABqIAIgAxCUARog\
ASAAIANqOgDQAgwZCyAFIAggBxCUARoLIAEgBzoAYAwXCwJAIABBiQFPDQAgBiACIAVqIAAQlAEaIA\
EgADoA0AIMFwsgAEGIAUGAgMAAEIsBAAsCQCAAQakBTw0AIAYgAiAFaiAAEJQBGiABIAA6APACDBYL\
IABBqAFBgIDAABCLAQALIAYgBSAAEJQBGiABIAA6ANABDBQLIAYgBSAAEJQBGiABIAA6ANABDBMLIA\
YgBSAAEJQBGiABIAA6AGgMEgsgBiAFIAAQlAEaIAEgADoAaAwRCwJAIABByQBPDQAgBiACIAVqIAAQ\
lAEaIAEgADoAkAIMEQsgAEHIAEGAgMAAEIsBAAsCQCAAQekATw0AIAYgAiAFaiAAEJQBGiABIAA6AL\
ACDBALIABB6ABBgIDAABCLAQALAkAgAEGJAU8NACAGIAIgBWogABCUARogASAAOgDQAgwPCyAAQYgB\
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\
QX9zcnNqQc76z8p6akEFdyAKaiIJaiAOIAJqIAwgBEEKdyICcyANc2pBDXcgA2oiBEEKd2o2AgAgAC\
gCECEMIAAgASAVaiAGIApqIAkgDyAgQX9zcnNqQc76z8p6akEGd2ogAyALaiANIAVzIARzakELdyAC\
aiIKajYCECAAIAEgDGogBWogAiAHaiAEIBZzIApzakELd2o2AgwLhCgCMH8BfiMAQcAAayIDQRhqIg\
RCADcDACADQSBqIgVCADcDACADQThqIgZCADcDACADQTBqIgdCADcDACADQShqIghCADcDACADQQhq\
IgkgASkACDcDACADQRBqIgogASkAEDcDACAEIAEoABgiCzYCACAFIAEoACAiBDYCACADIAEpAAA3Aw\
AgAyABKAAcIgU2AhwgAyABKAAkIgw2AiQgCCABKAAoIg02AgAgAyABKAAsIgg2AiwgByABKAAwIg42\
AgAgAyABKAA0Igc2AjQgBiABKAA4Ig82AgAgAyABKAA8IgE2AjwgACAIIAEgBCAFIAcgCCALIAQgDC\
AMIA0gDyABIAQgBCALIAEgDSAPIAggBSAHIAEgBSAIIAsgByAHIA4gBSALIABBJGoiECgCACIRIABB\
FGoiEigCACITamoiBkGZmoPfBXNBEHciFEG66r+qemoiFSARc0EUdyIWIAZqaiIXIBRzQRh3IhggFW\
oiGSAWc0EZdyIaIABBIGoiGygCACIVIABBEGoiHCgCACIdaiAKKAIAIgZqIgogAnNBq7OP/AFzQRB3\
Ih5B8ua74wNqIh8gFXNBFHciICAKaiADKAIUIgJqIiFqaiIiIABBHGoiIygCACIWIABBDGoiJCgCAC\
IlaiAJKAIAIglqIgogACkDACIzQiCIp3NBjNGV2HlzQRB3IhRBhd2e23tqIiYgFnNBFHciJyAKaiAD\
KAIMIgpqIiggFHNBGHciKXNBEHciKiAAQRhqIisoAgAiLCAAKAIIIi1qIAMoAgAiFGoiLiAzp3NB/6\
S5iAVzQRB3Ii9B58yn0AZqIjAgLHNBFHciMSAuaiADKAIEIgNqIi4gL3NBGHciLyAwaiIwaiIyIBpz\
QRR3IhogImpqIiIgKnNBGHciKiAyaiIyIBpzQRl3IhogASAPIBcgMCAxc0EZdyIwamoiFyAhIB5zQR\
h3Ih5zQRB3IiEgKSAmaiImaiIpIDBzQRR3IjAgF2pqIhdqaiIxIAwgBCAmICdzQRl3IiYgLmpqIicg\
GHNBEHciGCAeIB9qIh5qIh8gJnNBFHciJiAnamoiJyAYc0EYdyIYc0EQdyIuIAggDSAeICBzQRl3Ih\
4gKGpqIiAgL3NBEHciKCAZaiIZIB5zQRR3Ih4gIGpqIiAgKHNBGHciKCAZaiIZaiIvIBpzQRR3Ihog\
MWpqIjEgLnNBGHciLiAvaiIvIBpzQRl3IhogASAMICIgGSAec0EZdyIZamoiHiAXICFzQRh3IhdzQR\
B3IiEgGCAfaiIYaiIfIBlzQRR3IhkgHmpqIh5qaiIiIAQgICAYICZzQRl3IhhqIAZqIiAgKnNBEHci\
JiAXIClqIhdqIikgGHNBFHciGCAgamoiICAmc0EYdyImc0EQdyIqIA0gDyAXIDBzQRl3IhcgJ2pqIi\
cgKHNBEHciKCAyaiIwIBdzQRR3IhcgJ2pqIicgKHNBGHciKCAwaiIwaiIyIBpzQRR3IhogImpqIiIg\
KnNBGHciKiAyaiIyIBpzQRl3IhogMSAwIBdzQRl3IhdqIAJqIjAgHiAhc0EYdyIec0EQdyIhICYgKW\
oiJmoiKSAXc0EUdyIXIDBqIApqIjBqaiIxIA4gJiAYc0EZdyIYICdqIANqIiYgLnNBEHciJyAeIB9q\
Ih5qIh8gGHNBFHciGCAmamoiJiAnc0EYdyInc0EQdyIuIB4gGXNBGXciGSAgaiAUaiIeIChzQRB3Ii\
AgL2oiKCAZc0EUdyIZIB5qIAlqIh4gIHNBGHciICAoaiIoaiIvIBpzQRR3IhogMWpqIjEgLnNBGHci\
LiAvaiIvIBpzQRl3IhogIiAoIBlzQRl3IhlqIAJqIiIgMCAhc0EYdyIhc0EQdyIoICcgH2oiH2oiJy\
AZc0EUdyIZICJqIAlqIiJqaiIwIA4gHiAfIBhzQRl3IhhqaiIeICpzQRB3Ih8gISApaiIhaiIpIBhz\
QRR3IhggHmogFGoiHiAfc0EYdyIfc0EQdyIqIAQgCCAhIBdzQRl3IhcgJmpqIiEgIHNBEHciICAyai\
ImIBdzQRR3IhcgIWpqIiEgIHNBGHciICAmaiImaiIyIBpzQRR3IhogMGogA2oiMCAqc0EYdyIqIDJq\
IjIgGnNBGXciGiAMIDEgJiAXc0EZdyIXamoiJiAiIChzQRh3IiJzQRB3IiggHyApaiIfaiIpIBdzQR\
R3IhcgJmogBmoiJmpqIjEgDyANIB8gGHNBGXciGCAhamoiHyAuc0EQdyIhICIgJ2oiImoiJyAYc0EU\
dyIYIB9qaiIfICFzQRh3IiFzQRB3Ii4gCyAiIBlzQRl3IhkgHmogCmoiHiAgc0EQdyIgIC9qIiIgGX\
NBFHciGSAeamoiHiAgc0EYdyIgICJqIiJqIi8gGnNBFHciGiAxamoiMSAuc0EYdyIuIC9qIi8gGnNB\
GXciGiAOIAcgMCAiIBlzQRl3IhlqaiIiICYgKHNBGHciJnNBEHciKCAhICdqIiFqIicgGXNBFHciGS\
AiamoiImogBmoiMCAeICEgGHNBGXciGGogCmoiHiAqc0EQdyIhICYgKWoiJmoiKSAYc0EUdyIYIB5q\
IANqIh4gIXNBGHciIXNBEHciKiAMIAUgJiAXc0EZdyIXIB9qaiIfICBzQRB3IiAgMmoiJiAXc0EUdy\
IXIB9qaiIfICBzQRh3IiAgJmoiJmoiMiAac0EUdyIaIDBqIBRqIjAgKnNBGHciKiAyaiIyIBpzQRl3\
IhogBCABIDEgJiAXc0EZdyIXamoiJiAiIChzQRh3IiJzQRB3IiggISApaiIhaiIpIBdzQRR3IhcgJm\
pqIiZqaiIxIAsgISAYc0EZdyIYIB9qIAlqIh8gLnNBEHciISAiICdqIiJqIicgGHNBFHciGCAfamoi\
HyAhc0EYdyIhc0EQdyIuIA0gIiAZc0EZdyIZIB5qIAJqIh4gIHNBEHciICAvaiIiIBlzQRR3IhkgHm\
pqIh4gIHNBGHciICAiaiIiaiIvIBpzQRR3IhogMWpqIjEgLnNBGHciLiAvaiIvIBpzQRl3IhogMCAi\
IBlzQRl3IhlqIAlqIiIgJiAoc0EYdyImc0EQdyIoICEgJ2oiIWoiJyAZc0EUdyIZICJqIAZqIiJqai\
IwIAUgHiAhIBhzQRl3IhhqIAJqIh4gKnNBEHciISAmIClqIiZqIikgGHNBFHciGCAeamoiHiAhc0EY\
dyIhc0EQdyIqIAwgJiAXc0EZdyIXIB9qaiIfICBzQRB3IiAgMmoiJiAXc0EUdyIXIB9qIBRqIh8gIH\
NBGHciICAmaiImaiIyIBpzQRR3IhogMGpqIjAgKnNBGHciKiAyaiIyIBpzQRl3IhogByAxICYgF3NB\
GXciF2ogCmoiJiAiIChzQRh3IiJzQRB3IiggISApaiIhaiIpIBdzQRR3IhcgJmpqIiZqaiIxIA8gIS\
AYc0EZdyIYIB9qaiIfIC5zQRB3IiEgIiAnaiIiaiInIBhzQRR3IhggH2ogA2oiHyAhc0EYdyIhc0EQ\
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\
ciAJQQh2QYD+A3EgCUEYdnJyNgIQIAMgASgAFCIJQRh0IAlBCHRBgID8B3FyIAlBCHZBgP4DcSAJQR\
h2cnI2AhQgAyABKAAcIglBGHQgCUEIdEGAgPwHcXIgCUEIdkGA/gNxIAlBGHZyciIKNgIcIAMgASgA\
ICIJQRh0IAlBCHRBgID8B3FyIAlBCHZBgP4DcSAJQRh2cnIiCzYCICADIAEoABgiCUEYdCAJQQh0QY\
CA/AdxciAJQQh2QYD+A3EgCUEYdnJyIgw2AhggAygCACENIAMoAgQhDiADKAIIIQ8gAygCECEQIAMo\
AgwhESADKAIUIRIgAyABKAAkIglBGHQgCUEIdEGAgPwHcXIgCUEIdkGA/gNxIAlBGHZyciITNgIkIA\
MgASgAKCIJQRh0IAlBCHRBgID8B3FyIAlBCHZBgP4DcSAJQRh2cnIiFDYCKCADIAEoADAiCUEYdCAJ\
QQh0QYCA/AdxciAJQQh2QYD+A3EgCUEYdnJyIhU2AjAgAyABKAAsIglBGHQgCUEIdEGAgPwHcXIgCU\
EIdkGA/gNxIAlBGHZyciIWNgIsIAMgASgANCIJQRh0IAlBCHRBgID8B3FyIAlBCHZBgP4DcSAJQRh2\
cnIiCTYCNCADIAEoADgiF0EYdCAXQQh0QYCA/AdxciAXQQh2QYD+A3EgF0EYdnJyIhc2AjggAyABKA\
A8IhhBGHQgGEEIdEGAgPwHcXIgGEEIdkGA/gNxIBhBGHZyciIYNgI8IAUgEyAKcyAYcyAMIBBzIBVz\
IBEgDnMgE3MgF3NBAXciGXNBAXciGnNBAXciGyAKIBJzIAlzIBAgD3MgFHMgGHNBAXciHHNBAXciHX\
MgGCAJcyAdcyAVIBRzIBxzIBtzQQF3Ih5zQQF3Ih9zIBogHHMgHnMgGSAYcyAbcyAXIBVzIBpzIBYg\
E3MgGXMgCyAMcyAXcyASIBFzIBZzIA8gDXMgC3MgCXNBAXciIHNBAXciIXNBAXciInNBAXciI3NBAX\
ciJHNBAXciJXNBAXciJnNBAXciJyAdICFzIAkgFnMgIXMgFCALcyAgcyAdc0EBdyIoc0EBdyIpcyAc\
ICBzIChzIB9zQQF3IipzQQF3IitzIB8gKXMgK3MgHiAocyAqcyAnc0EBdyIsc0EBdyItcyAmICpzIC\
xzICUgH3MgJ3MgJCAecyAmcyAjIBtzICVzICIgGnMgJHMgISAZcyAjcyAgIBdzICJzIClzQQF3Ii5z\
QQF3Ii9zQQF3IjBzQQF3IjFzQQF3IjJzQQF3IjNzQQF3IjRzQQF3IjUgKyAvcyApICNzIC9zICggIn\
MgLnMgK3NBAXciNnNBAXciN3MgKiAucyA2cyAtc0EBdyI4c0EBdyI5cyAtIDdzIDlzICwgNnMgOHMg\
NXNBAXciOnNBAXciO3MgNCA4cyA6cyAzIC1zIDVzIDIgLHMgNHMgMSAncyAzcyAwICZzIDJzIC8gJX\
MgMXMgLiAkcyAwcyA3c0EBdyI8c0EBdyI9c0EBdyI+c0EBdyI/c0EBdyJAc0EBdyJBc0EBdyJCc0EB\
dyJDIDkgPXMgNyAxcyA9cyA2IDBzIDxzIDlzQQF3IkRzQQF3IkVzIDggPHMgRHMgO3NBAXciRnNBAX\
ciR3MgOyBFcyBHcyA6IERzIEZzIENzQQF3IkhzQQF3IklzIEIgRnMgSHMgQSA7cyBDcyBAIDpzIEJz\
ID8gNXMgQXMgPiA0cyBAcyA9IDNzID9zIDwgMnMgPnMgRXNBAXciSnNBAXciS3NBAXciTHNBAXciTX\
NBAXciTnNBAXciT3NBAXciUHNBAXdqIEYgSnMgRCA+cyBKcyBHc0EBdyJRcyBJc0EBdyJSIEUgP3Mg\
S3MgUXNBAXciUyBMIEEgOiA5IDwgMSAmIB8gKCAhIBcgEyAQIAVBHnciVGogDiAHIAZBHnciECACcy\
AFcSACc2pqIA0gCCAFQQV3aiACIAdzIAZxIAdzampBmfOJ1AVqIg5BBXdqQZnzidQFaiJVQR53IgUg\
DkEedyINcyACIA9qIA4gVCAQc3EgEHNqIFVBBXdqQZnzidQFaiIOcSANc2ogECARaiBVIA0gVHNxIF\
RzaiAOQQV3akGZ84nUBWoiEEEFd2pBmfOJ1AVqIhFBHnciD2ogBSAMaiARIBBBHnciEyAOQR53Igxz\
cSAMc2ogDSASaiAMIAVzIBBxIAVzaiARQQV3akGZ84nUBWoiEUEFd2pBmfOJ1AVqIhJBHnciBSARQR\
53IhBzIAogDGogESAPIBNzcSATc2ogEkEFd2pBmfOJ1AVqIgpxIBBzaiALIBNqIBAgD3MgEnEgD3Nq\
IApBBXdqQZnzidQFaiIMQQV3akGZ84nUBWoiD0EedyILaiAVIApBHnciF2ogCyAMQR53IhNzIBQgEG\
ogDCAXIAVzcSAFc2ogD0EFd2pBmfOJ1AVqIhRxIBNzaiAWIAVqIA8gEyAXc3EgF3NqIBRBBXdqQZnz\
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\
AEEAQcgBEJMBQdACakEAOgAADBELIAFBCGooAgBBAEHIARCTAUGwAmpBADoAAAwQCyABQQhqKAIAQQ\
BByAEQkwFBkAJqQQA6AAAMDwsgAUEIaigCACIDQv6568XpjpWZEDcDECADQoHGlLqW8ermbzcDCCAD\
QgA3AwAgA0HYAGpBADoAAAwOCyABQQhqKAIAIgNC/rnrxemOlZkQNwMQIANCgcaUupbx6uZvNwMIIA\
NCADcDACADQdgAakEAOgAADA0LIAFBCGooAgAiA0IANwMAIANBACkD2IxANwMIIANBEGpBACkD4IxA\
NwMAIANBGGpBACgC6IxANgIAIANB4ABqQQA6AAAMDAsgAUEIaigCACIDQfDDy558NgIYIANC/rnrxe\
mOlZkQNwMQIANCgcaUupbx6uZvNwMIIANCADcDACADQeAAakEAOgAADAsLIAFBCGooAgBBAEHIARCT\
AUHYAmpBADoAAAwKCyABQQhqKAIAQQBByAEQkwFB0AJqQQA6AAAMCQsgAUEIaigCAEEAQcgBEJMBQb\
ACakEAOgAADAgLIAFBCGooAgBBAEHIARCTAUGQAmpBADoAAAwHCyABQQhqKAIAIgNCADcDACADQQAp\
A5CNQDcDCCADQRBqQQApA5iNQDcDACADQRhqQQApA6CNQDcDACADQSBqQQApA6iNQDcDACADQegAak\
EAOgAADAYLIAFBCGooAgAiA0IANwMAIANBACkD8IxANwMIIANBEGpBACkD+IxANwMAIANBGGpBACkD\
gI1ANwMAIANBIGpBACkDiI1ANwMAIANB6ABqQQA6AAAMBQsgAUEIaigCACIDQgA3A0AgA0EAKQPwjU\
A3AwAgA0HIAGpCADcDACADQQhqQQApA/iNQDcDACADQRBqQQApA4COQDcDACADQRhqQQApA4iOQDcD\
ACADQSBqQQApA5COQDcDACADQShqQQApA5iOQDcDACADQTBqQQApA6COQDcDACADQThqQQApA6iOQD\
cDACADQdABakEAOgAADAQLIAFBCGooAgAiA0IANwNAIANBACkDsI1ANwMAIANByABqQgA3AwAgA0EI\
akEAKQO4jUA3AwAgA0EQakEAKQPAjUA3AwAgA0EYakEAKQPIjUA3AwAgA0EgakEAKQPQjUA3AwAgA0\
EoakEAKQPYjUA3AwAgA0EwakEAKQPgjUA3AwAgA0E4akEAKQPojUA3AwAgA0HQAWpBADoAAAwDCyAB\
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\
BkIhhkKAgICAgOA/gyAGQhGGQoCAgIDwH4OEhCEIAkAgBEE/cyIARQ0AIAVBAWpBACAAEJMBGgsgCC\
AJhCEIAkACQCAEQThxQThGDQAgASAINwA4IANBCGogAUEBEBUMAQsgA0EIaiABQQEQFSADQeAAakEM\
akIANwIAIANB4ABqQRRqQgA3AgAgA0HgAGpBHGpCADcCACADQeAAakEkakIANwIAIANB4ABqQSxqQg\
A3AgAgA0HgAGpBNGpCADcCACADQZwBakIANwIAIANCADcCZCADQQA2AmAgA0HgAGogA0HgAGpBBHJB\
f3NqQcQAakEHSRogA0HAADYCYCADQagBaiADQeAAakHEABCUARogA0HQAGogA0GoAWpBNGopAgA3Aw\
AgA0HIAGogA0GoAWpBLGopAgA3AwAgA0HAAGogA0GoAWpBJGopAgA3AwAgA0E4aiADQagBakEcaikC\
ADcDACADQTBqIANBqAFqQRRqKQIANwMAIANBKGogA0GoAWpBDGopAgA3AwAgAyADKQKsATcDICADIA\
g3A1ggA0EIaiADQSBqQQEQFQsgAUEAOgBAIAIgAygCCCIBQRh0IAFBCHRBgID8B3FyIAFBCHZBgP4D\
cSABQRh2cnI2AAAgAiADKAIMIgFBGHQgAUEIdEGAgPwHcXIgAUEIdkGA/gNxIAFBGHZycjYABCACIA\
MoAhAiAUEYdCABQQh0QYCA/AdxciABQQh2QYD+A3EgAUEYdnJyNgAIIAIgAygCFCIBQRh0IAFBCHRB\
gID8B3FyIAFBCHZBgP4DcSABQRh2cnI2AAwgAiADKAIYIgFBGHQgAUEIdEGAgPwHcXIgAUEIdkGA/g\
NxIAFBGHZycjYAECADQfABaiQAC/8GARd/IwBB0AFrIgIkAAJAAkACQCAAKAKQASIDIAF7pyIETQ0A\
IANBf2ohBSAAQfAAaiEGIANBBXQgAGpB1ABqIQcgAkEgakEoaiEIIAJBIGpBCGohCSACQZABakEgai\
EKIAJBEGohCyACQRhqIQwgA0F+akE3SSENA0AgACAFNgKQASACQQhqIgMgB0EoaikAADcDACALIAdB\
MGopAAA3AwAgDCAHQThqKQAANwMAIAIgB0EgaikAADcDACAFRQ0CIAAgBUF/aiIONgKQASAALQBqIQ\
8gCiACKQMANwAAIApBCGogAykDADcAACAKQRBqIAspAwA3AAAgCkEYaiAMKQMANwAAIAJBkAFqQRhq\
IgMgB0EYaiIQKQAANwMAIAJBkAFqQRBqIhEgB0EQaiISKQAANwMAIAJBkAFqQQhqIhMgB0EIaiIUKQ\
AANwMAIAkgBikDADcDACAJQQhqIAZBCGoiFSkDADcDACAJQRBqIAZBEGoiFikDADcDACAJQRhqIAZB\
GGoiFykDADcDACACIAcpAAA3A5ABIAhBOGogAkGQAWpBOGopAwA3AAAgCEEwaiACQZABakEwaikDAD\
cAACAIQShqIAJBkAFqQShqKQMANwAAIAhBIGogCikDADcAACAIQRhqIAMpAwA3AAAgCEEQaiARKQMA\
NwAAIAhBCGogEykDADcAACAIIAIpA5ABNwAAIAJBwAA6AIgBIAIgD0EEciIPOgCJASACQgA3AyAgAy\
AXKQIANwMAIBEgFikCADcDACATIBUpAgA3AwAgAiAGKQIANwOQASACQZABaiAIQcAAQgAgDxAYIAMo\
AgAhAyARKAIAIREgEygCACETIAIoAqwBIQ8gAigCpAEhFSACKAKcASEWIAIoApQBIRcgAigCkAEhGC\
ANRQ0DIAcgGDYCACAHQRxqIA82AgAgECADNgIAIAdBFGogFTYCACASIBE2AgAgB0EMaiAWNgIAIBQg\
EzYCACAHQQRqIBc2AgAgACAFNgKQASAHQWBqIQcgDiEFIA4gBE8NAAsLIAJB0AFqJAAPC0GgkMAAQS\
tBqIXAABByAAsgAiAPNgKsASACIAM2AqgBIAIgFTYCpAEgAiARNgKgASACIBY2ApwBIAIgEzYCmAEg\
AiAXNgKUASACIBg2ApABQfiQwAAgAkGQAWpBkIfAAEHwhsAAEGEAC5wFAQp/IwBBMGsiAyQAIANBJG\
ogATYCACADQQM6ACggA0KAgICAgAQ3AwggAyAANgIgQQAhBCADQQA2AhggA0EANgIQAkACQAJAAkAg\
AigCCCIFDQAgAkEUaigCACIARQ0BIAIoAhAhASAAQQN0IQYgAEF/akH/////AXFBAWohBCACKAIAIQ\
ADQAJAIABBBGooAgAiB0UNACADKAIgIAAoAgAgByADKAIkKAIMEQgADQQLIAEoAgAgA0EIaiABQQRq\
KAIAEQYADQMgAUEIaiEBIABBCGohACAGQXhqIgYNAAwCCwsgAkEMaigCACIBRQ0AIAFBBXQhCCABQX\
9qQf///z9xQQFqIQQgAigCACEAQQAhBgNAAkAgAEEEaigCACIBRQ0AIAMoAiAgACgCACABIAMoAiQo\
AgwRCAANAwsgAyAFIAZqIgFBHGotAAA6ACggAyABQQRqKQIAQiCJNwMIIAFBGGooAgAhCSACKAIQIQ\
pBACELQQAhBwJAAkACQCABQRRqKAIADgMBAAIBCyAJQQN0IQxBACEHIAogDGoiDEEEaigCAEEERw0B\
IAwoAgAoAgAhCQtBASEHCyADIAk2AhQgAyAHNgIQIAFBEGooAgAhBwJAAkACQCABQQxqKAIADgMBAA\
IBCyAHQQN0IQkgCiAJaiIJQQRqKAIAQQRHDQEgCSgCACgCACEHC0EBIQsLIAMgBzYCHCADIAs2Ahgg\
CiABKAIAQQN0aiIBKAIAIANBCGogASgCBBEGAA0CIABBCGohACAIIAZBIGoiBkcNAAsLAkAgBCACKA\
IETw0AIAMoAiAgAigCACAEQQN0aiIBKAIAIAEoAgQgAygCJCgCDBEIAA0BC0EAIQEMAQtBASEBCyAD\
QTBqJAAgAQuaBAIDfwJ+IwBB8AFrIgMkACAAKQMAIQYgASABLQBAIgRqIgVBgAE6AAAgA0EIakEQai\
AAQRhqKAIANgIAIANBEGogAEEQaikCADcDACADIAApAgg3AwggBkIJhiEGIAStQgOGIQcCQCAEQT9z\
IgBFDQAgBUEBakEAIAAQkwEaCyAGIAeEIQYCQAJAIARBOHFBOEYNACABIAY3ADggA0EIaiABEBMMAQ\
sgA0EIaiABEBMgA0HgAGpBDGpCADcCACADQeAAakEUakIANwIAIANB4ABqQRxqQgA3AgAgA0HgAGpB\
JGpCADcCACADQeAAakEsakIANwIAIANB4ABqQTRqQgA3AgAgA0GcAWpCADcCACADQgA3AmQgA0EANg\
JgIANB4ABqIANB4ABqQQRyQX9zakHEAGpBB0kaIANBwAA2AmAgA0GoAWogA0HgAGpBxAAQlAEaIANB\
0ABqIANBqAFqQTRqKQIANwMAIANByABqIANBqAFqQSxqKQIANwMAIANBwABqIANBqAFqQSRqKQIANw\
MAIANBOGogA0GoAWpBHGopAgA3AwAgA0EwaiADQagBakEUaikCADcDACADQShqIANBqAFqQQxqKQIA\
NwMAIAMgAykCrAE3AyAgAyAGNwNYIANBCGogA0EgahATCyABQQA6AEAgAiADKAIINgAAIAIgAykCDD\
cABCACIAMpAhQ3AAwgA0HwAWokAAuKBAEKfyMAQTBrIgYkAEEAIQcgBkEANgIIAkAgAUFAcSIIRQ0A\
QQEhByAGQQE2AgggBiAANgIAIAhBwABGDQBBAiEHIAZBAjYCCCAGIABBwABqNgIEIAhBgAFGDQAgBi\
AAQYABajYCEEH4kMAAIAZBEGpBgIfAAEHwhsAAEGEACyABQT9xIQkCQCAHIAVBBXYiASAHIAFJGyIB\
RQ0AIANBBHIhCiABQQV0IQtBACEDIAYhDANAIAwoAgAhASAGQRBqQRhqIg0gAkEYaikCADcDACAGQR\
BqQRBqIg4gAkEQaikCADcDACAGQRBqQQhqIg8gAkEIaikCADcDACAGIAIpAgA3AxAgBkEQaiABQcAA\
QgAgChAYIAQgA2oiAUEYaiANKQMANwAAIAFBEGogDikDADcAACABQQhqIA8pAwA3AAAgASAGKQMQNw\
AAIAxBBGohDCALIANBIGoiA0cNAAsLAkACQAJAAkAgCUUNACAHQQV0IgIgBUsNASAFIAJrIgFBH00N\
AiAJQSBHDQMgBCACaiICIAAgCGoiASkAADcAACACQRhqIAFBGGopAAA3AAAgAkEQaiABQRBqKQAANw\
AAIAJBCGogAUEIaikAADcAACAHQQFqIQcLIAZBMGokACAHDwsgAiAFQaiEwAAQjAEAC0EgIAFBqITA\
ABCLAQALQSAgCUG4hMAAEGoAC/IDAgN/An4jAEHgAWsiAyQAIAApAwAhBiABIAEtAEAiBGoiBUGAAT\
oAACADQQhqIABBEGopAgA3AwAgAyAAKQIINwMAIAZCCYYhBiAErUIDhiEHAkAgBEE/cyIARQ0AIAVB\
AWpBACAAEJMBGgsgBiAHhCEGAkACQCAEQThxQThGDQAgASAGNwA4IAMgARAdDAELIAMgARAdIANB0A\
BqQQxqQgA3AgAgA0HQAGpBFGpCADcCACADQdAAakEcakIANwIAIANB0ABqQSRqQgA3AgAgA0HQAGpB\
LGpCADcCACADQdAAakE0akIANwIAIANBjAFqQgA3AgAgA0IANwJUIANBADYCUCADQdAAaiADQdAAak\
EEckF/c2pBxABqQQdJGiADQcAANgJQIANBmAFqIANB0ABqQcQAEJQBGiADQcAAaiADQZgBakE0aikC\
ADcDACADQThqIANBmAFqQSxqKQIANwMAIANBMGogA0GYAWpBJGopAgA3AwAgA0EoaiADQZgBakEcai\
kCADcDACADQSBqIANBmAFqQRRqKQIANwMAIANBGGogA0GYAWpBDGopAgA3AwAgAyADKQKcATcDECAD\
IAY3A0ggAyADQRBqEB0LIAFBADoAQCACIAMpAwA3AAAgAiADKQMINwAIIANB4AFqJAAL8gMCA38Cfi\
MAQeABayIDJAAgACkDACEGIAEgAS0AQCIEaiIFQYABOgAAIANBCGogAEEQaikCADcDACADIAApAgg3\
AwAgBkIJhiEGIAStQgOGIQcCQCAEQT9zIgBFDQAgBUEBakEAIAAQkwEaCyAGIAeEIQYCQAJAIARBOH\
FBOEYNACABIAY3ADggAyABEBsMAQsgAyABEBsgA0HQAGpBDGpCADcCACADQdAAakEUakIANwIAIANB\
0ABqQRxqQgA3AgAgA0HQAGpBJGpCADcCACADQdAAakEsakIANwIAIANB0ABqQTRqQgA3AgAgA0GMAW\
pCADcCACADQgA3AlQgA0EANgJQIANB0ABqIANB0ABqQQRyQX9zakHEAGpBB0kaIANBwAA2AlAgA0GY\
AWogA0HQAGpBxAAQlAEaIANBwABqIANBmAFqQTRqKQIANwMAIANBOGogA0GYAWpBLGopAgA3AwAgA0\
EwaiADQZgBakEkaikCADcDACADQShqIANBmAFqQRxqKQIANwMAIANBIGogA0GYAWpBFGopAgA3AwAg\
A0EYaiADQZgBakEMaikCADcDACADIAMpApwBNwMQIAMgBjcDSCADIANBEGoQGwsgAUEAOgBAIAIgAy\
kDADcAACACIAMpAwg3AAggA0HgAWokAAvnAwIEfwJ+IwBB0AFrIgMkACABIAEtAEAiBGoiBUEBOgAA\
IAApAwBCCYYhByAErUIDhiEIAkAgBEE/cyIGRQ0AIAVBAWpBACAGEJMBGgsgByAIhCEHAkACQCAEQT\
hxQThGDQAgASAHNwA4IABBCGogARAWDAELIABBCGoiBCABEBYgA0HAAGpBDGpCADcCACADQcAAakEU\
akIANwIAIANBwABqQRxqQgA3AgAgA0HAAGpBJGpCADcCACADQcAAakEsakIANwIAIANBwABqQTRqQg\
A3AgAgA0H8AGpCADcCACADQgA3AkQgA0EANgJAIANBwABqIANBwABqQQRyQX9zakHEAGpBB0kaIANB\
wAA2AkAgA0GIAWogA0HAAGpBxAAQlAEaIANBMGogA0GIAWpBNGopAgA3AwAgA0EoaiADQYgBakEsai\
kCADcDACADQSBqIANBiAFqQSRqKQIANwMAIANBGGogA0GIAWpBHGopAgA3AwAgA0EQaiADQYgBakEU\
aikCADcDACADQQhqIANBiAFqQQxqKQIANwMAIAMgAykCjAE3AwAgAyAHNwM4IAQgAxAWCyABQQA6AE\
AgAiAAKQMINwAAIAIgAEEQaikDADcACCACIABBGGopAwA3ABAgA0HQAWokAAuAAwEFfwJAAkACQCAB\
QQlJDQBBACECQc3/eyABQRAgAUEQSxsiAWsgAE0NASABQRAgAEELakF4cSAAQQtJGyIDakEMahAZIg\
BFDQEgAEF4aiECAkACQCABQX9qIgQgAHENACACIQEMAQsgAEF8aiIFKAIAIgZBeHEgBCAAakEAIAFr\
cUF4aiIAQQAgASAAIAJrQRBLG2oiASACayIAayEEAkAgBkEDcUUNACABIAEoAgRBAXEgBHJBAnI2Ag\
QgASAEaiIEIAQoAgRBAXI2AgQgBSAFKAIAQQFxIAByQQJyNgIAIAIgAGoiBCAEKAIEQQFyNgIEIAIg\
ABAkDAELIAIoAgAhAiABIAQ2AgQgASACIABqNgIACyABKAIEIgBBA3FFDQIgAEF4cSICIANBEGpNDQ\
IgASAAQQFxIANyQQJyNgIEIAEgA2oiACACIANrIgNBA3I2AgQgASACaiICIAIoAgRBAXI2AgQgACAD\
ECQMAgsgABAZIQILIAIPCyABQQhqC4sDAQJ/IwBBkAFrIgAkAAJAQfAAEBkiAUUNACAAQQxqQgA3Ag\
AgAEEUakIANwIAIABBHGpCADcCACAAQSRqQgA3AgAgAEEsakIANwIAIABBNGpCADcCACAAQTxqQgA3\
AgAgAEIANwIEIABBADYCACAAIABBBHJBf3NqQcQAakEHSRogAEHAADYCACAAQcgAaiAAQcQAEJQBGi\
ABQeAAaiAAQcgAakE8aikCADcAACABQdgAaiAAQcgAakE0aikCADcAACABQdAAaiAAQcgAakEsaikC\
ADcAACABQcgAaiAAQcgAakEkaikCADcAACABQcAAaiAAQcgAakEcaikCADcAACABQThqIABByABqQR\
RqKQIANwAAIAFBMGogAEHIAGpBDGopAgA3AAAgASAAKQJMNwAoIAFCADcDACABQegAakEAOgAAIAFB\
ACkDkI1ANwMIIAFBEGpBACkDmI1ANwMAIAFBGGpBACkDoI1ANwMAIAFBIGpBACkDqI1ANwMAIABBkA\
FqJAAgAQ8LAAuLAwECfyMAQZABayIAJAACQEHwABAZIgFFDQAgAEEMakIANwIAIABBFGpCADcCACAA\
QRxqQgA3AgAgAEEkakIANwIAIABBLGpCADcCACAAQTRqQgA3AgAgAEE8akIANwIAIABCADcCBCAAQQ\
A2AgAgACAAQQRyQX9zakHEAGpBB0kaIABBwAA2AgAgAEHIAGogAEHEABCUARogAUHgAGogAEHIAGpB\
PGopAgA3AAAgAUHYAGogAEHIAGpBNGopAgA3AAAgAUHQAGogAEHIAGpBLGopAgA3AAAgAUHIAGogAE\
HIAGpBJGopAgA3AAAgAUHAAGogAEHIAGpBHGopAgA3AAAgAUE4aiAAQcgAakEUaikCADcAACABQTBq\
IABByABqQQxqKQIANwAAIAEgACkCTDcAKCABQgA3AwAgAUHoAGpBADoAACABQQApA/CMQDcDCCABQR\
BqQQApA/iMQDcDACABQRhqQQApA4CNQDcDACABQSBqQQApA4iNQDcDACAAQZABaiQAIAEPCwAL+wIB\
An8jAEGQAWsiACQAAkBB6AAQGSIBRQ0AIABBDGpCADcCACAAQRRqQgA3AgAgAEEcakIANwIAIABBJG\
pCADcCACAAQSxqQgA3AgAgAEE0akIANwIAIABBPGpCADcCACAAQgA3AgQgAEEANgIAIAAgAEEEckF/\
c2pBxABqQQdJGiAAQcAANgIAIABByABqIABBxAAQlAEaIAFB2ABqIABByABqQTxqKQIANwAAIAFB0A\
BqIABByABqQTRqKQIANwAAIAFByABqIABByABqQSxqKQIANwAAIAFBwABqIABByABqQSRqKQIANwAA\
IAFBOGogAEHIAGpBHGopAgA3AAAgAUEwaiAAQcgAakEUaikCADcAACABQShqIABByABqQQxqKQIANw\
AAIAEgACkCTDcAICABQgA3AwAgAUHgAGpBADoAACABQQApA9iMQDcDCCABQRBqQQApA+CMQDcDACAB\
QRhqQQAoAuiMQDYCACAAQZABaiQAIAEPCwAL+wIBAn8jAEGQAWsiACQAAkBB6AAQGSIBRQ0AIAFCAD\
cDACABQQApA6iRQDcDCCABQRBqQQApA7CRQDcDACABQRhqQQApA7iRQDcDACAAQQxqQgA3AgAgAEEU\
akIANwIAIABBHGpCADcCACAAQSRqQgA3AgAgAEEsakIANwIAIABBNGpCADcCACAAQTxqQgA3AgAgAE\
IANwIEIABBADYCACAAIABBBHJBf3NqQcQAakEHSRogAEHAADYCACAAQcgAaiAAQcQAEJQBGiABQdgA\
aiAAQcgAakE8aikCADcAACABQdAAaiAAQcgAakE0aikCADcAACABQcgAaiAAQcgAakEsaikCADcAAC\
ABQcAAaiAAQcgAakEkaikCADcAACABQThqIABByABqQRxqKQIANwAAIAFBMGogAEHIAGpBFGopAgA3\
AAAgAUEoaiAAQcgAakEMaikCADcAACABIAApAkw3ACAgAUHgAGpBADoAACAAQZABaiQAIAEPCwALqQ\
MBAX8gAiACLQCoASIDakEAQagBIANrEJMBIQMgAkEAOgCoASADQR86AAAgAiACLQCnAUGAAXI6AKcB\
IAEgASkDACACKQAAhTcDACABIAEpAwggAikACIU3AwggASABKQMQIAIpABCFNwMQIAEgASkDGCACKQ\
AYhTcDGCABIAEpAyAgAikAIIU3AyAgASABKQMoIAIpACiFNwMoIAEgASkDMCACKQAwhTcDMCABIAEp\
AzggAikAOIU3AzggASABKQNAIAIpAECFNwNAIAEgASkDSCACKQBIhTcDSCABIAEpA1AgAikAUIU3A1\
AgASABKQNYIAIpAFiFNwNYIAEgASkDYCACKQBghTcDYCABIAEpA2ggAikAaIU3A2ggASABKQNwIAIp\
AHCFNwNwIAEgASkDeCACKQB4hTcDeCABIAEpA4ABIAIpAIABhTcDgAEgASABKQOIASACKQCIAYU3A4\
gBIAEgASkDkAEgAikAkAGFNwOQASABIAEpA5gBIAIpAJgBhTcDmAEgASABKQOgASACKQCgAYU3A6AB\
IAEQJSAAIAFByAEQlAEaC+8CAQN/AkACQAJAAkAgAC0AaCIDRQ0AAkAgA0HBAE8NACAAQShqIgQgA2\
ogAUHAACADayIDIAIgAyACSRsiAxCUARogACAALQBoIANqIgU6AGggASADaiEBAkAgAiADayICDQBB\
ACECDAMLIABBCGogBEHAACAAKQMAIAAtAGogAEHpAGoiAy0AAEVyEBggBEEAQcEAEJMBGiADIAMtAA\
BBAWo6AAAMAQsgA0HAAEGIhMAAEIwBAAtBACEDIAJBwQBJDQEgAEEIaiEEIABB6QBqIgMtAAAhBQNA\
IAQgAUHAACAAKQMAIAAtAGogBUH/AXFFchAYIAMgAy0AAEEBaiIFOgAAIAFBwABqIQEgAkFAaiICQc\
AASw0ACyAALQBoIQULIAVB/wFxIgNBwQBPDQELIAAgA2pBKGogAUHAACADayIDIAIgAyACSRsiAhCU\
ARogACAALQBoIAJqOgBoIAAPCyADQcAAQYiEwAAQjAEAC50DAQJ/IwBBEGsiAyQAIAEgAS0AkAEiBG\
pBAEGQASAEaxCTASEEIAFBADoAkAEgBEEBOgAAIAEgAS0AjwFBgAFyOgCPASAAIAApAwAgASkAAIU3\
AwAgACAAKQMIIAEpAAiFNwMIIAAgACkDECABKQAQhTcDECAAIAApAxggASkAGIU3AxggACAAKQMgIA\
EpACCFNwMgIAAgACkDKCABKQAohTcDKCAAIAApAzAgASkAMIU3AzAgACAAKQM4IAEpADiFNwM4IAAg\
ACkDQCABKQBAhTcDQCAAIAApA0ggASkASIU3A0ggACAAKQNQIAEpAFCFNwNQIAAgACkDWCABKQBYhT\
cDWCAAIAApA2AgASkAYIU3A2AgACAAKQNoIAEpAGiFNwNoIAAgACkDcCABKQBwhTcDcCAAIAApA3gg\
ASkAeIU3A3ggACAAKQOAASABKQCAAYU3A4ABIAAgACkDiAEgASkAiAGFNwOIASAAECUgAiAAKQMANw\
AAIAIgACkDCDcACCACIAApAxA3ABAgAiAAKQMYPgAYIANBEGokAAudAwECfyMAQRBrIgMkACABIAEt\
AJABIgRqQQBBkAEgBGsQkwEhBCABQQA6AJABIARBBjoAACABIAEtAI8BQYABcjoAjwEgACAAKQMAIA\
EpAACFNwMAIAAgACkDCCABKQAIhTcDCCAAIAApAxAgASkAEIU3AxAgACAAKQMYIAEpABiFNwMYIAAg\
ACkDICABKQAghTcDICAAIAApAyggASkAKIU3AyggACAAKQMwIAEpADCFNwMwIAAgACkDOCABKQA4hT\
cDOCAAIAApA0AgASkAQIU3A0AgACAAKQNIIAEpAEiFNwNIIAAgACkDUCABKQBQhTcDUCAAIAApA1gg\
ASkAWIU3A1ggACAAKQNgIAEpAGCFNwNgIAAgACkDaCABKQBohTcDaCAAIAApA3AgASkAcIU3A3AgAC\
AAKQN4IAEpAHiFNwN4IAAgACkDgAEgASkAgAGFNwOAASAAIAApA4gBIAEpAIgBhTcDiAEgABAlIAIg\
ACkDADcAACACIAApAwg3AAggAiAAKQMQNwAQIAIgACkDGD4AGCADQRBqJAALlgMBBH8jAEGQBGsiAy\
QAAkAgAkUNACACQagBbCEEIANB4AJqQQRyIQUgA0GwAWogA0GwAWpBBHIiBkF/c2pBrAFqQQdJGgNA\
IAAoAgAhAiADQQA2ArABIAZBAEGoARCTARogA0GoATYCsAEgA0HgAmogA0GwAWpBrAEQlAEaIANBCG\
ogBUGoARCUARogAyACKQMANwMIIAMgAikDCDcDECADIAIpAxA3AxggAyACKQMYNwMgIAMgAikDIDcD\
KCADIAIpAyg3AzAgAyACKQMwNwM4IAMgAikDODcDQCADIAIpA0A3A0ggAyACKQNINwNQIAMgAikDUD\
cDWCADIAIpA1g3A2AgAyACKQNgNwNoIAMgAikDaDcDcCADIAIpA3A3A3ggAyACKQN4NwOAASADIAIp\
A4ABNwOIASADIAIpA4gBNwOQASADIAIpA5ABNwOYASADIAIpA5gBNwOgASADIAIpA6ABNwOoASACEC\
UgASADQQhqQagBEJQBGiABQagBaiEBIARB2H5qIgQNAAsLIANBkARqJAAL+gIBAn8jAEGQAWsiACQA\
AkBB6AAQGSIBRQ0AIABBDGpCADcCACAAQRRqQgA3AgAgAEEcakIANwIAIABBJGpCADcCACAAQSxqQg\
A3AgAgAEE0akIANwIAIABBPGpCADcCACAAQgA3AgQgAEEANgIAIAAgAEEEckF/c2pBxABqQQdJGiAA\
QcAANgIAIABByABqIABBxAAQlAEaIAFB2ABqIABByABqQTxqKQIANwAAIAFB0ABqIABByABqQTRqKQ\
IANwAAIAFByABqIABByABqQSxqKQIANwAAIAFBwABqIABByABqQSRqKQIANwAAIAFBOGogAEHIAGpB\
HGopAgA3AAAgAUEwaiAAQcgAakEUaikCADcAACABQShqIABByABqQQxqKQIANwAAIAEgACkCTDcAIC\
ABQfDDy558NgIYIAFC/rnrxemOlZkQNwMQIAFCgcaUupbx6uZvNwMIIAFCADcDACABQeAAakEAOgAA\
IABBkAFqJAAgAQ8LAAvkAgEEfyMAQZAEayIDJAAgAyAANgIEIABByAFqIQQCQAJAAkACQAJAIABB8A\
JqLQAAIgVFDQBBqAEgBWsiBiACSw0BIAEgBCAFaiAGEJQBIAZqIQEgAiAGayECCyACIAJBqAFuIgZB\
qAFsIgVJDQEgA0EEaiABIAYQOgJAIAIgBWsiAg0AQQAhAgwECyADQQA2ArABIANBsAFqIANBsAFqQQ\
RyQQBBqAEQkwFBf3NqQawBakEHSRogA0GoATYCsAEgA0HgAmogA0GwAWpBrAEQlAEaIANBCGogA0Hg\
AmpBBHJBqAEQlAEaIANBBGogA0EIakEBEDogAkGpAU8NAiABIAVqIANBCGogAhCUARogBCADQQhqQa\
gBEJQBGgwDCyABIAQgBWogAhCUARogBSACaiECDAILQbSMwABBI0GUjMAAEHIACyACQagBQaSMwAAQ\
iwEACyAAIAI6APACIANBkARqJAAL5AIBBH8jAEGwA2siAyQAIAMgADYCBCAAQcgBaiEEAkACQAJAAk\
ACQCAAQdACai0AACIFRQ0AQYgBIAVrIgYgAksNASABIAQgBWogBhCUASAGaiEBIAIgBmshAgsgAiAC\
QYgBbiIGQYgBbCIFSQ0BIANBBGogASAGEEMCQCACIAVrIgINAEEAIQIMBAsgA0EANgKQASADQZABai\
ADQZABakEEckEAQYgBEJMBQX9zakGMAWpBB0kaIANBiAE2ApABIANBoAJqIANBkAFqQYwBEJQBGiAD\
QQhqIANBoAJqQQRyQYgBEJQBGiADQQRqIANBCGpBARBDIAJBiQFPDQIgASAFaiADQQhqIAIQlAEaIA\
QgA0EIakGIARCUARoMAwsgASAEIAVqIAIQlAEaIAUgAmohAgwCC0G0jMAAQSNBlIzAABByAAsgAkGI\
AUGkjMAAEIsBAAsgACACOgDQAiADQbADaiQAC5EDAQF/AkAgAkUNACABIAJBqAFsaiEDIAAoAgAhAg\
NAIAIgAikDACABKQAAhTcDACACIAIpAwggASkACIU3AwggAiACKQMQIAEpABCFNwMQIAIgAikDGCAB\
KQAYhTcDGCACIAIpAyAgASkAIIU3AyAgAiACKQMoIAEpACiFNwMoIAIgAikDMCABKQAwhTcDMCACIA\
IpAzggASkAOIU3AzggAiACKQNAIAEpAECFNwNAIAIgAikDSCABKQBIhTcDSCACIAIpA1AgASkAUIU3\
A1AgAiACKQNYIAEpAFiFNwNYIAIgAikDYCABKQBghTcDYCACIAIpA2ggASkAaIU3A2ggAiACKQNwIA\
EpAHCFNwNwIAIgAikDeCABKQB4hTcDeCACIAIpA4ABIAEpAIABhTcDgAEgAiACKQOIASABKQCIAYU3\
A4gBIAIgAikDkAEgASkAkAGFNwOQASACIAIpA5gBIAEpAJgBhTcDmAEgAiACKQOgASABKQCgAYU3A6\
ABIAIQJSABQagBaiIBIANHDQALCwvuAgECfyMAQZABayIAJAACQEHgABAZIgFFDQAgAEEMakIANwIA\
IABBFGpCADcCACAAQRxqQgA3AgAgAEEkakIANwIAIABBLGpCADcCACAAQTRqQgA3AgAgAEE8akIANw\
IAIABCADcCBCAAQQA2AgAgACAAQQRyQX9zakHEAGpBB0kaIABBwAA2AgAgAEHIAGogAEHEABCUARog\
AUHQAGogAEHIAGpBPGopAgA3AAAgAUHIAGogAEHIAGpBNGopAgA3AAAgAUHAAGogAEHIAGpBLGopAg\
A3AAAgAUE4aiAAQcgAakEkaikCADcAACABQTBqIABByABqQRxqKQIANwAAIAFBKGogAEHIAGpBFGop\
AgA3AAAgAUEgaiAAQcgAakEMaikCADcAACABIAApAkw3ABggAUL+uevF6Y6VmRA3AxAgAUKBxpS6lv\
Hq5m83AwggAUIANwMAIAFB2ABqQQA6AAAgAEGQAWokACABDwsAC7wCAQh/AkACQCACQQ9LDQAgACED\
DAELIABBACAAa0EDcSIEaiEFAkAgBEUNACAAIQMgASEGA0AgAyAGLQAAOgAAIAZBAWohBiADQQFqIg\
MgBUkNAAsLIAUgAiAEayIHQXxxIghqIQMCQAJAIAEgBGoiCUEDcSIGRQ0AIAhBAUgNASAJQXxxIgpB\
BGohAUEAIAZBA3QiAmtBGHEhBCAKKAIAIQYDQCAFIAYgAnYgASgCACIGIAR0cjYCACABQQRqIQEgBU\
EEaiIFIANJDQAMAgsLIAhBAUgNACAJIQEDQCAFIAEoAgA2AgAgAUEEaiEBIAVBBGoiBSADSQ0ACwsg\
B0EDcSECIAkgCGohAQsCQCACRQ0AIAMgAmohBQNAIAMgAS0AADoAACABQQFqIQEgA0EBaiIDIAVJDQ\
ALCyAAC/oCAQF/IAEgAS0AiAEiA2pBAEGIASADaxCTASEDIAFBADoAiAEgA0EBOgAAIAEgAS0AhwFB\
gAFyOgCHASAAIAApAwAgASkAAIU3AwAgACAAKQMIIAEpAAiFNwMIIAAgACkDECABKQAQhTcDECAAIA\
ApAxggASkAGIU3AxggACAAKQMgIAEpACCFNwMgIAAgACkDKCABKQAohTcDKCAAIAApAzAgASkAMIU3\
AzAgACAAKQM4IAEpADiFNwM4IAAgACkDQCABKQBAhTcDQCAAIAApA0ggASkASIU3A0ggACAAKQNQIA\
EpAFCFNwNQIAAgACkDWCABKQBYhTcDWCAAIAApA2AgASkAYIU3A2AgACAAKQNoIAEpAGiFNwNoIAAg\
ACkDcCABKQBwhTcDcCAAIAApA3ggASkAeIU3A3ggACAAKQOAASABKQCAAYU3A4ABIAAQJSACIAApAw\
A3AAAgAiAAKQMINwAIIAIgACkDEDcAECACIAApAxg3ABgL+gIBAX8gASABLQCIASIDakEAQYgBIANr\
EJMBIQMgAUEAOgCIASADQQY6AAAgASABLQCHAUGAAXI6AIcBIAAgACkDACABKQAAhTcDACAAIAApAw\
ggASkACIU3AwggACAAKQMQIAEpABCFNwMQIAAgACkDGCABKQAYhTcDGCAAIAApAyAgASkAIIU3AyAg\
ACAAKQMoIAEpACiFNwMoIAAgACkDMCABKQAwhTcDMCAAIAApAzggASkAOIU3AzggACAAKQNAIAEpAE\
CFNwNAIAAgACkDSCABKQBIhTcDSCAAIAApA1AgASkAUIU3A1AgACAAKQNYIAEpAFiFNwNYIAAgACkD\
YCABKQBghTcDYCAAIAApA2ggASkAaIU3A2ggACAAKQNwIAEpAHCFNwNwIAAgACkDeCABKQB4hTcDeC\
AAIAApA4ABIAEpAIABhTcDgAEgABAlIAIgACkDADcAACACIAApAwg3AAggAiAAKQMQNwAQIAIgACkD\
GDcAGAvmAgEEfyMAQbADayIDJAACQCACRQ0AIAJBiAFsIQQgA0GgAmpBBHIhBSADQZABaiADQZABak\
EEciIGQX9zakGMAWpBB0kaA0AgACgCACECIANBADYCkAEgBkEAQYgBEJMBGiADQYgBNgKQASADQaAC\
aiADQZABakGMARCUARogA0EIaiAFQYgBEJQBGiADIAIpAwA3AwggAyACKQMINwMQIAMgAikDEDcDGC\
ADIAIpAxg3AyAgAyACKQMgNwMoIAMgAikDKDcDMCADIAIpAzA3AzggAyACKQM4NwNAIAMgAikDQDcD\
SCADIAIpA0g3A1AgAyACKQNQNwNYIAMgAikDWDcDYCADIAIpA2A3A2ggAyACKQNoNwNwIAMgAikDcD\
cDeCADIAIpA3g3A4ABIAMgAikDgAE3A4gBIAIQJSABIANBCGpBiAEQlAEaIAFBiAFqIQEgBEH4fmoi\
BA0ACwsgA0GwA2okAAvYAgEBfwJAIAJFDQAgASACQZABbGohAyAAKAIAIQIDQCACIAIpAwAgASkAAI\
U3AwAgAiACKQMIIAEpAAiFNwMIIAIgAikDECABKQAQhTcDECACIAIpAxggASkAGIU3AxggAiACKQMg\
IAEpACCFNwMgIAIgAikDKCABKQAohTcDKCACIAIpAzAgASkAMIU3AzAgAiACKQM4IAEpADiFNwM4IA\
IgAikDQCABKQBAhTcDQCACIAIpA0ggASkASIU3A0ggAiACKQNQIAEpAFCFNwNQIAIgAikDWCABKQBY\
hTcDWCACIAIpA2AgASkAYIU3A2AgAiACKQNoIAEpAGiFNwNoIAIgAikDcCABKQBwhTcDcCACIAIpA3\
ggASkAeIU3A3ggAiACKQOAASABKQCAAYU3A4ABIAIgAikDiAEgASkAiAGFNwOIASACECUgAUGQAWoi\
ASADRw0ACwsL3QIBAX8gAiACLQCIASIDakEAQYgBIANrEJMBIQMgAkEAOgCIASADQR86AAAgAiACLQ\
CHAUGAAXI6AIcBIAEgASkDACACKQAAhTcDACABIAEpAwggAikACIU3AwggASABKQMQIAIpABCFNwMQ\
IAEgASkDGCACKQAYhTcDGCABIAEpAyAgAikAIIU3AyAgASABKQMoIAIpACiFNwMoIAEgASkDMCACKQ\
AwhTcDMCABIAEpAzggAikAOIU3AzggASABKQNAIAIpAECFNwNAIAEgASkDSCACKQBIhTcDSCABIAEp\
A1AgAikAUIU3A1AgASABKQNYIAIpAFiFNwNYIAEgASkDYCACKQBghTcDYCABIAEpA2ggAikAaIU3A2\
ggASABKQNwIAIpAHCFNwNwIAEgASkDeCACKQB4hTcDeCABIAEpA4ABIAIpAIABhTcDgAEgARAlIAAg\
AUHIARCUARoLswIBBH9BHyECAkAgAUH///8HSw0AIAFBBiABQQh2ZyICa3ZBAXEgAkEBdGtBPmohAg\
sgAEIANwIQIAAgAjYCHCACQQJ0QcTUwABqIQMCQAJAAkACQAJAQQAoArjSQCIEQQEgAnQiBXFFDQAg\
AygCACIEKAIEQXhxIAFHDQEgBCECDAILQQAgBCAFcjYCuNJAIAMgADYCACAAIAM2AhgMAwsgAUEAQR\
kgAkEBdmtBH3EgAkEfRht0IQMDQCAEIANBHXZBBHFqQRBqIgUoAgAiAkUNAiADQQF0IQMgAiEEIAIo\
AgRBeHEgAUcNAAsLIAIoAggiAyAANgIMIAIgADYCCCAAQQA2AhggACACNgIMIAAgAzYCCA8LIAUgAD\
YCACAAIAQ2AhgLIAAgADYCDCAAIAA2AggLugIBBX8gACgCGCEBAkACQAJAIAAoAgwiAiAARw0AIABB\
FEEQIABBFGoiAigCACIDG2ooAgAiBA0BQQAhAgwCCyAAKAIIIgQgAjYCDCACIAQ2AggMAQsgAiAAQR\
BqIAMbIQMDQCADIQUCQCAEIgJBFGoiAygCACIEDQAgAkEQaiEDIAIoAhAhBAsgBA0ACyAFQQA2AgAL\
AkAgAUUNAAJAAkAgACgCHEECdEHE1MAAaiIEKAIAIABGDQAgAUEQQRQgASgCECAARhtqIAI2AgAgAg\
0BDAILIAQgAjYCACACDQBBAEEAKAK40kBBfiAAKAIcd3E2ArjSQA8LIAIgATYCGAJAIAAoAhAiBEUN\
ACACIAQ2AhAgBCACNgIYCyAAQRRqKAIAIgRFDQAgAkEUaiAENgIAIAQgAjYCGA8LC8UCAQF/AkAgAk\
UNACABIAJBiAFsaiEDIAAoAgAhAgNAIAIgAikDACABKQAAhTcDACACIAIpAwggASkACIU3AwggAiAC\
KQMQIAEpABCFNwMQIAIgAikDGCABKQAYhTcDGCACIAIpAyAgASkAIIU3AyAgAiACKQMoIAEpACiFNw\
MoIAIgAikDMCABKQAwhTcDMCACIAIpAzggASkAOIU3AzggAiACKQNAIAEpAECFNwNAIAIgAikDSCAB\
KQBIhTcDSCACIAIpA1AgASkAUIU3A1AgAiACKQNYIAEpAFiFNwNYIAIgAikDYCABKQBghTcDYCACIA\
IpA2ggASkAaIU3A2ggAiACKQNwIAEpAHCFNwNwIAIgAikDeCABKQB4hTcDeCACIAIpA4ABIAEpAIAB\
hTcDgAEgAhAlIAFBiAFqIgEgA0cNAAsLC8cCAQF/IAEgAS0AaCIDakEAQegAIANrEJMBIQMgAUEAOg\
BoIANBAToAACABIAEtAGdBgAFyOgBnIAAgACkDACABKQAAhTcDACAAIAApAwggASkACIU3AwggACAA\
KQMQIAEpABCFNwMQIAAgACkDGCABKQAYhTcDGCAAIAApAyAgASkAIIU3AyAgACAAKQMoIAEpACiFNw\
MoIAAgACkDMCABKQAwhTcDMCAAIAApAzggASkAOIU3AzggACAAKQNAIAEpAECFNwNAIAAgACkDSCAB\
KQBIhTcDSCAAIAApA1AgASkAUIU3A1AgACAAKQNYIAEpAFiFNwNYIAAgACkDYCABKQBghTcDYCAAEC\
UgAiAAKQMANwAAIAIgACkDCDcACCACIAApAxA3ABAgAiAAKQMYNwAYIAIgACkDIDcAICACIAApAyg3\
ACgLxwIBAX8gASABLQBoIgNqQQBB6AAgA2sQkwEhAyABQQA6AGggA0EGOgAAIAEgAS0AZ0GAAXI6AG\
cgACAAKQMAIAEpAACFNwMAIAAgACkDCCABKQAIhTcDCCAAIAApAxAgASkAEIU3AxAgACAAKQMYIAEp\
ABiFNwMYIAAgACkDICABKQAghTcDICAAIAApAyggASkAKIU3AyggACAAKQMwIAEpADCFNwMwIAAgAC\
kDOCABKQA4hTcDOCAAIAApA0AgASkAQIU3A0AgACAAKQNIIAEpAEiFNwNIIAAgACkDUCABKQBQhTcD\
UCAAIAApA1ggASkAWIU3A1ggACAAKQNgIAEpAGCFNwNgIAAQJSACIAApAwA3AAAgAiAAKQMINwAIIA\
IgACkDEDcAECACIAApAxg3ABggAiAAKQMgNwAgIAIgACkDKDcAKAubAgEBfyABIAEtAEgiA2pBAEHI\
ACADaxCTASEDIAFBADoASCADQQE6AAAgASABLQBHQYABcjoARyAAIAApAwAgASkAAIU3AwAgACAAKQ\
MIIAEpAAiFNwMIIAAgACkDECABKQAQhTcDECAAIAApAxggASkAGIU3AxggACAAKQMgIAEpACCFNwMg\
IAAgACkDKCABKQAohTcDKCAAIAApAzAgASkAMIU3AzAgACAAKQM4IAEpADiFNwM4IAAgACkDQCABKQ\
BAhTcDQCAAECUgAiAAKQMANwAAIAIgACkDCDcACCACIAApAxA3ABAgAiAAKQMYNwAYIAIgACkDIDcA\
ICACIAApAyg3ACggAiAAKQMwNwAwIAIgACkDODcAOAubAgEBfyABIAEtAEgiA2pBAEHIACADaxCTAS\
EDIAFBADoASCADQQY6AAAgASABLQBHQYABcjoARyAAIAApAwAgASkAAIU3AwAgACAAKQMIIAEpAAiF\
NwMIIAAgACkDECABKQAQhTcDECAAIAApAxggASkAGIU3AxggACAAKQMgIAEpACCFNwMgIAAgACkDKC\
ABKQAohTcDKCAAIAApAzAgASkAMIU3AzAgACAAKQM4IAEpADiFNwM4IAAgACkDQCABKQBAhTcDQCAA\
ECUgAiAAKQMANwAAIAIgACkDCDcACCACIAApAxA3ABAgAiAAKQMYNwAYIAIgACkDIDcAICACIAApAy\
g3ACggAiAAKQMwNwAwIAIgACkDODcAOAuIAgECfyMAQZACayIAJAACQEHYARAZIgFFDQAgAEEANgIA\
IAAgAEEEckEAQYABEJMBQX9zakGEAWpBB0kaIABBgAE2AgAgAEGIAWogAEGEARCUARogAUHQAGogAE\
GIAWpBBHJBgAEQlAEaIAFByABqQgA3AwAgAUIANwNAIAFB0AFqQQA6AAAgAUEAKQOwjUA3AwAgAUEI\
akEAKQO4jUA3AwAgAUEQakEAKQPAjUA3AwAgAUEYakEAKQPIjUA3AwAgAUEgakEAKQPQjUA3AwAgAU\
EoakEAKQPYjUA3AwAgAUEwakEAKQPgjUA3AwAgAUE4akEAKQPojUA3AwAgAEGQAmokACABDwsAC4gC\
AQJ/IwBBkAJrIgAkAAJAQdgBEBkiAUUNACAAQQA2AgAgACAAQQRyQQBBgAEQkwFBf3NqQYQBakEHSR\
ogAEGAATYCACAAQYgBaiAAQYQBEJQBGiABQdAAaiAAQYgBakEEckGAARCUARogAUHIAGpCADcDACAB\
QgA3A0AgAUHQAWpBADoAACABQQApA/CNQDcDACABQQhqQQApA/iNQDcDACABQRBqQQApA4COQDcDAC\
ABQRhqQQApA4iOQDcDACABQSBqQQApA5COQDcDACABQShqQQApA5iOQDcDACABQTBqQQApA6COQDcD\
ACABQThqQQApA6iOQDcDACAAQZACaiQAIAEPCwALggIBAX8CQCACRQ0AIAEgAkHoAGxqIQMgACgCAC\
ECA0AgAiACKQMAIAEpAACFNwMAIAIgAikDCCABKQAIhTcDCCACIAIpAxAgASkAEIU3AxAgAiACKQMY\
IAEpABiFNwMYIAIgAikDICABKQAghTcDICACIAIpAyggASkAKIU3AyggAiACKQMwIAEpADCFNwMwIA\
IgAikDOCABKQA4hTcDOCACIAIpA0AgASkAQIU3A0AgAiACKQNIIAEpAEiFNwNIIAIgAikDUCABKQBQ\
hTcDUCACIAIpA1ggASkAWIU3A1ggAiACKQNgIAEpAGCFNwNgIAIQJSABQegAaiIBIANHDQALCwvnAQ\
EHfyMAQRBrIgMkACACEAIhBCACEAMhBSACEAQhBgJAAkAgBEGBgARJDQBBACEHIAQhCANAIAMgBiAF\
IAdqIAhBgIAEIAhBgIAESRsQBSIJEF0CQCAJQSRJDQAgCRABCyAAIAEgAygCACIJIAMoAggQESAHQY\
CABGohBwJAIAMoAgRFDQAgCRAiCyAIQYCAfGohCCAEIAdLDQAMAgsLIAMgAhBdIAAgASADKAIAIgcg\
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\
AiQAQQAhAyACQQA2AgADQCACIANqQQRqIAEgA2ooAAA2AgAgAiADQQRqIgM2AgAgA0GAAUcNAAsgAk\
GIAWogAkGEARCUARogACACQYgBakEEckGAARCUASABLQCAAToAgAEgAkGQAmokAAt1AQJ/IwBBsAJr\
IgIkAEEAIQMgAkEANgIAA0AgAiADakEEaiABIANqKAAANgIAIAIgA0EEaiIDNgIAIANBkAFHDQALIA\
JBmAFqIAJBlAEQlAEaIAAgAkGYAWpBBHJBkAEQlAEgAS0AkAE6AJABIAJBsAJqJAALdQECfyMAQaAC\
ayICJABBACEDIAJBADYCAANAIAIgA2pBBGogASADaigAADYCACACIANBBGoiAzYCACADQYgBRw0ACy\
ACQZABaiACQYwBEJQBGiAAIAJBkAFqQQRyQYgBEJQBIAEtAIgBOgCIASACQaACaiQAC3MBAn8jAEHg\
AWsiAiQAQQAhAyACQQA2AgADQCACIANqQQRqIAEgA2ooAAA2AgAgAiADQQRqIgM2AgAgA0HoAEcNAA\
sgAkHwAGogAkHsABCUARogACACQfAAakEEckHoABCUASABLQBoOgBoIAJB4AFqJAALcwECfyMAQaAB\
ayICJABBACEDIAJBADYCAANAIAIgA2pBBGogASADaigAADYCACACIANBBGoiAzYCACADQcgARw0ACy\
ACQdAAaiACQcwAEJQBGiAAIAJB0ABqQQRyQcgAEJQBIAEtAEg6AEggAkGgAWokAAt1AQJ/IwBB4AJr\
IgIkAEEAIQMgAkEANgIAA0AgAiADakEEaiABIANqKAAANgIAIAIgA0EEaiIDNgIAIANBqAFHDQALIA\
JBsAFqIAJBrAEQlAEaIAAgAkGwAWpBBHJBqAEQlAEgAS0AqAE6AKgBIAJB4AJqJAALewECfyMAQTBr\
IgIkACACQRRqQQI2AgAgAkHQh8AANgIQIAJBAjYCDCACQbCHwAA2AgggAUEcaigCACEDIAEoAhghAS\
ACQQI2AiwgAkICNwIcIAJBsIjAADYCGCACIAJBCGo2AiggASADIAJBGGoQKyEBIAJBMGokACABC3sB\
An8jAEEwayICJAAgAkEUakECNgIAIAJB0IfAADYCECACQQI2AgwgAkGwh8AANgIIIAFBHGooAgAhAy\
ABKAIYIQEgAkECNgIsIAJCAjcCHCACQbCIwAA2AhggAiACQQhqNgIoIAEgAyACQRhqECshASACQTBq\
JAAgAQtsAQF/IwBBMGsiAyQAIAMgATYCBCADIAA2AgAgA0EcakECNgIAIANBLGpBAzYCACADQgM3Ag\
wgA0Gsi8AANgIIIANBAzYCJCADIANBIGo2AhggAyADNgIoIAMgA0EEajYCICADQQhqIAIQdwALbAEB\
fyMAQTBrIgMkACADIAE2AgQgAyAANgIAIANBHGpBAjYCACADQSxqQQM2AgAgA0ICNwIMIANBjIjAAD\
YCCCADQQM2AiQgAyADQSBqNgIYIAMgAzYCKCADIANBBGo2AiAgA0EIaiACEHcAC2wBAX8jAEEwayID\
JAAgAyABNgIEIAMgADYCACADQRxqQQI2AgAgA0EsakEDNgIAIANCAjcCDCADQbyKwAA2AgggA0EDNg\
IkIAMgA0EgajYCGCADIANBBGo2AiggAyADNgIgIANBCGogAhB3AAtsAQF/IwBBMGsiAyQAIAMgATYC\
BCADIAA2AgAgA0EcakECNgIAIANBLGpBAzYCACADQgI3AgwgA0HcisAANgIIIANBAzYCJCADIANBIG\
o2AhggAyADQQRqNgIoIAMgAzYCICADQQhqIAIQdwALVwECfwJAAkAgAEUNACAAKAIADQEgAEEANgIA\
IAAoAgghASAAKAIEIQIgABAiAkAgAkEERw0AIAEoApABRQ0AIAFBADYCkAELIAEQIg8LEJABAAsQkQ\
EAC1gBAn9BAEEAKAKw0kAiAUEBajYCsNJAQQBBACgC+NVAQQFqIgI2AvjVQAJAIAFBAEgNACACQQJL\
DQBBACgCrNJAQX9MDQAgAkEBSw0AIABFDQAQlwEACwALSgEDf0EAIQMCQCACRQ0AAkADQCAALQAAIg\
QgAS0AACIFRw0BIABBAWohACABQQFqIQEgAkF/aiICRQ0CDAALCyAEIAVrIQMLIAMLRgACQAJAIAFF\
DQAgASgCAA0BIAFBfzYCACABQQRqKAIAIAFBCGooAgAgAhBQIAFBADYCACAAQgA3AwAPCxCQAQALEJ\
EBAAtHAQF/IwBBIGsiAyQAIANBFGpBADYCACADQaCQwAA2AhAgA0IBNwIEIAMgATYCHCADIAA2Ahgg\
AyADQRhqNgIAIAMgAhB3AAuLAQAgAEIANwNAIABC+cL4m5Gjs/DbADcDOCAAQuv6htq/tfbBHzcDMC\
AAQp/Y+dnCkdqCm383AyggAELRhZrv+s+Uh9EANwMgIABC8e30+KWn/aelfzcDGCAAQqvw0/Sv7ry3\
PDcDECAAQrvOqqbY0Ouzu383AwggACABrUKIkveV/8z5hOoAhTcDAAtFAQJ/IwBBEGsiASQAAkAgAC\
gCCCICDQBBoJDAAEErQeiQwAAQcgALIAEgACgCDDYCCCABIAA2AgQgASACNgIAIAEQewALQgEBfwJA\
AkACQCACQYCAxABGDQBBASEEIAAgAiABKAIQEQYADQELIAMNAUEAIQQLIAQPCyAAIANBACABKAIMEQ\
gACz8BAX8jAEEgayIAJAAgAEEcakEANgIAIABBoJDAADYCGCAAQgE3AgwgAEGUgsAANgIIIABBCGpB\
nILAABB3AAs+AQF/IwBBIGsiAiQAIAJBAToAGCACIAE2AhQgAiAANgIQIAJBnIjAADYCDCACQaCQwA\
A2AgggAkEIahB0AAs9AQJ/IAAoAgAiAUEUaigCACECAkACQCABKAIEDgIAAAELIAINACAAKAIELQAQ\
EG8ACyAAKAIELQAQEG8ACzMAAkAgAEH8////B0sNAAJAIAANAEEEDwsgACAAQf3///8HSUECdBAxIg\
BFDQAgAA8LAAtSACAAQsfMo9jW0Ouzu383AwggAEIANwMAIABBIGpCq7OP/JGjs/DbADcDACAAQRhq\
Qv+kuYjFkdqCm383AwAgAEEQakLy5rvjo6f9p6V/NwMACywBAX8jAEEQayIBJAAgAUEIaiAAQQhqKA\
IANgIAIAEgACkCADcDACABEHgACyYAAkAgAA0AQbCOwABBMBCSAQALIAAgAiADIAQgBSABKAIQEQwA\
CyQAAkAgAA0AQbCOwABBMBCSAQALIAAgAiADIAQgASgCEBEKAAskAAJAIAANAEGwjsAAQTAQkgEACy\
AAIAIgAyAEIAEoAhARCQALJAACQCAADQBBsI7AAEEwEJIBAAsgACACIAMgBCABKAIQEQoACyQAAkAg\
AA0AQbCOwABBMBCSAQALIAAgAiADIAQgASgCEBEJAAskAAJAIAANAEGwjsAAQTAQkgEACyAAIAIgAy\
AEIAEoAhARCQALJAACQCAADQBBsI7AAEEwEJIBAAsgACACIAMgBCABKAIQERcACyQAAkAgAA0AQbCO\
wABBMBCSAQALIAAgAiADIAQgASgCEBEYAAskAAJAIAANAEGwjsAAQTAQkgEACyAAIAIgAyAEIAEoAh\
ARFgALIgACQCAADQBBsI7AAEEwEJIBAAsgACACIAMgASgCEBEHAAsgAAJAAkAgAUH8////B0sNACAA\
IAIQJiIBDQELAAsgAQsgAAJAIAANAEGwjsAAQTAQkgEACyAAIAIgASgCEBEGAAsUACAAKAIAIAEgAC\
gCBCgCDBEGAAsQACABIAAoAgAgACgCBBAcCw4AAkAgAUUNACAAECILCwsAIAAgASACEG0ACwsAIAAg\
ASACEGwACxEAQayCwABBL0Gsg8AAEHIACw0AIAAoAgAaA38MAAsLCwAgACMAaiQAIwALDQBBwNHAAE\
EbEJIBAAsOAEHb0cAAQc8AEJIBAAsJACAAIAEQCwALCgAgACABIAIQUwsKACAAIAEgAhBACwoAIAAg\
ASACEHALDABCuInPl4nG0fhMCwMAAAsCAAsLtNKAgAABAEGAgMAAC6pSxAUQAFAAAACVAAAACQAAAE\
JMQUtFMkJCTEFLRTJCLTI1NkJMQUtFMkItMzg0QkxBS0UyU0JMQUtFM0tFQ0NBSy0yMjRLRUNDQUst\
MjU2S0VDQ0FLLTM4NEtFQ0NBSy01MTJNRDRNRDVSSVBFTUQtMTYwU0hBLTFTSEEtMjI0U0hBLTI1Nl\
NIQS0zODRTSEEtNTEyVElHRVJ1bnN1cHBvcnRlZCBhbGdvcml0aG1ub24tZGVmYXVsdCBsZW5ndGgg\
c3BlY2lmaWVkIGZvciBub24tZXh0ZW5kYWJsZSBhbGdvcml0aG1saWJyYXJ5L2FsbG9jL3NyYy9yYX\
dfdmVjLnJzY2FwYWNpdHkgb3ZlcmZsb3cAAgEQABEAAADmABAAHAAAAAYCAAAFAAAAQXJyYXlWZWM6\
IGNhcGFjaXR5IGV4Y2VlZGVkIGluIGV4dGVuZC9mcm9tX2l0ZXJ+Ly5jYXJnby9yZWdpc3RyeS9zcm\
MvZ2l0aHViLmNvbS0xZWNjNjI5OWRiOWVjODIzL2FycmF5dmVjLTAuNy4yL3NyYy9hcnJheXZlYy5y\
cwBbARAAUAAAAAEEAAAFAAAAfi8uY2FyZ28vcmVnaXN0cnkvc3JjL2dpdGh1Yi5jb20tMWVjYzYyOT\
lkYjllYzgyMy9ibGFrZTMtMS4zLjEvc3JjL2xpYi5ycwAAALwBEABJAAAAuQEAAAkAAAC8ARAASQAA\
AF8CAAAKAAAAvAEQAEkAAACNAgAACQAAALwBEABJAAAAjQIAADQAAAC8ARAASQAAALkCAAAfAAAAvA\
EQAEkAAADdAgAACgAAALwBEABJAAAA1gIAAAkAAAC8ARAASQAAAAEDAAAZAAAAvAEQAEkAAAADAwAA\
CQAAALwBEABJAAAAAwMAADgAAAC8ARAASQAAAPgDAAAeAAAAvAEQAEkAAACqBAAAFgAAALwBEABJAA\
AAvAQAABYAAAC8ARAASQAAAO0EAAASAAAAvAEQAEkAAAD3BAAAEgAAALwBEABJAAAAaQUAACEAAAAR\
AAAABAAAAAQAAAASAAAAfi8uY2FyZ28vcmVnaXN0cnkvc3JjL2dpdGh1Yi5jb20tMWVjYzYyOTlkYj\
llYzgyMy9hcnJheXZlYy0wLjcuMi9zcmMvYXJyYXl2ZWNfaW1wbC5ycwAAABgDEABVAAAAJwAAAAkA\
AAARAAAABAAAAAQAAAASAAAAEQAAACAAAAABAAAAEwAAAENhcGFjaXR5RXJyb3IAAACgAxAADQAAAG\
luc3VmZmljaWVudCBjYXBhY2l0eQAAALgDEAAVAAAAKWluZGV4IG91dCBvZiBib3VuZHM6IHRoZSBs\
ZW4gaXMgIGJ1dCB0aGUgaW5kZXggaXMgANkDEAAgAAAA+QMQABIAAAARAAAAAAAAAAEAAAAUAAAAOi\
AAACAIEAAAAAAALAQQAAIAAAAwMDAxMDIwMzA0MDUwNjA3MDgwOTEwMTExMjEzMTQxNTE2MTcxODE5\
MjAyMTIyMjMyNDI1MjYyNzI4MjkzMDMxMzIzMzM0MzUzNjM3MzgzOTQwNDE0MjQzNDQ0NTQ2NDc0OD\
Q5NTA1MTUyNTM1NDU1NTY1NzU4NTk2MDYxNjI2MzY0NjU2NjY3Njg2OTcwNzE3MjczNzQ3NTc2Nzc3\
ODc5ODA4MTgyODM4NDg1ODY4Nzg4ODk5MDkxOTI5Mzk0OTU5Njk3OTg5OXJhbmdlIHN0YXJ0IGluZG\
V4ICBvdXQgb2YgcmFuZ2UgZm9yIHNsaWNlIG9mIGxlbmd0aCAIBRAAEgAAABoFEAAiAAAAcmFuZ2Ug\
ZW5kIGluZGV4IEwFEAAQAAAAGgUQACIAAABzb3VyY2Ugc2xpY2UgbGVuZ3RoICgpIGRvZXMgbm90IG\
1hdGNoIGRlc3RpbmF0aW9uIHNsaWNlIGxlbmd0aCAobAUQABUAAACBBRAAKwAAANgDEAABAAAAfi8u\
Y2FyZ28vcmVnaXN0cnkvc3JjL2dpdGh1Yi5jb20tMWVjYzYyOTlkYjllYzgyMy9ibG9jay1idWZmZX\
ItMC4xMC4wL3NyYy9saWIucnPEBRAAUAAAAD8BAAAeAAAAxAUQAFAAAAD8AAAAJwAAAGFzc2VydGlv\
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\
9ea3Fc+cftTextfbGrsoAkFc5USZTtteJdRHtjD8qrgriBFdKiHTKbuLCfWzlgLpFOq1j1oC3VchlH\
tntayQo8DnWPsBSr2DTGfTiTu580vfpC2eKUirjDIexPxSLFi6lozzA7Jd2H+9vdHKg66CYMFCtLuw\
mtqla+hfuT+pcTdnBC6y2FIxSclYU4QeVLSXhkgqvmZpjtMt3KKVK4U8kqwRLMB7qPINmbGII743Tx\
v6CIB8A+VUTcjQcB/UV85+7K2QVDo6BtknPCsAv6IwgISjrn7AAyDtbTICxoZAqWl9KKeDinr1MMtf\
esV55+t55ERotem83AUPtHOj4g5XiG54Gteg9ui9zbqchy+jZMG80WqXi9dmll7iIas8w+XlqmMQkJ\
CNaUhEsxiYu4oePq6HZOO03DuJMfm9rxnVu1/coEVjymWUmyb+KIbsUZw/YAFdHrdJUKEGQORNsct2\
9+VwbL/tK1Xv8hgSQaM2WnAIBwzLRGCYT3UUTecOKKgOQ9lWzWVQX1PXkSXBlu8KcvEjMsgfpWNzbz\
mgw251bGwgcG9pbnRlciBwYXNzZWQgdG8gcnVzdHJlY3Vyc2l2ZSB1c2Ugb2YgYW4gb2JqZWN0IGRl\
dGVjdGVkIHdoaWNoIHdvdWxkIGxlYWQgdG8gdW5zYWZlIGFsaWFzaW5nIGluIHJ1c3QA58+AgAAEbm\
FtZQHcz4CAAJkBAEVqc19zeXM6OlR5cGVFcnJvcjo6bmV3OjpfX3diZ19uZXdfZGIyNTRhZTBhMWJi\
MGZmNTo6aGU1YTViY2I5N2UzNWVlOTEBO3dhc21fYmluZGdlbjo6X193YmluZGdlbl9vYmplY3RfZH\
JvcF9yZWY6Omg3MDI4MTAxYzVkZDAzMWM5AlVqc19zeXM6OlVpbnQ4QXJyYXk6OmJ5dGVfbGVuZ3Ro\
OjpfX3diZ19ieXRlTGVuZ3RoXzg3YTA0MzZhNzRhZGMyNmM6OmhjZDQ0M2I5NTE3NDg1ZTQ4A1Vqc1\
9zeXM6OlVpbnQ4QXJyYXk6OmJ5dGVfb2Zmc2V0OjpfX3diZ19ieXRlT2Zmc2V0XzQ0NzdkNTQ3MTBh\
ZjZmOWI6OmgxOTBhYjU2ZGQxMmViZjEyBExqc19zeXM6OlVpbnQ4QXJyYXk6OmJ1ZmZlcjo6X193Ym\
dfYnVmZmVyXzIxMzEwZWExNzI1N2IwYjQ6Omg3NTEzNDhhMDRjMjc1ZDk3BXlqc19zeXM6OlVpbnQ4\
QXJyYXk6Om5ld193aXRoX2J5dGVfb2Zmc2V0X2FuZF9sZW5ndGg6Ol9fd2JnX25ld3dpdGhieXRlb2\
Zmc2V0YW5kbGVuZ3RoX2Q5YWEyNjY3MDNjYjk4YmU6OmgxNDIxMzk4ZDhkMjBlYjY4Bkxqc19zeXM6\
OlVpbnQ4QXJyYXk6Omxlbmd0aDo6X193YmdfbGVuZ3RoXzllMWFlMTkwMGNiMGZiZDU6OmgzMDRhZT\
U1ZDBjYjNkZGQ3BzJ3YXNtX2JpbmRnZW46Ol9fd2JpbmRnZW5fbWVtb3J5OjpoOThkMDcxZmRlMWQ2\
M2Q3ZghVanNfc3lzOjpXZWJBc3NlbWJseTo6TWVtb3J5OjpidWZmZXI6Ol9fd2JnX2J1ZmZlcl8zZj\
NkNzY0ZDQ3NDdkNTY0OjpoNzYxM2VjZTFiNjI1N2QwYwlGanNfc3lzOjpVaW50OEFycmF5OjpuZXc6\
Ol9fd2JnX25ld184YzNmMDA1MjI3MmE0NTdhOjpoOTM5NDM5OWIzMzA3MmJkZQpGanNfc3lzOjpVaW\
50OEFycmF5OjpzZXQ6Ol9fd2JnX3NldF84M2RiOTY5MGY5MzUzZTc5OjpoMmMzYTNhZjQxYmVlN2Uw\
Ygsxd2FzbV9iaW5kZ2VuOjpfX3diaW5kZ2VuX3Rocm93OjpoZDI2NjNkNGU1YTBiZjQ3YgxAZGVub1\
9zdGRfd2FzbV9jcnlwdG86OmRpZ2VzdDo6Q29udGV4dDo6ZGlnZXN0OjpoN2I5NTBjNzY3NTAwMThi\
MA0sc2hhMjo6c2hhNTEyOjpjb21wcmVzczUxMjo6aDgwYjZjM2U0MjZhMGQ1ZjMOSmRlbm9fc3RkX3\
dhc21fY3J5cHRvOjpkaWdlc3Q6OkNvbnRleHQ6OmRpZ2VzdF9hbmRfcmVzZXQ6OmgxYTU3ZGM2ZTBj\
NDgzN2YwDyxzaGEyOjpzaGEyNTY6OmNvbXByZXNzMjU2OjpoMDIxMDEwM2M3YjNkYzIyORATZGlnZX\
N0Y29udGV4dF9jbG9uZRFAZGVub19zdGRfd2FzbV9jcnlwdG86OmRpZ2VzdDo6Q29udGV4dDo6dXBk\
YXRlOjpoMDIyZjk3YmM5NDdiZjIxNhIzYmxha2UyOjpCbGFrZTJiVmFyQ29yZTo6Y29tcHJlc3M6Om\
hjMmYzMDEzNTFjMzhhNmZiEylyaXBlbWQ6OmMxNjA6OmNvbXByZXNzOjpoMjdkNWNhZGNlN2JhNjNm\
NxQzYmxha2UyOjpCbGFrZTJzVmFyQ29yZTo6Y29tcHJlc3M6OmgzNDI0ZTU5MjA4NzM1ZjAxFStzaG\
ExOjpjb21wcmVzczo6Y29tcHJlc3M6Omg2OGNiMGVhYTU0ZmNmZDljFix0aWdlcjo6Y29tcHJlc3M6\
OmNvbXByZXNzOjpoYTVmYzQxYjA5Y2I1NTFjYhctYmxha2UzOjpPdXRwdXRSZWFkZXI6OmZpbGw6Om\
gxNDk4OTZiZjFmMzRjOWNmGDZibGFrZTM6OnBvcnRhYmxlOjpjb21wcmVzc19pbl9wbGFjZTo6aDNi\
MTcwNDFlM2EyYWQ0ZjEZOmRsbWFsbG9jOjpkbG1hbGxvYzo6RGxtYWxsb2M8QT46Om1hbGxvYzo6aG\
E5NmZjZWZiYjQ0ZDZkYTUaZTxkaWdlc3Q6OmNvcmVfYXBpOjp3cmFwcGVyOjpDb3JlV3JhcHBlcjxU\
PiBhcyBkaWdlc3Q6OlVwZGF0ZT46OnVwZGF0ZTo6e3tjbG9zdXJlfX06Omg5OGEyNmM3ZjA2NjRkMz\
MzG2g8bWQ1OjpNZDVDb3JlIGFzIGRpZ2VzdDo6Y29yZV9hcGk6OkZpeGVkT3V0cHV0Q29yZT46OmZp\
bmFsaXplX2ZpeGVkX2NvcmU6Ont7Y2xvc3VyZX19OjpoZjQwOGE4NDJlNzQwM2Y0ZRwsY29yZTo6Zm\
10OjpGb3JtYXR0ZXI6OnBhZDo6aDhjNzUzZTQ5NGY3YjU2OWQdIG1kNDo6Y29tcHJlc3M6OmhlYjZl\
YTc3NjgzMDc5MTJjHjBibGFrZTM6OmNvbXByZXNzX3N1YnRyZWVfd2lkZTo6aGQxY2IwNWY0NTBhYT\
cwZWQfL2JsYWtlMzo6SGFzaGVyOjpmaW5hbGl6ZV94b2Y6Omg1YzQ3NGJhNjI1NWZhOTU5ID1kZW5v\
X3N0ZF93YXNtX2NyeXB0bzo6ZGlnZXN0OjpDb250ZXh0OjpuZXc6OmgxZDJlYTZhYmRjMGM4MTI3IR\
NkaWdlc3Rjb250ZXh0X3Jlc2V0IjhkbG1hbGxvYzo6ZGxtYWxsb2M6OkRsbWFsbG9jPEE+OjpmcmVl\
OjpoYTQ3MzdiN2Y4NDk3MGFkZCNyPHNoYTI6OmNvcmVfYXBpOjpTaGE1MTJWYXJDb3JlIGFzIGRpZ2\
VzdDo6Y29yZV9hcGk6OlZhcmlhYmxlT3V0cHV0Q29yZT46OmZpbmFsaXplX3ZhcmlhYmxlX2NvcmU6\
OmgwNDU2Yzg2YjQ3NWNjOWIxJEFkbG1hbGxvYzo6ZGxtYWxsb2M6OkRsbWFsbG9jPEE+OjpkaXNwb3\
NlX2NodW5rOjpoM2I2YzRlNzRmYThhYTA0YiUga2VjY2FrOjpmMTYwMDo6aDM0YmRlNTM0MGY3NGE2\
YTgmDl9fcnVzdF9yZWFsbG9jJ3I8c2hhMjo6Y29yZV9hcGk6OlNoYTI1NlZhckNvcmUgYXMgZGlnZX\
N0Ojpjb3JlX2FwaTo6VmFyaWFibGVPdXRwdXRDb3JlPjo6ZmluYWxpemVfdmFyaWFibGVfY29yZTo6\
aGZhMzUyNzAwMzRlYzgyZDUoTmNvcmU6OmZtdDo6bnVtOjppbXA6OjxpbXBsIGNvcmU6OmZtdDo6RG\
lzcGxheSBmb3IgdTMyPjo6Zm10OjpoYzUwYTFjOWI4MmViNDQ0NildPHNoYTE6OlNoYTFDb3JlIGFz\
IGRpZ2VzdDo6Y29yZV9hcGk6OkZpeGVkT3V0cHV0Q29yZT46OmZpbmFsaXplX2ZpeGVkX2NvcmU6Om\
g5OTZiY2RmNDE2MTUwYzExKjFibGFrZTM6Okhhc2hlcjo6bWVyZ2VfY3Zfc3RhY2s6Omg3MTMzMTRm\
ZWQ4YjMxMjcwKyNjb3JlOjpmbXQ6OndyaXRlOjpoZWQ4ZmU3ZDA5NTQ3OWVhMixkPHJpcGVtZDo6Um\
lwZW1kMTYwQ29yZSBhcyBkaWdlc3Q6OmNvcmVfYXBpOjpGaXhlZE91dHB1dENvcmU+OjpmaW5hbGl6\
ZV9maXhlZF9jb3JlOjpoMzkxZjg1Y2JlMzY3YmE0OC00Ymxha2UzOjpjb21wcmVzc19wYXJlbnRzX3\
BhcmFsbGVsOjpoNjI3NDYyMTFkMGE0ZGFjMi5bPG1kNDo6TWQ0Q29yZSBhcyBkaWdlc3Q6OmNvcmVf\
YXBpOjpGaXhlZE91dHB1dENvcmU+OjpmaW5hbGl6ZV9maXhlZF9jb3JlOjpoZTgxNjA3N2Y4NzdhYj\
RiZS9bPG1kNTo6TWQ1Q29yZSBhcyBkaWdlc3Q6OmNvcmVfYXBpOjpGaXhlZE91dHB1dENvcmU+Ojpm\
aW5hbGl6ZV9maXhlZF9jb3JlOjpoYTIzMWI4OGE4ODcyM2ViMjBfPHRpZ2VyOjpUaWdlckNvcmUgYX\
MgZGlnZXN0Ojpjb3JlX2FwaTo6Rml4ZWRPdXRwdXRDb3JlPjo6ZmluYWxpemVfZml4ZWRfY29yZTo6\
aGJhMjU4N2Y0Y2ZlYjRjNjAxMGRsbWFsbG9jOjpEbG1hbGxvYzxBPjo6bWFsbG9jOjpoMDA1NzM1Nj\
dhMzMzOGRmODJMPGFsbG9jOjpib3hlZDo6Qm94PFQ+IGFzIGNvcmU6OmRlZmF1bHQ6OkRlZmF1bHQ+\
OjpkZWZhdWx0OjpoNmQwOGY1ZjVlYzRmYTVmMjNMPGFsbG9jOjpib3hlZDo6Qm94PFQ+IGFzIGNvcm\
U6OmRlZmF1bHQ6OkRlZmF1bHQ+OjpkZWZhdWx0OjpoMDQyN2VjY2YzNzk5NTdiYzRMPGFsbG9jOjpi\
b3hlZDo6Qm94PFQ+IGFzIGNvcmU6OmRlZmF1bHQ6OkRlZmF1bHQ+OjpkZWZhdWx0OjpoN2QwMmNjMm\
IyM2Q1NTlkZDVMPGFsbG9jOjpib3hlZDo6Qm94PFQ+IGFzIGNvcmU6OmRlZmF1bHQ6OkRlZmF1bHQ+\
OjpkZWZhdWx0OjpoNGMyYjExMDJkOTJlYjg2MjZkPHNoYTM6OlNoYWtlMTI4Q29yZSBhcyBkaWdlc3\
Q6OmNvcmVfYXBpOjpFeHRlbmRhYmxlT3V0cHV0Q29yZT46OmZpbmFsaXplX3hvZl9jb3JlOjpoN2Fl\
Yjk4ODRiZjgwZGI5ZjctYmxha2UzOjpDaHVua1N0YXRlOjp1cGRhdGU6OmhjYWRlYzU5N2NiOTJhOD\
hlOGI8c2hhMzo6S2VjY2FrMjI0Q29yZSBhcyBkaWdlc3Q6OmNvcmVfYXBpOjpGaXhlZE91dHB1dENv\
cmU+OjpmaW5hbGl6ZV9maXhlZF9jb3JlOjpoMGY5NDA1NjkzYWY0MTk1ZDlhPHNoYTM6OlNoYTNfMj\
I0Q29yZSBhcyBkaWdlc3Q6OmNvcmVfYXBpOjpGaXhlZE91dHB1dENvcmU+OjpmaW5hbGl6ZV9maXhl\
ZF9jb3JlOjpoNjQ0NjcyYWEwOWQyMzczNDpyPGRpZ2VzdDo6Y29yZV9hcGk6OnhvZl9yZWFkZXI6Ol\
hvZlJlYWRlckNvcmVXcmFwcGVyPFQ+IGFzIGRpZ2VzdDo6WG9mUmVhZGVyPjo6cmVhZDo6e3tjbG9z\
dXJlfX06OmhjMGIxNDZkODFjOGUxYTJlO0w8YWxsb2M6OmJveGVkOjpCb3g8VD4gYXMgY29yZTo6ZG\
VmYXVsdDo6RGVmYXVsdD46OmRlZmF1bHQ6OmhhMDc5MzUyNTQ2MTRlMDI5PGU8ZGlnZXN0Ojpjb3Jl\
X2FwaTo6eG9mX3JlYWRlcjo6WG9mUmVhZGVyQ29yZVdyYXBwZXI8VD4gYXMgZGlnZXN0OjpYb2ZSZW\
FkZXI+OjpyZWFkOjpoMTU0NmE3ZDc5MjNlYmVmNT1lPGRpZ2VzdDo6Y29yZV9hcGk6OnhvZl9yZWFk\
ZXI6OlhvZlJlYWRlckNvcmVXcmFwcGVyPFQ+IGFzIGRpZ2VzdDo6WG9mUmVhZGVyPjo6cmVhZDo6aD\
EzYWE2NDZkYmJiZjJkM2M+ZTxkaWdlc3Q6OmNvcmVfYXBpOjp3cmFwcGVyOjpDb3JlV3JhcHBlcjxU\
PiBhcyBkaWdlc3Q6OlVwZGF0ZT46OnVwZGF0ZTo6e3tjbG9zdXJlfX06Omg0MzY0MDRjNjQ1NDYwZG\
Q4P0w8YWxsb2M6OmJveGVkOjpCb3g8VD4gYXMgY29yZTo6ZGVmYXVsdDo6RGVmYXVsdD46OmRlZmF1\
bHQ6Omg1NzY4YjMxZGE5ZWVmYjhjQDFjb21waWxlcl9idWlsdGluczo6bWVtOjptZW1jcHk6Omg0NW\
ViNTM2MDFkOWQ2YmYwQWI8c2hhMzo6S2VjY2FrMjU2Q29yZSBhcyBkaWdlc3Q6OmNvcmVfYXBpOjpG\
aXhlZE91dHB1dENvcmU+OjpmaW5hbGl6ZV9maXhlZF9jb3JlOjpoN2RhMzE4ZDEyOTc0ZDdkOEJhPH\
NoYTM6OlNoYTNfMjU2Q29yZSBhcyBkaWdlc3Q6OmNvcmVfYXBpOjpGaXhlZE91dHB1dENvcmU+Ojpm\
aW5hbGl6ZV9maXhlZF9jb3JlOjpoNjY0NjM3NDQ5NmFiNGI2NkNyPGRpZ2VzdDo6Y29yZV9hcGk6On\
hvZl9yZWFkZXI6OlhvZlJlYWRlckNvcmVXcmFwcGVyPFQ+IGFzIGRpZ2VzdDo6WG9mUmVhZGVyPjo6\
cmVhZDo6e3tjbG9zdXJlfX06OmgwYmYzMWE1MWMzYzRhNTNjRGU8ZGlnZXN0Ojpjb3JlX2FwaTo6d3\
JhcHBlcjo6Q29yZVdyYXBwZXI8VD4gYXMgZGlnZXN0OjpVcGRhdGU+Ojp1cGRhdGU6Ont7Y2xvc3Vy\
ZX19OjpoN2ExNmQxNDcyMDQ3NWE0ZUVkPHNoYTM6OlNoYWtlMjU2Q29yZSBhcyBkaWdlc3Q6OmNvcm\
VfYXBpOjpFeHRlbmRhYmxlT3V0cHV0Q29yZT46OmZpbmFsaXplX3hvZl9jb3JlOjpoMDk2NTY4MjQ1\
YzEyMzEzOUZGZGxtYWxsb2M6OmRsbWFsbG9jOjpEbG1hbGxvYzxBPjo6aW5zZXJ0X2xhcmdlX2NodW\
5rOjpoYjEyOTkwZjkyNTM4ZmJiZkdGZGxtYWxsb2M6OmRsbWFsbG9jOjpEbG1hbGxvYzxBPjo6dW5s\
aW5rX2xhcmdlX2NodW5rOjpoYmU4ZDM2YTlmNDA2MGNlZUhlPGRpZ2VzdDo6Y29yZV9hcGk6OndyYX\
BwZXI6OkNvcmVXcmFwcGVyPFQ+IGFzIGRpZ2VzdDo6VXBkYXRlPjo6dXBkYXRlOjp7e2Nsb3N1cmV9\
fTo6aDkwZTcxOTliNmM5Yzg0ZDVJYjxzaGEzOjpLZWNjYWszODRDb3JlIGFzIGRpZ2VzdDo6Y29yZV\
9hcGk6OkZpeGVkT3V0cHV0Q29yZT46OmZpbmFsaXplX2ZpeGVkX2NvcmU6OmhjNzMxNWU3MjdiNDk4\
ZjJiSmE8c2hhMzo6U2hhM18zODRDb3JlIGFzIGRpZ2VzdDo6Y29yZV9hcGk6OkZpeGVkT3V0cHV0Q2\
9yZT46OmZpbmFsaXplX2ZpeGVkX2NvcmU6OmhiMjgxYjZkYWM5MzM5NzYxS2I8c2hhMzo6S2VjY2Fr\
NTEyQ29yZSBhcyBkaWdlc3Q6OmNvcmVfYXBpOjpGaXhlZE91dHB1dENvcmU+OjpmaW5hbGl6ZV9maX\
hlZF9jb3JlOjpoMTE4YWVmNjA5MWUyNDczN0xhPHNoYTM6OlNoYTNfNTEyQ29yZSBhcyBkaWdlc3Q6\
OmNvcmVfYXBpOjpGaXhlZE91dHB1dENvcmU+OjpmaW5hbGl6ZV9maXhlZF9jb3JlOjpoMTJkOWIyMW\
RhNzk0M2E2MU1MPGFsbG9jOjpib3hlZDo6Qm94PFQ+IGFzIGNvcmU6OmRlZmF1bHQ6OkRlZmF1bHQ+\
OjpkZWZhdWx0OjpoYTEzNzIzMDcwMWQ4YTA4NE5MPGFsbG9jOjpib3hlZDo6Qm94PFQ+IGFzIGNvcm\
U6OmRlZmF1bHQ6OkRlZmF1bHQ+OjpkZWZhdWx0OjpoMGM5YTJiNDA4NmExNDk1OU9lPGRpZ2VzdDo6\
Y29yZV9hcGk6OndyYXBwZXI6OkNvcmVXcmFwcGVyPFQ+IGFzIGRpZ2VzdDo6VXBkYXRlPjo6dXBkYX\
RlOjp7e2Nsb3N1cmV9fTo6aDI5YmQ4NWE4MDU5NjlhMGZQPmRlbm9fc3RkX3dhc21fY3J5cHRvOjpE\
aWdlc3RDb250ZXh0Ojp1cGRhdGU6Omg2ZmM2MzZkMTdkYTI1MDM1UVs8YmxvY2tfYnVmZmVyOjpCbG\
9ja0J1ZmZlcjxCbG9ja1NpemUsS2luZD4gYXMgY29yZTo6Y2xvbmU6OkNsb25lPjo6Y2xvbmU6Omgw\
NzFjYWI4NjlkMDlhNzgzUgZkaWdlc3RTMWNvbXBpbGVyX2J1aWx0aW5zOjptZW06Om1lbXNldDo6aD\
ViOGI5OThhNGIyZmIyMDVUZTxkaWdlc3Q6OmNvcmVfYXBpOjp3cmFwcGVyOjpDb3JlV3JhcHBlcjxU\
PiBhcyBkaWdlc3Q6OlVwZGF0ZT46OnVwZGF0ZTo6e3tjbG9zdXJlfX06Omg3MmQzOTNjYTdhNDJjMT\
Q4VRRkaWdlc3Rjb250ZXh0X2RpZ2VzdFYRZGlnZXN0Y29udGV4dF9uZXdXHGRpZ2VzdGNvbnRleHRf\
ZGlnZXN0QW5kUmVzZXRYTDxhbGxvYzo6Ym94ZWQ6OkJveDxUPiBhcyBjb3JlOjpkZWZhdWx0OjpEZW\
ZhdWx0Pjo6ZGVmYXVsdDo6aDUwY2YzMGQwNTU4ZjM5NzNZTDxhbGxvYzo6Ym94ZWQ6OkJveDxUPiBh\
cyBjb3JlOjpkZWZhdWx0OjpEZWZhdWx0Pjo6ZGVmYXVsdDo6aDEwZGIyOWY3M2EyODhlY2NaTDxhbG\
xvYzo6Ym94ZWQ6OkJveDxUPiBhcyBjb3JlOjpkZWZhdWx0OjpEZWZhdWx0Pjo6ZGVmYXVsdDo6aGIz\
OWVhZDY2MjhlYTQ2OWVbTDxhbGxvYzo6Ym94ZWQ6OkJveDxUPiBhcyBjb3JlOjpkZWZhdWx0OjpEZW\
ZhdWx0Pjo6ZGVmYXVsdDo6aDkxODM1OGM3OGY3ZWMwNTdcTDxhbGxvYzo6Ym94ZWQ6OkJveDxUPiBh\
cyBjb3JlOjpkZWZhdWx0OjpEZWZhdWx0Pjo6ZGVmYXVsdDo6aDdlMjlhOGQ1NWUxOGFiMTJdLWpzX3\
N5czo6VWludDhBcnJheTo6dG9fdmVjOjpoNTExZmY3NDM1NTJhYmYyM14bZGlnZXN0Y29udGV4dF9k\
aWdlc3RBbmREcm9wXz93YXNtX2JpbmRnZW46OmNvbnZlcnQ6OmNsb3N1cmVzOjppbnZva2UzX211dD\
o6aDZmNWY3MDU3OTQ0NDg2MmVgR2Rlbm9fc3RkX3dhc21fY3J5cHRvOjpEaWdlc3RDb250ZXh0Ojpk\
aWdlc3RfYW5kX2Ryb3A6OmgwYzhjZmNhY2I4NzM4NjI1YS5jb3JlOjpyZXN1bHQ6OnVud3JhcF9mYW\
lsZWQ6OmgyZGM3MDZkOTQ4YzIyOTYwYls8YmxvY2tfYnVmZmVyOjpCbG9ja0J1ZmZlcjxCbG9ja1Np\
emUsS2luZD4gYXMgY29yZTo6Y2xvbmU6OkNsb25lPjo6Y2xvbmU6OmhhMzcwZGU5ZWU0OTc3OTY5Y1\
s8YmxvY2tfYnVmZmVyOjpCbG9ja0J1ZmZlcjxCbG9ja1NpemUsS2luZD4gYXMgY29yZTo6Y2xvbmU6\
OkNsb25lPjo6Y2xvbmU6OmhlMDUyZDMyZmZhZjY1MDY1ZFs8YmxvY2tfYnVmZmVyOjpCbG9ja0J1Zm\
ZlcjxCbG9ja1NpemUsS2luZD4gYXMgY29yZTo6Y2xvbmU6OkNsb25lPjo6Y2xvbmU6OmgwNGU2Y2Jj\
MjYxODU2NjVmZVs8YmxvY2tfYnVmZmVyOjpCbG9ja0J1ZmZlcjxCbG9ja1NpemUsS2luZD4gYXMgY2\
9yZTo6Y2xvbmU6OkNsb25lPjo6Y2xvbmU6OmgyZjA2OWU0MTM4Y2Q1NzVkZls8YmxvY2tfYnVmZmVy\
OjpCbG9ja0J1ZmZlcjxCbG9ja1NpemUsS2luZD4gYXMgY29yZTo6Y2xvbmU6OkNsb25lPjo6Y2xvbm\
U6Omg2MDNjOWFlZTQwMzkxY2I5Z1s8YmxvY2tfYnVmZmVyOjpCbG9ja0J1ZmZlcjxCbG9ja1NpemUs\
S2luZD4gYXMgY29yZTo6Y2xvbmU6OkNsb25lPjo6Y2xvbmU6OmgyN2ZjNWY5N2EyNjUwM2E0aFA8YX\
JyYXl2ZWM6OmVycm9yczo6Q2FwYWNpdHlFcnJvcjxUPiBhcyBjb3JlOjpmbXQ6OkRlYnVnPjo6Zm10\
OjpoMmFhYjQ0MTQ3MWIxNTBmNmlQPGFycmF5dmVjOjplcnJvcnM6OkNhcGFjaXR5RXJyb3I8VD4gYX\
MgY29yZTo6Zm10OjpEZWJ1Zz46OmZtdDo6aDk1YTdhNTAyYjFmNDkxMTNqTmNvcmU6OnNsaWNlOjo8\
aW1wbCBbVF0+Ojpjb3B5X2Zyb21fc2xpY2U6Omxlbl9taXNtYXRjaF9mYWlsOjpoZjNiYmFiYzAyMD\
Q4NjRiY2s2Y29yZTo6cGFuaWNraW5nOjpwYW5pY19ib3VuZHNfY2hlY2s6OmgxZmI3YTZkZjEwMzMx\
Mjc5bERjb3JlOjpzbGljZTo6aW5kZXg6OnNsaWNlX3N0YXJ0X2luZGV4X2xlbl9mYWlsX3J0OjpoYj\
MxN2NhODMzMjA0NjVhNm1CY29yZTo6c2xpY2U6OmluZGV4OjpzbGljZV9lbmRfaW5kZXhfbGVuX2Zh\
aWxfcnQ6OmhmY2Y5M2RkMzVmMDExMmJkbhhfX3diZ19kaWdlc3Rjb250ZXh0X2ZyZWVvN3N0ZDo6cG\
FuaWNraW5nOjpydXN0X3BhbmljX3dpdGhfaG9vazo6aDcwYTBlMTk1ZjRkYjJhMjlwMWNvbXBpbGVy\
X2J1aWx0aW5zOjptZW06Om1lbWNtcDo6aDEyODViODQxMjBkZjVkY2RxFGRpZ2VzdGNvbnRleHRfdX\
BkYXRlciljb3JlOjpwYW5pY2tpbmc6OnBhbmljOjpoOGFmMDQ2Mzk3YTJiZjY1ZHM6Ymxha2UyOjpC\
bGFrZTJiVmFyQ29yZTo6bmV3X3dpdGhfcGFyYW1zOjpoZmU3YThiOTZmMTJiYjNlZHQRcnVzdF9iZW\
dpbl91bndpbmR1Q2NvcmU6OmZtdDo6Rm9ybWF0dGVyOjpwYWRfaW50ZWdyYWw6OndyaXRlX3ByZWZp\
eDo6aDYwYjFiNTAzZTY2ZjMyYjF2NGFsbG9jOjpyYXdfdmVjOjpjYXBhY2l0eV9vdmVyZmxvdzo6aD\
RiMjc1Y2IzYzEwYjBhNzh3LWNvcmU6OnBhbmlja2luZzo6cGFuaWNfZm10OjpoNzUxYmU4MDc3OWQ0\
MmI1M3hDc3RkOjpwYW5pY2tpbmc6OmJlZ2luX3BhbmljX2hhbmRsZXI6Ont7Y2xvc3VyZX19OjpoZG\
NmYzgxOWNlODM2ODI5ZXkRX193YmluZGdlbl9tYWxsb2N6OmJsYWtlMjo6Qmxha2Uyc1ZhckNvcmU6\
Om5ld193aXRoX3BhcmFtczo6aDdkODRlMGQyN2JiNzFmYWF7SXN0ZDo6c3lzX2NvbW1vbjo6YmFja3\
RyYWNlOjpfX3J1c3RfZW5kX3Nob3J0X2JhY2t0cmFjZTo6aDUzY2FiYWZhYjViMDlhZGF8P3dhc21f\
YmluZGdlbjo6Y29udmVydDo6Y2xvc3VyZXM6Omludm9rZTRfbXV0OjpoMjVkYWUzZDIwMTM3NzFmNn\
0/d2FzbV9iaW5kZ2VuOjpjb252ZXJ0OjpjbG9zdXJlczo6aW52b2tlM19tdXQ6Omg5NDRjN2I1M2Rk\
MDI5YmE1fj93YXNtX2JpbmRnZW46OmNvbnZlcnQ6OmNsb3N1cmVzOjppbnZva2UzX211dDo6aDEwMW\
I3OGEyODkzYzAxZTV/P3dhc21fYmluZGdlbjo6Y29udmVydDo6Y2xvc3VyZXM6Omludm9rZTNfbXV0\
OjpoMzhhZGU0YTg1OGY0ZGM2ZIABP3dhc21fYmluZGdlbjo6Y29udmVydDo6Y2xvc3VyZXM6Omludm\
9rZTNfbXV0OjpoN2RmYzg4OGY4ZjlkMzdiNoEBP3dhc21fYmluZGdlbjo6Y29udmVydDo6Y2xvc3Vy\
ZXM6Omludm9rZTNfbXV0OjpoMDdmM2UzYjY5YTk5OTIzYYIBP3dhc21fYmluZGdlbjo6Y29udmVydD\
o6Y2xvc3VyZXM6Omludm9rZTNfbXV0OjpoYjZkNGQ3NTFlMTZlMjk4MIMBP3dhc21fYmluZGdlbjo6\
Y29udmVydDo6Y2xvc3VyZXM6Omludm9rZTNfbXV0OjpoOWEzZDE1NTIzNWRjZDNmN4QBP3dhc21fYm\
luZGdlbjo6Y29udmVydDo6Y2xvc3VyZXM6Omludm9rZTNfbXV0OjpoYjA5YWIyZDQyN2QzMGM1YoUB\
P3dhc21fYmluZGdlbjo6Y29udmVydDo6Y2xvc3VyZXM6Omludm9rZTJfbXV0OjpoNDEzNzc0ZjVmOG\
RkZDI0OIYBEl9fd2JpbmRnZW5fcmVhbGxvY4cBP3dhc21fYmluZGdlbjo6Y29udmVydDo6Y2xvc3Vy\
ZXM6Omludm9rZTFfbXV0OjpoOTc0NTJhMjc1ZGMwNjdiZogBMDwmVCBhcyBjb3JlOjpmbXQ6OkRlYn\
VnPjo6Zm10OjpoZmY0YWYxYjRhODEzOTk2YYkBMjwmVCBhcyBjb3JlOjpmbXQ6OkRpc3BsYXk+Ojpm\
bXQ6Omg5YWRhMTVjZmFlN2Y0MjEyigEPX193YmluZGdlbl9mcmVliwE/Y29yZTo6c2xpY2U6OmluZG\
V4OjpzbGljZV9lbmRfaW5kZXhfbGVuX2ZhaWw6OmgzZGI0NzZiMGQwOTk5NGQyjAFBY29yZTo6c2xp\
Y2U6OmluZGV4OjpzbGljZV9zdGFydF9pbmRleF9sZW5fZmFpbDo6aDEzNmNjYWQ3NjQxMzY4MTCNAT\
NhcnJheXZlYzo6YXJyYXl2ZWM6OmV4dGVuZF9wYW5pYzo6aGQyNThlMDk3YWY0N2M2N2OOATljb3Jl\
OjpvcHM6OmZ1bmN0aW9uOjpGbk9uY2U6OmNhbGxfb25jZTo6aGUwMjFkYmJmNmZhYWEwNmSPAR9fX3\
diaW5kZ2VuX2FkZF90b19zdGFja19wb2ludGVykAExd2FzbV9iaW5kZ2VuOjpfX3J0Ojp0aHJvd19u\
dWxsOjpoZjUxNzFmMGNmZjlhMTUyMZEBMndhc21fYmluZGdlbjo6X19ydDo6Ym9ycm93X2ZhaWw6Om\
g5NGJkODFmOTI4YjM4Mjk4kgEqd2FzbV9iaW5kZ2VuOjp0aHJvd19zdHI6OmgzMGFjMGQ5NjhlZWQy\
OGQ0kwEGbWVtc2V0lAEGbWVtY3B5lQEGbWVtY21wlgExPFQgYXMgY29yZTo6YW55OjpBbnk+Ojp0eX\
BlX2lkOjpoMTNjNzg1OTY2ODhmNjdiMpcBCnJ1c3RfcGFuaWOYAW9jb3JlOjpwdHI6OmRyb3BfaW5f\
cGxhY2U8JmNvcmU6Oml0ZXI6OmFkYXB0ZXJzOjpjb3BpZWQ6OkNvcGllZDxjb3JlOjpzbGljZTo6aX\
Rlcjo6SXRlcjx1OD4+Pjo6aDA1ZmEwZjk3MWI0NmIwZTcA74CAgAAJcHJvZHVjZXJzAghsYW5ndWFn\
ZQEEUnVzdAAMcHJvY2Vzc2VkLWJ5AwVydXN0Yx0xLjY1LjAgKDg5N2UzNzU1MyAyMDIyLTExLTAyKQ\
Z3YWxydXMGMC4xOS4wDHdhc20tYmluZGdlbgYwLjIuODM=\
");
    const wasmModule = new WebAssembly.Module(wasmBytes);
    return new WebAssembly.Instance(wasmModule, imports);
}
function base64decode(b64) {
    const binString = atob(b64);
    const size = binString.length;
    const bytes = new Uint8Array(size);
    for(let i = 0; i < size; i++){
        bytes[i] = binString.charCodeAt(i);
    }
    return bytes;
}
const digestAlgorithms = [
    "BLAKE2B-256",
    "BLAKE2B-384",
    "BLAKE2B",
    "BLAKE2S",
    "BLAKE3",
    "KECCAK-224",
    "KECCAK-256",
    "KECCAK-384",
    "KECCAK-512",
    "SHA-384",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "SHAKE128",
    "SHAKE256",
    "TIGER",
    "RIPEMD-160",
    "SHA-224",
    "SHA-256",
    "SHA-512",
    "MD4",
    "MD5",
    "SHA-1"
];
function swap32(val) {
    return (val & 0xff) << 24 | (val & 0xff00) << 8 | val >> 8 & 0xff00 | val >> 24 & 0xff;
}
function n16(n) {
    return n & 0xffff;
}
function n32(n) {
    return n >>> 0;
}
function add32WithCarry(a, b) {
    const added = n32(a) + n32(b);
    return [
        n32(added),
        added > 0xffffffff ? 1 : 0
    ];
}
function mul32WithCarry(a, b) {
    const al = n16(a);
    const ah = n16(a >>> 16);
    const bl = n16(b);
    const bh = n16(b >>> 16);
    const [t, tc] = add32WithCarry(al * bh, ah * bl);
    const [n, nc] = add32WithCarry(al * bl, n32(t << 16));
    const carry = nc + (tc << 16) + n16(t >>> 16) + ah * bh;
    return [
        n,
        carry
    ];
}
function mul32(a, b) {
    const al = n16(a);
    const ah = a - al;
    return n32(n32(ah * b) + al * b);
}
function mul64([ah, al], [bh, bl]) {
    const [n, c] = mul32WithCarry(al, bl);
    return [
        n32(mul32(al, bh) + mul32(ah, bl) + c),
        n
    ];
}
const prime32 = 16777619;
const fnv32 = (data)=>{
    let hash = 2166136261;
    data.forEach((c)=>{
        hash = mul32(hash, prime32);
        hash ^= c;
    });
    return Uint32Array.from([
        swap32(hash)
    ]).buffer;
};
const fnv32a = (data)=>{
    let hash = 2166136261;
    data.forEach((c)=>{
        hash ^= c;
        hash = mul32(hash, prime32);
    });
    return Uint32Array.from([
        swap32(hash)
    ]).buffer;
};
const prime64Lo = 435;
const prime64Hi = 256;
const fnv64 = (data)=>{
    let hashLo = 2216829733;
    let hashHi = 3421674724;
    data.forEach((c)=>{
        [hashHi, hashLo] = mul64([
            hashHi,
            hashLo
        ], [
            prime64Hi,
            prime64Lo
        ]);
        hashLo ^= c;
    });
    return new Uint32Array([
        swap32(hashHi >>> 0),
        swap32(hashLo >>> 0)
    ]).buffer;
};
const fnv64a = (data)=>{
    let hashLo = 2216829733;
    let hashHi = 3421674724;
    data.forEach((c)=>{
        hashLo ^= c;
        [hashHi, hashLo] = mul64([
            hashHi,
            hashLo
        ], [
            prime64Hi,
            prime64Lo
        ]);
    });
    return new Uint32Array([
        swap32(hashHi >>> 0),
        swap32(hashLo >>> 0)
    ]).buffer;
};
function fnv(name, buf) {
    if (!buf) {
        throw new TypeError("no data provided for hashing");
    }
    switch(name){
        case "FNV32":
            return fnv32(buf);
        case "FNV64":
            return fnv64(buf);
        case "FNV32A":
            return fnv32a(buf);
        case "FNV64A":
            return fnv64a(buf);
        default:
            throw new TypeError(`unsupported fnv digest: ${name}`);
    }
}
const webCrypto = ((crypto1)=>({
        getRandomValues: crypto1.getRandomValues?.bind(crypto1),
        randomUUID: crypto1.randomUUID?.bind(crypto1),
        subtle: {
            decrypt: crypto1.subtle?.decrypt?.bind(crypto1.subtle),
            deriveBits: crypto1.subtle?.deriveBits?.bind(crypto1.subtle),
            deriveKey: crypto1.subtle?.deriveKey?.bind(crypto1.subtle),
            digest: crypto1.subtle?.digest?.bind(crypto1.subtle),
            encrypt: crypto1.subtle?.encrypt?.bind(crypto1.subtle),
            exportKey: crypto1.subtle?.exportKey?.bind(crypto1.subtle),
            generateKey: crypto1.subtle?.generateKey?.bind(crypto1.subtle),
            importKey: crypto1.subtle?.importKey?.bind(crypto1.subtle),
            sign: crypto1.subtle?.sign?.bind(crypto1.subtle),
            unwrapKey: crypto1.subtle?.unwrapKey?.bind(crypto1.subtle),
            verify: crypto1.subtle?.verify?.bind(crypto1.subtle),
            wrapKey: crypto1.subtle?.wrapKey?.bind(crypto1.subtle)
        }
    }))(globalThis.crypto);
const bufferSourceBytes = (data)=>{
    let bytes;
    if (data instanceof Uint8Array) {
        bytes = data;
    } else if (ArrayBuffer.isView(data)) {
        bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    } else if (data instanceof ArrayBuffer) {
        bytes = new Uint8Array(data);
    }
    return bytes;
};
const stdCrypto = ((x)=>x)({
    ...webCrypto,
    subtle: {
        ...webCrypto.subtle,
        async digest (algorithm, data) {
            const { name , length  } = normalizeAlgorithm(algorithm);
            const bytes = bufferSourceBytes(data);
            if (FNVAlgorithms.includes(name)) {
                return fnv(name, bytes);
            }
            if (webCryptoDigestAlgorithms.includes(name) && bytes) {
                return webCrypto.subtle.digest(algorithm, bytes);
            } else if (digestAlgorithms.includes(name)) {
                if (bytes) {
                    return stdCrypto.subtle.digestSync(algorithm, bytes);
                } else if (data[Symbol.iterator]) {
                    return stdCrypto.subtle.digestSync(algorithm, data);
                } else if (data[Symbol.asyncIterator]) {
                    const wasmCrypto = instantiate();
                    const context = new wasmCrypto.DigestContext(name);
                    for await (const chunk of data){
                        const chunkBytes = bufferSourceBytes(chunk);
                        if (!chunkBytes) {
                            throw new TypeError("data contained chunk of the wrong type");
                        }
                        context.update(chunkBytes);
                    }
                    return context.digestAndDrop(length).buffer;
                } else {
                    throw new TypeError("data must be a BufferSource or [Async]Iterable<BufferSource>");
                }
            } else if (webCrypto.subtle?.digest) {
                return webCrypto.subtle.digest(algorithm, data);
            } else {
                throw new TypeError(`unsupported digest algorithm: ${algorithm}`);
            }
        },
        digestSync (algorithm, data) {
            algorithm = normalizeAlgorithm(algorithm);
            const bytes = bufferSourceBytes(data);
            if (FNVAlgorithms.includes(algorithm.name)) {
                return fnv(algorithm.name, bytes);
            }
            const wasmCrypto = instantiate();
            if (bytes) {
                return wasmCrypto.digest(algorithm.name, bytes, algorithm.length).buffer;
            } else if (data[Symbol.iterator]) {
                const context = new wasmCrypto.DigestContext(algorithm.name);
                for (const chunk of data){
                    const chunkBytes = bufferSourceBytes(chunk);
                    if (!chunkBytes) {
                        throw new TypeError("data contained chunk of the wrong type");
                    }
                    context.update(chunkBytes);
                }
                return context.digestAndDrop(algorithm.length).buffer;
            } else {
                throw new TypeError("data must be a BufferSource or Iterable<BufferSource>");
            }
        },
        timingSafeEqual
    }
});
const FNVAlgorithms = [
    "FNV32",
    "FNV32A",
    "FNV64",
    "FNV64A"
];
const webCryptoDigestAlgorithms = [
    "SHA-384",
    "SHA-256",
    "SHA-512",
    "SHA-1"
];
const normalizeAlgorithm = (algorithm)=>typeof algorithm === "string" ? {
        name: algorithm.toUpperCase()
    } : {
        ...algorithm,
        name: algorithm.name.toUpperCase()
    };
new TextEncoder().encode("0123456789abcdef");
new TextDecoder();
const base64abc2 = [
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "+",
    "/"
];
function encode3(data) {
    const uint8 = typeof data === "string" ? new TextEncoder().encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
    let result = "", i;
    const l = uint8.length;
    for(i = 2; i < l; i += 3){
        result += base64abc2[uint8[i - 2] >> 2];
        result += base64abc2[(uint8[i - 2] & 0x03) << 4 | uint8[i - 1] >> 4];
        result += base64abc2[(uint8[i - 1] & 0x0f) << 2 | uint8[i] >> 6];
        result += base64abc2[uint8[i] & 0x3f];
    }
    if (i === l + 1) {
        result += base64abc2[uint8[i - 2] >> 2];
        result += base64abc2[(uint8[i - 2] & 0x03) << 4];
        result += "==";
    }
    if (i === l) {
        result += base64abc2[uint8[i - 2] >> 2];
        result += base64abc2[(uint8[i - 2] & 0x03) << 4 | uint8[i - 1] >> 4];
        result += base64abc2[(uint8[i - 1] & 0x0f) << 2];
        result += "=";
    }
    return result;
}
function decode1(b64) {
    const binString = atob(b64);
    const size = binString.length;
    const bytes = new Uint8Array(size);
    for(let i = 0; i < size; i++){
        bytes[i] = binString.charCodeAt(i);
    }
    return bytes;
}
function addPaddingToBase64url(base64url) {
    if (base64url.length % 4 === 2) return base64url + "==";
    if (base64url.length % 4 === 3) return base64url + "=";
    if (base64url.length % 4 === 1) {
        throw new TypeError("Illegal base64url string!");
    }
    return base64url;
}
function convertBase64urlToBase64(b64url) {
    if (!/^[-_A-Z0-9]*?={0,2}$/i.test(b64url)) {
        throw new TypeError("Failed to decode base64url: invalid character");
    }
    return addPaddingToBase64url(b64url).replace(/\-/g, "+").replace(/_/g, "/");
}
function convertBase64ToBase64url1(b64) {
    return b64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function encode4(data) {
    return convertBase64ToBase64url1(encode3(data));
}
function decode2(b64url) {
    return decode1(convertBase64urlToBase64(b64url));
}
const mod9 = {
    encode: encode4,
    decode: decode2
};
const encoder7 = new TextEncoder();
const decoder3 = new TextDecoder();
function isArray(input) {
    return Array.isArray(input);
}
function isDefined(input) {
    return input !== undefined;
}
function isNotNull(input) {
    return input !== null;
}
function isNotNumber(input) {
    return typeof input !== "number";
}
function isNotString(input) {
    return typeof input !== "string";
}
function isNull(input) {
    return input === null;
}
function isNumber(input) {
    return typeof input === "number";
}
function isObject(input) {
    return input !== null && typeof input === "object" && Array.isArray(input) === false;
}
function isString(input) {
    return typeof input === "string";
}
function isUndefined(input) {
    return input === undefined;
}
function isHashedKeyAlgorithm(algorithm) {
    return isString(algorithm.hash?.name);
}
function isEcKeyAlgorithm(algorithm) {
    return isString(algorithm.namedCurve);
}
function verify(alg, key) {
    if (alg === "none") {
        if (isNotNull(key)) {
            throw new Error(`The alg '${alg}' does not allow a key.`);
        } else return true;
    } else {
        if (!key) throw new Error(`The alg '${alg}' demands a key.`);
        const keyAlgorithm = key.algorithm;
        const algAlgorithm = getAlgorithm(alg);
        if (keyAlgorithm.name === algAlgorithm.name) {
            if (isHashedKeyAlgorithm(keyAlgorithm)) {
                return keyAlgorithm.hash.name === algAlgorithm.hash.name;
            } else if (isEcKeyAlgorithm(keyAlgorithm)) {
                return keyAlgorithm.namedCurve === algAlgorithm.namedCurve;
            }
        }
        return false;
    }
}
function getAlgorithm(alg) {
    switch(alg){
        case "HS256":
            return {
                hash: {
                    name: "SHA-256"
                },
                name: "HMAC"
            };
        case "HS384":
            return {
                hash: {
                    name: "SHA-384"
                },
                name: "HMAC"
            };
        case "HS512":
            return {
                hash: {
                    name: "SHA-512"
                },
                name: "HMAC"
            };
        case "PS256":
            return {
                hash: {
                    name: "SHA-256"
                },
                name: "RSA-PSS",
                saltLength: 256 >> 3
            };
        case "PS384":
            return {
                hash: {
                    name: "SHA-384"
                },
                name: "RSA-PSS",
                saltLength: 384 >> 3
            };
        case "PS512":
            return {
                hash: {
                    name: "SHA-512"
                },
                name: "RSA-PSS",
                saltLength: 512 >> 3
            };
        case "RS256":
            return {
                hash: {
                    name: "SHA-256"
                },
                name: "RSASSA-PKCS1-v1_5"
            };
        case "RS384":
            return {
                hash: {
                    name: "SHA-384"
                },
                name: "RSASSA-PKCS1-v1_5"
            };
        case "RS512":
            return {
                hash: {
                    name: "SHA-512"
                },
                name: "RSASSA-PKCS1-v1_5"
            };
        case "ES256":
            return {
                hash: {
                    name: "SHA-256"
                },
                name: "ECDSA",
                namedCurve: "P-256"
            };
        case "ES384":
            return {
                hash: {
                    name: "SHA-384"
                },
                name: "ECDSA",
                namedCurve: "P-384"
            };
        default:
            throw new Error(`The jwt's alg '${alg}' is not supported.`);
    }
}
async function verify1(signature, key, alg, signingInput) {
    return isNull(key) ? signature.length === 0 : await crypto.subtle.verify(getAlgorithm(alg), key, signature, encoder7.encode(signingInput));
}
async function create(alg, key, signingInput) {
    return isNull(key) ? "" : mod9.encode(new Uint8Array(await crypto.subtle.sign(getAlgorithm(alg), key, encoder7.encode(signingInput))));
}
function isExpired(exp, leeway) {
    return exp + leeway < Date.now() / 1000;
}
function isTooEarly(nbf, leeway) {
    return nbf - leeway > Date.now() / 1000;
}
function is3Tuple(arr) {
    return arr.length === 3;
}
function hasInvalidTimingClaims(...claimValues) {
    return claimValues.some((claimValue)=>isDefined(claimValue) && isNotNumber(claimValue));
}
function validateTimingClaims(payload, { expLeeway =1 , nbfLeeway =1  } = {}) {
    if (hasInvalidTimingClaims(payload.exp, payload.nbf)) {
        throw new Error(`The jwt has an invalid 'exp' or 'nbf' claim.`);
    }
    if (isNumber(payload.exp) && isExpired(payload.exp, expLeeway)) {
        throw RangeError("The jwt is expired.");
    }
    if (isNumber(payload.nbf) && isTooEarly(payload.nbf, nbfLeeway)) {
        throw RangeError("The jwt is used too early.");
    }
}
function hasValidAudClaim(claimValue) {
    if (isUndefined(claimValue) || isString(claimValue)) return true;
    else return isArray(claimValue) && claimValue.every(isString);
}
function validateAudClaim(aud, audience) {
    if (hasValidAudClaim(aud)) {
        if (isUndefined(aud)) {
            throw new Error("The jwt has no 'aud' claim.");
        }
        const audArray = isString(aud) ? [
            aud
        ] : aud;
        const audienceArrayOrRegex = isString(audience) ? [
            audience
        ] : audience;
        if (!audArray.some((audString)=>isArray(audienceArrayOrRegex) ? audienceArrayOrRegex.includes(audString) : audienceArrayOrRegex.test(audString))) {
            throw new Error("The identification with the value in the 'aud' claim has failed.");
        }
    } else {
        throw new Error(`The jwt has an invalid 'aud' claim.`);
    }
}
function decode3(jwt) {
    try {
        const arr = jwt.split(".").map(mod9.decode).map((uint8Array, index)=>index === 0 || index === 1 ? JSON.parse(decoder3.decode(uint8Array)) : uint8Array);
        if (is3Tuple(arr)) return arr;
        else throw new Error();
    } catch  {
        throw Error("The serialization of the jwt is invalid.");
    }
}
function validate([header, payload, signature], options) {
    if (isNotString(header?.alg)) {
        throw new Error(`The jwt's 'alg' header parameter value must be a string.`);
    }
    if (isObject(payload)) {
        validateTimingClaims(payload, options);
        if (isDefined(options?.audience)) {
            validateAudClaim(payload.aud, options.audience);
        }
        return {
            header,
            payload,
            signature
        };
    } else {
        throw new Error(`The jwt claims set is not a JSON object.`);
    }
}
async function verify2(jwt, key, options) {
    const { header , payload , signature  } = validate(decode3(jwt), options);
    if (verify(header.alg, key)) {
        if (!await verify1(signature, key, header.alg, jwt.slice(0, jwt.lastIndexOf(".")))) {
            throw new Error("The jwt's signature does not match the verification signature.");
        }
        return payload;
    } else {
        throw new Error(`The jwt's alg '${header.alg}' does not match the key's algorithm.`);
    }
}
function createSigningInput(header, payload) {
    return `${mod9.encode(encoder7.encode(JSON.stringify(header)))}.${mod9.encode(encoder7.encode(JSON.stringify(payload)))}`;
}
async function create1(header, payload, key) {
    if (verify(header.alg, key)) {
        const signingInput = createSigningInput(header, payload);
        const signature = await create(header.alg, key, signingInput);
        return `${signingInput}.${signature}`;
    } else {
        throw new Error(`The jwt's alg '${header.alg}' does not match the key's algorithm.`);
    }
}
function getNumericDate(exp) {
    return Math.round((exp instanceof Date ? exp.getTime() : Date.now() + exp * 1000) / 1000);
}
const mod10 = {
    decode: decode3,
    validate: validate,
    verify: verify2,
    create: create1,
    getNumericDate: getNumericDate
};
class DenoStdInternalError1 extends Error {
    constructor(message){
        super(message);
        this.name = "DenoStdInternalError";
    }
}
function assert2(expr, msg = "") {
    if (!expr) {
        throw new DenoStdInternalError1(msg);
    }
}
function copy1(src, dst, off = 0) {
    off = Math.max(0, Math.min(off, dst.byteLength));
    const dstBytesAvailable = dst.byteLength - off;
    if (src.byteLength > dstBytesAvailable) {
        src = src.subarray(0, dstBytesAvailable);
    }
    dst.set(src, off);
    return src.byteLength;
}
const MIN_READ1 = 32 * 1024;
const MAX_SIZE2 = 2 ** 32 - 2;
class Buffer2 {
    #buf;
    #off = 0;
    constructor(ab){
        this.#buf = ab === undefined ? new Uint8Array(0) : new Uint8Array(ab);
    }
    bytes(options = {
        copy: true
    }) {
        if (options.copy === false) return this.#buf.subarray(this.#off);
        return this.#buf.slice(this.#off);
    }
    empty() {
        return this.#buf.byteLength <= this.#off;
    }
    get length() {
        return this.#buf.byteLength - this.#off;
    }
    get capacity() {
        return this.#buf.buffer.byteLength;
    }
    truncate(n) {
        if (n === 0) {
            this.reset();
            return;
        }
        if (n < 0 || n > this.length) {
            throw Error("bytes.Buffer: truncation out of range");
        }
        this.#reslice(this.#off + n);
    }
    reset() {
        this.#reslice(0);
        this.#off = 0;
    }
    #tryGrowByReslice(n4) {
        const l = this.#buf.byteLength;
        if (n4 <= this.capacity - l) {
            this.#reslice(l + n4);
            return l;
        }
        return -1;
    }
    #reslice(len2) {
        assert2(len2 <= this.#buf.buffer.byteLength);
        this.#buf = new Uint8Array(this.#buf.buffer, 0, len2);
    }
    readSync(p) {
        if (this.empty()) {
            this.reset();
            if (p.byteLength === 0) {
                return 0;
            }
            return null;
        }
        const nread = copy1(this.#buf.subarray(this.#off), p);
        this.#off += nread;
        return nread;
    }
    read(p) {
        const rr = this.readSync(p);
        return Promise.resolve(rr);
    }
    writeSync(p) {
        const m = this.#grow(p.byteLength);
        return copy1(p, this.#buf, m);
    }
    write(p) {
        const n = this.writeSync(p);
        return Promise.resolve(n);
    }
    #grow(n12) {
        const m = this.length;
        if (m === 0 && this.#off !== 0) {
            this.reset();
        }
        const i = this.#tryGrowByReslice(n12);
        if (i >= 0) {
            return i;
        }
        const c = this.capacity;
        if (n12 <= Math.floor(c / 2) - m) {
            copy1(this.#buf.subarray(this.#off), this.#buf);
        } else if (c + n12 > MAX_SIZE2) {
            throw new Error("The buffer cannot be grown beyond the maximum size.");
        } else {
            const buf = new Uint8Array(Math.min(2 * c + n12, MAX_SIZE2));
            copy1(this.#buf.subarray(this.#off), buf);
            this.#buf = buf;
        }
        this.#off = 0;
        this.#reslice(Math.min(m + n12, MAX_SIZE2));
        return m;
    }
    grow(n) {
        if (n < 0) {
            throw Error("Buffer.grow: negative count");
        }
        const m = this.#grow(n);
        this.#reslice(m);
    }
    async readFrom(r) {
        let n = 0;
        const tmp = new Uint8Array(MIN_READ1);
        while(true){
            const shouldGrow = this.capacity - this.length < MIN_READ1;
            const buf = shouldGrow ? tmp : new Uint8Array(this.#buf.buffer, this.length);
            const nread = await r.read(buf);
            if (nread === null) {
                return n;
            }
            if (shouldGrow) this.writeSync(buf.subarray(0, nread));
            else this.#reslice(this.length + nread);
            n += nread;
        }
    }
    readFromSync(r) {
        let n = 0;
        const tmp = new Uint8Array(MIN_READ1);
        while(true){
            const shouldGrow = this.capacity - this.length < MIN_READ1;
            const buf = shouldGrow ? tmp : new Uint8Array(this.#buf.buffer, this.length);
            const nread = r.readSync(buf);
            if (nread === null) {
                return n;
            }
            if (shouldGrow) this.writeSync(buf.subarray(0, nread));
            else this.#reslice(this.length + nread);
            n += nread;
        }
    }
}
function readableStreamFromIterable(iterable) {
    const iterator = iterable[Symbol.asyncIterator]?.() ?? iterable[Symbol.iterator]?.();
    return new ReadableStream({
        async pull (controller) {
            const { value , done  } = await iterator.next();
            if (done) {
                controller.close();
            } else {
                controller.enqueue(value);
            }
        },
        async cancel (reason) {
            if (typeof iterator.throw == "function") {
                try {
                    await iterator.throw(reason);
                } catch  {}
            }
        }
    });
}
class TransformChunkSizes extends TransformStream {
    constructor(outChunkSize){
        const buffer = new Buffer2();
        buffer.grow(outChunkSize);
        const outChunk = new Uint8Array(outChunkSize);
        super({
            start () {},
            async transform (chunk, controller) {
                buffer.write(chunk);
                while(buffer.length >= outChunkSize){
                    const readFromBuffer = await buffer.read(outChunk);
                    if (readFromBuffer !== outChunkSize) {
                        throw new Error(`Unexpectedly read ${readFromBuffer} bytes from transform buffer when trying to read ${outChunkSize} bytes.`);
                    }
                    controller.enqueue(outChunk);
                }
            },
            flush (controller) {
                if (buffer.length) {
                    controller.enqueue(buffer.bytes());
                }
            }
        });
    }
}
function parse5(xml) {
    xml = xml.trim();
    xml = xml.replace(/<!--[\s\S]*?-->/g, "");
    return document();
    function document() {
        return {
            declaration: declaration(),
            root: tag()
        };
    }
    function declaration() {
        const m = match(/^<\?xml\s*/);
        if (!m) return;
        const node = {
            attributes: {}
        };
        while(!(eos() || is("?>"))){
            const attr = attribute();
            if (!attr) return node;
            node.attributes[attr.name] = attr.value;
        }
        match(/\?>\s*/);
        return node;
    }
    function tag() {
        const m = match(/^<([\w-:.]+)\s*/);
        if (!m) return;
        const node = {
            name: m[1],
            attributes: {},
            children: []
        };
        while(!(eos() || is(">") || is("?>") || is("/>"))){
            const attr = attribute();
            if (!attr) return node;
            node.attributes[attr.name] = attr.value;
        }
        if (match(/^\s*\/>\s*/)) {
            return node;
        }
        match(/\??>\s*/);
        node.content = content();
        let child;
        while(child = tag()){
            node.children.push(child);
        }
        match(/^<\/[\w-:.]+>\s*/);
        return node;
    }
    function content() {
        const m = match(/^([^<]*)/);
        if (m) return m[1];
        return "";
    }
    function attribute() {
        const m = match(/([\w:-]+)\s*=\s*("[^"]*"|'[^']*'|\w+)\s*/);
        if (!m) return;
        return {
            name: m[1],
            value: strip(m[2])
        };
    }
    function strip(val) {
        return val.replace(/^['"]|['"]$/g, "");
    }
    function match(re) {
        const m = xml.match(re);
        if (!m) return;
        xml = xml.slice(m[0].length);
        return m;
    }
    function eos() {
        return 0 == xml.length;
    }
    function is(prefix) {
        return 0 == xml.indexOf(prefix);
    }
}
class DenoS3LiteClientError extends Error {
    constructor(message){
        super(message);
    }
}
class InvalidArgumentError extends DenoS3LiteClientError {
}
class InvalidEndpointError extends DenoS3LiteClientError {
}
class InvalidBucketNameError extends DenoS3LiteClientError {
}
class InvalidObjectNameError extends DenoS3LiteClientError {
}
class AccessKeyRequiredError extends DenoS3LiteClientError {
}
class SecretKeyRequiredError extends DenoS3LiteClientError {
}
class ServerError extends DenoS3LiteClientError {
    statusCode;
    code;
    key;
    bucketName;
    resource;
    region;
    constructor(statusCode, code, message, otherData = {}){
        super(message);
        this.statusCode = statusCode;
        this.code = code;
        this.key = otherData.key;
        this.bucketName = otherData.bucketName;
        this.resource = otherData.resource;
        this.region = otherData.region;
    }
}
async function parseServerError(response) {
    try {
        const xmlParsed = parse5(await response.text());
        const errorRoot = xmlParsed.root;
        if (errorRoot?.name !== "Error") {
            throw new Error("Invalid root, expected <Error>");
        }
        const code = errorRoot.children.find((c)=>c.name === "Code")?.content ?? "UnknownErrorCode";
        const message = errorRoot.children.find((c)=>c.name === "Message")?.content ?? "The error message could not be determined.";
        const key = errorRoot.children.find((c)=>c.name === "Key")?.content;
        const bucketName = errorRoot.children.find((c)=>c.name === "BucketName")?.content;
        const resource = errorRoot.children.find((c)=>c.name === "Resource")?.content;
        const region = errorRoot.children.find((c)=>c.name === "Region")?.content;
        return new ServerError(response.status, code, message, {
            key,
            bucketName,
            resource,
            region
        });
    } catch  {
        return new ServerError(response.status, "UnrecognizedError", `Error: Unexpected response code ${response.status} ${response.statusText}. Unable to parse response as XML.`);
    }
}
const mod11 = {
    DenoS3LiteClientError: DenoS3LiteClientError,
    InvalidArgumentError: InvalidArgumentError,
    InvalidEndpointError: InvalidEndpointError,
    InvalidBucketNameError: InvalidBucketNameError,
    InvalidObjectNameError: InvalidObjectNameError,
    AccessKeyRequiredError: AccessKeyRequiredError,
    SecretKeyRequiredError: SecretKeyRequiredError,
    ServerError: ServerError,
    parseServerError: parseServerError
};
function isValidPort(port) {
    if (typeof port !== "number" || isNaN(port)) {
        return false;
    }
    if (port <= 0) {
        return false;
    }
    return port >= 1 && port <= 65535;
}
function isValidBucketName(bucket) {
    if (typeof bucket !== "string") {
        return false;
    }
    if (bucket.length < 3 || bucket.length > 63) {
        return false;
    }
    if (bucket.indexOf("..") > -1) {
        return false;
    }
    if (bucket.match(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
        return false;
    }
    if (bucket.match(/^[a-z0-9][a-z0-9.-]+[a-z0-9]$/)) {
        return true;
    }
    return false;
}
function isValidObjectName(objectName) {
    if (!isValidPrefix(objectName)) return false;
    if (objectName.length === 0) return false;
    return true;
}
function isValidPrefix(prefix) {
    if (typeof prefix !== "string") return false;
    if (prefix.length > 1024) return false;
    return true;
}
function bin2hex(binary) {
    return Array.from(binary).map((b)=>b.toString(16).padStart(2, "0")).join("");
}
function sanitizeETag(etag = "") {
    const replaceChars = {
        '"': "",
        "&quot;": "",
        "&#34;": "",
        "&QUOT;": "",
        "&#x00022": ""
    };
    return etag.replace(/^("|&quot;|&#34;)|("|&quot;|&#34;)$/g, (m)=>replaceChars[m]);
}
function getVersionId(headers) {
    return headers.get("x-amz-version-id") ?? null;
}
function makeDateLong(date) {
    date = date || new Date();
    const dateStr = date.toISOString();
    return dateStr.substr(0, 4) + dateStr.substr(5, 2) + dateStr.substr(8, 5) + dateStr.substr(14, 2) + dateStr.substr(17, 2) + "Z";
}
function makeDateShort(date) {
    date = date || new Date();
    const dateStr = date.toISOString();
    return dateStr.substr(0, 4) + dateStr.substr(5, 2) + dateStr.substr(8, 2);
}
function getScope(region, date) {
    return `${makeDateShort(date)}/${region}/s3/aws4_request`;
}
async function sha256digestHex(data) {
    if (!(data instanceof Uint8Array)) {
        data = new TextEncoder().encode(data);
    }
    return bin2hex(new Uint8Array(await crypto.subtle.digest("SHA-256", data)));
}
class ObjectUploader extends WritableStream {
    getResult;
    constructor({ client , bucketName , objectName , partSize , metadata  }){
        let result;
        let nextPartNumber = 1;
        let uploadId;
        const etags = [];
        const partsPromises = [];
        super({
            start () {},
            async write (chunk, _controller) {
                const method = "PUT";
                const partNumber = nextPartNumber++;
                try {
                    if (partNumber == 1 && chunk.length < partSize) {
                        const response = await client.makeRequest({
                            method,
                            headers: new Headers({
                                ...metadata,
                                "Content-Length": String(chunk.length)
                            }),
                            bucketName,
                            objectName,
                            payload: chunk
                        });
                        result = {
                            etag: sanitizeETag(response.headers.get("etag") ?? undefined),
                            versionId: getVersionId(response.headers)
                        };
                        return;
                    }
                    if (partNumber === 1) {
                        uploadId = (await initiateNewMultipartUpload({
                            client,
                            bucketName,
                            objectName,
                            metadata
                        })).uploadId;
                    }
                    const partPromise = client.makeRequest({
                        method,
                        query: {
                            partNumber: partNumber.toString(),
                            uploadId
                        },
                        headers: new Headers({
                            "Content-Length": String(chunk.length)
                        }),
                        bucketName: bucketName,
                        objectName: objectName,
                        payload: chunk
                    });
                    partPromise.then((response)=>{
                        let etag = response.headers.get("etag") ?? "";
                        if (etag) {
                            etag = etag.replace(/^"/, "").replace(/"$/, "");
                        }
                        etags.push({
                            part: partNumber,
                            etag
                        });
                    });
                    partsPromises.push(partPromise);
                } catch (err) {
                    throw err;
                }
            },
            async close () {
                if (result) {} else if (uploadId) {
                    await Promise.all(partsPromises);
                    etags.sort((a, b)=>a.part > b.part ? 1 : -1);
                    result = await completeMultipartUpload({
                        client,
                        bucketName,
                        objectName,
                        uploadId,
                        etags
                    });
                } else {
                    throw new Error("Stream was closed without uploading any data.");
                }
            }
        });
        this.getResult = ()=>{
            if (result === undefined) {
                throw new Error("Result is not ready. await the stream first.");
            }
            return result;
        };
    }
}
async function initiateNewMultipartUpload(options) {
    const method = "POST";
    const headers = new Headers(options.metadata);
    const query = "uploads";
    const response = await options.client.makeRequest({
        method,
        bucketName: options.bucketName,
        objectName: options.objectName,
        query,
        headers,
        returnBody: true
    });
    const responseText = await response.text();
    const root = parse5(responseText).root;
    if (!root || root.name !== "InitiateMultipartUploadResult") {
        throw new Error(`Unexpected response: ${responseText}`);
    }
    const uploadId = root.children.find((c)=>c.name === "UploadId")?.content;
    if (!uploadId) {
        throw new Error(`Unable to get UploadId from response: ${responseText}`);
    }
    return {
        uploadId
    };
}
async function completeMultipartUpload({ client , bucketName , objectName , uploadId , etags  }) {
    const payload = `
    <CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        ${etags.map((et)=>`  <Part><PartNumber>${et.part}</PartNumber><ETag>${et.etag}</ETag></Part>`).join("\n")}
    </CompleteMultipartUpload>
  `;
    const response = await client.makeRequest({
        method: "POST",
        bucketName,
        objectName,
        query: `uploadId=${encodeURIComponent(uploadId)}`,
        payload: new TextEncoder().encode(payload),
        returnBody: true
    });
    const responseText = await response.text();
    const root = parse5(responseText).root;
    if (!root || root.name !== "CompleteMultipartUploadResult") {
        throw new Error(`Unexpected response: ${responseText}`);
    }
    const etagRaw = root.children.find((c)=>c.name === "ETag")?.content;
    if (!etagRaw) throw new Error(`Unable to get ETag from response: ${responseText}`);
    const versionId = getVersionId(response.headers);
    return {
        etag: sanitizeETag(etagRaw),
        versionId
    };
}
const signV4Algorithm = "AWS4-HMAC-SHA256";
async function signV4(request) {
    if (!request.accessKey) {
        throw new AccessKeyRequiredError("accessKey is required for signing");
    }
    if (!request.secretKey) {
        throw new SecretKeyRequiredError("secretKey is required for signing");
    }
    const sha256sum = request.headers.get("x-amz-content-sha256");
    if (sha256sum === null) {
        throw new Error("Internal S3 client error - expected x-amz-content-sha256 header, but it's missing.");
    }
    const signedHeaders = getHeadersToSign(request.headers);
    const canonicalRequest = getCanonicalRequest(request.method, request.path, request.headers, signedHeaders, sha256sum);
    const stringToSign = await getStringToSign(canonicalRequest, request.date, request.region);
    const signingKey = await getSigningKey(request.date, request.region, request.secretKey);
    const credential = getCredential(request.accessKey, request.region, request.date);
    const signature = bin2hex(await sha256hmac(signingKey, stringToSign)).toLowerCase();
    return `${signV4Algorithm} Credential=${credential}, SignedHeaders=${signedHeaders.join(";").toLowerCase()}, Signature=${signature}`;
}
function getHeadersToSign(headers) {
    const ignoredHeaders = [
        "authorization",
        "content-length",
        "content-type",
        "user-agent"
    ];
    const headersToSign = [];
    for (const key of headers.keys()){
        if (ignoredHeaders.includes(key.toLowerCase())) {
            continue;
        }
        headersToSign.push(key);
    }
    headersToSign.sort();
    return headersToSign;
}
function getCanonicalRequest(method, path, headers, headersToSign, payloadHash) {
    const headersArray = headersToSign.reduce((acc, headerKey)=>{
        const val = `${headers.get(headerKey)}`.replace(/ +/g, " ");
        acc.push(`${headerKey.toLowerCase()}:${val}`);
        return acc;
    }, []);
    const requestResource = path.split("?")[0];
    let requestQuery = path.split("?")[1];
    if (requestQuery) {
        requestQuery = requestQuery.split("&").sort().map((element)=>element.indexOf("=") === -1 ? element + "=" : element).join("&");
    } else {
        requestQuery = "";
    }
    const canonical = [];
    canonical.push(method.toUpperCase());
    canonical.push(requestResource);
    canonical.push(requestQuery);
    canonical.push(headersArray.join("\n") + "\n");
    canonical.push(headersToSign.join(";").toLowerCase());
    canonical.push(payloadHash);
    return canonical.join("\n");
}
async function getStringToSign(canonicalRequest, requestDate, region) {
    const hash = await sha256digestHex(canonicalRequest);
    const scope = getScope(region, requestDate);
    const stringToSign = [];
    stringToSign.push(signV4Algorithm);
    stringToSign.push(makeDateLong(requestDate));
    stringToSign.push(scope);
    stringToSign.push(hash);
    return stringToSign.join("\n");
}
async function getSigningKey(date, region, secretKey) {
    const dateLine = makeDateShort(date);
    const hmac1 = await sha256hmac("AWS4" + secretKey, dateLine);
    const hmac2 = await sha256hmac(hmac1, region);
    const hmac3 = await sha256hmac(hmac2, "s3");
    return await sha256hmac(hmac3, "aws4_request");
}
function getCredential(accessKey, region, requestDate) {
    return `${accessKey}/${getScope(region, requestDate)}`;
}
async function sha256hmac(secretKey, data) {
    const enc = new TextEncoder();
    const keyObject = await crypto.subtle.importKey("raw", secretKey instanceof Uint8Array ? secretKey : enc.encode(secretKey), {
        name: "HMAC",
        hash: {
            name: "SHA-256"
        }
    }, false, [
        "sign",
        "verify"
    ]);
    const signature = await crypto.subtle.sign("HMAC", keyObject, data instanceof Uint8Array ? data : enc.encode(data));
    return new Uint8Array(signature);
}
const metadataKeys = [
    "Content-Type",
    "Cache-Control",
    "Content-Disposition",
    "Content-Encoding",
    "Content-Language",
    "Expires",
    "x-amz-acl",
    "x-amz-grant-full-control",
    "x-amz-grant-read",
    "x-amz-grant-read-acp",
    "x-amz-grant-write-acp",
    "x-amz-server-side-encryption",
    "x-amz-storage-class",
    "x-amz-website-redirect-location",
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-customer-key",
    "x-amz-server-side-encryption-customer-key-MD5",
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-amz-server-side-encryption-context",
    "x-amz-server-side-encryption-bucket-key-enabled",
    "x-amz-request-payer",
    "x-amz-tagging",
    "x-amz-object-lock-mode",
    "x-amz-object-lock-retain-until-date",
    "x-amz-object-lock-legal-hold",
    "x-amz-expected-bucket-owner"
];
const minimumPartSize = 5 * 1024 * 1024;
const maximumPartSize = 5 * 1024 * 1024 * 1024;
const maxObjectSize = 5 * 1024 * 1024 * 1024 * 1024;
class Client {
    host;
    port;
    protocol;
    accessKey;
    #secretKey;
    defaultBucket;
    region;
    userAgent = "deno-s3-lite-client";
    pathStyle;
    constructor(params){
        if (params.useSSL === undefined) {
            params.useSSL = true;
        }
        if (typeof params.endPoint !== "string" || params.endPoint.length === 0 || params.endPoint.indexOf("/") !== -1) {
            throw new InvalidEndpointError(`Invalid endPoint : ${params.endPoint}`);
        }
        if (params.port !== undefined && !isValidPort(params.port)) {
            throw new InvalidArgumentError(`Invalid port : ${params.port}`);
        }
        this.port = params.port ?? (params.useSSL ? 443 : 80);
        this.host = params.endPoint.toLowerCase() + (params.port ? `:${params.port}` : "");
        this.protocol = params.useSSL ? "https:" : "http:";
        this.accessKey = params.accessKey;
        this.#secretKey = params.secretKey;
        this.pathStyle = params.pathStyle ?? true;
        this.defaultBucket = params.bucket;
        this.region = params.region;
    }
    getBucketName(options) {
        const bucketName = options?.bucketName ?? this.defaultBucket;
        if (bucketName === undefined || !isValidBucketName(bucketName)) {
            throw new InvalidBucketNameError(`Invalid bucket name: ${bucketName}`);
        }
        return bucketName;
    }
    async makeRequest({ method , payload , ...options }) {
        const date = new Date();
        const bucketName = this.getBucketName(options);
        const headers = options.headers ?? new Headers();
        const host = this.pathStyle ? this.host : `${bucketName}.${this.host}`;
        const queryAsString = typeof options.query === "object" ? new URLSearchParams(options.query).toString().replace("+", "%20") : options.query;
        const path = (this.pathStyle ? `/${bucketName}/${options.objectName}` : `/${options.objectName}`) + (queryAsString ? `?${queryAsString}` : "");
        const statusCode = options.statusCode ?? 200;
        if (method === "POST" || method === "PUT" || method === "DELETE") {
            if (payload === undefined) {
                payload = new Uint8Array();
            } else if (typeof payload === "string") {
                payload = new TextEncoder().encode(payload);
            }
            headers.set("Content-Length", String(payload.length));
        } else if (payload) {
            throw new Error(`Unexpected payload on ${method} request.`);
        }
        const sha256sum = await sha256digestHex(payload ?? new Uint8Array());
        headers.set("host", host);
        headers.set("x-amz-date", makeDateLong(date));
        headers.set("x-amz-content-sha256", sha256sum);
        headers.set("authorization", await signV4({
            headers,
            method,
            path,
            accessKey: this.accessKey,
            secretKey: this.#secretKey,
            region: this.region,
            date
        }));
        const fullUrl = `${this.protocol}//${host}${path}`;
        const response = await fetch(fullUrl, {
            method,
            headers,
            body: payload
        });
        if (response.status !== statusCode) {
            if (response.status >= 400) {
                const error = await parseServerError(response);
                throw error;
            } else {
                throw new ServerError(response.status, "UnexpectedStatusCode", `Unexpected response code from the server (expected ${statusCode}, got ${response.status} ${response.statusText}).`);
            }
        }
        if (!options.returnBody) {
            await response.body?.getReader().read();
        }
        return response;
    }
    async deleteObject(objectName, options = {}) {
        const bucketName = this.getBucketName(options);
        if (!isValidObjectName(objectName)) {
            throw new InvalidObjectNameError(`Invalid object name: ${objectName}`);
        }
        const query = options.versionId ? {
            versionId: options.versionId
        } : {};
        const headers = new Headers();
        if (options.governanceBypass) {
            headers.set("X-Amz-Bypass-Governance-Retention", "true");
        }
        await this.makeRequest({
            method: "DELETE",
            bucketName,
            objectName,
            headers,
            query,
            statusCode: 204
        });
    }
    async exists(objectName, options) {
        try {
            await this.statObject(objectName, options);
            return true;
        } catch (err) {
            if (err instanceof ServerError && err.statusCode === 404) {
                return false;
            }
            throw err;
        }
    }
    getObject(objectName, options) {
        return this.getPartialObject(objectName, {
            ...options,
            offset: 0,
            length: 0
        });
    }
    async getPartialObject(objectName, { offset , length , ...options }) {
        const bucketName = this.getBucketName(options);
        if (!isValidObjectName(objectName)) {
            throw new InvalidObjectNameError(`Invalid object name: ${objectName}`);
        }
        const headers = new Headers();
        let statusCode = 200;
        if (offset || length) {
            let range = "";
            if (offset) {
                range = `bytes=${+offset}-`;
            } else {
                range = "bytes=0-";
                offset = 0;
            }
            if (length) {
                range += `${+length + offset - 1}`;
            }
            headers.set("Range", range);
            statusCode = 206;
        }
        const query = options.versionId ? {
            versionId: options.versionId
        } : undefined;
        return await this.makeRequest({
            method: "GET",
            bucketName,
            objectName,
            headers,
            query,
            statusCode,
            returnBody: true
        });
    }
    async *listObjects(options = {}) {
        for await (const result of this.listObjectsGrouped({
            ...options,
            delimiter: ""
        })){
            if (result.type === "Object") {
                yield result;
            } else {
                throw new Error(`Unexpected result from listObjectsGrouped(): ${result}`);
            }
        }
    }
    async *listObjectsGrouped(options) {
        const bucketName = this.getBucketName(options);
        let continuationToken = "";
        const pageSize = options.pageSize ?? 1_000;
        if (pageSize < 1 || pageSize > 1_000) {
            throw new InvalidArgumentError("pageSize must be between 1 and 1,000.");
        }
        let resultCount = 0;
        while(true){
            const maxKeys = options.maxResults ? Math.min(pageSize, options.maxResults - resultCount) : pageSize;
            if (maxKeys === 0) {
                return;
            }
            const pageResponse = await this.makeRequest({
                method: "GET",
                bucketName,
                objectName: "",
                query: {
                    "list-type": "2",
                    prefix: options.prefix ?? "",
                    delimiter: options.delimiter,
                    "max-keys": String(maxKeys),
                    ...continuationToken ? {
                        "continuation-token": continuationToken
                    } : {}
                },
                returnBody: true
            });
            const responseText = await pageResponse.text();
            const root = parse5(responseText).root;
            if (!root || root.name !== "ListBucketResult") {
                throw new Error(`Unexpected response: ${responseText}`);
            }
            const commonPrefixesElement = root.children.find((c)=>c.name === "CommonPrefixes");
            const toYield = [];
            if (commonPrefixesElement) {
                for (const prefixElement of commonPrefixesElement.children){
                    toYield.push({
                        type: "CommonPrefix",
                        prefix: prefixElement.content ?? ""
                    });
                    resultCount++;
                }
            }
            for (const objectElement of root.children.filter((c)=>c.name === "Contents")){
                toYield.push({
                    type: "Object",
                    key: objectElement.children.find((c)=>c.name === "Key")?.content ?? "",
                    etag: sanitizeETag(objectElement.children.find((c)=>c.name === "ETag")?.content ?? ""),
                    size: parseInt(objectElement.children.find((c)=>c.name === "Size")?.content ?? "", 10),
                    lastModified: new Date(objectElement.children.find((c)=>c.name === "LastModified")?.content ?? "invalid")
                });
                resultCount++;
            }
            toYield.sort((a, b)=>{
                const aStr = a.type === "Object" ? a.key : a.prefix;
                const bStr = b.type === "Object" ? b.key : b.prefix;
                return aStr > bStr ? 1 : aStr < bStr ? -1 : 0;
            });
            for (const entry of toYield){
                yield entry;
            }
            const isTruncated = root.children.find((c)=>c.name === "IsTruncated")?.content === "true";
            if (isTruncated) {
                const nextContinuationToken = root.children.find((c)=>c.name === "NextContinuationToken")?.content;
                if (!nextContinuationToken) {
                    throw new Error("Unexpectedly missing continuation token, but server said there are more results.");
                }
                continuationToken = nextContinuationToken;
            } else {
                return;
            }
        }
    }
    async putObject(objectName, streamOrData, options) {
        const bucketName = this.getBucketName(options);
        if (!isValidObjectName(objectName)) {
            throw new InvalidObjectNameError(`Invalid object name: ${objectName}`);
        }
        let size;
        let stream;
        if (typeof streamOrData === "string") {
            const binaryData = new TextEncoder().encode(streamOrData);
            stream = readableStreamFromIterable([
                binaryData
            ]);
            size = binaryData.length;
        } else if (streamOrData instanceof Uint8Array) {
            stream = readableStreamFromIterable([
                streamOrData
            ]);
            size = streamOrData.byteLength;
        } else if (streamOrData instanceof ReadableStream) {
            stream = streamOrData;
        } else {
            throw new InvalidArgumentError(`Invalid stream/data type provided.`);
        }
        if (options?.size !== undefined) {
            if (size !== undefined && options?.size !== size) {
                throw new InvalidArgumentError(`size was specified (${options.size}) but doesn't match auto-detected size (${size}).`);
            }
            if (typeof size !== "number" || size < 0 || isNaN(size)) {
                throw new InvalidArgumentError(`invalid size specified: ${options.size}`);
            } else {
                size = options.size;
            }
        }
        const partSize = options?.partSize ?? this.calculatePartSize(size);
        if (partSize < minimumPartSize) {
            throw new InvalidArgumentError(`Part size should be greater than 5MB`);
        } else if (partSize > maximumPartSize) {
            throw new InvalidArgumentError(`Part size should be less than 6MB`);
        }
        const chunker = new TransformChunkSizes(partSize);
        const uploader = new ObjectUploader({
            client: this,
            bucketName,
            objectName,
            partSize,
            metadata: options?.metadata ?? {}
        });
        await stream.pipeThrough(chunker).pipeTo(uploader);
        return uploader.getResult();
    }
    calculatePartSize(size) {
        if (size === undefined) {
            size = maxObjectSize;
        }
        if (size > maxObjectSize) {
            throw new TypeError(`size should not be more than ${maxObjectSize}`);
        }
        let partSize = 64 * 1024 * 1024;
        while(true){
            if (partSize * 10_000 > size) {
                return partSize;
            }
            partSize += 16 * 1024 * 1024;
        }
    }
    async statObject(objectName, options) {
        const bucketName = this.getBucketName(options);
        if (!isValidObjectName(objectName)) {
            throw new InvalidObjectNameError(`Invalid object name: ${objectName}`);
        }
        const query = {};
        if (options?.versionId) {
            query.versionId = options.versionId;
        }
        const response = await this.makeRequest({
            method: "HEAD",
            bucketName,
            objectName,
            query
        });
        const metadata = {};
        for (const header of metadataKeys){
            if (response.headers.has(header)) {
                metadata[header] = response.headers.get(header);
            }
        }
        response.headers.forEach((_value, key)=>{
            if (key.startsWith("x-amz-meta-")) {
                metadata[key] = response.headers.get(key);
            }
        });
        return {
            type: "Object",
            key: objectName,
            size: parseInt(response.headers.get("content-length") ?? "", 10),
            metadata,
            lastModified: new Date(response.headers.get("Last-Modified") ?? "error: missing last modified"),
            versionId: response.headers.get("x-amz-version-id") || null,
            etag: sanitizeETag(response.headers.get("ETag") ?? "")
        };
    }
}
const mod12 = {
    S3Client: Client,
    S3Errors: mod11
};
function isSubdir(src, dest, sep = sep2) {
    if (src === dest) {
        return false;
    }
    src = toPathString(src);
    const srcArray = src.split(sep);
    dest = toPathString(dest);
    const destArray = dest.split(sep);
    return srcArray.every((current, i)=>destArray[i] === current);
}
function getFileInfoType(fileInfo) {
    return fileInfo.isFile ? "file" : fileInfo.isDirectory ? "dir" : fileInfo.isSymlink ? "symlink" : undefined;
}
function createWalkEntrySync(path) {
    path = toPathString(path);
    path = normalize3(path);
    const name = basename2(path);
    const info = Deno.statSync(path);
    return {
        path,
        name,
        isFile: info.isFile,
        isDirectory: info.isDirectory,
        isSymlink: info.isSymlink
    };
}
async function createWalkEntry(path) {
    path = toPathString(path);
    path = normalize3(path);
    const name = basename2(path);
    const info = await Deno.stat(path);
    return {
        path,
        name,
        isFile: info.isFile,
        isDirectory: info.isDirectory,
        isSymlink: info.isSymlink
    };
}
function toPathString(path) {
    return path instanceof URL ? fromFileUrl2(path) : path;
}
async function emptyDir(dir) {
    try {
        const items = [];
        for await (const dirEntry of Deno.readDir(dir)){
            items.push(dirEntry);
        }
        while(items.length){
            const item = items.shift();
            if (item && item.name) {
                const filepath = join3(toPathString(dir), item.name);
                await Deno.remove(filepath, {
                    recursive: true
                });
            }
        }
    } catch (err) {
        if (!(err instanceof Deno.errors.NotFound)) {
            throw err;
        }
        await Deno.mkdir(dir, {
            recursive: true
        });
    }
}
function emptyDirSync(dir) {
    try {
        const items = [
            ...Deno.readDirSync(dir)
        ];
        while(items.length){
            const item = items.shift();
            if (item && item.name) {
                const filepath = join3(toPathString(dir), item.name);
                Deno.removeSync(filepath, {
                    recursive: true
                });
            }
        }
    } catch (err) {
        if (!(err instanceof Deno.errors.NotFound)) {
            throw err;
        }
        Deno.mkdirSync(dir, {
            recursive: true
        });
    }
}
async function ensureDir(dir) {
    try {
        const fileInfo = await Deno.lstat(dir);
        if (!fileInfo.isDirectory) {
            throw new Error(`Ensure path exists, expected 'dir', got '${getFileInfoType(fileInfo)}'`);
        }
    } catch (err) {
        if (err instanceof Deno.errors.NotFound) {
            await Deno.mkdir(dir, {
                recursive: true
            });
            return;
        }
        throw err;
    }
}
function ensureDirSync(dir) {
    try {
        const fileInfo = Deno.lstatSync(dir);
        if (!fileInfo.isDirectory) {
            throw new Error(`Ensure path exists, expected 'dir', got '${getFileInfoType(fileInfo)}'`);
        }
    } catch (err) {
        if (err instanceof Deno.errors.NotFound) {
            Deno.mkdirSync(dir, {
                recursive: true
            });
            return;
        }
        throw err;
    }
}
async function ensureFile(filePath) {
    try {
        const stat = await Deno.lstat(filePath);
        if (!stat.isFile) {
            throw new Error(`Ensure path exists, expected 'file', got '${getFileInfoType(stat)}'`);
        }
    } catch (err) {
        if (err instanceof Deno.errors.NotFound) {
            await ensureDir(dirname2(toPathString(filePath)));
            await Deno.writeFile(filePath, new Uint8Array());
            return;
        }
        throw err;
    }
}
function ensureFileSync(filePath) {
    try {
        const stat = Deno.lstatSync(filePath);
        if (!stat.isFile) {
            throw new Error(`Ensure path exists, expected 'file', got '${getFileInfoType(stat)}'`);
        }
    } catch (err) {
        if (err instanceof Deno.errors.NotFound) {
            ensureDirSync(dirname2(toPathString(filePath)));
            Deno.writeFileSync(filePath, new Uint8Array());
            return;
        }
        throw err;
    }
}
async function ensureLink(src, dest) {
    dest = toPathString(dest);
    await ensureDir(dirname2(dest));
    await Deno.link(toPathString(src), dest);
}
function ensureLinkSync(src, dest) {
    dest = toPathString(dest);
    ensureDirSync(dirname2(dest));
    Deno.linkSync(toPathString(src), dest);
}
async function ensureSymlink(src, dest) {
    const srcStatInfo = await Deno.lstat(src);
    const srcFilePathType = getFileInfoType(srcStatInfo);
    await ensureDir(dirname2(toPathString(dest)));
    const options = isWindows ? {
        type: srcFilePathType === "dir" ? "dir" : "file"
    } : undefined;
    try {
        await Deno.symlink(src, dest, options);
    } catch (error) {
        if (!(error instanceof Deno.errors.AlreadyExists)) {
            throw error;
        }
    }
}
function ensureSymlinkSync(src, dest) {
    const srcStatInfo = Deno.lstatSync(src);
    const srcFilePathType = getFileInfoType(srcStatInfo);
    ensureDirSync(dirname2(toPathString(dest)));
    const options = isWindows ? {
        type: srcFilePathType === "dir" ? "dir" : "file"
    } : undefined;
    try {
        Deno.symlinkSync(src, dest, options);
    } catch (error) {
        if (!(error instanceof Deno.errors.AlreadyExists)) {
            throw error;
        }
    }
}
function include(path, exts, match, skip) {
    if (exts && !exts.some((ext)=>path.endsWith(ext))) {
        return false;
    }
    if (match && !match.some((pattern)=>!!path.match(pattern))) {
        return false;
    }
    if (skip && skip.some((pattern)=>!!path.match(pattern))) {
        return false;
    }
    return true;
}
function wrapErrorWithRootPath(err, root) {
    if (err instanceof Error && "root" in err) return err;
    const e = new Error();
    e.root = root;
    e.message = err instanceof Error ? `${err.message} for path "${root}"` : `[non-error thrown] for path "${root}"`;
    e.stack = err instanceof Error ? err.stack : undefined;
    e.cause = err instanceof Error ? err.cause : undefined;
    return e;
}
async function* walk(root, { maxDepth =Infinity , includeFiles =true , includeDirs =true , followSymlinks =false , exts =undefined , match =undefined , skip =undefined  } = {}) {
    if (maxDepth < 0) {
        return;
    }
    root = toPathString(root);
    if (includeDirs && include(root, exts, match, skip)) {
        yield await createWalkEntry(root);
    }
    if (maxDepth < 1 || !include(root, undefined, undefined, skip)) {
        return;
    }
    try {
        for await (const entry of Deno.readDir(root)){
            assert(entry.name != null);
            let path = join3(root, entry.name);
            let { isSymlink , isDirectory  } = entry;
            if (isSymlink) {
                if (!followSymlinks) continue;
                path = await Deno.realPath(path);
                ({ isSymlink , isDirectory  } = await Deno.lstat(path));
            }
            if (isSymlink || isDirectory) {
                yield* walk(path, {
                    maxDepth: maxDepth - 1,
                    includeFiles,
                    includeDirs,
                    followSymlinks,
                    exts,
                    match,
                    skip
                });
            } else if (includeFiles && include(path, exts, match, skip)) {
                yield {
                    path,
                    ...entry
                };
            }
        }
    } catch (err) {
        throw wrapErrorWithRootPath(err, normalize3(root));
    }
}
function* walkSync(root, { maxDepth =Infinity , includeFiles =true , includeDirs =true , followSymlinks =false , exts =undefined , match =undefined , skip =undefined  } = {}) {
    root = toPathString(root);
    if (maxDepth < 0) {
        return;
    }
    if (includeDirs && include(root, exts, match, skip)) {
        yield createWalkEntrySync(root);
    }
    if (maxDepth < 1 || !include(root, undefined, undefined, skip)) {
        return;
    }
    let entries;
    try {
        entries = Deno.readDirSync(root);
    } catch (err) {
        throw wrapErrorWithRootPath(err, normalize3(root));
    }
    for (const entry of entries){
        assert(entry.name != null);
        let path = join3(root, entry.name);
        let { isSymlink , isDirectory  } = entry;
        if (isSymlink) {
            if (!followSymlinks) continue;
            path = Deno.realPathSync(path);
            ({ isSymlink , isDirectory  } = Deno.lstatSync(path));
        }
        if (isSymlink || isDirectory) {
            yield* walkSync(path, {
                maxDepth: maxDepth - 1,
                includeFiles,
                includeDirs,
                followSymlinks,
                exts,
                match,
                skip
            });
        } else if (includeFiles && include(path, exts, match, skip)) {
            yield {
                path,
                ...entry
            };
        }
    }
}
function split(path) {
    const s = SEP_PATTERN.source;
    const segments = path.replace(new RegExp(`^${s}|${s}$`, "g"), "").split(SEP_PATTERN);
    const isAbsolute_ = isAbsolute2(path);
    return {
        segments,
        isAbsolute: isAbsolute_,
        hasTrailingSep: !!path.match(new RegExp(`${s}$`)),
        winRoot: isWindows && isAbsolute_ ? segments.shift() : undefined
    };
}
function throwUnlessNotFound(error) {
    if (!(error instanceof Deno.errors.NotFound)) {
        throw error;
    }
}
function comparePath(a, b) {
    if (a.path < b.path) return -1;
    if (a.path > b.path) return 1;
    return 0;
}
async function* expandGlob(glob, { root =Deno.cwd() , exclude =[] , includeDirs =true , extended =true , globstar =true , caseInsensitive  } = {}) {
    const globOptions = {
        extended,
        globstar,
        caseInsensitive
    };
    const absRoot = resolve2(root);
    const resolveFromRoot = (path)=>resolve2(absRoot, path);
    const excludePatterns = exclude.map(resolveFromRoot).map((s)=>globToRegExp(s, globOptions));
    const shouldInclude = (path)=>!excludePatterns.some((p)=>!!path.match(p));
    const { segments , isAbsolute: isGlobAbsolute , hasTrailingSep , winRoot  } = split(toPathString(glob));
    let fixedRoot = isGlobAbsolute ? winRoot != undefined ? winRoot : "/" : absRoot;
    while(segments.length > 0 && !isGlob(segments[0])){
        const seg = segments.shift();
        assert(seg != null);
        fixedRoot = joinGlobs([
            fixedRoot,
            seg
        ], globOptions);
    }
    let fixedRootInfo;
    try {
        fixedRootInfo = await createWalkEntry(fixedRoot);
    } catch (error) {
        return throwUnlessNotFound(error);
    }
    async function* advanceMatch(walkInfo, globSegment) {
        if (!walkInfo.isDirectory) {
            return;
        } else if (globSegment == "..") {
            const parentPath = joinGlobs([
                walkInfo.path,
                ".."
            ], globOptions);
            try {
                if (shouldInclude(parentPath)) {
                    return yield await createWalkEntry(parentPath);
                }
            } catch (error) {
                throwUnlessNotFound(error);
            }
            return;
        } else if (globSegment == "**") {
            return yield* walk(walkInfo.path, {
                skip: excludePatterns,
                maxDepth: globstar ? Infinity : 1
            });
        }
        const globPattern = globToRegExp(globSegment, globOptions);
        for await (const walkEntry of walk(walkInfo.path, {
            maxDepth: 1,
            skip: excludePatterns
        })){
            if (walkEntry.path != walkInfo.path && walkEntry.name.match(globPattern)) {
                yield walkEntry;
            }
        }
    }
    let currentMatches = [
        fixedRootInfo
    ];
    for (const segment of segments){
        const nextMatchMap = new Map();
        await Promise.all(currentMatches.map(async (currentMatch)=>{
            for await (const nextMatch of advanceMatch(currentMatch, segment)){
                nextMatchMap.set(nextMatch.path, nextMatch);
            }
        }));
        currentMatches = [
            ...nextMatchMap.values()
        ].sort(comparePath);
    }
    if (hasTrailingSep) {
        currentMatches = currentMatches.filter((entry)=>entry.isDirectory);
    }
    if (!includeDirs) {
        currentMatches = currentMatches.filter((entry)=>!entry.isDirectory);
    }
    yield* currentMatches;
}
function* expandGlobSync(glob, { root =Deno.cwd() , exclude =[] , includeDirs =true , extended =true , globstar =true , caseInsensitive  } = {}) {
    const globOptions = {
        extended,
        globstar,
        caseInsensitive
    };
    const absRoot = resolve2(root);
    const resolveFromRoot = (path)=>resolve2(absRoot, path);
    const excludePatterns = exclude.map(resolveFromRoot).map((s)=>globToRegExp(s, globOptions));
    const shouldInclude = (path)=>!excludePatterns.some((p)=>!!path.match(p));
    const { segments , isAbsolute: isGlobAbsolute , hasTrailingSep , winRoot  } = split(toPathString(glob));
    let fixedRoot = isGlobAbsolute ? winRoot != undefined ? winRoot : "/" : absRoot;
    while(segments.length > 0 && !isGlob(segments[0])){
        const seg = segments.shift();
        assert(seg != null);
        fixedRoot = joinGlobs([
            fixedRoot,
            seg
        ], globOptions);
    }
    let fixedRootInfo;
    try {
        fixedRootInfo = createWalkEntrySync(fixedRoot);
    } catch (error) {
        return throwUnlessNotFound(error);
    }
    function* advanceMatch(walkInfo, globSegment) {
        if (!walkInfo.isDirectory) {
            return;
        } else if (globSegment == "..") {
            const parentPath = joinGlobs([
                walkInfo.path,
                ".."
            ], globOptions);
            try {
                if (shouldInclude(parentPath)) {
                    return yield createWalkEntrySync(parentPath);
                }
            } catch (error) {
                throwUnlessNotFound(error);
            }
            return;
        } else if (globSegment == "**") {
            return yield* walkSync(walkInfo.path, {
                skip: excludePatterns,
                maxDepth: globstar ? Infinity : 1
            });
        }
        const globPattern = globToRegExp(globSegment, globOptions);
        for (const walkEntry of walkSync(walkInfo.path, {
            maxDepth: 1,
            skip: excludePatterns
        })){
            if (walkEntry.path != walkInfo.path && walkEntry.name.match(globPattern)) {
                yield walkEntry;
            }
        }
    }
    let currentMatches = [
        fixedRootInfo
    ];
    for (const segment of segments){
        const nextMatchMap = new Map();
        for (const currentMatch of currentMatches){
            for (const nextMatch of advanceMatch(currentMatch, segment)){
                nextMatchMap.set(nextMatch.path, nextMatch);
            }
        }
        currentMatches = [
            ...nextMatchMap.values()
        ].sort(comparePath);
    }
    if (hasTrailingSep) {
        currentMatches = currentMatches.filter((entry)=>entry.isDirectory);
    }
    if (!includeDirs) {
        currentMatches = currentMatches.filter((entry)=>!entry.isDirectory);
    }
    yield* currentMatches;
}
const EXISTS_ERROR = new Deno.errors.AlreadyExists("dest already exists.");
async function move(src, dest, { overwrite =false  } = {}) {
    const srcStat = await Deno.stat(src);
    if (srcStat.isDirectory && isSubdir(src, dest)) {
        throw new Error(`Cannot move '${src}' to a subdirectory of itself, '${dest}'.`);
    }
    if (overwrite) {
        try {
            await Deno.remove(dest, {
                recursive: true
            });
        } catch (error) {
            if (!(error instanceof Deno.errors.NotFound)) {
                throw error;
            }
        }
    } else {
        try {
            await Deno.lstat(dest);
            return Promise.reject(EXISTS_ERROR);
        } catch  {}
    }
    await Deno.rename(src, dest);
}
function moveSync(src, dest, { overwrite =false  } = {}) {
    const srcStat = Deno.statSync(src);
    if (srcStat.isDirectory && isSubdir(src, dest)) {
        throw new Error(`Cannot move '${src}' to a subdirectory of itself, '${dest}'.`);
    }
    if (overwrite) {
        try {
            Deno.removeSync(dest, {
                recursive: true
            });
        } catch (error) {
            if (!(error instanceof Deno.errors.NotFound)) {
                throw error;
            }
        }
    } else {
        try {
            Deno.lstatSync(dest);
            throw EXISTS_ERROR;
        } catch (error) {
            if (error === EXISTS_ERROR) {
                throw error;
            }
        }
    }
    Deno.renameSync(src, dest);
}
async function ensureValidCopy(src, dest, options) {
    let destStat;
    try {
        destStat = await Deno.lstat(dest);
    } catch (err) {
        if (err instanceof Deno.errors.NotFound) {
            return;
        }
        throw err;
    }
    if (options.isFolder && !destStat.isDirectory) {
        throw new Error(`Cannot overwrite non-directory '${dest}' with directory '${src}'.`);
    }
    if (!options.overwrite) {
        throw new Deno.errors.AlreadyExists(`'${dest}' already exists.`);
    }
    return destStat;
}
function ensureValidCopySync(src, dest, options) {
    let destStat;
    try {
        destStat = Deno.lstatSync(dest);
    } catch (err) {
        if (err instanceof Deno.errors.NotFound) {
            return;
        }
        throw err;
    }
    if (options.isFolder && !destStat.isDirectory) {
        throw new Error(`Cannot overwrite non-directory '${dest}' with directory '${src}'.`);
    }
    if (!options.overwrite) {
        throw new Deno.errors.AlreadyExists(`'${dest}' already exists.`);
    }
    return destStat;
}
async function copyFile(src, dest, options) {
    await ensureValidCopy(src, dest, options);
    await Deno.copyFile(src, dest);
    if (options.preserveTimestamps) {
        const statInfo = await Deno.stat(src);
        assert(statInfo.atime instanceof Date, `statInfo.atime is unavailable`);
        assert(statInfo.mtime instanceof Date, `statInfo.mtime is unavailable`);
        await Deno.utime(dest, statInfo.atime, statInfo.mtime);
    }
}
function copyFileSync(src, dest, options) {
    ensureValidCopySync(src, dest, options);
    Deno.copyFileSync(src, dest);
    if (options.preserveTimestamps) {
        const statInfo = Deno.statSync(src);
        assert(statInfo.atime instanceof Date, `statInfo.atime is unavailable`);
        assert(statInfo.mtime instanceof Date, `statInfo.mtime is unavailable`);
        Deno.utimeSync(dest, statInfo.atime, statInfo.mtime);
    }
}
async function copySymLink(src, dest, options) {
    await ensureValidCopy(src, dest, options);
    const originSrcFilePath = await Deno.readLink(src);
    const type = getFileInfoType(await Deno.lstat(src));
    if (isWindows) {
        await Deno.symlink(originSrcFilePath, dest, {
            type: type === "dir" ? "dir" : "file"
        });
    } else {
        await Deno.symlink(originSrcFilePath, dest);
    }
    if (options.preserveTimestamps) {
        const statInfo = await Deno.lstat(src);
        assert(statInfo.atime instanceof Date, `statInfo.atime is unavailable`);
        assert(statInfo.mtime instanceof Date, `statInfo.mtime is unavailable`);
        await Deno.utime(dest, statInfo.atime, statInfo.mtime);
    }
}
function copySymlinkSync(src, dest, options) {
    ensureValidCopySync(src, dest, options);
    const originSrcFilePath = Deno.readLinkSync(src);
    const type = getFileInfoType(Deno.lstatSync(src));
    if (isWindows) {
        Deno.symlinkSync(originSrcFilePath, dest, {
            type: type === "dir" ? "dir" : "file"
        });
    } else {
        Deno.symlinkSync(originSrcFilePath, dest);
    }
    if (options.preserveTimestamps) {
        const statInfo = Deno.lstatSync(src);
        assert(statInfo.atime instanceof Date, `statInfo.atime is unavailable`);
        assert(statInfo.mtime instanceof Date, `statInfo.mtime is unavailable`);
        Deno.utimeSync(dest, statInfo.atime, statInfo.mtime);
    }
}
async function copyDir(src, dest, options) {
    const destStat = await ensureValidCopy(src, dest, {
        ...options,
        isFolder: true
    });
    if (!destStat) {
        await ensureDir(dest);
    }
    if (options.preserveTimestamps) {
        const srcStatInfo = await Deno.stat(src);
        assert(srcStatInfo.atime instanceof Date, `statInfo.atime is unavailable`);
        assert(srcStatInfo.mtime instanceof Date, `statInfo.mtime is unavailable`);
        await Deno.utime(dest, srcStatInfo.atime, srcStatInfo.mtime);
    }
    src = toPathString(src);
    dest = toPathString(dest);
    for await (const entry of Deno.readDir(src)){
        const srcPath = join3(src, entry.name);
        const destPath = join3(dest, basename2(srcPath));
        if (entry.isSymlink) {
            await copySymLink(srcPath, destPath, options);
        } else if (entry.isDirectory) {
            await copyDir(srcPath, destPath, options);
        } else if (entry.isFile) {
            await copyFile(srcPath, destPath, options);
        }
    }
}
function copyDirSync(src, dest, options) {
    const destStat = ensureValidCopySync(src, dest, {
        ...options,
        isFolder: true
    });
    if (!destStat) {
        ensureDirSync(dest);
    }
    if (options.preserveTimestamps) {
        const srcStatInfo = Deno.statSync(src);
        assert(srcStatInfo.atime instanceof Date, `statInfo.atime is unavailable`);
        assert(srcStatInfo.mtime instanceof Date, `statInfo.mtime is unavailable`);
        Deno.utimeSync(dest, srcStatInfo.atime, srcStatInfo.mtime);
    }
    src = toPathString(src);
    dest = toPathString(dest);
    for (const entry of Deno.readDirSync(src)){
        assert(entry.name != null, "file.name must be set");
        const srcPath = join3(src, entry.name);
        const destPath = join3(dest, basename2(srcPath));
        if (entry.isSymlink) {
            copySymlinkSync(srcPath, destPath, options);
        } else if (entry.isDirectory) {
            copyDirSync(srcPath, destPath, options);
        } else if (entry.isFile) {
            copyFileSync(srcPath, destPath, options);
        }
    }
}
async function copy2(src, dest, options = {}) {
    src = resolve2(toPathString(src));
    dest = resolve2(toPathString(dest));
    if (src === dest) {
        throw new Error("Source and destination cannot be the same.");
    }
    const srcStat = await Deno.lstat(src);
    if (srcStat.isDirectory && isSubdir(src, dest)) {
        throw new Error(`Cannot copy '${src}' to a subdirectory of itself, '${dest}'.`);
    }
    if (srcStat.isSymlink) {
        await copySymLink(src, dest, options);
    } else if (srcStat.isDirectory) {
        await copyDir(src, dest, options);
    } else if (srcStat.isFile) {
        await copyFile(src, dest, options);
    }
}
function copySync(src, dest, options = {}) {
    src = resolve2(toPathString(src));
    dest = resolve2(toPathString(dest));
    if (src === dest) {
        throw new Error("Source and destination cannot be the same.");
    }
    const srcStat = Deno.lstatSync(src);
    if (srcStat.isDirectory && isSubdir(src, dest)) {
        throw new Error(`Cannot copy '${src}' to a subdirectory of itself, '${dest}'.`);
    }
    if (srcStat.isSymlink) {
        copySymlinkSync(src, dest, options);
    } else if (srcStat.isDirectory) {
        copyDirSync(src, dest, options);
    } else if (srcStat.isFile) {
        copyFileSync(src, dest, options);
    }
}
var EOL;
(function(EOL) {
    EOL["LF"] = "\n";
    EOL["CRLF"] = "\r\n";
})(EOL || (EOL = {}));
const regDetect = /(?:\r?\n)/g;
function detect(content) {
    const d = content.match(regDetect);
    if (!d || d.length === 0) {
        return null;
    }
    const hasCRLF = d.some((x)=>x === EOL.CRLF);
    return hasCRLF ? EOL.CRLF : EOL.LF;
}
function format4(content, eol) {
    return content.replace(regDetect, eol);
}
const mod13 = {
    exists: exists1,
    existsSync,
    emptyDir,
    emptyDirSync,
    ensureDir,
    ensureDirSync,
    ensureFile,
    ensureFileSync,
    ensureLink,
    ensureLinkSync,
    ensureSymlink,
    ensureSymlinkSync,
    expandGlob,
    expandGlobSync,
    walk,
    walkSync,
    move,
    moveSync,
    copy: copy2,
    copySync,
    EOL,
    detect,
    format: format4
};
const random = (bytes)=>crypto.getRandomValues(new Uint8Array(bytes));
const urlAlphabet = 'ModuleSymbhasOwnPr-0123456789ABCDEFGHNRVfgctiUvz_KqYTJkLxpZXIjQW';
const nanoid = (size = 21)=>{
    let id = "";
    const bytes = random(size);
    while(size--)id += urlAlphabet[bytes[size] & 63];
    return id;
};
const { hasOwn  } = Object;
function get(obj, key) {
    if (hasOwn(obj, key)) {
        return obj[key];
    }
}
function getForce(obj, key) {
    const v = get(obj, key);
    assert(v != null);
    return v;
}
function isNumber1(x) {
    if (typeof x === "number") return true;
    if (/^0x[0-9a-f]+$/i.test(String(x))) return true;
    return /^[-+]?(?:\d+(?:\.\d*)?|\.\d+)(e[-+]?\d+)?$/.test(String(x));
}
function hasKey(obj, keys) {
    let o = obj;
    keys.slice(0, -1).forEach((key)=>{
        o = get(o, key) ?? {};
    });
    const key = keys[keys.length - 1];
    return hasOwn(o, key);
}
function parse6(args, { "--": doubleDash = false , alias ={} , boolean: __boolean = false , default: defaults = {} , stopEarly =false , string =[] , collect =[] , negatable =[] , unknown =(i)=>i  } = {}) {
    const aliases = {};
    const flags = {
        bools: {},
        strings: {},
        unknownFn: unknown,
        allBools: false,
        collect: {},
        negatable: {}
    };
    if (alias !== undefined) {
        for(const key in alias){
            const val = getForce(alias, key);
            if (typeof val === "string") {
                aliases[key] = [
                    val
                ];
            } else {
                aliases[key] = val;
            }
            for (const alias of getForce(aliases, key)){
                aliases[alias] = [
                    key
                ].concat(aliases[key].filter((y)=>alias !== y));
            }
        }
    }
    if (__boolean !== undefined) {
        if (typeof __boolean === "boolean") {
            flags.allBools = !!__boolean;
        } else {
            const booleanArgs = typeof __boolean === "string" ? [
                __boolean
            ] : __boolean;
            for (const key of booleanArgs.filter(Boolean)){
                flags.bools[key] = true;
                const alias = get(aliases, key);
                if (alias) {
                    for (const al of alias){
                        flags.bools[al] = true;
                    }
                }
            }
        }
    }
    if (string !== undefined) {
        const stringArgs = typeof string === "string" ? [
            string
        ] : string;
        for (const key of stringArgs.filter(Boolean)){
            flags.strings[key] = true;
            const alias = get(aliases, key);
            if (alias) {
                for (const al of alias){
                    flags.strings[al] = true;
                }
            }
        }
    }
    if (collect !== undefined) {
        const collectArgs = typeof collect === "string" ? [
            collect
        ] : collect;
        for (const key of collectArgs.filter(Boolean)){
            flags.collect[key] = true;
            const alias = get(aliases, key);
            if (alias) {
                for (const al of alias){
                    flags.collect[al] = true;
                }
            }
        }
    }
    if (negatable !== undefined) {
        const negatableArgs = typeof negatable === "string" ? [
            negatable
        ] : negatable;
        for (const key of negatableArgs.filter(Boolean)){
            flags.negatable[key] = true;
            const alias = get(aliases, key);
            if (alias) {
                for (const al of alias){
                    flags.negatable[al] = true;
                }
            }
        }
    }
    const argv = {
        _: []
    };
    function argDefined(key, arg) {
        return flags.allBools && /^--[^=]+$/.test(arg) || get(flags.bools, key) || !!get(flags.strings, key) || !!get(aliases, key);
    }
    function setKey(obj, name, value, collect = true) {
        let o = obj;
        const keys = name.split(".");
        keys.slice(0, -1).forEach(function(key) {
            if (get(o, key) === undefined) {
                o[key] = {};
            }
            o = get(o, key);
        });
        const key = keys[keys.length - 1];
        const collectable = collect && !!get(flags.collect, name);
        if (!collectable) {
            o[key] = value;
        } else if (get(o, key) === undefined) {
            o[key] = [
                value
            ];
        } else if (Array.isArray(get(o, key))) {
            o[key].push(value);
        } else {
            o[key] = [
                get(o, key),
                value
            ];
        }
    }
    function setArg(key, val, arg = undefined, collect) {
        if (arg && flags.unknownFn && !argDefined(key, arg)) {
            if (flags.unknownFn(arg, key, val) === false) return;
        }
        const value = !get(flags.strings, key) && isNumber1(val) ? Number(val) : val;
        setKey(argv, key, value, collect);
        const alias = get(aliases, key);
        if (alias) {
            for (const x of alias){
                setKey(argv, x, value, collect);
            }
        }
    }
    function aliasIsBoolean(key) {
        return getForce(aliases, key).some((x)=>typeof get(flags.bools, x) === "boolean");
    }
    let notFlags = [];
    if (args.includes("--")) {
        notFlags = args.slice(args.indexOf("--") + 1);
        args = args.slice(0, args.indexOf("--"));
    }
    for(let i = 0; i < args.length; i++){
        const arg = args[i];
        if (/^--.+=/.test(arg)) {
            const m = arg.match(/^--([^=]+)=(.*)$/s);
            assert(m != null);
            const [, key, value] = m;
            if (flags.bools[key]) {
                const booleanValue = value !== "false";
                setArg(key, booleanValue, arg);
            } else {
                setArg(key, value, arg);
            }
        } else if (/^--no-.+/.test(arg) && get(flags.negatable, arg.replace(/^--no-/, ""))) {
            const m = arg.match(/^--no-(.+)/);
            assert(m != null);
            setArg(m[1], false, arg, false);
        } else if (/^--.+/.test(arg)) {
            const m = arg.match(/^--(.+)/);
            assert(m != null);
            const [, key] = m;
            const next = args[i + 1];
            if (next !== undefined && !/^-/.test(next) && !get(flags.bools, key) && !flags.allBools && (get(aliases, key) ? !aliasIsBoolean(key) : true)) {
                setArg(key, next, arg);
                i++;
            } else if (/^(true|false)$/.test(next)) {
                setArg(key, next === "true", arg);
                i++;
            } else {
                setArg(key, get(flags.strings, key) ? "" : true, arg);
            }
        } else if (/^-[^-]+/.test(arg)) {
            const letters = arg.slice(1, -1).split("");
            let broken = false;
            for(let j = 0; j < letters.length; j++){
                const next = arg.slice(j + 2);
                if (next === "-") {
                    setArg(letters[j], next, arg);
                    continue;
                }
                if (/[A-Za-z]/.test(letters[j]) && /=/.test(next)) {
                    setArg(letters[j], next.split(/=(.+)/)[1], arg);
                    broken = true;
                    break;
                }
                if (/[A-Za-z]/.test(letters[j]) && /-?\d+(\.\d*)?(e-?\d+)?$/.test(next)) {
                    setArg(letters[j], next, arg);
                    broken = true;
                    break;
                }
                if (letters[j + 1] && letters[j + 1].match(/\W/)) {
                    setArg(letters[j], arg.slice(j + 2), arg);
                    broken = true;
                    break;
                } else {
                    setArg(letters[j], get(flags.strings, letters[j]) ? "" : true, arg);
                }
            }
            const [key] = arg.slice(-1);
            if (!broken && key !== "-") {
                if (args[i + 1] && !/^(-|--)[^-]/.test(args[i + 1]) && !get(flags.bools, key) && (get(aliases, key) ? !aliasIsBoolean(key) : true)) {
                    setArg(key, args[i + 1], arg);
                    i++;
                } else if (args[i + 1] && /^(true|false)$/.test(args[i + 1])) {
                    setArg(key, args[i + 1] === "true", arg);
                    i++;
                } else {
                    setArg(key, get(flags.strings, key) ? "" : true, arg);
                }
            }
        } else {
            if (!flags.unknownFn || flags.unknownFn(arg) !== false) {
                argv._.push(flags.strings["_"] ?? !isNumber1(arg) ? arg : Number(arg));
            }
            if (stopEarly) {
                argv._.push(...args.slice(i + 1));
                break;
            }
        }
    }
    for (const [key, value] of Object.entries(defaults)){
        if (!hasKey(argv, key.split("."))) {
            setKey(argv, key, value);
            if (aliases[key]) {
                for (const x of aliases[key]){
                    setKey(argv, x, value);
                }
            }
        }
    }
    for (const key of Object.keys(flags.bools)){
        if (!hasKey(argv, key.split("."))) {
            const value = get(flags.collect, key) ? [] : false;
            setKey(argv, key, value, false);
        }
    }
    for (const key of Object.keys(flags.strings)){
        if (!hasKey(argv, key.split(".")) && get(flags.collect, key)) {
            setKey(argv, key, [], false);
        }
    }
    if (doubleDash) {
        argv["--"] = [];
        for (const key of notFlags){
            argv["--"].push(key);
        }
    } else {
        for (const key of notFlags){
            argv._.push(key);
        }
    }
    return argv;
}
const mod14 = {
    parse: parse6
};
const args1 = mod14.parse(Deno.args);
function getArg(name) {
    return args1[name] || args1[name.toLowerCase().replaceAll('_', '-')] || Deno.env.get('EDRYS_' + name);
}
const address = getArg('ADDRESS') ?? 'localhost:8000';
const secret = getArg('SECRET') ?? 'secret';
if (secret == 'secret') mod8.warning('For production, please specify a unique --secret to generate a secret private key. Currently using default.');
const totp_window = parseInt(getArg('TOTP_WINDOW'));
const serve_path = getArg('SERVE_PATH') ?? `./static`;
const config_class_creators = (getArg('CONFIG_CLASS_CREATORS_CSV') ?? '*').split(',');
getArg('HTTPS_CERT_FILE') ?? undefined;
getArg('HTTPS_KEY_FILE') ?? undefined;
const log_level = getArg('LOG_LEVEL') ?? 'DEBUG';
const smtp_tls = getArg('SMTP_TLS') == 'true';
const smtp_hostname = getArg('SMTP_HOST') ?? '';
const smtp_port = Number(getArg('SMTP_PORT') ?? '0');
const smtp_username = getArg('SMTP_USERNAME') ?? '';
const smtp_password = getArg('SMTP_PASSWORD') ?? '';
const smtp_from = getArg('SMTP_FROM') ?? '';
const smtp_debug = getArg('SMTP_DEBUG') == 'true';
const data_engine = getArg('DATA_ENGINE') ?? 'file';
const data_file_path = getArg('DATA_FILE_PATH') ?? '.edrys';
const data_s3_endpoint = getArg('DATA_S3_ENDPOINT') ?? '';
const data_s3_port = Number(getArg('DATA_S3_PORT') ?? '443');
const data_s3_use_ssl = getArg('DATA_S3_USE_SSL') == 'true';
const data_s3_region = getArg('DATA_S3_REGION') ?? '';
const data_s3_access_key = getArg('DATA_S3_ACCESS_KEY') ?? '';
const data_s3_secret_key = getArg('DATA_S3_SECRET_KEY') ?? '';
const data_s3_bucket = getArg('DATA_S3_BUCKET') ?? '';
const frontend_address = getArg('FRONTEND_ADDRESS') ?? address;
const config_default_modules = JSON.parse(getArg('CONFIG_DEFAULT_MODULES_JSON') ?? 'null') ?? [
    {
        url: 'https://edrys-org.github.io/module-reference/',
        config: '',
        studentConfig: '',
        teacherConfig: '',
        stationConfig: '',
        showInCustom: '',
        width: 'full',
        height: 'tall'
    }
];
const jwt_lifetime_days = Number(getArg('JWT_LIFETIME_DAYS') ?? '30');
const jwt_keys_path = getArg('JWT_KEYS_PATH') ?? false;
const limit_msg_len = Number(getArg('LIMIT_MSG_LEN') ?? '10000');
const limit_state_len = Number(getArg('LIMIT_STATE_LEN') ?? '999000');
let ready = false;
let s3c;
const inMemoryStorage = {};
if (data_engine == 's3') {
    if (data_s3_endpoint == '' || data_s3_port == 0 || data_s3_region == '' || data_s3_access_key == '' || data_s3_secret_key == '' || data_s3_bucket == '') {
        throw new Error('Invalid Data S3 config');
    }
    s3c = new mod12.S3Client({
        endPoint: data_s3_endpoint,
        port: data_s3_port,
        useSSL: data_s3_use_ssl,
        region: data_s3_region,
        accessKey: data_s3_access_key,
        secretKey: data_s3_secret_key,
        bucket: data_s3_bucket,
        pathStyle: true
    });
} else if (data_engine == 'file') {
    await mod13.ensureDir(data_file_path);
}
ready = true;
async function read(folder, file) {
    const path = `${data_file_path}/${folder}/${file}.json`;
    if (data_engine == 's3') {
        const res = await s3c.getObject(path);
        if (res.status == 200) {
            return res.json();
        } else {
            throw new Error(`S3 Error (${res.status})`);
        }
    } else if (data_engine == 'file') {
        await mod13.ensureDir(`${data_file_path}/${folder}`);
        return JSON.parse(await Deno.readTextFile(path));
    } else {
        if (path in inMemoryStorage) return JSON.parse(inMemoryStorage[path]);
        else throw new Error(`Not found: ${path}`);
    }
}
async function write(folder, file, value) {
    const text = JSON.stringify(value);
    const path = `${data_file_path}/${folder}/${file}.json`;
    if (data_engine == 's3') {
        if (text == undefined) {
            return await s3c.deleteObject(path);
        }
        await s3c.putObject(path, text);
    } else if (data_engine == 'file') {
        await mod13.ensureDir(`${data_file_path}/${folder}`);
        if (text == undefined) {
            return await Deno.remove(path);
        }
        await Deno.writeTextFile(path, text);
    } else {
        if (text == undefined) {
            delete inMemoryStorage[path];
        } else {
            inMemoryStorage[path] = text;
        }
    }
}
function setToValue(obj, pathArr, value) {
    let i = 0;
    for(i = 0; i < pathArr.length - 1; i++){
        obj = obj[pathArr[i]];
        if (!obj[pathArr[i + 1]]) {
            obj[pathArr[i + 1]] = {};
        }
    }
    obj[pathArr[i]] = value;
    if (value === null) delete obj[pathArr[i]];
}
var RoleName;
(function(RoleName) {
    RoleName["Student"] = 'student';
    RoleName["Teacher"] = 'teacher';
})(RoleName || (RoleName = {}));
var ReservedRoomNames;
(function(ReservedRoomNames) {
    ReservedRoomNames["Lobby"] = "Lobby";
    ReservedRoomNames["TeachersLounge"] = "Teacher's Lounge";
    ReservedRoomNames["StationX"] = 'Station *';
})(ReservedRoomNames || (ReservedRoomNames = {}));
function can_create_class(e) {
    return config_class_creators.includes('*') || config_class_creators.includes(`*@${e.split('@')[1]}`) || config_class_creators.filter((p)=>p.includes('/')).some((p)=>new RegExp(p, 'g').test(e)) || config_class_creators.includes(e);
}
function validate_class(c) {
    return typeof c.id == 'string' && typeof c.dateCreated == 'number' && validate_email(c.createdBy) && validate_name(c.name) && typeof c.members == 'object' && Object.entries(c.members).every((e)=>Object.values(RoleName).includes(e[0])) && Object.entries(c.members).every((e)=>e[1].every((v, _i, _a)=>validate_email(v))) && Array.isArray(c.modules) && c.modules.every((v, _i, _a)=>validate_module(v));
}
function validate_user(u) {
    return validate_email(u.email) && typeof u.dateCreated == 'number' && validate_human_name(u.displayName) && u.memberships.every((m)=>validate_url(m.instance) && typeof m.class_id == 'string' && validate_name(m.class_name) && Object.values(RoleName).includes(m.role));
}
function validate_email(e) {
    return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);
}
function validate_name(n) {
    return typeof n == 'string' && /^([A-Za-z0-9 ]{1,100})$/.test(n);
}
function validate_human_name(n) {
    return typeof n == 'string' && /^[^§¡@£%§¶^&*€#±!_+¢•ªº«\\/<>?$:;|=.,]{1,50}$/.test(n);
}
function validate_url(u) {
    try {
        new URL(u);
        return true;
    } catch (_error) {
        return false;
    }
}
function validate_module(m) {
    return validate_url(m.url) && [
        'full',
        'half',
        'third'
    ].includes(m.width) && [
        'tall',
        'medium',
        'short'
    ].includes(m.height);
}
function validate_live_state(s) {
    return JSON.stringify(s).length < limit_state_len;
}
function validate_message(message, role) {
    return message.subject.length < 1000 && (message.body.length < limit_msg_len || role == RoleName.Teacher) && validate_url(message.module);
}
async function get_class_and_role(class_id, user_id) {
    try {
        if (!class_id) {
            return undefined;
        }
        const class_ = await read('classes', class_id);
        if (!class_) {
            return undefined;
        }
        if (class_.members.student?.includes(user_id)) {
            return [
                class_,
                RoleName.Student
            ];
        } else if (class_.members.teacher?.includes(user_id)) {
            return [
                class_,
                RoleName.Teacher
            ];
        } else {
            return undefined;
        }
    } catch (_error) {
        return undefined;
    }
}
let jwt_public_key;
let jwt_private_key;
if (jwt_keys_path && data_engine === 'file') {
    jwt_private_key = await crypto.subtle.importKey('pkcs8', mod.decode(await Deno.readTextFile(`${jwt_keys_path}/jwt_private_key`)), {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-512'
    }, true, [
        'sign'
    ]);
    jwt_public_key = await crypto.subtle.importKey('spki', mod.decode(await Deno.readTextFile(`${jwt_keys_path}/jwt_public_key`)), {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-512'
    }, true, [
        'verify'
    ]);
} else {
    jwt_private_key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), {
        name: 'HMAC',
        hash: 'SHA-512'
    }, true, [
        'sign',
        'verify'
    ]);
}
true;
async function sendToken(email) {
    ensureEmailValid(email);
    const token = getTotp(email).generate();
    if (smtp_hostname == '' || smtp_port == 0 || smtp_username == '' || smtp_password == '' || smtp_from == '') {
        console.log('Email sent', {
            from: smtp_from,
            to: email,
            subject: 'Your Edrys secret code',
            content: `Use this secret code in the Edrys app: ${token}`,
            html: `Use this secret code in the Edrys app: <em>${token}</em>`
        });
    } else {
        try {
            const smtpClient = new SMTPHandler({
                debug: {
                    log: smtp_debug
                },
                connection: {
                    hostname: smtp_hostname,
                    port: smtp_port,
                    tls: smtp_tls,
                    auth: {
                        username: smtp_username,
                        password: smtp_password
                    }
                }
            });
            await smtpClient.send({
                from: smtp_from,
                to: email,
                subject: 'Your Edrys secret code',
                content: `Use this secret code in the Edrys app: ${token}`,
                html: `Use this secret code in the Edrys app: <em>${token}</em>`
            });
            smtpClient.close();
        } catch (e) {
            console.warn('SMTPclient failed:', e);
        }
    }
}
async function verifyToken(token, email) {
    ensureEmailValid(email);
    ensureTokenValid(token, email);
    return [
        await ensureUserExists(email),
        await mod10.create({
            alg: jwt_public_key ? 'RS512' : 'HS512',
            typ: 'JWT'
        }, {
            sub: normaliseEmail(email),
            iat: new Date().getTime(),
            exp: new Date().setDate(new Date().getDate() + jwt_lifetime_days)
        }, jwt_private_key)
    ];
}
async function ensureUserExists(email) {
    if (!ready) {
        throw new Error(`Error ensuring user exists, data module not ready (${email})`);
    }
    try {
        await read('users', email);
        return false;
    } catch (_error) {
        let displayName = email.trim().split('@')[0].replaceAll(/[^A-Za-z ]+/g, ' ').slice(0, 99);
        displayName = displayName.length <= 1 ? 'New User' : displayName;
        await write('users', normaliseEmail(email), {
            email: normaliseEmail(email),
            displayName: displayName,
            dateCreated: new Date().getTime(),
            memberships: []
        });
        return true;
    }
}
function ensureTokenValid(token, email) {
    const res = getTotp(email).validate({
        token: token,
        window: totp_window >= 2 ? totp_window : 11
    });
    if (res == null) {
        throw new Error(`Invalid token ${email} ${token}`);
    }
}
function getTotp(email) {
    return new mod7.TOTP({
        issuer: 'App',
        label: 'EmailToken',
        algorithm: 'SHA3-256',
        digits: 6,
        period: 30,
        secret: mod7.Secret.fromUTF8(secret + email)
    });
}
function ensureEmailValid(email) {
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
        throw new Error(`Invalid email ${email}`);
    }
}
async function ensureJwtValid(jwt) {
    try {
        return await mod10.verify(jwt, jwt_public_key ?? jwt_private_key);
    } catch (_error) {
        throw new Error(`JWT signiture validation error ${jwt}`);
    }
}
function normaliseEmail(email) {
    return email.trim().toLowerCase();
}
const middleware1 = async (ctx, next)=>{
    try {
        const jwt = ctx.request.headers?.get('Authorization')?.replace('Bearer ', '') || mod6.helpers.getQuery(ctx)['jwt'];
        if (!jwt) throw new Error('Unauthorized');
        const jwt_verified = await ensureJwtValid(jwt);
        ctx.state.user = jwt_verified.sub;
    } catch (_error) {}
    await next();
};
const router = new mod6.Router().get('/jwtPublicKey', async (ctx)=>{
    ctx.response.body = mod.encode(await crypto.subtle.exportKey('spki', jwt_public_key));
}).get('/sendToken', async (ctx)=>{
    await sendToken(mod6.helpers.getQuery(ctx)['email']);
    ctx.response.body = 'Sent';
}).get('/verifyToken', async (ctx)=>{
    try {
        const [isNewbie, jwt] = await verifyToken(mod6.helpers.getQuery(ctx)['token'], mod6.helpers.getQuery(ctx)['email']);
        ctx.response.body = [
            isNewbie,
            jwt
        ];
    } catch (error) {
        console.log(error);
        ctx.response.status = 401;
    }
});
const classes = {};
const router1 = new mod6.Router().get('/readUser', async (ctx)=>{
    if (!ctx.state.user) ctx.throw(401);
    ctx.response.body = await read('users', ctx.state.user);
    ctx.response.status = 200;
}).get('/updateUser', async (ctx)=>{
    if (!ctx.state.user) ctx.throw(401);
    const user_new = JSON.parse(mod6.helpers.getQuery(ctx)['user']);
    if (!user_new || ctx.state.user != user_new.email || !validate_user(user_new)) {
        ctx.response.status = 400;
        return;
    } else {
        const user_old = await read('users', ctx.state.user);
        user_new.dateCreated = user_old.dateCreated;
        const user = {
            ...user_old,
            ...user_new
        };
        await write('users', ctx.state.user, user);
        ctx.response.body = user;
        ctx.response.status = 200;
    }
}).get('/canCreateClass', (ctx)=>{
    if (!ctx.state.user) ctx.throw(401);
    ctx.response.body = can_create_class(ctx.state.user);
    ctx.response.status = 200;
}).get('/readClass/:class_id', async (ctx)=>{
    if (!ctx.state.user) ctx.throw(401);
    const class_id = ctx?.params?.class_id;
    const res = await get_class_and_role(class_id, ctx.state.user);
    if (res == undefined) {
        ctx.response.status = 404;
        return;
    }
    const [class_, role] = res;
    if (role == RoleName.Student) {
        ctx.response.body = {
            id: class_.id,
            dateCreated: class_.dateCreated,
            createdBy: class_.createdBy,
            name: class_.name,
            modules: class_.modules.map((m)=>({
                    url: m.url,
                    config: m.config,
                    studentConfig: m.studentConfig,
                    width: m.width,
                    height: m.height
                })),
            members: {
                [RoleName.Student]: [
                    ctx.state.user
                ]
            }
        };
        ctx.response.status = 200;
    } else if (role == RoleName.Teacher) {
        ctx.response.body = class_;
        ctx.response.status = 200;
    } else {
        ctx.response.status = 404;
    }
}).get('/createClass', async (ctx)=>{
    if (!ctx.state.user) ctx.throw(401);
    if (can_create_class(ctx.state.user)) {
        const new_class_id = nanoid();
        const new_class = {
            id: new_class_id,
            createdBy: ctx.state.user,
            dateCreated: new Date().getTime(),
            name: 'My New Class',
            members: {
                teacher: [
                    ctx.state.user
                ],
                student: []
            },
            modules: config_default_modules
        };
        await write('classes', new_class_id, new_class);
        ctx.response.body = new_class_id;
        ctx.response.status = 200;
    }
}).get('/updateClass/:class_id', async (ctx)=>{
    if (!ctx.state.user) ctx.throw(401);
    const class_id = ctx?.params?.class_id;
    const class_new = JSON.parse(mod6.helpers.getQuery(ctx)['class']);
    if (!class_new || class_id != class_new.id || !validate_class(class_new)) {
        ctx.response.status = 400;
        return;
    }
    const res = await get_class_and_role(class_id, ctx.state.user);
    if (typeof res == 'undefined') {
        ctx.response.status = 404;
        return;
    }
    const [class_old, role] = res;
    class_new.dateCreated = class_old.dateCreated;
    class_new.createdBy = class_old.createdBy;
    class_new.members.teacher.push(ctx.state.user);
    class_new.members.teacher = [
        ...new Set(class_new.members.teacher)
    ];
    class_new.members.student = [
        ...new Set(class_new.members.student)
    ];
    if (role == RoleName.Student) {
        ctx.response.status = 404;
    } else if (role == RoleName.Teacher) {
        const class_ = {
            ...class_old,
            ...class_new
        };
        await write('classes', class_id, class_);
        for (const user_id of Object.keys(classes[class_id]?.users || [])){
            if (!class_new.members.student.includes(user_id) && !class_new.members.teacher.includes(user_id) && classes[class_id]?.users[user_id].room !== 'Station ' + user_id) {
                delete classes[class_id]?.users[user_id];
            }
        }
        await onClassUpdated(class_id);
        ctx.response.body = class_;
        ctx.response.status = 200;
    } else {
        ctx.response.status = 404;
    }
}).get('/deleteClass/:class_id', async (ctx)=>{
    if (!ctx.state.user) ctx.throw(401);
    const class_id = ctx?.params?.class_id;
    const res = await get_class_and_role(class_id, ctx.state.user);
    if (typeof res == 'undefined') {
        ctx.response.status = 404;
        return;
    }
    const [_, role] = res;
    if (role == RoleName.Teacher) {
        await Object.values(classes[class_id]?.users || []).flatMap((u)=>u.connections).forEach(async (c)=>{
            await c.target.close();
        });
        delete classes[class_id];
        await write('classes', class_id, undefined);
        ctx.response.body = 'OK';
        ctx.response.status = 200;
    } else {
        ctx.response.status = 404;
    }
}).get('/readLiveClass/:class_id', async (ctx)=>{
    if (!ctx.state.user) ctx.throw(401);
    const class_id = ctx?.params?.class_id;
    const display_name = mod6.helpers.getQuery(ctx)['displayName'];
    const is_station = mod6.helpers.getQuery(ctx)['isStation'] == 'true';
    const username = is_station ? display_name : ctx.state.user;
    const res = await get_class_and_role(class_id, ctx.state.user);
    if (typeof res == 'undefined' || !validate_name(display_name) || is_station && display_name.includes('@')) {
        ctx.response.status = 404;
        return;
    }
    const target = ctx.sendEvents();
    const [_, role] = res;
    let live_class = classes[class_id];
    if (role != RoleName.Teacher && is_station) {
        ctx.response.status = 401;
        return;
    }
    if (!live_class) {
        classes[class_id] = {
            autoAssign: undefined,
            users: {},
            rooms: {
                Lobby: {
                    studentPublicState: '',
                    teacherPublicState: '',
                    teacherPrivateState: ''
                },
                "Teacher's Lounge": {
                    studentPublicState: '',
                    teacherPublicState: '',
                    teacherPrivateState: ''
                }
            }
        };
        live_class = classes[class_id];
    }
    let connection_id = '';
    if (live_class.users[username]) {
        connection_id = nanoid();
        live_class.users[username].connections ??= [];
        live_class.users[username].connections.push({
            id: connection_id,
            target: target
        });
    } else {
        live_class.users[username] = {
            displayName: display_name,
            room: is_station ? `Station ${display_name}` : ReservedRoomNames.Lobby,
            role: role,
            dateJoined: new Date().getTime(),
            handRaised: false,
            connections: [
                {
                    id: connection_id,
                    target: target
                }
            ]
        };
        if (is_station) {
            live_class.rooms[`Station ${display_name}`] = {
                studentPublicState: '',
                teacherPublicState: '',
                teacherPrivateState: '',
                userLinked: username
            };
        }
    }
    await onClassUpdated(class_id);
    if (!classes[class_id]?.users[username] || !classes[class_id]?.users[username].connections.length) {
        target.close();
    }
    const kaInterval = setInterval(()=>{
        target.dispatchComment('ka');
    }, 1000);
    target.addEventListener('close', async (_e)=>{
        clearInterval(kaInterval);
        const live_class = classes[class_id];
        if (!live_class) {
            return;
        }
        mod8.debug([
            'Disconnection',
            username
        ]);
        const all_connections = Object.values(live_class.users).flatMap((u)=>u.connections);
        if (all_connections.length == 1) {
            delete classes[class_id];
        } else if (!live_class.users[username]) {
            delete classes[class_id]?.users[username];
        } else if (live_class.users[username]?.connections?.length == 1) {
            delete classes[class_id]?.users[username];
            Object.entries(live_class.rooms).filter((r)=>r[1].userLinked == username).forEach((r)=>{
                delete classes[class_id]?.rooms[r[0]];
            });
        } else {
            live_class.users[username].connections = live_class.users[username].connections?.filter((c)=>c.id != connection_id);
            live_class.users[username].connections ??= [];
        }
        await onClassUpdated(class_id);
    });
}).get('/updateLiveClass/:class_id', async (ctx)=>{
    if (!ctx.state.user) ctx.throw(401);
    const class_id = ctx?.params?.class_id;
    if (!classes[class_id]) {
        ctx.response.status = 404;
        return;
    }
    const res = await get_class_and_role(class_id, ctx.state.user);
    if (typeof res == 'undefined') {
        ctx.response.status = 404;
        return;
    }
    const [_, role] = res;
    const live_class = classes[class_id];
    if (!live_class) {
        ctx.response.status = 400;
        return;
    }
    const stationId = mod6.helpers.getQuery(ctx)['stationId'];
    const username = stationId || ctx.state.user;
    if (role != RoleName.Teacher && stationId) {
        ctx.response.status = 401;
        return;
    }
    const user = live_class.users[username];
    const update_str = mod6.helpers.getQuery(ctx)['update'];
    if (update_str.length > 100000) {
        ctx.response.status = 401;
        return;
    }
    const update = JSON.parse(update_str);
    const update_path_str = JSON.stringify(update.path);
    if (role == RoleName.Student) {
        const valid_student_updates = [
            [
                JSON.stringify([
                    'rooms',
                    user.room,
                    'studentPublicState'
                ]),
                validate_live_state
            ],
            [
                JSON.stringify([
                    'users',
                    username,
                    'displayName'
                ]),
                validate_human_name
            ],
            [
                JSON.stringify([
                    'users',
                    username,
                    'handRaised'
                ]),
                (v)=>v === true || v === false
            ]
        ];
        if (!valid_student_updates.some((u)=>u[0] == update_path_str && u[1](update.value))) {
            ctx.response.status = 401;
            return;
        }
    } else if (role == RoleName.Teacher) {
        if (update.path.length == 3 && update.path[0] == 'users' && update.path[2] == 'room') {
            const dateJoiendPath = [
                ...update.path
            ];
            dateJoiendPath[2] = 'dateJoined';
            setToValue(classes[class_id], dateJoiendPath, new Date().getTime());
        }
    }
    setToValue(classes[class_id], update.path, update.value);
    await onClassUpdated(class_id);
    ctx.response.status = 200;
}).get('/sendMessage/:class_id', (ctx)=>{
    if (!ctx.state.user) ctx.throw(401);
    const class_id = ctx?.params?.class_id;
    const message = JSON.parse(mod6.helpers.getQuery(ctx)['message']);
    const user_role = classes[class_id]?.users[ctx.state.user]?.role || RoleName.Student;
    if (!class_id || !validate_message(message, user_role) || validate_email(message.from) && message.from != ctx.state.user || !validate_email(message.from) && user_role == 'student') {
        ctx.response.status = 400;
        return;
    }
    if (sendMessage(class_id, message)) {
        ctx.response.status = 200;
    } else {
        ctx.response.status = 401;
    }
});
async function onClassUpdated(class_id) {
    const live_class = classes[class_id];
    if (!live_class) {
        return false;
    }
    mod8.debug([
        'Class Update',
        class_id,
        live_class
    ]);
    for (const user_id of Object.keys(classes[class_id]?.users || [])){
        const user = live_class.users[user_id];
        const connections = user?.connections;
        if (!user || !connections) {
            continue;
        }
        let res = undefined;
        if (user.role == RoleName.Student) {
            res = {
                rooms: {
                    [user.room]: {
                        ...live_class.rooms[user.room],
                        teacherPrivateState: undefined
                    }
                },
                users: {
                    [user_id]: {
                        ...user
                    }
                }
            };
        } else if (user.role == RoleName.Teacher) {
            res = live_class;
        }
        connections.forEach((c)=>c.target.dispatchEvent(new mod6.ServerSentEvent('update', res)));
    }
    return true;
}
function sendMessage(class_id, message) {
    const live_class = classes[class_id];
    if (!live_class) return false;
    mod8.debug([
        'Message to be sent',
        class_id,
        message
    ]);
    const user_from = live_class.users[message.from];
    if (!user_from) return true;
    const user_conns_in_room = Object.entries(classes[class_id]?.users || []).filter((u)=>u[1].room == user_from.room).flatMap((u)=>u[1].connections);
    for (const user_conn of user_conns_in_room){
        user_conn.target.dispatchEvent(new mod6.ServerSentEvent('message', {
            ...message,
            date: new Date().getTime()
        }));
    }
    return true;
}
const app = new mod6.Application();
if (frontend_address) {
    app.use((ctx, next)=>{
        ctx.response.headers.set('Access-Control-Allow-Origin', frontend_address);
        ctx.response.headers.set('Access-Control-Allow-Credential', 'true');
        ctx.response.headers.set('Access-Control-Allow-Methods', 'GET,HEAD,OPTIONS');
        ctx.response.headers.set('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
        return next();
    });
}
app.use(async (ctx, next)=>{
    await next();
    mod8.info(`${new Date().toISOString()} ${ctx.request.method} ${ctx.request.url}`);
});
await mod8.setup({
    handlers: {
        console: new mod8.handlers.ConsoleHandler('DEBUG', {
            formatter: '{levelName} {datetime} {msg}'
        })
    },
    loggers: {
        default: {
            level: log_level,
            handlers: [
                'console'
            ]
        }
    }
});
const ping_router = new mod6.Router();
ping_router.get('/ping', (ctx)=>{
    ctx.response.body = address;
});
app.use(ping_router.routes());
app.use(ping_router.allowedMethods());
const auth_router = new mod6.Router().use('/auth', router.routes(), router.allowedMethods());
app.use(auth_router.routes());
app.use(auth_router.allowedMethods());
app.use(middleware1);
const data_router = new mod6.Router().use('/data', router1.routes(), router1.allowedMethods());
app.use(data_router.routes());
app.use(data_router.allowedMethods());
app.use(async (context, next)=>{
    try {
        await context.send({
            root: serve_path,
            index: 'index.html'
        });
    } catch  {
        next();
    }
});
const hostname = address.split(':')[0];
const port = address.split(':')[1];
mod8.info(`Listening on ${hostname}:${port}`);
await app.listen({
    hostname: hostname,
    port: Number(port),
    alpnProtocols: [
        'h2'
    ]
});
