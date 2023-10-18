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
            const { offset, start, end } = this.#chunks[i];
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
        const { value, offset, start } = this.#chunks[idx];
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
        for (const { value, start, end } of this.#chunks){
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
        const { length } = this;
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
        const { length } = this;
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
        const { secure = false, response = new Headers() } = options;
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
        const { keys } = options;
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
    #grow(n) {
        const m = this.length;
        if (m === 0 && this.#off !== 0) {
            this.reset();
        }
        const i = this.#tryGrowByReslice(n);
        if (i >= 0) {
            return i;
        }
        const c = this.capacity;
        if (n <= Math.floor(c / 2) - m) {
            copy(this.#buf.subarray(this.#off), this.#buf);
        } else if (c + n > MAX_SIZE) {
            throw new Error("The buffer cannot be grown beyond the maximum size.");
        } else {
            const buf = new Uint8Array(Math.min(2 * c + n, MAX_SIZE));
            copy(this.#buf.subarray(this.#off), buf);
            this.#buf = buf;
        }
        this.#off = 0;
        this.#reslice(Math.min(m + n, MAX_SIZE));
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
    reader;
    limit;
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
    #grow(n) {
        const m = this.length;
        if (m === 0 && this.#off !== 0) {
            this.reset();
        }
        const i = this.#tryGrowByReslice(n);
        if (i >= 0) {
            return i;
        }
        const c = this.capacity;
        if (n <= Math.floor(c / 2) - m) {
            copy(this.#buf.subarray(this.#off), this.#buf);
        } else if (c + n > MAX_SIZE1) {
            throw new Error("The buffer cannot be grown beyond the maximum size.");
        } else {
            const buf = new Uint8Array(Math.min(2 * c + n, MAX_SIZE1));
            copy(this.#buf.subarray(this.#off), buf);
            this.#buf = buf;
        }
        this.#off = 0;
        this.#reslice(Math.min(m + n, MAX_SIZE1));
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
    const { Deno: Deno1 } = globalThis;
    if (typeof Deno1?.build?.os === "string") {
        return Deno1.build.os;
    }
    const { navigator } = globalThis;
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
        const { Deno: Deno1 } = globalThis;
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
            const { Deno: Deno1 } = globalThis;
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
const path = isWindows ? mod1 : mod2;
const { join: join2, normalize: normalize2 } = path;
const path1 = isWindows ? mod1 : mod2;
const { basename: basename2, delimiter: delimiter2, dirname: dirname2, extname: extname2, format: format2, fromFileUrl: fromFileUrl2, isAbsolute: isAbsolute2, join: join3, normalize: normalize3, parse: parse2, relative: relative2, resolve: resolve2, sep: sep2, toFileUrl: toFileUrl2, toNamespacedPath: toNamespacedPath2 } = path1;
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
    const { prefixes = "./" } = options;
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
        const { type: nextType, index } = tokens[i];
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
    const { encode = (x)=>x, validate = true } = options;
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
    const { strict = false, start = true, end = true, encode = (x)=>x, delimiter = "/#?", endsWith = "" } = options;
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
    type;
    subtype;
    suffix;
    constructor(type, subtype, suffix){
        this.type = type;
        this.subtype = subtype;
        this.suffix = suffix;
    }
}
function format3(obj) {
    const { subtype, suffix, type } = obj;
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
    const { autoClose = true, chunkSize = 16_640, strategy } = options;
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
    partial;
    name;
    constructor(partial){
        super("Buffer full");
        this.partial = partial;
        this.name = "BufferFullError";
    }
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
            let { partial } = err;
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
        const { bytes } = readResult;
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
async function* parts({ body, customContentTypes = {}, final: __final, part, maxFileSize, maxSize, outPath, prefix }) {
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
                const { bytes } = readResult;
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
                const { bytes } = readResult;
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
        const { outPath, maxFileSize = 10_485_760, maxSize = 0, bufferSize = 1_048_576, customContentTypes } = options;
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
        const { outPath, customContentTypes, maxFileSize = 10_485_760, maxSize = 0, bufferSize = 32000 } = options;
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
    #parse(type, limit) {
        switch(type){
            case "form":
                this.#type = "bytes";
                if (this.#exceedsLimit(limit)) {
                    return ()=>Promise.reject(new RangeError(`Body exceeds a limit of ${limit}.`));
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
                if (this.#exceedsLimit(limit)) {
                    return ()=>Promise.reject(new RangeError(`Body exceeds a limit of ${limit}.`));
                }
                return async ()=>{
                    const value = await this.#valuePromise();
                    return value.length ? JSON.parse(decoder2.decode(await this.#valuePromise()), this.#jsonBodyReviver) : null;
                };
            case "bytes":
                this.#type = "bytes";
                if (this.#exceedsLimit(limit)) {
                    return ()=>Promise.reject(new RangeError(`Body exceeds a limit of ${limit}.`));
                }
                return ()=>this.#valuePromise();
            case "text":
                this.#type = "bytes";
                if (this.#exceedsLimit(limit)) {
                    return ()=>Promise.reject(new RangeError(`Body exceeds a limit of ${limit}.`));
                }
                return async ()=>decoder2.decode(await this.#valuePromise());
            default:
                throw new TypeError(`Invalid body type: "${type}"`);
        }
    }
    #validateGetArgs(type, contentTypes) {
        if (type === "reader" && this.#type && this.#type !== "reader") {
            throw new TypeError(`Body already consumed as "${this.#type}" and cannot be returned as a reader.`);
        }
        if (type === "stream" && this.#type && this.#type !== "stream") {
            throw new TypeError(`Body already consumed as "${this.#type}" and cannot be returned as a stream.`);
        }
        if (type === "form-data" && this.#type && this.#type !== "form-data") {
            throw new TypeError(`Body already consumed as "${this.#type}" and cannot be returned as a stream.`);
        }
        if (this.#type === "reader" && type !== "reader") {
            throw new TypeError("Body already consumed as a reader and can only be returned as a reader.");
        }
        if (this.#type === "stream" && type !== "stream") {
            throw new TypeError("Body already consumed as a stream and can only be returned as a stream.");
        }
        if (this.#type === "form-data" && type !== "form-data") {
            throw new TypeError("Body already consumed as form data and can only be returned as form data.");
        }
        if (type && Object.keys(contentTypes).length) {
            throw new TypeError(`"type" and "contentTypes" cannot be specified at the same time`);
        }
    }
    #valuePromise() {
        return this.#readAllBody ?? (this.#readAllBody = this.#readBody());
    }
    constructor({ body, readBody }, headers, jsonBodyReviver){
        this.#body = body;
        this.#headers = headers;
        this.#jsonBodyReviver = jsonBodyReviver;
        this.#readBody = readBody;
    }
    get({ limit = 10_485_760, type, contentTypes = {} } = {}) {
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
    constructor(serverRequest, { proxy = false, secure = false, jsonBodyReviver } = {}){
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
        const { hasBody, headers, ip, ips, method, secure, url } = this;
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
        const { hasBody, headers, ip, ips, method, secure, url } = this;
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
        const { conn } = options;
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
        const { response, socket } = this.#upgradeWebSocket(this.#request, options);
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
        const { headers } = this;
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
        const { body, headers, status, type, writable } = this;
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
        const { body, headers, status, type, writable } = this;
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
    const { body } = context.response;
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
        this.#contentLength = ranges.reduce((prev, { start, end })=>{
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
async function send({ request, response }, path, options = {
    root: ""
}) {
    const { brotli = true, contentTypes = {}, extensions, format = true, gzip = true, hidden = false, immutable = false, index, maxbuffer = 1_048_576, maxage = 0, root } = options;
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
        const { replacer, space } = eventInit;
        this.#type = type;
        try {
            this.#data = typeof data === "string" ? data : JSON.stringify(data, replacer, space);
        } catch (e) {
            assert1(e instanceof Error);
            throw new TypeError(`data could not be coerced into a serialized string.\n  ${e.message}`);
        }
        const { id } = eventInit;
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
    constructor(context, { headers, keepAlive = false } = {}){
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
    constructor(app, serverRequest, state, { secure = false, jsonBodyReplacer, jsonBodyReviver } = {}){
        this.app = app;
        this.state = state;
        const { proxy } = app;
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
        const { path = this.request.url.pathname, ...sendOptions } = options;
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
        const { app, cookies, isUpgradable, respond, request, response, socket, state } = this;
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
        const { app, cookies, isUpgradable, respond, request, response, socket, state } = this;
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
        const { response, socket } = this.#upgradeWebSocket(this.#request, options);
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
    #untrackHttpConnection(httpConn) {
        this.#httpConnections.delete(httpConn);
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
function logErrorListener({ error, context }) {
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
        const { state, keys, proxy, serverConstructor = HttpServer, contextState = "clone", logErrors = true, ...contextOptions } = options;
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
    #handleError(context, error) {
        if (!(error instanceof Error)) {
            error = new Error(`non-error thrown: ${JSON.stringify(error)}`);
        }
        const { message } = error;
        this.dispatchEvent(new ApplicationErrorEvent({
            context,
            message,
            error
        }));
        if (!context.response.writable) {
            return;
        }
        for (const key of [
            ...context.response.headers.keys()
        ]){
            context.response.headers.delete(key);
        }
        if (error.headers && error.headers instanceof Headers) {
            for (const [key, value] of error.headers){
                context.response.headers.set(key, value);
            }
        }
        context.response.type = "text";
        const status = context.response.status = Deno.errors && error instanceof Deno.errors.NotFound ? 404 : error.status && typeof error.status === "number" ? error.status : 500;
        context.response.body = error.expose ? error.message : STATUS_TEXT[status];
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
            const { message } = error;
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
        const { signal } = options;
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
        const { secure = false } = options;
        const serverType = server instanceof HttpServer ? "native" : server instanceof FlashServer ? "flash" : "custom";
        const listener = await server.listen();
        const { hostname, port } = listener.addr;
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
        const { keys, proxy, state } = this;
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
        const { keys, proxy, state } = this;
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            "#middleware": this.#middleware,
            keys,
            proxy,
            state
        }, newOptions)}`;
    }
}
function getQuery(ctx, { mergeParams, asMap } = {}) {
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
function createMatcher({ match }) {
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
async function createRequest(target, ctx, { headers: optHeaders, map, proxyHeaders = true, request: reqFn }) {
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
async function processResponse(response, ctx, { contentType: contentTypeFn, response: resFn }) {
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
        const { fetch: fetch1 = globalThis.fetch } = options;
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
    constructor(path, methods, middleware, { name, ...opts } = {}){
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
    #match(path, method) {
        const matches = {
            path: [],
            pathAndMethod: [],
            route: false
        };
        for (const route of this.#stack){
            if (route.match(path)) {
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
    #register(path, middlewares, methods, options = {}) {
        if (Array.isArray(path)) {
            for (const p of path){
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
                this.#addLayer(path, layerMiddlewares, methods, options);
                layerMiddlewares = [];
            }
            const router = middleware.router.#clone();
            for (const layer of router.#stack){
                if (!options.ignorePrefix) {
                    layer.setPrefix(path);
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
            this.#addLayer(path, layerMiddlewares, methods, options);
        }
    }
    #addLayer(path, middlewares, methods, options = {}) {
        const { end, name, sensitive = this.#opts.sensitive, strict = this.#opts.strict, ignoreCaptures } = options;
        const route = new Layer(path, methods, middlewares, {
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
    #useVerb(nameOrPath, pathOrMiddleware, middleware, methods) {
        let name = undefined;
        let path;
        if (typeof pathOrMiddleware === "string") {
            name = nameOrPath;
            path = pathOrMiddleware;
        } else {
            path = nameOrPath;
            middleware.unshift(pathOrMiddleware);
        }
        this.#register(path, middleware, methods, {
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
                const { url: { pathname: p }, method: m } = ctx.request;
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
            const { pathAndMethod: matchedRoutes } = matches;
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
function createMockContext({ ip = "127.0.0.1", method = "GET", params, path = "/", state, app = createMockApp(state), headers: requestHeaders } = {}) {
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
const t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function n(t, n, e, r) {
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
                    return n(new Uint8Array(t), e, r, i);
                }(t, e, r, i);
            };
        case "UINT8ARRAY":
            try {
                new Uint8Array(0);
            } catch (t) {
                throw new Error("UINT8ARRAY not supported by this environment");
            }
            return function(t, e, r) {
                return n(t, e, r, i);
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
    {
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
    {
        if (!globalScope.crypto?.getRandomValues) {
            throw new Error("Cryptography API not available");
        }
        return globalScope.crypto.getRandomValues(new Uint8Array(size)).buffer;
    }
};
class Secret {
    constructor({ buffer, size = 20 } = {}){
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
    {
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
    constructor({ issuer = HOTP.defaults.issuer, label = HOTP.defaults.label, secret = new Secret(), algorithm = HOTP.defaults.algorithm, digits = HOTP.defaults.digits, counter = HOTP.defaults.counter } = {}){
        this.issuer = issuer;
        this.label = label;
        this.secret = typeof secret === "string" ? Secret.fromBase32(secret) : secret;
        this.algorithm = algorithm.toUpperCase();
        this.digits = digits;
        this.counter = counter;
    }
    static generate({ secret, algorithm = HOTP.defaults.algorithm, digits = HOTP.defaults.digits, counter = HOTP.defaults.counter }) {
        const digest = new Uint8Array(hmacDigest(algorithm, secret.buffer, uintToBuf(counter)));
        const offset = digest[digest.byteLength - 1] & 15;
        const otp = ((digest[offset] & 127) << 24 | (digest[offset + 1] & 255) << 16 | (digest[offset + 2] & 255) << 8 | digest[offset + 3] & 255) % 10 ** digits;
        return otp.toString().padStart(digits, "0");
    }
    generate({ counter = this.counter++ } = {}) {
        return HOTP.generate({
            secret: this.secret,
            algorithm: this.algorithm,
            digits: this.digits,
            counter
        });
    }
    static validate({ token, secret, algorithm, digits, counter = HOTP.defaults.counter, window: window1 = HOTP.defaults.window }) {
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
    validate({ token, counter = this.counter, window: window1 }) {
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
    constructor({ issuer = TOTP.defaults.issuer, label = TOTP.defaults.label, secret = new Secret(), algorithm = TOTP.defaults.algorithm, digits = TOTP.defaults.digits, period = TOTP.defaults.period } = {}){
        this.issuer = issuer;
        this.label = label;
        this.secret = typeof secret === "string" ? Secret.fromBase32(secret) : secret;
        this.algorithm = algorithm.toUpperCase();
        this.digits = digits;
        this.period = period;
    }
    static generate({ secret, algorithm, digits, period = TOTP.defaults.period, timestamp = Date.now() }) {
        return HOTP.generate({
            secret,
            algorithm,
            digits,
            counter: Math.floor(timestamp / 1000 / period)
        });
    }
    generate({ timestamp = Date.now() } = {}) {
        return TOTP.generate({
            secret: this.secret,
            algorithm: this.algorithm,
            digits: this.digits,
            period: this.period,
            timestamp
        });
    }
    static validate({ token, secret, algorithm, digits, period = TOTP.defaults.period, timestamp = Date.now(), window: window1 }) {
        return HOTP.validate({
            token,
            secret,
            algorithm,
            digits,
            counter: Math.floor(timestamp / 1000 / period),
            window: window1
        });
    }
    validate({ token, timestamp, window: window1 }) {
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
const version = "9.1.4";
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
    #handle(chunk, controller) {
        chunk = this.#buf + chunk;
        const chunks = chunk.split("\r\n");
        if (chunks.length > 1) {
            for(let i = 0; i < chunks.length - 1; i++){
                controller.enqueue(chunks[i]);
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
    conn;
    config;
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
    config;
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
function resolveContent({ text, html, mimeContent }) {
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
    const { to, cc = [], bcc = [], from, date = new Date().toUTCString().split(",")[1].slice(1), subject, content, mimeContent, html, inReplyTo, replyTo, references, priority, attachments, internalTag, headers } = config;
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
    asString(data, isProperty = false) {
        if (typeof data === "string") {
            if (isProperty) return `"${data}"`;
            return data;
        } else if (data === null || typeof data === "number" || typeof data === "bigint" || typeof data === "boolean" || typeof data === "undefined" || typeof data === "symbol") {
            return String(data);
        } else if (data instanceof Error) {
            return data.stack;
        } else if (typeof data === "object") {
            return `{${Object.entries(data).map(([k, v])=>`"${k}":${this.asString(v, true)}`).join(",")}}`;
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
const { Deno: Deno1 } = globalThis;
const noColor = typeof Deno1?.noColor === "boolean" ? Deno1.noColor : false;
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
async function exists1(path, options) {
    try {
        const stat = await Deno.stat(path);
        if (options && (options.isReadable || options.isDirectory || options.isFile)) {
            if (options.isDirectory && options.isFile) {
                throw new TypeError("ExistsOptions.options.isDirectory and ExistsOptions.options.isFile must not be true together.");
            }
            if (options.isDirectory && !stat.isDirectory || options.isFile && !stat.isFile) {
                return false;
            }
            if (options.isReadable) {
                if (stat.mode === null) {
                    return true;
                }
                if (Deno.uid() === stat.uid) {
                    return (stat.mode & 0o400) === 0o400;
                } else if (Deno.gid() === stat.gid) {
                    return (stat.mode & 0o040) === 0o040;
                }
                return (stat.mode & 0o004) === 0o004;
            }
        }
        return true;
    } catch (error) {
        if (error instanceof Deno.errors.NotFound) {
            return false;
        }
        if (error instanceof Deno.errors.PermissionDenied) {
            if ((await Deno.permissions.query({
                name: "read",
                path
            })).state === "granted") {
                return !options?.isReadable;
            }
        }
        throw error;
    }
}
function existsSync(path, options) {
    try {
        const stat = Deno.statSync(path);
        if (options && (options.isReadable || options.isDirectory || options.isFile)) {
            if (options.isDirectory && options.isFile) {
                throw new TypeError("ExistsOptions.options.isDirectory and ExistsOptions.options.isFile must not be true together.");
            }
            if (options.isDirectory && !stat.isDirectory || options.isFile && !stat.isFile) {
                return false;
            }
            if (options.isReadable) {
                if (stat.mode === null) {
                    return true;
                }
                if (Deno.uid() === stat.uid) {
                    return (stat.mode & 0o400) === 0o400;
                } else if (Deno.gid() === stat.gid) {
                    return (stat.mode & 0o040) === 0o040;
                }
                return (stat.mode & 0o004) === 0o004;
            }
        }
        return true;
    } catch (error) {
        if (error instanceof Deno.errors.NotFound) {
            return false;
        }
        if (error instanceof Deno.errors.PermissionDenied) {
            if (Deno.permissions.querySync({
                name: "read",
                path
            }).state === "granted") {
                return !options?.isReadable;
            }
        }
        throw error;
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
                numBytesWritten = copy1(data, this.buf, this.usedBufferBytes);
                this.usedBufferBytes += numBytesWritten;
                this.flush();
            }
            totalBytesWritten += numBytesWritten;
            data = data.subarray(numBytesWritten);
        }
        numBytesWritten = copy1(data, this.buf, this.usedBufferBytes);
        this.usedBufferBytes += numBytesWritten;
        totalBytesWritten += numBytesWritten;
        return totalBytesWritten;
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
            if (value === undefined) {
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
    setup() {
        if (this.#maxBytes < 1) {
            this.destroy();
            throw new Error("maxBytes cannot be less than 1");
        }
        if (this.#maxBackupCount < 1) {
            this.destroy();
            throw new Error("maxBackupCount cannot be less than 1");
        }
        super.setup();
        if (this._mode === "w") {
            for(let i = 1; i <= this.#maxBackupCount; i++){
                try {
                    Deno.removeSync(this._filename + "." + i);
                } catch (error) {
                    if (!(error instanceof Deno.errors.NotFound)) {
                        throw error;
                    }
                }
            }
        } else if (this._mode === "x") {
            for(let i = 1; i <= this.#maxBackupCount; i++){
                if (existsSync(this._filename + "." + i)) {
                    this.destroy();
                    throw new Deno.errors.AlreadyExists("Backup log file " + this._filename + "." + i + " already exists");
                }
            }
        } else {
            this.#currentFileSize = Deno.statSync(this._filename).size;
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
class AssertionError extends Error {
    name = "AssertionError";
    constructor(message){
        super(message);
    }
}
function assert2(expr, msg = "") {
    if (!expr) {
        throw new AssertionError(msg);
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
const state = {
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
        const d = state.loggers.get("default");
        assert2(d !== undefined, `"default" logger must be set for getting logger without name`);
        return d;
    }
    const result = state.loggers.get(name);
    if (!result) {
        const logger = new Logger(name, "NOTSET", {
            handlers: []
        });
        state.loggers.set(name, logger);
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
function error(msg, ...args) {
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
    state.config = {
        handlers: {
            ...DEFAULT_CONFIG.handlers,
            ...config.handlers
        },
        loggers: {
            ...DEFAULT_CONFIG.loggers,
            ...config.loggers
        }
    };
    state.handlers.forEach((handler)=>{
        handler.destroy();
    });
    state.handlers.clear();
    const handlers = state.config.handlers || {};
    for(const handlerName in handlers){
        const handler = handlers[handlerName];
        handler.setup();
        state.handlers.set(handlerName, handler);
    }
    state.loggers.clear();
    const loggers = state.config.loggers || {};
    for(const loggerName in loggers){
        const loggerConfig = loggers[loggerName];
        const handlerNames = loggerConfig.handlers || [];
        const handlers = [];
        handlerNames.forEach((handlerName)=>{
            const handler = state.handlers.get(handlerName);
            if (handler) {
                handlers.push(handler);
            }
        });
        const levelName = loggerConfig.level || DEFAULT_LEVEL;
        const logger = new Logger(loggerName, levelName, {
            handlers: handlers
        });
        state.loggers.set(loggerName, logger);
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
    error: error,
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
ZTc5AAcYX193YmluZGdlbl9wbGFjZWhvbGRlcl9fEF9fd2JpbmRnZW5fdGhyb3cABQOQgYCAAI4BCw\
cLBwMJEQUHBwUHDwMHBQgFEAUFBwIHBQIGBwYHFQgHDgcHBwYBAQEBBwgHBwcBBwcHAQgHBwcHBwUC\
BwcHBwcBAQcHBQ0IBwkHCQEBAQEBBQEJDQsJBQUFBQUFBgYHBwcHAgIIBwcFAgoABQIDAgIODAsMCw\
sTFBIJCAgGBgUHBwAGAwAABQgICAQAAgSFgICAAAFwARUVBYOAgIAAAQARBomAgIAAAX8BQYCAwAAL\
B7mCgIAADgZtZW1vcnkCAAZkaWdlc3QAUhhfX3diZ19kaWdlc3Rjb250ZXh0X2ZyZWUAbxFkaWdlc3\
Rjb250ZXh0X25ldwBWFGRpZ2VzdGNvbnRleHRfdXBkYXRlAHIUZGlnZXN0Y29udGV4dF9kaWdlc3QA\
VRxkaWdlc3Rjb250ZXh0X2RpZ2VzdEFuZFJlc2V0AFcbZGlnZXN0Y29udGV4dF9kaWdlc3RBbmREcm\
9wAF8TZGlnZXN0Y29udGV4dF9yZXNldAAgE2RpZ2VzdGNvbnRleHRfY2xvbmUAEB9fX3diaW5kZ2Vu\
X2FkZF90b19zdGFja19wb2ludGVyAJABEV9fd2JpbmRnZW5fbWFsbG9jAHoSX193YmluZGdlbl9yZW\
FsbG9jAIcBD19fd2JpbmRnZW5fZnJlZQCLAQmngICAAAEAQQELFIkBigEojwF+YH+AAX2IAYYBgQGC\
AYMBhAGFAZkBammXAQqchImAAI4BhX0CEX8CfiMAQYApayIFJAACQAJAAkACQAJAAkACQAJAAkACQA\
JAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkAgAQ4ZAAECAwQFBgcICQoLDA0O\
DxAREhMUFRYXGAALQdABEBkiBkUNGSAFQZAUakE4aiACQThqKQMANwMAIAVBkBRqQTBqIAJBMGopAw\
A3AwAgBUGQFGpBKGogAkEoaikDADcDACAFQZAUakEgaiACQSBqKQMANwMAIAVBkBRqQRhqIAJBGGop\
AwA3AwAgBUGQFGpBEGogAkEQaikDADcDACAFQZAUakEIaiACQQhqKQMANwMAIAUgAikDADcDkBQgAi\
kDQCEWIAVBkBRqQcgAaiACQcgAahBjIAUgFjcD0BQgBiAFQZAUakHQARCVARoMGAtB0AEQGSIGRQ0Y\
IAVBkBRqQThqIAJBOGopAwA3AwAgBUGQFGpBMGogAkEwaikDADcDACAFQZAUakEoaiACQShqKQMANw\
MAIAVBkBRqQSBqIAJBIGopAwA3AwAgBUGQFGpBGGogAkEYaikDADcDACAFQZAUakEQaiACQRBqKQMA\
NwMAIAVBkBRqQQhqIAJBCGopAwA3AwAgBSACKQMANwOQFCACKQNAIRYgBUGQFGpByABqIAJByABqEG\
MgBSAWNwPQFCAGIAVBkBRqQdABEJUBGgwXC0HQARAZIgZFDRcgBUGQFGpBOGogAkE4aikDADcDACAF\
QZAUakEwaiACQTBqKQMANwMAIAVBkBRqQShqIAJBKGopAwA3AwAgBUGQFGpBIGogAkEgaikDADcDAC\
AFQZAUakEYaiACQRhqKQMANwMAIAVBkBRqQRBqIAJBEGopAwA3AwAgBUGQFGpBCGogAkEIaikDADcD\
ACAFIAIpAwA3A5AUIAIpA0AhFiAFQZAUakHIAGogAkHIAGoQYyAFIBY3A9AUIAYgBUGQFGpB0AEQlQ\
EaDBYLQdABEBkiBkUNFiAFQZAUakE4aiACQThqKQMANwMAIAVBkBRqQTBqIAJBMGopAwA3AwAgBUGQ\
FGpBKGogAkEoaikDADcDACAFQZAUakEgaiACQSBqKQMANwMAIAVBkBRqQRhqIAJBGGopAwA3AwAgBU\
GQFGpBEGogAkEQaikDADcDACAFQZAUakEIaiACQQhqKQMANwMAIAUgAikDADcDkBQgAikDQCEWIAVB\
kBRqQcgAaiACQcgAahBjIAUgFjcD0BQgBiAFQZAUakHQARCVARoMFQtB8AAQGSIGRQ0VIAVBkBRqQS\
BqIAJBIGopAwA3AwAgBUGQFGpBGGogAkEYaikDADcDACAFQZAUakEQaiACQRBqKQMANwMAIAUgAikD\
CDcDmBQgAikDACEWIAVBkBRqQShqIAJBKGoQUSAFIBY3A5AUIAYgBUGQFGpB8AAQlQEaDBQLQfgOEB\
kiBkUNFCAFQZAUakGIAWogAkGIAWopAwA3AwAgBUGQFGpBgAFqIAJBgAFqKQMANwMAIAVBkBRqQfgA\
aiACQfgAaikDADcDACAFQZAUakEQaiACQRBqKQMANwMAIAVBkBRqQRhqIAJBGGopAwA3AwAgBUGQFG\
pBIGogAkEgaikDADcDACAFQZAUakEwaiACQTBqKQMANwMAIAVBkBRqQThqIAJBOGopAwA3AwAgBUGQ\
FGpBwABqIAJBwABqKQMANwMAIAVBkBRqQcgAaiACQcgAaikDADcDACAFQZAUakHQAGogAkHQAGopAw\
A3AwAgBUGQFGpB2ABqIAJB2ABqKQMANwMAIAVBkBRqQeAAaiACQeAAaikDADcDACAFIAIpA3A3A4AV\
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\
akEkakIANwIAIARB+A5qQSxqQgA3AgAgBEH4DmpBNGpCADcCACAEQfgOakE8akIANwIAIARCADcC/A\
4gBEEANgL4DiAEQfgOaiAEQfgOakEEckF/c2pBxABqQQdJGiAEQcAANgL4DiAEQZAUaiAEQfgOakHE\
ABCVARogBEG4J2pBOGoiCSAEQZAUakE8aikCADcDACAEQbgnakEwaiIDIARBkBRqQTRqKQIANwMAIA\
RBuCdqQShqIgggBEGQFGpBLGopAgA3AwAgBEG4J2pBIGoiByAEQZAUakEkaikCADcDACAEQbgnakEY\
aiIMIARBkBRqQRxqKQIANwMAIARBuCdqQRBqIgsgBEGQFGpBFGopAgA3AwAgBEG4J2pBCGoiDSAEQZ\
AUakEMaikCADcDACAEIAQpApQUNwO4JyAEQZAUaiAEQdABEJUBGiAEIAQpA9AUIARB2BVqLQAAIgKt\
fDcD0BQgBEHYFGohAQJAIAJBgAFGDQAgASACakEAQYABIAJrEJQBGgsgBEEAOgDYFSAEQZAUaiABQn\
8QEiAEQfgOakEIaiICIARBkBRqQQhqKQMANwMAIARB+A5qQRBqIgEgBEGQFGpBEGopAwA3AwAgBEH4\
DmpBGGoiCiAEQZAUakEYaikDADcDACAEQfgOakEgaiIOIAQpA7AUNwMAIARB+A5qQShqIg8gBEGQFG\
pBKGopAwA3AwAgBEH4DmpBMGoiECAEQZAUakEwaikDADcDACAEQfgOakE4aiIRIARBkBRqQThqKQMA\
NwMAIAQgBCkDkBQ3A/gOIA0gAikDADcDACALIAEpAwA3AwAgDCAKKQMANwMAIAcgDikDADcDACAIIA\
8pAwA3AwAgAyAQKQMANwMAIAkgESkDADcDACAEIAQpA/gONwO4J0HAABAZIgJFDR4gAiAEKQO4JzcA\
ACACQThqIARBuCdqQThqKQMANwAAIAJBMGogBEG4J2pBMGopAwA3AAAgAkEoaiAEQbgnakEoaikDAD\
cAACACQSBqIARBuCdqQSBqKQMANwAAIAJBGGogBEG4J2pBGGopAwA3AAAgAkEQaiAEQbgnakEQaikD\
ADcAACACQQhqIARBuCdqQQhqKQMANwAAIAYQIkHAACEEDCALIAUgBkHQARCVASIEQYQPakIANwIAIA\
RBjA9qQgA3AgAgBEGUD2pBADYCACAEQgA3AvwOIARBADYC+A5BBCECIARB+A5qIARB+A5qQQRyQX9z\
akEgaiEBA0AgAkF/aiICDQALAkAgAUEHSQ0AQRghAgNAIAJBeGoiAg0ACwsgBEEcNgL4DiAEQZAUak\
EQaiIHIARB+A5qQRBqIgIpAwA3AwAgBEGQFGpBCGoiDCAEQfgOakEIaiIBKQMANwMAIARBkBRqQRhq\
IgsgBEH4DmpBGGoiCSkDADcDACAEQbgnakEIaiINIARBnBRqKQIANwMAIARBuCdqQRBqIgogBEGkFG\
opAgA3AwAgBEG4J2pBGGoiDiAEQZAUakEcaigCADYCACAEIAQpA/gONwOQFCAEIAQpApQUNwO4JyAE\
QZAUaiAEQdABEJUBGiAEIAQpA9AUIARB2BVqLQAAIgOtfDcD0BQgBEHYFGohCAJAIANBgAFGDQAgCC\
ADakEAQYABIANrEJQBGgsgBEEAOgDYFSAEQZAUaiAIQn8QEiABIAwpAwA3AwAgAiAHKQMANwMAIAkg\
CykDADcDACAEQZgPaiAEKQOwFDcDACAEQfgOakEoaiAEQZAUakEoaikDADcDACAEQfgOakEwaiAEQZ\
AUakEwaikDADcDACAEQfgOakE4aiAEQZAUakE4aikDADcDACAEIAQpA5AUNwP4DiANIAEpAwA3AwAg\
CiACKQMANwMAIA4gCSgCADYCACAEIAQpA/gONwO4J0EcEBkiAkUNHSACIAQpA7gnNwAAIAJBGGogBE\
G4J2pBGGooAgA2AAAgAkEQaiAEQbgnakEQaikDADcAACACQQhqIARBuCdqQQhqKQMANwAADBELIAUg\
BkHQARCVASIEQfgOakEMakIANwIAIARB+A5qQRRqQgA3AgAgBEH4DmpBHGpCADcCACAEQgA3AvwOIA\
RBADYC+A4gBEH4DmogBEH4DmpBBHJBf3NqQSRqQQdJGiAEQSA2AvgOIARBkBRqQRBqIgcgBEH4DmpB\
EGoiASkDADcDACAEQZAUakEIaiIMIARB+A5qQQhqIgkpAwA3AwAgBEGQFGpBGGoiCyAEQfgOakEYai\
IDKQMANwMAIARBkBRqQSBqIARB+A5qQSBqIg0oAgA2AgAgBEG4J2pBCGoiCiAEQZAUakEMaikCADcD\
ACAEQbgnakEQaiIOIARBkBRqQRRqKQIANwMAIARBuCdqQRhqIg8gBEGQFGpBHGopAgA3AwAgBCAEKQ\
P4DjcDkBQgBCAEKQKUFDcDuCcgBEGQFGogBEHQARCVARogBCAEKQPQFCAEQdgVai0AACICrXw3A9AU\
IARB2BRqIQgCQCACQYABRg0AIAggAmpBAEGAASACaxCUARoLIARBADoA2BUgBEGQFGogCEJ/EBIgCS\
AMKQMANwMAIAEgBykDADcDACADIAspAwA3AwAgDSAEKQOwFDcDACAEQfgOakEoaiAEQZAUakEoaikD\
ADcDACAEQfgOakEwaiAEQZAUakEwaikDADcDACAEQfgOakE4aiAEQZAUakE4aikDADcDACAEIAQpA5\
AUNwP4DiAKIAkpAwA3AwAgDiABKQMANwMAIA8gAykDADcDACAEIAQpA/gONwO4J0EgEBkiAkUNHCAC\
IAQpA7gnNwAAIAJBGGogBEG4J2pBGGopAwA3AAAgAkEQaiAEQbgnakEQaikDADcAACACQQhqIARBuC\
dqQQhqKQMANwAADB0LIAUgBkHQARCVASIEQfgOakEMakIANwIAIARB+A5qQRRqQgA3AgAgBEH4DmpB\
HGpCADcCACAEQfgOakEkakIANwIAIARB+A5qQSxqQgA3AgAgBEIANwL8DiAEQQA2AvgOIARB+A5qIA\
RB+A5qQQRyQX9zakE0akEHSRogBEEwNgL4DiAEQZAUakEQaiILIARB+A5qQRBqIgIpAwA3AwAgBEGQ\
FGpBCGoiDSAEQfgOakEIaiIBKQMANwMAIARBkBRqQRhqIgogBEH4DmpBGGoiCSkDADcDACAEQZAUak\
EgaiAEQfgOakEgaiIDKQMANwMAIARBkBRqQShqIg4gBEH4DmpBKGoiCCkDADcDACAEQZAUakEwaiIP\
IARB+A5qQTBqIhAoAgA2AgAgBEG4J2pBCGoiESAEQZAUakEMaikCADcDACAEQbgnakEQaiISIARBkB\
RqQRRqKQIANwMAIARBuCdqQRhqIhMgBEGQFGpBHGopAgA3AwAgBEG4J2pBIGoiFCAEQZAUakEkaikC\
ADcDACAEQbgnakEoaiIVIARBkBRqQSxqKQIANwMAIAQgBCkD+A43A5AUIAQgBCkClBQ3A7gnIARBkB\
RqIARB0AEQlQEaIAQgBCkD0BQgBEHYFWotAAAiB618NwPQFCAEQdgUaiEMAkAgB0GAAUYNACAMIAdq\
QQBBgAEgB2sQlAEaCyAEQQA6ANgVIARBkBRqIAxCfxASIAEgDSkDADcDACACIAspAwA3AwAgCSAKKQ\
MANwMAIAMgBCkDsBQ3AwAgCCAOKQMANwMAIBAgDykDADcDACAEQfgOakE4aiAEQZAUakE4aikDADcD\
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\
NwMAIAFBkBRqQSBqIAFB+A5qQSBqKQMANwMAIAFBkBRqQShqIAFB+A5qQShqKQMANwMAIAFBkBRqQT\
BqIAFB+A5qQTBqKAIANgIAIAFBuCdqQQhqIgkgAUGQFGpBDGopAgA3AwAgAUG4J2pBEGoiAyABQZAU\
akEUaikCADcDACABQbgnakEYaiIIIAFBkBRqQRxqKQIANwMAIAFBuCdqQSBqIgcgAUGQFGpBJGopAg\
A3AwAgAUG4J2pBKGoiDCABQZAUakEsaikCADcDACABIAEpA/gONwOQFCABIAEpApQUNwO4JyABQZAU\
aiABQbgCEJUBGiABQZAUaiABQdgVaiABQbgnahBJQTAQGSICRQ0WIAIgASkDuCc3AAAgAkEoaiAMKQ\
MANwAAIAJBIGogBykDADcAACACQRhqIAgpAwA3AAAgAkEQaiADKQMANwAAIAJBCGogCSkDADcAAAwV\
CyAFIAZBmAIQlQEiAUH4DmpBDGpCADcCACABQfgOakEUakIANwIAIAFB+A5qQRxqQgA3AgAgAUH4Dm\
pBJGpCADcCACABQfgOakEsakIANwIAIAFB+A5qQTRqQgA3AgAgAUH4DmpBPGpCADcCACABQgA3AvwO\
IAFBADYC+A4gAUH4DmogAUH4DmpBBHJBf3NqQcQAakEHSRpBwAAhBCABQcAANgL4DiABQZAUaiABQf\
gOakHEABCVARogAUG4J2pBOGoiCSABQZAUakE8aikCADcDACABQbgnakEwaiIDIAFBkBRqQTRqKQIA\
NwMAIAFBuCdqQShqIgggAUGQFGpBLGopAgA3AwAgAUG4J2pBIGoiByABQZAUakEkaikCADcDACABQb\
gnakEYaiIMIAFBkBRqQRxqKQIANwMAIAFBuCdqQRBqIgsgAUGQFGpBFGopAgA3AwAgAUG4J2pBCGoi\
DSABQZAUakEMaikCADcDACABIAEpApQUNwO4JyABQZAUaiABQZgCEJUBGiABQZAUaiABQdgVaiABQb\
gnahBLQcAAEBkiAkUNFSACIAEpA7gnNwAAIAJBOGogCSkDADcAACACQTBqIAMpAwA3AAAgAkEoaiAI\
KQMANwAAIAJBIGogBykDADcAACACQRhqIAwpAwA3AAAgAkEQaiALKQMANwAAIAJBCGogDSkDADcAAA\
wUCyAFIAZB4AAQlQEiAUH4DmpBDGpCADcCACABQgA3AvwOIAFBADYC+A4gAUH4DmogAUH4DmpBBHJB\
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\
IAFB+A5qQRRqKQIANwMAIAFBiCZqQRhqIgwgAUH4DmpBHGopAgA3AwAgASABKQO4JzcD+A4gASABKQ\
L8DjcDiCYgAUGQFGogAUG4FGogAUGIJmoQJyAIIAwpAwA3AwAgCSAHKQMANwMAIAMgAikDADcDACAB\
IAEpA4gmNwP4DkEgEBkiAkUNCiACIAEpA/gONwAAIAJBGGogCCkDADcAACACQRBqIAkpAwA3AAAgAk\
EIaiADKQMANwAADAkLIAUgBkHYARCVASIBQZAUaiABQdgBEJUBGiABQbgnakEMakIANwIAIAFBuCdq\
QRRqQgA3AgAgAUG4J2pBHGpCADcCACABQbgnakEkakIANwIAIAFBuCdqQSxqQgA3AgAgAUG4J2pBNG\
pCADcCACABQbgnakE8akIANwIAIAFCADcCvCcgAUEANgK4JyABQbgnaiABQbgnakEEckF/c2pBxABq\
QQdJGiABQcAANgK4JyABQfgOaiABQbgnakHEABCVARogAUHAJmogAUH4DmpBPGopAgA3AwBBMCEEIA\
FBiCZqQTBqIAFB+A5qQTRqKQIANwMAIAFBiCZqQShqIgIgAUH4DmpBLGopAgA3AwAgAUGIJmpBIGoi\
CSABQfgOakEkaikCADcDACABQYgmakEYaiIDIAFB+A5qQRxqKQIANwMAIAFBiCZqQRBqIgggAUH4Dm\
pBFGopAgA3AwAgAUGIJmpBCGoiByABQfgOakEMaikCADcDACABIAEpAvwONwOIJiABQZAUaiABQeAU\
aiABQYgmahAjIAFB+A5qQShqIgwgAikDADcDACABQfgOakEgaiILIAkpAwA3AwAgAUH4DmpBGGoiCS\
ADKQMANwMAIAFB+A5qQRBqIgMgCCkDADcDACABQfgOakEIaiIIIAcpAwA3AwAgASABKQOIJjcD+A5B\
MBAZIgJFDQkgAiABKQP4DjcAACACQShqIAwpAwA3AAAgAkEgaiALKQMANwAAIAJBGGogCSkDADcAAC\
ACQRBqIAMpAwA3AAAgAkEIaiAIKQMANwAADAgLIAUgBkHYARCVASIBQZAUaiABQdgBEJUBGiABQbgn\
akEMakIANwIAIAFBuCdqQRRqQgA3AgAgAUG4J2pBHGpCADcCACABQbgnakEkakIANwIAIAFBuCdqQS\
xqQgA3AgAgAUG4J2pBNGpCADcCACABQbgnakE8akIANwIAIAFCADcCvCcgAUEANgK4JyABQbgnaiAB\
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\
AwA3AwAgBUHAAmpBCGogBUGYCGpBCGopAwA3AwAgBUHAAmpBGGogBUGYCGpBGGopAwA3AwAgBUHAAm\
pBIGogBUGYCGpBIGooAgA2AgAgBUHoBmpBCGoiAyAFQcACakEMaikCADcDACAFQegGakEQaiIGIAVB\
wAJqQRRqKQIANwMAIAVB6AZqQRhqIgcgBUHAAmpBHGopAgA3AwAgBSAFKQOYCDcDwAIgBSAFKQLEAj\
cD6AYgAiACQcgBaiAFQegGahBCIAJBAEHIARCUAUHQAmpBADoAAEEgEBkiAUUNECABIAUpA+gGNwAA\
IAFBGGogBykDADcAACABQRBqIAYpAwA3AAAgAUEIaiADKQMANwAADA8LIAVBmAhqQQxqQgA3AgAgBU\
GYCGpBFGpCADcCACAFQZgIakEcakIANwIAIAVBmAhqQSRqQgA3AgAgBUGYCGpBLGpCADcCACAFQgA3\
ApwIIAVBADYCmAggBUGYCGogBUGYCGpBBHJBf3NqQTRqQQdJGkEwIQQgBUEwNgKYCCAFQcACakEQai\
AFQZgIakEQaikDADcDACAFQcACakEIaiAFQZgIakEIaikDADcDACAFQcACakEYaiAFQZgIakEYaikD\
ADcDACAFQcACakEgaiAFQZgIakEgaikDADcDACAFQcACakEoaiAFQZgIakEoaikDADcDACAFQcACak\
EwaiAFQZgIakEwaigCADYCACAFQegGakEIaiIDIAVBwAJqQQxqKQIANwMAIAVB6AZqQRBqIgYgBUHA\
AmpBFGopAgA3AwAgBUHoBmpBGGoiByAFQcACakEcaikCADcDACAFQegGakEgaiIIIAVBwAJqQSRqKQ\
IANwMAIAVB6AZqQShqIgkgBUHAAmpBLGopAgA3AwAgBSAFKQOYCDcDwAIgBSAFKQLEAjcD6AYgAiAC\
QcgBaiAFQegGahBKIAJBAEHIARCUAUGwAmpBADoAAEEwEBkiAUUNDyABIAUpA+gGNwAAIAFBKGogCS\
kDADcAACABQSBqIAgpAwA3AAAgAUEYaiAHKQMANwAAIAFBEGogBikDADcAACABQQhqIAMpAwA3AAAM\
DgsgBUGYCGpBDGpCADcCACAFQZgIakEUakIANwIAIAVBmAhqQRxqQgA3AgAgBUGYCGpBJGpCADcCAC\
AFQZgIakEsakIANwIAIAVBmAhqQTRqQgA3AgAgBUGYCGpBPGpCADcCACAFQgA3ApwIIAVBADYCmAgg\
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\
fwR+IwBBgA9rIgEkAAJAAkACQAJAIABFDQAgACgCACICQX9GDQEgACACQQFqNgIAIABBCGooAgAhAg\
JAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkAgAEEEaigC\
ACIDDhkAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYAAtB0AEQGSIERQ0bIAFBCGpBOGogAkE4aikDAD\
cDACABQQhqQTBqIAJBMGopAwA3AwAgAUEIakEoaiACQShqKQMANwMAIAFBCGpBIGogAkEgaikDADcD\
ACABQQhqQRhqIAJBGGopAwA3AwAgAUEIakEQaiACQRBqKQMANwMAIAFBCGpBCGogAkEIaikDADcDAC\
ABIAIpAwA3AwggAikDQCELIAFBCGpByABqIAJByABqEGMgASALNwNIIAQgAUEIakHQARCVARoMGAtB\
0AEQGSIERQ0aIAFBCGpBOGogAkE4aikDADcDACABQQhqQTBqIAJBMGopAwA3AwAgAUEIakEoaiACQS\
hqKQMANwMAIAFBCGpBIGogAkEgaikDADcDACABQQhqQRhqIAJBGGopAwA3AwAgAUEIakEQaiACQRBq\
KQMANwMAIAFBCGpBCGogAkEIaikDADcDACABIAIpAwA3AwggAikDQCELIAFBCGpByABqIAJByABqEG\
MgASALNwNIIAQgAUEIakHQARCVARoMFwtB0AEQGSIERQ0ZIAFBCGpBOGogAkE4aikDADcDACABQQhq\
QTBqIAJBMGopAwA3AwAgAUEIakEoaiACQShqKQMANwMAIAFBCGpBIGogAkEgaikDADcDACABQQhqQR\
hqIAJBGGopAwA3AwAgAUEIakEQaiACQRBqKQMANwMAIAFBCGpBCGogAkEIaikDADcDACABIAIpAwA3\
AwggAikDQCELIAFBCGpByABqIAJByABqEGMgASALNwNIIAQgAUEIakHQARCVARoMFgtB0AEQGSIERQ\
0YIAFBCGpBOGogAkE4aikDADcDACABQQhqQTBqIAJBMGopAwA3AwAgAUEIakEoaiACQShqKQMANwMA\
IAFBCGpBIGogAkEgaikDADcDACABQQhqQRhqIAJBGGopAwA3AwAgAUEIakEQaiACQRBqKQMANwMAIA\
FBCGpBCGogAkEIaikDADcDACABIAIpAwA3AwggAikDQCELIAFBCGpByABqIAJByABqEGMgASALNwNI\
IAQgAUEIakHQARCVARoMFQtB8AAQGSIERQ0XIAFBCGpBIGogAkEgaikDADcDACABQQhqQRhqIAJBGG\
opAwA3AwAgAUEIakEQaiACQRBqKQMANwMAIAEgAikDCDcDECACKQMAIQsgAUEIakEoaiACQShqEFEg\
ASALNwMIIAQgAUEIakHwABCVARoMFAtB+A4QGSIERQ0WIAFBCGpBiAFqIAJBiAFqKQMANwMAIAFBCG\
pBgAFqIAJBgAFqKQMANwMAIAFBCGpB+ABqIAJB+ABqKQMANwMAIAEgAikDcDcDeCABQQhqQRBqIAJB\
EGopAwA3AwAgAUEIakEYaiACQRhqKQMANwMAIAFBCGpBIGogAkEgaikDADcDACABIAIpAwg3AxAgAi\
kDACELIAFBCGpB4ABqIAJB4ABqKQMANwMAIAFBCGpB2ABqIAJB2ABqKQMANwMAIAFBCGpB0ABqIAJB\
0ABqKQMANwMAIAFBCGpByABqIAJByABqKQMANwMAIAFBCGpBwABqIAJBwABqKQMANwMAIAFBCGpBOG\
ogAkE4aikDADcDACABQQhqQTBqIAJBMGopAwA3AwAgASACKQMoNwMwIAItAGohBSACLQBpIQYgAi0A\
aCEHIAFBADYCmAECQCACKAKQASIIRQ0AIAJBlAFqIglBCGopAAAhDCAJQRBqKQAAIQ0gCSkAACEOIA\
FBtAFqIAlBGGopAAA3AgAgAUGsAWogDTcCACABQaQBaiAMNwIAIAFBCGpBlAFqIA43AgAgAkG0AWoi\
CiAJIAhBBXRqIglGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUHUAWogCkEYaikAADcCAC\
ABQcwBaiANNwIAIAFBxAFqIAw3AgAgAUEIakG0AWogDjcCACACQdQBaiIKIAlGDQAgCkEIaikAACEM\
IApBEGopAAAhDSAKKQAAIQ4gAUH0AWogCkEYaikAADcCACABQewBaiANNwIAIAFB5AFqIAw3AgAgAU\
EIakHUAWogDjcCACACQfQBaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUGUAmog\
CkEYaikAADcCACABQYwCaiANNwIAIAFBhAJqIAw3AgAgAUEIakH0AWogDjcCACACQZQCaiIKIAlGDQ\
AgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUG0AmogCkEYaikAADcCACABQawCaiANNwIAIAFB\
pAJqIAw3AgAgAUEIakGUAmogDjcCACACQbQCaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQ\
AAIQ4gAUHUAmogCkEYaikAADcCACABQcwCaiANNwIAIAFBxAJqIAw3AgAgAUEIakG0AmogDjcCACAC\
QdQCaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUH0AmogCkEYaikAADcCACABQe\
wCaiANNwIAIAFB5AJqIAw3AgAgAUEIakHUAmogDjcCACACQfQCaiIKIAlGDQAgCkEIaikAACEMIApB\
EGopAAAhDSAKKQAAIQ4gAUGUA2ogCkEYaikAADcCACABQYwDaiANNwIAIAFBhANqIAw3AgAgAUEIak\
H0AmogDjcCACACQZQDaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUG0A2ogCkEY\
aikAADcCACABQawDaiANNwIAIAFBpANqIAw3AgAgAUEIakGUA2ogDjcCACACQbQDaiIKIAlGDQAgCk\
EIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUHUA2ogCkEYaikAADcCACABQcwDaiANNwIAIAFBxANq\
IAw3AgAgAUEIakG0A2ogDjcCACACQdQDaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ\
4gAUH0A2ogCkEYaikAADcCACABQewDaiANNwIAIAFB5ANqIAw3AgAgAUEIakHUA2ogDjcCACACQfQD\
aiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUGUBGogCkEYaikAADcCACABQYwEai\
ANNwIAIAFBhARqIAw3AgAgAUEIakH0A2ogDjcCACACQZQEaiIKIAlGDQAgCkEIaikAACEMIApBEGop\
AAAhDSAKKQAAIQ4gAUG0BGogCkEYaikAADcCACABQawEaiANNwIAIAFBpARqIAw3AgAgAUEIakGUBG\
ogDjcCACACQbQEaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUHUBGogCkEYaikA\
ADcCACABQcwEaiANNwIAIAFBxARqIAw3AgAgAUEIakG0BGogDjcCACACQdQEaiIKIAlGDQAgCkEIai\
kAACEMIApBEGopAAAhDSAKKQAAIQ4gAUH0BGogCkEYaikAADcCACABQewEaiANNwIAIAFB5ARqIAw3\
AgAgAUEIakHUBGogDjcCACACQfQEaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAU\
GUBWogCkEYaikAADcCACABQYwFaiANNwIAIAFBhAVqIAw3AgAgAUEIakH0BGogDjcCACACQZQFaiIK\
IAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUG0BWogCkEYaikAADcCACABQawFaiANNw\
IAIAFBpAVqIAw3AgAgAUEIakGUBWogDjcCACACQbQFaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAh\
DSAKKQAAIQ4gAUHUBWogCkEYaikAADcCACABQcwFaiANNwIAIAFBxAVqIAw3AgAgAUEIakG0BWogDj\
cCACACQdQFaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUH0BWogCkEYaikAADcC\
ACABQewFaiANNwIAIAFB5AVqIAw3AgAgAUEIakHUBWogDjcCACACQfQFaiIKIAlGDQAgCkEIaikAAC\
EMIApBEGopAAAhDSAKKQAAIQ4gAUGUBmogCkEYaikAADcCACABQYwGaiANNwIAIAFBhAZqIAw3AgAg\
AUEIakH0BWogDjcCACACQZQGaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUG0Bm\
ogCkEYaikAADcCACABQawGaiANNwIAIAFBpAZqIAw3AgAgAUEIakGUBmogDjcCACACQbQGaiIKIAlG\
DQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUHUBmogCkEYaikAADcCACABQcwGaiANNwIAIA\
FBxAZqIAw3AgAgAUEIakG0BmogDjcCACACQdQGaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAK\
KQAAIQ4gAUH0BmogCkEYaikAADcCACABQewGaiANNwIAIAFB5AZqIAw3AgAgAUEIakHUBmogDjcCAC\
ACQfQGaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUGUB2ogCkEYaikAADcCACAB\
QYwHaiANNwIAIAFBhAdqIAw3AgAgAUEIakH0BmogDjcCACACQZQHaiIKIAlGDQAgCkEIaikAACEMIA\
pBEGopAAAhDSAKKQAAIQ4gAUG0B2ogCkEYaikAADcCACABQawHaiANNwIAIAFBpAdqIAw3AgAgAUEI\
akGUB2ogDjcCACACQbQHaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUHUB2ogCk\
EYaikAADcCACABQcwHaiANNwIAIAFBxAdqIAw3AgAgAUEIakG0B2ogDjcCACACQdQHaiIKIAlGDQAg\
CkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUH0B2ogCkEYaikAADcCACABQewHaiANNwIAIAFB5A\
dqIAw3AgAgAUEIakHUB2ogDjcCACACQfQHaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAA\
IQ4gAUGUCGogCkEYaikAADcCACABQYwIaiANNwIAIAFBhAhqIAw3AgAgAUEIakH0B2ogDjcCACACQZ\
QIaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUG0CGogCkEYaikAADcCACABQawI\
aiANNwIAIAFBpAhqIAw3AgAgAUEIakGUCGogDjcCACACQbQIaiIKIAlGDQAgCkEIaikAACEMIApBEG\
opAAAhDSAKKQAAIQ4gAUHUCGogCkEYaikAADcCACABQcwIaiANNwIAIAFBxAhqIAw3AgAgAUEIakG0\
CGogDjcCACACQdQIaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUH0CGogCkEYai\
kAADcCACABQewIaiANNwIAIAFB5AhqIAw3AgAgAUEIakHUCGogDjcCACACQfQIaiIKIAlGDQAgCkEI\
aikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUGUCWogCkEYaikAADcCACABQYwJaiANNwIAIAFBhAlqIA\
w3AgAgAUEIakH0CGogDjcCACACQZQJaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4g\
AUG0CWogCkEYaikAADcCACABQawJaiANNwIAIAFBpAlqIAw3AgAgAUEIakGUCWogDjcCACACQbQJai\
IKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUHUCWogCkEYaikAADcCACABQcwJaiAN\
NwIAIAFBxAlqIAw3AgAgAUEIakG0CWogDjcCACACQdQJaiIKIAlGDQAgCkEIaikAACEMIApBEGopAA\
AhDSAKKQAAIQ4gAUH0CWogCkEYaikAADcCACABQewJaiANNwIAIAFB5AlqIAw3AgAgAUEIakHUCWog\
DjcCACACQfQJaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUGUCmogCkEYaikAAD\
cCACABQYwKaiANNwIAIAFBhApqIAw3AgAgAUEIakH0CWogDjcCACACQZQKaiIKIAlGDQAgCkEIaikA\
ACEMIApBEGopAAAhDSAKKQAAIQ4gAUG0CmogCkEYaikAADcCACABQawKaiANNwIAIAFBpApqIAw3Ag\
AgAUEIakGUCmogDjcCACACQbQKaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUHU\
CmogCkEYaikAADcCACABQcwKaiANNwIAIAFBxApqIAw3AgAgAUEIakG0CmogDjcCACACQdQKaiIKIA\
lGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUH0CmogCkEYaikAADcCACABQewKaiANNwIA\
IAFB5ApqIAw3AgAgAUEIakHUCmogDjcCACACQfQKaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDS\
AKKQAAIQ4gAUGUC2ogCkEYaikAADcCACABQYwLaiANNwIAIAFBhAtqIAw3AgAgAUEIakH0CmogDjcC\
ACACQZQLaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUG0C2ogCkEYaikAADcCAC\
ABQawLaiANNwIAIAFBpAtqIAw3AgAgAUEIakGUC2ogDjcCACACQbQLaiIKIAlGDQAgCkEIaikAACEM\
IApBEGopAAAhDSAKKQAAIQ4gAUHUC2ogCkEYaikAADcCACABQcwLaiANNwIAIAFBxAtqIAw3AgAgAU\
EIakG0C2ogDjcCACACQdQLaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUH0C2og\
CkEYaikAADcCACABQewLaiANNwIAIAFB5AtqIAw3AgAgAUEIakHUC2ogDjcCACACQfQLaiIKIAlGDQ\
AgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUGUDGogCkEYaikAADcCACABQYwMaiANNwIAIAFB\
hAxqIAw3AgAgAUEIakH0C2ogDjcCACACQZQMaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQ\
AAIQ4gAUG0DGogCkEYaikAADcCACABQawMaiANNwIAIAFBpAxqIAw3AgAgAUEIakGUDGogDjcCACAC\
QbQMaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUHUDGogCkEYaikAADcCACABQc\
wMaiANNwIAIAFBxAxqIAw3AgAgAUEIakG0DGogDjcCACACQdQMaiIKIAlGDQAgCkEIaikAACEMIApB\
EGopAAAhDSAKKQAAIQ4gAUH0DGogCkEYaikAADcCACABQewMaiANNwIAIAFB5AxqIAw3AgAgAUEIak\
HUDGogDjcCACACQfQMaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUGUDWogCkEY\
aikAADcCACABQYwNaiANNwIAIAFBhA1qIAw3AgAgAUEIakH0DGogDjcCACACQZQNaiIKIAlGDQAgCk\
EIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUG0DWogCkEYaikAADcCACABQawNaiANNwIAIAFBpA1q\
IAw3AgAgAUEIakGUDWogDjcCACACQbQNaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ\
4gAUHUDWogCkEYaikAADcCACABQcwNaiANNwIAIAFBxA1qIAw3AgAgAUEIakG0DWogDjcCACACQdQN\
aiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUH0DWogCkEYaikAADcCACABQewNai\
ANNwIAIAFB5A1qIAw3AgAgAUEIakHUDWogDjcCACACQfQNaiIKIAlGDQAgCkEIaikAACEMIApBEGop\
AAAhDSAKKQAAIQ4gAUGUDmogCkEYaikAADcCACABQYwOaiANNwIAIAFBhA5qIAw3AgAgAUEIakH0DW\
ogDjcCACACQZQOaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAUG0DmogCkEYaikA\
ADcCACABQawOaiANNwIAIAFBpA5qIAw3AgAgAUEIakGUDmogDjcCACACQbQOaiIKIAlGDQAgCkEIai\
kAACEMIApBEGopAAAhDSAKKQAAIQ4gAUHUDmogCkEYaikAADcCACABQcwOaiANNwIAIAFBxA5qIAw3\
AgAgAUEIakG0DmogDjcCACACQdQOaiIKIAlGDQAgCkEIaikAACEMIApBEGopAAAhDSAKKQAAIQ4gAU\
H0DmogCkEYaikAADcCACABQewOaiANNwIAIAFB5A5qIAw3AgAgAUEIakHUDmogDjcCACACQfQOaiAJ\
Rw0YCyABIAU6AHIgASAGOgBxIAEgBzoAcCABIAs3AwggASAIQf///z9xIgJBNyACQTdJGzYCmAEgBC\
ABQQhqQfgOEJUBGgwTC0HgAhAZIgRFDRUgAUEIaiACQcgBEJUBGiABQQhqQcgBaiACQcgBahBkIAQg\
AUEIakHgAhCVARoMEgtB2AIQGSIERQ0UIAFBCGogAkHIARCVARogAUEIakHIAWogAkHIAWoQZSAEIA\
FBCGpB2AIQlQEaDBELQbgCEBkiBEUNEyABQQhqIAJByAEQlQEaIAFBCGpByAFqIAJByAFqEGYgBCAB\
QQhqQbgCEJUBGgwQC0GYAhAZIgRFDRIgAUEIaiACQcgBEJUBGiABQQhqQcgBaiACQcgBahBnIAQgAU\
EIakGYAhCVARoMDwtB4AAQGSIERQ0RIAFBCGpBEGogAkEQaikDADcDACABIAIpAwg3AxAgAikDACEL\
IAFBCGpBGGogAkEYahBRIAEgCzcDCCAEIAFBCGpB4AAQlQEaDA4LQeAAEBkiBEUNECABQQhqQRBqIA\
JBEGopAwA3AwAgASACKQMINwMQIAIpAwAhCyABQQhqQRhqIAJBGGoQUSABIAs3AwggBCABQQhqQeAA\
EJUBGgwNC0HoABAZIgRFDQ8gAUEIakEYaiACQRhqKAIANgIAIAFBCGpBEGogAkEQaikDADcDACABIA\
IpAwg3AxAgAikDACELIAFBCGpBIGogAkEgahBRIAEgCzcDCCAEIAFBCGpB6AAQlQEaDAwLQegAEBki\
BEUNDiABQQhqQRhqIAJBGGooAgA2AgAgAUEIakEQaiACQRBqKQMANwMAIAEgAikDCDcDECACKQMAIQ\
sgAUEIakEgaiACQSBqEFEgASALNwMIIAQgAUEIakHoABCVARoMCwtB4AIQGSIERQ0NIAFBCGogAkHI\
ARCVARogAUEIakHIAWogAkHIAWoQZCAEIAFBCGpB4AIQlQEaDAoLQdgCEBkiBEUNDCABQQhqIAJByA\
EQlQEaIAFBCGpByAFqIAJByAFqEGUgBCABQQhqQdgCEJUBGgwJC0G4AhAZIgRFDQsgAUEIaiACQcgB\
EJUBGiABQQhqQcgBaiACQcgBahBmIAQgAUEIakG4AhCVARoMCAtBmAIQGSIERQ0KIAFBCGogAkHIAR\
CVARogAUEIakHIAWogAkHIAWoQZyAEIAFBCGpBmAIQlQEaDAcLQfAAEBkiBEUNCSABQQhqQSBqIAJB\
IGopAwA3AwAgAUEIakEYaiACQRhqKQMANwMAIAFBCGpBEGogAkEQaikDADcDACABIAIpAwg3AxAgAi\
kDACELIAFBCGpBKGogAkEoahBRIAEgCzcDCCAEIAFBCGpB8AAQlQEaDAYLQfAAEBkiBEUNCCABQQhq\
QSBqIAJBIGopAwA3AwAgAUEIakEYaiACQRhqKQMANwMAIAFBCGpBEGogAkEQaikDADcDACABIAIpAw\
g3AxAgAikDACELIAFBCGpBKGogAkEoahBRIAEgCzcDCCAEIAFBCGpB8AAQlQEaDAULQdgBEBkiBEUN\
ByABQQhqQThqIAJBOGopAwA3AwAgAUEIakEwaiACQTBqKQMANwMAIAFBCGpBKGogAkEoaikDADcDAC\
ABQQhqQSBqIAJBIGopAwA3AwAgAUEIakEYaiACQRhqKQMANwMAIAFBCGpBEGogAkEQaikDADcDACAB\
QQhqQQhqIAJBCGopAwA3AwAgASACKQMANwMIIAJByABqKQMAIQsgAikDQCEMIAFBCGpB0ABqIAJB0A\
BqEGMgAUEIakHIAGogCzcDACABIAw3A0ggBCABQQhqQdgBEJUBGgwEC0HYARAZIgRFDQYgAUEIakE4\
aiACQThqKQMANwMAIAFBCGpBMGogAkEwaikDADcDACABQQhqQShqIAJBKGopAwA3AwAgAUEIakEgai\
ACQSBqKQMANwMAIAFBCGpBGGogAkEYaikDADcDACABQQhqQRBqIAJBEGopAwA3AwAgAUEIakEIaiAC\
QQhqKQMANwMAIAEgAikDADcDCCACQcgAaikDACELIAIpA0AhDCABQQhqQdAAaiACQdAAahBjIAFBCG\
pByABqIAs3AwAgASAMNwNIIAQgAUEIakHYARCVARoMAwtB+AIQGSIERQ0FIAFBCGogAkHIARCVARog\
AUEIakHIAWogAkHIAWoQaCAEIAFBCGpB+AIQlQEaDAILQdgCEBkiBEUNBCABQQhqIAJByAEQlQEaIA\
FBCGpByAFqIAJByAFqEGUgBCABQQhqQdgCEJUBGgwBC0HoABAZIgRFDQMgAUEIakEQaiACQRBqKQMA\
NwMAIAFBCGpBGGogAkEYaikDADcDACABIAIpAwg3AxAgAikDACELIAFBCGpBIGogAkEgahBRIAEgCz\
cDCCAEIAFBCGpB6AAQlQEaCyAAIAAoAgBBf2o2AgBBDBAZIgBFDQIgACAENgIIIAAgAzYCBCAAQQA2\
AgAgAUGAD2okACAADwsQkQEACxCSAQALAAsQjgEAC9k+AhN/An4jAEGAAmsiBCQAAkACQAJAAkACQA\
JAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkAC\
QAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAk\
ACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQCAADhkAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYAAsg\
AUHIAGohBUGAASABQcgBai0AACIAayIGIANPDRgCQCAARQ0AIAUgAGogAiAGEJUBGiABIAEpA0BCgA\
F8NwNAIAEgBUIAEBIgAyAGayEDIAIgBmohAgsgAyADQQd2IANBAEcgA0H/AHFFcWsiAEEHdCIHayED\
IABFDUkgByEGIAIhAANAIAEgASkDQEKAAXw3A0AgASAAQgAQEiAAQYABaiEAIAZBgH9qIgYNAAxKCw\
sgAUHIAGohBUGAASABQcgBai0AACIAayIGIANPDRgCQCAARQ0AIAUgAGogAiAGEJUBGiABIAEpA0BC\
gAF8NwNAIAEgBUIAEBIgAyAGayEDIAIgBmohAgsgAyADQQd2IANBAEcgA0H/AHFFcWsiAEEHdCIHay\
EDIABFDUcgByEGIAIhAANAIAEgASkDQEKAAXw3A0AgASAAQgAQEiAAQYABaiEAIAZBgH9qIgYNAAxI\
CwsgAUHIAGohBUGAASABQcgBai0AACIAayIGIANPDRgCQCAARQ0AIAUgAGogAiAGEJUBGiABIAEpA0\
BCgAF8NwNAIAEgBUIAEBIgAyAGayEDIAIgBmohAgsgAyADQQd2IANBAEcgA0H/AHFFcWsiAEEHdCIH\
ayEDIABFDUUgByEGIAIhAANAIAEgASkDQEKAAXw3A0AgASAAQgAQEiAAQYABaiEAIAZBgH9qIgYNAA\
xGCwsgAUHIAGohBUGAASABQcgBai0AACIAayIGIANPDRgCQCAARQ0AIAUgAGogAiAGEJUBGiABIAEp\
A0BCgAF8NwNAIAEgBUIAEBIgAyAGayEDIAIgBmohAgsgAyADQQd2IANBAEcgA0H/AHFFcWsiAEEHdC\
IHayEDIABFDUMgByEGIAIhAANAIAEgASkDQEKAAXw3A0AgASAAQgAQEiAAQYABaiEAIAZBgH9qIgYN\
AAxECwsgAUEoaiEFQcAAIAFB6ABqLQAAIgBrIgYgA08NGAJAIABFDQAgBSAAaiACIAYQlQEaIAEgAS\
kDAELAAHw3AwAgASAFQQAQFCADIAZrIQMgAiAGaiECCyADIANBBnYgA0EARyADQT9xRXFrIgBBBnQi\
B2shAyAARQ1BIAchBiACIQADQCABIAEpAwBCwAB8NwMAIAEgAEEAEBQgAEHAAGohACAGQUBqIgYNAA\
xCCwsgAUHpAGotAABBBnQgAS0AaGoiAEUNPyABIAJBgAggAGsiACADIAAgA0kbIgUQNyEAIAMgBWsi\
A0UNRSAEQfAAakEQaiAAQRBqIgYpAwA3AwAgBEHwAGpBGGogAEEYaiIHKQMANwMAIARB8ABqQSBqIA\
BBIGoiCCkDADcDACAEQfAAakEwaiAAQTBqKQMANwMAIARB8ABqQThqIABBOGopAwA3AwAgBEHwAGpB\
wABqIABBwABqKQMANwMAIARB8ABqQcgAaiAAQcgAaikDADcDACAEQfAAakHQAGogAEHQAGopAwA3Aw\
AgBEHwAGpB2ABqIABB2ABqKQMANwMAIARB8ABqQeAAaiAAQeAAaikDADcDACAEIAApAwg3A3ggBCAA\
KQMoNwOYASABQekAai0AACEJIAAtAGohCiAEIAEtAGgiCzoA2AEgBCAAKQMAIhc3A3AgBCAKIAlFck\
ECciIJOgDZASAEQRhqIgogCCkCADcDACAEQRBqIgggBykCADcDACAEQQhqIgcgBikCADcDACAEIAAp\
Agg3AwAgBCAEQfAAakEoaiALIBcgCRAYIAooAgAhCSAIKAIAIQggBygCACEKIAQoAhwhCyAEKAIUIQ\
wgBCgCDCENIAQoAgQhDiAEKAIAIQ8gACAXECogACgCkAEiB0E3Tw0YIABBkAFqIAdBBXRqIgZBIGog\
CzYCACAGQRxqIAk2AgAgBkEYaiAMNgIAIAZBFGogCDYCACAGQRBqIA02AgAgBkEMaiAKNgIAIAZBCG\
ogDjYCACAGQQRqIA82AgAgAEEoaiIGQRhqQgA3AwAgBkEgakIANwMAIAZBKGpCADcDACAGQTBqQgA3\
AwAgBkE4akIANwMAIAZCADcDACAAIAdBAWo2ApABIAZBCGpCADcDACAGQRBqQgA3AwAgAEEIaiIGQR\
hqIABBiAFqKQMANwMAIAZBEGogAEGAAWopAwA3AwAgBkEIaiAAQfgAaikDADcDACAGIAApA3A3AwAg\
ACAAKQMAQgF8NwMAIAFBADsBaCACIAVqIQIMPwsgBCABNgJwIAFByAFqIQZBkAEgAUHYAmotAAAiAG\
siBSADSw0YAkAgAEUNACAGIABqIAIgBRCVARogBEHwAGogBkEBEEQgAyAFayEDIAIgBWohAgsgAyAD\
QZABbiIHQZABbCIFayEAIANBjwFNDT0gBEHwAGogAiAHEEQMPQsgBCABNgJwIAFByAFqIQZBiAEgAU\
HQAmotAAAiAGsiBSADSw0YAkAgAEUNACAGIABqIAIgBRCVARogBEHwAGogBkEBEEggAyAFayEDIAIg\
BWohAgsgAyADQYgBbiIHQYgBbCIFayEAIANBhwFNDTsgBEHwAGogAiAHEEgMOwsgBCABNgJwIAFByA\
FqIQZB6AAgAUGwAmotAAAiAGsiBSADSw0YAkAgAEUNACAGIABqIAIgBRCVARogBEHwAGogBkEBEE8g\
AyAFayEDIAIgBWohAgsgAyADQegAbiIHQegAbCIFayEAIANB5wBNDTkgBEHwAGogAiAHEE8MOQsgBC\
ABNgJwIAFByAFqIQZByAAgAUGQAmotAAAiAGsiBSADSw0YAkAgAEUNACAGIABqIAIgBRCVARogBEHw\
AGogBkEBEFQgAyAFayEDIAIgBWohAgsgAyADQcgAbiIHQcgAbCIFayEAIANBxwBNDTcgBEHwAGogAi\
AHEFQMNwsgAUEYaiEFQcAAIAFB2ABqLQAAIgBrIgYgA0sNGAJAIABFDQAgBSAAaiACIAYQlQEaIAEg\
ASkDAEIBfDcDACABQQhqIAUQHSADIAZrIQMgAiAGaiECCyADQT9xIQcgAiADQUBxIgBqIQggA0E/TQ\
01IAEgASkDACADQQZ2rXw3AwAgAUEIaiEGA0AgBiACEB0gAkHAAGohAiAAQUBqIgANAAw2CwsgBCAB\
NgJwIAFBGGohBkHAACABQdgAai0AACIAayIFIANLDRgCQCAARQ0AIAYgAGogAiAFEJUBGiAEQfAAai\
AGQQEQGiADIAVrIQMgAiAFaiECCyADQT9xIQAgAiADQUBxaiEFIANBP00NMyAEQfAAaiACIANBBnYQ\
GgwzCyABQSBqIQVBwAAgAUHgAGotAAAiAGsiBiADSw0YAkAgAEUNACAFIABqIAIgBhCVARogASABKQ\
MAQgF8NwMAIAFBCGogBRATIAMgBmshAyACIAZqIQILIANBP3EhByACIANBQHEiAGohCCADQT9NDTEg\
ASABKQMAIANBBnatfDcDACABQQhqIQYDQCAGIAIQEyACQcAAaiECIABBQGoiAA0ADDILCyABQSBqIQ\
ZBwAAgAUHgAGotAAAiAGsiBSADSw0YAkAgAEUNACAGIABqIAIgBRCVARogASABKQMAQgF8NwMAIAFB\
CGogBkEBEBUgAyAFayEDIAIgBWohAgsgA0E/cSEAIAIgA0FAcWohBSADQT9NDS8gASABKQMAIANBBn\
YiA618NwMAIAFBCGogAiADEBUMLwsgBCABNgJwIAFByAFqIQZBkAEgAUHYAmotAAAiAGsiBSADSw0Y\
AkAgAEUNACAGIABqIAIgBRCVARogBEHwAGogBkEBEEQgAyAFayEDIAIgBWohAgsgAyADQZABbiIHQZ\
ABbCIFayEAIANBjwFNDS0gBEHwAGogAiAHEEQMLQsgBCABNgJwIAFByAFqIQZBiAEgAUHQAmotAAAi\
AGsiBSADSw0YAkAgAEUNACAGIABqIAIgBRCVARogBEHwAGogBkEBEEggAyAFayEDIAIgBWohAgsgAy\
ADQYgBbiIHQYgBbCIFayEAIANBhwFNDSsgBEHwAGogAiAHEEgMKwsgBCABNgJwIAFByAFqIQZB6AAg\
AUGwAmotAAAiAGsiBSADSw0YAkAgAEUNACAGIABqIAIgBRCVARogBEHwAGogBkEBEE8gAyAFayEDIA\
IgBWohAgsgAyADQegAbiIHQegAbCIFayEAIANB5wBNDSkgBEHwAGogAiAHEE8MKQsgBCABNgJwIAFB\
yAFqIQZByAAgAUGQAmotAAAiAGsiBSADSw0YAkAgAEUNACAGIABqIAIgBRCVARogBEHwAGogBkEBEF\
QgAyAFayEDIAIgBWohAgsgAyADQcgAbiIHQcgAbCIFayEAIANBxwBNDScgBEHwAGogAiAHEFQMJwsg\
AUEoaiEGQcAAIAFB6ABqLQAAIgBrIgUgA0sNGAJAIABFDQAgBiAAaiACIAUQlQEaIAEgASkDAEIBfD\
cDACABQQhqIAZBARAPIAMgBWshAyACIAVqIQILIANBP3EhACACIANBQHFqIQUgA0E/TQ0lIAEgASkD\
ACADQQZ2IgOtfDcDACABQQhqIAIgAxAPDCULIAFBKGohBkHAACABQegAai0AACIAayIFIANLDRgCQC\
AARQ0AIAYgAGogAiAFEJUBGiABIAEpAwBCAXw3AwAgAUEIaiAGQQEQDyADIAVrIQMgAiAFaiECCyAD\
QT9xIQAgAiADQUBxaiEFIANBP00NIyABIAEpAwAgA0EGdiIDrXw3AwAgAUEIaiACIAMQDwwjCyABQd\
AAaiEGQYABIAFB0AFqLQAAIgBrIgUgA0sNGAJAIABFDQAgBiAAaiACIAUQlQEaIAEgASkDQCIXQgF8\
Ihg3A0AgAUHIAGoiACAAKQMAIBggF1StfDcDACABIAZBARANIAMgBWshAyACIAVqIQILIANB/wBxIQ\
AgAiADQYB/cWohBSADQf8ATQ0hIAEgASkDQCIXIANBB3YiA618Ihg3A0AgAUHIAGoiByAHKQMAIBgg\
F1StfDcDACABIAIgAxANDCELIAFB0ABqIQZBgAEgAUHQAWotAAAiAGsiBSADSw0YAkAgAEUNACAGIA\
BqIAIgBRCVARogASABKQNAIhdCAXwiGDcDQCABQcgAaiIAIAApAwAgGCAXVK18NwMAIAEgBkEBEA0g\
AyAFayEDIAIgBWohAgsgA0H/AHEhACACIANBgH9xaiEFIANB/wBNDR8gASABKQNAIhcgA0EHdiIDrX\
wiGDcDQCABQcgAaiIHIAcpAwAgGCAXVK18NwMAIAEgAiADEA0MHwsgBCABNgJwIAFByAFqIQZBqAEg\
AUHwAmotAAAiAGsiBSADSw0YAkAgAEUNACAGIABqIAIgBRCVARogBEHwAGogBkEBED4gAyAFayEDIA\
IgBWohAgsgAyADQagBbiIHQagBbCIFayEAIANBpwFNDR0gBEHwAGogAiAHED4MHQsgBCABNgJwIAFB\
yAFqIQZBiAEgAUHQAmotAAAiAGsiBSADSw0YAkAgAEUNACAGIABqIAIgBRCVARogBEHwAGogBkEBEE\
ggAyAFayEDIAIgBWohAgsgAyADQYgBbiIHQYgBbCIFayEAIANBhwFNDRsgBEHwAGogAiAHEEgMGwsg\
AUEgaiEFAkBBwAAgAUHgAGotAAAiAGsiBiADSw0AAkAgAEUNACAFIABqIAIgBhCVARogASABKQMAQg\
F8NwMAIAFBCGogBRAWIAMgBmshAyACIAZqIQILIANBP3EhByACIANBQHEiAGohCCADQT9NDRkgASAB\
KQMAIANBBnatfDcDACABQQhqIQYDQCAGIAIQFiACQcAAaiECIABBQGoiAA0ADBoLCyAFIABqIAIgAx\
CVARogACADaiEHDBkLIAUgAGogAiADEJUBGiABIAAgA2o6AMgBDDELIAUgAGogAiADEJUBGiABIAAg\
A2o6AMgBDDALIAUgAGogAiADEJUBGiABIAAgA2o6AMgBDC8LIAUgAGogAiADEJUBGiABIAAgA2o6AM\
gBDC4LIAUgAGogAiADEJUBGiABIAAgA2o6AGgMLQsgBCALNgKMASAEIAk2AogBIAQgDDYChAEgBCAI\
NgKAASAEIA02AnwgBCAKNgJ4IAQgDjYCdCAEIA82AnBBiJHAACAEQfAAakGch8AAQfyGwAAQYgALIA\
YgAGogAiADEJUBGiABIAAgA2o6ANgCDCsLIAYgAGogAiADEJUBGiABIAAgA2o6ANACDCoLIAYgAGog\
AiADEJUBGiABIAAgA2o6ALACDCkLIAYgAGogAiADEJUBGiABIAAgA2o6AJACDCgLIAUgAGogAiADEJ\
UBGiABIAAgA2o6AFgMJwsgBiAAaiACIAMQlQEaIAEgACADajoAWAwmCyAFIABqIAIgAxCVARogASAA\
IANqOgBgDCULIAYgAGogAiADEJUBGiABIAAgA2o6AGAMJAsgBiAAaiACIAMQlQEaIAEgACADajoA2A\
IMIwsgBiAAaiACIAMQlQEaIAEgACADajoA0AIMIgsgBiAAaiACIAMQlQEaIAEgACADajoAsAIMIQsg\
BiAAaiACIAMQlQEaIAEgACADajoAkAIMIAsgBiAAaiACIAMQlQEaIAEgACADajoAaAwfCyAGIABqIA\
IgAxCVARogASAAIANqOgBoDB4LIAYgAGogAiADEJUBGiABIAAgA2o6ANABDB0LIAYgAGogAiADEJUB\
GiABIAAgA2o6ANABDBwLIAYgAGogAiADEJUBGiABIAAgA2o6APACDBsLIAYgAGogAiADEJUBGiABIA\
AgA2o6ANACDBoLIAUgCCAHEJUBGgsgASAHOgBgDBgLAkAgAEGJAU8NACAGIAIgBWogABCVARogASAA\
OgDQAgwYCyAAQYgBQYCAwAAQjAEACwJAIABBqQFPDQAgBiACIAVqIAAQlQEaIAEgADoA8AIMFwsgAE\
GoAUGAgMAAEIwBAAsgBiAFIAAQlQEaIAEgADoA0AEMFQsgBiAFIAAQlQEaIAEgADoA0AEMFAsgBiAF\
IAAQlQEaIAEgADoAaAwTCyAGIAUgABCVARogASAAOgBoDBILAkAgAEHJAE8NACAGIAIgBWogABCVAR\
ogASAAOgCQAgwSCyAAQcgAQYCAwAAQjAEACwJAIABB6QBPDQAgBiACIAVqIAAQlQEaIAEgADoAsAIM\
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\
ajYCCCAAIBEgCiAXaiAcIBsgGUEKdyIKQX9zcnNqQc76z8p6akEIdyAYaiIPQQp3aiADIBZqIAQgDU\
EKdyIDcyAMc2pBD3cgDmoiDUEKdyIWajYCBCAAIBMgASAYaiAPIBwgG0EKdyIBQX9zcnNqQc76z8p6\
akEFdyAKaiIJaiAOIAJqIAwgBEEKdyICcyANc2pBDXcgA2oiBEEKd2o2AgAgACgCECEMIAAgASAVai\
AGIApqIAkgDyAgQX9zcnNqQc76z8p6akEGd2ogAyALaiANIAVzIARzakELdyACaiIKajYCECAAIAEg\
DGogBWogAiAHaiAEIBZzIApzakELd2o2AgwLhCgCMH8BfiMAQcAAayIDQRhqIgRCADcDACADQSBqIg\
VCADcDACADQThqIgZCADcDACADQTBqIgdCADcDACADQShqIghCADcDACADQQhqIgkgASkACDcDACAD\
QRBqIgogASkAEDcDACAEIAEoABgiCzYCACAFIAEoACAiBDYCACADIAEpAAA3AwAgAyABKAAcIgU2Ah\
wgAyABKAAkIgw2AiQgCCABKAAoIg02AgAgAyABKAAsIgg2AiwgByABKAAwIg42AgAgAyABKAA0Igc2\
AjQgBiABKAA4Ig82AgAgAyABKAA8IgE2AjwgACAIIAEgBCAFIAcgCCALIAQgDCAMIA0gDyABIAQgBC\
ALIAEgDSAPIAggBSAHIAEgBSAIIAsgByAHIA4gBSALIABBJGoiECgCACIRIABBFGoiEigCACITamoi\
BkGZmoPfBXNBEHciFEG66r+qemoiFSARc0EUdyIWIAZqaiIXIBRzQRh3IhggFWoiGSAWc0EZdyIaIA\
BBIGoiGygCACIVIABBEGoiHCgCACIdaiAKKAIAIgZqIgogAnNBq7OP/AFzQRB3Ih5B8ua74wNqIh8g\
FXNBFHciICAKaiADKAIUIgJqIiFqaiIiIABBHGoiIygCACIWIABBDGoiJCgCACIlaiAJKAIAIglqIg\
ogACkDACIzQiCIp3NBjNGV2HlzQRB3IhRBhd2e23tqIiYgFnNBFHciJyAKaiADKAIMIgpqIiggFHNB\
GHciKXNBEHciKiAAQRhqIisoAgAiLCAAKAIIIi1qIAMoAgAiFGoiLiAzp3NB/6S5iAVzQRB3Ii9B58\
yn0AZqIjAgLHNBFHciMSAuaiADKAIEIgNqIi4gL3NBGHciLyAwaiIwaiIyIBpzQRR3IhogImpqIiIg\
KnNBGHciKiAyaiIyIBpzQRl3IhogASAPIBcgMCAxc0EZdyIwamoiFyAhIB5zQRh3Ih5zQRB3IiEgKS\
AmaiImaiIpIDBzQRR3IjAgF2pqIhdqaiIxIAwgBCAmICdzQRl3IiYgLmpqIicgGHNBEHciGCAeIB9q\
Ih5qIh8gJnNBFHciJiAnamoiJyAYc0EYdyIYc0EQdyIuIAggDSAeICBzQRl3Ih4gKGpqIiAgL3NBEH\
ciKCAZaiIZIB5zQRR3Ih4gIGpqIiAgKHNBGHciKCAZaiIZaiIvIBpzQRR3IhogMWpqIjEgLnNBGHci\
LiAvaiIvIBpzQRl3IhogASAMICIgGSAec0EZdyIZamoiHiAXICFzQRh3IhdzQRB3IiEgGCAfaiIYai\
IfIBlzQRR3IhkgHmpqIh5qaiIiIAQgICAYICZzQRl3IhhqIAZqIiAgKnNBEHciJiAXIClqIhdqIikg\
GHNBFHciGCAgamoiICAmc0EYdyImc0EQdyIqIA0gDyAXIDBzQRl3IhcgJ2pqIicgKHNBEHciKCAyai\
IwIBdzQRR3IhcgJ2pqIicgKHNBGHciKCAwaiIwaiIyIBpzQRR3IhogImpqIiIgKnNBGHciKiAyaiIy\
IBpzQRl3IhogMSAwIBdzQRl3IhdqIAJqIjAgHiAhc0EYdyIec0EQdyIhICYgKWoiJmoiKSAXc0EUdy\
IXIDBqIApqIjBqaiIxIA4gJiAYc0EZdyIYICdqIANqIiYgLnNBEHciJyAeIB9qIh5qIh8gGHNBFHci\
GCAmamoiJiAnc0EYdyInc0EQdyIuIB4gGXNBGXciGSAgaiAUaiIeIChzQRB3IiAgL2oiKCAZc0EUdy\
IZIB5qIAlqIh4gIHNBGHciICAoaiIoaiIvIBpzQRR3IhogMWpqIjEgLnNBGHciLiAvaiIvIBpzQRl3\
IhogIiAoIBlzQRl3IhlqIAJqIiIgMCAhc0EYdyIhc0EQdyIoICcgH2oiH2oiJyAZc0EUdyIZICJqIA\
lqIiJqaiIwIA4gHiAfIBhzQRl3IhhqaiIeICpzQRB3Ih8gISApaiIhaiIpIBhzQRR3IhggHmogFGoi\
HiAfc0EYdyIfc0EQdyIqIAQgCCAhIBdzQRl3IhcgJmpqIiEgIHNBEHciICAyaiImIBdzQRR3IhcgIW\
pqIiEgIHNBGHciICAmaiImaiIyIBpzQRR3IhogMGogA2oiMCAqc0EYdyIqIDJqIjIgGnNBGXciGiAM\
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\
CCIJQRh0IAlBCHRBgID8B3FyIAlBCHZBgP4DcSAJQRh2cnI2AgggAyABKAAMIglBGHQgCUEIdEGAgP\
wHcXIgCUEIdkGA/gNxIAlBGHZycjYCDCADIAEoABAiCUEYdCAJQQh0QYCA/AdxciAJQQh2QYD+A3Eg\
CUEYdnJyNgIQIAMgASgAFCIJQRh0IAlBCHRBgID8B3FyIAlBCHZBgP4DcSAJQRh2cnI2AhQgAyABKA\
AcIglBGHQgCUEIdEGAgPwHcXIgCUEIdkGA/gNxIAlBGHZyciIKNgIcIAMgASgAICIJQRh0IAlBCHRB\
gID8B3FyIAlBCHZBgP4DcSAJQRh2cnIiCzYCICADIAEoABgiCUEYdCAJQQh0QYCA/AdxciAJQQh2QY\
D+A3EgCUEYdnJyIgw2AhggAygCACENIAMoAgQhDiADKAIIIQ8gAygCECEQIAMoAgwhESADKAIUIRIg\
AyABKAAkIglBGHQgCUEIdEGAgPwHcXIgCUEIdkGA/gNxIAlBGHZyciITNgIkIAMgASgAKCIJQRh0IA\
lBCHRBgID8B3FyIAlBCHZBgP4DcSAJQRh2cnIiFDYCKCADIAEoADAiCUEYdCAJQQh0QYCA/AdxciAJ\
QQh2QYD+A3EgCUEYdnJyIhU2AjAgAyABKAAsIglBGHQgCUEIdEGAgPwHcXIgCUEIdkGA/gNxIAlBGH\
ZyciIWNgIsIAMgASgANCIJQRh0IAlBCHRBgID8B3FyIAlBCHZBgP4DcSAJQRh2cnIiCTYCNCADIAEo\
ADgiF0EYdCAXQQh0QYCA/AdxciAXQQh2QYD+A3EgF0EYdnJyIhc2AjggAyABKAA8IhhBGHQgGEEIdE\
GAgPwHcXIgGEEIdkGA/gNxIBhBGHZyciIYNgI8IAUgEyAKcyAYcyAMIBBzIBVzIBEgDnMgE3MgF3NB\
AXciGXNBAXciGnNBAXciGyAKIBJzIAlzIBAgD3MgFHMgGHNBAXciHHNBAXciHXMgGCAJcyAdcyAVIB\
RzIBxzIBtzQQF3Ih5zQQF3Ih9zIBogHHMgHnMgGSAYcyAbcyAXIBVzIBpzIBYgE3MgGXMgCyAMcyAX\
cyASIBFzIBZzIA8gDXMgC3MgCXNBAXciIHNBAXciIXNBAXciInNBAXciI3NBAXciJHNBAXciJXNBAX\
ciJnNBAXciJyAdICFzIAkgFnMgIXMgFCALcyAgcyAdc0EBdyIoc0EBdyIpcyAcICBzIChzIB9zQQF3\
IipzQQF3IitzIB8gKXMgK3MgHiAocyAqcyAnc0EBdyIsc0EBdyItcyAmICpzICxzICUgH3MgJ3MgJC\
AecyAmcyAjIBtzICVzICIgGnMgJHMgISAZcyAjcyAgIBdzICJzIClzQQF3Ii5zQQF3Ii9zQQF3IjBz\
QQF3IjFzQQF3IjJzQQF3IjNzQQF3IjRzQQF3IjUgKyAvcyApICNzIC9zICggInMgLnMgK3NBAXciNn\
NBAXciN3MgKiAucyA2cyAtc0EBdyI4c0EBdyI5cyAtIDdzIDlzICwgNnMgOHMgNXNBAXciOnNBAXci\
O3MgNCA4cyA6cyAzIC1zIDVzIDIgLHMgNHMgMSAncyAzcyAwICZzIDJzIC8gJXMgMXMgLiAkcyAwcy\
A3c0EBdyI8c0EBdyI9c0EBdyI+c0EBdyI/c0EBdyJAc0EBdyJBc0EBdyJCc0EBdyJDIDkgPXMgNyAx\
cyA9cyA2IDBzIDxzIDlzQQF3IkRzQQF3IkVzIDggPHMgRHMgO3NBAXciRnNBAXciR3MgOyBFcyBHcy\
A6IERzIEZzIENzQQF3IkhzQQF3IklzIEIgRnMgSHMgQSA7cyBDcyBAIDpzIEJzID8gNXMgQXMgPiA0\
cyBAcyA9IDNzID9zIDwgMnMgPnMgRXNBAXciSnNBAXciS3NBAXciTHNBAXciTXNBAXciTnNBAXciT3\
NBAXciUHNBAXdqIEYgSnMgRCA+cyBKcyBHc0EBdyJRcyBJc0EBdyJSIEUgP3MgS3MgUXNBAXciUyBM\
IEEgOiA5IDwgMSAmIB8gKCAhIBcgEyAQIAVBHnciVGogDiAHIAZBHnciECACcyAFcSACc2pqIA0gCC\
AFQQV3aiACIAdzIAZxIAdzampBmfOJ1AVqIg5BBXdqQZnzidQFaiJVQR53IgUgDkEedyINcyACIA9q\
IA4gVCAQc3EgEHNqIFVBBXdqQZnzidQFaiIOcSANc2ogECARaiBVIA0gVHNxIFRzaiAOQQV3akGZ84\
nUBWoiEEEFd2pBmfOJ1AVqIhFBHnciD2ogBSAMaiARIBBBHnciEyAOQR53IgxzcSAMc2ogDSASaiAM\
IAVzIBBxIAVzaiARQQV3akGZ84nUBWoiEUEFd2pBmfOJ1AVqIhJBHnciBSARQR53IhBzIAogDGogES\
APIBNzcSATc2ogEkEFd2pBmfOJ1AVqIgpxIBBzaiALIBNqIBAgD3MgEnEgD3NqIApBBXdqQZnzidQF\
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\
AWpBADoAAAwVCyABQQhqKAIAIQMgAkHQAGpBCGoQeyACQQhqQSBqIAJB+ABqKQMAIgU3AwAgAkEIak\
EYaiACQdAAakEgaikDACIGNwMAIAJBCGpBEGogAkHQAGpBGGopAwAiBzcDACACQQhqQQhqIAJB0ABq\
QRBqKQMAIgg3AwAgAiACKQNYIgk3AwggA0EgaiAFNwMAIANBGGogBjcDACADQRBqIAc3AwAgA0EIai\
AINwMAIAMgCTcDACADQegAakEAOgAADBQLIAFBCGooAgAiA0IANwMAIAMgAykDcDcDCCADQRBqIANB\
+ABqKQMANwMAIANBGGogA0GAAWopAwA3AwAgA0EgaiADQYgBaikDADcDACADQShqQQBBwgAQlAEaIA\
MoApABRQ0TIANBADYCkAEMEwsgAUEIaigCAEEAQcgBEJQBQdgCakEAOgAADBILIAFBCGooAgBBAEHI\
ARCUAUHQAmpBADoAAAwRCyABQQhqKAIAQQBByAEQlAFBsAJqQQA6AAAMEAsgAUEIaigCAEEAQcgBEJ\
QBQZACakEAOgAADA8LIAFBCGooAgAiA0L+uevF6Y6VmRA3AxAgA0KBxpS6lvHq5m83AwggA0IANwMA\
IANB2ABqQQA6AAAMDgsgAUEIaigCACIDQv6568XpjpWZEDcDECADQoHGlLqW8ermbzcDCCADQgA3Aw\
AgA0HYAGpBADoAAAwNCyABQQhqKAIAIgNCADcDACADQQApA+iMQDcDCCADQRBqQQApA/CMQDcDACAD\
QRhqQQAoAviMQDYCACADQeAAakEAOgAADAwLIAFBCGooAgAiA0Hww8uefDYCGCADQv6568XpjpWZED\
cDECADQoHGlLqW8ermbzcDCCADQgA3AwAgA0HgAGpBADoAAAwLCyABQQhqKAIAQQBByAEQlAFB2AJq\
QQA6AAAMCgsgAUEIaigCAEEAQcgBEJQBQdACakEAOgAADAkLIAFBCGooAgBBAEHIARCUAUGwAmpBAD\
oAAAwICyABQQhqKAIAQQBByAEQlAFBkAJqQQA6AAAMBwsgAUEIaigCACIDQgA3AwAgA0EAKQOgjUA3\
AwggA0EQakEAKQOojUA3AwAgA0EYakEAKQOwjUA3AwAgA0EgakEAKQO4jUA3AwAgA0HoAGpBADoAAA\
wGCyABQQhqKAIAIgNCADcDACADQQApA4CNQDcDCCADQRBqQQApA4iNQDcDACADQRhqQQApA5CNQDcD\
ACADQSBqQQApA5iNQDcDACADQegAakEAOgAADAULIAFBCGooAgAiA0IANwNAIANBACkDgI5ANwMAIA\
NByABqQgA3AwAgA0EIakEAKQOIjkA3AwAgA0EQakEAKQOQjkA3AwAgA0EYakEAKQOYjkA3AwAgA0Eg\
akEAKQOgjkA3AwAgA0EoakEAKQOojkA3AwAgA0EwakEAKQOwjkA3AwAgA0E4akEAKQO4jkA3AwAgA0\
HQAWpBADoAAAwECyABQQhqKAIAIgNCADcDQCADQQApA8CNQDcDACADQcgAakIANwMAIANBCGpBACkD\
yI1ANwMAIANBEGpBACkD0I1ANwMAIANBGGpBACkD2I1ANwMAIANBIGpBACkD4I1ANwMAIANBKGpBAC\
kD6I1ANwMAIANBMGpBACkD8I1ANwMAIANBOGpBACkD+I1ANwMAIANB0AFqQQA6AAAMAwsgAUEIaigC\
AEEAQcgBEJQBQfACakEAOgAADAILIAFBCGooAgBBAEHIARCUAUHQAmpBADoAAAwBCyABQQhqKAIAIg\
NCADcDACADQQApA7iRQDcDCCADQRBqQQApA8CRQDcDACADQRhqQQApA8iRQDcDACADQeAAakEAOgAA\
CyABQQA2AgAgAEIANwMAIAJBoAFqJAAPCxCRAQALEJIBAAumDQECfyMAQZACayIDJAACQAJAAkACQA\
JAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAIAJBfWoOCQMMCgsBBQwCAAwLAkAC\
QCABQZeAwABBCxCWAUUNACABQaKAwABBCxCWAUUNASABQa2AwABBCxCWAQ0NQdABEBkiAUUNFyADQZ\
ABaiICQTAQdCABIAJByAAQlQEhAiADQQA2AgAgAyADQQRyQQBBgAEQlAFBf3NqQYQBakEHSRogA0GA\
ATYCACADQYgBaiADQYQBEJUBGiACQcgAaiADQYgBakEEckGAARCVARogAkHIAWpBADoAAEEDIQIMFQ\
tB0AEQGSIBRQ0WIANBkAFqIgJBHBB0IAEgAkHIABCVASECIANBADYCACADIANBBHJBAEGAARCUAUF/\
c2pBhAFqQQdJGiADQYABNgIAIANBiAFqIANBhAEQlQEaIAJByABqIANBiAFqQQRyQYABEJUBGiACQc\
gBakEAOgAAQQEhAgwUC0HQARAZIgFFDRUgA0GQAWoiAkEgEHQgASACQcgAEJUBIQIgA0EANgIAIAMg\
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\
IGohCiACQRBqIQsgAkEYaiEMIANBfmpBN0khDQNAIAAgBTYCkAEgAkEIaiIDIAdBKGopAAA3AwAgCy\
AHQTBqKQAANwMAIAwgB0E4aikAADcDACACIAdBIGopAAA3AwAgBUUNAiAAIAVBf2oiDjYCkAEgAC0A\
aiEPIAogAikDADcAACAKQQhqIAMpAwA3AAAgCkEQaiALKQMANwAAIApBGGogDCkDADcAACACQZABak\
EYaiIDIAdBGGoiECkAADcDACACQZABakEQaiIRIAdBEGoiEikAADcDACACQZABakEIaiITIAdBCGoi\
FCkAADcDACAJIAYpAwA3AwAgCUEIaiAGQQhqIhUpAwA3AwAgCUEQaiAGQRBqIhYpAwA3AwAgCUEYai\
AGQRhqIhcpAwA3AwAgAiAHKQAANwOQASAIQThqIAJBkAFqQThqKQMANwAAIAhBMGogAkGQAWpBMGop\
AwA3AAAgCEEoaiACQZABakEoaikDADcAACAIQSBqIAopAwA3AAAgCEEYaiADKQMANwAAIAhBEGogES\
kDADcAACAIQQhqIBMpAwA3AAAgCCACKQOQATcAACACQcAAOgCIASACIA9BBHIiDzoAiQEgAkIANwMg\
IAMgFykCADcDACARIBYpAgA3AwAgEyAVKQIANwMAIAIgBikCADcDkAEgAkGQAWogCEHAAEIAIA8QGC\
ADKAIAIQMgESgCACERIBMoAgAhEyACKAKsASEPIAIoAqQBIRUgAigCnAEhFiACKAKUASEXIAIoApAB\
IRggDUUNAyAHIBg2AgAgB0EcaiAPNgIAIBAgAzYCACAHQRRqIBU2AgAgEiARNgIAIAdBDGogFjYCAC\
AUIBM2AgAgB0EEaiAXNgIAIAAgBTYCkAEgB0FgaiEHIA4hBSAOIARPDQALCyACQdABaiQADwtBsJDA\
AEErQbSFwAAQcwALIAIgDzYCrAEgAiADNgKoASACIBU2AqQBIAIgETYCoAEgAiAWNgKcASACIBM2Ap\
gBIAIgFzYClAEgAiAYNgKQAUGIkcAAIAJBkAFqQZyHwABB/IbAABBiAAucBQEKfyMAQTBrIgMkACAD\
QSRqIAE2AgAgA0EDOgAoIANCgICAgIAENwMIIAMgADYCIEEAIQQgA0EANgIYIANBADYCEAJAAkACQA\
JAIAIoAggiBQ0AIAJBFGooAgAiAEUNASACKAIQIQEgAEEDdCEGIABBf2pB/////wFxQQFqIQQgAigC\
ACEAA0ACQCAAQQRqKAIAIgdFDQAgAygCICAAKAIAIAcgAygCJCgCDBEIAA0ECyABKAIAIANBCGogAU\
EEaigCABEGAA0DIAFBCGohASAAQQhqIQAgBkF4aiIGDQAMAgsLIAJBDGooAgAiAUUNACABQQV0IQgg\
AUF/akH///8/cUEBaiEEIAIoAgAhAEEAIQYDQAJAIABBBGooAgAiAUUNACADKAIgIAAoAgAgASADKA\
IkKAIMEQgADQMLIAMgBSAGaiIBQRxqLQAAOgAoIAMgAUEEaikCAEIgiTcDCCABQRhqKAIAIQkgAigC\
ECEKQQAhC0EAIQcCQAJAAkAgAUEUaigCAA4DAQACAQsgCUEDdCEMQQAhByAKIAxqIgxBBGooAgBBBE\
cNASAMKAIAKAIAIQkLQQEhBwsgAyAJNgIUIAMgBzYCECABQRBqKAIAIQcCQAJAAkAgAUEMaigCAA4D\
AQACAQsgB0EDdCEJIAogCWoiCUEEaigCAEEERw0BIAkoAgAoAgAhBwtBASELCyADIAc2AhwgAyALNg\
IYIAogASgCAEEDdGoiASgCACADQQhqIAEoAgQRBgANAiAAQQhqIQAgCCAGQSBqIgZHDQALCwJAIAQg\
AigCBE8NACADKAIgIAIoAgAgBEEDdGoiASgCACABKAIEIAMoAiQoAgwRCAANAQtBACEBDAELQQEhAQ\
sgA0EwaiQAIAELmgQCA38CfiMAQfABayIDJAAgACkDACEGIAEgAS0AQCIEaiIFQYABOgAAIANBCGpB\
EGogAEEYaigCADYCACADQRBqIABBEGopAgA3AwAgAyAAKQIINwMIIAZCCYYhBiAErUIDhiEHAkAgBE\
E/cyIARQ0AIAVBAWpBACAAEJQBGgsgBiAHhCEGAkACQCAEQThxQThGDQAgASAGNwA4IANBCGogARAT\
DAELIANBCGogARATIANB4ABqQQxqQgA3AgAgA0HgAGpBFGpCADcCACADQeAAakEcakIANwIAIANB4A\
BqQSRqQgA3AgAgA0HgAGpBLGpCADcCACADQeAAakE0akIANwIAIANBnAFqQgA3AgAgA0IANwJkIANB\
ADYCYCADQeAAaiADQeAAakEEckF/c2pBxABqQQdJGiADQcAANgJgIANBqAFqIANB4ABqQcQAEJUBGi\
ADQdAAaiADQagBakE0aikCADcDACADQcgAaiADQagBakEsaikCADcDACADQcAAaiADQagBakEkaikC\
ADcDACADQThqIANBqAFqQRxqKQIANwMAIANBMGogA0GoAWpBFGopAgA3AwAgA0EoaiADQagBakEMai\
kCADcDACADIAMpAqwBNwMgIAMgBjcDWCADQQhqIANBIGoQEwsgAUEAOgBAIAIgAygCCDYAACACIAMp\
Agw3AAQgAiADKQIUNwAMIANB8AFqJAALigQBCn8jAEEwayIGJABBACEHIAZBADYCCAJAIAFBQHEiCE\
UNAEEBIQcgBkEBNgIIIAYgADYCACAIQcAARg0AQQIhByAGQQI2AgggBiAAQcAAajYCBCAIQYABRg0A\
IAYgAEGAAWo2AhBBiJHAACAGQRBqQYyHwABB/IbAABBiAAsgAUE/cSEJAkAgByAFQQV2IgEgByABSR\
siAUUNACADQQRyIQogAUEFdCELQQAhAyAGIQwDQCAMKAIAIQEgBkEQakEYaiINIAJBGGopAgA3AwAg\
BkEQakEQaiIOIAJBEGopAgA3AwAgBkEQakEIaiIPIAJBCGopAgA3AwAgBiACKQIANwMQIAZBEGogAU\
HAAEIAIAoQGCAEIANqIgFBGGogDSkDADcAACABQRBqIA4pAwA3AAAgAUEIaiAPKQMANwAAIAEgBikD\
EDcAACAMQQRqIQwgCyADQSBqIgNHDQALCwJAAkACQAJAIAlFDQAgB0EFdCICIAVLDQEgBSACayIBQR\
9NDQIgCUEgRw0DIAQgAmoiAiAAIAhqIgEpAAA3AAAgAkEYaiABQRhqKQAANwAAIAJBEGogAUEQaikA\
ADcAACACQQhqIAFBCGopAAA3AAAgB0EBaiEHCyAGQTBqJAAgBw8LIAIgBUG0hMAAEI0BAAtBICABQb\
SEwAAQjAEAC0EgIAlBxITAABBrAAvyAwIDfwJ+IwBB4AFrIgMkACAAKQMAIQYgASABLQBAIgRqIgVB\
gAE6AAAgA0EIaiAAQRBqKQIANwMAIAMgACkCCDcDACAGQgmGIQYgBK1CA4YhBwJAIARBP3MiAEUNAC\
AFQQFqQQAgABCUARoLIAYgB4QhBgJAAkAgBEE4cUE4Rg0AIAEgBjcAOCADIAEQHQwBCyADIAEQHSAD\
QdAAakEMakIANwIAIANB0ABqQRRqQgA3AgAgA0HQAGpBHGpCADcCACADQdAAakEkakIANwIAIANB0A\
BqQSxqQgA3AgAgA0HQAGpBNGpCADcCACADQYwBakIANwIAIANCADcCVCADQQA2AlAgA0HQAGogA0HQ\
AGpBBHJBf3NqQcQAakEHSRogA0HAADYCUCADQZgBaiADQdAAakHEABCVARogA0HAAGogA0GYAWpBNG\
opAgA3AwAgA0E4aiADQZgBakEsaikCADcDACADQTBqIANBmAFqQSRqKQIANwMAIANBKGogA0GYAWpB\
HGopAgA3AwAgA0EgaiADQZgBakEUaikCADcDACADQRhqIANBmAFqQQxqKQIANwMAIAMgAykCnAE3Ax\
AgAyAGNwNIIAMgA0EQahAdCyABQQA6AEAgAiADKQMANwAAIAIgAykDCDcACCADQeABaiQAC/IDAgN/\
An4jAEHgAWsiAyQAIAApAwAhBiABIAEtAEAiBGoiBUGAAToAACADQQhqIABBEGopAgA3AwAgAyAAKQ\
IINwMAIAZCCYYhBiAErUIDhiEHAkAgBEE/cyIARQ0AIAVBAWpBACAAEJQBGgsgBiAHhCEGAkACQCAE\
QThxQThGDQAgASAGNwA4IAMgARAbDAELIAMgARAbIANB0ABqQQxqQgA3AgAgA0HQAGpBFGpCADcCAC\
ADQdAAakEcakIANwIAIANB0ABqQSRqQgA3AgAgA0HQAGpBLGpCADcCACADQdAAakE0akIANwIAIANB\
jAFqQgA3AgAgA0IANwJUIANBADYCUCADQdAAaiADQdAAakEEckF/c2pBxABqQQdJGiADQcAANgJQIA\
NBmAFqIANB0ABqQcQAEJUBGiADQcAAaiADQZgBakE0aikCADcDACADQThqIANBmAFqQSxqKQIANwMA\
IANBMGogA0GYAWpBJGopAgA3AwAgA0EoaiADQZgBakEcaikCADcDACADQSBqIANBmAFqQRRqKQIANw\
MAIANBGGogA0GYAWpBDGopAgA3AwAgAyADKQKcATcDECADIAY3A0ggAyADQRBqEBsLIAFBADoAQCAC\
IAMpAwA3AAAgAiADKQMINwAIIANB4AFqJAAL5wMCBH8CfiMAQdABayIDJAAgASABLQBAIgRqIgVBAT\
oAACAAKQMAQgmGIQcgBK1CA4YhCAJAIARBP3MiBkUNACAFQQFqQQAgBhCUARoLIAcgCIQhBwJAAkAg\
BEE4cUE4Rg0AIAEgBzcAOCAAQQhqIAEQFgwBCyAAQQhqIgQgARAWIANBwABqQQxqQgA3AgAgA0HAAG\
pBFGpCADcCACADQcAAakEcakIANwIAIANBwABqQSRqQgA3AgAgA0HAAGpBLGpCADcCACADQcAAakE0\
akIANwIAIANB/ABqQgA3AgAgA0IANwJEIANBADYCQCADQcAAaiADQcAAakEEckF/c2pBxABqQQdJGi\
ADQcAANgJAIANBiAFqIANBwABqQcQAEJUBGiADQTBqIANBiAFqQTRqKQIANwMAIANBKGogA0GIAWpB\
LGopAgA3AwAgA0EgaiADQYgBakEkaikCADcDACADQRhqIANBiAFqQRxqKQIANwMAIANBEGogA0GIAW\
pBFGopAgA3AwAgA0EIaiADQYgBakEMaikCADcDACADIAMpAowBNwMAIAMgBzcDOCAEIAMQFgsgAUEA\
OgBAIAIgACkDCDcAACACIABBEGopAwA3AAggAiAAQRhqKQMANwAQIANB0AFqJAALgAMBBX8CQAJAAk\
AgAUEJSQ0AQQAhAkHN/3sgAUEQIAFBEEsbIgFrIABNDQEgAUEQIABBC2pBeHEgAEELSRsiA2pBDGoQ\
GSIARQ0BIABBeGohAgJAAkAgAUF/aiIEIABxDQAgAiEBDAELIABBfGoiBSgCACIGQXhxIAQgAGpBAC\
ABa3FBeGoiAEEAIAEgACACa0EQSxtqIgEgAmsiAGshBAJAIAZBA3FFDQAgASABKAIEQQFxIARyQQJy\
NgIEIAEgBGoiBCAEKAIEQQFyNgIEIAUgBSgCAEEBcSAAckECcjYCACACIABqIgQgBCgCBEEBcjYCBC\
ACIAAQJAwBCyACKAIAIQIgASAENgIEIAEgAiAAajYCAAsgASgCBCIAQQNxRQ0CIABBeHEiAiADQRBq\
TQ0CIAEgAEEBcSADckECcjYCBCABIANqIgAgAiADayIDQQNyNgIEIAEgAmoiAiACKAIEQQFyNgIEIA\
AgAxAkDAILIAAQGSECCyACDwsgAUEIaguLAwECfyMAQZABayIAJAACQEHwABAZIgFFDQAgAEEMakIA\
NwIAIABBFGpCADcCACAAQRxqQgA3AgAgAEEkakIANwIAIABBLGpCADcCACAAQTRqQgA3AgAgAEE8ak\
IANwIAIABCADcCBCAAQQA2AgAgACAAQQRyQX9zakHEAGpBB0kaIABBwAA2AgAgAEHIAGogAEHEABCV\
ARogAUHgAGogAEHIAGpBPGopAgA3AAAgAUHYAGogAEHIAGpBNGopAgA3AAAgAUHQAGogAEHIAGpBLG\
opAgA3AAAgAUHIAGogAEHIAGpBJGopAgA3AAAgAUHAAGogAEHIAGpBHGopAgA3AAAgAUE4aiAAQcgA\
akEUaikCADcAACABQTBqIABByABqQQxqKQIANwAAIAEgACkCTDcAKCABQgA3AwAgAUHoAGpBADoAAC\
ABQQApA6CNQDcDCCABQRBqQQApA6iNQDcDACABQRhqQQApA7CNQDcDACABQSBqQQApA7iNQDcDACAA\
QZABaiQAIAEPCwALiwMBAn8jAEGQAWsiACQAAkBB8AAQGSIBRQ0AIABBDGpCADcCACAAQRRqQgA3Ag\
AgAEEcakIANwIAIABBJGpCADcCACAAQSxqQgA3AgAgAEE0akIANwIAIABBPGpCADcCACAAQgA3AgQg\
AEEANgIAIAAgAEEEckF/c2pBxABqQQdJGiAAQcAANgIAIABByABqIABBxAAQlQEaIAFB4ABqIABByA\
BqQTxqKQIANwAAIAFB2ABqIABByABqQTRqKQIANwAAIAFB0ABqIABByABqQSxqKQIANwAAIAFByABq\
IABByABqQSRqKQIANwAAIAFBwABqIABByABqQRxqKQIANwAAIAFBOGogAEHIAGpBFGopAgA3AAAgAU\
EwaiAAQcgAakEMaikCADcAACABIAApAkw3ACggAUIANwMAIAFB6ABqQQA6AAAgAUEAKQOAjUA3Awgg\
AUEQakEAKQOIjUA3AwAgAUEYakEAKQOQjUA3AwAgAUEgakEAKQOYjUA3AwAgAEGQAWokACABDwsAC/\
sCAQJ/IwBBkAFrIgAkAAJAQegAEBkiAUUNACAAQQxqQgA3AgAgAEEUakIANwIAIABBHGpCADcCACAA\
QSRqQgA3AgAgAEEsakIANwIAIABBNGpCADcCACAAQTxqQgA3AgAgAEIANwIEIABBADYCACAAIABBBH\
JBf3NqQcQAakEHSRogAEHAADYCACAAQcgAaiAAQcQAEJUBGiABQdgAaiAAQcgAakE8aikCADcAACAB\
QdAAaiAAQcgAakE0aikCADcAACABQcgAaiAAQcgAakEsaikCADcAACABQcAAaiAAQcgAakEkaikCAD\
cAACABQThqIABByABqQRxqKQIANwAAIAFBMGogAEHIAGpBFGopAgA3AAAgAUEoaiAAQcgAakEMaikC\
ADcAACABIAApAkw3ACAgAUIANwMAIAFB4ABqQQA6AAAgAUEAKQPojEA3AwggAUEQakEAKQPwjEA3Aw\
AgAUEYakEAKAL4jEA2AgAgAEGQAWokACABDwsAC/sCAQJ/IwBBkAFrIgAkAAJAQegAEBkiAUUNACAB\
QgA3AwAgAUEAKQO4kUA3AwggAUEQakEAKQPAkUA3AwAgAUEYakEAKQPIkUA3AwAgAEEMakIANwIAIA\
BBFGpCADcCACAAQRxqQgA3AgAgAEEkakIANwIAIABBLGpCADcCACAAQTRqQgA3AgAgAEE8akIANwIA\
IABCADcCBCAAQQA2AgAgACAAQQRyQX9zakHEAGpBB0kaIABBwAA2AgAgAEHIAGogAEHEABCVARogAU\
HYAGogAEHIAGpBPGopAgA3AAAgAUHQAGogAEHIAGpBNGopAgA3AAAgAUHIAGogAEHIAGpBLGopAgA3\
AAAgAUHAAGogAEHIAGpBJGopAgA3AAAgAUE4aiAAQcgAakEcaikCADcAACABQTBqIABByABqQRRqKQ\
IANwAAIAFBKGogAEHIAGpBDGopAgA3AAAgASAAKQJMNwAgIAFB4ABqQQA6AAAgAEGQAWokACABDwsA\
C6kDAQF/IAIgAi0AqAEiA2pBAEGoASADaxCUASEDIAJBADoAqAEgA0EfOgAAIAIgAi0ApwFBgAFyOg\
CnASABIAEpAwAgAikAAIU3AwAgASABKQMIIAIpAAiFNwMIIAEgASkDECACKQAQhTcDECABIAEpAxgg\
AikAGIU3AxggASABKQMgIAIpACCFNwMgIAEgASkDKCACKQAohTcDKCABIAEpAzAgAikAMIU3AzAgAS\
ABKQM4IAIpADiFNwM4IAEgASkDQCACKQBAhTcDQCABIAEpA0ggAikASIU3A0ggASABKQNQIAIpAFCF\
NwNQIAEgASkDWCACKQBYhTcDWCABIAEpA2AgAikAYIU3A2AgASABKQNoIAIpAGiFNwNoIAEgASkDcC\
ACKQBwhTcDcCABIAEpA3ggAikAeIU3A3ggASABKQOAASACKQCAAYU3A4ABIAEgASkDiAEgAikAiAGF\
NwOIASABIAEpA5ABIAIpAJABhTcDkAEgASABKQOYASACKQCYAYU3A5gBIAEgASkDoAEgAikAoAGFNw\
OgASABECUgACABQcgBEJUBGgvvAgEDfwJAAkACQAJAIAAtAGgiA0UNAAJAIANBwQBPDQAgAEEoaiIE\
IANqIAFBwAAgA2siAyACIAMgAkkbIgMQlQEaIAAgAC0AaCADaiIFOgBoIAEgA2ohAQJAIAIgA2siAg\
0AQQAhAgwDCyAAQQhqIARBwAAgACkDACAALQBqIABB6QBqIgMtAABFchAYIARBAEHBABCUARogAyAD\
LQAAQQFqOgAADAELIANBwABBlITAABCNAQALQQAhAyACQcEASQ0BIABBCGohBCAAQekAaiIDLQAAIQ\
UDQCAEIAFBwAAgACkDACAALQBqIAVB/wFxRXIQGCADIAMtAABBAWoiBToAACABQcAAaiEBIAJBQGoi\
AkHAAEsNAAsgAC0AaCEFCyAFQf8BcSIDQcEATw0BCyAAIANqQShqIAFBwAAgA2siAyACIAMgAkkbIg\
IQlQEaIAAgAC0AaCACajoAaCAADwsgA0HAAEGUhMAAEI0BAAudAwECfyMAQRBrIgMkACABIAEtAJAB\
IgRqQQBBkAEgBGsQlAEhBCABQQA6AJABIARBAToAACABIAEtAI8BQYABcjoAjwEgACAAKQMAIAEpAA\
CFNwMAIAAgACkDCCABKQAIhTcDCCAAIAApAxAgASkAEIU3AxAgACAAKQMYIAEpABiFNwMYIAAgACkD\
ICABKQAghTcDICAAIAApAyggASkAKIU3AyggACAAKQMwIAEpADCFNwMwIAAgACkDOCABKQA4hTcDOC\
AAIAApA0AgASkAQIU3A0AgACAAKQNIIAEpAEiFNwNIIAAgACkDUCABKQBQhTcDUCAAIAApA1ggASkA\
WIU3A1ggACAAKQNgIAEpAGCFNwNgIAAgACkDaCABKQBohTcDaCAAIAApA3AgASkAcIU3A3AgACAAKQ\
N4IAEpAHiFNwN4IAAgACkDgAEgASkAgAGFNwOAASAAIAApA4gBIAEpAIgBhTcDiAEgABAlIAIgACkD\
ADcAACACIAApAwg3AAggAiAAKQMQNwAQIAIgACkDGD4AGCADQRBqJAALnQMBAn8jAEEQayIDJAAgAS\
ABLQCQASIEakEAQZABIARrEJQBIQQgAUEAOgCQASAEQQY6AAAgASABLQCPAUGAAXI6AI8BIAAgACkD\
ACABKQAAhTcDACAAIAApAwggASkACIU3AwggACAAKQMQIAEpABCFNwMQIAAgACkDGCABKQAYhTcDGC\
AAIAApAyAgASkAIIU3AyAgACAAKQMoIAEpACiFNwMoIAAgACkDMCABKQAwhTcDMCAAIAApAzggASkA\
OIU3AzggACAAKQNAIAEpAECFNwNAIAAgACkDSCABKQBIhTcDSCAAIAApA1AgASkAUIU3A1AgACAAKQ\
NYIAEpAFiFNwNYIAAgACkDYCABKQBghTcDYCAAIAApA2ggASkAaIU3A2ggACAAKQNwIAEpAHCFNwNw\
IAAgACkDeCABKQB4hTcDeCAAIAApA4ABIAEpAIABhTcDgAEgACAAKQOIASABKQCIAYU3A4gBIAAQJS\
ACIAApAwA3AAAgAiAAKQMINwAIIAIgACkDEDcAECACIAApAxg+ABggA0EQaiQAC5YDAQR/IwBBkARr\
IgMkAAJAIAJFDQAgAkGoAWwhBCADQeACakEEciEFIANBsAFqIANBsAFqQQRyIgZBf3NqQawBakEHSR\
oDQCAAKAIAIQIgA0EANgKwASAGQQBBqAEQlAEaIANBqAE2ArABIANB4AJqIANBsAFqQawBEJUBGiAD\
QQhqIAVBqAEQlQEaIAMgAikDADcDCCADIAIpAwg3AxAgAyACKQMQNwMYIAMgAikDGDcDICADIAIpAy\
A3AyggAyACKQMoNwMwIAMgAikDMDcDOCADIAIpAzg3A0AgAyACKQNANwNIIAMgAikDSDcDUCADIAIp\
A1A3A1ggAyACKQNYNwNgIAMgAikDYDcDaCADIAIpA2g3A3AgAyACKQNwNwN4IAMgAikDeDcDgAEgAy\
ACKQOAATcDiAEgAyACKQOIATcDkAEgAyACKQOQATcDmAEgAyACKQOYATcDoAEgAyACKQOgATcDqAEg\
AhAlIAEgA0EIakGoARCVARogAUGoAWohASAEQdh+aiIEDQALCyADQZAEaiQAC/oCAQJ/IwBBkAFrIg\
AkAAJAQegAEBkiAUUNACAAQQxqQgA3AgAgAEEUakIANwIAIABBHGpCADcCACAAQSRqQgA3AgAgAEEs\
akIANwIAIABBNGpCADcCACAAQTxqQgA3AgAgAEIANwIEIABBADYCACAAIABBBHJBf3NqQcQAakEHSR\
ogAEHAADYCACAAQcgAaiAAQcQAEJUBGiABQdgAaiAAQcgAakE8aikCADcAACABQdAAaiAAQcgAakE0\
aikCADcAACABQcgAaiAAQcgAakEsaikCADcAACABQcAAaiAAQcgAakEkaikCADcAACABQThqIABByA\
BqQRxqKQIANwAAIAFBMGogAEHIAGpBFGopAgA3AAAgAUEoaiAAQcgAakEMaikCADcAACABIAApAkw3\
ACAgAUHww8uefDYCGCABQv6568XpjpWZEDcDECABQoHGlLqW8ermbzcDCCABQgA3AwAgAUHgAGpBAD\
oAACAAQZABaiQAIAEPCwAL5AIBBH8jAEGQBGsiAyQAIAMgADYCBCAAQcgBaiEEAkACQAJAAkACQCAA\
QfACai0AACIFRQ0AQagBIAVrIgYgAksNASABIAQgBWogBhCVASAGaiEBIAIgBmshAgsgAiACQagBbi\
IGQagBbCIFSQ0BIANBBGogASAGEDoCQCACIAVrIgINAEEAIQIMBAsgA0EANgKwASADQbABaiADQbAB\
akEEckEAQagBEJQBQX9zakGsAWpBB0kaIANBqAE2ArABIANB4AJqIANBsAFqQawBEJUBGiADQQhqIA\
NB4AJqQQRyQagBEJUBGiADQQRqIANBCGpBARA6IAJBqQFPDQIgASAFaiADQQhqIAIQlQEaIAQgA0EI\
akGoARCVARoMAwsgASAEIAVqIAIQlQEaIAUgAmohAgwCC0HAjMAAQSNBoIzAABBzAAsgAkGoAUGwjM\
AAEIwBAAsgACACOgDwAiADQZAEaiQAC+QCAQR/IwBBsANrIgMkACADIAA2AgQgAEHIAWohBAJAAkAC\
QAJAAkAgAEHQAmotAAAiBUUNAEGIASAFayIGIAJLDQEgASAEIAVqIAYQlQEgBmohASACIAZrIQILIA\
IgAkGIAW4iBkGIAWwiBUkNASADQQRqIAEgBhBDAkAgAiAFayICDQBBACECDAQLIANBADYCkAEgA0GQ\
AWogA0GQAWpBBHJBAEGIARCUAUF/c2pBjAFqQQdJGiADQYgBNgKQASADQaACaiADQZABakGMARCVAR\
ogA0EIaiADQaACakEEckGIARCVARogA0EEaiADQQhqQQEQQyACQYkBTw0CIAEgBWogA0EIaiACEJUB\
GiAEIANBCGpBiAEQlQEaDAMLIAEgBCAFaiACEJUBGiAFIAJqIQIMAgtBwIzAAEEjQaCMwAAQcwALIA\
JBiAFBsIzAABCMAQALIAAgAjoA0AIgA0GwA2okAAuRAwEBfwJAIAJFDQAgASACQagBbGohAyAAKAIA\
IQIDQCACIAIpAwAgASkAAIU3AwAgAiACKQMIIAEpAAiFNwMIIAIgAikDECABKQAQhTcDECACIAIpAx\
ggASkAGIU3AxggAiACKQMgIAEpACCFNwMgIAIgAikDKCABKQAohTcDKCACIAIpAzAgASkAMIU3AzAg\
AiACKQM4IAEpADiFNwM4IAIgAikDQCABKQBAhTcDQCACIAIpA0ggASkASIU3A0ggAiACKQNQIAEpAF\
CFNwNQIAIgAikDWCABKQBYhTcDWCACIAIpA2AgASkAYIU3A2AgAiACKQNoIAEpAGiFNwNoIAIgAikD\
cCABKQBwhTcDcCACIAIpA3ggASkAeIU3A3ggAiACKQOAASABKQCAAYU3A4ABIAIgAikDiAEgASkAiA\
GFNwOIASACIAIpA5ABIAEpAJABhTcDkAEgAiACKQOYASABKQCYAYU3A5gBIAIgAikDoAEgASkAoAGF\
NwOgASACECUgAUGoAWoiASADRw0ACwsL7gIBAn8jAEGQAWsiACQAAkBB4AAQGSIBRQ0AIABBDGpCAD\
cCACAAQRRqQgA3AgAgAEEcakIANwIAIABBJGpCADcCACAAQSxqQgA3AgAgAEE0akIANwIAIABBPGpC\
ADcCACAAQgA3AgQgAEEANgIAIAAgAEEEckF/c2pBxABqQQdJGiAAQcAANgIAIABByABqIABBxAAQlQ\
EaIAFB0ABqIABByABqQTxqKQIANwAAIAFByABqIABByABqQTRqKQIANwAAIAFBwABqIABByABqQSxq\
KQIANwAAIAFBOGogAEHIAGpBJGopAgA3AAAgAUEwaiAAQcgAakEcaikCADcAACABQShqIABByABqQR\
RqKQIANwAAIAFBIGogAEHIAGpBDGopAgA3AAAgASAAKQJMNwAYIAFC/rnrxemOlZkQNwMQIAFCgcaU\
upbx6uZvNwMIIAFCADcDACABQdgAakEAOgAAIABBkAFqJAAgAQ8LAAu8AgEIfwJAAkAgAkEPSw0AIA\
AhAwwBCyAAQQAgAGtBA3EiBGohBQJAIARFDQAgACEDIAEhBgNAIAMgBi0AADoAACAGQQFqIQYgA0EB\
aiIDIAVJDQALCyAFIAIgBGsiB0F8cSIIaiEDAkACQCABIARqIglBA3EiBkUNACAIQQFIDQEgCUF8cS\
IKQQRqIQFBACAGQQN0IgJrQRhxIQQgCigCACEGA0AgBSAGIAJ2IAEoAgAiBiAEdHI2AgAgAUEEaiEB\
IAVBBGoiBSADSQ0ADAILCyAIQQFIDQAgCSEBA0AgBSABKAIANgIAIAFBBGohASAFQQRqIgUgA0kNAA\
sLIAdBA3EhAiAJIAhqIQELAkAgAkUNACADIAJqIQUDQCADIAEtAAA6AAAgAUEBaiEBIANBAWoiAyAF\
SQ0ACwsgAAv6AgEBfyABIAEtAIgBIgNqQQBBiAEgA2sQlAEhAyABQQA6AIgBIANBAToAACABIAEtAI\
cBQYABcjoAhwEgACAAKQMAIAEpAACFNwMAIAAgACkDCCABKQAIhTcDCCAAIAApAxAgASkAEIU3AxAg\
ACAAKQMYIAEpABiFNwMYIAAgACkDICABKQAghTcDICAAIAApAyggASkAKIU3AyggACAAKQMwIAEpAD\
CFNwMwIAAgACkDOCABKQA4hTcDOCAAIAApA0AgASkAQIU3A0AgACAAKQNIIAEpAEiFNwNIIAAgACkD\
UCABKQBQhTcDUCAAIAApA1ggASkAWIU3A1ggACAAKQNgIAEpAGCFNwNgIAAgACkDaCABKQBohTcDaC\
AAIAApA3AgASkAcIU3A3AgACAAKQN4IAEpAHiFNwN4IAAgACkDgAEgASkAgAGFNwOAASAAECUgAiAA\
KQMANwAAIAIgACkDCDcACCACIAApAxA3ABAgAiAAKQMYNwAYC/oCAQF/IAEgAS0AiAEiA2pBAEGIAS\
ADaxCUASEDIAFBADoAiAEgA0EGOgAAIAEgAS0AhwFBgAFyOgCHASAAIAApAwAgASkAAIU3AwAgACAA\
KQMIIAEpAAiFNwMIIAAgACkDECABKQAQhTcDECAAIAApAxggASkAGIU3AxggACAAKQMgIAEpACCFNw\
MgIAAgACkDKCABKQAohTcDKCAAIAApAzAgASkAMIU3AzAgACAAKQM4IAEpADiFNwM4IAAgACkDQCAB\
KQBAhTcDQCAAIAApA0ggASkASIU3A0ggACAAKQNQIAEpAFCFNwNQIAAgACkDWCABKQBYhTcDWCAAIA\
ApA2AgASkAYIU3A2AgACAAKQNoIAEpAGiFNwNoIAAgACkDcCABKQBwhTcDcCAAIAApA3ggASkAeIU3\
A3ggACAAKQOAASABKQCAAYU3A4ABIAAQJSACIAApAwA3AAAgAiAAKQMINwAIIAIgACkDEDcAECACIA\
ApAxg3ABgL5gIBBH8jAEGwA2siAyQAAkAgAkUNACACQYgBbCEEIANBoAJqQQRyIQUgA0GQAWogA0GQ\
AWpBBHIiBkF/c2pBjAFqQQdJGgNAIAAoAgAhAiADQQA2ApABIAZBAEGIARCUARogA0GIATYCkAEgA0\
GgAmogA0GQAWpBjAEQlQEaIANBCGogBUGIARCVARogAyACKQMANwMIIAMgAikDCDcDECADIAIpAxA3\
AxggAyACKQMYNwMgIAMgAikDIDcDKCADIAIpAyg3AzAgAyACKQMwNwM4IAMgAikDODcDQCADIAIpA0\
A3A0ggAyACKQNINwNQIAMgAikDUDcDWCADIAIpA1g3A2AgAyACKQNgNwNoIAMgAikDaDcDcCADIAIp\
A3A3A3ggAyACKQN4NwOAASADIAIpA4ABNwOIASACECUgASADQQhqQYgBEJUBGiABQYgBaiEBIARB+H\
5qIgQNAAsLIANBsANqJAAL2AIBAX8CQCACRQ0AIAEgAkGQAWxqIQMgACgCACECA0AgAiACKQMAIAEp\
AACFNwMAIAIgAikDCCABKQAIhTcDCCACIAIpAxAgASkAEIU3AxAgAiACKQMYIAEpABiFNwMYIAIgAi\
kDICABKQAghTcDICACIAIpAyggASkAKIU3AyggAiACKQMwIAEpADCFNwMwIAIgAikDOCABKQA4hTcD\
OCACIAIpA0AgASkAQIU3A0AgAiACKQNIIAEpAEiFNwNIIAIgAikDUCABKQBQhTcDUCACIAIpA1ggAS\
kAWIU3A1ggAiACKQNgIAEpAGCFNwNgIAIgAikDaCABKQBohTcDaCACIAIpA3AgASkAcIU3A3AgAiAC\
KQN4IAEpAHiFNwN4IAIgAikDgAEgASkAgAGFNwOAASACIAIpA4gBIAEpAIgBhTcDiAEgAhAlIAFBkA\
FqIgEgA0cNAAsLC90CAQF/IAIgAi0AiAEiA2pBAEGIASADaxCUASEDIAJBADoAiAEgA0EfOgAAIAIg\
Ai0AhwFBgAFyOgCHASABIAEpAwAgAikAAIU3AwAgASABKQMIIAIpAAiFNwMIIAEgASkDECACKQAQhT\
cDECABIAEpAxggAikAGIU3AxggASABKQMgIAIpACCFNwMgIAEgASkDKCACKQAohTcDKCABIAEpAzAg\
AikAMIU3AzAgASABKQM4IAIpADiFNwM4IAEgASkDQCACKQBAhTcDQCABIAEpA0ggAikASIU3A0ggAS\
ABKQNQIAIpAFCFNwNQIAEgASkDWCACKQBYhTcDWCABIAEpA2AgAikAYIU3A2AgASABKQNoIAIpAGiF\
NwNoIAEgASkDcCACKQBwhTcDcCABIAEpA3ggAikAeIU3A3ggASABKQOAASACKQCAAYU3A4ABIAEQJS\
AAIAFByAEQlQEaC7MCAQR/QR8hAgJAIAFB////B0sNACABQQYgAUEIdmciAmt2QQFxIAJBAXRrQT5q\
IQILIABCADcCECAAIAI2AhwgAkECdEHU1MAAaiEDAkACQAJAAkACQEEAKALI0kAiBEEBIAJ0IgVxRQ\
0AIAMoAgAiBCgCBEF4cSABRw0BIAQhAgwCC0EAIAQgBXI2AsjSQCADIAA2AgAgACADNgIYDAMLIAFB\
AEEZIAJBAXZrQR9xIAJBH0YbdCEDA0AgBCADQR12QQRxakEQaiIFKAIAIgJFDQIgA0EBdCEDIAIhBC\
ACKAIEQXhxIAFHDQALCyACKAIIIgMgADYCDCACIAA2AgggAEEANgIYIAAgAjYCDCAAIAM2AggPCyAF\
IAA2AgAgACAENgIYCyAAIAA2AgwgACAANgIIC7oCAQV/IAAoAhghAQJAAkACQCAAKAIMIgIgAEcNAC\
AAQRRBECAAQRRqIgIoAgAiAxtqKAIAIgQNAUEAIQIMAgsgACgCCCIEIAI2AgwgAiAENgIIDAELIAIg\
AEEQaiADGyEDA0AgAyEFAkAgBCICQRRqIgMoAgAiBA0AIAJBEGohAyACKAIQIQQLIAQNAAsgBUEANg\
IACwJAIAFFDQACQAJAIAAoAhxBAnRB1NTAAGoiBCgCACAARg0AIAFBEEEUIAEoAhAgAEYbaiACNgIA\
IAINAQwCCyAEIAI2AgAgAg0AQQBBACgCyNJAQX4gACgCHHdxNgLI0kAPCyACIAE2AhgCQCAAKAIQIg\
RFDQAgAiAENgIQIAQgAjYCGAsgAEEUaigCACIERQ0AIAJBFGogBDYCACAEIAI2AhgPCwvFAgEBfwJA\
IAJFDQAgASACQYgBbGohAyAAKAIAIQIDQCACIAIpAwAgASkAAIU3AwAgAiACKQMIIAEpAAiFNwMIIA\
IgAikDECABKQAQhTcDECACIAIpAxggASkAGIU3AxggAiACKQMgIAEpACCFNwMgIAIgAikDKCABKQAo\
hTcDKCACIAIpAzAgASkAMIU3AzAgAiACKQM4IAEpADiFNwM4IAIgAikDQCABKQBAhTcDQCACIAIpA0\
ggASkASIU3A0ggAiACKQNQIAEpAFCFNwNQIAIgAikDWCABKQBYhTcDWCACIAIpA2AgASkAYIU3A2Ag\
AiACKQNoIAEpAGiFNwNoIAIgAikDcCABKQBwhTcDcCACIAIpA3ggASkAeIU3A3ggAiACKQOAASABKQ\
CAAYU3A4ABIAIQJSABQYgBaiIBIANHDQALCwvHAgEBfyABIAEtAGgiA2pBAEHoACADaxCUASEDIAFB\
ADoAaCADQQE6AAAgASABLQBnQYABcjoAZyAAIAApAwAgASkAAIU3AwAgACAAKQMIIAEpAAiFNwMIIA\
AgACkDECABKQAQhTcDECAAIAApAxggASkAGIU3AxggACAAKQMgIAEpACCFNwMgIAAgACkDKCABKQAo\
hTcDKCAAIAApAzAgASkAMIU3AzAgACAAKQM4IAEpADiFNwM4IAAgACkDQCABKQBAhTcDQCAAIAApA0\
ggASkASIU3A0ggACAAKQNQIAEpAFCFNwNQIAAgACkDWCABKQBYhTcDWCAAIAApA2AgASkAYIU3A2Ag\
ABAlIAIgACkDADcAACACIAApAwg3AAggAiAAKQMQNwAQIAIgACkDGDcAGCACIAApAyA3ACAgAiAAKQ\
MoNwAoC8cCAQF/IAEgAS0AaCIDakEAQegAIANrEJQBIQMgAUEAOgBoIANBBjoAACABIAEtAGdBgAFy\
OgBnIAAgACkDACABKQAAhTcDACAAIAApAwggASkACIU3AwggACAAKQMQIAEpABCFNwMQIAAgACkDGC\
ABKQAYhTcDGCAAIAApAyAgASkAIIU3AyAgACAAKQMoIAEpACiFNwMoIAAgACkDMCABKQAwhTcDMCAA\
IAApAzggASkAOIU3AzggACAAKQNAIAEpAECFNwNAIAAgACkDSCABKQBIhTcDSCAAIAApA1AgASkAUI\
U3A1AgACAAKQNYIAEpAFiFNwNYIAAgACkDYCABKQBghTcDYCAAECUgAiAAKQMANwAAIAIgACkDCDcA\
CCACIAApAxA3ABAgAiAAKQMYNwAYIAIgACkDIDcAICACIAApAyg3ACgLmwIBAX8gASABLQBIIgNqQQ\
BByAAgA2sQlAEhAyABQQA6AEggA0EBOgAAIAEgAS0AR0GAAXI6AEcgACAAKQMAIAEpAACFNwMAIAAg\
ACkDCCABKQAIhTcDCCAAIAApAxAgASkAEIU3AxAgACAAKQMYIAEpABiFNwMYIAAgACkDICABKQAghT\
cDICAAIAApAyggASkAKIU3AyggACAAKQMwIAEpADCFNwMwIAAgACkDOCABKQA4hTcDOCAAIAApA0Ag\
ASkAQIU3A0AgABAlIAIgACkDADcAACACIAApAwg3AAggAiAAKQMQNwAQIAIgACkDGDcAGCACIAApAy\
A3ACAgAiAAKQMoNwAoIAIgACkDMDcAMCACIAApAzg3ADgLmwIBAX8gASABLQBIIgNqQQBByAAgA2sQ\
lAEhAyABQQA6AEggA0EGOgAAIAEgAS0AR0GAAXI6AEcgACAAKQMAIAEpAACFNwMAIAAgACkDCCABKQ\
AIhTcDCCAAIAApAxAgASkAEIU3AxAgACAAKQMYIAEpABiFNwMYIAAgACkDICABKQAghTcDICAAIAAp\
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\
ACABECJBBCEBDAELIAEgBUECdBAmIgFFDQILIAAgBTYCBCAAIAE2AgAgBkEQaiQADwtBwI7AAEEwEJ\
MBAAsAC4MBAQF/IwBBEGsiBSQAIAUgASACIAMgBBAOIAVBCGooAgAhBCAFKAIEIQMCQAJAIAUoAgAN\
ACAAIAQ2AgQgACADNgIADAELIAMgBBAAIQQgAEEANgIAIAAgBDYCBAsCQCABQQVHDQAgAigCkAFFDQ\
AgAkEANgKQAQsgAhAiIAVBEGokAAt+AQF/IwBBwABrIgQkACAEQSs2AgwgBCAANgIIIAQgAjYCFCAE\
IAE2AhAgBEEsakECNgIAIARBPGpBATYCACAEQgI3AhwgBEG8iMAANgIYIARBAjYCNCAEIARBMGo2Ai\
ggBCAEQRBqNgI4IAQgBEEIajYCMCAEQRhqIAMQeAALdQECfyMAQZACayICJABBACEDIAJBADYCAANA\
IAIgA2pBBGogASADaigAADYCACACIANBBGoiAzYCACADQYABRw0ACyACQYgBaiACQYQBEJUBGiAAIA\
JBiAFqQQRyQYABEJUBIAEtAIABOgCAASACQZACaiQAC3UBAn8jAEGwAmsiAiQAQQAhAyACQQA2AgAD\
QCACIANqQQRqIAEgA2ooAAA2AgAgAiADQQRqIgM2AgAgA0GQAUcNAAsgAkGYAWogAkGUARCVARogAC\
ACQZgBakEEckGQARCVASABLQCQAToAkAEgAkGwAmokAAt1AQJ/IwBBoAJrIgIkAEEAIQMgAkEANgIA\
A0AgAiADakEEaiABIANqKAAANgIAIAIgA0EEaiIDNgIAIANBiAFHDQALIAJBkAFqIAJBjAEQlQEaIA\
AgAkGQAWpBBHJBiAEQlQEgAS0AiAE6AIgBIAJBoAJqJAALcwECfyMAQeABayICJABBACEDIAJBADYC\
AANAIAIgA2pBBGogASADaigAADYCACACIANBBGoiAzYCACADQegARw0ACyACQfAAaiACQewAEJUBGi\
AAIAJB8ABqQQRyQegAEJUBIAEtAGg6AGggAkHgAWokAAtzAQJ/IwBBoAFrIgIkAEEAIQMgAkEANgIA\
A0AgAiADakEEaiABIANqKAAANgIAIAIgA0EEaiIDNgIAIANByABHDQALIAJB0ABqIAJBzAAQlQEaIA\
AgAkHQAGpBBHJByAAQlQEgAS0ASDoASCACQaABaiQAC3UBAn8jAEHgAmsiAiQAQQAhAyACQQA2AgAD\
QCACIANqQQRqIAEgA2ooAAA2AgAgAiADQQRqIgM2AgAgA0GoAUcNAAsgAkGwAWogAkGsARCVARogAC\
ACQbABakEEckGoARCVASABLQCoAToAqAEgAkHgAmokAAt7AQJ/IwBBMGsiAiQAIAJBFGpBAjYCACAC\
QdyHwAA2AhAgAkECNgIMIAJBvIfAADYCCCABQRxqKAIAIQMgASgCGCEBIAJBAjYCLCACQgI3AhwgAk\
G8iMAANgIYIAIgAkEIajYCKCABIAMgAkEYahArIQEgAkEwaiQAIAELewECfyMAQTBrIgIkACACQRRq\
QQI2AgAgAkHch8AANgIQIAJBAjYCDCACQbyHwAA2AgggAUEcaigCACEDIAEoAhghASACQQI2AiwgAk\
ICNwIcIAJBvIjAADYCGCACIAJBCGo2AiggASADIAJBGGoQKyEBIAJBMGokACABC2wBAX8jAEEwayID\
JAAgAyABNgIEIAMgADYCACADQRxqQQI2AgAgA0EsakEDNgIAIANCAzcCDCADQbiLwAA2AgggA0EDNg\
IkIAMgA0EgajYCGCADIAM2AiggAyADQQRqNgIgIANBCGogAhB4AAtsAQF/IwBBMGsiAyQAIAMgATYC\
BCADIAA2AgAgA0EcakECNgIAIANBLGpBAzYCACADQgI3AgwgA0GYiMAANgIIIANBAzYCJCADIANBIG\
o2AhggAyADNgIoIAMgA0EEajYCICADQQhqIAIQeAALbAEBfyMAQTBrIgMkACADIAE2AgQgAyAANgIA\
IANBHGpBAjYCACADQSxqQQM2AgAgA0ICNwIMIANByIrAADYCCCADQQM2AiQgAyADQSBqNgIYIAMgA0\
EEajYCKCADIAM2AiAgA0EIaiACEHgAC2wBAX8jAEEwayIDJAAgAyABNgIEIAMgADYCACADQRxqQQI2\
AgAgA0EsakEDNgIAIANCAjcCDCADQeiKwAA2AgggA0EDNgIkIAMgA0EgajYCGCADIANBBGo2AiggAy\
ADNgIgIANBCGogAhB4AAtXAQJ/AkACQCAARQ0AIAAoAgANASAAQQA2AgAgACgCCCEBIAAoAgQhAiAA\
ECICQCACQQVHDQAgASgCkAFFDQAgAUEANgKQAQsgARAiDwsQkQEACxCSAQALWAECf0EAQQAoAsDSQC\
IBQQFqNgLA0kBBAEEAKAKI1kBBAWoiAjYCiNZAAkAgAUEASA0AIAJBAksNAEEAKAK80kBBf0wNACAC\
QQFLDQAgAEUNABCYAQALAAtKAQN/QQAhAwJAIAJFDQACQANAIAAtAAAiBCABLQAAIgVHDQEgAEEBai\
EAIAFBAWohASACQX9qIgJFDQIMAAsLIAQgBWshAwsgAwtGAAJAAkAgAUUNACABKAIADQEgAUF/NgIA\
IAFBBGooAgAgAUEIaigCACACEFAgAUEANgIAIABCADcDAA8LEJEBAAsQkgEAC0cBAX8jAEEgayIDJA\
AgA0EUakEANgIAIANBsJDAADYCECADQgE3AgQgAyABNgIcIAMgADYCGCADIANBGGo2AgAgAyACEHgA\
C4sBACAAQgA3A0AgAEL5wvibkaOz8NsANwM4IABC6/qG2r+19sEfNwMwIABCn9j52cKR2oKbfzcDKC\
AAQtGFmu/6z5SH0QA3AyAgAELx7fT4paf9p6V/NwMYIABCq/DT9K/uvLc8NwMQIABCu86qptjQ67O7\
fzcDCCAAIAGtQoiS95X/zPmE6gCFNwMAC0UBAn8jAEEQayIBJAACQCAAKAIIIgINAEGwkMAAQStB+J\
DAABBzAAsgASAAKAIMNgIIIAEgADYCBCABIAI2AgAgARB8AAtCAQF/AkACQAJAIAJBgIDEAEYNAEEB\
IQQgACACIAEoAhARBgANAQsgAw0BQQAhBAsgBA8LIAAgA0EAIAEoAgwRCAALPwEBfyMAQSBrIgAkAC\
AAQRxqQQA2AgAgAEGwkMAANgIYIABCATcCDCAAQaCCwAA2AgggAEEIakGogsAAEHgACz4BAX8jAEEg\
ayICJAAgAkEBOgAYIAIgATYCFCACIAA2AhAgAkGoiMAANgIMIAJBsJDAADYCCCACQQhqEHUACz0BAn\
8gACgCACIBQRRqKAIAIQICQAJAIAEoAgQOAgAAAQsgAg0AIAAoAgQtABAQcAALIAAoAgQtABAQcAAL\
MwACQCAAQfz///8HSw0AAkAgAA0AQQQPCyAAIABB/f///wdJQQJ0EDEiAEUNACAADwsAC1IAIABCx8\
yj2NbQ67O7fzcDCCAAQgA3AwAgAEEgakKrs4/8kaOz8NsANwMAIABBGGpC/6S5iMWR2oKbfzcDACAA\
QRBqQvLmu+Ojp/2npX83AwALLAEBfyMAQRBrIgEkACABQQhqIABBCGooAgA2AgAgASAAKQIANwMAIA\
EQeQALJgACQCAADQBBwI7AAEEwEJMBAAsgACACIAMgBCAFIAEoAhARDAALJAACQCAADQBBwI7AAEEw\
EJMBAAsgACACIAMgBCABKAIQEQoACyQAAkAgAA0AQcCOwABBMBCTAQALIAAgAiADIAQgASgCEBEJAA\
skAAJAIAANAEHAjsAAQTAQkwEACyAAIAIgAyAEIAEoAhARCgALJAACQCAADQBBwI7AAEEwEJMBAAsg\
ACACIAMgBCABKAIQEQkACyQAAkAgAA0AQcCOwABBMBCTAQALIAAgAiADIAQgASgCEBEJAAskAAJAIA\
ANAEHAjsAAQTAQkwEACyAAIAIgAyAEIAEoAhARFwALJAACQCAADQBBwI7AAEEwEJMBAAsgACACIAMg\
BCABKAIQERgACyQAAkAgAA0AQcCOwABBMBCTAQALIAAgAiADIAQgASgCEBEWAAsiAAJAIAANAEHAjs\
AAQTAQkwEACyAAIAIgAyABKAIQEQcACyAAAkACQCABQfz///8HSw0AIAAgAhAmIgENAQsACyABCyAA\
AkAgAA0AQcCOwABBMBCTAQALIAAgAiABKAIQEQYACxQAIAAoAgAgASAAKAIEKAIMEQYACxAAIAEgAC\
gCACAAKAIEEBwLDgACQCABRQ0AIAAQIgsLCwAgACABIAIQbgALCwAgACABIAIQbQALEQBBuILAAEEv\
QbiDwAAQcwALDQAgACgCABoDfwwACwsLACAAIwBqJAAjAAsNAEHQ0cAAQRsQkwEACw4AQevRwABBzw\
AQkwEACwkAIAAgARALAAsKACAAIAEgAhBTCwoAIAAgASACEEALCgAgACABIAIQcQsMAEK4ic+XicbR\
+EwLAwAACwIACwvE0oCAAAEAQYCAwAALulLQBRAAUAAAAJUAAAAJAAAAQkxBS0UyQkJMQUtFMkItMj\
I0QkxBS0UyQi0yNTZCTEFLRTJCLTM4NEJMQUtFMlNCTEFLRTNLRUNDQUstMjI0S0VDQ0FLLTI1NktF\
Q0NBSy0zODRLRUNDQUstNTEyTUQ0TUQ1UklQRU1ELTE2MFNIQS0xU0hBLTIyNFNIQS0yNTZTSEEtMz\
g0U0hBLTUxMlRJR0VSdW5zdXBwb3J0ZWQgYWxnb3JpdGhtbm9uLWRlZmF1bHQgbGVuZ3RoIHNwZWNp\
ZmllZCBmb3Igbm9uLWV4dGVuZGFibGUgYWxnb3JpdGhtbGlicmFyeS9hbGxvYy9zcmMvcmF3X3ZlYy\
5yc2NhcGFjaXR5IG92ZXJmbG93AAANARAAEQAAAPEAEAAcAAAABgIAAAUAAABBcnJheVZlYzogY2Fw\
YWNpdHkgZXhjZWVkZWQgaW4gZXh0ZW5kL2Zyb21faXRlcn4vLmNhcmdvL3JlZ2lzdHJ5L3NyYy9naX\
RodWIuY29tLTFlY2M2Mjk5ZGI5ZWM4MjMvYXJyYXl2ZWMtMC43LjIvc3JjL2FycmF5dmVjLnJzAGcB\
EABQAAAAAQQAAAUAAAB+Ly5jYXJnby9yZWdpc3RyeS9zcmMvZ2l0aHViLmNvbS0xZWNjNjI5OWRiOW\
VjODIzL2JsYWtlMy0xLjMuMS9zcmMvbGliLnJzAAAAyAEQAEkAAAC5AQAACQAAAMgBEABJAAAAXwIA\
AAoAAADIARAASQAAAI0CAAAJAAAAyAEQAEkAAACNAgAANAAAAMgBEABJAAAAuQIAAB8AAADIARAASQ\
AAAN0CAAAKAAAAyAEQAEkAAADWAgAACQAAAMgBEABJAAAAAQMAABkAAADIARAASQAAAAMDAAAJAAAA\
yAEQAEkAAAADAwAAOAAAAMgBEABJAAAA+AMAAB4AAADIARAASQAAAKoEAAAWAAAAyAEQAEkAAAC8BA\
AAFgAAAMgBEABJAAAA7QQAABIAAADIARAASQAAAPcEAAASAAAAyAEQAEkAAABpBQAAIQAAABEAAAAE\
AAAABAAAABIAAAB+Ly5jYXJnby9yZWdpc3RyeS9zcmMvZ2l0aHViLmNvbS0xZWNjNjI5OWRiOWVjOD\
IzL2FycmF5dmVjLTAuNy4yL3NyYy9hcnJheXZlY19pbXBsLnJzAAAAJAMQAFUAAAAnAAAACQAAABEA\
AAAEAAAABAAAABIAAAARAAAAIAAAAAEAAAATAAAAQ2FwYWNpdHlFcnJvcgAAAKwDEAANAAAAaW5zdW\
ZmaWNpZW50IGNhcGFjaXR5AAAAxAMQABUAAAApaW5kZXggb3V0IG9mIGJvdW5kczogdGhlIGxlbiBp\
cyAgYnV0IHRoZSBpbmRleCBpcyAA5QMQACAAAAAFBBAAEgAAABEAAAAAAAAAAQAAABQAAAA6IAAAMA\
gQAAAAAAA4BBAAAgAAADAwMDEwMjAzMDQwNTA2MDcwODA5MTAxMTEyMTMxNDE1MTYxNzE4MTkyMDIx\
MjIyMzI0MjUyNjI3MjgyOTMwMzEzMjMzMzQzNTM2MzczODM5NDA0MTQyNDM0NDQ1NDY0NzQ4NDk1MD\
UxNTI1MzU0NTU1NjU3NTg1OTYwNjE2MjYzNjQ2NTY2Njc2ODY5NzA3MTcyNzM3NDc1NzY3Nzc4Nzk4\
MDgxODI4Mzg0ODU4Njg3ODg4OTkwOTE5MjkzOTQ5NTk2OTc5ODk5cmFuZ2Ugc3RhcnQgaW5kZXggIG\
91dCBvZiByYW5nZSBmb3Igc2xpY2Ugb2YgbGVuZ3RoIBQFEAASAAAAJgUQACIAAAByYW5nZSBlbmQg\
aW5kZXggWAUQABAAAAAmBRAAIgAAAHNvdXJjZSBzbGljZSBsZW5ndGggKCkgZG9lcyBub3QgbWF0Y2\
ggZGVzdGluYXRpb24gc2xpY2UgbGVuZ3RoICh4BRAAFQAAAI0FEAArAAAA5AMQAAEAAAB+Ly5jYXJn\
by9yZWdpc3RyeS9zcmMvZ2l0aHViLmNvbS0xZWNjNjI5OWRiOWVjODIzL2Jsb2NrLWJ1ZmZlci0wLj\
EwLjAvc3JjL2xpYi5yc9AFEABQAAAAPwEAAB4AAADQBRAAUAAAAPwAAAAnAAAAYXNzZXJ0aW9uIGZh\
aWxlZDogbWlkIDw9IHNlbGYubGVuKCkAAAAAAAEjRWeJq83v/ty6mHZUMhDw4dLDAAAAAGfmCWqFrm\
e7cvNuPDr1T6V/Ug5RjGgFm6vZgx8ZzeBb2J4FwQfVfDYX3XAwOVkO9zELwP8RFVhop4/5ZKRP+r4I\
ybzzZ+YJajunyoSFrme7K/iU/nLzbjzxNh1fOvVPpdGC5q1/Ug5RH2w+K4xoBZtrvUH7q9mDH3khfh\
MZzeBb2J4FwV2du8sH1Xw2KimaYhfdcDBaAVmROVkO99jsLxUxC8D/ZyYzZxEVWGiHSrSOp4/5ZA0u\
DNukT/q+HUi1R2Nsb3N1cmUgaW52b2tlZCByZWN1cnNpdmVseSBvciBkZXN0cm95ZWQgYWxyZWFkeQ\
EAAAAAAAAAgoAAAAAAAACKgAAAAAAAgACAAIAAAACAi4AAAAAAAAABAACAAAAAAIGAAIAAAACACYAA\
AAAAAICKAAAAAAAAAIgAAAAAAAAACYAAgAAAAAAKAACAAAAAAIuAAIAAAAAAiwAAAAAAAICJgAAAAA\
AAgAOAAAAAAACAAoAAAAAAAICAAAAAAAAAgAqAAAAAAAAACgAAgAAAAICBgACAAAAAgICAAAAAAACA\
AQAAgAAAAAAIgACAAAAAgGNhbGxlZCBgT3B0aW9uOjp1bndyYXAoKWAgb24gYSBgTm9uZWAgdmFsdW\
VsaWJyYXJ5L3N0ZC9zcmMvcGFuaWNraW5nLnJzAFsIEAAcAAAARwIAAA8AAABjYWxsZWQgYFJlc3Vs\
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\
9ZY43HWPsT2PY6qOgOmrjTU5n6xyC8CR+t63ki1JYv1BVWtbTS756N7GbX7qvsSrVz81zpBW2tZpV3\
OEFDlCpkojCp0N+CiAUPn2FfKzeqIZ47hNGjRREZytMQVY73ulIjx3M4aWBxpWx0U2vp0kntoT+WhM\
pnibLWXa7zTDO3+pJ0z0F2vmIBJidgt9zZqJQ3eWgmft4Mpb7vP8ecgANnWfQLZtkrU5mtAGiMV6Mb\
Cug28hHziGSsrmASUwn9FiNP9m+zv93SR8IHLr4uzi07b2St4I6se+TZmcxIuasJflrEm6lwfPZkeM\
s3UqfMVzkxsTWB6TYc4sgrEMHLoJuVV1ndIRfZPdr38S5JJtxq072im87MJUcdXBoiT+9oJNE8VYTy\
diW1HjOhwmgcsBLsgH6ct/4xMZCe34yUYAyPnYSTJj+4jj7ZvPgJ7xbBGaU4EYVyTVa/fzA1Go90eu\
9ea3Fc+cftTextfbGrsoAkFc5USZTtteJdRHtjD8qrgriBFdKiHTKbuLCfWzlgLpFOq1j1oC3VchlH\
tntayQo8DnWPsBSr2DTGfTiTu580vfpC2eKUirjDIexPxSLFi6lozzA7Jd2H+9vdHKg66CYMFCtLuw\
mtqla+hfuT+pcTdnBC6y2FIxSclYU4QeVLSXhkgqvmZpjtMt3KKVK4U8kqwRLMB7qPINmbGII743Tx\
v6CIB8A+VUTcjQcB/UV85+7K2QVDo6BtknPCsAv6IwgISjrn7AAyDtbTICxoZAqWl9KKeDinr1MMtf\
esV55+t55ERotem83AUPtHOj4g5XiG54Gteg9ui9zbqchy+jZMG80WqXi9dmll7iIas8w+XlqmMQkJ\
CNaUhEsxiYu4oePq6HZOO03DuJMfm9rxnVu1/coEVjymWUmyb+KIbsUZw/YAFdHrdJUKEGQORNsct2\
9+VwbL/tK1Xv8hgSQaM2WnAIBwzLRGCYT3UUTecOKKgOQ9lWzWVQX1PXkSXBlu8KcvEjMsgfpWNzbz\
mgw251bGwgcG9pbnRlciBwYXNzZWQgdG8gcnVzdHJlY3Vyc2l2ZSB1c2Ugb2YgYW4gb2JqZWN0IGRl\
dGVjdGVkIHdoaWNoIHdvdWxkIGxlYWQgdG8gdW5zYWZlIGFsaWFzaW5nIGluIHJ1c3QAttCAgAAEbm\
FtZQGr0ICAAJoBAEVqc19zeXM6OlR5cGVFcnJvcjo6bmV3OjpfX3diZ19uZXdfZGIyNTRhZTBhMWJi\
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
9zdGRfd2FzbV9jcnlwdG86OmRpZ2VzdDo6Q29udGV4dDo6ZGlnZXN0OjpoMGZkNzY4MDY4OThmNjM5\
Nw0sc2hhMjo6c2hhNTEyOjpjb21wcmVzczUxMjo6aDgwYjZjM2U0MjZhMGQ1ZjMOSmRlbm9fc3RkX3\
dhc21fY3J5cHRvOjpkaWdlc3Q6OkNvbnRleHQ6OmRpZ2VzdF9hbmRfcmVzZXQ6Omg2OTAzZDQxYWVk\
Yjc2ZDQ2DyxzaGEyOjpzaGEyNTY6OmNvbXByZXNzMjU2OjpoMDIxMDEwM2M3YjNkYzIyORATZGlnZX\
N0Y29udGV4dF9jbG9uZRFAZGVub19zdGRfd2FzbV9jcnlwdG86OmRpZ2VzdDo6Q29udGV4dDo6dXBk\
YXRlOjpoOGMwN2Y3YmEwMDA1YWYwNBIzYmxha2UyOjpCbGFrZTJiVmFyQ29yZTo6Y29tcHJlc3M6Om\
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
cwZWQfL2JsYWtlMzo6SGFzaGVyOjpmaW5hbGl6ZV94b2Y6Omg1YzQ3NGJhNjI1NWZhOTU5IBNkaWdl\
c3Rjb250ZXh0X3Jlc2V0IT1kZW5vX3N0ZF93YXNtX2NyeXB0bzo6ZGlnZXN0OjpDb250ZXh0OjpuZX\
c6Omg2YWExMzU3YWVjN2E0NmIxIjhkbG1hbGxvYzo6ZGxtYWxsb2M6OkRsbWFsbG9jPEE+OjpmcmVl\
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
N5czo6VWludDhBcnJheTo6dG9fdmVjOjpoNTExZmY3NDM1NTJhYmYyM15MPGFsbG9jOjpib3hlZDo6\
Qm94PFQ+IGFzIGNvcmU6OmRlZmF1bHQ6OkRlZmF1bHQ+OjpkZWZhdWx0OjpoNTZkNzZlNmVlMGNmMT\
EzMF8bZGlnZXN0Y29udGV4dF9kaWdlc3RBbmREcm9wYD93YXNtX2JpbmRnZW46OmNvbnZlcnQ6OmNs\
b3N1cmVzOjppbnZva2UzX211dDo6aDZmNWY3MDU3OTQ0NDg2MmVhR2Rlbm9fc3RkX3dhc21fY3J5cH\
RvOjpEaWdlc3RDb250ZXh0OjpkaWdlc3RfYW5kX2Ryb3A6OmgwYzhjZmNhY2I4NzM4NjI1Yi5jb3Jl\
OjpyZXN1bHQ6OnVud3JhcF9mYWlsZWQ6OmgyZGM3MDZkOTQ4YzIyOTYwY1s8YmxvY2tfYnVmZmVyOj\
pCbG9ja0J1ZmZlcjxCbG9ja1NpemUsS2luZD4gYXMgY29yZTo6Y2xvbmU6OkNsb25lPjo6Y2xvbmU6\
OmhhMzcwZGU5ZWU0OTc3OTY5ZFs8YmxvY2tfYnVmZmVyOjpCbG9ja0J1ZmZlcjxCbG9ja1NpemUsS2\
luZD4gYXMgY29yZTo6Y2xvbmU6OkNsb25lPjo6Y2xvbmU6OmhlMDUyZDMyZmZhZjY1MDY1ZVs8Ymxv\
Y2tfYnVmZmVyOjpCbG9ja0J1ZmZlcjxCbG9ja1NpemUsS2luZD4gYXMgY29yZTo6Y2xvbmU6OkNsb2\
5lPjo6Y2xvbmU6OmgwNGU2Y2JjMjYxODU2NjVmZls8YmxvY2tfYnVmZmVyOjpCbG9ja0J1ZmZlcjxC\
bG9ja1NpemUsS2luZD4gYXMgY29yZTo6Y2xvbmU6OkNsb25lPjo6Y2xvbmU6OmgyZjA2OWU0MTM4Y2\
Q1NzVkZ1s8YmxvY2tfYnVmZmVyOjpCbG9ja0J1ZmZlcjxCbG9ja1NpemUsS2luZD4gYXMgY29yZTo6\
Y2xvbmU6OkNsb25lPjo6Y2xvbmU6Omg2MDNjOWFlZTQwMzkxY2I5aFs8YmxvY2tfYnVmZmVyOjpCbG\
9ja0J1ZmZlcjxCbG9ja1NpemUsS2luZD4gYXMgY29yZTo6Y2xvbmU6OkNsb25lPjo6Y2xvbmU6Omgy\
N2ZjNWY5N2EyNjUwM2E0aVA8YXJyYXl2ZWM6OmVycm9yczo6Q2FwYWNpdHlFcnJvcjxUPiBhcyBjb3\
JlOjpmbXQ6OkRlYnVnPjo6Zm10OjpoMmFhYjQ0MTQ3MWIxNTBmNmpQPGFycmF5dmVjOjplcnJvcnM6\
OkNhcGFjaXR5RXJyb3I8VD4gYXMgY29yZTo6Zm10OjpEZWJ1Zz46OmZtdDo6aDk1YTdhNTAyYjFmND\
kxMTNrTmNvcmU6OnNsaWNlOjo8aW1wbCBbVF0+Ojpjb3B5X2Zyb21fc2xpY2U6Omxlbl9taXNtYXRj\
aF9mYWlsOjpoZjNiYmFiYzAyMDQ4NjRiY2w2Y29yZTo6cGFuaWNraW5nOjpwYW5pY19ib3VuZHNfY2\
hlY2s6OmgxZmI3YTZkZjEwMzMxMjc5bURjb3JlOjpzbGljZTo6aW5kZXg6OnNsaWNlX3N0YXJ0X2lu\
ZGV4X2xlbl9mYWlsX3J0OjpoYjMxN2NhODMzMjA0NjVhNm5CY29yZTo6c2xpY2U6OmluZGV4OjpzbG\
ljZV9lbmRfaW5kZXhfbGVuX2ZhaWxfcnQ6OmhmY2Y5M2RkMzVmMDExMmJkbxhfX3diZ19kaWdlc3Rj\
b250ZXh0X2ZyZWVwN3N0ZDo6cGFuaWNraW5nOjpydXN0X3BhbmljX3dpdGhfaG9vazo6aDcwYTBlMT\
k1ZjRkYjJhMjlxMWNvbXBpbGVyX2J1aWx0aW5zOjptZW06Om1lbWNtcDo6aDEyODViODQxMjBkZjVk\
Y2RyFGRpZ2VzdGNvbnRleHRfdXBkYXRlcyljb3JlOjpwYW5pY2tpbmc6OnBhbmljOjpoOGFmMDQ2Mz\
k3YTJiZjY1ZHQ6Ymxha2UyOjpCbGFrZTJiVmFyQ29yZTo6bmV3X3dpdGhfcGFyYW1zOjpoZmU3YThi\
OTZmMTJiYjNlZHURcnVzdF9iZWdpbl91bndpbmR2Q2NvcmU6OmZtdDo6Rm9ybWF0dGVyOjpwYWRfaW\
50ZWdyYWw6OndyaXRlX3ByZWZpeDo6aDYwYjFiNTAzZTY2ZjMyYjF3NGFsbG9jOjpyYXdfdmVjOjpj\
YXBhY2l0eV9vdmVyZmxvdzo6aDRiMjc1Y2IzYzEwYjBhNzh4LWNvcmU6OnBhbmlja2luZzo6cGFuaW\
NfZm10OjpoNzUxYmU4MDc3OWQ0MmI1M3lDc3RkOjpwYW5pY2tpbmc6OmJlZ2luX3BhbmljX2hhbmRs\
ZXI6Ont7Y2xvc3VyZX19OjpoZGNmYzgxOWNlODM2ODI5ZXoRX193YmluZGdlbl9tYWxsb2N7OmJsYW\
tlMjo6Qmxha2Uyc1ZhckNvcmU6Om5ld193aXRoX3BhcmFtczo6aDdkODRlMGQyN2JiNzFmYWF8SXN0\
ZDo6c3lzX2NvbW1vbjo6YmFja3RyYWNlOjpfX3J1c3RfZW5kX3Nob3J0X2JhY2t0cmFjZTo6aDUzY2\
FiYWZhYjViMDlhZGF9P3dhc21fYmluZGdlbjo6Y29udmVydDo6Y2xvc3VyZXM6Omludm9rZTRfbXV0\
OjpoMjVkYWUzZDIwMTM3NzFmNn4/d2FzbV9iaW5kZ2VuOjpjb252ZXJ0OjpjbG9zdXJlczo6aW52b2\
tlM19tdXQ6Omg5NDRjN2I1M2RkMDI5YmE1fz93YXNtX2JpbmRnZW46OmNvbnZlcnQ6OmNsb3N1cmVz\
OjppbnZva2UzX211dDo6aDEwMWI3OGEyODkzYzAxZTWAAT93YXNtX2JpbmRnZW46OmNvbnZlcnQ6Om\
Nsb3N1cmVzOjppbnZva2UzX211dDo6aDM4YWRlNGE4NThmNGRjNmSBAT93YXNtX2JpbmRnZW46OmNv\
bnZlcnQ6OmNsb3N1cmVzOjppbnZva2UzX211dDo6aDdkZmM4ODhmOGY5ZDM3YjaCAT93YXNtX2Jpbm\
RnZW46OmNvbnZlcnQ6OmNsb3N1cmVzOjppbnZva2UzX211dDo6aDA3ZjNlM2I2OWE5OTkyM2GDAT93\
YXNtX2JpbmRnZW46OmNvbnZlcnQ6OmNsb3N1cmVzOjppbnZva2UzX211dDo6aGI2ZDRkNzUxZTE2ZT\
I5ODCEAT93YXNtX2JpbmRnZW46OmNvbnZlcnQ6OmNsb3N1cmVzOjppbnZva2UzX211dDo6aDlhM2Qx\
NTUyMzVkY2QzZjeFAT93YXNtX2JpbmRnZW46OmNvbnZlcnQ6OmNsb3N1cmVzOjppbnZva2UzX211dD\
o6aGIwOWFiMmQ0MjdkMzBjNWKGAT93YXNtX2JpbmRnZW46OmNvbnZlcnQ6OmNsb3N1cmVzOjppbnZv\
a2UyX211dDo6aDQxMzc3NGY1ZjhkZGQyNDiHARJfX3diaW5kZ2VuX3JlYWxsb2OIAT93YXNtX2Jpbm\
RnZW46OmNvbnZlcnQ6OmNsb3N1cmVzOjppbnZva2UxX211dDo6aDk3NDUyYTI3NWRjMDY3YmaJATA8\
JlQgYXMgY29yZTo6Zm10OjpEZWJ1Zz46OmZtdDo6aGZmNGFmMWI0YTgxMzk5NmGKATI8JlQgYXMgY2\
9yZTo6Zm10OjpEaXNwbGF5Pjo6Zm10OjpoOWFkYTE1Y2ZhZTdmNDIxMosBD19fd2JpbmRnZW5fZnJl\
ZYwBP2NvcmU6OnNsaWNlOjppbmRleDo6c2xpY2VfZW5kX2luZGV4X2xlbl9mYWlsOjpoM2RiNDc2Yj\
BkMDk5OTRkMo0BQWNvcmU6OnNsaWNlOjppbmRleDo6c2xpY2Vfc3RhcnRfaW5kZXhfbGVuX2ZhaWw6\
OmgxMzZjY2FkNzY0MTM2ODEwjgEzYXJyYXl2ZWM6OmFycmF5dmVjOjpleHRlbmRfcGFuaWM6OmhkMj\
U4ZTA5N2FmNDdjNjdjjwE5Y29yZTo6b3BzOjpmdW5jdGlvbjo6Rm5PbmNlOjpjYWxsX29uY2U6Omhl\
MDIxZGJiZjZmYWFhMDZkkAEfX193YmluZGdlbl9hZGRfdG9fc3RhY2tfcG9pbnRlcpEBMXdhc21fYm\
luZGdlbjo6X19ydDo6dGhyb3dfbnVsbDo6aGY1MTcxZjBjZmY5YTE1MjGSATJ3YXNtX2JpbmRnZW46\
Ol9fcnQ6OmJvcnJvd19mYWlsOjpoOTRiZDgxZjkyOGIzODI5OJMBKndhc21fYmluZGdlbjo6dGhyb3\
dfc3RyOjpoMzBhYzBkOTY4ZWVkMjhkNJQBBm1lbXNldJUBBm1lbWNweZYBBm1lbWNtcJcBMTxUIGFz\
IGNvcmU6OmFueTo6QW55Pjo6dHlwZV9pZDo6aDEzYzc4NTk2Njg4ZjY3YjKYAQpydXN0X3BhbmljmQ\
FvY29yZTo6cHRyOjpkcm9wX2luX3BsYWNlPCZjb3JlOjppdGVyOjphZGFwdGVyczo6Y29waWVkOjpD\
b3BpZWQ8Y29yZTo6c2xpY2U6Oml0ZXI6Okl0ZXI8dTg+Pj46OmgwNWZhMGY5NzFiNDZiMGU3AO+AgI\
AACXByb2R1Y2VycwIIbGFuZ3VhZ2UBBFJ1c3QADHByb2Nlc3NlZC1ieQMFcnVzdGMdMS42NS4wICg4\
OTdlMzc1NTMgMjAyMi0xMS0wMikGd2FscnVzBjAuMTkuMAx3YXNtLWJpbmRnZW4GMC4yLjgz\
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
    "BLAKE2B-224",
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
function timingSafeEqual2(a, b) {
    if (a.byteLength !== b.byteLength) {
        return false;
    }
    if (!(a instanceof DataView)) {
        a = ArrayBuffer.isView(a) ? new DataView(a.buffer, a.byteOffset, a.byteLength) : new DataView(a);
    }
    if (!(b instanceof DataView)) {
        b = ArrayBuffer.isView(b) ? new DataView(b.buffer, b.byteOffset, b.byteLength) : new DataView(b);
    }
    assert2(a instanceof DataView);
    assert2(b instanceof DataView);
    const length = a.byteLength;
    let out = 0;
    let i = -1;
    while(++i < length){
        out |= a.getUint8(i) ^ b.getUint8(i);
    }
    return out === 0;
}
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
            const { name, length } = normalizeAlgorithm(algorithm);
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
        timingSafeEqual: timingSafeEqual2
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
const mod9 = {
    encode: encode3,
    decode: decode1
};
function convertBase64ToBase64url1(b64) {
    return b64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function encode4(data) {
    return convertBase64ToBase64url1(encode3(data));
}
const encoder7 = new TextEncoder();
function importKey1(key) {
    if (typeof key === "string") {
        key = encoder7.encode(key);
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
function sign1(data, key) {
    if (typeof data === "string") {
        data = encoder7.encode(data);
    } else if (Array.isArray(data)) {
        data = Uint8Array.from(data);
    }
    return crypto.subtle.sign("HMAC", key, data);
}
async function compare1(a, b) {
    const key = new Uint8Array(32);
    globalThis.crypto.getRandomValues(key);
    const cryptoKey = await importKey1(key);
    const ah = await sign1(a, cryptoKey);
    const bh = await sign1(b, cryptoKey);
    return timingSafeEqual2(ah, bh);
}
class KeyStack1 {
    #cryptoKeys = new Map();
    #keys;
    async #toCryptoKey(key) {
        if (!this.#cryptoKeys.has(key)) {
            this.#cryptoKeys.set(key, await importKey1(key));
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
        return encode4(await sign1(data, key));
    }
    async verify(data, digest) {
        return await this.indexOf(data, digest) > -1;
    }
    async indexOf(data, digest) {
        for(let i = 0; i < this.#keys.length; i++){
            const cryptoKey = await this.#toCryptoKey(this.#keys[i]);
            if (await compare1(digest, encode4(await sign1(data, cryptoKey)))) {
                return i;
            }
        }
        return -1;
    }
    [Symbol.for("Deno.customInspect")](inspect) {
        const { length } = this;
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
        const { length } = this;
        return `${options.stylize(this.constructor.name, "special")} ${inspect({
            length
        }, newOptions)}`;
    }
}
new TextEncoder().encode("0123456789abcdef");
new TextDecoder();
const base64abc3 = [
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
function encode5(data) {
    const uint8 = typeof data === "string" ? new TextEncoder().encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
    let result = "", i;
    const l = uint8.length;
    for(i = 2; i < l; i += 3){
        result += base64abc3[uint8[i - 2] >> 2];
        result += base64abc3[(uint8[i - 2] & 0x03) << 4 | uint8[i - 1] >> 4];
        result += base64abc3[(uint8[i - 1] & 0x0f) << 2 | uint8[i] >> 6];
        result += base64abc3[uint8[i] & 0x3f];
    }
    if (i === l + 1) {
        result += base64abc3[uint8[i - 2] >> 2];
        result += base64abc3[(uint8[i - 2] & 0x03) << 4];
        result += "==";
    }
    if (i === l) {
        result += base64abc3[uint8[i - 2] >> 2];
        result += base64abc3[(uint8[i - 2] & 0x03) << 4 | uint8[i - 1] >> 4];
        result += base64abc3[(uint8[i - 1] & 0x0f) << 2];
        result += "=";
    }
    return result;
}
function decode2(b64) {
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
function convertBase64ToBase64url2(b64) {
    return b64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function encode6(data) {
    return convertBase64ToBase64url2(encode5(data));
}
function decode3(b64url) {
    return decode2(convertBase64urlToBase64(b64url));
}
const mod10 = {
    encode: encode6,
    decode: decode3
};
const encoder8 = new TextEncoder();
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
    return isNull(key) ? signature.length === 0 : await crypto.subtle.verify(getAlgorithm(alg), key, signature, encoder8.encode(signingInput));
}
async function create(alg, key, signingInput) {
    return isNull(key) ? "" : mod10.encode(new Uint8Array(await crypto.subtle.sign(getAlgorithm(alg), key, encoder8.encode(signingInput))));
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
function validateTimingClaims(payload, { expLeeway = 1, nbfLeeway = 1 } = {}) {
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
function decode4(jwt) {
    try {
        const arr = jwt.split(".").map(mod10.decode).map((uint8Array, index)=>index === 0 || index === 1 ? JSON.parse(decoder3.decode(uint8Array)) : uint8Array);
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
    const { header, payload, signature } = validate(decode4(jwt), options);
    if (verify(header.alg, key)) {
        if (!await verify1(signature, key, header.alg, jwt.slice(0, jwt.lastIndexOf(".")))) {
            throw new Error("The jwt's signature does not match the verification signature.");
        }
        if (!(options?.predicates || []).every((predicate)=>predicate(payload))) {
            throw new Error("The payload does not satisfy all passed predicates.");
        }
        return payload;
    } else {
        throw new Error(`The jwt's alg '${header.alg}' does not match the key's algorithm.`);
    }
}
function createSigningInput(header, payload) {
    return `${mod10.encode(encoder8.encode(JSON.stringify(header)))}.${mod10.encode(encoder8.encode(JSON.stringify(payload)))}`;
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
const mod11 = {
    decode: decode4,
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
function assert3(expr, msg = "") {
    if (!expr) {
        throw new DenoStdInternalError1(msg);
    }
}
function copy2(src, dst, off = 0) {
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
    #tryGrowByReslice(n) {
        const l = this.#buf.byteLength;
        if (n <= this.capacity - l) {
            this.#reslice(l + n);
            return l;
        }
        return -1;
    }
    #reslice(len) {
        assert3(len <= this.#buf.buffer.byteLength);
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
        const nread = copy2(this.#buf.subarray(this.#off), p);
        this.#off += nread;
        return nread;
    }
    read(p) {
        const rr = this.readSync(p);
        return Promise.resolve(rr);
    }
    writeSync(p) {
        const m = this.#grow(p.byteLength);
        return copy2(p, this.#buf, m);
    }
    write(p) {
        const n = this.writeSync(p);
        return Promise.resolve(n);
    }
    #grow(n) {
        const m = this.length;
        if (m === 0 && this.#off !== 0) {
            this.reset();
        }
        const i = this.#tryGrowByReslice(n);
        if (i >= 0) {
            return i;
        }
        const c = this.capacity;
        if (n <= Math.floor(c / 2) - m) {
            copy2(this.#buf.subarray(this.#off), this.#buf);
        } else if (c + n > MAX_SIZE2) {
            throw new Error("The buffer cannot be grown beyond the maximum size.");
        } else {
            const buf = new Uint8Array(Math.min(2 * c + n, MAX_SIZE2));
            copy2(this.#buf.subarray(this.#off), buf);
            this.#buf = buf;
        }
        this.#off = 0;
        this.#reslice(Math.min(m + n, MAX_SIZE2));
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
            const { value, done } = await iterator.next();
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
const mod12 = {
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
    constructor({ client, bucketName, objectName, partSize, metadata }){
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
async function completeMultipartUpload({ client, bucketName, objectName, uploadId, etags }) {
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
    async makeRequest({ method, payload, ...options }) {
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
    async getPartialObject(objectName, { offset, length, ...options }) {
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
const mod13 = {
    S3Client: Client,
    S3Errors: mod12
};
const osType1 = (()=>{
    const { Deno: Deno1 } = globalThis;
    if (typeof Deno1?.build?.os === "string") {
        return Deno1.build.os;
    }
    const { navigator } = globalThis;
    if (navigator?.appVersion?.includes?.("Win")) {
        return "windows";
    }
    return "linux";
})();
const isWindows1 = osType1 === "windows";
const CHAR_FORWARD_SLASH1 = 47;
function assertPath1(path) {
    if (typeof path !== "string") {
        throw new TypeError(`Path must be a string. Received ${JSON.stringify(path)}`);
    }
}
function isPosixPathSeparator1(code) {
    return code === 47;
}
function isPathSeparator1(code) {
    return isPosixPathSeparator1(code) || code === 92;
}
function isWindowsDeviceRoot1(code) {
    return code >= 97 && code <= 122 || code >= 65 && code <= 90;
}
function normalizeString1(path, allowAboveRoot, separator, isPathSeparator) {
    let res = "";
    let lastSegmentLength = 0;
    let lastSlash = -1;
    let dots = 0;
    let code;
    for(let i = 0, len = path.length; i <= len; ++i){
        if (i < len) code = path.charCodeAt(i);
        else if (isPathSeparator(code)) break;
        else code = CHAR_FORWARD_SLASH1;
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
function stripTrailingSeparators1(segment, isSep) {
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
function assertArg(path) {
    assertPath1(path);
    if (path.length === 0) return ".";
}
function posixNormalize(path) {
    assertArg(path);
    const isAbsolute = isPosixPathSeparator1(path.charCodeAt(0));
    const trailingSeparator = isPosixPathSeparator1(path.charCodeAt(path.length - 1));
    path = normalizeString1(path, !isAbsolute, "/", isPosixPathSeparator1);
    if (path.length === 0 && !isAbsolute) path = ".";
    if (path.length > 0 && trailingSeparator) path += "/";
    if (isAbsolute) return `/${path}`;
    return path;
}
function windowsNormalize(path) {
    assertArg(path);
    const len = path.length;
    let rootEnd = 0;
    let device;
    let isAbsolute = false;
    const code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator1(code)) {
            isAbsolute = true;
            if (isPathSeparator1(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator1(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    const firstPart = path.slice(last, j);
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator1(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator1(path.charCodeAt(j))) break;
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
        } else if (isWindowsDeviceRoot1(code)) {
            if (path.charCodeAt(1) === 58) {
                device = path.slice(0, 2);
                rootEnd = 2;
                if (len > 2) {
                    if (isPathSeparator1(path.charCodeAt(2))) {
                        isAbsolute = true;
                        rootEnd = 3;
                    }
                }
            }
        }
    } else if (isPathSeparator1(code)) {
        return "\\";
    }
    let tail;
    if (rootEnd < len) {
        tail = normalizeString1(path.slice(rootEnd), !isAbsolute, "\\", isPathSeparator1);
    } else {
        tail = "";
    }
    if (tail.length === 0 && !isAbsolute) tail = ".";
    if (tail.length > 0 && isPathSeparator1(path.charCodeAt(len - 1))) {
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
function posixJoin(...paths) {
    if (paths.length === 0) return ".";
    let joined;
    for(let i = 0, len = paths.length; i < len; ++i){
        const path = paths[i];
        assertPath1(path);
        if (path.length > 0) {
            if (!joined) joined = path;
            else joined += `/${path}`;
        }
    }
    if (!joined) return ".";
    return posixNormalize(joined);
}
function windowsJoin(...paths) {
    if (paths.length === 0) return ".";
    let joined;
    let firstPart = null;
    for(let i = 0; i < paths.length; ++i){
        const path = paths[i];
        assertPath1(path);
        if (path.length > 0) {
            if (joined === undefined) joined = firstPart = path;
            else joined += `\\${path}`;
        }
    }
    if (joined === undefined) return ".";
    let needsReplace = true;
    let slashCount = 0;
    assert2(firstPart !== null);
    if (isPathSeparator1(firstPart.charCodeAt(0))) {
        ++slashCount;
        const firstLen = firstPart.length;
        if (firstLen > 1) {
            if (isPathSeparator1(firstPart.charCodeAt(1))) {
                ++slashCount;
                if (firstLen > 2) {
                    if (isPathSeparator1(firstPart.charCodeAt(2))) ++slashCount;
                    else {
                        needsReplace = false;
                    }
                }
            }
        }
    }
    if (needsReplace) {
        for(; slashCount < joined.length; ++slashCount){
            if (!isPathSeparator1(joined.charCodeAt(slashCount))) break;
        }
        if (slashCount >= 2) joined = `\\${joined.slice(slashCount)}`;
    }
    return windowsNormalize(joined);
}
function join4(...paths) {
    return isWindows1 ? windowsJoin(...paths) : posixJoin(...paths);
}
function posixResolve(...pathSegments) {
    let resolvedPath = "";
    let resolvedAbsolute = false;
    for(let i = pathSegments.length - 1; i >= -1 && !resolvedAbsolute; i--){
        let path;
        if (i >= 0) path = pathSegments[i];
        else {
            const { Deno: Deno1 } = globalThis;
            if (typeof Deno1?.cwd !== "function") {
                throw new TypeError("Resolved a relative path without a CWD.");
            }
            path = Deno1.cwd();
        }
        assertPath1(path);
        if (path.length === 0) {
            continue;
        }
        resolvedPath = `${path}/${resolvedPath}`;
        resolvedAbsolute = isPosixPathSeparator1(path.charCodeAt(0));
    }
    resolvedPath = normalizeString1(resolvedPath, !resolvedAbsolute, "/", isPosixPathSeparator1);
    if (resolvedAbsolute) {
        if (resolvedPath.length > 0) return `/${resolvedPath}`;
        else return "/";
    } else if (resolvedPath.length > 0) return resolvedPath;
    else return ".";
}
function windowsResolve(...pathSegments) {
    let resolvedDevice = "";
    let resolvedTail = "";
    let resolvedAbsolute = false;
    for(let i = pathSegments.length - 1; i >= -1; i--){
        let path;
        const { Deno: Deno1 } = globalThis;
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
        assertPath1(path);
        const len = path.length;
        if (len === 0) continue;
        let rootEnd = 0;
        let device = "";
        let isAbsolute = false;
        const code = path.charCodeAt(0);
        if (len > 1) {
            if (isPathSeparator1(code)) {
                isAbsolute = true;
                if (isPathSeparator1(path.charCodeAt(1))) {
                    let j = 2;
                    let last = j;
                    for(; j < len; ++j){
                        if (isPathSeparator1(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        const firstPart = path.slice(last, j);
                        last = j;
                        for(; j < len; ++j){
                            if (!isPathSeparator1(path.charCodeAt(j))) break;
                        }
                        if (j < len && j !== last) {
                            last = j;
                            for(; j < len; ++j){
                                if (isPathSeparator1(path.charCodeAt(j))) break;
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
            } else if (isWindowsDeviceRoot1(code)) {
                if (path.charCodeAt(1) === 58) {
                    device = path.slice(0, 2);
                    rootEnd = 2;
                    if (len > 2) {
                        if (isPathSeparator1(path.charCodeAt(2))) {
                            isAbsolute = true;
                            rootEnd = 3;
                        }
                    }
                }
            }
        } else if (isPathSeparator1(code)) {
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
    resolvedTail = normalizeString1(resolvedTail, !resolvedAbsolute, "\\", isPathSeparator1);
    return resolvedDevice + (resolvedAbsolute ? "\\" : "") + resolvedTail || ".";
}
function windowsIsAbsolute(path) {
    assertPath1(path);
    const len = path.length;
    if (len === 0) return false;
    const code = path.charCodeAt(0);
    if (isPathSeparator1(code)) {
        return true;
    } else if (isWindowsDeviceRoot1(code)) {
        if (len > 2 && path.charCodeAt(1) === 58) {
            if (isPathSeparator1(path.charCodeAt(2))) return true;
        }
    }
    return false;
}
function posixIsAbsolute(path) {
    assertPath1(path);
    return path.length > 0 && isPosixPathSeparator1(path.charCodeAt(0));
}
function assertArgs(from, to) {
    assertPath1(from);
    assertPath1(to);
    if (from === to) return "";
}
function posixRelative(from, to) {
    assertArgs(from, to);
    from = posixResolve(from);
    to = posixResolve(to);
    if (from === to) return "";
    let fromStart = 1;
    const fromEnd = from.length;
    for(; fromStart < fromEnd; ++fromStart){
        if (!isPosixPathSeparator1(from.charCodeAt(fromStart))) break;
    }
    const fromLen = fromEnd - fromStart;
    let toStart = 1;
    const toEnd = to.length;
    for(; toStart < toEnd; ++toStart){
        if (!isPosixPathSeparator1(to.charCodeAt(toStart))) break;
    }
    const toLen = toEnd - toStart;
    const length = fromLen < toLen ? fromLen : toLen;
    let lastCommonSep = -1;
    let i = 0;
    for(; i <= length; ++i){
        if (i === length) {
            if (toLen > length) {
                if (isPosixPathSeparator1(to.charCodeAt(toStart + i))) {
                    return to.slice(toStart + i + 1);
                } else if (i === 0) {
                    return to.slice(toStart + i);
                }
            } else if (fromLen > length) {
                if (isPosixPathSeparator1(from.charCodeAt(fromStart + i))) {
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
        else if (isPosixPathSeparator1(fromCode)) lastCommonSep = i;
    }
    let out = "";
    for(i = fromStart + lastCommonSep + 1; i <= fromEnd; ++i){
        if (i === fromEnd || isPosixPathSeparator1(from.charCodeAt(i))) {
            if (out.length === 0) out += "..";
            else out += "/..";
        }
    }
    if (out.length > 0) return out + to.slice(toStart + lastCommonSep);
    else {
        toStart += lastCommonSep;
        if (isPosixPathSeparator1(to.charCodeAt(toStart))) ++toStart;
        return to.slice(toStart);
    }
}
function windowsRelative(from, to) {
    assertArgs(from, to);
    const fromOrig = windowsResolve(from);
    const toOrig = windowsResolve(to);
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
function posixToNamespacedPath(path) {
    return path;
}
function windowsToNamespacedPath(path) {
    if (typeof path !== "string") return path;
    if (path.length === 0) return "";
    const resolvedPath = windowsResolve(path);
    if (resolvedPath.length >= 3) {
        if (resolvedPath.charCodeAt(0) === 92) {
            if (resolvedPath.charCodeAt(1) === 92) {
                const code = resolvedPath.charCodeAt(2);
                if (code !== 63 && code !== 46) {
                    return `\\\\?\\UNC\\${resolvedPath.slice(2)}`;
                }
            }
        } else if (isWindowsDeviceRoot1(resolvedPath.charCodeAt(0))) {
            if (resolvedPath.charCodeAt(1) === 58 && resolvedPath.charCodeAt(2) === 92) {
                return `\\\\?\\${resolvedPath}`;
            }
        }
    }
    return path;
}
function assertArg1(path) {
    assertPath1(path);
    if (path.length === 0) return ".";
}
function posixDirname(path) {
    assertArg1(path);
    let end = -1;
    let matchedNonSeparator = false;
    for(let i = path.length - 1; i >= 1; --i){
        if (isPosixPathSeparator1(path.charCodeAt(i))) {
            if (matchedNonSeparator) {
                end = i;
                break;
            }
        } else {
            matchedNonSeparator = true;
        }
    }
    if (end === -1) {
        return isPosixPathSeparator1(path.charCodeAt(0)) ? "/" : ".";
    }
    return stripTrailingSeparators1(path.slice(0, end), isPosixPathSeparator1);
}
function windowsDirname(path) {
    assertArg1(path);
    const len = path.length;
    let rootEnd = -1;
    let end = -1;
    let matchedSlash = true;
    let offset = 0;
    const code = path.charCodeAt(0);
    if (len > 1) {
        if (isPathSeparator1(code)) {
            rootEnd = offset = 1;
            if (isPathSeparator1(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator1(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator1(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator1(path.charCodeAt(j))) break;
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
        } else if (isWindowsDeviceRoot1(code)) {
            if (path.charCodeAt(1) === 58) {
                rootEnd = offset = 2;
                if (len > 2) {
                    if (isPathSeparator1(path.charCodeAt(2))) rootEnd = offset = 3;
                }
            }
        }
    } else if (isPathSeparator1(code)) {
        return path;
    }
    for(let i = len - 1; i >= offset; --i){
        if (isPathSeparator1(path.charCodeAt(i))) {
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
    return stripTrailingSeparators1(path.slice(0, end), isPosixPathSeparator1);
}
function stripSuffix1(name, suffix) {
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
function lastPathSegment1(path, isSep, start = 0) {
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
function assertArgs1(path, suffix) {
    assertPath1(path);
    if (path.length === 0) return path;
    if (typeof suffix !== "string") {
        throw new TypeError(`Suffix must be a string. Received ${JSON.stringify(suffix)}`);
    }
}
function posixBasename(path, suffix = "") {
    assertArgs1(path, suffix);
    const lastSegment = lastPathSegment1(path, isPosixPathSeparator1);
    const strippedSegment = stripTrailingSeparators1(lastSegment, isPosixPathSeparator1);
    return suffix ? stripSuffix1(strippedSegment, suffix) : strippedSegment;
}
function windowsBasename(path, suffix = "") {
    assertArgs1(path, suffix);
    let start = 0;
    if (path.length >= 2) {
        const drive = path.charCodeAt(0);
        if (isWindowsDeviceRoot1(drive)) {
            if (path.charCodeAt(1) === 58) start = 2;
        }
    }
    const lastSegment = lastPathSegment1(path, isPathSeparator1, start);
    const strippedSegment = stripTrailingSeparators1(lastSegment, isPathSeparator1);
    return suffix ? stripSuffix1(strippedSegment, suffix) : strippedSegment;
}
function posixExtname(path) {
    assertPath1(path);
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let preDotState = 0;
    for(let i = path.length - 1; i >= 0; --i){
        const code = path.charCodeAt(i);
        if (isPosixPathSeparator1(code)) {
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
function windowsExtname(path) {
    assertPath1(path);
    let start = 0;
    let startDot = -1;
    let startPart = 0;
    let end = -1;
    let matchedSlash = true;
    let preDotState = 0;
    if (path.length >= 2 && path.charCodeAt(1) === 58 && isWindowsDeviceRoot1(path.charCodeAt(0))) {
        start = startPart = 2;
    }
    for(let i = path.length - 1; i >= start; --i){
        const code = path.charCodeAt(i);
        if (isPathSeparator1(code)) {
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
function _format1(sep, pathObject) {
    const dir = pathObject.dir || pathObject.root;
    const base = pathObject.base || (pathObject.name || "") + (pathObject.ext || "");
    if (!dir) return base;
    if (base === sep) return dir;
    if (dir === pathObject.root) return dir + base;
    return dir + sep + base;
}
function assertArg2(pathObject) {
    if (pathObject === null || typeof pathObject !== "object") {
        throw new TypeError(`The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`);
    }
}
function posixFormat(pathObject) {
    assertArg2(pathObject);
    return _format1("/", pathObject);
}
function windowsFormat(pathObject) {
    assertArg2(pathObject);
    return _format1("\\", pathObject);
}
function posixParse(path) {
    assertPath1(path);
    const ret = {
        root: "",
        dir: "",
        base: "",
        ext: "",
        name: ""
    };
    if (path.length === 0) return ret;
    const isAbsolute = isPosixPathSeparator1(path.charCodeAt(0));
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
        if (isPosixPathSeparator1(code)) {
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
        ret.dir = stripTrailingSeparators1(path.slice(0, startPart - 1), isPosixPathSeparator1);
    } else if (isAbsolute) ret.dir = "/";
    return ret;
}
function windowsParse(path) {
    assertPath1(path);
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
        if (isPathSeparator1(code)) {
            rootEnd = 1;
            if (isPathSeparator1(path.charCodeAt(1))) {
                let j = 2;
                let last = j;
                for(; j < len; ++j){
                    if (isPathSeparator1(path.charCodeAt(j))) break;
                }
                if (j < len && j !== last) {
                    last = j;
                    for(; j < len; ++j){
                        if (!isPathSeparator1(path.charCodeAt(j))) break;
                    }
                    if (j < len && j !== last) {
                        last = j;
                        for(; j < len; ++j){
                            if (isPathSeparator1(path.charCodeAt(j))) break;
                        }
                        if (j === len) {
                            rootEnd = j;
                        } else if (j !== last) {
                            rootEnd = j + 1;
                        }
                    }
                }
            }
        } else if (isWindowsDeviceRoot1(code)) {
            if (path.charCodeAt(1) === 58) {
                rootEnd = 2;
                if (len > 2) {
                    if (isPathSeparator1(path.charCodeAt(2))) {
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
    } else if (isPathSeparator1(code)) {
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
        if (isPathSeparator1(code)) {
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
function assertArg3(url) {
    url = url instanceof URL ? url : new URL(url);
    if (url.protocol !== "file:") {
        throw new TypeError("Must be a file URL.");
    }
    return url;
}
function posixFromFileUrl(url) {
    url = assertArg3(url);
    return decodeURIComponent(url.pathname.replace(/%(?![0-9A-Fa-f]{2})/g, "%25"));
}
function windowsFromFileUrl(url) {
    url = assertArg3(url);
    let path = decodeURIComponent(url.pathname.replace(/\//g, "\\").replace(/%(?![0-9A-Fa-f]{2})/g, "%25")).replace(/^\\*([A-Za-z]:)(\\|$)/, "$1\\");
    if (url.hostname !== "") {
        path = `\\\\${url.hostname}${path}`;
    }
    return path;
}
const WHITESPACE_ENCODINGS1 = {
    "\u0009": "%09",
    "\u000A": "%0A",
    "\u000B": "%0B",
    "\u000C": "%0C",
    "\u000D": "%0D",
    "\u0020": "%20"
};
function encodeWhitespace1(string) {
    return string.replaceAll(/[\s]/g, (c)=>{
        return WHITESPACE_ENCODINGS1[c] ?? c;
    });
}
function posixToFileUrl(path) {
    if (!posixIsAbsolute(path)) {
        throw new TypeError("Must be an absolute path.");
    }
    const url = new URL("file:///");
    url.pathname = encodeWhitespace1(path.replace(/%/g, "%25").replace(/\\/g, "%5C"));
    return url;
}
function windowsToFileUrl(path) {
    if (!windowsIsAbsolute(path)) {
        throw new TypeError("Must be an absolute path.");
    }
    const [, hostname, pathname] = path.match(/^(?:[/\\]{2}([^/\\]+)(?=[/\\](?:[^/\\]|$)))?(.*)/);
    const url = new URL("file:///");
    url.pathname = encodeWhitespace1(pathname.replace(/%/g, "%25"));
    if (hostname !== undefined && hostname !== "localhost") {
        url.hostname = hostname;
        if (!url.hostname) {
            throw new TypeError("Invalid hostname.");
        }
    }
    return url;
}
const sep3 = "\\";
const delimiter3 = ";";
const mod14 = {
    resolve: windowsResolve,
    normalize: windowsNormalize,
    isAbsolute: windowsIsAbsolute,
    join: windowsJoin,
    relative: windowsRelative,
    toNamespacedPath: windowsToNamespacedPath,
    dirname: windowsDirname,
    basename: windowsBasename,
    extname: windowsExtname,
    format: windowsFormat,
    parse: windowsParse,
    fromFileUrl: windowsFromFileUrl,
    toFileUrl: windowsToFileUrl,
    sep: sep3,
    delimiter: delimiter3
};
const sep4 = "/";
const delimiter4 = ":";
const mod15 = {
    resolve: posixResolve,
    normalize: posixNormalize,
    isAbsolute: posixIsAbsolute,
    join: posixJoin,
    relative: posixRelative,
    toNamespacedPath: posixToNamespacedPath,
    dirname: posixDirname,
    basename: posixBasename,
    extname: posixExtname,
    format: posixFormat,
    parse: posixParse,
    fromFileUrl: posixFromFileUrl,
    toFileUrl: posixToFileUrl,
    sep: sep4,
    delimiter: delimiter4
};
function basename3(path, suffix = "") {
    return isWindows1 ? windowsBasename(path, suffix) : posixBasename(path, suffix);
}
function dirname3(path) {
    return isWindows1 ? windowsDirname(path) : posixDirname(path);
}
function fromFileUrl3(url) {
    return isWindows1 ? windowsFromFileUrl(url) : posixFromFileUrl(url);
}
function isAbsolute3(path) {
    return isWindows1 ? windowsIsAbsolute(path) : posixIsAbsolute(path);
}
function normalize5(path) {
    return isWindows1 ? windowsNormalize(path) : posixNormalize(path);
}
function resolve3(...pathSegments) {
    return isWindows1 ? windowsResolve(...pathSegments) : posixResolve(...pathSegments);
}
const SEP = isWindows1 ? "\\" : "/";
const SEP_PATTERN = isWindows1 ? /[\\/]+/ : /\/+/;
const path2 = isWindows1 ? mod14 : mod15;
const { join: join5, normalize: normalize6 } = path2;
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
function globToRegExp(glob, { extended = true, globstar: globstarOption = true, os = osType1, caseInsensitive = false } = {}) {
    if (glob === "") {
        return /(?!)/;
    }
    const sep = os === "windows" ? "(?:\\\\|/)+" : "/+";
    const sepMaybe = os === "windows" ? "(?:\\\\|/)*" : "/*";
    const seps = os === "windows" ? [
        "\\",
        "/"
    ] : [
        "/"
    ];
    const globstar = os === "windows" ? "(?:[^\\\\/]*(?:\\\\|/|$)+)*" : "(?:[^/]*(?:/|$)+)*";
    const wildcard = os === "windows" ? "[^\\\\/]*" : "[^/]*";
    const escapePrefix = os === "windows" ? "`" : "\\";
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
            if (glob[i] === escapePrefix) {
                inEscape = true;
                continue;
            }
            if (glob[i] === "[") {
                if (!inRange) {
                    inRange = true;
                    segment += "[";
                    if (glob[i + 1] === "!") {
                        i++;
                        segment += "^";
                    } else if (glob[i + 1] === "^") {
                        i++;
                        segment += "\\^";
                    }
                    continue;
                } else if (glob[i + 1] === ":") {
                    let k = i + 1;
                    let value = "";
                    while(glob[k + 1] !== undefined && glob[k + 1] !== ":"){
                        value += glob[k + 1];
                        k++;
                    }
                    if (glob[k + 1] === ":" && glob[k + 2] === "]") {
                        i = k + 2;
                        if (value === "alnum") segment += "\\dA-Za-z";
                        else if (value === "alpha") segment += "A-Za-z";
                        else if (value === "ascii") segment += "\x00-\x7F";
                        else if (value === "blank") segment += "\t ";
                        else if (value === "cntrl") segment += "\x00-\x1F\x7F";
                        else if (value === "digit") segment += "\\d";
                        else if (value === "graph") segment += "\x21-\x7E";
                        else if (value === "lower") segment += "a-z";
                        else if (value === "print") segment += "\x20-\x7E";
                        else if (value === "punct") {
                            segment += "!\"#$%&'()*+,\\-./:;<=>?@[\\\\\\]^_‘{|}~";
                        } else if (value === "space") segment += "\\s\v";
                        else if (value === "upper") segment += "A-Z";
                        else if (value === "word") segment += "\\w";
                        else if (value === "xdigit") segment += "\\dA-Fa-f";
                        continue;
                    }
                }
            }
            if (glob[i] === "]" && inRange) {
                inRange = false;
                segment += "]";
                continue;
            }
            if (inRange) {
                if (glob[i] === "\\") {
                    segment += `\\\\`;
                } else {
                    segment += glob[i];
                }
                continue;
            }
            if (glob[i] === ")" && groupStack.length > 0 && groupStack[groupStack.length - 1] !== "BRACE") {
                segment += ")";
                const type = groupStack.pop();
                if (type === "!") {
                    segment += wildcard;
                } else if (type !== "@") {
                    segment += type;
                }
                continue;
            }
            if (glob[i] === "|" && groupStack.length > 0 && groupStack[groupStack.length - 1] !== "BRACE") {
                segment += "|";
                continue;
            }
            if (glob[i] === "+" && extended && glob[i + 1] === "(") {
                i++;
                groupStack.push("+");
                segment += "(?:";
                continue;
            }
            if (glob[i] === "@" && extended && glob[i + 1] === "(") {
                i++;
                groupStack.push("@");
                segment += "(?:";
                continue;
            }
            if (glob[i] === "?") {
                if (extended && glob[i + 1] === "(") {
                    i++;
                    groupStack.push("?");
                    segment += "(?:";
                } else {
                    segment += ".";
                }
                continue;
            }
            if (glob[i] === "!" && extended && glob[i + 1] === "(") {
                i++;
                groupStack.push("!");
                segment += "(?!";
                continue;
            }
            if (glob[i] === "{") {
                groupStack.push("BRACE");
                segment += "(?:";
                continue;
            }
            if (glob[i] === "}" && groupStack[groupStack.length - 1] === "BRACE") {
                groupStack.pop();
                segment += ")";
                continue;
            }
            if (glob[i] === "," && groupStack[groupStack.length - 1] === "BRACE") {
                segment += "|";
                continue;
            }
            if (glob[i] === "*") {
                if (extended && glob[i + 1] === "(") {
                    i++;
                    groupStack.push("*");
                    segment += "(?:";
                } else {
                    const prevChar = glob[i - 1];
                    let numStars = 1;
                    while(glob[i + 1] === "*"){
                        i++;
                        numStars++;
                    }
                    const nextChar = glob[i + 1];
                    if (globstarOption && numStars === 2 && [
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
function normalizeGlob(glob, { globstar = false } = {}) {
    if (glob.match(/\0/g)) {
        throw new Error(`Glob contains invalid characters: "${glob}"`);
    }
    if (!globstar) {
        return normalize6(glob);
    }
    const s = SEP_PATTERN.source;
    const badParentPattern = new RegExp(`(?<=(${s}|^)\\*\\*${s})\\.\\.(?=${s}|$)`, "g");
    return normalize6(glob.replace(badParentPattern, "\0")).replace(/\0/g, "..");
}
function joinGlobs(globs, { extended = true, globstar = false } = {}) {
    if (!globstar || globs.length === 0) {
        return join5(...globs);
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
isWindows1 ? mod14.delimiter : mod15.delimiter;
function isSamePath(src, dest) {
    src = toPathString(src);
    dest = toPathString(dest);
    return resolve3(src) === resolve3(dest);
}
function isSubdir(src, dest, sep = SEP) {
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
    path = normalize5(path);
    const name = basename3(path);
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
    path = normalize5(path);
    const name = basename3(path);
    const info = await Deno.stat(path);
    return {
        path,
        name,
        isFile: info.isFile,
        isDirectory: info.isDirectory,
        isSymlink: info.isSymlink
    };
}
function toPathString(pathUrl) {
    return pathUrl instanceof URL ? fromFileUrl3(pathUrl) : pathUrl;
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
                const filepath = join4(toPathString(dir), item.name);
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
                const filepath = join4(toPathString(dir), item.name);
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
        await Deno.mkdir(dir, {
            recursive: true
        });
    } catch (err) {
        if (!(err instanceof Deno.errors.AlreadyExists)) {
            throw err;
        }
        const fileInfo = await Deno.lstat(dir);
        if (!fileInfo.isDirectory) {
            throw new Error(`Ensure path exists, expected 'dir', got '${getFileInfoType(fileInfo)}'`);
        }
    }
}
function ensureDirSync(dir) {
    try {
        Deno.mkdirSync(dir, {
            recursive: true
        });
    } catch (err) {
        if (!(err instanceof Deno.errors.AlreadyExists)) {
            throw err;
        }
        const fileInfo = Deno.lstatSync(dir);
        if (!fileInfo.isDirectory) {
            throw new Error(`Ensure path exists, expected 'dir', got '${getFileInfoType(fileInfo)}'`);
        }
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
            await ensureDir(dirname3(toPathString(filePath)));
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
            ensureDirSync(dirname3(toPathString(filePath)));
            Deno.writeFileSync(filePath, new Uint8Array());
            return;
        }
        throw err;
    }
}
async function ensureLink(src, dest) {
    dest = toPathString(dest);
    await ensureDir(dirname3(dest));
    await Deno.link(toPathString(src), dest);
}
function ensureLinkSync(src, dest) {
    dest = toPathString(dest);
    ensureDirSync(dirname3(dest));
    Deno.linkSync(toPathString(src), dest);
}
const isWindows2 = Deno.build.os === "windows";
function resolveSymlinkTarget(target, linkName) {
    if (typeof target !== "string") return target;
    if (typeof linkName === "string") {
        return resolve3(dirname3(linkName), target);
    } else {
        return new URL(target, linkName);
    }
}
async function ensureSymlink(target, linkName) {
    const targetRealPath = resolveSymlinkTarget(target, linkName);
    const srcStatInfo = await Deno.lstat(targetRealPath);
    const srcFilePathType = getFileInfoType(srcStatInfo);
    await ensureDir(dirname3(toPathString(linkName)));
    const options = isWindows2 ? {
        type: srcFilePathType === "dir" ? "dir" : "file"
    } : undefined;
    try {
        await Deno.symlink(target, linkName, options);
    } catch (error) {
        if (!(error instanceof Deno.errors.AlreadyExists)) {
            throw error;
        }
    }
}
function ensureSymlinkSync(target, linkName) {
    const targetRealPath = resolveSymlinkTarget(target, linkName);
    const srcStatInfo = Deno.lstatSync(targetRealPath);
    const srcFilePathType = getFileInfoType(srcStatInfo);
    ensureDirSync(dirname3(toPathString(linkName)));
    const options = isWindows2 ? {
        type: srcFilePathType === "dir" ? "dir" : "file"
    } : undefined;
    try {
        Deno.symlinkSync(target, linkName, options);
    } catch (error) {
        if (!(error instanceof Deno.errors.AlreadyExists)) {
            throw error;
        }
    }
}
class WalkError extends Error {
    cause;
    name = "WalkError";
    path;
    constructor(cause, path){
        super(`${cause instanceof Error ? cause.message : cause} for path "${path}"`);
        this.path = path;
        this.cause = cause;
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
function wrapErrorWithPath(err, root) {
    if (err instanceof WalkError) return err;
    return new WalkError(err, root);
}
async function* walk(root, { maxDepth = Infinity, includeFiles = true, includeDirs = true, includeSymlinks = true, followSymlinks = false, exts = undefined, match = undefined, skip = undefined } = {}) {
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
            let path = join4(root, entry.name);
            let { isSymlink, isDirectory } = entry;
            if (isSymlink) {
                if (!followSymlinks) {
                    if (includeSymlinks && include(path, exts, match, skip)) {
                        yield {
                            path,
                            ...entry
                        };
                    }
                    continue;
                }
                path = await Deno.realPath(path);
                ({ isSymlink, isDirectory } = await Deno.lstat(path));
            }
            if (isSymlink || isDirectory) {
                yield* walk(path, {
                    maxDepth: maxDepth - 1,
                    includeFiles,
                    includeDirs,
                    includeSymlinks,
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
        throw wrapErrorWithPath(err, normalize5(root));
    }
}
function* walkSync(root, { maxDepth = Infinity, includeFiles = true, includeDirs = true, includeSymlinks = true, followSymlinks = false, exts = undefined, match = undefined, skip = undefined } = {}) {
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
        throw wrapErrorWithPath(err, normalize5(root));
    }
    for (const entry of entries){
        let path = join4(root, entry.name);
        let { isSymlink, isDirectory } = entry;
        if (isSymlink) {
            if (!followSymlinks) {
                if (includeSymlinks && include(path, exts, match, skip)) {
                    yield {
                        path,
                        ...entry
                    };
                }
                continue;
            }
            path = Deno.realPathSync(path);
            ({ isSymlink, isDirectory } = Deno.lstatSync(path));
        }
        if (isSymlink || isDirectory) {
            yield* walkSync(path, {
                maxDepth: maxDepth - 1,
                includeFiles,
                includeDirs,
                includeSymlinks,
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
const isWindows3 = Deno.build.os === "windows";
function split(path) {
    const s = SEP_PATTERN.source;
    const segments = path.replace(new RegExp(`^${s}|${s}$`, "g"), "").split(SEP_PATTERN);
    const isAbsolute_ = isAbsolute3(path);
    return {
        segments,
        isAbsolute: isAbsolute_,
        hasTrailingSep: !!path.match(new RegExp(`${s}$`)),
        winRoot: isWindows3 && isAbsolute_ ? segments.shift() : undefined
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
async function* expandGlob(glob, { root = Deno.cwd(), exclude = [], includeDirs = true, extended = true, globstar = true, caseInsensitive, followSymlinks } = {}) {
    const globOptions = {
        extended,
        globstar,
        caseInsensitive
    };
    const absRoot = resolve3(root);
    const resolveFromRoot = (path)=>resolve3(absRoot, path);
    const excludePatterns = exclude.map(resolveFromRoot).map((s)=>globToRegExp(s, globOptions));
    const shouldInclude = (path)=>!excludePatterns.some((p)=>!!path.match(p));
    const { segments, isAbsolute: isGlobAbsolute, hasTrailingSep, winRoot } = split(toPathString(glob));
    let fixedRoot = isGlobAbsolute ? winRoot !== undefined ? winRoot : "/" : absRoot;
    while(segments.length > 0 && !isGlob(segments[0])){
        const seg = segments.shift();
        assert2(seg !== undefined);
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
        } else if (globSegment === "..") {
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
        } else if (globSegment === "**") {
            return yield* walk(walkInfo.path, {
                skip: excludePatterns,
                maxDepth: globstar ? Infinity : 1,
                followSymlinks
            });
        }
        const globPattern = globToRegExp(globSegment, globOptions);
        for await (const walkEntry of walk(walkInfo.path, {
            maxDepth: 1,
            skip: excludePatterns,
            followSymlinks
        })){
            if (walkEntry.path !== walkInfo.path && walkEntry.name.match(globPattern)) {
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
function* expandGlobSync(glob, { root = Deno.cwd(), exclude = [], includeDirs = true, extended = true, globstar = true, caseInsensitive, followSymlinks } = {}) {
    const globOptions = {
        extended,
        globstar,
        caseInsensitive
    };
    const absRoot = resolve3(root);
    const resolveFromRoot = (path)=>resolve3(absRoot, path);
    const excludePatterns = exclude.map(resolveFromRoot).map((s)=>globToRegExp(s, globOptions));
    const shouldInclude = (path)=>!excludePatterns.some((p)=>!!path.match(p));
    const { segments, isAbsolute: isGlobAbsolute, hasTrailingSep, winRoot } = split(toPathString(glob));
    let fixedRoot = isGlobAbsolute ? winRoot !== undefined ? winRoot : "/" : absRoot;
    while(segments.length > 0 && !isGlob(segments[0])){
        const seg = segments.shift();
        assert2(seg !== undefined);
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
        } else if (globSegment === "..") {
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
        } else if (globSegment === "**") {
            return yield* walkSync(walkInfo.path, {
                skip: excludePatterns,
                maxDepth: globstar ? Infinity : 1,
                followSymlinks
            });
        }
        const globPattern = globToRegExp(globSegment, globOptions);
        for (const walkEntry of walkSync(walkInfo.path, {
            maxDepth: 1,
            skip: excludePatterns,
            followSymlinks
        })){
            if (walkEntry.path !== walkInfo.path && walkEntry.name.match(globPattern)) {
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
class SubdirectoryMoveError extends Error {
    constructor(src, dest){
        super(`Cannot move '${src}' to a subdirectory of itself, '${dest}'.`);
    }
}
async function move(src, dest, { overwrite = false } = {}) {
    const srcStat = await Deno.stat(src);
    if (srcStat.isDirectory && (isSubdir(src, dest) || isSamePath(src, dest))) {
        throw new SubdirectoryMoveError(src, dest);
    }
    if (overwrite) {
        if (isSamePath(src, dest)) return;
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
function moveSync(src, dest, { overwrite = false } = {}) {
    const srcStat = Deno.statSync(src);
    if (srcStat.isDirectory && (isSubdir(src, dest) || isSamePath(src, dest))) {
        throw new SubdirectoryMoveError(src, dest);
    }
    if (overwrite) {
        if (isSamePath(src, dest)) return;
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
const isWindows4 = Deno.build.os === "windows";
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
        assert2(statInfo.atime instanceof Date, `statInfo.atime is unavailable`);
        assert2(statInfo.mtime instanceof Date, `statInfo.mtime is unavailable`);
        await Deno.utime(dest, statInfo.atime, statInfo.mtime);
    }
}
function copyFileSync(src, dest, options) {
    ensureValidCopySync(src, dest, options);
    Deno.copyFileSync(src, dest);
    if (options.preserveTimestamps) {
        const statInfo = Deno.statSync(src);
        assert2(statInfo.atime instanceof Date, `statInfo.atime is unavailable`);
        assert2(statInfo.mtime instanceof Date, `statInfo.mtime is unavailable`);
        Deno.utimeSync(dest, statInfo.atime, statInfo.mtime);
    }
}
async function copySymLink(src, dest, options) {
    await ensureValidCopy(src, dest, options);
    const originSrcFilePath = await Deno.readLink(src);
    const type = getFileInfoType(await Deno.lstat(src));
    if (isWindows4) {
        await Deno.symlink(originSrcFilePath, dest, {
            type: type === "dir" ? "dir" : "file"
        });
    } else {
        await Deno.symlink(originSrcFilePath, dest);
    }
    if (options.preserveTimestamps) {
        const statInfo = await Deno.lstat(src);
        assert2(statInfo.atime instanceof Date, `statInfo.atime is unavailable`);
        assert2(statInfo.mtime instanceof Date, `statInfo.mtime is unavailable`);
        await Deno.utime(dest, statInfo.atime, statInfo.mtime);
    }
}
function copySymlinkSync(src, dest, options) {
    ensureValidCopySync(src, dest, options);
    const originSrcFilePath = Deno.readLinkSync(src);
    const type = getFileInfoType(Deno.lstatSync(src));
    if (isWindows4) {
        Deno.symlinkSync(originSrcFilePath, dest, {
            type: type === "dir" ? "dir" : "file"
        });
    } else {
        Deno.symlinkSync(originSrcFilePath, dest);
    }
    if (options.preserveTimestamps) {
        const statInfo = Deno.lstatSync(src);
        assert2(statInfo.atime instanceof Date, `statInfo.atime is unavailable`);
        assert2(statInfo.mtime instanceof Date, `statInfo.mtime is unavailable`);
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
        assert2(srcStatInfo.atime instanceof Date, `statInfo.atime is unavailable`);
        assert2(srcStatInfo.mtime instanceof Date, `statInfo.mtime is unavailable`);
        await Deno.utime(dest, srcStatInfo.atime, srcStatInfo.mtime);
    }
    src = toPathString(src);
    dest = toPathString(dest);
    for await (const entry of Deno.readDir(src)){
        const srcPath = join4(src, entry.name);
        const destPath = join4(dest, basename3(srcPath));
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
        assert2(srcStatInfo.atime instanceof Date, `statInfo.atime is unavailable`);
        assert2(srcStatInfo.mtime instanceof Date, `statInfo.mtime is unavailable`);
        Deno.utimeSync(dest, srcStatInfo.atime, srcStatInfo.mtime);
    }
    src = toPathString(src);
    dest = toPathString(dest);
    for (const entry of Deno.readDirSync(src)){
        const srcPath = join4(src, entry.name);
        const destPath = join4(dest, basename3(srcPath));
        if (entry.isSymlink) {
            copySymlinkSync(srcPath, destPath, options);
        } else if (entry.isDirectory) {
            copyDirSync(srcPath, destPath, options);
        } else if (entry.isFile) {
            copyFileSync(srcPath, destPath, options);
        }
    }
}
async function copy3(src, dest, options = {}) {
    src = resolve3(toPathString(src));
    dest = resolve3(toPathString(dest));
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
    src = resolve3(toPathString(src));
    dest = resolve3(toPathString(dest));
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
const mod16 = {
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
    WalkError,
    walk,
    walkSync,
    SubdirectoryMoveError,
    move,
    moveSync,
    copy: copy3,
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
const { hasOwn } = Object;
function get(obj, key) {
    if (hasOwn(obj, key)) {
        return obj[key];
    }
}
function getForce(obj, key) {
    const v = get(obj, key);
    assert2(v !== undefined);
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
function parse6(args, { "--": doubleDash = false, alias = {}, boolean: __boolean = false, default: defaults = {}, stopEarly = false, string = [], collect = [], negatable = [], unknown = (i)=>i } = {}) {
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
            assert2(m !== null);
            const [, key, value] = m;
            if (flags.bools[key]) {
                const booleanValue = value !== "false";
                setArg(key, booleanValue, arg);
            } else {
                setArg(key, value, arg);
            }
        } else if (/^--no-.+/.test(arg) && get(flags.negatable, arg.replace(/^--no-/, ""))) {
            const m = arg.match(/^--no-(.+)/);
            assert2(m !== null);
            setArg(m[1], false, arg, false);
        } else if (/^--.+/.test(arg)) {
            const m = arg.match(/^--(.+)/);
            assert2(m !== null);
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
            setKey(argv, key, value, false);
            if (aliases[key]) {
                for (const x of aliases[key]){
                    setKey(argv, x, value, false);
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
const mod17 = {
    parse: parse6
};
const args = mod17.parse(Deno.args);
function getArg(name) {
    return args[name] || args[name.toLowerCase().replaceAll('_', '-')] || Deno.env.get('EDRYS_' + name);
}
const address = getArg('ADDRESS') ?? 'localhost:8000';
const secret = getArg('SECRET') ?? 'secret';
if (secret == 'secret') mod8.warning('For production, please specify a unique --secret to generate a secret private key. Currently using default.');
const totp_window = parseInt(getArg('TOTP_WINDOW'));
const serve_path = getArg('SERVE_PATH') ?? `dist/static`;
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
const readPermission = (await Deno.permissions.query({
    name: 'write'
})).state === 'granted';
const data_engine = getArg('DATA_ENGINE') ?? (readPermission ? 'file' : 'memory');
const data_file_path = getArg('DATA_FILE_PATH') ?? '.edrys';
const data_s3_endpoint = getArg('DATA_S3_ENDPOINT') ?? '';
const data_s3_port = Number(getArg('DATA_S3_PORT') ?? '443');
const data_s3_use_ssl = getArg('DATA_S3_USE_SSL') == 'true';
const data_s3_region = getArg('DATA_S3_REGION') ?? '';
const data_s3_access_key = getArg('DATA_S3_ACCESS_KEY') ?? '';
const data_s3_secret_key = getArg('DATA_S3_SECRET_KEY') ?? '';
const data_s3_bucket = getArg('DATA_S3_BUCKET') ?? '';
if (!getArg('DATA_ENGINE')) {
    if (readPermission) {
        mod8.debug('Undefined "DATA_ENGINE", setting storage to file.');
    } else {
        mod8.warning('Undefined "DATA_ENGINE" and no write access, setting storage to memory. Use this not in production, all states will be deleted after a reload.');
    }
}
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
let kv;
const inMemoryStorage = {};
switch(data_engine){
    case 's3':
        {
            if (data_s3_endpoint == '' || data_s3_port == 0 || data_s3_region == '' || data_s3_access_key == '' || data_s3_secret_key == '' || data_s3_bucket == '') {
                throw new Error('Invalid Data S3 config');
            }
            s3c = new mod13.S3Client({
                endPoint: data_s3_endpoint,
                port: data_s3_port,
                useSSL: data_s3_use_ssl,
                region: data_s3_region,
                accessKey: data_s3_access_key,
                secretKey: data_s3_secret_key,
                bucket: data_s3_bucket,
                pathStyle: true
            });
            break;
        }
    case 'kv':
        {
            try {
                kv = await Deno.openKv();
            } catch (_error) {
                throw new Error('KV Engine not supported (run with --unstable)');
            }
            break;
        }
    case 'file':
        {
            await mod16.ensureDir(data_file_path);
            break;
        }
}
ready = true;
async function read(folder, file) {
    const path = `${data_file_path}/${folder}/${file}.json`;
    switch(data_engine){
        case 's3':
            {
                const res = await s3c.getObject(path);
                if (res.status == 200) {
                    return res.json();
                }
                throw new Error(`S3 Error (${res.status})`);
            }
        case 'kv':
            {
                const res = await kv.get([
                    path
                ]);
                if (res.versionstamp !== null) {
                    return JSON.parse(res.value.text);
                }
                throw new Error(`KV Error (${res})`);
            }
        case 'file':
            {
                await mod16.ensureDir(`${data_file_path}/${folder}`);
                return JSON.parse(await Deno.readTextFile(path));
            }
        default:
            {
                if (path in inMemoryStorage) {
                    return JSON.parse(inMemoryStorage[path]);
                }
                throw new Error(`Not found: ${path}`);
            }
    }
}
async function write(folder, file, value) {
    const text = JSON.stringify(value);
    const path = `${data_file_path}/${folder}/${file}.json`;
    switch(data_engine){
        case 's3':
            {
                if (text == undefined) {
                    return await s3c.deleteObject(path);
                }
                await s3c.putObject(path, text);
                break;
            }
        case 'kv':
            {
                if (text == undefined) {
                    return await kv.delete([
                        path
                    ]);
                }
                await kv.set([
                    path
                ], {
                    text
                });
                break;
            }
        case 'file':
            {
                await mod16.ensureDir(`${data_file_path}/${folder}`);
                if (text == undefined) {
                    return await Deno.remove(path);
                }
                await Deno.writeTextFile(path, text);
                break;
            }
        default:
            {
                if (text == undefined) {
                    delete inMemoryStorage[path];
                } else {
                    inMemoryStorage[path] = text;
                }
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
const readPermission1 = await Deno.permissions.query({
    name: 'read'
});
if (jwt_keys_path && readPermission1.state === 'granted') {
    jwt_private_key = await crypto.subtle.importKey('pkcs8', mod9.decode(await Deno.readTextFile(`${jwt_keys_path}/jwt_private_key`)), {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-512'
    }, true, [
        'sign'
    ]);
    jwt_public_key = await crypto.subtle.importKey('spki', mod9.decode(await Deno.readTextFile(`${jwt_keys_path}/jwt_public_key`)), {
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
        await mod11.create({
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
        return await mod11.verify(jwt, jwt_public_key ?? jwt_private_key);
    } catch (_error) {
        throw new Error(`JWT signiture validation error ${jwt}`);
    }
}
function normaliseEmail(email) {
    return email.trim().toLowerCase();
}
const middleware = async (ctx, next)=>{
    try {
        const jwt = ctx.request.headers?.get('Authorization')?.replace('Bearer ', '') || mod6.helpers.getQuery(ctx)['jwt'];
        if (!jwt) throw new Error('Unauthorized');
        const jwt_verified = await ensureJwtValid(jwt);
        ctx.state.user = jwt_verified.sub;
    } catch (_error) {}
    await next();
};
const router = new mod6.Router().get('/jwtPublicKey', async (ctx)=>{
    ctx.response.body = mod9.encode(await crypto.subtle.exportKey('spki', jwt_public_key));
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
            meta: class_.meta || {
                logo: '',
                description: '',
                selfAssign: false,
                defaultNumberOfRooms: 0
            },
            modules: class_.modules.map((m)=>({
                    url: m.url,
                    config: m.config,
                    studentConfig: m.studentConfig,
                    width: m.width,
                    height: m.height,
                    showInCustom: m.showInCustom
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
            meta: {
                logo: '',
                description: '',
                selfAssign: false,
                defaultNumberOfRooms: 0
            },
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
}).post('/updateClass/:class_id', async (ctx)=>{
    if (!ctx.state.user) ctx.throw(401);
    const class_id = ctx?.params?.class_id;
    const body = await ctx.request.body();
    const class_new = body.type === 'json' ? await body.value : null;
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
    if (!live_class && class_id) {
        const rooms = {
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
        };
        if (res[0]?.meta?.defaultNumberOfRooms) {
            for(let i = 1; i <= res[0]?.meta?.defaultNumberOfRooms; i++){
                rooms[`Room ${i}`] = {
                    studentPublicState: '',
                    teacherPublicState: '',
                    teacherPrivateState: ''
                };
            }
        }
        classes[class_id] = {
            autoAssign: undefined,
            users: {},
            rooms
        };
        live_class = classes[class_id];
    }
    let connection_id = '';
    if (live_class && live_class.users[username]) {
        connection_id = nanoid();
        live_class.users[username].connections ??= [];
        live_class.users[username].connections.push({
            id: connection_id,
            target: target
        });
    } else if (live_class) {
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
            ],
            [
                JSON.stringify([
                    'users',
                    username,
                    'room'
                ]),
                (v)=>{
                    return true;
                }
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
}).post('/sendMessage/:class_id', async (ctx)=>{
    if (!ctx.state.user) ctx.throw(401);
    const class_id = ctx?.params?.class_id;
    const body = await ctx.request.body();
    const message = body.type === 'json' ? await body.value : null;
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
        res = live_class;
        connections.forEach((c)=>c.target.dispatchEvent(new mod6.ServerSentEvent('update', res)));
    }
    return true;
}
function sendMessage(class_id, message) {
    const live_class = classes[class_id];
    if (!live_class) return false;
    const info = JSON.stringify(message);
    mod8.debug(`Message to be sent (${class_id}) => ${info.length > 100 ? `${info.slice(0, 100)}...` : info}`);
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
app.use(middleware);
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
