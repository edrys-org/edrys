/**
 * This the Edrys javascript client library.
 * Properties:
 *  Edrys.ready
 *  Edrys.role
 *  Edrys.username
 *  Edrys.module
 *  Edrys.liveClass (this is reactive, meaning setting a property on it will also update it in real time)
 *  Edrys.liveRoom (also reactive)
 *  Edrys.liveUser (also reactive)
 * Functions:
 *  Edrys.sendMessage(subject, body)
 *  Edrys.onMessage(({from, subject, body}) => { // Called when a message is recieved in your room })
 *  Edrys.onUpdate((e) => { // Called when any Edrys properties change })
 */

let Edrys = {
    origin: '*',
    ready: false,
    role: undefined,
    username: undefined,
    liveClass: undefined,
    liveRoom: undefined,
    liveUser: undefined,
    module: undefined,
    onReady(handler) {
        if (Edrys.ready) return
        window.addEventListener("$Edrys.update", e => { handler(Edrys) })
        Edrys.ready = true
    },
    onUpdate(handler) {
        window.addEventListener("$Edrys.update", e => { handler(Edrys) })
    },
    onMessage(handler) {
        window.addEventListener("$Edrys.message", e => { handler(e.detail) })
    },
    sendMessage: (subject, body) => {
        if (typeof subject !== 'string') subject = JSON.stringify(subject)
        if (typeof body !== 'string') body = JSON.stringify(body)
        window.parent.postMessage({
            event: 'message',
            subject: subject,
            body: body
        }, Edrys.origin)
    },
}

const edrysProxyValidator = (path) => ({
    get(target, key) {
        if (key == "isProxy") return true;
        const prop = target[key];
        if (typeof prop == "undefined") return;
        if (!prop.isProxy && typeof prop === "object")
            target[key] = new Proxy(prop, edrysProxyValidator([...path, key]));
        return target[key];
    },
    set(target, key, value) {
        if (!path.includes("__ob__")) {
            const path_ = [...path, key];
            window.parent.postMessage({
                event: 'update',
                path: path_,
                value: value
            }, Edrys.origin)
        }
        target[key] = value;
        return true;
    },
})

window.addEventListener("message", function (e) {
    switch (e.data.event) {
        case 'update':
            Edrys.origin = e.data.origin;
            Edrys.role = e.data.role
            Edrys.username = e.data.username
            Edrys.module = e.data.module
            Object.entries(e.data.liveClass.rooms).forEach(([n, r]) => { r.name = n })
            Object.entries(e.data.liveClass.users).forEach(([n, u]) => { u.name = n })
            Edrys.liveClass = new Proxy(e.data.liveClass, edrysProxyValidator(''))
            Edrys.liveUser = Edrys.liveClass.users[Edrys.username]
            Edrys.liveRoom = Edrys.liveClass.rooms[Edrys.liveUser.room]
            break;
        case 'message':
            // Available: e.data.from, e.data.subject, e.data.body
            break;
        case 'echo':
            console.log("ECHO:", e.data)
            break;
        default:
            break;
    }
    dispatchEvent(new CustomEvent('$Edrys.' + e.data.event, { bubbles: false, detail: e.data }))
}, false);
