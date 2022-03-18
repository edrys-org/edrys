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
 *  Edrys.onUpdate(() => { // Called when any Edrys properties change })
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
    class_id: undefined,
    onReady(handler) {
        if (Edrys.ready)
            handler(Edrys)
        else
            window.addEventListener("$Edrys.ready", e => { handler(Edrys) })
    },
    onUpdate(handler) {
        window.addEventListener("$Edrys.update", e => { handler(Edrys) })
    },
    onMessage(handler, promiscuous=false) {
        window.addEventListener("$Edrys.message", e => { 
            if (!promiscuous && e.detail.module != Edrys.module?.url)
                return
            handler(e.detail) 
        })
    },
    sendMessage: (subject, body) => {
        if (typeof subject !== 'string') subject = JSON.stringify(subject)
        if (typeof body !== 'string') body = JSON.stringify(body)
        window.parent.postMessage({
            event: 'message',
            subject: subject,
            body: body,
            module: Edrys.module.url
        }, Edrys.origin)
    },
    setItem(key, value) {
        localStorage.setItem(`${Edrys.class_id}.${Edrys.liveUser.room}.${key}`, value)
    },
    getItem(key) {
        return localStorage.getItem(`${Edrys.class_id}.${Edrys.liveUser.room}.${key}`)
    }
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

            try { Edrys.module.config = JSON.parse(e.data.module.config) }
            catch (e) {}
            try { Edrys.module.studentConfig = JSON.parse(e.data.module.studentConfig) }
            catch (e) {}
            try { Edrys.module.teacherConfig = JSON.parse(e.data.module.teacherConfig) }
            catch (e) {}
            try { Edrys.module.stationConfig = JSON.parse(e.data.module.stationConfig) }
            catch (e) {}

            Edrys.class_id = e.data.class_id
            Object.entries(e.data.liveClass.rooms).forEach(([n, r]) => { r.name = n })
            Object.entries(e.data.liveClass.users).forEach(([n, u]) => { u.name = n })
            Edrys.liveClass = new Proxy(e.data.liveClass, edrysProxyValidator(''))
            Edrys.liveUser = Edrys.liveClass.users[Edrys.username]
            Edrys.liveRoom = Edrys.liveClass.rooms[Edrys.liveUser.room]

            if (!Edrys.ready)
            {
                Edrys.ready = true
                dispatchEvent(new CustomEvent('$Edrys.ready', { bubbles: false, detail: e.data }))
            }

            break;
        case 'message':
            // available: e.data.from, e.data.subject, e.data.body
            break;
        case 'echo':
            console.log("ECHO:", e.data)
            break;
        default:
            break;
    }
    dispatchEvent(new CustomEvent('$Edrys.' + e.data.event, { bubbles: false, detail: e.data }))
}, false);
