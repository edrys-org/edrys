export const state = () => ({
    drawer: true,
    user: undefined,
    class_: undefined,
    scrapedModules: [],
    lastRecievedMessage: undefined,
})

export const mutations = {
    toggleDrawer(state, val) {
        state.drawer = val
    },
    setState(state, { key, value }) {
        state[key] = value
    },
    setUser(state, user) {
        state.user = user
    },
    setClass(state, class_) {
        state.class_ = class_
    },
    setScrapedModules(state, scrapedModules) {
        state.scrapedModules = scrapedModules

    },
    setLastRecievedMessage(state, lastRecievedMessage) {
        state.lastRecievedMessage = lastRecievedMessage
    },
    setInstance(state, instance) {
        state.instance = instance
    }
}