r<template>
  <div
    style="height: 100%; width: 100%"
    :key="scrapedModule.url"
  >
    <iframe
      style="height: 100%; width: 100%"
      :key="liveClassProxy.users[username].room"
      :src="scrapedModule.srcdoc ? scrapedModule.srcdoc : (scrapedModule.url.startsWith('data:') ? null : scrapedModule.url)"
      :srcdoc="!scrapedModule.srcdoc ? null : ( scrapedModule.url.startsWith('data:') ? scrapedModule.url : null )"
      allow="camera; microphone; fullscreen; display-capture; accelerometer; autoplay; encrypted-media; geolocation; gyroscope; magnetometer; midi; serial; vr;"
      @load="updateIframe"
      ref="iframe"
      scrolling
      frameborder="0"
    ></iframe>
  </div>
</template>


<script>
export default {
  name: "Module",
  props: ["role", "username", "liveClassProxy", "scrapedModule"],
  data() {
    return {};
  },
  computed: {
    iframeOrigin() {
      return new URL(this.scrapedModule.url).origin;
    },
  },
  watch: {
    liveClassProxy() {
      this.updateIframe();
    },
    "$store.state.lastRecievedMessage"(val) {
      if (val != undefined) {
        this.$refs.iframe.contentWindow.postMessage(
          {
            event: "message",
            ...val,
          },
          this.scrapedModule.origin || this.iframeOrigin
        );
      }
    },
  },

  methods: {
    updateIframe() {
      this.$refs.iframe.contentWindow.postMessage(
        {
          event: "update",
          origin: window.origin,
          role: this.role,
          username: this.username,
          liveClass: JSON.parse(JSON.stringify(this.liveClassProxy)),
          module: this.scrapedModule,
          class_id: this.$store.state.class_.id,
        },
        this.scrapedModule.origin || this.iframeOrigin
      );
    },
  },
};
</script>

<style scoped>
</style>