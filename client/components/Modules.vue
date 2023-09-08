<template>
  <div :key="role">
    <div class="items">
      <!-- :style="{
          height:
            m.height == 'tall'
              ? '700px'
              : m.height == 'short'
              ? '300px'
              : '500px',
        }" -->
      <Module
        class="item"
        v-for="(m, i) in scrapedModules"
        :key="i"
        :username="username"
        :live-class-proxy="liveClassProxy"
        :scrapedModule="scrapedModules[i]"
        :role="role"
      >
      </Module>
    </div>

    <v-card v-if="!scrapedModules.length">
      <v-card-text v-if="role == 'teacher' || role == 'station'">
        Sorry, looks like you have not loaded up any {{ modulesType }} modules.
        Add some in the class settings to get started.
      </v-card-text>
      <v-card-text v-if="role == 'student'">
        Sorry, it looks like the class creators have not added any modules yet.
      </v-card-text>
    </v-card>
  </div>
</template>

<script>
export default {
  name: "Modules",
  props: ["role", "username", "liveClassProxy"],
  data() {
    return { ws: null };
  },
  computed: {
    roomName() {
      return (
        this.liveClassProxy.users[this.username]?.room ||
        "Station " + this.username
      );
    },
    modulesType() {
      return this.roomName.startsWith("Station ") ? "station" : "chat";
    },
    scrapedModules() {
      return this.$store.state.scrapedModules.filter((m) => {
        const showIn = m.showInCustom
          ? m.showInCustom.split(",").map((e) => e.trim())
          : m.shownIn;

        return (
          (showIn.includes(this.modulesType) ||
            showIn
              .map((e) => e.toLowerCase().replace(/\*/g, ".*"))
              .map((e) => new RegExp(e))
              .map((e) => this.roomName.toLowerCase().match(e) !== null)
              .includes(true) ||
            showIn == "*") &&
          (this.role != "student" || !showIn.includes("teacher-only"))
        );
      });
    },
  },
  created() {
    window.addEventListener("message", this.messageHandler);
  },
  beforeDestroy() {
    window.removeEventListener("message", this.messageHandler);
  },
  async mounted() {},
  methods: {
    messageHandler(e) {
      switch (e.data.event) {
        case "message":
          this.sendMessage(e.data.subject, e.data.body, e.data.module);
          break;
        case "update":
          this.setToValue(this.liveClassProxy, e.data.path, e.data.value);
          break;
        case "echo":
          console.log("ECHO:", e.data);
          break;
        default:
          break;
      }
    },
    async sendMessage(subject, body, module_url) {
      if (this.ws === null) {
        const self = this;

        const socket = new WebSocket(
          (document.location.protocol === "http:" ? "ws" : "wss") +
            "://" +
            document.location.host +
            "/data/wss/" +
            this.$store.state.class_.id +
            "/" +
            this.username
        );

        socket.onopen = function (e) {
          console.warn("[open] Connection established");
          self.sendMessage(subject, body, module_url);
        };

        const iframes = document.getElementsByTagName("iframe");

        socket.onmessage = function (event) {
          const data = JSON.parse(event.data);
          data["event"] = "message";

          for (let i = 0; i < iframes.length; i++) {
            iframes[i].contentWindow.postMessage(data, "*");
          }
        };

        socket.onclose = function (event) {
          if (event.wasClean) {
            console.warn(
              `[close] Connection closed cleanly, code=${event.code} reason=${event.reason}`
            );
          } else {
            console.warn("[close] Connection died");
          }
        };

        socket.onerror = function (error) {
          console.warn("error =>", error);
        };

        this.ws = socket;
      }

      if (body !== undefined) {
        const data = {
          from: this.username /* Email if teacher, name if station */,
          subject: subject,
          body: body,
          module: module_url,
        };

        if (this.ws) {
          this.ws.send(JSON.stringify(data));
        } else {
          await this.$axios.$post(
            "/data/sendMessage/" + this.$store.state.class_.id,
            data
          );
        }
      }
    },
  },
};
</script>

<style scoped>
.item {
  height: 700px !important;
}

.items {
  margin: 0 auto;
  display: grid;
  grid-gap: 0.4rem;
  /* grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); */
}
</style>