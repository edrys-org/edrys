<template>
  <div>
    <div v-if="ready && modulesLoaded">
      <Teacher
        v-if="role == 'teacher'"
        :live-class-proxy="liveClassProxy"
        :is-station="isStation"
        :station-name="stationName"
      >
      </Teacher>
      <Student
        v-else-if="role == 'student'"
        :live-class-proxy="liveClassProxy"
      ></Student>
    </div>
    <div v-else justify="center" align="center">
      <v-progress-circular indeterminate color="primary"></v-progress-circular>
    </div>
  </div>
</template>

<script>
import Student from "../../components/Student.vue";
import Teacher from "../../components/Teacher.vue";

export default {
  name: "ClassPage",
  data() {
    return {
      ready: false,
      liveClass: undefined,
      liveClassProxy: undefined,
      role: "",
      liveClassEventSource: undefined,
      isStation: false,
      stationName: "",
      modulesLoaded: false,
    };
  },
  head() {
    return {
      title: "Class",
    };
  },
  watch: {
    async "$store.state.class_.modules"() {
      this.modulesLoaded = false;
      const scrapedModules = [];
      for (const m of this.$store.state.class_.modules) {
        scrapedModules.push(await this.scrapeModule(m));
      }
      this.$store.commit("setScrapedModules", scrapedModules);
      this.modulesLoaded = true;
    },
    async "$store.state.class_"(to, from) {
      this.ready = false;

      let new_user = undefined;

      if (this.$store.state.class_ === null) {
        new_user = {
          ...this.$store.state.user,
          memberships: this.$store.state.user.memberships.filter(
            (m) => m.class_id != this.$route.params.id
          ),
        };
      } else if (this.$store.state.class_) {
        const class_membership = this.$store.state.user.memberships?.find(
          (m) =>
            m.class_id == this.$route.params.id &&
            m.instance == this.$store.state.instance
        );
        if (
          !class_membership ||
          class_membership.role != this.role ||
          class_membership.class_name != this.$store.state.class_.name
        ) {
          if (
            this.$store.state.class_.members.teacher?.includes(
              localStorage.email
            )
          ) {
            this.role = "teacher";
          } else if (
            this.$store.state.class_.members.student?.includes(
              localStorage.email
            )
          ) {
            this.role = "student";
          }
          new_user = {
            ...this.$store.state.user,
            memberships: [
              {
                instance: this.$store.state.instance,
                class_id: this.$route.params.id,
                class_name: this.$store.state.class_.name,
                role: this.role,
              },
              ...this.$store.state.user.memberships.filter(
                (m) => m.class_id != this.$route.params.id
              ),
            ],
          };
        }
      } else {
        console.log("Undefined class");
        return;
      }
      
      if (new_user)
        this.$store.commit(
          "setUser",
          await this.$axios.$get(
            `/data/updateUser?user=${encodeURIComponent(
              JSON.stringify(new_user)
            )}`
          )
        );

      if (this.$store.state.class_ === null) {
        this.$router.push({ path: "/" });
        this.$emit("class-not-found");
        return;
      }

      // Subscribe to live class
      if (!this.liveClassEventSource) {

        const url = new URL(
          `${this.$store.state.instance}/data/readLiveClass/${this.$route.params.id}`
        );

        url.searchParams.append(
          "displayName",
          this.isStation ? this.stationName : this.$store.state.user.displayName
        );
        url.searchParams.append("jwt", localStorage.jwt);
        if (this.isStation) url.searchParams.append("isStation", "true");

        this.liveClassEventSource = new EventSource(url.href);

        this.liveClassEventSource.addEventListener("update", (evt) => {
          this.liveClass = JSON.parse(evt.data);
          this.buildLiveClassProxy();
          this.ready = true;

          // Return user to lobby if current room removed
          if (
            !Object.keys(this.liveClass.rooms).includes(
              this.liveClass.users[this.$store.state.user.email].room
            )
          )
            this.liveClassProxy.users[this.$store.state.user.email].room =
              "Lobby";
        });
        this.liveClassEventSource.addEventListener("message", (evt) => {
          this.$store.commit("setLastRecievedMessage", JSON.parse(evt.data));
        });
      } else {
        this.ready = true;
      }
    },
  },
  async mounted() {
    if (window.location.hash.includes("#station")) {
      this.isStation = true;
      this.stationName =
        localStorage.stationName || new Date().getTime().toString();
    } else {
      this.isStation = false;
      this.stationName = undefined;
    }

    await this.fetchClass();
  },
  methods: {
    buildLiveClassProxy() {
      const validator = (path) => ({
        get: function (target, key) {
          if (key == "isProxy") return true;

          const prop = target[key];

          // Return if property not found
          if (typeof prop == "undefined") return;

          // Set value as proxy if object
          if (!prop.isProxy && typeof prop === "object")
            target[key] = new Proxy(prop, validator([...path, key]));

          return target[key];
        },
        set: async (target, key, value) => {
          if (!path.includes("__ob__")) {
            const path_ = [...path, key];
            await this.$axios.$get(
              `/data/updateLiveClass/${
                this.$store.state.class_.id
              }?update=${encodeURIComponent(
                JSON.stringify({
                  path: path_,
                  value: value,
                })
              )}`
            );
          }

          target[key] = value;
          return true;
        },
      });

      this.liveClassProxy = new Proxy(this.liveClass, validator(""));
    },
    async fetchClass() {
      try {
        this.$store.commit(
          "setClass",
          await this.$axios.$get(`/data/readClass/${this.$route.params.id}`)
        );
        return true;
      } catch (error) {
        if (error.response.status == 404) {
          this.$store.commit("setClass", null);
          return false;
        }
      }
      throw new Error("Unknown response in class page");
    },
  },
  components: {
    Teacher,
    Student,
  },
};
</script>

<style scoped>
</style>
