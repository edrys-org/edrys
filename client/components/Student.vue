<template>
  <div>
    <v-navigation-drawer
      :width="310"
      :value="$store.state.drawer"
      @input="(v) => $store.commit('toggleDrawer', v)"
      app
      clipped
      v-show="selfAssign"
    >
      <v-list-item style="margin: 10px">
        <v-list-item-content>
          <v-list-item-title class="text-h6">
            {{ $store.state.class_.name }}
          </v-list-item-title>
          <v-list-item-subtitle>
            {{ liveStudentCount }}
            {{ liveStudentCount == 1 ? "student" : "students" }},
            {{ liveTeacherCount }}
            {{ liveTeacherCount == 1 ? "teacher" : "teachers" }} online
          </v-list-item-subtitle>
        </v-list-item-content>
      </v-list-item>
      <v-list dense>
        <v-list-item-group
          :value="currentRoomName"
          mandatory
        >
          <div
            v-for="[room_name, room] in Object.entries(
              liveClassProxy.rooms || {}
            )"
            :key="room_name"
            :value="room_name"
          >
            <v-divider v-if="room_name != 'Teacher\'s Lounge'"></v-divider>
            <v-hover v-slot="{ hover }">
              <v-list-item
                :value="room_name"
                v-if="room_name != 'Teacher\'s Lounge'"
                link
                @click="
                  () => {
                    setCurrentRoom(room_name);
                  }
                "
              >
                <v-list-item-icon style="margin-right: 15px">
                  <v-icon color="grey">
                    <template v-if="room_name == 'Lobby'">mdi-account-multiple</template>
                    <template v-else-if="room_name == 'PA Mode'">mdi-bullhorn</template>
                    <template v-else-if="room_name.startsWith('Station ')">mdi-router-wireless</template>
                    <template v-else>mdi-forum</template>
                  </v-icon>
                </v-list-item-icon>

                <v-list-item-title>{{ room_name }} </v-list-item-title>

                <v-list-item-icon>
                  <v-icon color="grey">mdi-arrow-right</v-icon>
                </v-list-item-icon>
              </v-list-item>
            </v-hover>

            <v-list
              dense
              flat
            >
              <draggable
                group="users"
                @end="userRoomChange"
                :id="`$ROOM:${room_name}`"
              >
                <v-hover
                  v-slot="{ hover }"
                  v-for="[email, user] in Object.entries(
                    liveClassProxy.users
                  ).filter(([e, u]) => u.room == room_name)"
                  :key="email"
                  :id="`$EMAIL:${email}`"
                >
                  <v-list-item
                    :disabled="email!=username"
                    inactive
                    :ripple="false"
                    :selectable="false"
                    v-show="room.userLinked != email"
                  >
                    <v-list-item-icon style="margin-right: 15px; margin-left: 20px">
                      <v-icon
                        v-if="user.role == 'student'"
                        color="grey"
                      >mdi-account-circle-outline</v-icon>
                      <v-icon
                        v-else-if="user.role == 'teacher'"
                        color="grey"
                      >mdi-clipboard-account-outline</v-icon>
                    </v-list-item-icon>
                    <v-list-item-title>
                      {{ user.displayName }}</v-list-item-title>

                    <v-icon
                      color="grey"
                      v-show="hover"
                      class="handle"
                    >mdi-drag-horizontal-variant</v-icon>
                  </v-list-item>
                </v-hover>
              </draggable>
            </v-list>
          </div>
        </v-list-item-group>
      </v-list>
    </v-navigation-drawer>

    <v-slide-y-transition> </v-slide-y-transition>

    <v-container>
      <div>
        <v-row
          justify="center"
          align="center"
          v-if="ready"
        >
          <v-col
            cols="12"
            sm="10"
            md="10"
          >
            <v-card>
              <v-card-title>{{ $store.state.class_.name }} – {{ roomName }}</v-card-title>
              <Modules
                role="student"
                :username="$store.state.user.email"
                :live-class-proxy="liveClassProxy"
              ></Modules>
            </v-card>
          </v-col>
        </v-row>
      </div>
    </v-container>
  </div>
</template>

<script>
import draggable from "vuedraggable";
import Module from "./Module.vue";
import Modules from "./Modules.vue";
import Settings from "./Settings.vue";

export default {
  name: "Student",
  props: ["liveClassProxy"],
  computed: {
    username() {
      return this.$store.state.user.email;
    },
    roomName() {
      return this.liveClassProxy.users[this.$store.state.user.email].room;
    },
    selfAssign() {
      try {
        return this.$store.state.class_.meta.selfAssign;
      } catch (e) {}

      return false;
    },
  },
  watch: {
    "$store.state.user.displayName"() {
      if (this.$store.state.class_)
        this.liveClassProxy.users[this.username].displayName =
          this.$store.state.user.displayName;
    },
    currentRoomName() {
      if (["md", "sm", "xs"].includes(this.$vuetify.breakpoint.name))
        this.$store.commit("toggleDrawer", false);
    },
    liveClassProxy() {
      this.updateDisplay();
    },
  },

  methods: {
    updateDisplay() {
      this.liveTeacherCount = Object.values(this.liveClassProxy.users).filter(
        (u) => u.role == "teacher"
      ).length;
      this.liveStudentCount = Object.values(this.liveClassProxy.users).filter(
        (u) => u.role == "student"
      ).length;

      if (this.liveClassProxy && !this.ready) {
        this.ready = true;
      }
    },
    setCurrentRoom(room_name) {
      this.liveClassProxy.users[this.username].room = room_name;
    },
    enableAutoAssign() {
      this.liveClassProxy.autoAssign = this.username;
    },
    userRoomChange(e) {
      if (e.type == "end") {
        const room_name = e.to.id.replace("$ROOM:", "");
        const user_email = e.item.id.replace("$EMAIL:", "");

        if (user_email == this.username) {
          this.setCurrentRoom(room_name);
        }
      }
    },
  },

  data() {
    return {
      liveRoomProxy: {},
      ready: false,
      liveTeacherCount: 0,
      liveStudentCount: 0,
      lists: {},
      myUrl: "",
    };
  },
  async mounted() {
    this.ready = true;
  },
  components: {
    Settings,
    Module,
    draggable,
    Modules,
  },
};
</script>

<style scoped>
</style>