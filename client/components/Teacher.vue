<template>
  <div>
    <v-navigation-drawer
      :disabled="isStation"
      :width="310"
      :value="$store.state.drawer"
      @input="(v) => $store.commit('toggleDrawer', v)"
      app
      clipped
    >
      <v-overlay :value="isStation" :opacity="0.8">
        <v-card tile width="100%" class="blue-grey darken-4 text-center">
          <v-card-text class="white--text"> Station Mode Active </v-card-text>

          <v-divider></v-divider>

          <v-card-text>
            <v-form @submit.prevent="setStationName">
              <v-text-field
                outlined
                v-model="stationNameInput"
                :rules="stationNameRules"
                label="Station Name"
                required
                append-icon="mdi-arrow-right"
                @click:append="setStationName"
              ></v-text-field>
            </v-form>

            This browser is now running as a station and ready to serve students
          </v-card-text>
          <v-divider></v-divider>
          <v-card-text>
            <v-btn @click="exitStationMode">
              <v-icon left>mdi-export-variant</v-icon>

              Exit Station mode
            </v-btn>
          </v-card-text>
        </v-card>
      </v-overlay>

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

        <v-list-item-icon>
          <v-btn icon @click="showSettings = !showSettings" color="grey">
            <v-icon>mdi-cog</v-icon>
          </v-btn>
        </v-list-item-icon>
      </v-list-item>
      <v-list dense>
        <v-list-item-group :value="currentRoomName" mandatory>
          <div
            v-for="[room_name, room] in Object.entries(
              liveClassProxy.rooms || {}
            )"
            :key="room_name"
            :value="room_name"
          >
            <v-divider></v-divider>
            <v-hover v-slot="{ hover }">
              <v-list-item
                :value="room_name"
                link
                @click="
                  () => {
                    setCurrentRoom(room_name);
                  }
                "
              >
                <v-list-item-icon style="margin-right: 15px">
                  <v-icon color="grey">
                    <template v-if="room_name == 'Lobby'"
                      >mdi-account-multiple</template
                    >
                    <template v-else-if="room_name == 'PA Mode'"
                      >mdi-bullhorn</template
                    >
                    <template v-else-if="room_name.startsWith('Station ')"
                      >mdi-router-wireless</template
                    >
                    <template v-else>mdi-forum</template></v-icon
                  >
                </v-list-item-icon>

                <v-list-item-title>{{ room_name }} </v-list-item-title>

                <v-btn
                  icon
                  v-show="hover && room_name.startsWith('Room ')"
                  @click.stop="removeRoom(room_name)"
                >
                  <v-icon color="grey">mdi-close</v-icon>
                </v-btn>

                <v-list-item-icon>
                  <v-icon color="grey">mdi-arrow-right</v-icon>
                </v-list-item-icon>
              </v-list-item>
            </v-hover>

            <v-list dense flat>
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
                    inactive
                    :ripple="false"
                    :selectable="false"
                    v-show="room.userLinked != email"
                  >
                    <v-list-item-icon
                      style="margin-right: 15px; margin-left: 20px"
                    >
                      <v-icon v-if="user.role == 'student'" color="grey"
                        >mdi-account-circle-outline</v-icon
                      >
                      <v-icon v-else-if="user.role == 'teacher'" color="grey"
                        >mdi-clipboard-account-outline</v-icon
                      >
                    </v-list-item-icon>
                    <v-list-item-title>
                      {{ user.displayName }}</v-list-item-title
                    >

                    <v-icon color="grey" v-show="hover" class="handle"
                      >mdi-drag-horizontal-variant</v-icon
                    >
                  </v-list-item>
                </v-hover>
              </draggable>
            </v-list>
          </div>
        </v-list-item-group>
      </v-list>

      <template v-slot:append>
        <div class="pa-2">
          <v-btn depressed block class="mb-2" @click="addRoom">
            <v-icon left>mdi-forum</v-icon>
            New room
          </v-btn>
        </div>
      </template>
    </v-navigation-drawer>

    <v-dialog
      v-model="showSettings"
      max-width="700px"
      scrollable
      :persistent="settingspendingEdits"
    >
      <Settings
        :pendingEdits.sync="settingspendingEdits"
        @close="showSettings = false"
      />
    </v-dialog>

    <v-slide-y-transition> </v-slide-y-transition>

    <v-container>
      <div v-if="ready">
        <v-row justify="center" align="center">
          <v-col cols="12" sm="10" md="10">
            <v-card>
              <v-card-title> {{ currentRoomName }} </v-card-title>
              <Modules
                :role="isStation ? 'station' : 'teacher'"
                :username="username"
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
  name: "Teacher",
  props: ["liveClassProxy", "isStation", "stationName"],
  data() {
    return {
      settingspendingEdits: false,
      ready: false,
      liveTeacherCount: 0,
      liveStudentCount: 0,
      lists: {},
      myUrl: "",
      showSettings: false,
      stationNameInput: "",
      stationNameRules: [
        (v) => !!v || "Name required",
        (v) =>
          /^([A-Za-z0-9 ]{1,50})$/.test(v) ||
          "Up to 50 letters and numbers only",
      ],
    };
  },
  computed: {
    username() {
      return this.isStation ? this.stationName : this.$store.state.user.email;
    },
    currentRoomName() {
      return this.liveClassProxy.users[this.username].room;
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
  mounted() {
    this.stationNameInput = this.stationName;
    this.updateDisplay();
    if (this.$route.hash.includes("#settings")) {
      this.showSettings = true;
      window.location.hash = window.location.hash.replace("#settings", "");
    }
  },
  methods: {
    addRoom() {
      let roomNo = Object.keys(this.liveClassProxy.rooms)
        .filter((r) => r.startsWith("Room "))
        .map((r) => Number(r.replace("Room ", "")));
      roomNo.push(0);
      roomNo.sort((a, b) => a - b).reverse();
      roomNo = roomNo[0] + 1;
      this.liveClassProxy.rooms["Room " + roomNo] = {};
    },
    removeRoom(name) {
      if (this.currentRoomName == name) this.setCurrentRoom("Lobby");
      this.liveClassProxy.rooms[name] = null;
    },
    setStationName() {
      localStorage.stationName = this.stationNameInput;
      window.location.reload();
    },
    exitStationMode() {
      window.location.hash = window.location.hash.replace("#station", "");
      window.location.reload();
    },
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
        } else {
          this.liveClassProxy.users[user_email].room = room_name;
        }
      }
    },
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