<template>
  <div>
    <v-container>
      <div>
        <v-row justify="center" align="center" v-if="ready">
          <v-col cols="12" sm="10" md="10">
            <v-card>
              <v-card-title
                >{{ $store.state.class_.name }} – {{ roomName }}</v-card-title
              >
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
export default {
  name: "Student",
  props: ["liveClassProxy"],
  computed: {
    roomName() {
      return this.liveClassProxy.users[this.$store.state.user.email].room;
    },
  },
  data() {
    return {
      liveRoomProxy: {},
      ready: false,
    };
  },
  async mounted() {
    this.ready = true;
  },
  methods: {},
};
</script>

<style scoped>
</style>