<template>
  <div>
    <v-container>
      <v-row
        justify="center"
        align="center"
      >
        <v-col>
          <div
            class="title"
            style="padding: 10px"
            v-if="
              canCreateClass || this.$store.state.user.memberships.length >= 1
            "
          >
            My Classes
          </div>
          <div
            class="subtitle"
            style="padding: 10px"
            v-else
          >
            Looks like you aren't a part of any classes on this isntance yet.
            Ask your instructors for an invite link.
          </div>
          <div class="items">
            <v-card
              class="item"
              elevation="2"
              :to="`/class/${m.class_id}`"
              nuxt
              v-for="m in this.$store.state.user.memberships"
              :key="m.class_id"
            >
              <v-img
                :src="m.meta && m.meta.logo ? m.meta.logo : 'https://repository-images.githubusercontent.com/453979926/ab6bf9d7-a4bc-4a47-97b7-c8bc8bb4654d'"
                height="200px"
              ></v-img>
              <v-card-title>{{ m.class_name }}</v-card-title>
              <v-card-subtitle>
                <span v-if="m.role == 'student'">You're a student here</span>
                <span v-else-if="m.role == 'teacher'">You teach this class</span>
              </v-card-subtitle>

              <v-card-text v-html="m.meta && m.meta.description ? m.meta.description : 'No description'">

              </v-card-text>

              <v-card-actions>
                <v-spacer></v-spacer>
                <v-btn icon>
                  <v-icon>mdi-arrow-right-bold</v-icon>
                </v-btn>
              </v-card-actions>
            </v-card>
            <v-card
              class="item"
              color="primary"
              elevation="2"
              v-show="canCreateClass"
              @click="
                canCreateClass ? createClass() : (alertCantCreateClass = true)
              "
              :disabled="creatingClass"
            >
              <v-card-title>Create a class</v-card-title>
              <v-card-subtitle>Start teaching now</v-card-subtitle>
              <v-card-actions>
                <v-spacer></v-spacer>

                <v-btn
                  icon
                  :loading="creatingClass"
                  :disabled="creatingClass"
                >
                  <v-icon>mdi-plus</v-icon>
                </v-btn>
              </v-card-actions>
            </v-card>

            <v-dialog
              v-model="alertCantCreateClass"
              width="500"
            >
              <v-card>
                <v-card-title> Sorry </v-card-title>

                <v-card-text>
                  It looks like you're not allowed to create new classes on your
                  current instance. Switch to a new instance and try again.
                </v-card-text>

                <v-divider></v-divider>

                <v-card-actions>
                  <v-spacer></v-spacer>
                  <v-btn
                    color="primary"
                    text
                    @click="alertCantCreateClass = false"
                  >
                    OK
                  </v-btn>
                </v-card-actions>
              </v-card>
            </v-dialog>
          </div>
        </v-col>
      </v-row>
    </v-container>
  </div>
</template>

<script>
export default {
  name: "IndexPage",
  data() {
    return {
      canCreateClass: false,
      creatingClass: false,
      alertCantCreateClass: false,
    };
  },
  head() {
    return {
      title: "Home",
    };
  },
  async mounted() {
    this.canCreateClass = await this.$axios.$get(`/data/canCreateClass`, {
      timeout: 1000,
    });
    this.$store.commit("setUser", await this.$axios.$get(`/data/readUser`));
  },
  methods: {
    async createClass() {
      this.creatingClass = true;

      const id = await this.$axios.$get("data/createClass");

      this.$router.push({
        path: `/class/${encodeURIComponent(id)}#settings`,
      });

      this.creatingClass = false;
    },
  },
};
</script>

<style scoped>
.items {
  column-count: 3;
  column-gap: 10px;
  padding: 0;
}

.item {
  display: inline-block;
  width: 100%;
  margin: 5px 0;
}

/* Make it responsive */
@media only screen and (max-width: 1200px) {
  .items {
    column-count: 3;
  }
}
@media only screen and (max-width: 500px) {
  .items {
    column-count: 1;
  }
}
</style>