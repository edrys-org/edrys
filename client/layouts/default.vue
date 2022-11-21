<template>
  <v-app dark>
    <v-main>
      <v-app-bar clipped-left fixed app>
        <v-app-bar-nav-icon
          @click.stop="$store.commit('toggleDrawer', !$store.state.drawer)"
          v-show="$vuetify.breakpoint.mdAndDown && $route.name == 'class-id'"
        />
        <v-btn depressed text @click="$router.push('/')" active-class="">
          <img
            v-if="$vuetify.theme.dark"
            src="~/assets/logo-dark.svg"
            alt=""
            style="height: 30px; padding: 1px"
          />
          <img
            v-else
            src="~/assets/logo.svg"
            alt=""
            style="height: 30px; padding: 1px"
          />
        </v-btn>
        <v-toolbar-title> </v-toolbar-title>
        <v-spacer></v-spacer>
        <div v-show="email != '' && ready">
          <v-btn
            depressed
            tile
            class="text-capitalize"
            @click="
              () => {
                state = 'name';
                dialogShown = true;
                inputDisplayName = $store.state.user.displayName;
              }
            "
          >
            <v-icon left>mdi-account-circle-outline</v-icon>
            <span>{{
              $store.state.user ? $store.state.user.displayName : email
            }}</span>
          </v-btn>
          <v-btn icon depressed tile @click="logout">
            <v-icon>mdi-export</v-icon>
          </v-btn>
        </div>
      </v-app-bar>
      <v-dialog
        v-model="dialogShown"
        :persistent="state != 'name' || isNewbie"
        width="500"
      >
        <v-card>
          <v-card-title v-if="state == 'name'">My Account</v-card-title>
          <v-card-title v-else>Login to Edrys</v-card-title>
          <v-card-text v-if="state == 'name'"
            >You are currently logged in as {{ email }}. Please enter your name
            that will be visible to others:
          </v-card-text>
          <v-card-text>
            <span v-if="showLoginFail" class="red--text"
              >Something wasn't right, please try again.</span
            >

            <v-form
              @submit.prevent="sendToken"
              v-model="emailValid"
              v-if="state == 'email'"
            >
              <v-text-field
                required
                label="Email"
                type="email"
                v-model="inputEmail"
                :rules="emailRules"
                :disabled="loginLoading"
              ></v-text-field>
            </v-form>
            <v-form @submit.prevent="verifyToken" v-else-if="state == 'token'">
              <v-btn
                icon
                @click="
                  state = 'email';
                  inputEmail = '';
                "
              >
                <v-icon left>mdi-arrow-left-bold</v-icon>
              </v-btn>
              Enter code sent to <code>{{ inputEmail }}</code
              >:

              <v-otp-input
                v-model="token"
                :disabled="loginLoading"
                @finish="verifyToken"
              ></v-otp-input>
            </v-form>
            <v-form
              @submit.prevent="setDisplayName"
              v-model="displaNameValid"
              v-else-if="state == 'name'"
            >
              <v-text-field
                outlined
                label="Name"
                type="name"
                v-model="inputDisplayName"
                :rules="displayNameRules"
                :disabled="loginLoading"
              ></v-text-field>
            </v-form>

            <v-overlay absolute :value="loginLoading">
              <v-progress-circular
                indeterminate
                color="primary"
              ></v-progress-circular>
            </v-overlay>
          </v-card-text>

          <v-card-actions>
            <v-spacer></v-spacer>

            <v-btn
              color="primary"
              @click="
                state == 'name'
                  ? setDisplayName()
                  : state == 'token'
                  ? verifyToken()
                  : sendToken()
              "
              depressed
              :disabled="
                (state == 'email' && !emailValid) ||
                (state == 'name' && !displaNameValid) ||
                (state == 'token' && token.length < 6) ||
                loginLoading
              "
            >
              <v-icon left>mdi-arrow-right-bold</v-icon>
              Continue
            </v-btn>
          </v-card-actions>
        </v-card>
      </v-dialog>
      <v-snackbar
        :timeout="1000"
        :value="showLoginSuccess"
        absolute
        bottom
        color="success"
        outlined
        right
      >
        Logged in as <strong>{{ email }}</strong>
      </v-snackbar>

      <v-snackbar :timeout="3000" :value="classNotFound" absolute bottom right>
        Sorry, it looks like that class no longer exists
      </v-snackbar>

      <NuxtChild
        v-if="ready && email && $store.state.user"
        :key="email"
        @class-not-found="classNotFound = true"
      />
      <div v-else justify="center" align="center" v-show="email != ''">
        <v-progress-circular
          class="centered"
          indeterminate
          color="primary"
        ></v-progress-circular>
      </div>
    </v-main>
    <v-footer app>
      <v-btn depressed small tile href="https://edrys.org">
        <span> &copy; {{ new Date().getFullYear() }} Edrys.org</span>
      </v-btn>

      <span></span>
      <v-spacer></v-spacer>
    </v-footer>
  </v-app>
</template>

<script>
export default {
  name: "DefaultLayout",
  data() {
    return {
      ready: false,

      inputEmail: "",
      emailValid: false,
      emailRules: [
        (v) => !!v || "E-mail is required",
        (v) => /.+@.+\..+/.test(v) || "E-mail must be valid",
      ],

      token: "",

      inputDisplayName: "",
      displaNameValid: false,
      displayNameRules: [
        (v) => !!v || "Name required",
        (v) =>
          /^([^0-9]{1,100})$/.test(v) || "Name can only contain letters",
        (v) => v.split(" ").length >= 2 || "Please enter your full name",
      ],

      dialogShown: true,

      email: "", // Used to tell if logged in
      state: "start", // start -> email -> token -> name -> end
      loginLoading: false,
      showLoginFail: false,
      showConnectFail: false,
      showLoginSuccess: false,

      classNotFound: false,

      isNewbie: false,
    };
  },
  watch: {
    state() {
      this.dialogShown = this.state != "end";
    },
  },
  async mounted() {
    this.$store.commit(
      "setInstance",
      process.env.NODE_ENV !== "production"
        ? window.location.protocol + "//" + window.location.hostname + ":8080"
        : window.location.protocol + "//" + window.location.host
    );

    this.$axios.onRequest((config) => {
      config.baseURL = this.$store.state.instance;
    });

    const darkMediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
    if (darkMediaQuery.matches) {
      console.log("change default light to dark theme");
      // Need to set 0 sec timeout to set the dark more after mounted event, due to some bug in the framework
      setTimeout(() => (this.$vuetify.theme.dark = true), 0);
    }

    this.email = localStorage.email;
    if (!this.email) this.state = "email";
    else await this.tryLogin(true);
    this.ready = true;
  },
  updated() {},
  methods: {
    async sendToken() {
      if (!this.emailValid) return;

      this.loginLoading = true;
      try {
        const res = await this.$axios.get(
          "/auth/sendToken?email=" + this.inputEmail
        );

        if (res.status == 200) this.state = "token";
      } catch (error) {
        this.showLoginFail = true;
      }

      this.loginLoading = false;
    },
    async verifyToken() {
      if (!this.emailValid) return;
      this.showConnectFail = false;
      this.showLoginFail = false;
      this.loginLoading = true;
      try {
        const res = await this.$axios.get(
          "/auth/verifyToken?email=" + this.inputEmail + "&token=" + this.token
        );
        if (res.status == 200) {
          localStorage.email = this.inputEmail;
          this.email = this.inputEmail;
          this.isNewbie = res.data[0];
          localStorage.jwt = res.data[1];
          this.showLoginSuccess = true;
          await this.tryLogin();
        } else {
          throw new Error();
        }
      } catch (error) {
        this.token = "";
        this.showLoginFail = true;
      }
      this.loginLoading = false;
    },
    async tryLogin(logoutOnFail = false) {
      if (localStorage.jwt) {
        this.$axios.onRequest((config) => {
          config.headers.common["Authorization"] = `Bearer ${localStorage.jwt}`;
        });
        try {
          this.$store.commit(
            "setUser",
            await this.$axios.$get(`/data/readUser`)
          );
        } catch (error) {
          if (logoutOnFail) this.logout();
        }
        if (this.isNewbie) this.state = "name";
        else this.state = "end";
        this.emailValid = true;
      }
    },
    async setDisplayName() {
      if (!this.emailValid) return;
      this.$store.commit(
        "setUser",
        await this.$axios.$get(
          `/data/updateUser?user=${encodeURIComponent(
            JSON.stringify({
              ...this.$store.state.user,
              displayName: this.inputDisplayName,
            })
          )}`
        )
      );
      this.state = "end";
    },
    logout() {
      this.showConnectFail = false;
      this.showLoginFail = false;
      this.inputEmail = "";
      this.token = "";
      this.loginLoading = false;
      localStorage.jwt = "";
      localStorage.email = "";
      this.email = "";
      this.state = "email";
      this.$axios.onRequest((config) => {
        config.headers.common["Authorization"] = undefined;
      });
      this.$router.push({ path: "/" });
      window.location.reload();
    },
  },
};
</script>

<style scoped>
.circle {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  margin-right: 5px;
}
.centered {
  position: fixed;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
}

.theme--dark.v-application {
  background-color: var(--v-background-base, #121212) !important;
}
.theme--light.v-application {
  background-color: var(--v-background-base, white) !important;
}
</style>