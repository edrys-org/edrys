<template>
  <v-card>
    <v-toolbar dark flat>
      <v-toolbar-title>Class Settings</v-toolbar-title>

      <v-spacer></v-spacer>

      <v-btn icon @click="$emit('close')">
        <v-icon>mdi-close</v-icon>
      </v-btn>

      <template v-slot:extension>
        <v-tabs v-model="tab" fixed-tabs center-active show-arrows>
          <v-tab active>
            <v-icon left> mdi-book-open-outline </v-icon>
            Settings
          </v-tab>
          <v-tab>
            <v-icon left> mdi-account-group </v-icon>
            Members
          </v-tab>
          <v-tab>
            <v-icon left> mdi-view-dashboard </v-icon>
            Modules
          </v-tab>
          <v-tab>
            <v-icon left> mdi-router-wireless </v-icon>
            Stations
          </v-tab>
          <v-tab>
            <v-icon left> mdi-share-variant </v-icon>
            Share
          </v-tab>
        </v-tabs>
      </template>
    </v-toolbar>

    <v-card-text style="height: 565px">
      <v-tabs-items v-model="tab" class="pt-5">
        <v-tab-item>
          <v-form ref="form" @submit.prevent="save">
            <v-text-field
              v-model="className"
              :counter="20"
              label="Class Name"
              outlined
              required
            ></v-text-field>
          </v-form>
        </v-tab-item>
        <v-tab-item>
          <v-alert outlined dense type="info">
            Enter emails below, one per line or separated by commas. Next,
            invite your users in by sharing this link:
            <br />
            <br />
            <blockquote style="margin-left: 10px">
              <a :href="`//${memberUrl}`">{{ memberUrl }}</a>

              <v-btn icon small @click="copyMemberUrl">
                <v-icon small>mdi-content-copy</v-icon>
              </v-btn>
            </blockquote>
          </v-alert>
          <v-textarea
            outlined
            label="List of teacher emails"
            v-model="memberTeacher"
          ></v-textarea>
          <v-textarea
            outlined
            label="List of student emails"
            v-model="memberStudent"
          ></v-textarea>
        </v-tab-item>
        <v-tab-item>
          <v-form @submit.prevent="importModule">
            <v-list two-line v-if="scrapedModules.length == modules.length">
              <draggable v-model="modules" handle=".handle">
                <v-list-item v-for="(m, i) in modules" :key="i" class="handle">
                  <v-list-item-avatar>
                    <v-icon class="grey darken-3" dark
                      >{{ scrapedModules[i].icon || "mdi-package" }}
                    </v-icon>
                  </v-list-item-avatar>

                  <v-list-item-content>
                    <v-list-item-title>{{
                      scrapedModules[i].name
                    }}</v-list-item-title>

                    <v-list-item-subtitle>
                      {{ scrapedModules[i].description }}
                    </v-list-item-subtitle>
                  </v-list-item-content>

                  <v-list-item-action>
                    <v-menu
                      :close-on-content-click="false"
                      :nudge-width="200"
                      offset-x
                      offset-y
                      transition="slide-y-transition"
                      bottom
                    >
                      <template v-slot:activator="{ on, attrs }">
                        <v-btn icon v-bind="attrs" v-on="on">
                          <v-icon color="grey darken-1">mdi-cog</v-icon>
                        </v-btn>
                      </template>
                      <v-expansion-panels accordion style="width: 100%">
                        <v-expansion-panel>
                          <v-expansion-panel-header disable-icon-rotate>
                            URL
                            <template v-slot:actions>
                              <v-icon> mdi-link </v-icon>
                            </template>
                          </v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <v-text-field
                              filled
                              label="Module URL"
                              v-model="m.url"
                            ></v-text-field>
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel>
                          <v-expansion-panel-header>
                            General settings
                            <template v-slot:actions>
                              <v-icon> mdi-script-text </v-icon>
                            </template>
                          </v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <prism-editor
                              class="prism-editor"
                              v-model="m.config"
                              :highlight="highlighter"
                              line-numbers>
                            </prism-editor>
                            
                            <!--v-textarea
                              filled
                              prepend-inner-icon="mdi-script-text"
                              label="General settings"
                              v-model="m.config"
                            ></v-textarea-->
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel>
                          <v-expansion-panel-header>
                            Student Settings
                            <template v-slot:actions>
                              <v-icon> mdi-account-circle-outline </v-icon>
                            </template>
                          </v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <prism-editor
                              class="prism-editor"
                              v-model="m.studentConfig"
                              :highlight="highlighter"
                              line-numbers>
                            </prism-editor>

                            <!--v-textarea
                              filled
                              prepend-inner-icon="mdi-account-circle-outline"
                              label="Student-only settings"
                              v-model="m.studentConfig"
                            ></v-textarea-->
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel>
                          <v-expansion-panel-header>
                            Teacher Settings
                            <template v-slot:actions>
                              <v-icon> mdi-clipboard-account-outline </v-icon>
                            </template>
                          </v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <prism-editor
                              class="prism-editor"
                              v-model="m.teacherConfig"
                              :highlight="highlighter"
                              line-numbers>
                            </prism-editor>
                            <!--v-textarea
                              filled
                              prepend-inner-icon="mdi-clipboard-account-outline"
                              label="Teacher-only settings"
                              v-model="m.teacherConfig"
                            ></v-textarea-->
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                        <v-expansion-panel>
                          <v-expansion-panel-header>
                            Station Settings
                            <template v-slot:actions>
                              <v-icon> mdi-router-wireless </v-icon>
                            </template>
                          </v-expansion-panel-header>
                          <v-expansion-panel-content>
                            <prism-editor
                              class="prism-editor"
                              v-model="m.stationConfig"
                              :highlight="highlighter"
                              line-numbers>
                            </prism-editor>
                            
                            <!--v-textarea
                              filled
                              prepend-inner-icon="mdi-router-wireless"
                              label="Station-only settings"
                              v-model="m.stationConfig"
                            ></v-textarea-->
                          </v-expansion-panel-content>
                        </v-expansion-panel>
                      </v-expansion-panels>
                    </v-menu>
                  </v-list-item-action>
                  <v-list-item-action>
                    <v-btn
                      icon
                      @click="
                        () => {
                          modules.splice(i, 1);
                        }
                      "
                    >
                      <v-icon color="grey darken-1">mdi-close</v-icon>
                    </v-btn>
                  </v-list-item-action>
                </v-list-item>
              </draggable>
            </v-list>
            <div v-else>
              <v-skeleton-loader
                class="mx-auto"
                type="list-item-avatar-two-line"
              ></v-skeleton-loader>
            </div>
            <v-list-item>
              <v-list-item-avatar>
                <v-icon class="grey darken-3" dark> mdi-link </v-icon>
              </v-list-item-avatar>

              <v-list-item-content>
                <v-text-field
                  v-model="moduleImportUrl"
                  label="Module URL"
                  required
                ></v-text-field>
              </v-list-item-content>
              <v-list-item-action>
                <v-btn
                  depressed
                  type="submit"
                  :disabled="!validate_url(moduleImportUrl)"
                >
                  <v-icon left> mdi-view-grid-plus </v-icon>
                  Add
                </v-btn>
              </v-list-item-action>
            </v-list-item>
          </v-form>
          <v-divider class="pb-2"></v-divider>
          <v-btn href="https://github.com/topics/edrys-module" target="_blank">
            <v-icon left> mdi-github </v-icon>
            Explore on GitHub
          </v-btn>
        </v-tab-item>
        <v-tab-item>
          To add a new station, simply open this link on the client device:
          <br />
          <br />
          <blockquote style="margin-left: 15px">
            <a :href="`//${stationUrl}`" target="_blank">{{ stationUrl }}</a>

            <v-btn icon small @click="copyStationUrl">
              <v-icon small>mdi-content-copy</v-icon>
            </v-btn>
          </blockquote>
          <br />
        </v-tab-item>
        <v-tab-item>
          <v-row>
            <v-col>
              <v-btn depressed block @click="downloadClass('yaml')">
                <v-icon left> mdi-download </v-icon>
                Download class file (.yml)
              </v-btn>
            </v-col>
            <v-col>
              <v-btn depressed block @click="downloadClass('json')">
                <v-icon left> mdi-download </v-icon>
                Download class file (.json)
              </v-btn>
            </v-col>
          </v-row>
          <v-row>
            <v-col>
              <v-file-input
                dense
                :rules="restoreFileRules"
                accept="application/yaml,application/json"
                label="Restore class from file (yaml, json)"
                @change="restoreFile"
                v-model="selectedFile"
                prepend-icon="mdi-upload"
              ></v-file-input>
            </v-col>
            <v-col>
              <v-text-field
                dense
                label="Load class from URL"
                v-model="selectedURL"
                @keyup.enter="restoreURL"
                prepend-icon="mdi-link"
              ></v-text-field>
            </v-col>
          </v-row>
        </v-tab-item>
      </v-tabs-items>
    </v-card-text>
    <v-snackbar
      :timeout="2000"
      :value="restoreSuccess"
      absolute
      bottom
      right
      color="success"
    >
      File restored - check everything is okay then save
    </v-snackbar>

    <v-snackbar :timeout="600" :value="saveSuccess" absolute bottom right>
      Class saved successfully
    </v-snackbar>

    <v-snackbar
      :timeout="1400"
      :value="saveError"
      color="error"
      absolute
      bottom
      right
    >
      Sorry there was a problem saving, please try again
    </v-snackbar>

    <v-card-actions>
      <div class="pr-4 float-right">
        <v-badge
          overlap
          dot
          color="red"
          style="margin-top: 30px"
          :value="pendingEdits"
        >
          <v-btn
            @click="save"
            color="primary"
            :loading="saveLoading"
            :disabled="saveLoading"
          >
            <v-icon left> mdi-upload </v-icon>
            Save</v-btn
          >
        </v-badge>
      </div>

      <v-menu offset-y>
        <template v-slot:activator="{ on, attrs }">
          <v-btn
            color=""
            depressed
            v-bind="attrs"
            v-on="on"
            class="float-right"
            style="margin-top: 30px; margin-right: 10px"
          >
            Delete Class</v-btn
          >
        </template>
        <v-list>
          <v-list-item>
            <v-list-item-content
              >Are you sure?

              <v-btn
                color="red"
                depressed
                @click="deleteClass"
                class="float-right"
                style="margin-top: 10px"
              >
                Yes, delete forever</v-btn
              >
            </v-list-item-content>
          </v-list-item>
        </v-list>
      </v-menu>
    </v-card-actions>
  </v-card>
</template>

<script>
const yaml = require('js-yaml')
// import Prism Editor
import { PrismEditor } from 'vue-prism-editor'
import 'vue-prism-editor/dist/prismeditor.min.css' // import the styles somewhere

// import highlighting library (you can use any library you want just return html string)
import { highlight, languages } from 'prismjs/components/prism-core';
import 'prismjs/components/prism-clike'
import 'prismjs/components/prism-javascript'
import 'prismjs/components/prism-json'
import 'prismjs/components/prism-yaml'
import 'prismjs/themes/prism-tomorrow.css' // import syntax highlighting styles

import draggable from "vuedraggable";

function parseClassroom(config) {
  try {
    return JSON.parse(config)
  } catch (e) {
    try {
      return yaml.load(config)
    } catch (e) {
      console.warn("could not parse content")
    }
  }

  return
}

export default {
  name: "Settings",
  props: ["pendingEdits"],
  data() {
    return {
      tab: 0,
      saveLoading: false,
      saveSuccess: false,
      memberTeacher: "",
      memberStudent: "",
      className: "",
      saveError: false,
      modules: [],
      pageLoading: true,
      stationUrl: "",
      memberUrl: "",
      moduleImportUrl: "",
      moduleImportUrlRules: [
        (v) => this.validate_url(v) || "Please enter a valid module URL",
      ],
      scrapedModules: [],
      selectedFile: undefined,
      selectedURL: undefined,
      restoreFileRules: [
        (value) =>
          !value || value.size < 2000000 || "File should be less than 2 MB!",
      ],
      restoreSuccess: false,
    };
  },
  computed: {
    newClass() {
      return {
        ...this.$store.state.class_,
        name: this.className,
        members: {
          teacher: this.strToList(this.memberTeacher),
          student: this.strToList(this.memberStudent),
        },
        modules: this.modules.map((m) => ({
          ...m,
          config: m.config,
          studentConfig: m.studentConfig,
          teacherConfig: m.teacherConfig,
          stationConfig: m.stationConfig,
        })),
      };
    },
  },
  watch: {
    "$store.state.class_"() {
      this.updateState();
    },
    newClass() {
      if (
        JSON.stringify(this.newClass) !==
        JSON.stringify(this.$store.state.class_)
      )
        this.$emit("update:pendingEdits", true);
    },
    async modules() {
      const scrapedModules = [];
      for (const m of this.modules) {
        scrapedModules.push(await this.scrapeModule(m));
      }
      this.scrapedModules = scrapedModules;
    },
  },
  mounted() {
    this.updateState();
  },
  methods: {
    downloadClass(format) {
      if (format === 'yaml') {
        this.download(
          `class-${this.$store.state.class_.id}.yml`,
          yaml.dump(this.$store.state.class_)
        );
      } else if (format === 'json') {
        this.download(
          `class-${this.$store.state.class_.id}.json`,
          JSON.stringify(this.$store.state.class_, null, 2)
        );
      }
    },
    async restoreURL() {
      this.restoreSuccess = false;
      this.saveError = false;

      const response = await fetch(this.selectedURL)

      if (response.ok) {
        const text = await response.text()

        const newClass = parseClassroom(text)

        if (newClass) {
          this.updateState(newClass);
          this.restoreSuccess = true;
          return
        }
      }

      console.warn("could not parse the content within the URL:", this.selectedURL)
    },
    restoreFile(e) {
      this.restoreSuccess = false;
      this.saveError = false;
      const reader = new FileReader();
      reader.readAsText(this.selectedFile);
      reader.onload = (res) => {
        // will load yaml and json as well
        const newClass = parseClassroom(res.target.result)

        if (newClass) {
          this.updateState(newClass);
          this.restoreSuccess = true;
        } else {
          this.restoreSuccess = false
          this.saveError = true;
        }
      };
      reader.onerror = (err) => {
        this.restoreSuccess = false;
        this.saveError = true;
      };
    },
    validate_url(url) {
      try {
        new URL(url);
        return true;
      } catch (_error) {
        return false;
      }
    },
    updateState(class_ = undefined) {
      class_ = class_ || this.$store.state.class_;
      this.className = class_.name;
      this.memberTeacher = class_.members?.teacher.join("\n") || "";
      this.memberStudent = class_.members?.student?.join("\n") || "";
      this.modules =
        [
        ...class_?.modules.map((m) => {
          return {
            ...m,
            config: yaml.dump(m.config),
            studentConfig: yaml.dump(m.studentConfig),
            teacherConfig: yaml.dump(m.teacherConfig),
            stationConfig: yaml.dump(m.stationConfig),
          }}),
        ] || [];
      this.memberUrl = window.location.href
        .replace("#station", "")
        .replace("http://", "")
        .replace("https://", "");
      this.stationUrl =
        window.location.href
          .replace("#settings", "")
          .replace("#station", "")
          .replace("http://", "")
          .replace("https://", "") + "#station";
    },
    copyStationUrl() {
      navigator.clipboard.writeText(this.stationUrl);
    },
    copyMemberUrl() {
      navigator.clipboard.writeText(this.memberUrl);
    },
    async deleteClass() {
      const class_id = this.$store.state.class_.id;
      try {
        await this.$axios.$get(`/data/deleteClass/${class_id}`);
      } catch (error) {
        console.log("Error deleting class...");
        return;
      }
      const user = await this.$axios.$get(`/data/readUser`);
      this.$store.commit(
        "setUser",
        await this.$axios.$get(
          `/data/updateUser?user=${encodeURIComponent(
            JSON.stringify({
              ...user,
              memberships: user.memberships.filter(
                (m) => m.class_id != class_id
              ),
            })
          )}`
        )
      );

      this.$router.push({
        path: `/`,
      });
    },
    strToList(str) {
      return str
        .replace(/ /g, "")
        .split(",")
        .flatMap((s) => s.trim().split("\n"))
        .filter((e) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e));
    },
    importModule() {
      this.modules.push({
        url: this.moduleImportUrl,
        config: "",
        studentConfig: "",
        teacherConfig: "",
        stationConfig: "",
        width: "full",
        height: "tall",
      });
      this.moduleImportUrl = "";
    },
    async save() {

      let newClass = this.newClass

      newClass.modules = newClass.modules.map((m) => {
        return {
          ...m,
          config: yaml.load(m.config),
          studentConfig: yaml.load(m.studentConfig),
          teacherConfig: yaml.load(m.teacherConfig),
          stationConfig: yaml.load(m.stationConfig),
        }
      })

      this.saveError = false;
      this.saveSuccess = false;
      this.saveLoading = true;
      try {
        this.$store.commit(
          "setClass",
          await this.$axios.$get(
            `/data/updateClass/${this.$store.state.class_.id}` +
              `?class=${encodeURIComponent(JSON.stringify(newClass))}`
          )
        );

        this.saveLoading = false;
        this.saveSuccess = true;
        this.$emit("update:pendingEdits", false);
        this.$emit("close");
      } catch (error) {
        console.log(error);
        this.saveError = true;
        this.saveLoading = false;
      }
      this.$router.app.refresh();
    },

    highlighter(code) {
      // js highlight example
      return highlight(code, languages.yaml, "yaml");
    },
  },
  components: {
    PrismEditor,
    draggable,
  },
};
</script>

<style>
.prism-editor {
  /* we dont use `language-` classes anymore so thats why we need to add background and text color manually */
  background: #2d2d2d;
  color: #ccc;

  /* you must provide font-family font-size line-height. Example: */
  font-family: Fira code, Fira Mono, Consolas, Menlo, Courier, monospace;
  font-size: 14px;
  line-height: 1.5;
  padding: 5px;

  max-height: 60 vh;
}
</style>

