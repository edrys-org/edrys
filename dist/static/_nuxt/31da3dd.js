(window.webpackJsonp=window.webpackJsonp||[]).push([[1],{551:function(t,e,n){"use strict";n.r(e);n(13),n(11),n(16),n(12),n(17),n(56),n(61),n(67),n(78);var r=n(550),o=n(84),l=n(145),c=(n(218),n(62),n(4),n(46),n(54),n(540),n(302),n(38),n(100),n(26),n(72),n(14),n(557),n(558),n(68),n(85),n(541));function v(t,e){var n="undefined"!=typeof Symbol&&t[Symbol.iterator]||t["@@iterator"];if(!n){if(Array.isArray(t)||(n=function(t,e){if(!t)return;if("string"==typeof t)return d(t,e);var n=Object.prototype.toString.call(t).slice(8,-1);"Object"===n&&t.constructor&&(n=t.constructor.name);if("Map"===n||"Set"===n)return Array.from(t);if("Arguments"===n||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n))return d(t,e)}(t))||e&&t&&"number"==typeof t.length){n&&(t=n);var i=0,r=function(){};return{s:r,n:function(){return i>=t.length?{done:!0}:{done:!1,value:t[i++]}},e:function(t){throw t},f:r}}throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}var o,l=!0,c=!1;return{s:function(){n=n.call(t)},n:function(){var t=n.next();return l=t.done,t},e:function(t){c=!0,o=t},f:function(){try{l||null==n.return||n.return()}finally{if(c)throw o}}}}function d(t,e){(null==e||e>t.length)&&(e=t.length);for(var i=0,n=new Array(e);i<e;i++)n[i]=t[i];return n}function m(object,t){var e=Object.keys(object);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(object);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(object,t).enumerable}))),e.push.apply(e,n)}return e}function f(t){for(var i=1;i<arguments.length;i++){var source=null!=arguments[i]?arguments[i]:{};i%2?m(Object(source),!0).forEach((function(e){Object(l.a)(t,e,source[e])})):Object.getOwnPropertyDescriptors?Object.defineProperties(t,Object.getOwnPropertyDescriptors(source)):m(Object(source)).forEach((function(e){Object.defineProperty(t,e,Object.getOwnPropertyDescriptor(source,e))}))}return t}var h={name:"Settings",data:function(){var t=this;return{saveLoading:!1,saveSuccess:!1,memberTeacher:"",memberStudent:"",className:"",saveError:!1,modules:[],pageLoading:!0,stationUrl:"",memberUrl:"",moduleImportUrl:"",pendingEdits:!1,moduleImportUrlRules:[function(t){return!!t||"URL required"},function(e){return t.validate_url(e)||"Please enter a valid module URL"}],scrapedModules:[],selectedFile:void 0,restoreFileRules:[function(t){return!t||t.size<2e6||"File should be less than 2 MB!"}],restoreSuccess:!1}},computed:{newClass:function(){return f(f({},this.$store.state.class_),{},{name:this.className,members:{teacher:this.strToList(this.memberTeacher),student:this.strToList(this.memberStudent)},modules:this.modules.map((function(t){return f(f({},t),{},{config:"string"==typeof t.config?JSON.parse(t.config):t.config,studentConfig:"string"==typeof t.studentConfig?JSON.parse(t.studentConfig):t.studentConfig,teacherConfig:"string"==typeof t.teacherConfig?JSON.parse(t.teacherConfig):t.teacherConfig,stationConfig:"string"==typeof t.stationConfig?JSON.parse(t.stationConfig):t.stationConfig})}))})}},watch:{"$store.state.class_":function(){this.updateState()},newClass:function(){JSON.stringify(this.newClass)!==JSON.stringify(this.$store.state.class_)&&(this.pendingEdits=!0)},modules:function(){var t=this;return Object(o.a)(regeneratorRuntime.mark((function e(){var n,r,o,l;return regeneratorRuntime.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:n=[],r=v(t.modules),e.prev=2,r.s();case 4:if((o=r.n()).done){e.next=13;break}return l=o.value,e.t0=n,e.next=9,t.scrapeModule(l);case 9:e.t1=e.sent,e.t0.push.call(e.t0,e.t1);case 11:e.next=4;break;case 13:e.next=18;break;case 15:e.prev=15,e.t2=e.catch(2),r.e(e.t2);case 18:return e.prev=18,r.f(),e.finish(18);case 21:t.scrapedModules=n;case 22:case"end":return e.stop()}}),e,null,[[2,15,18,21]])})))()}},mounted:function(){this.updateState()},methods:{downloadClass:function(){this.download("class-".concat(this.$store.state.class_.id,".json"),JSON.stringify(this.$store.state.class_))},restoreFile:function(t){var e=this;this.restoreSuccess=!1,this.saveError=!1;var n=new FileReader;n.readAsText(this.selectedFile),n.onload=function(t){e.updateState(JSON.parse(t.target.result)),e.restoreSuccess=!0},n.onerror=function(t){e.restoreSuccess=!1,e.saveError=!0}},validate_url:function(t){try{return new URL(t),!0}catch(t){return!1}},updateState:function(){var t,e,n,o,l=arguments.length>0&&void 0!==arguments[0]?arguments[0]:void 0;l=l||this.$store.state.class_,this.className=l.name,this.memberTeacher=(null===(t=l.members)||void 0===t?void 0:t.teacher.join("\n"))||"",this.memberStudent=(null===(e=l.members)||void 0===e||null===(n=e.student)||void 0===n?void 0:n.join("\n"))||"",this.modules=Object(r.a)(null===(o=l)||void 0===o?void 0:o.modules.map((function(t){return f(f({},t),{},{config:JSON.stringify(t.config),studentConfig:JSON.stringify(t.studentConfig),teacherConfig:JSON.stringify(t.teacherConfig),stationConfig:JSON.stringify(t.stationConfig)})})))||[],this.memberUrl=window.location.href.replace("?station=true","").replace("http://","").replace("https://",""),this.stationUrl=window.location.href.replace("#settings","").replace("?station=true","").replace("http://","").replace("https://","")+"?station=true"},copyStationUrl:function(){navigator.clipboard.writeText(this.stationUrl)},copyMemberUrl:function(){navigator.clipboard.writeText(this.memberUrl)},deleteClass:function(){var t=this;return Object(o.a)(regeneratorRuntime.mark((function e(){var n,r;return regeneratorRuntime.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return n=t.$store.state.class_.id,e.prev=1,e.next=4,t.$axios.$get("/data/deleteClass/".concat(n));case 4:e.next=10;break;case 6:return e.prev=6,e.t0=e.catch(1),console.log("Error deleting class..."),e.abrupt("return");case 10:return e.next=12,t.$axios.$get("/data/readUser");case 12:return r=e.sent,e.t1=t.$store,e.next=16,t.$axios.$get("/data/updateUser?user=".concat(encodeURIComponent(JSON.stringify(f(f({},r),{},{memberships:r.memberships.filter((function(t){return t.class_id!=n}))})))));case 16:e.t2=e.sent,e.t1.commit.call(e.t1,"setUser",e.t2),t.$router.push({path:"/"});case 19:case"end":return e.stop()}}),e,null,[[1,6]])})))()},strToList:function(t){return t.replace(/ /g,"").split(",").flatMap((function(s){return s.trim().split("\n")})).filter((function(t){return/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(t)}))},importModule:function(){this.modules.push({url:this.moduleImportUrl,config:{},studentConfig:{},teacherConfig:{},stationConfig:{},width:"full",height:"medium"})},save:function(){var t=this;return Object(o.a)(regeneratorRuntime.mark((function e(){return regeneratorRuntime.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return t.saveError=!1,t.saveSuccess=!1,t.saveLoading=!0,e.prev=3,e.t0=t.$store,e.next=7,t.$axios.$get("/data/updateClass/".concat(t.$store.state.class_.id)+"?class=".concat(encodeURIComponent(JSON.stringify(t.newClass))));case 7:e.t1=e.sent,e.t0.commit.call(e.t0,"setClass",e.t1),t.saveLoading=!1,t.saveSuccess=!0,t.pendingEdits=!1,e.next=19;break;case 14:e.prev=14,e.t2=e.catch(3),console.log(e.t2),t.saveError=!0,t.saveLoading=!1;case 19:t.$router.app.refresh();case 20:case"end":return e.stop()}}),e,null,[[3,14]])})))()}},components:{draggable:n.n(c).a}},_=h,x=n(107),y=n(143),S=n.n(y),k=n(614),C=n(615),w=n(228),O=n(208),V=n(97),U=n(530),$=n(563),L=n(616),N=n(617),j=n(618),T=n(619),E=n(628),R=n(494),I=n(204),M=n(544),J=n(535),P=n(545),F=n(552),A=n(502),D=n(629),H=n(627),B=n(620),G=n(531),z=n(621),W=n(497),Y=n(498),K=n(622),Q=n(630),X=n(625),Z=n(223),tt=n(623),component=Object(x.a)(_,(function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("v-row",{staticClass:"pt-5 pb-3 mb-3",staticStyle:{"border-bottom":"black 1px dotted"},attrs:{justify:"center",align:"center"}},[n("v-col",{attrs:{cols:"12",sm:"8",md:"8"}},[n("v-card",[n("v-card-title",[t._v("\n        Class Settings\n        "),n("v-spacer"),t._v(" "),n("v-btn",{attrs:{icon:""},on:{click:function(e){return t.$emit("close")}}},[n("v-icon",[t._v("mdi-close")])],1)],1),t._v(" "),n("v-tabs",{attrs:{"fixed-tabs":"","center-active":"","show-arrows":""}},[n("v-tab",{attrs:{active:""}},[n("v-icon",{attrs:{left:""}},[t._v(" mdi-book-open-outline ")]),t._v("\n          Settings\n        ")],1),t._v(" "),n("v-tab",[n("v-icon",{attrs:{left:""}},[t._v(" mdi-account-group ")]),t._v("\n          Members\n        ")],1),t._v(" "),n("v-tab",[n("v-icon",{attrs:{left:""}},[t._v(" mdi-view-dashboard ")]),t._v("\n          Modules\n        ")],1),t._v(" "),n("v-tab",[n("v-icon",{attrs:{left:""}},[t._v(" mdi-router-wireless ")]),t._v("\n          Stations\n        ")],1),t._v(" "),n("v-tab",[n("v-icon",{attrs:{left:""}},[t._v(" mdi-file-download ")]),t._v("\n          Export\n        ")],1),t._v(" "),n("v-tab-item",[n("v-card",{attrs:{flat:""}},[n("v-card-text",[n("v-form",{ref:"form",on:{submit:function(e){return e.preventDefault(),t.save.apply(null,arguments)}}},[n("v-text-field",{attrs:{counter:20,label:"Class Name",required:""},model:{value:t.className,callback:function(e){t.className=e},expression:"className"}})],1)],1)],1)],1),t._v(" "),n("v-tab-item",[n("v-card",{attrs:{flat:""}},[n("v-card-text",[n("v-alert",{attrs:{type:"info",outlined:""}},[t._v("\n                Enter emails below, one per line or separated by commas. Next,\n                invite your users in by sharing this link (as users are not\n                notified of their addition here):\n                "),n("br"),t._v(" "),n("br"),t._v(" "),n("blockquote",{staticStyle:{"margin-left":"10px"}},[n("code",[t._v(t._s(t.memberUrl))]),t._v(" "),n("v-btn",{attrs:{icon:"",small:""},on:{click:t.copyMemberUrl}},[n("v-icon",{attrs:{small:""}},[t._v("mdi-content-copy")])],1)],1)]),t._v(" "),n("v-textarea",{attrs:{outlined:"",label:"List of teacher emails"},model:{value:t.memberTeacher,callback:function(e){t.memberTeacher=e},expression:"memberTeacher"}}),t._v(" "),n("v-textarea",{attrs:{outlined:"",label:"List of student emails"},model:{value:t.memberStudent,callback:function(e){t.memberStudent=e},expression:"memberStudent"}})],1)],1)],1),t._v(" "),n("v-tab-item",[n("v-card",{attrs:{flat:""}},[n("v-card-text",[n("v-btn",{attrs:{depressed:"",block:"",tile:"",href:"https://github.com/topics/Edrys",target:"_blank"}},[n("v-icon",{attrs:{left:""}},[t._v(" mdi-github ")]),t._v("\n                Explore modules on GitHub\n              ")],1),t._v(" "),n("v-form",{on:{submit:function(e){return e.preventDefault(),t.importModule.apply(null,arguments)}}},[n("v-list-item",[n("v-list-item-avatar",[n("v-icon",{staticClass:"grey darken-3",attrs:{dark:""}},[t._v(" mdi-link ")])],1),t._v(" "),n("v-list-item-content",[n("v-text-field",{attrs:{rules:t.moduleImportUrlRules,label:"Module URL",required:""},model:{value:t.moduleImportUrl,callback:function(e){t.moduleImportUrl=e},expression:"moduleImportUrl"}})],1),t._v(" "),n("v-list-item-action",[n("v-btn",{attrs:{depressed:"",type:"submit",disabled:!t.validate_url(t.moduleImportUrl)}},[n("v-icon",{attrs:{left:""}},[t._v(" mdi-view-grid-plus ")]),t._v("\n                      Add\n                    ")],1)],1)],1)],1),t._v(" "),t.scrapedModules.length==t.modules.length?n("v-list",{attrs:{"two-line":""}},[n("draggable",{attrs:{handle:".handle"},model:{value:t.modules,callback:function(e){t.modules=e},expression:"modules"}},t._l(t.modules,(function(e,i){return n("v-list-item",{key:i,staticClass:"handle"},[n("v-list-item-avatar",[n("v-icon",{staticClass:"grey darken-3",attrs:{dark:""}},[t._v(t._s(t.scrapedModules[i].icon||"mdi-package")+"\n                      ")])],1),t._v(" "),n("v-list-item-content",[n("v-list-item-title",[t._v(t._s(t.scrapedModules[i].name))]),t._v(" "),n("v-list-item-subtitle",[t._v("\n                        "+t._s(t.scrapedModules[i].description)+"\n                      ")])],1),t._v(" "),n("v-list-item-action",[n("v-menu",{attrs:{"close-on-content-click":!1,"nudge-width":200,"offset-x":"","offset-y":"",transition:"slide-y-transition",bottom:""},scopedSlots:t._u([{key:"activator",fn:function(e){var r=e.on,o=e.attrs;return[n("v-btn",t._g(t._b({attrs:{icon:""}},"v-btn",o,!1),r),[n("v-icon",{attrs:{color:"grey darken-1"}},[t._v("mdi-cog")])],1)]}}],null,!0)},[t._v(" "),n("v-expansion-panels",{staticStyle:{width:"300px"},attrs:{accordion:""}},[n("v-expansion-panel",[n("v-expansion-panel-header",{attrs:{"disable-icon-rotate":""},scopedSlots:t._u([{key:"actions",fn:function(){return[n("v-icon",[t._v(" mdi-link ")])]},proxy:!0}],null,!0)},[t._v("\n                              URL\n                              ")]),t._v(" "),n("v-expansion-panel-content",[n("v-textarea",{attrs:{filled:"",label:"Module URL"},model:{value:e.url,callback:function(n){t.$set(e,"url",n)},expression:"m.url"}})],1)],1),t._v(" "),n("v-expansion-panel",[n("v-expansion-panel-header",{attrs:{"disable-icon-rotate":""},scopedSlots:t._u([{key:"actions",fn:function(){return[n("v-icon",[t._v(" mdi-pencil-ruler ")])]},proxy:!0}],null,!0)},[t._v("\n                              Design\n                              ")]),t._v(" "),n("v-expansion-panel-content",[n("v-row",[n("v-col",[n("div",{staticClass:"subtitle-2"},[t._v("Width")]),t._v(" "),n("v-radio-group",{model:{value:e.width,callback:function(n){t.$set(e,"width",n)},expression:"m.width"}},[n("v-radio",{attrs:{label:"Full",value:"full"}}),t._v(" "),n("v-radio",{attrs:{label:"Half",value:"half"}}),t._v(" "),n("v-radio",{attrs:{label:"Third",value:"third"}})],1)],1),t._v(" "),n("v-col",[n("div",{staticClass:"subtitle-2"},[t._v("Height")]),t._v(" "),n("v-radio-group",{model:{value:e.height,callback:function(n){t.$set(e,"height",n)},expression:"m.height"}},[n("v-radio",{attrs:{label:"Tall",value:"tall"}}),t._v(" "),n("v-radio",{attrs:{label:"Medium",value:"medium"}}),t._v(" "),n("v-radio",{attrs:{label:"Short",value:"short"}})],1)],1)],1)],1)],1),t._v(" "),n("v-expansion-panel",[n("v-expansion-panel-header",{attrs:{"disable-icon-rotate":""},scopedSlots:t._u([{key:"actions",fn:function(){return[n("v-icon",[t._v(" mdi-script-text ")])]},proxy:!0}],null,!0)},[t._v("\n                              General Settings\n                              ")]),t._v(" "),n("v-expansion-panel-content",[n("v-textarea",{attrs:{filled:"",label:"Paste JSON here"},model:{value:e.config,callback:function(n){t.$set(e,"config",n)},expression:"m.config"}})],1)],1),t._v(" "),n("v-expansion-panel",[n("v-expansion-panel-header",{attrs:{"disable-icon-rotate":""},scopedSlots:t._u([{key:"actions",fn:function(){return[n("v-icon",[t._v(" mdi-account-circle-outline ")])]},proxy:!0}],null,!0)},[t._v("\n                              Student Settings\n                              ")]),t._v(" "),n("v-expansion-panel-content",[n("v-textarea",{attrs:{filled:"",label:"Paste JSON here"},model:{value:e.studentConfig,callback:function(n){t.$set(e,"studentConfig",n)},expression:"m.studentConfig"}})],1)],1),t._v(" "),n("v-expansion-panel",[n("v-expansion-panel-header",{attrs:{"disable-icon-rotate":""},scopedSlots:t._u([{key:"actions",fn:function(){return[n("v-icon",[t._v("\n                                  mdi-clipboard-account-outline\n                                ")])]},proxy:!0}],null,!0)},[t._v("\n                              Teacher Settings\n                              ")]),t._v(" "),n("v-expansion-panel-content",[n("v-textarea",{attrs:{filled:"",label:"Paste JSON here"},model:{value:e.teacherConfig,callback:function(n){t.$set(e,"teacherConfig",n)},expression:"m.teacherConfig"}})],1)],1),t._v(" "),n("v-expansion-panel",[n("v-expansion-panel-header",{attrs:{"disable-icon-rotate":""},scopedSlots:t._u([{key:"actions",fn:function(){return[n("v-icon",[t._v(" mdi-router-wireless ")])]},proxy:!0}],null,!0)},[t._v("\n                              Station Settings\n                              ")]),t._v(" "),n("v-expansion-panel-content",[n("v-textarea",{attrs:{filled:"",label:"Paste JSON here"},model:{value:e.stationConfig,callback:function(n){t.$set(e,"stationConfig",n)},expression:"m.stationConfig"}})],1)],1)],1)],1)],1),t._v(" "),n("v-list-item-action",[n("v-btn",{attrs:{icon:""},on:{click:function(){t.modules.splice(i,1)}}},[n("v-icon",{attrs:{color:"grey darken-1"}},[t._v("mdi-close")])],1)],1)],1)})),1)],1):n("div",[n("v-skeleton-loader",{staticClass:"mx-auto",attrs:{type:"list-item-avatar-two-line"}})],1)],1)],1)],1),t._v(" "),n("v-tab-item",[n("v-card",{attrs:{flat:""}},[n("v-card-text",[t._v("\n              To add a new station, simply open this link on the client\n              device, and modules will be automatically loaded. Make sure to\n              log in as a teacher.\n              "),n("br"),t._v(" "),n("br"),t._v(" "),n("blockquote",{staticStyle:{"margin-left":"15px"}},[n("code",[t._v(t._s(t.stationUrl))]),t._v(" "),n("v-btn",{attrs:{icon:"",small:""},on:{click:t.copyStationUrl}},[n("v-icon",{attrs:{small:""}},[t._v("mdi-content-copy")])],1)],1),t._v(" "),n("br")])],1)],1),t._v(" "),n("v-tab-item",[n("v-card",{attrs:{flat:""}},[n("v-card-text",[n("v-btn",{attrs:{depressed:"",block:""},on:{click:t.downloadClass}},[n("v-icon",{attrs:{left:""}},[t._v(" mdi-download ")]),t._v("\n                Download class file\n              ")],1),t._v(" "),n("v-divider",{staticClass:"mb-4 mt-5"}),t._v(" "),n("v-file-input",{attrs:{outlined:"",filled:"",dense:"",rules:t.restoreFileRules,accept:"application/json",label:"Restore class from file","prepend-icon":"mdi-upload"},on:{change:t.restoreFile},model:{value:t.selectedFile,callback:function(e){t.selectedFile=e},expression:"selectedFile"}})],1)],1)],1)],1),t._v(" "),n("v-snackbar",{attrs:{timeout:2e3,value:t.restoreSuccess,absolute:"",bottom:"",right:"",color:"success"}},[t._v("\n        File restored - check everything is okay then save\n      ")]),t._v(" "),n("v-snackbar",{attrs:{timeout:600,value:t.saveSuccess,absolute:"",bottom:"",right:""}},[t._v("\n        Class saved successfully\n      ")]),t._v(" "),n("v-snackbar",{attrs:{timeout:1400,value:t.saveError,color:"error",absolute:"",bottom:"",right:""}},[t._v("\n        Sorry there was a problem saving, please try again\n      ")]),t._v(" "),n("v-badge",{staticClass:"float-right",staticStyle:{"margin-top":"30px"},attrs:{overlap:"",dot:"",color:"red",value:t.pendingEdits}},[n("v-btn",{attrs:{color:"primary",loading:t.saveLoading,disabled:t.saveLoading},on:{click:t.save}},[n("v-icon",{attrs:{left:""}},[t._v(" mdi-upload ")]),t._v("\n          Save")],1)],1),t._v(" "),n("v-menu",{attrs:{"offset-y":""},scopedSlots:t._u([{key:"activator",fn:function(e){var r=e.on,o=e.attrs;return[n("v-btn",t._g(t._b({staticClass:"float-right",staticStyle:{"margin-top":"30px","margin-right":"10px"},attrs:{color:"",depressed:""}},"v-btn",o,!1),r),[t._v("\n            Delete Class")])]}}])},[t._v(" "),n("v-list",[n("v-list-item",[n("v-list-item-content",[t._v("Are you sure?\n\n              "),n("v-btn",{staticClass:"float-right",staticStyle:{"margin-top":"10px"},attrs:{color:"red",depressed:""},on:{click:t.deleteClass}},[t._v("\n                Yes, delete forever")])],1)],1)],1)],1)],1)],1)],1)}),[],!1,null,null,null);e.default=component.exports;S()(component,{VAlert:k.a,VBadge:C.a,VBtn:w.a,VCard:O.a,VCardText:V.c,VCardTitle:V.d,VCol:U.a,VDivider:$.a,VExpansionPanel:L.a,VExpansionPanelContent:N.a,VExpansionPanelHeader:j.a,VExpansionPanels:T.a,VFileInput:E.a,VForm:R.a,VIcon:I.a,VList:M.a,VListItem:J.a,VListItemAction:P.a,VListItemAvatar:F.a,VListItemContent:A.a,VListItemSubtitle:A.b,VListItemTitle:A.c,VMenu:D.a,VRadio:H.a,VRadioGroup:B.a,VRow:G.a,VSkeletonLoader:z.a,VSnackbar:W.a,VSpacer:Y.a,VTab:K.a,VTabItem:Q.a,VTabs:X.a,VTextField:Z.a,VTextarea:tt.a})}}]);