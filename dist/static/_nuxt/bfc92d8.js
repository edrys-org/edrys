(window.webpackJsonp=window.webpackJsonp||[]).push([[7,6],{501:function(e,t,r){var content=r(507);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[e.i,content,""]]),content.locals&&(e.exports=content.locals);(0,r(20).default)("87813c46",content,!0,{sourceMap:!1})},503:function(e,t,r){"use strict";r.r(t);var o=r(143);r(4),r(46),r(54),r(505),r(301),r(13),r(11),r(14),r(16),r(12),r(17);function d(object,e){var t=Object.keys(object);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(object);e&&(r=r.filter((function(e){return Object.getOwnPropertyDescriptor(object,e).enumerable}))),t.push.apply(t,r)}return t}var n={name:"Module",props:["role","username","liveClassProxy","scrapedModule"],data:function(){return{}},computed:{iframeOrigin:function(){return new URL(this.scrapedModule.url).origin}},watch:{liveClassProxy:function(){this.updateIframe()},"$store.state.lastRecievedMessage":function(e){null!=e&&this.$refs.iframe.contentWindow.postMessage(function(e){for(var i=1;i<arguments.length;i++){var source=null!=arguments[i]?arguments[i]:{};i%2?d(Object(source),!0).forEach((function(t){Object(o.a)(e,t,source[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(source)):d(Object(source)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(source,t))}))}return e}({event:"message"},e),this.iframeOrigin)}},methods:{updateIframe:function(){console.log(this.$store.state.class_),this.$refs.iframe.contentWindow.postMessage({event:"update",origin:window.origin,role:this.role,username:this.username,liveClass:JSON.parse(JSON.stringify(this.liveClassProxy)),module:this.scrapedModule,class_id:this.$store.state.class_.id},this.iframeOrigin)}}},l=n,c=r(107),component=Object(c.a)(l,(function(){var e=this,t=e.$createElement,r=e._self._c||t;return r("div",{staticStyle:{height:"100%",width:"100%"}},[r("iframe",{ref:"iframe",staticStyle:{height:"100%",width:"100%"},attrs:{src:e.scrapedModule.url.startsWith("data:")?null:e.scrapedModule.url,srcdoc:e.scrapedModule.url.startsWith("data:")?e.scrapedModule.url:null,allow:"camera; microphone; fullscreen; display-capture;",scrolling:"",frameborder:"0"},on:{load:e.updateIframe}})])}),[],!1,null,"6dfcdffe",null);t.default=component.exports},504:function(e,t,r){"use strict";r.r(t);var o=r(85),d=(r(218),r(98),r(14),r(4),r(37),r(55),r(32),{name:"Modules",props:["role","username","liveClassProxy"],data:function(){return{}},computed:{roomName:function(){return this.liveClassProxy.users[this.$store.state.user.email].room},modules_type:function(){return this.roomName.startsWith("Station ")?"station":"chat"},scrapedModules:function(){var e=this;return this.$store.state.scrapedModules.filter((function(t){return t.shownIn.includes(e.modules_type)||"*"==t.shownIn}))}},created:function(){window.addEventListener("message",this.messageHandler)},beforeDestroy:function(){window.removeEventListener("message",this.messageHandler)},mounted:function(){return Object(o.a)(regeneratorRuntime.mark((function e(){return regeneratorRuntime.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:case"end":return e.stop()}}),e)})))()},methods:{messageHandler:function(e){switch(e.data.event){case"message":this.sendMessage(e.data.subject,e.data.body);break;case"update":this.setToValue(this.liveClassProxy,e.data.path,e.data.value);break;case"echo":console.log("ECHO:",e.data)}},sendMessage:function(e,body){var t=this;return Object(o.a)(regeneratorRuntime.mark((function r(){return regeneratorRuntime.wrap((function(r){for(;;)switch(r.prev=r.next){case 0:return r.next=2,t.$axios.$get("/data/sendMessage/".concat(t.$store.state.class_.id,"?message=").concat(encodeURIComponent(JSON.stringify({from:t.username,subject:e,body:body}))));case 2:case"end":return r.stop()}}),r)})))()}}}),n=(r(506),r(107)),l=r(142),c=r.n(l),h=r(209),f=r(97),m=r(612),v=r(613),component=Object(n.a)(d,(function(){var e=this,t=e.$createElement,r=e._self._c||t;return r("div",{key:e.role},[e._l(e.scrapedModules,(function(t,i){return r("v-row",{key:i,style:{display:e.scrapedModules[i-1]&&"half"==e.scrapedModules[i-1].width&&"half"==e.scrapedModules[i].width||e.scrapedModules[i-1]&&"third"==e.scrapedModules[i-1].width&&"third"==e.scrapedModules[i].width||e.scrapedModules[i-2]&&"third"==e.scrapedModules[i-2].width&&"third"==e.scrapedModules[i-1].width&&"third"==e.scrapedModules[i].width?"none":"",height:"tall"==t.height?"700px":"short"==t.height?"300px":"500px"}},[["full","half","third"].includes(e.scrapedModules[i].width)?r("v-col",[r("Module",{attrs:{username:e.username,"live-class-proxy":e.liveClassProxy,scrapedModule:e.scrapedModules[i],role:e.role}})],1):e._e(),e._v(" "),e.scrapedModules[i+1]&&e.scrapedModules[i+1].width==e.scrapedModules[i].width&&["half","third"].includes(e.scrapedModules[i].width)?r("v-col",[r("Module",{attrs:{username:e.username,"live-class-proxy":e.liveClassProxy,scrapedModule:e.scrapedModules[i+1],role:e.role}})],1):["half","third"].includes(e.scrapedModules[i].width)?r("v-col"):e._e(),e._v(" "),e.scrapedModules[i+2]&&e.scrapedModules[i+1].width==e.scrapedModules[i].width&&e.scrapedModules[i+2].width==e.scrapedModules[i].width&&["third"].includes(e.scrapedModules[i+2].width)?r("v-col",[r("Module",{attrs:{role:e.role,username:e.username,"live-class-proxy":e.liveClassProxy,scrapedModule:e.scrapedModules[i+2]}})],1):["third"].includes(e.scrapedModules[i].width)?r("v-col"):e._e()],1)})),e._v(" "),e.scrapedModules.length?e._e():r("v-card",["teacher"==e.role||"station"==e.role?r("v-card-text",[e._v("\n      Sorry, looks like you have not loaded up any "+e._s(e.modules_type)+" modules.\n      Add some in the class settings to get started.\n    ")]):e._e(),e._v(" "),"student"==e.role?r("v-card-text",[e._v("\n      Sorry, it looks like the class creators have not added any modules yet.\n    ")]):e._e()],1)],2)}),[],!1,null,"679932d6",null);t.default=component.exports;c()(component,{Module:r(503).default}),c()(component,{VCard:h.a,VCardText:f.c,VCol:m.a,VRow:v.a})},506:function(e,t,r){"use strict";r(501)},507:function(e,t,r){var o=r(19)(!1);o.push([e.i,".row[data-v-679932d6]{margin:0!important;height:100%}.col[data-v-679932d6],.row[data-v-679932d6]{padding:0}",""]),e.exports=o}}]);