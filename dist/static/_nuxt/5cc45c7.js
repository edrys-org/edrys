(window.webpackJsonp=window.webpackJsonp||[]).push([[6],{498:function(e,r,t){"use strict";t.r(r);var o=t(2);t(4),t(53),t(64),t(497),t(295),t(13),t(12),t(14),t(15),t(11),t(16);function n(object,e){var r=Object.keys(object);if(Object.getOwnPropertySymbols){var t=Object.getOwnPropertySymbols(object);e&&(t=t.filter((function(e){return Object.getOwnPropertyDescriptor(object,e).enumerable}))),r.push.apply(r,t)}return r}var c={name:"Module",props:["role","username","liveClassProxy","scrapedModule"],data:function(){return{}},computed:{iframeOrigin:function(){return new URL(this.scrapedModule.url).origin}},watch:{liveClassProxy:function(){this.updateIframe()},"$store.state.lastRecievedMessage":function(e){null!=e&&this.$refs.iframe.contentWindow.postMessage(function(e){for(var i=1;i<arguments.length;i++){var source=null!=arguments[i]?arguments[i]:{};i%2?n(Object(source),!0).forEach((function(r){Object(o.a)(e,r,source[r])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(source)):n(Object(source)).forEach((function(r){Object.defineProperty(e,r,Object.getOwnPropertyDescriptor(source,r))}))}return e}({event:"message"},e),this.iframeOrigin)}},methods:{updateIframe:function(){this.$refs.iframe.contentWindow.postMessage({event:"update",origin:window.origin,role:this.role,username:this.username,liveClass:JSON.parse(JSON.stringify(this.liveClassProxy)),module:this.scrapedModule,class_id:this.$store.state.class_.id},this.iframeOrigin)}}},l=c,d=t(107),component=Object(d.a)(l,(function(){var e=this,r=e.$createElement,t=e._self._c||r;return t("div",{key:e.scrapedModule.url,staticStyle:{height:"100%",width:"100%"}},[t("iframe",{key:e.liveClassProxy.users[e.username].room,ref:"iframe",staticStyle:{height:"100%",width:"100%"},attrs:{src:e.scrapedModule.url.startsWith("data:")?null:e.scrapedModule.url,srcdoc:e.scrapedModule.url.startsWith("data:")?e.scrapedModule.url:null,allow:"camera; microphone; fullscreen; display-capture; accelerometer; autoplay; encrypted-media; geolocation; gyroscope; magnetometer; midi; serial; vr;",scrolling:"",frameborder:"0"},on:{load:e.updateIframe}})])}),[],!1,null,"45c47da4",null);r.default=component.exports}}]);