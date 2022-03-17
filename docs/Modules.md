# Modules

Edrys classes are based on the concept of "modules". A module is a class
building block. You can create your own modules or explore existing modules and
add them to your class.

A module is just an HTML page that is run in an iframe and shown to your
students, teachers, and on stations. You can make the module behave differently
depending on where it is currently loaded. Modules use the Edrys.js API to send
and receive messages in real time, allowing you to build any live functionality
without setting up any real-time infrastructure, authenticating users, or
configuring anything else, as that is all handled upstream by Edrys.

## Usage

To use a module you simply host it anywhere and paste its link into the Edrys
app.

- To explore existing ready-to-use modules, check out the
  [`edrys-module` tag on GitHub](https://github.com/topics/edrys-module)
- The easiest way to start developing modules is to use the
  [Official Module Template](https://github.com/edrys-org/module)
 - Bring your own stack by using Edrys.js:
 
 ```html
 <script src="https://edrys-org.github.io/edrys/module/edrys.js"></script>
 ```

## The API

When using Edrys.js, you have to listen for the onReady event that will be
called when the module has been fully loaded:

```js
Edrys.onReady(() => console.log("Module is loaded!"));
```

There is also the onUpdate event, which is called on any real-time state changes:

```js
Edrys.onUpdate(() => console.log("Something has changed in the class"));
```
### Metadata

Edrys scrapes module HTML files for metadata. It looks at meta tags in your HTML
and stores this information. The following meta tags can be set:

- `description`: module description that will be shown to people adding your
  module
- `show-in`: defines where the module will be shown. Can be "*" to load it
  everywhere, "chat" for the Lobby and other chat-rooms, or "station" to load it
  only on Stations
- Page title: the page title tag will be used as the module name

For an example of how to use meta tags, check out the
[tags in the template module](https://github.com/edrys-org/module/blob/main/index.html).

### Config

Users of the module can pass in some run-time configuration to your module to
customize its behavior. The content and structure of this config is entirely up
to you. You can read the config in this manner:

```js
console.log(Edrys.module.config); // Always available
console.log(Edrys.module.studentConfig); // Only available when this module is loaded to a student
console.log(Edrys.module.teacherConfig); // Only available when this module is loaded to a teacher
console.log(Edrys.module.stationConfig); // Only available when this module is loaded on a station
```

To get where the module is currently loaded:

```js
console.log(Edrys.role); // Is one of "teacher", "student", or "station"
```

### Messaging

Modules can send and receive messages delivered with an at-most-once guarantee. Messages are transferred in real time to
everyone else in the same room. Messages each have a "subject" and a "body"
which you can use however you want (eg. Use subject for message type and body as
stringified JSON).

To send a message:

```js
Edrys.sendMessage("subject", "body");
```

To receive messages:

```js
Edrys.onMessage(({ from, subject, body }) => {
  console.log("Got new message: ", from, subject, body)
});
```

Messages are scoped to the module, meaning you won't get messages from other modules.
This prevents creating ugly dependencies across modules. However, if necessary,
"promiscuous mode" can be used to listen to all messages in the room regardless of module:

```js
Edrys.onMessage(
  ({ from, subject, body, module }) => {
    console.log("Got new message: ", from, subject, body, module) 
  }, promiscuous=true);
```

### Live Class Reactive API

Edrys modules receive lots of data which can be useful in developing extra
functionality into Edrys. This can be found in `Edrys.liveClass`, which is
reactive in real-time, meaning if you make any changes to that object (for
example set a student's room to something else), it will be applied in real
time to everyone in the class! Provided of course you have proper permissions,
modules loaded on the student's end won't be able to make use of this API.

For example, the [Auto-Assign Module](https://github.com/edrys-org/module-auto-assign)
uses this API to automatically move students around rooms at a configurable interval.

### Persistent State

Messages are ephemeral (eg. newly joining students won't see previously sent messages, so request-reponse semantics are usually employed). For more persistent state, you can for example use the S3 API and store data there at a known location. A more integrated solution will be available in the future.

---

➡️ Next, read about [Working with Stations](Stations.md)

⬆️ Back to [contents](README.md)
