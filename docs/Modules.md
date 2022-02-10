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

- To explore existing modules, check out the
  [`edrys-module` tag on GitHub](https://github.com/topics/edrys-module)
- The easiest way to start developing modules is to use the
  [Official Module Template](https://github.com/edrys-org/module)
- To start from scratch, you can find
  [Edrys.js here](https://github.com/edrys-org/edrys/blob/main/module/edrys.js)
  and include it in your HTML pages

## The API

When using Edrys.js, you have to listen for the onReady event that will be
called when the module has been fully loaded:

```js
Edrys.onReady(() => console.log("Module is loaded!"));
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

Modules can send and receive messages. Messages are transferred in real time to
everyone else in the same room. Messages each have a "subject" and a "body"
which you can use however you want (eg. Use subject for message type and body as
stringified JSON).

To send a message:

```js
Edrys.sendMessage("subject", "body");
```

To receive messages:

```js
Edrys.onMessage(({ from, subject, body }) =>
  console.log("Got new message: ", from, subject, body)
);
```

### Room State

Messaging can be used when at-most-once delivery is okay (that is, newly joining
users cannot see previously sent messages). When you want to have state that can
be seen by users that join the room at any time, you use room state.

There are three room states:

```js
console.log(Edrys.liveRoom.studentPublicState); // Can be seen and edited by the module when loaded to students
console.log(Edrys.liveRoom.teacherPublicState); // Can only be edited by teachers but seen by students
console.log(Edrys.liveRoom.teacherPrivateState); // Can only be seen/edited by teachers
```

This `Edrys.liveRoom` object is reactive, meaning you can change it anywhere in
your code and Edrys will automatically update it in all other modules in
real-time. For example:

```js
Edrys.liveRoom.studentPublicState = "test"; // Every student and teacher with this module loaded in this room will now have this update!
```

To listen to changes (eg. to re-render UI on change):

```js
Edrys.onUpdate((e) => console.log("Some state has changed!"));
```

### Persistent State

Room state is not persistent, meaning it will be wiped if the server is
restarted or if the class ends and starts again. This is by design as Room State
is only meant to last in the short term. For more persistent state that will
remain forever until deleted, you can for example use an S3 API and store data
there at a known location. A more integrated solution will be available in the
future.

### Other data

Edrys modules receive lots of data which can be useful in developing extra
functionality into Edrys. This can be found in `Edrys.liveClass`, which is also
reactive in real-time.
