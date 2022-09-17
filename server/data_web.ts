import { nanoid, log, oak } from "./deps.ts";
import * as data from "./data.ts";
import * as env from "./env.ts";

/**
 * Main in-memory data storage for all current classes on this instance
 */
const classes: data.LiveClasses = {};

export const router = (new oak.Router())
  /**
   * Reads currently logged-in user from persistent storage (lock-free/not ACID)
   */
  .get("/readUser", async (ctx) => {
    if (!ctx.state.user) ctx.throw(401);
    ctx.response.body = await data.read("users", ctx.state.user);
    ctx.response.status = 200;
  })
  /**
   * Updates a user in persistent storage (lock-free/not ACID)
   * @param user JSON formatted User
   */
  .get("/updateUser", async (ctx) => {
    if (!ctx.state.user) ctx.throw(401);
    const user_new = JSON.parse(oak.helpers.getQuery(ctx)["user"]) as data.User;
    if (
      !user_new ||
      ctx.state.user != user_new.email ||
      !data.validate_user(user_new)
    ) {
      ctx.response.status = 400;
      return;
    } else {
      const user_old = await data.read("users", ctx.state.user) as data.User;

      user_new.dateCreated = user_old.dateCreated;

      const user = { ...user_old, ...user_new };
      await data.write("users", ctx.state.user, user);
      ctx.response.body = user;
      ctx.response.status = 200;
    }
  })
  /**
   * Checks if a user is allows to create a class on this instance
   * @returns Either 200 or 401
   */
  .get("/canCreateClass", (ctx) => {
    if (!ctx.state.user) ctx.throw(401);
    ctx.response.body = data.can_create_class(ctx.state.user);
    ctx.response.status = 200;
  })
  /**
   * Reads a class from persistent storage (lock-free/not ACID)
   * @param class_id
   */
  .get("/readClass/:class_id", async (ctx) => {
    if (!ctx.state.user) ctx.throw(401);
    const class_id = ctx?.params?.class_id;
    const res = await data.get_class_and_role(class_id, ctx.state.user);
    if (res == undefined) {
      ctx.response.status = 404;
      return;
    }

    const [class_, role] = res;
    if (role == data.RoleName.Student) {
      ctx.response.body = {
        id: class_.id,
        dateCreated: class_.dateCreated,
        createdBy: class_.createdBy,
        name: class_.name,
        modules: class_.modules.map((m) => ({
          url: m.url,
          config: m.config,
          studentConfig: m.studentConfig,
          width: m.width,
          height: m.height,
        })),
        members: {
          [data.RoleName.Student]: [ctx.state.user],
        },
      } as data.Class;
      ctx.response.status = 200;
    } else if (role == data.RoleName.Teacher) {
      ctx.response.body = class_;
      ctx.response.status = 200;
    } else {
      ctx.response.status = 404;
    }
  })
  /**
   * Creates a new class in persistent storage.
   * Default values can not be specified
   */
  .get("/createClass", async (ctx) => {
    if (!ctx.state.user) ctx.throw(401);
    if (data.can_create_class(ctx.state.user)) {
      /* Creating new class */
      const new_class_id = nanoid();
      const new_class = {
        id: new_class_id,
        createdBy: ctx.state.user,
        dateCreated: new Date().getTime(),
        name: "My New Class",
        members: {
          "teacher": [ctx.state.user],
          "student": [],
        },
        modules: env.config_default_modules,
      } as data.Class;
      await data.write("classes", new_class_id, new_class);
      ctx.response.body = new_class_id;
      ctx.response.status = 200;
    }
  })
  /**
   * Updates a class in persistent storage (lock-free/not ACID)
   * @param class_id
   */
  .get("/updateClass/:class_id", async (ctx) => { // ?class=Class
    if (!ctx.state.user) ctx.throw(401);
    const class_id = ctx?.params?.class_id;
    const class_new = JSON.parse(
      oak.helpers.getQuery(ctx)["class"],
    ) as data.Class;
    if (
      !class_new ||
      class_id != class_new.id ||
      !data.validate_class(class_new)
    ) {
      ctx.response.status = 400;
      return;
    }

    const res = await data.get_class_and_role(class_id, ctx.state.user);
    if (typeof res == "undefined") {
      ctx.response.status = 404;
      return;
    }

    const [class_old, role] = res;

    class_new.dateCreated = class_old.dateCreated;
    class_new.createdBy = class_old.createdBy;
    class_new.members.teacher.push(ctx.state.user); /* If you're editing the class, you have to be in it */
    class_new.members.teacher = [...new Set(class_new.members.teacher)];
    class_new.members.student = [...new Set(class_new.members.student)];

    if (role == data.RoleName.Student) {
      ctx.response.status = 404;
    } else if (role == data.RoleName.Teacher) {
      const class_ = { ...class_old, ...class_new };
      await data.write("classes", class_id, class_);

      /* Remove any users that no longer belong */
      for (const user_id of Object.keys(classes[class_id]?.users || [])) {
        if (
          !class_new.members.student.includes(user_id) &&
          !class_new.members.teacher.includes(user_id)
        ) {
          delete classes[class_id]?.users[user_id];
        }
      }
      await onClassUpdated(class_id);
      ctx.response.body = class_;
      ctx.response.status = 200;
    } else {
      ctx.response.status = 404;
    }
  })
  /**
   * Remove a class from persistent storage
   * @param class_id
   */
  .get("/deleteClass/:class_id", async (ctx) => {
    if (!ctx.state.user) ctx.throw(401);
    const class_id = ctx?.params?.class_id;

    const res = await data.get_class_and_role(class_id, ctx.state.user);
    if (typeof res == "undefined") {
      ctx.response.status = 404;
      return;
    }

    const [_, role] = res;

    if (role == data.RoleName.Teacher) {
      await Object.values(classes[class_id]?.users || []).flatMap((u) =>
        u.connections
      ).forEach(async (c) => {
        await c.target.close();
      });
      delete classes[class_id];
      await data.write("classes", class_id, undefined);
      ctx.response.body = "OK";
      ctx.response.status = 200;
    } else {
      ctx.response.status = 404;
    }
  })
  /**
   * Subscribe to a live class and all future changes (via SSE)
   * @param displayName any string
   * @param isStation "true" if you'd like to act as a station
   */
  .get("/readLiveClass/:class_id", async (ctx) => {
    if (!ctx.state.user) ctx.throw(401);

    const class_id = ctx?.params?.class_id;
    const display_name = oak.helpers.getQuery(ctx)["displayName"];
    const is_station = oak.helpers.getQuery(ctx)["isStation"] == "true";
    const username = is_station ? display_name : ctx.state.user;
    const res = await data.get_class_and_role(class_id, ctx.state.user);
    if (
      typeof res == "undefined" || !data.validate_name(display_name) ||
      (is_station && display_name.includes("@"))
    ) {
      ctx.response.status = 404;
      return;
    }

    const target = ctx.sendEvents();

    const [_, role] = res;
    let live_class = classes[class_id];

    /* Only teachers can create stations */
    if (((role != data.RoleName.Teacher) && is_station)) {
      ctx.response.status = 401;
      return;
    }

    /* Create live class if doesn't exist - no concept of starting a class */
    if (!live_class) {
      classes[class_id] = {
        autoAssign: undefined,
        users: {}, // I'm added later
        rooms: {
          "Lobby": {
            studentPublicState: "",
            teacherPublicState: "",
            teacherPrivateState: "",
          },
          "Teacher's Lounge": {
            studentPublicState: "",
            teacherPublicState: "",
            teacherPrivateState: "",
          }
        },
      };
      live_class = classes[class_id] as data.LiveClass;
    }

    let connection_id = "";

    if (live_class.users[username]) {
      /* User already exists in class... */
      connection_id = nanoid();

      /**
       * WIP: connection limits
       */
      // if (connection_id > 10) {
      //     // Users aren't allowed more than 10 concurrent connections at a time
      //     await target.close()
      //     return
      // }
      live_class.users[username].connections ??= []
      live_class.users[username].connections.push(
        {
          id: connection_id,
          target: target,
        },
      );
    } else {
      /* Add user to live class */
      live_class.users[username] = {
        displayName: display_name,
        room: is_station
          ? `Station ${display_name}`
          : data.ReservedRoomNames.Lobby,
        role: role,
        dateJoined: new Date().getTime(),
        handRaised: false,
        connections: [{ id: connection_id, target: target }],
      };

      if (is_station) {
        /**
         * Name starts with Station as hint to frontend
         * Also, it is linked with station user, so they wont be shown in room
         * Here username == display_name
         */
        live_class.rooms[`Station ${display_name}`] = {
          studentPublicState: "",
          teacherPublicState: "",
          teacherPrivateState: "",
          userLinked: username,
        };
      }
    }

    await onClassUpdated(class_id);

    if (
      !classes[class_id]?.users[username] ||
      !classes[class_id]?.users[username].connections.length
    ) {
      target.close();
    }
    
    const kaInterval = setInterval(() => {
      target.dispatchComment("ka");
    }, 1000);

    /* No other rooms with same name as station name */
    target.addEventListener("close", async (_e) => {
      clearInterval(kaInterval);
      const live_class = classes[class_id];

      if (!live_class) {
        return;
      }

      log.debug(["Disconnection", username])

      /* Delete class if I am last connection ever */
      const all_connections = Object.values(live_class.users)
        .flatMap(u => u.connections);

      if (all_connections.length == 1) {
        delete classes[class_id];
      } else if (!live_class.users[username]) {

        /* User has been removed from state deliberately */
        delete classes[class_id]?.users[username];
      } else if (live_class.users[username]?.connections?.length == 1) {

        /* This is the user's last connection and it is gone, remove them */
        delete classes[class_id]?.users[username];

        Object.entries(live_class.rooms)
          .filter((r) => r[1].userLinked == username)
          .forEach((r) => {
            delete classes[class_id]?.rooms[r[0]];
          });
      } else {
        
        /* Just this one, of many user's connections removed, I am still online */
        live_class.users[username].connections = live_class.users[username]
          .connections?.filter((c) => c.id != connection_id);

        live_class.users[username].connections ??= []
      }
      await onClassUpdated(class_id);
    });
  })
  /**
   * Modify a live class the user belongs to
   * For students:
   * @param studentPublicState any string
   * For teachers:
   * @param update JSON formatted {path:string,value:any}
   * @param stationId To act on behalf of a station
   */
  .get("/updateLiveClass/:class_id", async (ctx) => {
    if (!ctx.state.user) ctx.throw(401);

    const class_id = ctx?.params?.class_id;

    if (!classes[class_id]) {
      ctx.response.status = 404;
      return;
    }

    const res = await data.get_class_and_role(class_id, ctx.state.user);
    if (typeof res == "undefined") {
      ctx.response.status = 404;
      return;
    }
    const [_, role] = res;

    const live_class = classes[class_id];

    if (!live_class) {
      ctx.response.status = 400;
      return;
    }

    const stationId = oak.helpers.getQuery(ctx)["stationId"];
    const username = stationId || ctx.state.user;
    /* Only teachers can update stations */
    if (role != data.RoleName.Teacher && stationId) {
      ctx.response.status = 401;
      return;
    }

    const user = live_class.users[username];
    // const user_room = live_class.rooms[user.room]; 

    const update_str = oak.helpers.getQuery(ctx)["update"];
    if (update_str.length > 100000) { /* TODO: Make configurable */
      ctx.response.status = 401;
      return;
    }
    const update = JSON.parse(update_str) as {
      path: Array<string>;
      value: any;
    };

    const update_path_str = JSON.stringify(update.path);

    if (role == data.RoleName.Student) {
      const valid_student_updates: Array<[string, Function]> = [
        [
          JSON.stringify(["rooms", user.room, "studentPublicState"]),
          data.validate_live_state,
        ],
        [
          JSON.stringify(["users", username, "displayName"]),
          data.validate_human_name,
        ],
        [
          JSON.stringify(["users", username, "handRaised"]),
          (v: any) => v === true || v === false,
        ],
      ];

      if (
        !valid_student_updates.some((u) =>
          u[0] == update_path_str && u[1](update.value)
        )
      ) {
        ctx.response.status = 401;
        return;
      }

    } else if (role == data.RoleName.Teacher) {
      /**
       * TODO: Validate teacher updates as well
       */

      if (update.path.length == 3 && update.path[0] == 'users' && update.path[2] == 'room')
      {
        const dateJoiendPath = [...update.path]
        dateJoiendPath[2] = 'dateJoined'
        data.setToValue(classes[class_id], dateJoiendPath, new Date().getTime());
      }
    }

    data.setToValue(classes[class_id], update.path, update.value);

    await onClassUpdated(class_id);

    ctx.response.status = 200;
  })
  /**
   * Broadcast message within a class room
   * @param message JSON formatted: {from, subject, body}
   */
  .get("/sendMessage/:class_id", (ctx) => {
    if (!ctx.state.user) ctx.throw(401);

    const class_id = ctx?.params?.class_id;

    const message = JSON.parse(
      oak.helpers.getQuery(ctx)["message"],
    ) as data.LiveMessage;

    const user_role = classes[class_id]?.users[ctx.state.user]?.role || data.RoleName.Student

    if (
      !class_id || !data.validate_message(message, user_role) ||
      (data.validate_email(message.from) && message.from != ctx.state.user) ||
      (!data.validate_email(message.from) && user_role == 'student')
    ) {
      ctx.response.status = 400;
      return;
    }

    /* No role permission checks since message sending is the same within a room for everyone */
    if (sendMessage(class_id, message)) {
      ctx.response.status = 200;
    } else {
      ctx.response.status = 401;
    }
  });

/**
 * Send users updated class
 * Does not send incremental updates, sends full declarative state
 * @param class_id Only this class will be updated to users
 * @returns Success
 */
async function onClassUpdated(class_id: string): Promise<boolean> {
  const live_class = classes[class_id];

  if (!live_class) {
    return false;
  }

  log.debug(["Class Update", class_id, live_class])
  
  for (const user_id of Object.keys(classes[class_id]?.users || [])) {
    const user = live_class.users[user_id];
    const connections = user?.connections;

    /* User removed, disconnect */
    if (!user || !connections) {
      // for (const conn of connections) await conn.target.close()
      continue
    }

    /* Send whole room to student, or whole class to teacher */
    let res: data.LiveRoom | data.LiveClass | undefined = undefined;
    if (user.role == data.RoleName.Student) {
      res = {
        rooms: {
          [user.room]: {
            ...live_class.rooms[user.room],
            teacherPrivateState: undefined,
          }
        },
        users: {
          [user_id]: {
            ...user,
          },
          /* TODO: Include stubs for other users in my room */
        },
      } as data.LiveClass;

    } else if (user.role == data.RoleName.Teacher) {
      res = live_class as data.LiveClass;
    }
    connections.forEach((c) =>
      c.target.dispatchEvent(new oak.ServerSentEvent("update", res))
    );
  }
  return true;
}

/**
 * Broadcast message within a class
 * @param class_id Only this class will be updated
 * @param message Message to broadcase
 * @returns Success
 */
function sendMessage(class_id: string, message: data.LiveMessage): boolean {
  const live_class = classes[class_id];
  if (!live_class) return false;

  log.debug(["Message to be sent", class_id, message])

  /* Don't send message if not in room in class */
  const user_from = live_class.users[message.from];
  if (!user_from) return true

  /* Send message to users within the target room */
  const user_conns_in_room = 
    Object.entries(classes[class_id]?.users || []).filter((u) =>
        u[1].room == user_from.room
      ).flatMap((u) => u[1].connections);

  for (const user_conn of user_conns_in_room) {
    user_conn.target.dispatchEvent(
      new oak.ServerSentEvent("message", {
        ...message,
        date: new Date().getTime(),
      }),
    );
  }

  return true;
}
