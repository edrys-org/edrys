import { fs, oak, s3 } from "./deps.ts";
import * as env from "./env.ts";

export let ready = false;
let s3c: s3.S3Client;

const inMemoryStorage: Record<string, string> = {};

/**
 * Init data storage
 */
if (env.data_engine == "s3") {

  if (
    env.data_s3_endpoint == "" ||
    env.data_s3_port == 0 ||
    env.data_s3_region == "" ||
    env.data_s3_access_key == "" ||
    env.data_s3_secret_key == "" ||
    env.data_s3_bucket == ""
  ) {
    throw new Error("Invalid Data S3 config");
  }

  s3c = new s3.S3Client({
    endPoint: env.data_s3_endpoint,
    port: env.data_s3_port,
    useSSL: env.data_s3_use_ssl,
    region: env.data_s3_region,
    accessKey: env.data_s3_access_key,
    secretKey: env.data_s3_secret_key,
    bucket: env.data_s3_bucket,
    pathStyle: true,
  });
} else if (env.data_engine == "file") {

  await fs.ensureDir(env.data_file_path);
}

ready = true;

/**
 * Read a file in a given folder (agnostic of data engine)
 * @param folder Folder path (no slashes)
 * @param file File name
 * @returns File contents parsed as JSON if found, else throws an error
 */
export async function read(
  folder: Folder,
  file: string,
): Promise<Record<string, unknown>> {
  const path = `${env.data_file_path}/${folder}/${file}.json`;

  if (env.data_engine == "s3") {

    const res = await s3c.getObject(path);
    if (res.status == 200) {
      return res.json();
    } else {
      throw new Error(`S3 Error (${res.status})`);
    }
  } 
  else if (env.data_engine == "file") {

    await fs.ensureDir(`${env.data_file_path}/${folder}`);
    return JSON.parse(await Deno.readTextFile(path));
  }
  else {

    if (path in inMemoryStorage)
      return JSON.parse(inMemoryStorage[path])
    else
      throw new Error(`Not found: ${path}`)
  }
}

/**
 * Write a file in a given folder (agnostic of data engine)
 * Obviously, there are no ACID guarantees
 * @param folder Folder path (no slashes)
 * @param file File name
 * @param value JSON to be written down to file
 */
export async function write(
  folder: Folder,
  file: string,
  value: Record<string, unknown> | undefined,
): Promise<void> {
  const text = JSON.stringify(value);

  const path = `${env.data_file_path}/${folder}/${file}.json`;

  if (env.data_engine == "s3") {
    if (text == undefined) {
      return await s3c.deleteObject(path);
    }

    await s3c.putObject(path, text);
  }   
  else if (env.data_engine == "file") {

    await fs.ensureDir(`${env.data_file_path}/${folder}`);
    if (text == undefined) {
      return await Deno.remove(path);
    }

    await Deno.writeTextFile(path, text);
  }
  else {

    if (text == undefined) {
      delete inMemoryStorage[path]
    }
    else {
      inMemoryStorage[path] = text
    }
  }
}

/**
 * Given a JS object, will set a specific property of the object
 * as defined by the path.
 * Useful for making isolated updates on an object
 * @param obj The JS objetc to update
 * @param pathArr The path to the property to update
 * 								(eg. ["details", "name"] is obj.details.name)
 * @param value Value to set property to (if null, it is deleted)
 */
export function setToValue(obj: any, pathArr: Array<string>, value: any) {
  let i = 0;

  for (i = 0; i < pathArr.length - 1; i++) {
    obj = obj[pathArr[i]];
    if (!obj[pathArr[i + 1]]) {
      obj[pathArr[i + 1]] = {};
    }
  }
  obj[pathArr[i]] = value;

  if (value === null)
    delete obj[pathArr[i]]
}

/**
 * Persistent Data model
 */
export type Folder = "users" | "classes";
export type Email = string;
export type Hostname = string;
export type User = {
  email: Email;
  dateCreated: number;
  displayName: string;
  memberships: Array<Membership>;
};

export type Membership = {
  instance: Hostname;
  class_id: ClassId;
  class_name: ClassName;
  role: RoleName;
};

export type ModuleUri = string;
export type Module = {
  url: ModuleUri;
  config: string | Record<string, unknown>;
  studentConfig: string | Record<string, unknown>;
  teacherConfig: string | Record<string, unknown>;
  stationConfig: string | Record<string, unknown>;
  width: "full" | "half" | "third";
  height: "tall" | "medium" | "short";
};
export enum RoleName {
  Student = "student",
  Teacher = "teacher",
  // Owner = "owner"
}

export enum ReservedRoomNames {
  Lobby = "Lobby",
  TeachersLounge = "Teacher's Lounge",
  StationX = "Station *",
}

export type ClassId = string;
export type ClassName = string;
export type Class = {
  id: ClassId;
  dateCreated: number;
  createdBy: Email;
  name: ClassName;
  members: Record<RoleName, Array<Email>>;
  modules: Array<Module>;
};

/**
 * Live Data Model
 */
export type LiveClasses = Record<ClassId, LiveClass | undefined>;
export type RoomName = string;

export type LiveClass = {
  autoAssign: Email | undefined;
  rooms: Record<RoomName, LiveRoom>;
  users: Record<Email, LiveUser>;
};

export type LiveRoom = {
  studentPublicState: string;
  teacherPublicState: string;
  teacherPrivateState: string | undefined;
  userLinked?: Email; // If this user dies, this room dies
};
export type LiveUserConnection = {
  id: string;
  target: oak.ServerSentEventTarget;
};
export type LiveUser = {
  displayName: string;
  room: RoomName;
  role: RoleName;
  dateJoined: number;
  handRaised: boolean;
  connections: Array<LiveUserConnection>;
};

export type LiveMessage = {
  from: Email;
  subject: string;
  body: string;
  module: ModuleUri; 
};

/**
 * Checks if an email is allowed to create a class
 */
export function can_create_class(e: Email): boolean {
  return env.config_class_creators.includes("*") || // Match any
    env.config_class_creators.includes(`*@${e.split("@")[1]}`) || // Match email domain
    env.config_class_creators.filter((p) => p.includes("/")).some((p) =>
      new RegExp(p, "g").test(e)
    ) || // Match regex
    env.config_class_creators.includes(e); // Match specific email
}

/**
 * Validates a Class
 */
export function validate_class(c: Class): boolean {
  return typeof (c.id) == "string" &&
    typeof (c.dateCreated) == "number" &&
    validate_email(c.createdBy) &&
    validate_name(c.name) &&
    typeof (c.members) == "object" &&
    Object.entries(c.members)
      .every((e) => Object.values(RoleName).includes(e[0] as RoleName)) &&
    Object.entries(c.members)
      .every((e) => e[1].every((v, _i, _a) => validate_email(v))) &&
    Array.isArray(c.modules) &&
    c.modules.every((v, _i, _a) => validate_module(v));
}

/**
 * Validates a User
 */
export function validate_user(u: User): boolean {
  return validate_email(u.email) &&
    typeof (u.dateCreated) == "number" &&
    validate_human_name(u.displayName) &&
    u.memberships.every((m) =>
      validate_url(m.instance) &&
      typeof (m.class_id) == "string" &&
      validate_name(m.class_name) &&
      Object.values(RoleName).includes(m.role)
    );
}

/**
 * Validates an email (for model purposes only, see auth.ts otherwise)
 */
export function validate_email(e: Email): boolean {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);
}

/**
 * Validates a human readable model name
 */
export function validate_name(n: string) {
  return typeof (n) == "string" &&
    /^([A-Za-z0-9 ]{1,100})$/.test(n);
}

/**
 * Validates a person's name
 */
export function validate_human_name(n: string) {
  return typeof (n) == "string" &&
    /^[^§¡@£%§¶^&*€#±!_+¢•ªº«\\/<>?$:;|=.,]{1,50}$/.test(n);
}

/**
 * Validates a user-proposed URL
 */
export function validate_url(u: string): boolean {
  try {
    new URL(u);
    return true;
  } catch (_error) {
    return false;
  }
}

/**
 * Validates a Module
 */
export function validate_module(m: Module): boolean {
  return validate_url(m.url) &&
    ["full", "half", "third"].includes(m.width) &&
    ["tall", "medium", "short"].includes(m.height);
}

/**
 * Validates a user-proposed LiveState
 */
export function validate_live_state(s: object): boolean {
  return JSON.stringify(s).length < env.limit_state_len;
}

/**
 * Validates a LiveMessage
 */
export function validate_message(message: LiveMessage, role: RoleName) {
  return message.subject.length < 1000 &&
    (message.body.length < env.limit_msg_len || role == RoleName.Teacher) &&
    validate_url(message.module)
}

/**
 * Given a class and a user, authorize the user against the class
 * and return thier role as well as the full class
 * Otherwise, returns undefined
 */
export async function get_class_and_role(
  class_id: ClassId,
  user_id: Email,
): Promise<[Class, RoleName] | undefined> {
  try {
    if (!class_id) {
      return undefined;
    }

    const class_ = await read("classes", class_id) as unknown as Class; // TODO check if returned null
    if (!class_) {
      return undefined;
    }

    if (class_.members.student?.includes(user_id)) {
      return [class_, RoleName.Student];
    } else if (class_.members.teacher?.includes(user_id)) {
      return [class_, RoleName.Teacher];
    } else {
      return undefined;
    }
  } catch (_error) {
    return undefined;
  }
}
