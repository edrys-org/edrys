import { flags, path, log } from "./deps.ts";

/**
 * Argument parser
 */
const args = flags.parse(Deno.args);
function getArg(name: string): string {
	return args[name] || args[name.toLowerCase().replaceAll('_', '-')] ||
		Deno.env.get("EDRYS_" + name);
}

/**
 * Basics
 */
export const address = getArg("ADDRESS") ?? "localhost:8000";
export const secret = getArg("SECRET") ?? "secret";
if (secret == 'secret') log.warning("For production, please specify a unique --secret to generate a secret private key. Currently using default.")
export const totp_window = parseInt(getArg("TOTP_WINDOW"));
export const serve_path = getArg("SERVE_PATH") ?? `./static`;
export const config_class_creators =
	(getArg("CONFIG_CLASS_CREATORS_CSV") ?? "*").split(",");
export const https_cert_file = getArg("HTTPS_CERT_FILE") ?? undefined;
export const https_key_file = getArg("HTTPS_KEY_FILE") ?? undefined;
export const log_level = getArg("LOG_LEVEL") ?? "DEBUG";

/**
 * Email
 */
export const smtp_tls = getArg("SMTP_TLS") == "true";
export const smtp_hostname = getArg("SMTP_HOST") ?? "";
export const smtp_port = Number(getArg("SMTP_PORT") ?? "0");
export const smtp_username = getArg("SMTP_USERNAME") ?? "";
export const smtp_password = getArg("SMTP_PASSWORD") ?? "";
export const smtp_from = getArg("SMTP_FROM") ?? "";

/**
 * Data
 */
export const data_engine = getArg("DATA_ENGINE") ?? "file";
export const data_file_path = getArg("DATA_FILE_PATH") ?? ".edrys";
export const data_s3_endpoint = getArg("DATA_S3_ENDPOINT") ?? "";
export const data_s3_port = Number(getArg("DATA_S3_PORT") ?? "443");
export const data_s3_use_ssl = getArg("DATA_S3_USE_SSL") == "true";
export const data_s3_region = getArg("DATA_S3_REGION") ?? "";
export const data_s3_access_key = getArg("DATA_S3_ACCESS_KEY") ?? "";
export const data_s3_secret_key = getArg("DATA_S3_SECRET_KEY") ?? "";
export const data_s3_bucket = getArg("DATA_S3_BUCKET") ?? "";

/**
 * Advanced
 */
export const frontend_address = getArg("FRONTEND_ADDRESS") ?? address;
export const config_default_modules =
	JSON.parse(getArg("CONFIG_DEFAULT_MODULES_JSON") ?? "null") ?? [
		{
			url: "https://edrys-org.github.io/module-reference/",
			config: '',
			studentConfig: '',
			teacherConfig: '',
			stationConfig: '',
			width: "full",
			height: "tall",
		},
	];
export const jwt_lifetime_days = Number(getArg("JWT_LIFETIME_DAYS") ?? "30");
export const jwt_keys_path = getArg("JWT_KEYS_PATH") ?? false;
export const limit_msg_len = Number(getArg("LIMIT_MSG_LEN") ?? '10000');
export const limit_state_len = Number(getArg("LIMIT_STATE_LEN") ?? '999000');

