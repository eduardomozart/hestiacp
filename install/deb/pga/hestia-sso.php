<?php

/* Hestia way to enable support for SSO to phpPgAdmin */
/* To install please run v-add-sys-pga-sso */

/* Following keys will get replaced when calling v-add-sys-pga-sso */
define("PHPPGADMIN_KEY", "%PHPPGADMIN_KEY%");
define("API_HOST_NAME", "%API_HOST_NAME%");
define("API_HESTIA_PORT", "%API_HESTIA_PORT%");
define("API_KEY", "%API_KEY%");

class Hestia_PGA_API {
	/** @var string */
	public $hostname;
	/** @var string */
	public $key;
	/** @var string */
	public $pga_key;

	public function __construct() {
		$this->hostname = "https://" . API_HOST_NAME . ":" . API_HESTIA_PORT . "/api/";
		$this->key = API_KEY;
		$this->pga_key = PHPPGADMIN_KEY;
	}

	/* Creates curl request */
	public function request($postvars) {
		$postdata = http_build_query($postvars);
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $this->hostname);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($curl, CURLOPT_POST, true);
		curl_setopt($curl, CURLOPT_POSTFIELDS, $postdata);
		$answer = curl_exec($curl);
		return $answer;
	}

	/* Creates a new temp user in postgresql */
	public function create_temp_user($database, $user, $host) {
		$post_request = [
			"hash" => $this->key,
			"returncode" => "no",
			"cmd" => "v-add-database-temp-user",
			"arg1" => $user,
			"arg2" => $database,
			"arg3" => "pgsql",
			"arg4" => $host,
		];
		$request = $this->request($post_request);
		$json = json_decode($request);
		if (json_last_error() == JSON_ERROR_NONE) {
			return $json;
		} else {
			trigger_error("Unable to connect over API please check api connection", E_USER_WARNING);
			return false;
		}
	}

	/* Delete a temp user in postgresql */
	public function delete_temp_user($database, $user, $dbuser, $host) {
		$post_request = [
			"hash" => $this->key,
			"returncode" => "yes",
			"cmd" => "v-delete-database-temp-user",
			"arg1" => $user,
			"arg2" => $database,
			"arg3" => $dbuser,
			"arg4" => "pgsql",
			"arg5" => $host,
		];
		$request = $this->request($post_request);
		if (is_numeric($request) && $request == 0) {
			return true;
		} else {
			return false;
		}
	}

	public function get_user_ip() {
		// Saving user IPs to the session for preventing session hijacking
		$user_combined_ip = [];
		if ($_SERVER["REMOTE_ADDR"] != $_SERVER["SERVER_ADDR"]) {
			$user_combined_ip[] = $_SERVER["REMOTE_ADDR"];
		}
		if (isset($_SERVER["HTTP_CLIENT_IP"])) {
			$user_combined_ip[] = $_SERVER["HTTP_CLIENT_IP"];
		}
		if (isset($_SERVER["HTTP_X_FORWARDED_FOR"])) {
			if ($_SERVER["REMOTE_ADDR"] != $_SERVER["HTTP_X_FORWARDED_FOR"]) {
				$user_combined_ip[] = $_SERVER["HTTP_X_FORWARDED_FOR"];
			}
		}
		if (isset($_SERVER["HTTP_FORWARDED_FOR"])) {
			if ($_SERVER["REMOTE_ADDR"] != $_SERVER["HTTP_FORWARDED_FOR"]) {
				$user_combined_ip[] = $_SERVER["HTTP_FORWARDED_FOR"];
			}
		}
		if (isset($_SERVER["HTTP_X_FORWARDED"])) {
			if ($_SERVER["REMOTE_ADDR"] != $_SERVER["HTTP_X_FORWARDED"]) {
				$user_combined_ip[] = $_SERVER["HTTP_X_FORWARDED"];
			}
		}
		if (isset($_SERVER["HTTP_FORWARDED"])) {
			if ($_SERVER["REMOTE_ADDR"] != $_SERVER["HTTP_FORWARDED"]) {
				$user_combined_ip[] = $_SERVER["HTTP_FORWARDED"];
			}
		}
		if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
			if (!empty($_SERVER["HTTP_CF_CONNECTING_IP"])) {
				$user_combined_ip[] = $_SERVER["HTTP_CF_CONNECTING_IP"];
			}
		}
		return implode("|", $user_combined_ip);
	}
}

function verify_token($database, $user, $ip, $time, $token) {
	if (!password_verify($database . $user . $ip . $time . PHPPGADMIN_KEY, $token)) {
		if (
			!password_verify(
				$database . $user . $_SERVER["SERVER_ADDR"] . "|" . $ip . $time . PHPPGADMIN_KEY,
				$token,
			)
		) {
			trigger_error(
				"Access denied: There is a security token mismatch " . $time,
				E_USER_WARNING,
			);
			session_invalid();
		}
	}
	return;
}

session_set_cookie_params(0, "/", "", true, true);
$session_name = "HestiaPGASession";
session_name($session_name);
@session_start();

function session_invalid() {
	global $session_name;
	session_destroy();
	setcookie($session_name, null, -1, "/");
	header("Location: " . dirname($_SERVER["PHP_SELF"]) . "/index.php");
	die();
}

$api = new Hestia_PGA_API();

if (!empty($_GET)) {
	if (isset($_GET["logout"])) {
		if (!empty($_SESSION["HESTIA_sso_dbuser"])) {
			$api->delete_temp_user(
				$_SESSION["HESTIA_sso_database"],
				$_SESSION["HESTIA_sso_user"],
				$_SESSION["HESTIA_sso_dbuser"],
				$_SESSION["HESTIA_sso_host"],
			);
		}
		session_invalid();
	} elseif (isset($_GET["user"]) && isset($_GET["hestia_token"])) {
		$database = $_GET["database"];
		$user = $_GET["user"];
		$host = "localhost";
		$token = $_GET["hestia_token"];
		if (is_numeric($_GET["exp"])) {
			$time = $_GET["exp"];
		} else {
			$time = 0;
		}

		if ($time + 60 > time()) {
			$ip = $api->get_user_ip();
			verify_token($database, $user, $ip, $time, $token);

			$data = $api->create_temp_user($database, $user, $host);
			if ($data) {
				$_SESSION["HESTIA_sso_dbuser"] = $data->login->user;
				$_SESSION["HESTIA_sso_password"] = $data->login->password;
				$_SESSION["HESTIA_sso_database"] = $database;
				$_SESSION["HESTIA_sso_user"] = $user;
				$_SESSION["HESTIA_sso_host"] = $host;

				$pga_base = dirname($_SERVER["PHP_SELF"]);
				$pga_login_url = $pga_base . "/redirect.php";
				$dbuser = htmlspecialchars($data->login->user, ENT_QUOTES, "UTF-8");
				$dbpass = htmlspecialchars($data->login->password, ENT_QUOTES, "UTF-8");
				$dbname = htmlspecialchars($database, ENT_QUOTES, "UTF-8");
				@session_write_close();
				?>
<!DOCTYPE html>
<html>
<head><title>Redirecting...</title></head>
<body>
<form id="pga_sso_form" method="post" action="<?= $pga_login_url ?>">
	<input type="hidden" name="server" value="0">
	<input type="hidden" name="loginServer" value="0">
	<input type="hidden" name="loginUsername" value="<?= $dbuser ?>">
	<input type="hidden" name="loginPassword" value="<?= $dbpass ?>">
	<input type="hidden" name="loginDatabase" value="<?= $dbname ?>">
	<input type="hidden" name="action" value="login">
</form>
<script>document.getElementById('pga_sso_form').submit();</script>
</body>
</html>
				<?php
				die();
			} else {
				session_invalid();
			}
		} else {
			trigger_error(
				"Link has been expired: System time: " .
					time() .
					" / Time provided in link: " .
					$time,
				E_USER_WARNING,
			);
			session_invalid();
		}
	} else {
		session_invalid();
	}
} else {
	session_invalid();
}
