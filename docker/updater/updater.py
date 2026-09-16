#!/usr/bin/env python3
"""Host-only updater for one explicitly configured Vaultwarden Compose service."""

import argparse
import copy
import fcntl
import http.server
import json
import os
from pathlib import Path
import re
import socketserver
import subprocess
import tarfile
import threading
import time
import uuid


CAPABILITY_LABEL = "org.vaultwarden.admin-updates"
IMAGE_PATTERN = re.compile(r"([a-z0-9][a-z0-9._:/-]*)(?::([\w][\w.-]{0,127})|@(sha256:[a-f0-9]{64}))", re.ASCII)


class UpdateError(Exception):
    pass


def atomic_json(path, value):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as file:
        json.dump(value, file, indent=2)
        file.flush()
        os.fsync(file.fileno())
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def validate_image(image, repositories):
    if not isinstance(image, str) or len(image) > 512:
        raise UpdateError("Enter a Docker image with an explicit tag or digest.")
    match = IMAGE_PATTERN.fullmatch(image)
    if not match or match.group(1) not in repositories:
        raise UpdateError("Use an approved image repository with an explicit tag or digest.")
    return image


class Docker:
    def run(self, *args, timeout=60):
        # Never run a shell, and never expose Docker output (which may contain secrets) to the browser.
        try:
            result = subprocess.run(
                ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise UpdateError("Docker is unavailable or the operation timed out. Check the host.") from error
        if result.returncode:
            raise UpdateError("Docker rejected the operation. Check the configured service, image, and registry access on the host.")
        return result.stdout.strip()


class Updater:
    def __init__(self, config, docker=None):
        self.config = config
        self.docker = docker or Docker()
        self.lock = threading.RLock()
        self.state_dir = Path(config["state_directory"]).resolve(strict=True)
        self.data_dir = Path(config["data_directory"]).resolve(strict=True)
        self.project_dir = Path(config["project_directory"]).resolve(strict=True)
        if self.data_dir == Path("/") or self.state_dir.is_relative_to(self.data_dir) or self.data_dir.is_relative_to(self.state_dir):
            raise UpdateError("Use separate data and updater state directories, neither containing the other.")
        self.override = self.state_dir / "image.override.json"
        self.state_path = self.state_dir / "status.json"
        validate_image(config["default_image"], config["image_repositories"])
        self.state = {
            "busy": False, "recovery_required": False, "current_image": None,
            "default_image": config["default_image"], "candidate": None,
            "message": "", "result": None, "events": [],
        }
        if self.state_path.exists():
            self.state.update(json.loads(self.state_path.read_text()))
        self.state["default_image"] = config["default_image"]
        if self.state["busy"]:
            self.state.update(busy=False, recovery_required=True, candidate=None)
            self.event("The updater was interrupted. Inspect the host before allowing another deployment.")

    def compose(self, *args, override=True, timeout=60):
        command = ["compose", "--project-directory", str(self.project_dir), "--project-name", self.config["project"]]
        for file in self.config["compose_files"]:
            command += ["--file", str(Path(file).resolve(strict=True))]
        if override and self.override.exists():
            command += ["--file", str(self.override)]
        return self.docker.run(*command, *args, timeout=timeout)

    def container(self):
        ids = self.compose("ps", "--all", "--quiet", self.config["service"]).splitlines()
        if len(ids) != 1:
            raise UpdateError("The updater requires exactly one existing Compose container for the configured service.")
        result = json.loads(self.docker.run("inspect", "--type", "container", ids[0]))[0]
        labels = result["Config"].get("Labels") or {}
        if labels.get("com.docker.compose.project") != self.config["project"] or labels.get("com.docker.compose.service") != self.config["service"]:
            raise UpdateError("The target container does not match the configured Compose project and service.")
        return result

    def preflight(self, container):
        configured_hash = self.compose("config", "--hash", self.config["service"]).split()
        running_hash = container["Config"].get("Labels", {}).get("com.docker.compose.config-hash")
        if len(configured_hash) != 2 or configured_hash[1] != running_hash:
            raise UpdateError("Compose configuration differs from the running service. Reconcile it on the host before updating.")
        if not container["State"]["Running"]:
            raise UpdateError("Start and verify the existing service before updating it.")
        if container["State"].get("Health", {}).get("Status") != "healthy":
            raise UpdateError("The existing service must have a passing Docker health check.")
        mounts = container["Mounts"]
        data_mount = [m for m in mounts if m["Destination"] == "/data"]
        if len(data_mount) != 1 or data_mount[0]["Type"] != "bind" or Path(data_mount[0]["Source"]).resolve() != self.data_dir or not data_mount[0]["RW"]:
            raise UpdateError("This updater requires the configured data directory bind-mounted read/write at /data.")
        if any(m["RW"] and m["Destination"] != "/data" for m in mounts):
            raise UpdateError("Additional writable mounts need a separate backup plan before updates can be enabled.")
        settings = dict(entry.split("=", 1) for entry in container["Config"].get("Env", []) if "=" in entry)
        if "ENV_FILE" in settings or any(m["Destination"] == "/.env" for m in mounts):
            raise UpdateError("External environment files require host-managed updates.")
        for key in ("DATABASE_URL", "DATA_FOLDER", "CONFIG_FILE", "ATTACHMENTS_FOLDER", "SENDS_FOLDER", "RSA_KEY_FILENAME"):
            if f"{key}_FILE" in settings:
                raise UpdateError("File-based storage configuration requires host-managed updates.")
        config_file = self.data_dir / "config.json"
        if config_file.exists():
            saved = json.loads(config_file.read_text())
            settings.update({key.upper(): value for key, value in saved.items() if value is not None})
        defaults = {
            "DATA_FOLDER": "/data", "DATABASE_URL": "sqlite:///data/db.sqlite3",
            "ATTACHMENTS_FOLDER": "/data/attachments", "SENDS_FOLDER": "/data/sends",
            "RSA_KEY_FILENAME": "/data/rsa_key", "CONFIG_FILE": "/data/config.json",
        }
        for key, default in defaults.items():
            path = str(settings.get(key, default))
            if key in ("DATA_FOLDER", "CONFIG_FILE") and path != default:
                raise UpdateError("Automatic updates require DATA_FOLDER=/data and CONFIG_FILE=/data/config.json.")
            if key == "DATABASE_URL":
                path = path.removeprefix("sqlite://")
            if not path.startswith("/data/") and path != "/data":
                raise UpdateError("Automatic updates require SQLite and all persistent vault data under /data.")
            if ".." in Path(path).parts:
                raise UpdateError("Persistent data paths must stay inside /data.")
        for path in self.data_dir.rglob("*"):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise UpdateError("The data directory contains links or special files. Set up a complete backup plan first.")

    def event(self, message, **values):
        with self.lock:
            self.state.update(values)
            self.state["message"] = message
            self.state["events"].append({"time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()), "message": message})
            self.state["events"] = self.state["events"][-30:]
            atomic_json(self.state_path, self.state)

    def status(self):
        with self.lock:
            return copy.deepcopy(self.state)

    def submit(self):
        with self.lock:
            if self.state["busy"] or self.state["recovery_required"]:
                raise UpdateError("A deployment is active or requires host recovery. Refresh status before continuing.")
            self.event("Updating…", busy=True, candidate=None, result=None)
            threading.Thread(target=self.work, args=(self.update,), daemon=False).start()
            return self.status()

    def update(self):
        image = validate_image(self.config["default_image"], self.config["image_repositories"])
        candidate = self.check(image)
        if candidate["update_available"]:
            self.deploy(candidate)
        else:
            self.event("Already up to date.", busy=False, result="unchanged", candidate=None)

    def work(self, operation):
        try:
            operation()
        except Exception as error:
            message = str(error) if isinstance(error, UpdateError) else "The updater failed. Inspect the host before retrying."
            self.event(message, busy=False, candidate=None, result="failed")

    def check(self, image):
        current = self.container()
        self.preflight(current)
        self.event("Downloading the selected image. The vault is still running.", current_image=current["Config"]["Image"])
        self.docker.run("pull", image, timeout=900)
        candidate = json.loads(self.docker.run("image", "inspect", image))[0]
        labels = candidate["Config"].get("Labels") or {}
        if labels.get(CAPABILITY_LABEL) != "1":
            raise UpdateError("This image does not include the admin update feature. Choose an image built with admin update support.")
        healthcheck = candidate["Config"].get("Healthcheck", {}).get("Test", [])
        if not healthcheck or healthcheck[0] == "NONE":
            raise UpdateError("The selected image must include a Docker health check.")
        available = current["Image"] != candidate["Id"]
        return {"check_id": str(uuid.uuid4()), "image": image, "image_id": candidate["Id"],
                "previous_id": current["Image"], "container_id": current["Id"], "update_available": available}

    def deploy(self, candidate):
        # Repeat all checks: the service could have changed since the image was downloaded.
        current = self.container()
        self.preflight(current)
        validate_image(candidate["image"], self.config["image_repositories"])
        if current["Id"] != candidate["container_id"] or current["Image"] != candidate["previous_id"]:
            raise UpdateError("The running service changed. Check the image again.")
        self.docker.run("image", "inspect", candidate["image_id"])
        deployment = self.state_dir / "backups" / candidate["check_id"]
        deployment.mkdir(parents=True, exist_ok=False)
        atomic_json(deployment / "deployment.json", {
            "previous_image": current["Image"], "target_image": candidate["image_id"],
            "requested_image": candidate["image"], "service": self.config["service"],
        })
        # Record the recovery boundary BEFORE requesting a stop: even a timed-out CLI may have stopped it.
        self.event("Stopping the vault for a consistent data backup…", recovery_required=True)
        self.compose("stop", "--timeout", "30", self.config["service"], timeout=120)
        if self.container()["State"]["Running"]:
            raise UpdateError("The vault did not stop. Deployment was cancelled; inspect the host.")
        self.event("Backing up all vault data…")
        archive_path = deployment / "data.tar"
        with tarfile.open(archive_path.with_suffix(".partial"), "w") as archive:
            archive.add(self.data_dir, arcname="data")
        with archive_path.with_suffix(".partial").open("rb") as archive:
            os.fsync(archive.fileno())
        archive_path.with_suffix(".partial").replace(archive_path)
        self.event("Starting the downloaded image…")
        atomic_json(self.override, {"services": {self.config["service"]: {"image": candidate["image_id"]}}})
        self.compose("up", "--detach", "--no-deps", "--no-build", "--pull", "never", "--force-recreate", self.config["service"], timeout=180)
        self.event("Waiting for the new container to become healthy…")
        deadline = time.monotonic() + self.config.get("health_timeout", 180)
        while time.monotonic() < deadline:
            container = self.container()
            if container["Image"] != candidate["image_id"]:
                raise UpdateError("The running image differs from the selected image. Inspect the host.")
            health = container["State"].get("Health", {}).get("Status")
            if container["State"]["Running"] and health == "healthy":
                self.event("Update completed. The new container is healthy.", busy=False, recovery_required=False,
                           current_image=candidate["image"], candidate=None, result="updated")
                return
            if not container["State"]["Running"] or health == "unhealthy":
                break
            time.sleep(2)
        # Never silently restore an old database after a new version may have accepted writes.
        raise UpdateError("The new container did not become healthy. Host recovery is required; the data backup is retained.")


class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *_args):
        pass

    def reply(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/status":
            self.reply(404, {"error": "Not found."})
            return
        self.reply(200, self.server.updater.status())

    def do_POST(self):
        if self.path != "/update":
            self.reply(404, {"error": "Not found."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 4096 or self.headers.get_content_type() != "application/json":
                raise ValueError()
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError()
        except (ValueError, UnicodeDecodeError):
            self.reply(400, {"error": "Expected a small JSON object."})
            return
        try:
            if payload:
                raise UpdateError("The update target is configured on the host.")
            self.reply(202, self.server.updater.submit())
        except UpdateError as error:
            self.reply(409, {"error": str(error)})


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--acknowledge-recovery", action="store_true",
                        help="Clear the recovery lock after an operator has repaired and verified the service")
    args = parser.parse_args()
    os.umask(0o077)
    config = json.loads(args.config.read_text())
    state_dir = Path(config["state_directory"])
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Keep the file descriptor open to exclude a second updater for this state directory.
    with (state_dir / "updater.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        updater = Updater(config)
        if args.acknowledge_recovery:
            current = updater.container()
            updater.preflight(current)
            updater.event("Server recovery confirmed.", busy=False, recovery_required=False,
                          candidate=None, result="recovered", current_image=current["Config"]["Image"])
            return
        socket_path = Path(config["socket"])
        socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        if socket_path.exists():
            if not socket_path.is_socket():
                raise UpdateError("The configured socket path already exists and is not a socket.")
            socket_path.unlink()
        with Server(str(socket_path), Handler) as server:
            os.chmod(socket_path, 0o660)
            server.updater = updater
            server.serve_forever()


if __name__ == "__main__":
    main()
