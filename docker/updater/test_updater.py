import copy
import json
from pathlib import Path
import tarfile
import tempfile
import threading
import unittest

from updater import CAPABILITY_LABEL, UpdateError, Updater, validate_image


class FakeDocker:
    def __init__(self, data):
        self.calls = []
        self.fail = None
        self.new_health = "healthy"
        self.pull_started = threading.Event()
        self.release_pull = threading.Event()
        self.release_pull.set()
        self.current = {
            "Id": "container-before", "Image": "sha256:old",
            "Config": {"Image": "example/vaultwarden:old", "Env": [], "Labels": {
                "com.docker.compose.project": "vault-test", "com.docker.compose.service": "vaultwarden",
                "com.docker.compose.config-hash": "test-config-hash",
            }},
            "Mounts": [{"Destination": "/data", "Source": str(data), "Type": "bind", "RW": True}],
            "State": {"Running": True, "Health": {"Status": "healthy"}},
        }
        self.image = {"Id": "sha256:new", "Config": {
            "Labels": {CAPABILITY_LABEL: "1"}, "Healthcheck": {"Test": ["CMD", "/healthcheck"]},
        }}

    def run(self, *args, timeout=60):
        self.calls.append(args)
        if args[0] == "pull":
            self.pull_started.set()
            if not self.release_pull.wait(5):
                raise RuntimeError("Test pull timed out")
            if self.fail == "pull":
                raise UpdateError("Image download failed.")
            return ""
        if args[:2] == ("image", "inspect"):
            return json.dumps([self.image])
        if args[0] == "inspect":
            return json.dumps([self.current])
        if "ps" in args:
            return self.current["Id"]
        if "--hash" in args:
            return "vaultwarden test-config-hash"
        if "stop" in args:
            self.current["State"]["Running"] = False
            return ""
        if "up" in args:
            if self.fail == "up":
                raise UpdateError("Container recreation failed.")
            self.current["Id"] = "container-after"
            self.current["Image"] = self.image["Id"]
            self.current["State"] = {"Running": True, "Health": {"Status": self.new_health}}
            return ""
        raise AssertionError(args)


class UpdateFlowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "db.sqlite3").write_bytes(b"original database")
        (self.data / "attachments").mkdir()
        (self.data / "attachments" / "file").write_bytes(b"original attachment")
        self.state = self.root / "state"
        self.state.mkdir()
        self.compose = self.root / "compose.json"
        self.compose.write_text("{}")
        self.config = {
            "state_directory": str(self.state), "data_directory": str(self.data),
            "project_directory": str(self.root), "project": "vault-test", "service": "vaultwarden",
            "compose_files": [str(self.compose)], "default_image": "example/vaultwarden:latest",
            "image_repositories": ["example/vaultwarden"], "health_timeout": 1,
        }
        self.docker = FakeDocker(self.data)
        self.updater = Updater(self.config, self.docker)

    def run_update(self):
        self.updater.state["busy"] = True
        self.updater.work(self.updater.update)
        return self.updater.status()

    def test_success_backs_up_data_and_deploys_downloaded_id(self):
        state = self.run_update()
        self.assertEqual(state["result"], "updated")
        self.assertFalse(state["recovery_required"])
        archive_path, = self.state.glob("backups/*/data.tar")
        with tarfile.open(archive_path) as archive:
            self.assertEqual(archive.extractfile("data/db.sqlite3").read(), b"original database")
            self.assertEqual(archive.extractfile("data/attachments/file").read(), b"original attachment")
        override = json.loads(self.updater.override.read_text())
        self.assertEqual(override["services"]["vaultwarden"]["image"], "sha256:new")
        up, = [call for call in self.docker.calls if "up" in call]
        self.assertIn("--no-deps", up)
        self.assertIn("never", up)

    def test_download_failure_keeps_running_service_and_data(self):
        self.docker.fail = "pull"
        state = self.run_update()
        self.assertEqual(state["result"], "failed")
        self.assertFalse(state["recovery_required"])
        self.assertTrue(self.docker.current["State"]["Running"])
        self.assertFalse(any("stop" in call for call in self.docker.calls))
        self.assertFalse(self.updater.override.exists())

    def test_same_image_does_not_restart(self):
        self.docker.image["Id"] = self.docker.current["Image"]
        self.assertEqual(self.run_update()["result"], "unchanged")
        self.assertFalse(any("stop" in call for call in self.docker.calls))

    def test_image_without_update_feature_is_rejected_before_stop(self):
        self.docker.image["Config"]["Labels"] = {}
        self.assertEqual(self.run_update()["result"], "failed")
        self.assertFalse(any("stop" in call for call in self.docker.calls))

    def test_unapplied_compose_changes_are_rejected_before_stop(self):
        self.docker.current["Config"]["Labels"]["com.docker.compose.config-hash"] = "different-config"
        self.assertEqual(self.run_update()["result"], "failed")
        self.assertFalse(any("stop" in call for call in self.docker.calls))

    def test_external_database_and_data_mounts_are_rejected(self):
        original = copy.deepcopy(self.docker.current)
        for environment in (["DATABASE_URL=postgresql://database/vault"], ["ATTACHMENTS_FOLDER=/external"],
                            ["DATABASE_URL_FILE=/run/secrets/database"], ["ENV_FILE=/config/.env"]):
            self.docker.current = copy.deepcopy(original)
            self.docker.current["Config"]["Env"] = environment
            with self.assertRaises(UpdateError):
                self.updater.preflight(self.docker.current)
        self.docker.current = original
        self.docker.current["Mounts"].append({"Destination": "/external", "RW": True})
        with self.assertRaises(UpdateError):
            self.updater.preflight(self.docker.current)

    def test_recreation_and_health_failures_preserve_backup_and_block_retry(self):
        for failure in ("up", "health"):
            with self.subTest(failure=failure):
                self.docker.current["State"] = {"Running": True, "Health": {"Status": "healthy"}}
                self.docker.current["Image"] = "sha256:old"
                self.docker.fail = failure
                self.docker.new_health = "unhealthy"
                state = self.run_update()
                self.assertTrue(state["recovery_required"])
                self.assertEqual(state["result"], "failed")
                self.assertTrue(list(self.state.glob("backups/*/data.tar")))
                with self.assertRaises(UpdateError):
                    self.updater.submit()
                self.assertEqual((self.data / "db.sqlite3").read_bytes(), b"original database")

    def test_duplicate_requests_are_rejected_while_updating(self):
        self.docker.release_pull.clear()
        self.updater.submit()
        self.assertTrue(self.docker.pull_started.wait(2))
        try:
            with self.assertRaises(UpdateError):
                self.updater.submit()
        finally:
            self.docker.release_pull.set()
        # Join this updater's non-daemon worker before temporary data is removed.
        for thread in threading.enumerate():
            if thread is not threading.current_thread() and not thread.daemon:
                thread.join(5)
        self.assertEqual(self.updater.status()["result"], "updated")

    def test_interrupted_update_stays_blocked_after_restart(self):
        self.updater.event("Stopping…", busy=True, recovery_required=True)
        restarted = Updater(self.config, self.docker)
        self.assertFalse(restarted.status()["busy"])
        self.assertTrue(restarted.status()["recovery_required"])
        with self.assertRaises(UpdateError):
            restarted.submit()

    def test_repository_and_tag_validation(self):
        allowed = ["registry.example.com/vaultwarden", "localhost:5000/vaultwarden"]
        for image in ("registry.example.com/vaultwarden:latest", "localhost:5000/vaultwarden:v1", "registry.example.com/vaultwarden@sha256:" + "a" * 64):
            self.assertEqual(validate_image(image, allowed), image)
        for image in ("--help", "registry.example.com/vaultwarden", "evil/vaultwarden:latest", "registry.example.com/vaultwarden:latest;id"):
            with self.assertRaises(UpdateError):
                validate_image(image, allowed)


if __name__ == "__main__":
    unittest.main()
