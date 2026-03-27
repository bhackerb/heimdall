from __future__ import annotations
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional, List

logger = logging.getLogger("beorn.state")


class StateManager:
    """The Hive memory — handles persistence for Beorn."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.state_file = data_dir / "beorn_state.json"
        self._ensure_dir()
        self.state: Dict[str, Any] = self._load()

    def _ensure_dir(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _load(self) -> Dict[str, Any]:
        if not self.state_file.exists():
            return {"last_run": None, "bees": {}, "metadata": {}}
        try:
            with open(self.state_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
            return {"last_run": None, "bees": {}, "metadata": {}}

    def save(self):
        """Persist state to disk."""
        self.state["last_updated"] = datetime.now().isoformat()
        try:
            with open(self.state_file, "w") as f:
                json.dump(self.state, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def update_bee_state(self, bee_name: str, key: str, value: Any):
        """Store state for a specific Bee (e.g., baseline data)."""
        if bee_name not in self.state["bees"]:
            self.state["bees"][bee_name] = {}
        self.state["bees"][bee_name][key] = value
        self.save()

    def get_bee_state(self, bee_name: str, key: str) -> Optional[Any]:
        """Retrieve state for a Bee."""
        return self.state.get("bees", {}).get(bee_name, {}).get(key)
