from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from datetime import datetime

if TYPE_CHECKING:
    from beorn.config import BeornConfig


@dataclass
class BeeResult:
    """The result of a Bee's labor."""

    success: bool
    summary: str
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


class Bee(ABC):
    """Base class for all specialized plugins (Bees)."""

    def __init__(self, name: str, config: Any):
        self.name = name
        self.config = config

    @abstractmethod
    def collect(self) -> BeeResult:
        """Perform the scan/collection logic."""
        pass

    def pulse(self) -> Optional[BeeResult]:
        """Perform a lightweight check. Return None if not supported."""
        return None


from beorn.state import StateManager
from beorn.fim import FIMBee
from beorn.woodsman import WoodsmanBee
from beorn.eagles import EaglesBee
from beorn.skinchanger import SkinChangerBee
from beorn.starlight import ElvenStarlightBee


class Carrock:
    """The Core Engine that manages the Hive (Bees) and State."""

    def __init__(self, config: BeornConfig):
        self.config = config
        from beorn.config import STATE_DIR

        self.state_manager = StateManager(STATE_DIR)
        self.bees: List[Bee] = []
        self._load_bees()

    def _load_bees(self):
        """Register all Hive Bees in Audit Mode."""
        # 1. FIM Bee
        fim_bee = FIMBee("fim", self.config.fim.__dict__, self.state_manager)
        self.add_bee(fim_bee)

        # 2. Woodsman (Auditd)
        woodsman_bee = WoodsmanBee("woodsman", {})
        self.add_bee(woodsman_bee)

        # 3. Eagles (Network)
        eagles_bee = EaglesBee("eagles", {"auto_baseline": True}, self.state_manager)
        self.add_bee(eagles_bee)

        # 4. SkinChanger (Processes)
        skinchanger_bee = SkinChangerBee("skinchanger", {})
        self.add_bee(skinchanger_bee)

        # 5. Elven-Starlight (Log Pressure)
        starlight_bee = ElvenStarlightBee(
            "starlight", {"spike_threshold_bytes": 102400}, self.state_manager
        )
        self.add_bee(starlight_bee)

    def add_bee(self, bee: Bee):
        self.bees.append(bee)

    def run_all(self) -> Dict[str, BeeResult]:
        results = {}
        for bee in self.bees:
            results[bee.name] = bee.collect()
        return results

    def run_pulse(self) -> Dict[str, BeeResult]:
        results = {}
        for bee in self.bees:
            res = bee.pulse()
            if res:
                results[bee.name] = res
        return results
