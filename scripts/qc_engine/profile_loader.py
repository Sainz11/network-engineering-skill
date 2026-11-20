import json
import os
from typing import Dict, Any, Optional

PROFILES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "quality-control", "profiles")

class ProfileLoader:
    def __init__(self, profiles_dir: Optional[str] = None):
        self.profiles_dir = profiles_dir or PROFILES_DIR
        self._cache: Dict[str, Dict[str, Any]] = {}

    def get_profile(self, manufacturer: str, model: str) -> Optional[Dict[str, Any]]:
        key = f"{manufacturer.lower()}_{model.lower()}".replace(" ", "_").replace("-", "_")
        if key in self._cache:
            return self._cache[key]

        # Scan profiles dir
        if not os.path.exists(self.profiles_dir):
            return None

        for filename in os.listdir(self.profiles_dir):
            if filename.endswith(".json"):
                path = os.path.join(self.profiles_dir, filename)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        p_mfg = data.get("manufacturer", "").lower()
                        p_model = data.get("model", "").lower()
                        if p_mfg == manufacturer.lower() and p_model == model.lower():
                            self._cache[key] = data
                            return data
                except Exception:
                    continue
        return None

    def list_profiles(self):
        profiles = []
        if not os.path.exists(self.profiles_dir):
            return profiles
        for filename in os.listdir(self.profiles_dir):
            if filename.endswith(".json"):
                path = os.path.join(self.profiles_dir, filename)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        profiles.append({
                            "manufacturer": data.get("manufacturer"),
                            "model": data.get("model"),
                            "category": data.get("device_category"),
                            "file": filename
                        })
                except Exception:
                    pass
        return profiles
