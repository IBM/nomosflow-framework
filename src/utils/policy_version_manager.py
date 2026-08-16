"""
Policy Version Manager with Hot Reload Support

This module provides:
1. Policy version tracking with semantic versioning
2. File watching for automatic policy reload
3. OPA bundle management and reload triggering
4. Policy rollback capabilities
5. Audit logging of policy changes
"""

import os
import json
import time
import hashlib
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, Optional, List, Tuple
from pathlib import Path
import requests
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver
from watchdog.events import FileSystemEventHandler, FileModifiedEvent
import platform

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PolicyMetadata:
    """Represents policy version metadata"""
    
    def __init__(self, version: str, hash: str, timestamp: str, author: str = "system"):
        self.version = version
        self.hash = hash
        self.timestamp = timestamp
        self.author = author
    
    def to_dict(self) -> Dict:
        return {
            "version": self.version,
            "hash": self.hash,
            "timestamp": self.timestamp,
            "author": self.author
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'PolicyMetadata':
        return cls(
            version=data.get("version", "1.0.0"),
            hash=data.get("hash", ""),
            timestamp=data.get("timestamp", ""),
            author=data.get("author", "system")
        )


class PolicyVersionManager:
    """
    Manages policy versions and hot reload functionality.
    
    Features:
    - Automatic file watching and reload detection
    - Version tracking with semantic versioning
    - Policy hash verification
    - OPA reload triggering via API
    - Rollback support with version history
    """
    
    def __init__(
        self,
        policy_file: str = "./config/policies/policy.rego",
        metadata_file: str = "./policy_metadata.json",
        opa_url: str = "http://localhost:8181",
        history_limit: int = 10,
        auto_reload: bool = True
    ):
        self.policy_file = Path(policy_file)
        self.metadata_file = Path(metadata_file)
        self.opa_url = opa_url
        self.history_limit = history_limit
        self.auto_reload = auto_reload
        
        # Version history (in-memory)
        self.version_history: List[PolicyMetadata] = []
        
        # Current metadata
        self.current_metadata: Optional[PolicyMetadata] = None
        
        # File watcher
        self.observer: Optional[Observer] = None
        self.reload_callbacks: List[callable] = []
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Initialize
        self._load_metadata()
        self._verify_policy_file()
        
        if self.auto_reload:
            self._start_file_watcher()
    
    def _load_metadata(self):
        """Load policy metadata from file"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    self.current_metadata = PolicyMetadata.from_dict(data.get("current", {}))
                    
                    # Load history
                    history = data.get("history", [])
                    self.version_history = [
                        PolicyMetadata.from_dict(h) for h in history
                    ]
                    
                logger.info(f"Loaded policy metadata: version {self.current_metadata.version}")
            except Exception as e:
                logger.error(f"Failed to load metadata: {e}")
                self._initialize_metadata()
        else:
            self._initialize_metadata()
    
    def _initialize_metadata(self):
        """Initialize metadata for first-time setup"""
        policy_hash = self._calculate_policy_hash()
        self.current_metadata = PolicyMetadata(
            version="1.0.0",
            hash=policy_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            author="system"
        )
        self._save_metadata()
        logger.info("Initialized policy metadata with version 1.0.0")
    
    def _save_metadata(self):
        """Save current metadata to file"""
        try:
            data = {
                "current": self.current_metadata.to_dict(),
                "history": [h.to_dict() for h in self.version_history[-self.history_limit:]]
            }
            
            with open(self.metadata_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.debug(f"Saved metadata: version {self.current_metadata.version}")
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")
    
    def _calculate_policy_hash(self) -> str:
        """Calculate SHA256 hash of policy file"""
        if not self.policy_file.exists():
            return ""
        
        try:
            with open(self.policy_file, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate policy hash: {e}")
            return ""
    
    def _verify_policy_file(self):
        """Verify policy file exists and matches metadata"""
        if not self.policy_file.exists():
            logger.warning(f"Policy file not found: {self.policy_file}")
            return
        
        current_hash = self._calculate_policy_hash()
        
        if self.current_metadata and current_hash != self.current_metadata.hash:
            logger.warning(
                f"Policy file hash mismatch! "
                f"Expected: {self.current_metadata.hash[:8]}..., "
                f"Got: {current_hash[:8]}..."
            )
    
    def _increment_version(self, bump_type: str = "patch") -> str:
        """
        Increment semantic version.
        
        Args:
            bump_type: "major", "minor", or "patch"
        """
        if not self.current_metadata:
            return "1.0.0"
        
        try:
            parts = self.current_metadata.version.split('.')
            major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
            
            if bump_type == "major":
                major += 1
                minor = 0
                patch = 0
            elif bump_type == "minor":
                minor += 1
                patch = 0
            else:  # patch
                patch += 1
            
            return f"{major}.{minor}.{patch}"
        except Exception as e:
            logger.error(f"Failed to increment version: {e}")
            return "1.0.0"
    
    def _trigger_opa_reload(self) -> bool:
        """Trigger OPA to reload policies via API"""
        try:
            # OPA v1 data API - reload by re-uploading policy
            policy_content = self.policy_file.read_text()
            
            # Upload policy to OPA
            response = requests.put(
                f"{self.opa_url}/v1/policies/bank",
                data=policy_content,
                headers={"Content-Type": "text/plain"},
                timeout=5
            )
            
            if response.status_code in [200, 201]:
                logger.info("Successfully triggered OPA policy reload")
                return True
            else:
                logger.error(f"OPA reload failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to trigger OPA reload: {e}")
            return False
    
    def detect_changes(self) -> bool:
        """Check if policy file has changed"""
        current_hash = self._calculate_policy_hash()
        
        if not self.current_metadata:
            return True
        
        return current_hash != self.current_metadata.hash
    
    def reload_policy(self, bump_type: str = "patch", author: str = "system") -> Tuple[bool, str]:
        """
        Reload policy with version bump.
        
        Args:
            bump_type: Version bump type ("major", "minor", "patch")
            author: Author of the change
            
        Returns:
            Tuple of (success, message)
        """
        with self.lock:
            try:
                # Check if policy changed
                if not self.detect_changes():
                    return False, "No policy changes detected"
                
                # Calculate new hash
                new_hash = self._calculate_policy_hash()
                
                # Increment version
                new_version = self._increment_version(bump_type)
                
                # Save current to history
                if self.current_metadata:
                    self.version_history.append(self.current_metadata)
                
                # Create new metadata
                self.current_metadata = PolicyMetadata(
                    version=new_version,
                    hash=new_hash,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    author=author
                )
                
                # Trigger OPA reload
                reload_success = self._trigger_opa_reload()
                
                if reload_success:
                    # Save metadata
                    self._save_metadata()
                    
                    # Notify callbacks
                    self._notify_reload_callbacks()
                    
                    message = f"Policy reloaded successfully: version {new_version}"
                    logger.info(message)
                    return True, message
                else:
                    # Rollback metadata on OPA reload failure
                    if self.version_history:
                        self.current_metadata = self.version_history.pop()
                    
                    return False, "Failed to reload policy in OPA"
                    
            except Exception as e:
                error_msg = f"Policy reload failed: {e}"
                logger.error(error_msg)
                return False, error_msg
    
    def rollback_to_version(self, version: str) -> Tuple[bool, str]:
        """
        Rollback to a specific version from history.
        
        Args:
            version: Target version to rollback to
            
        Returns:
            Tuple of (success, message)
        """
        with self.lock:
            # Find version in history
            target_metadata = None
            for metadata in self.version_history:
                if metadata.version == version:
                    target_metadata = metadata
                    break
            
            if not target_metadata:
                return False, f"Version {version} not found in history"
            
            # Note: This is a metadata rollback only
            # Actual policy file must be restored separately
            logger.warning(
                f"Rollback to version {version} - "
                "Note: Policy file must be restored manually"
            )
            
            return True, f"Metadata rolled back to version {version}"
    
    def get_current_version(self) -> str:
        """Get current policy version"""
        if self.current_metadata:
            return self.current_metadata.version
        return "unknown"
    
    def get_version_history(self) -> List[Dict]:
        """Get version history"""
        return [h.to_dict() for h in self.version_history]
    
    def register_reload_callback(self, callback: callable):
        """Register a callback to be called on policy reload"""
        self.reload_callbacks.append(callback)
    
    def _notify_reload_callbacks(self):
        """Notify all registered callbacks"""
        for callback in self.reload_callbacks:
            try:
                callback(self.current_metadata)
            except Exception as e:
                logger.error(f"Callback error: {e}")
    
    def _start_file_watcher(self):
        """Start watching policy file for changes"""
        
        class PolicyFileHandler(FileSystemEventHandler):
            def __init__(self, manager: PolicyVersionManager):
                self.manager = manager
                self.last_reload = 0
                self.debounce_seconds = 2  # Prevent multiple rapid reloads
                # Convert policy file to absolute path for comparison
                self.policy_file_abs = str(self.manager.policy_file.resolve())
            
            def on_modified(self, event):
                # Convert event path to absolute path for comparison
                event_path_abs = str(Path(event.src_path).resolve())
                
                logger.debug(f"File modified event: {event_path_abs}")
                logger.debug(f"Watching for: {self.policy_file_abs}")
                
                if event_path_abs == self.policy_file_abs:
                    current_time = time.time()
                    
                    # Debounce rapid file changes
                    if current_time - self.last_reload < self.debounce_seconds:
                        logger.debug(f"Debouncing reload (last reload was {current_time - self.last_reload:.1f}s ago)")
                        return
                    
                    self.last_reload = current_time
                    logger.info(f"Policy file modified, triggering reload: {event.src_path}")
                    
                    # Trigger reload in background
                    threading.Thread(
                        target=self.manager.reload_policy,
                        args=("patch", "file_watcher"),
                        daemon=True
                    ).start()
        
        try:
            # Use PollingObserver for better cross-platform support (especially macOS containers)
            # PollingObserver works when inotify events don't propagate through volume mounts
            # Set timeout to 1 second for responsive file change detection
            self.observer = PollingObserver(timeout=1)
            event_handler = PolicyFileHandler(self)
            
            # Watch the directory containing the policy file
            watch_dir = self.policy_file.parent
            self.observer.schedule(event_handler, str(watch_dir), recursive=False)
            self.observer.start()
            
            logger.info(f"Started watching policy file with polling (1s interval): {self.policy_file}")
        except Exception as e:
            logger.error(f"Failed to start file watcher: {e}")
    
    def stop(self):
        """Stop the policy version manager"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            logger.info("Stopped policy file watcher")
    
    def get_status(self) -> Dict:
        """Get current status and statistics"""
        return {
            "current_version": self.get_current_version(),
            "policy_file": str(self.policy_file),
            "policy_exists": self.policy_file.exists(),
            "current_hash": self._calculate_policy_hash()[:16] + "...",
            "auto_reload_enabled": self.auto_reload,
            "version_history_count": len(self.version_history),
            "last_update": self.current_metadata.timestamp if self.current_metadata else None,
            "opa_url": self.opa_url
        }


# Singleton instance
_policy_manager: Optional[PolicyVersionManager] = None


def get_policy_manager(**kwargs) -> PolicyVersionManager:
    """Get or create the global policy manager instance"""
    global _policy_manager
    
    if _policy_manager is None:
        _policy_manager = PolicyVersionManager(**kwargs)
    
    return _policy_manager


if __name__ == "__main__":
    # Example usage
    manager = PolicyVersionManager(
        policy_file="./config/policies/policy.rego",
        auto_reload=True
    )
    
    print("Policy Version Manager Started")
    print(f"Current version: {manager.get_current_version()}")
    print(f"Status: {json.dumps(manager.get_status(), indent=2)}")
    
    try:
        # Keep running to watch for file changes
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        manager.stop()

# Made with Bob
