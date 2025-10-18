import base64
from datetime import datetime

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class Session:
    """Represents an authenticated session."""

    def __init__(self, session_token: str, expires_at: datetime):
        self.session_token = session_token
        self.expires_at = expires_at

    def is_valid(self):
        """Check if session is still valid."""
        return datetime.now() < self.expires_at


class Client:
    """HTTP client for interacting with the chat server."""

    def __init__(self):
        self.base_url: str = "http://127.0.0.1:8080"
        self._session: Session | None = None
        self._privkey: Ed25519PrivateKey | None = None
        self._uid: str = ""

    @property
    def privkey(self) -> Ed25519PrivateKey:
        if not self._privkey:
            raise ValueError("Private key not initialized")
        return self._privkey

    @privkey.setter
    def privkey(self, value: Ed25519PrivateKey):
        self._privkey = value

    @property
    def session(self) -> Session:
        if not self._session:
            raise ValueError("Session not initialized")
        return self._session

    @session.setter
    def session(self, value: Session):
        self._session = value

    @property
    def uid(self) -> str:
        if not self._uid:
            raise ValueError("UID not initialized")
        return self._uid

    @uid.setter
    def uid(self, value: str):
        self._uid = value

    def authenticate(self):
        """
        Authenticate with the server using challenge-response.

        Raises:
            RuntimeError: If authentication fails
        """
        res = requests.get(f"{self.base_url}/api/v1/auth/challenge?uid={self.uid}")
        if res.status_code != 200:
            raise RuntimeError(f"Failed to obtain the challenge. Server responded with {res.status_code}")

        nonce_bytes = base64.b64decode(res.json()['nonce'])
        sig_bytes = self.privkey.sign(nonce_bytes)

        payload = {"uid": self.uid, "sig": base64.b64encode(sig_bytes).decode("utf-8")}
        res = requests.post(f"{self.base_url}/api/v1/auth/verify", json=payload)
        if res.status_code != 200:
            raise RuntimeError(f"Failed to authenticate current user. Server responded with {res.status_code}")

        self.session = Session(res.json()["access_token"], res.json()["expires_at"])

    def api_request(self, method: str, endpoint: str, **kwargs):
        """
        Make an authenticated API request.

        Automatically re-authenticates if session is invalid.

        Args:
            method: HTTP method
            endpoint: API endpoint path
            **kwargs: Additional arguments to pass to requests.request

        Returns:
            Response object
        """
        if not self.session or not self.session.is_valid():
            self.authenticate()
        return requests.request(method, self.base_url + endpoint, **kwargs)
