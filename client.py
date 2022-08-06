import datetime
import logging
from typing import Dict, Iterable, Literal, Optional, TypedDict
import requests


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


class TmiAuthResponse(TypedDict):
    """Shape of the response to successful logins/token refreshes"""
    expiration: int
    refreshCountLeft: int
    refreshCountMax: int
    token: str


class TmiApiClient:
    """Client for the undocumented API on TMobile Home Internet gateways"""
    _BASE_URL: str = "http://192.168.12.1/TMI/v1/"
    _DEFAULT_HEADERS = {
        "accept": "application/json",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "max-age=0",
    }
    _auth_response: Optional[TmiAuthResponse] = None
    _auth_token: Optional[str] = None

    username: str
    password: str

    def __init__(
        self, username: str, password: str, loglevel: Optional[int] = None
    ) -> None:
        self.username = username
        self.password = password
        if loglevel:
            logging.basicConfig(level=loglevel)

    def _do_auth_refresh(self):
        """Refresh an authentication token"""
        resp = requests.post(
            self._BASE_URL + "auth/refresh",
            headers={
                **self._DEFAULT_HEADERS,
                "Authorization": f"Bearer {self._auth_token}",
            },
        )
        print(resp.text)

    def _get_auth_token(self) -> str:
        """Get a new auth token by logging in"""
        login_body = {"username": self.username, "password": self.password}
        login_response = requests.post(
            self._BASE_URL + "auth/login",
            json=login_body,
        )
        json_obj = login_response.json()
        response_auth_object: TmiAuthResponse = json_obj.get("auth", {})
        if not response_auth_object:
            raise RuntimeError(
                "failed to get token and expiration from request: %s",
                response_auth_object,
            )

        self._auth_token = response_auth_object["token"]
        self._auth_response = response_auth_object

        return self._auth_token

    @property
    def auth_expiration(self):
        """Using the cached response object, get the expiration datetime"""
        return datetime.datetime.utcfromtimestamp(
            self._auth_response.get("expiration", 0),
        )

    @property
    def auth_token(self) -> str:
        """Get the authentication token, either by logging in or by
        refreshing an existing token.
        """
        if self._auth_token is None or self.auth_expiration is None:
            logging.info("No previous token found, logging in")
            return self._get_auth_token()

        if datetime.datetime.utcnow() > (
            self.auth_expiration - datetime.timedelta(seconds=15)
        ):
            if self._auth_response.get("refreshCountLeft", 0) > 0:
                logging.info("Refreshing expiring token")
                self._do_auth_refresh()
                return self._auth_token

            logging.info(
                "Token expired and no more refreshes.",
                "Fetching new token.",
            )
            return self._get_auth_token()

        return self._auth_token

    def _get_headers(self) -> Dict[str, str]:
        """Get the headers for the request, including the auth token"""
        return {
            **self._DEFAULT_HEADERS,
            "Authorization": f"Bearer {self.auth_token}",
        }

    def get(self, *args, **kwargs) -> Dict:
        """Thin wrapper around requests.get to handle authentication."""
        spec_headers = kwargs.pop("headers") if "headers" in kwargs else {}
        response = requests.get(
            *args, **kwargs, headers={**spec_headers, **self._get_headers()}
        )

        return response.json()

    def post(self, *args, **kwargs) -> Dict:
        """Thin wrapper around requests.post to handle authentication."""
        spec_headers = kwargs.pop("headers") if "headers" in kwargs else {}
        response = requests.post(
            *args, **kwargs, headers={**spec_headers, **self._get_headers()}
        )

        return response.json()

    def get_gateway_config(self) -> Dict:
        """Get all available gateway config info"""
        return self.get(self._BASE_URL + "gateway?get=all")

    def get_gateway_signal(self) -> Dict:
        """Get the gateway's signal data."""
        return self.get(self._BASE_URL + "gateway?get=signal")

    def get_ap_config(self) -> Dict:
        """Get the access point config."""
        return self.get(self._BASE_URL + "network/configuration/v2?get=ap")

    def set_ap_config(self, new_ap_config: Dict):
        """Set the access point config."""
        return self.post(
            self._BASE_URL + "network/configuration/v2?set=ap",
            json=new_ap_config,
        )

    def disable_wifi(
        self,
        bands: Iterable[Literal["2.4ghz", "5.0ghz"]] = ["2.4ghz", "5.0ghz"],
    ):
        """Disable wifi on the specified bands. Both bands by default.
        This will cause the router to restart, so it's incredibly unlikely it
        will return successfully.

        Args:
            bands: List of bands to enable WiFi radio on
        """
        config = self.get_ap_config()
        for band in bands:
            config[band]["isRadioEnabled"] = False

        return self.set_ap_config(config)

    def enable_wifi(
        self,
        bands: Iterable[Literal["2.4ghz", "5.0ghz"]] = ["2.4ghz", "5.0ghz"],
    ):
        """Enable wifi on the specified bands. Both bands by default.
        This will cause the router to restart, so it's incredibly unlikely it
        will return successfully.

        Args:
            bands: List of bands to enable WiFi radio on
        """
        config = self.get_ap_config()
        for band in bands:
            config[band]["isRadioEnabled"] = True

        return self.set_ap_config(config)

    def get_version(self):
        """Get the API version string."""
        return self.get(self._BASE_URL + "version")


if __name__ == "__main__":
    cl = TmiApiClient("admin", "your.password.here")
    # print(cl.disable_wifi(['2.4ghz']))
    # print(cl.enable_wifi(['2.4ghz']))
    print(cl.get_ap_config())
    print(cl.get_version())
