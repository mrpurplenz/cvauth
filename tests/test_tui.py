from pathlib import Path
from types import SimpleNamespace
import pytest

from cvauth import crypto
from cvauth.config import (
    CVAuthConfig,
    IdentityConfig,
    KeysConfig,
    CryptoConfig,
    BehaviourConfig,
    ConfigLocationConfig,
)
from cvauth.cvauth_tui import sign_outgoing
from cvauth.packet import CVPacket


@pytest.fixture
def make_config(tmp_path):
    """Build an isolated config with keys for the selected crypto scheme."""

    def _make_config(scheme_name):
        config_file = tmp_path / "cvauth.toml"

        config = CVAuthConfig(
            identity=IdentityConfig(callsign="ZL2DRS", ssid="0"),
            keys=KeysConfig(
                private_key="keys/private.pem",
                public_key="keys/public.pem",
            ),
            crypto=CryptoConfig(scheme=scheme_name),
            behaviour=BehaviourConfig(),
            config_location=ConfigLocationConfig(
                config_path=str(config_file)
            ),
        )

        scheme = crypto.get_scheme(scheme_name)
        private_key, public_key = scheme.generate_keypair()

        private_path, public_path = config.resolve_keypair_paths(
            scheme_name
        )
        private_path.parent.mkdir(parents=True, exist_ok=True)
        public_path.parent.mkdir(parents=True, exist_ok=True)

        private_path.write_bytes(
            scheme.serialize_private(private_key)
        )
        public_path.write_bytes(
            scheme.serialize_public(public_key)
        )

        return config

    return _make_config


@pytest.mark.parametrize(
    "scheme_name",
    [
        crypto.DEFAULT_SCHEME,
        crypto.CHATTERVOX_SCHEME,
    ],
)
def test_sign_outgoing_uses_configured_scheme(make_config, scheme_name):
    config = make_config(scheme_name)

    state = SimpleNamespace(
        callsign="ZL2DRS",
        config=config,
    )

    packet = sign_outgoing("Hello over packet radio", state)

    #class State:
    #    callsign = "ZL2DRS"
    #    config = config

    #packet = sign_outgoing("Hello over packet radio", State())

    assert isinstance(packet, CVPacket)
    assert packet.from_call == "ZL2DRS"
    assert packet.payload == b"Hello over packet radio"
    assert packet.signature is not None
    assert packet.signed is True

    # Verify the signature with the public key for the configured scheme.
    _, public_path = config.resolve_keypair_paths(scheme_name)
    scheme = crypto.get_scheme(scheme_name)
    public_key = scheme.load_public(public_path.read_bytes())

    assert scheme.verify(
        packet.payload,
        packet.signature,
        public_key,
    )
