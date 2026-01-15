def test_public_api_imports():
    from cvauth import (
        CVPacket,
        sign_packet,
        verify_packet,
        AuthType,
        AuthResult,
        PublicKeyProvider,
    )

    assert CVPacket is not None
    assert sign_packet is not None
    assert verify_packet is not None
