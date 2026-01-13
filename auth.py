from enum import Enum
import crypto

class AuthType(Enum):
    """
    Type used to identify the authentication 
    status for display in application.
    """
    UNKNOWN           = "UK"  # Unknown or not yet determined
    NOTSIGNED         = "NS"  # No signature present 
    VALID             = "SV"  # Signature present and verified 
    KEYNOTFOUND       = "NK"  # No public key available "KeyNotFound"
    INVALID           = "IV"  # Signature invalid "Invalid""

def verify_packet(
    packet: CVPacket,
    keyring: PublicKeyProvider,
) -> AuthResult:

    #How do I check the keyring for presence of the needed key?
  
    AuthStatus = AuthType.UNKNOWN
    if CVPacket.signed:
      if crypto.verify(packet,keyring):
        AuthStatus = AuthType.VALID
      else:
        AuthStatus = AuthType.INVALID
    else:
      AuthStatus = AuthType.NOTSIGNED
  
@dataclass
class AuthResult:
    auth_type: AuthType
    signer: Optional[str]        # callsign or key ID
    reason: Optional[str]        # human/debug explanation
