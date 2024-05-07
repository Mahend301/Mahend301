from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import Account
from services.xrpl import XRPLClient

class XRPLWalletAuthentication(TokenAuthentication):
    keyword = 'signature'

    def authenticate_credentials(self, key):
        try:
            address, is_valid = XRPLClient.verify_signature(key)
        except Exception as e:
            raise AuthenticationFailed(f'Authentication failed due to {e!s}') from e
        
        if not is_valid:
            raise AuthenticationFailed('Invalid signature provide')
        
        try:
            account = Account.objects.get(address=address)
        except Account.DoesNotExist as e:
            raise AuthenticationFailed('Invalid token provide') from e
        
        return (account,)

        