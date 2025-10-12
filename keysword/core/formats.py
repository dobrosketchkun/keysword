"""Export format handlers for different key types."""

from typing import Dict, Any


class KeyFormatter:
    """Handle various key export formats."""
    
    @staticmethod
    def export_rsa_formats(key) -> Dict[str, str]:
        """
        Export RSA key in multiple formats.
        
        Args:
            key: RSA key object
            
        Returns:
            dict: Key in different formats
        """
        return {
            'pem': key.export_key().decode(),
            'pem_public': key.publickey().export_key().decode(),
            'pkcs8': key.export_key(format='PEM', pkcs=8).decode(),
            'der': key.export_key(format='DER').hex(),
            'der_public': key.publickey().export_key(format='DER').hex(),
            'openssh': key.publickey().export_key(format='OpenSSH').decode(),
        }
    
    @staticmethod
    def export_ecc_formats(key, curve='P-256') -> Dict[str, str]:
        """
        Export ECC key in multiple formats.
        
        Args:
            key: ECC key object
            curve: Curve name
            
        Returns:
            dict: Key in different formats
        """
        formats = {
            'pem': key.export_key(format='PEM').decode(),
            'pem_public': key.public_key().export_key(format='PEM').decode(),
            'der': key.export_key(format='DER').hex(),
            'der_public': key.public_key().export_key(format='DER').hex(),
        }
        
        # OpenSSH format only available for certain curves
        try:
            formats['openssh'] = key.public_key().export_key(format='OpenSSH').decode()
        except:
            pass
        
        return formats
    
    @staticmethod
    def export_curve25519_formats(key) -> Dict[str, str]:
        """
        Export Curve25519 key in hex format.
        
        Args:
            key: Curve25519 key object
            
        Returns:
            dict: Key in different formats
        """
        from nacl.encoding import HexEncoder, Base64Encoder, RawEncoder
        
        return {
            'hex_secret': HexEncoder.encode(key.__bytes__()).decode(),
            'hex_public': HexEncoder.encode(key.public_key.__bytes__()).decode(),
            'base64_secret': Base64Encoder.encode(key.__bytes__()).decode(),
            'base64_public': Base64Encoder.encode(key.public_key.__bytes__()).decode(),
            'raw_secret': RawEncoder.encode(key.__bytes__()).hex(),
            'raw_public': RawEncoder.encode(key.public_key.__bytes__()).hex(),
        }
    
    @staticmethod
    def export_ed25519_formats(key) -> Dict[str, str]:
        """
        Export Ed25519 key in hex format.
        
        Args:
            key: Ed25519 signing key object
            
        Returns:
            dict: Key in different formats
        """
        from nacl.encoding import HexEncoder, Base64Encoder
        
        return {
            'hex_secret': HexEncoder.encode(key.__bytes__()).decode(),
            'hex_public': HexEncoder.encode(key.verify_key.__bytes__()).decode(),
            'base64_secret': Base64Encoder.encode(key.__bytes__()).decode(),
            'base64_public': Base64Encoder.encode(key.verify_key.__bytes__()).decode(),
        }
    
    @staticmethod
    def export_bitcoin_formats(privkey_hex: str) -> Dict[str, str]:
        """
        Export Bitcoin key in multiple address formats.
        
        Args:
            privkey_hex: Private key in hex format
            
        Returns:
            dict: Key and addresses in different formats
        """
        from bitcoin import encode_privkey, privkey_to_address, privkey_to_pubkey
        
        # Take first 64 hex chars (32 bytes)
        privkey = privkey_hex[:64]
        
        return {
            'hex': privkey,
            'wif_compressed': encode_privkey(privkey, 'wif_compressed'),
            'wif_uncompressed': encode_privkey(privkey, 'wif'),
            'address_p2pkh': privkey_to_address(privkey),
            'pubkey_hex': privkey_to_pubkey(privkey),
        }
    
    @staticmethod
    def export_ethereum_formats(key_dict: Dict[str, Any]) -> Dict[str, str]:
        """
        Export Ethereum key in multiple formats.
        
        Args:
            key_dict: Dict with 'key' (ECC) and 'address'
            
        Returns:
            dict: Key and address in different formats
        """
        ecc_key = key_dict['key']
        address = key_dict['address']
        
        return {
            'address': address,
            'address_checksum': address,  # TODO: Add EIP-55 checksummed version
            'private_key_pem': ecc_key.export_key(format='PEM').decode(),
            'private_key_hex': hex(ecc_key.d)[2:].zfill(64),
            'public_key_pem': ecc_key.public_key().export_key(format='PEM').decode(),
        }
    
    @staticmethod
    def export_key(key, key_type: str) -> Dict[str, Any]:
        """
        Export a key in all available formats for its type.
        
        Args:
            key: Key object
            key_type: Type of key
            
        Returns:
            dict: Key in all available formats
        """
        if key_type == 'RSA':
            return KeyFormatter.export_rsa_formats(key)
        elif key_type in ['P-256', 'secp256k1']:
            return KeyFormatter.export_ecc_formats(key, curve=key_type)
        elif key_type == 'curve25519':
            return KeyFormatter.export_curve25519_formats(key)
        elif key_type == 'ed25519':
            return KeyFormatter.export_ed25519_formats(key)
        elif key_type == 'bitcoin':
            return KeyFormatter.export_bitcoin_formats(key)
        elif key_type == 'ethereum':
            return KeyFormatter.export_ethereum_formats(key)
        else:
            return {'error': f'Unknown key type: {key_type}'}

