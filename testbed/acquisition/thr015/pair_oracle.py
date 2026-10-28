"""Independent client-side outcome audit; never imports detector/producer code."""
import base64
import hashlib
import hmac
import json
import os
import time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def unb64(value):
    return base64.urlsafe_b64decode(value+'='*(-len(value)%4))

def payload(token):
    return json.loads(unb64(token.split('.')[1]))

def did_key(did):
    text=did.split('#')[0].removeprefix('did:key:')
    if not text.startswith('z'): raise ValueError('oracle supports Ed25519 did:key only')
    alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    number=0
    for char in text[1:]: number=number*58+alphabet.index(char)
    raw=number.to_bytes((number.bit_length()+7)//8,'big')
    if not raw.startswith(b'\xed\x01') or len(raw)!=34: raise ValueError('oracle key codec mismatch')
    return raw[2:]

def verify(token, public):
    h,p,s=token.split('.')
    if json.loads(unb64(h)).get('alg')!='EdDSA': raise ValueError('oracle requires EdDSA')
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(unb64(s),(h+'.'+p).encode())
        return True
    except InvalidSignature:
        return False

class ClientOracle:
    def __init__(self, product):
        self.product=product
        self.secret=os.urandom(32)
        self.expected={}
        self.minted_nonces=set()
        self.used={}
        self.issuer_did=None

    def register(self, request):
        r=json.loads(request.body)
        token=r.get('proof',{}).get('jwt') or r['proofs']['jwt'][0]
        claims=payload(token)
        self.expected[request.access_token]={'aud':claims['aud'],'nonce':claims['nonce']}
        self.minted_nonces.add(claims['nonce'])

    def finish(self, request, status, credentials):
        r=json.loads(request.body)
        token=r.get('proof',{}).get('jwt') or r['proofs']['jwt'][0]
        header=json.loads(unb64(token.split('.')[0]));claims=payload(token)
        public=unb64(header['jwk']['x']) if 'jwk' in header else did_key(header['kid'])
        signature_ok=verify(token,public)
        expected=self.expected[request.access_token]
        if self.product=='walt.id':
            nonce_ok=claims.get('nonce')==expected['nonce']
        else:
            nonce=claims.get('nonce')
            # Previously returned by this controlled issuer; issuer-wide nonce profile, not session-bound.
            nonce_ok=nonce in self.minted_nonces and payload(nonce)['exp']>time.time()
        audience_ok=claims.get('aud')==expected['aud']
        proof_identity=hmac.new(self.secret,token.encode(),hashlib.sha256).hexdigest()
        prior=self.used.get(proof_identity,set())
        outputs=set()
        signed=[]
        for credential in credentials:
            jwt=credential.split('~')[0]
            valid=verify(jwt,did_key(self.issuer_did)) and payload(jwt).get('iss')==self.issuer_did
            signed.append(valid)
            outputs.add(hmac.new(self.secret,credential.encode(),hashlib.sha256).hexdigest())
        duplicate=bool(prior and outputs-prior and all(signed) and signature_ok and nonce_ok and audience_ok)
        if status>=500 or (credentials and not all(signed)):
            outcome='unknown_server_outcome'
        else:
            outcome='duplicate_delivery' if duplicate else 'no_duplicate_delivery'
        result={'request_id':request.request_id,'outcome':outcome,'signature_ok':signature_ok,
            'nonce_matches_profile':nonce_ok,'audience_ok':audience_ok,
            'signed_outputs_checked':len(signed),'all_output_signatures_ok':all(signed) if signed else None,
            'distinct_delivered_before':len(prior),'new_distinct_outputs':len(outputs-prior),
            'http_status':status,'scope':'controlled issuer; one output per proof policy',
            'method':'independent cryptography Ed25519 verification, acquired nonce context, actual credential bytes'}
        self.used[proof_identity]=prior|outputs
        return result
