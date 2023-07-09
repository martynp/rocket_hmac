import hmac
import base64

from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA

from httpie_hmac import HmacGenerate

class HmacAuthCustom(HmacGenerate):

    def generate(request):

        # Create sha256 of message body
        content_sha256 = base64.b64encode(SHA256.new(request.inner.body).digest()).rstrip().decode('utf-8')

        string_to_sign = '\n'.join(
            [request.method, request.content_md5, content_sha256, request.path])

        private_key = RSA.importKey(request.secret_key)
        h = SHA256.new(string_to_sign.encode('utf-8'))
        signature = PKCS1_v1_5.new(private_key).sign(h)
        signature_str = base64.b64encode(signature).decode()

        print(h.hexdigest())

        request.inner.headers['Authorization'] = f"HMAC {signature_str}"
        request.inner.headers['x-public-key'] = base64.b64encode(request.raw_settings['public_key'].encode('utf-8')).decode()

        return request.inner
