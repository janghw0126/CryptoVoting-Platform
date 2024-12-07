from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64
import time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
CORS(app)

# 요청 제한 설정
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # 하루 200번, 시간당 50번 제한
)

# RSA 키 생성
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# 공개키를 PEM 형식으로 변환
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

@app.route('/get_public_key', methods=['GET'])
@limiter.limit("10 per minute")  # 클라이언트 요청 횟수 제한
def get_public_key():
    """클라이언트에 공개키 제공"""
    return public_pem.decode('utf-8')

@app.route('/submit_vote', methods=['POST'])
@limiter.limit("5 per minute")  # 투표 제출 제한
def submit_vote():
    """암호화된 투표 데이터를 수신 및 처리"""
    data = request.get_json()
    encrypted_vote_base64 = data.get('encrypted_vote', '')

    try:
        # Base64 디코딩
        encrypted_vote = base64.b64decode(encrypted_vote_base64)

        # 복호화
        decrypted_vote = private_key.decrypt(
            encrypted_vote,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        vote = decrypted_vote.decode('utf-8')
        print(f"Decrypted Vote: {vote}")

        # 서명 생성
        signature = private_key.sign(
            decrypted_vote,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # 클라이언트로 서명 전송
        return jsonify({'signature': base64.b64encode(signature).decode('utf-8')})

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    # SSL 인증서를 적용하여 HTTPS 실행
    app.run(ssl_context=('..\\openssl\\server.crt', '..\\openssl\\server.key'))