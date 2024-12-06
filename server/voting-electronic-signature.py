from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from flask_cors import CORS  # CORS 임포트
import base64  # base64 임포트 추가

app = Flask(__name__)
CORS(app)  # CORS 활성화

# RSA 키 생성
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# 공개키를 PEM 형식으로 저장
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 투표 데이터 저장소
votes = []

@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    """클라이언트가 사용할 공개키 제공"""
    return public_pem.decode('utf-8')

@app.route('/submit_vote', methods=['POST'])
def submit_vote():
    """클라이언트에서 암호화된 투표 데이터를 수신"""
    data = request.get_json()
    print(f"Received Data: {data}")  # 데이터 로그 출력
    
    try:
        # Base64로 디코딩
        # 서버에서 Base64 디코딩 및 데이터 길이 확인
        encrypted_vote = base64.b64decode(data['encrypted_vote'])
        if len(encrypted_vote) != private_key.key_size // 8:
            raise ValueError("RSA 키 길이와 암호화된 데이터 크기가 일치하지 않습니다.")
        print(f"Encrypted Vote (Decoded): {encrypted_vote}")  # 디코딩된 암호화된 데이터 로그 출력
        print(f"Decoded Vote Length: {len(encrypted_vote)} bytes")  # 디코딩된 데이터 길이 출력

        # RSA 키 길이 확인
        expected_length = private_key.key_size // 8  # 키 크기를 바이트 단위로 변환
        if len(encrypted_vote) != expected_length:
            raise ValueError(f"Decoded data length ({len(encrypted_vote)} bytes) does not match the expected RSA key length ({expected_length} bytes).")

        # 투표 데이터 복호화
        vote_data = private_key.decrypt(
            encrypted_vote,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print(f"Encrypted Vote (Decoded): {encrypted_vote}")
        print(f"Decrypted Vote: {vote_data.decode('utf-8')}")

        # 투표 데이터에 서명
        signature = private_key.sign(
            vote_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            Prehashed(hashes.SHA256())
        )
        return jsonify({'signature': signature.hex()})
    except Exception as e:
        print(f"Error: {e}")  # 에러 로그 출력
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)