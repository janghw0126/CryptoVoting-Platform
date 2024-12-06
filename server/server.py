from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

app = Flask(__name__)

# RSA 키 생성
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# 공개키를 PEM 형식으로 저장
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    """클라이언트가 사용할 공개키 제공"""
    return public_pem.decode('utf-8')

@app.route('/submit_vote', methods=['POST'])
def submit_vote():
    """클라이언트에서 암호화된 투표 데이터를 수신"""
    data = request.get_json()
    encrypted_vote = bytes.fromhex(data['encrypted_vote'])

    # 투표 데이터 복호화
    try:
        vote_data = private_key.decrypt(
            encrypted_vote,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Received vote: {vote_data.decode()}")
        
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
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)