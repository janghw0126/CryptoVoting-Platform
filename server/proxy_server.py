from flask import Flask, request, jsonify
import requests
from flask_cors import CORS

app = Flask(__name__)
# CORS(app)  # 모든 도메인에서의 요청을 허용
CORS(app, resources={r"/*": {"origins": "https://localhost:3000"}})

# 클라이언트 인증서 및 키 경로
CLIENT_CERT = '..\\openssl\\client.crt'
CLIENT_KEY = '..\\openssl\\client.key'

# 프록시 서버 라우트
@app.route('/submit_vote', methods=['POST'])
def submit_vote():
    try:
        # React로부터 받은 데이터
        vote_data = request.get_json()

        # 서버로 요청 보낼 URL
        target_url = 'https://127.0.0.1:5000/submit_vote'

        # 클라이언트 인증서를 사용해 HTTPS 요청
        response = requests.post(
            target_url,
            json=vote_data,
            cert=(CLIENT_CERT, CLIENT_KEY),  # 인증서와 키 지정
            verify=False  # SSL 경고 무시 (테스트용)
        )

        # 서버의 응답을 React로 반환
        return jsonify(response.json()), response.status_code

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(port=3001)