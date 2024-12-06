import React, { useState } from 'react';
import axios from 'axios';
import './App.css';
import { Buffer } from 'buffer'; // Buffer를 import

const App = () => {
  const [publicKey, setPublicKey] = useState('');
  const [vote, setVote] = useState('');
  const [signature, setSignature] = useState('');
  const [submittedVote, setSubmittedVote] = useState('');

  // 후보 목록
  const candidates = ['Candidate 1', 'Candidate 2', 'Candidate 3'];

  // 서버에서 공개키 가져오기
  const fetchPublicKey = async () => {
    try {
      const response = await axios.get('http://localhost:5000/get_public_key');
      setPublicKey(response.data);
      alert('Public key fetched successfully.');
    } catch (error) {
      console.error("Error fetching public key:", error);
    }
  };

  const importPublicKey = async (pem) => {
    const binaryDer = str2ab(pem);
    return await crypto.subtle.importKey(
      "spki", // 공개키 형식
      binaryDer, // PEM -> ArrayBuffer
      { name: "RSA-OAEP", hash: "SHA-256" }, // 암호화 알고리즘
      true,
      ["encrypt"] // 암호화 용도로만 사용
    );
  };  

  // PEM 형식을 ArrayBuffer로 변환하는 함수
  const str2ab = (str) => {
    const binaryString = atob(str.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", ""));
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  };

  // 투표 제출
  const submitVote = async () => {
    try {
      if (!vote) {
        alert("Please select a candidate before submitting.");
        return;
      }

      console.log("Received Public Key:", publicKey);

      // 공개키를 PEM 형식 그대로 사용
      const key = await importPublicKey(publicKey);

      // 투표 데이터 암호화
      const encryptedVote = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        key,
        new TextEncoder().encode(vote)
      );

      // ArrayBuffer를 Buffer로 변환한 후 base64로 변환
      const encryptedVoteBuffer = Buffer.from(encryptedVote);
      const encryptedVoteBase64 = encryptedVoteBuffer.from(encryptedVote).toString('base64');


      console.log("Encrypted Vote (Base64):", encryptedVoteBase64);
      console.log("Original Vote:", vote);
      console.log("Encrypted Vote (Base64):", encryptedVoteBase64);


      // 서버로 암호화된 투표 데이터 전송
      const response = await axios.post('http://localhost:5000/submit_vote', {
        encrypted_vote: encryptedVoteBase64,
      });

      // 서버 응답 확인
      if (response.data.signature) {
        setSignature(response.data.signature);
        setSubmittedVote(vote); // 선택된 투표 결과 설정
        alert('Vote submitted and signed successfully!');
      } else {
        alert('Error in submitting vote.');
      }
    } catch (error) {
      console.error("Error during vote submission:", error);
    }
  };

  return (
    <div className="container">
      <h1>Secure Voting System</h1>
      <button className="fetch-btn" onClick={fetchPublicKey}>Fetch Public Key</button>
      <div>
        <label htmlFor="candidate-select">Select a candidate:</label>
        <select
          id="candidate-select"
          value={vote}
          onChange={(e) => setVote(e.target.value)}
        >
          <option value="">-- Select a candidate --</option>
          {candidates.map((candidate, index) => (
            <option key={index} value={candidate}>
              {candidate}
            </option>
          ))}
        </select>
      </div>
      <button className="submit-btn" onClick={submitVote}>Submit Vote</button>
      {signature && (
        <div className="result">
          <p><strong>Server Signature:</strong> {signature}</p>
          <p><strong>Submitted Vote:</strong> {submittedVote}</p>
        </div>
      )}
    </div>
  );
};

export default App;