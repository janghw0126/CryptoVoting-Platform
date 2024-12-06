import React, { useState } from 'react';
import axios from 'axios';
import './App.css';
import { Buffer } from 'buffer'; // Buffer를 import

const App = () => {
  const [publicKey, setPublicKey] = useState('');
  const [vote, setVote] = useState('');
  const [signature, setSignature] = useState('');
  const [submittedVote, setSubmittedVote] = useState('');

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

  // 투표 제출
  const submitVote = async () => {
    try {
      // 공개키가 제대로 받아왔는지 확인
      console.log("Received Public Key:", publicKey);

      // 공개키를 base64에서 Buffer로 변환
      const keyBuffer = Buffer.from(publicKey, 'base64');

      // 공개키를 Crypto API에서 사용 가능한 형식으로 변환
      const key = await crypto.subtle.importKey(
        "spki",                // 공개키 형식
        keyBuffer,             // Buffer 형식으로 변환된 공개키
        { name: "RSA-OAEP", hash: "SHA-256" }, // 암호화 알고리즘
        true,
        ["encrypt"]
      );

      // 투표 데이터 암호화
      const encryptedVote = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        key,
        new TextEncoder().encode(vote)
      );

      // ArrayBuffer를 Buffer로 변환한 후 Hex로 변환
      const encryptedVoteBuffer = Buffer.from(encryptedVote);
      const encryptedVoteHex = encryptedVoteBuffer.toString('hex');
      console.log("Encrypted Vote (Hex):", encryptedVoteHex);

      // 서버로 암호화된 투표 데이터 전송
      const response = await axios.post('http://localhost:5000/submit_vote', {
        encrypted_vote: encryptedVoteHex,
      });

      // 서버 응답 확인
      if (response.data.signature) {
        setSignature(response.data.signature);
        setSubmittedVote(response.data.vote);
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
      <textarea 
        className="vote-input"
        placeholder="Enter your vote"
        value={vote}
        onChange={(e) => setVote(e.target.value)}
      />
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