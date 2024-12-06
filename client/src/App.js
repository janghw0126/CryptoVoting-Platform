import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

const App = () => {
  const [publicKey, setPublicKey] = useState('');
  const [vote, setVote] = useState('');
  const [signature, setSignature] = useState('');
  const [submittedVote, setSubmittedVote] = useState('');

  const candidates = ['Candidate 1', 'Candidate 2', 'Candidate 3'];

  // 서버에서 공개키 가져오기
  const fetchPublicKey = async () => {
    try {
      const response = await axios.get('http://localhost:5000/get_public_key');
      setPublicKey(response.data);
      alert('Public key fetched successfully.');
    } catch (error) {
      console.error('Error fetching public key:', error);
    }
  };

  // PEM 공개키를 ArrayBuffer로 변환
  const str2ab = (pem) => {
    const binaryString = window.atob(pem.replace(/-----.*-----/g, '').replace(/\n/g, ''));
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  };

  // RSA 공개키 가져오기
  const importPublicKey = async (pem) => {
    const binaryDer = str2ab(pem);
    return await crypto.subtle.importKey(
      'spki',
      binaryDer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['encrypt']
    );
  };

  // 투표 제출
  const submitVote = async () => {
    if (!vote) {
      alert('Please select a candidate before submitting.');
      return;
    }

    try {
      const key = await importPublicKey(publicKey);

      // 투표 데이터 암호화
      const encryptedVote = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        key,
        new TextEncoder().encode(vote)
      );

      // Base64로 변환
      const encryptedVoteBase64 = btoa(
        String.fromCharCode(...new Uint8Array(encryptedVote))
      );

      // 서버로 전송
      const response = await axios.post('http://localhost:5000/submit_vote', {
        encrypted_vote: encryptedVoteBase64,
      });

      // 서버 응답 확인
      if (response.data.signature) {
        setSignature(response.data.signature);
        setSubmittedVote(vote);
        alert('Vote submitted and signed successfully!');
      } else {
        alert('Error in submitting vote.');
      }
    } catch (error) {
      console.error('Error during vote submission:', error);
    }
  };

  return (
    <div className="container">
      <h1>Secure Voting System</h1>
      <button onClick={fetchPublicKey}>Fetch Public Key !</button>
      <div>
        <label htmlFor="candidate-select">Select a candidate</label>
        <select
          id="candidate-select"
          value={vote}
          onChange={(e) => setVote(e.target.value)}
        >
          <option value="">-- Select a candidate! --</option>
          {candidates.map((candidate, index) => (
            <option key={index} value={candidate}>
              {candidate}
            </option>
          ))}
        </select>
      </div>
      <button onClick={submitVote}>Submit Vote</button>
      {signature && (
        <div>
          <p><strong>Server Signature:</strong> <br></br> {signature}</p>
          <p><strong>Submitted Vote:</strong> <br></br> {submittedVote}</p>
        </div>
      )}
    </div>
  );
};

export default App;