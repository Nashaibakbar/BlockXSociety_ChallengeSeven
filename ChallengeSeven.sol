// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.6.0;

contract ChallengeSeven{
    
    function getHash(string memory _message) 
    public pure returns (bytes32){
    return(keccak256(abi.encode(_message)));
    }
    
    function getEthSignedMessageHash(bytes32 _messageHash) 
    pure public returns(bytes32){
    return(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32",_messageHash)));
    }
    
    function verifySignature(
    address _signer,
    string memory _message,
    bytes memory _signature)
    pure public returns(bool){
            
    bytes32 messageHash= getHash(_message);
    bytes32 ethSignedMessageHash= getEthSignedMessageHash(messageHash);
    return recoverSignature(ethSignedMessageHash,_signature) == _signer;
    }
        
    function recoverSignature(
    bytes32 _ethSignedMessageHash,
    bytes memory _signature)
    pure public returns (address){
        
    (bytes32 r,bytes32 s,uint8 v) = splitSignature(_signature);
    return ecrecover(_ethSignedMessageHash, v, r, s);
    }       
    
    function splitSignature(bytes memory _sig)
    public pure returns (bytes32 r, bytes32 s, uint8 v){
            
    require(_sig.length == 65, "invalid signature length");
    
    assembly{
    r := mload(add(_sig, 32))
    s := mload(add(_sig, 64))
    v := byte(0, mload(add(_sig, 96)))
    }
    }
}



