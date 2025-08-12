// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@chainlink/contracts/src/v0.8/functions/v1_0_0/FunctionsClient.sol";
import "@chainlink/contracts/src/v0.8/functions/v1_0_0/libraries/FunctionsRequest.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract BeadNFTValidator is FunctionsClient, AccessControl {
    using FunctionsRequest for FunctionsRequest.Request;

    // Sepolia Chainlink Functions configuration
    bytes32 private constant DON_ID = 0x66756e2d657468657265756d2d7365706f6c69612d3100000000000000000000;
    uint32 private constant GAS_LIMIT = 300000;
    
    // Ultra-compact JavaScript validator
    string private constant JS_SOURCE =
        "const v=async(a)=>{"
        "if(!a||!a[1])return Functions.encodeUint256(0);"
        "try{"
        "const r=await Functions.makeHttpRequest({url:a[1],method:'HEAD',timeout:8000});"
        "if(r.error||r.status>=400)return Functions.encodeUint256(0);"
        "const c=r.headers?.['content-type']||'';"
        "return Functions.encodeUint256("
        "c.includes('image/')||c.includes('video/')||"
        "a[1].includes('.jpg')||a[1].includes('.png')||a[1].includes('.gif')||"
        "a[1].includes('.mp4')||a[1].includes('.mov')||a[1].includes('ipfs')?1:0);"
        "}catch{return Functions.encodeUint256(0);}"
        "};"
        "return v(args);";

    mapping(bytes32 => string) public requestToBeadId;
    mapping(string => bool) public validatedBeads;
    mapping(string => bool) public validationResults;
    mapping(string => string) public beadURIs;

    bytes32 public constant BEAD_NFT_ROLE = keccak256("BEAD_NFT_ROLE");

    event ValidationRequestSent(bytes32 indexed requestId, string beadId);
    event ValidationFulfilled(bytes32 indexed requestId, string beadId, bool isValid);

    error UnexpectedRequestID(bytes32 requestId);

    constructor() FunctionsClient(0xb83E47C2bC239B3bf370bc41e1459A34b41238D0) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function grantBeadNFTRole(address beadNFTContract) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(BEAD_NFT_ROLE, beadNFTContract);
    }

    function storeBeadURI(string calldata beadId, string calldata uri) external onlyRole(BEAD_NFT_ROLE) {
        beadURIs[beadId] = uri;
    }

    function triggerMetadataValidation(uint64 subscriptionId, string calldata beadId) external onlyRole(BEAD_NFT_ROLE) returns (bytes32 requestId) {
        string memory uri = beadURIs[beadId];
        require(bytes(uri).length > 0, "No URI stored");

        FunctionsRequest.Request memory req;
        req.initializeRequestForInlineJavaScript(JS_SOURCE);

        string[] memory args = new string[](2);
        args[0] = beadId;
        args[1] = uri;
        req.setArgs(args);

        requestId = _sendRequest(req.encodeCBOR(), subscriptionId, GAS_LIMIT, DON_ID);
        requestToBeadId[requestId] = beadId;
        validatedBeads[beadId] = false;
        validationResults[beadId] = false;

        emit ValidationRequestSent(requestId, beadId);
        return requestId;
    }

    function fulfillRequest(bytes32 requestId, bytes memory response, bytes memory err) internal override {
        string memory beadId = requestToBeadId[requestId];
        if (bytes(beadId).length == 0) revert UnexpectedRequestID(requestId);

        validatedBeads[beadId] = true;
        validationResults[beadId] = (err.length == 0 && abi.decode(response, (uint256)) == 1);
        
        emit ValidationFulfilled(requestId, beadId, validationResults[beadId]);
        delete requestToBeadId[requestId];
    }

    function getValidationStatus(string memory beadId) external view returns (bool wasValidationAttempted, bool isCurrentlyValid) {
        return (validatedBeads[beadId], validationResults[beadId]);
    }

    function checkValidation(string memory beadId) external view returns (bool isValidated, bool isValid) {
        return (validatedBeads[beadId], validationResults[beadId]);
    }

    function getBeadURI(string memory beadId) external view returns (string memory) {
        return beadURIs[beadId];
    }

    function supportsInterface(bytes4 interfaceId) public view override(AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
