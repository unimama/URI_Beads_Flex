// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@chainlink/contracts/src/v0.8/functions/v1_0_0/FunctionsClient.sol";
import "@chainlink/contracts/src/v0.8/functions/v1_0_0/libraries/FunctionsRequest.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract BeadNFTValidator is FunctionsClient, AccessControl {
    using FunctionsRequest for FunctionsRequest.Request;

    address private immutable i_routers;
    bytes32 private immutable i_donId;
    uint32 private constant GAS_LIMIT = 300000;
    
    // Simplified JavaScript - much shorter
    string private constant JS_SOURCE =
        "const check = async (args) => {"
        "if (!args || !args[1]) return Functions.encodeUint256(0);"
        "try {"
        "const r = await Functions.makeHttpRequest({url: args[1], method: 'HEAD', timeout: 10000});"
        "if (r.error || (r.status && r.status >= 400)) return Functions.encodeUint256(0);"
        "const ct = r.headers && r.headers['content-type'];"
        "const validTypes = ['image/', 'video/', 'audio/', 'application/octet-stream'];"
        "const validExts = ['.jpg', '.png', '.gif', '.mp4', '.mov', '.pdf'];"
        "if ((ct && validTypes.some(t => ct.includes(t))) || validExts.some(e => args[1].includes(e)) || args[1].includes('ipfs')) return Functions.encodeUint256(1);"
        "return Functions.encodeUint256(0);"
        "} catch { return Functions.encodeUint256(0); }"
        "};"
        "return check(args);";

    bytes32 public s_lastRequestId;
    bytes public s_lastResponse;
    bytes public s_lastError;
    mapping(bytes32 => string) public requestToBeadId;
    mapping(string => bool) public validatedBeads;
    mapping(string => bool) public validationResults;
    mapping(string => string) public beadURIs;

    bytes32 public constant BEAD_NFT_ROLE = keccak256("BEAD_NFT_ROLE");

    event ValidationRequestSent(bytes32 indexed requestId, string beadId, string uri);
    event ValidationFulfilled(bytes32 indexed requestId, string beadId, bool isValid);
    event ValidationFailed(bytes32 indexed requestId, string beadId, bytes error);
    event BeadURIStored(string beadId, string uri);

    error UnexpectedRequestID(bytes32 requestId);

    constructor(address router, bytes32 donId) FunctionsClient(router) {
        require(router != address(0), "Router address cannot be zero");
        require(donId != bytes32(0), "DON ID cannot be empty");
        i_routers = router;
        i_donId = donId;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function grantBeadNFTRole(address beadNFTContract) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(BEAD_NFT_ROLE, beadNFTContract);
    }

    function storeBeadURI(string calldata beadId, string calldata uri) external onlyRole(BEAD_NFT_ROLE) {
        beadURIs[beadId] = uri;
        emit BeadURIStored(beadId, uri);
    }

    function triggerMetadataValidation(uint64 subscriptionId, string calldata beadId) external onlyRole(BEAD_NFT_ROLE) returns (bytes32 requestId) {
        string memory uri = beadURIs[beadId];
        require(bytes(uri).length > 0, "No URI stored for this bead");

        FunctionsRequest.Request memory req;
        req.initializeRequestForInlineJavaScript(JS_SOURCE);

        string[] memory args = new string[](2);
        args[0] = beadId;
        args[1] = uri;
        req.setArgs(args);

        requestId = _sendRequest(req.encodeCBOR(), subscriptionId, GAS_LIMIT, i_donId);

        s_lastRequestId = requestId;
        requestToBeadId[requestId] = beadId;
        validatedBeads[beadId] = false;
        validationResults[beadId] = false;

        emit ValidationRequestSent(requestId, beadId, uri);
        return requestId;
    }

    function fulfillRequest(bytes32 requestId, bytes memory response, bytes memory err) internal override {
        string memory beadId = requestToBeadId[requestId];
        if (bytes(beadId).length == 0) {
            revert UnexpectedRequestID(requestId);
        }

        s_lastResponse = response;
        s_lastError = err;

        if (err.length == 0) {
            uint256 isValidNum = abi.decode(response, (uint256));
            validatedBeads[beadId] = true;
            validationResults[beadId] = (isValidNum == 1);
            emit ValidationFulfilled(requestId, beadId, (isValidNum == 1));
        } else {
            validatedBeads[beadId] = true;
            validationResults[beadId] = false;
            emit ValidationFailed(requestId, beadId, err);
        }
        delete requestToBeadId[requestId];
    }

    function getValidationStatus(string memory beadId) external view returns (bool wasValidationAttempted, bool isCurrentlyValid) {
        return (validatedBeads[beadId], validationResults[beadId]);
    }

    function isBeadValidated(string memory beadId) external view returns (bool) {
        return validatedBeads[beadId] && validationResults[beadId];
    }

    function checkValidation(string memory beadId) external view returns (bool isValidated, bool isValid) {
        return (validatedBeads[beadId], validationResults[beadId]);
    }

    function getBeadURI(string memory beadId) external view returns (string memory) {
        return beadURIs[beadId];
    }

    function getSupportedFileTypes() external pure returns (string memory) {
        return "Images: .jpg, .png, .gif | Videos: .mp4, .mov | Audio/Other: .pdf | IPFS URIs | Web2 URLs";
    }

    function supportsInterface(bytes4 interfaceId) public view override(AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
