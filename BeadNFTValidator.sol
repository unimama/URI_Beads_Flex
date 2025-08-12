// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@chainlink/contracts/src/v0.8/functions/v1_0_0/FunctionsClient.sol";
import "@chainlink/contracts/src/v0.8/functions/v1_0_0/libraries/FunctionsRequest.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract BeadNFTValidator is FunctionsClient, AccessControl {
    using FunctionsRequest for FunctionsRequest.sol";

    // --- Chainlink Functions configuration ---
    address private immutable i_routers;
    bytes32 private immutable i_donId;
    uint32 private constant GAS_LIMIT = 300000;
    
    // Updated JavaScript source for filename validation
    string private constant JS_SOURCE =
        "const beadValidation = async (args) => {"
        "  if (!args || args.length < 3) {"
        "    return Functions.encodeUint256(0);"
        "  }"
        "  const beadId = args[0];"
        "  const sku = args[1];"
        "  const fileUrl = args[2];"
        "  try {"
        "    const response = await Functions.makeHttpRequest({"
        "      url: fileUrl,"
        "      method: 'HEAD'"
        "    });"
        "    if (response.error) {"
        "      return Functions.encodeUint256(0);"
        "    }"
        "    const urlParts = fileUrl.split('/');"
        "    const fileName = urlParts[urlParts.length - 1];"
        "    const expectedPrefix = sku + '_' + beadId;"
        "    const fileNameWithoutExt = fileName.substring(0, fileName.lastIndexOf('.'));"
        "    if (fileNameWithoutExt !== expectedPrefix) {"
        "      return Functions.encodeUint256(0);"
        "    }"
        "    const fileExtension = fileName.substring(fileName.lastIndexOf('.') + 1).toLowerCase();"
        "    const validExtensions = ['mov', 'mp4', 'gif', 'pdf', 'jpg', 'jpeg', 'png', 'webp', 'svg', 'mp3', 'wav', 'ogg', 'flac', 'avi', 'mkv', 'webm', 'doc', 'docx', 'txt', 'json'];"
        "    if (!validExtensions.includes(fileExtension)) {"
        "      return Functions.encodeUint256(0);"
        "    }"
        "    return Functions.encodeUint256(1);"
        "  } catch (error) {"
        "    return Functions.encodeUint256(0);"
        "  }"
        "};"
        "return beadValidation(args);";

    // --- Chainlink Functions state ---
    bytes32 public s_lastRequestId;
    bytes public s_lastResponse;
    bytes public s_lastError;
    mapping(bytes32 => string) public requestToBeadId;
    mapping(string => bool) public validatedBeads;
    mapping(string => bool) public validationResults;
    mapping(string => string) public beadIdToSku; // Store SKU for each beadId

    // Role for BeadNFT contract
    bytes32 public constant BEAD_NFT_ROLE = keccak256("BEAD_NFT_ROLE");

    // Events for Chainlink Functions operations
    event ValidationRequestSent(bytes32 indexed requestId, string beadId, string fileUrl);
    event ValidationFulfilled(
        bytes32 indexed requestId,
        string beadId,
        bool isValid
    );
    event ValidationFailed(
        bytes32 indexed requestId,
        string beadId,
        bytes error
    );

    // Errors
    error UnexpectedRequestID(bytes32 requestId);

    constructor(address router, bytes32 donId) FunctionsClient(router) {
        require(router != address(0), "Router address cannot be zero");
        require(donId != bytes32(0), "DON ID cannot be empty");

        i_routers = router;
        i_donId = donId;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function grantBeadNFTRole(
        address beadNFTContract
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(BEAD_NFT_ROLE, beadNFTContract);
    }

    // Function to set SKU for a beadId (called by BeadNFT contract)
    function setBeadSku(
        string calldata beadId,
        string calldata sku
    ) external onlyRole(BEAD_NFT_ROLE) {
        beadIdToSku[beadId] = sku;
    }

    function triggerMetadataValidation(
        uint64 subscriptionId,
        string calldata beadId,
        string calldata fileUrl
    ) external onlyRole(BEAD_NFT_ROLE) returns (bytes32 requestId) {
        require(bytes(fileUrl).length > 0, "File URL cannot be empty");
        
        string memory sku = beadIdToSku[beadId];
        require(bytes(sku).length > 0, "SKU not found for beadId");

        FunctionsRequest.Request memory req;
        req.initializeRequestForInlineJavaScript(JS_SOURCE);

        string[] memory args = new string[](3);
        args[0] = beadId;
        args[1] = sku;
        args[2] = fileUrl;
        req.setArgs(args);

        requestId = _sendRequest(
            req.encodeCBOR(),
            subscriptionId,
            GAS_LIMIT,
            i_donId
        );

        s_lastRequestId = requestId;
        requestToBeadId[requestId] = beadId;
        validatedBeads[beadId] = false;
        validationResults[beadId] = false;

        emit ValidationRequestSent(requestId, beadId, fileUrl);
        return requestId;
    }

    function fulfillRequest(
        bytes32 requestId,
        bytes memory response,
        bytes memory err
    ) internal override {
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

    function getValidationStatus(
        string memory beadId
    )
        external
        view
        returns (bool wasValidationAttempted, bool isCurrentlyValid)
    {
        return (validatedBeads[beadId], validationResults[beadId]);
    }

    function isBeadValidated(
        string memory beadId
    ) external view returns (bool) {
        return validatedBeads[beadId] && validationResults[beadId];
    }

    function checkValidation(
        string memory beadId
    ) external view returns (bool isValidated, bool isValid) {
        return (validatedBeads[beadId], validationResults[beadId]);
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
