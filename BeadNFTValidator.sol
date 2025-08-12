// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@chainlink/contracts/src/v0.8/functions/v1_0_0/FunctionsClient.sol";
import "@chainlink/contracts/src/v0.8/functions/v1_0_0/libraries/FunctionsRequest.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract BeadNFTValidator is FunctionsClient, AccessControl {
    using FunctionsRequest for FunctionsRequest.Request;

    // --- Chainlink Functions configuration ---
    address private immutable i_routers;
    bytes32 private immutable i_donId;
    uint32 private constant GAS_LIMIT = 300000;
    
    // Universal JavaScript validator - accepts ANY media file type
    string private constant JS_SOURCE =
        "const validateMediaURI = async (args) => {"
        "  if (!args || args.length < 2) {"
        "    return Functions.encodeUint256(0);"
        "  }"
        "  const beadId = args[0];"
        "  const uri = args[1];"
        "  "
        "  // Check if URI is provided"
        "  if (!uri || uri === '') {"
        "    return Functions.encodeUint256(0);"
        "  }"
        "  "
        "  try {"
        "    // Make HTTP request to check if URI is accessible"
        "    const response = await Functions.makeHttpRequest({"
        "      url: uri,"
        "      method: 'HEAD',"  // Use HEAD to check accessibility without downloading
        "      timeout: 15000,"
        "      headers: {"
        "        'User-Agent': 'ChainlinkFunctions/1.0',"
        "        'Accept': '*/*'"
        "      }"
        "    });"
        "    "
        "    if (response.error) {"
        "      console.log('HTTP Error:', response.error);"
        "      return Functions.encodeUint256(0);"
        "    }"
        "    "
        "    // Check if we got a successful response (200-299 status codes)"
        "    if (response.status && (response.status < 200 || response.status >= 400)) {"
        "      console.log('Bad status code:', response.status);"
        "      return Functions.encodeUint256(0);"
        "    }"
        "    "
        "    // Check content-type to ensure it's some kind of media"
        "    const contentType = response.headers && response.headers['content-type'];"
        "    const acceptedTypes = ["
        "      'image/',      // .jpg, .png, .gif, .webp, etc."
        "      'video/',      // .mp4, .mov, .avi, .webm, etc."
        "      'audio/',      // .mp3, .wav, etc."
        "      'application/octet-stream', // Generic binary"
        "      'text/plain'   // Sometimes IPFS returns this"
        "    ];"
        "    "
        "    let isValidType = false;"
        "    if (contentType) {"
        "      isValidType = acceptedTypes.some(type => "
        "        contentType.toLowerCase().includes(type)"
        "      );"
        "    }"
        "    "
        "    // Also accept based on file extension if content-type check fails"
        "    const validExtensions = ["
        "      '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg',"
        "      '.mp4', '.mov', '.avi', '.webm', '.mkv',"
        "      '.mp3', '.wav', '.ogg',"
        "      '.pdf', '.json'"
        "    ];"
        "    "
        "    const hasValidExtension = validExtensions.some(ext => "
        "      uri.toLowerCase().includes(ext)"
        "    );"
        "    "
        "    // Accept if either content-type is valid OR has valid extension"
        "    if (isValidType || hasValidExtension) {"
        "      console.log('Valid media file detected');"
        "      return Functions.encodeUint256(1);"
        "    }"
        "    "
        "    // For IPFS, be more lenient - just check if accessible"
        "    if (uri.toLowerCase().includes('ipfs')) {"
        "      console.log('IPFS URI detected, accepting if accessible');"
        "      return Functions.encodeUint256(1);"
        "    }"
        "    "
        "    console.log('Content type not recognized:', contentType);"
        "    return Functions.encodeUint256(0);"
        "    "
        "  } catch (error) {"
        "    console.log('Validation error:', error.message);"
        "    return Functions.encodeUint256(0);"
        "  }"
        "};"
        "return validateMediaURI(args);";

    // --- Chainlink Functions state ---
    bytes32 public s_lastRequestId;
    bytes public s_lastResponse;
    bytes public s_lastError;
    mapping(bytes32 => string) public requestToBeadId;
    mapping(string => bool) public validatedBeads;
    mapping(string => bool) public validationResults;
    
    // Store URIs and their detected types
    mapping(string => string) public beadURIs;
    mapping(string => string) public detectedContentTypes;

    // Role for BeadNFT contract
    bytes32 public constant BEAD_NFT_ROLE = keccak256("BEAD_NFT_ROLE");

    // Events for Chainlink Functions operations
    event ValidationRequestSent(bytes32 indexed requestId, string beadId, string uri);
    event ValidationFulfilled(
        bytes32 indexed requestId,
        string beadId,
        bool isValid,
        string contentType
    );
    event ValidationFailed(
        bytes32 indexed requestId,
        string beadId,
        bytes error
    );
    event BeadURIStored(string beadId, string uri);

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

    // Function to store URI when preMint is called
    function storeBeadURI(
        string calldata beadId,
        string calldata uri
    ) external onlyRole(BEAD_NFT_ROLE) {
        beadURIs[beadId] = uri;
        emit BeadURIStored(beadId, uri);
    }

    function triggerMetadataValidation(
        uint64 subscriptionId,
        string calldata beadId
    ) external onlyRole(BEAD_NFT_ROLE) returns (bytes32 requestId) {
        string memory uri = beadURIs[beadId];
        require(bytes(uri).length > 0, "No URI stored for this bead");

        FunctionsRequest.Request memory req;
        req.initializeRequestForInlineJavaScript(JS_SOURCE);

        // Pass both beadId and URI to the JavaScript function
        string[] memory args = new string[](2);
        args[0] = beadId;
        args[1] = uri;
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

        emit ValidationRequestSent(requestId, beadId, uri);
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
            
            // Store detected content type (could be enhanced to decode from response)
            detectedContentTypes[beadId] = "validated";
            
            emit
