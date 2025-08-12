// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@chainlink/contracts/src/v0.8/interfaces/LinkTokenInterface.sol";
import "@chainlink/contracts/src/v0.8/shared/access/ConfirmedOwner.sol";
import "./BeadNFTValidator.sol";

interface IBeadNFTValidator {
    function checkValidation(string memory beadId) external view returns (bool isValidated, bool isValid);
    function triggerMetadataValidation(uint64 subscriptionId, string calldata beadId) external returns (bytes32 requestId);
    function getValidationStatus(string memory beadId) external view returns (bool wasValidationAttempted, bool isCurrentlyValid);
    function storeBeadURI(string calldata beadId, string calldata uri) external;
}

contract BeadNFT is ERC721, ConfirmedOwner, ReentrancyGuard, AccessControl, Pausable {
    using Strings for uint256;

    address private constant LINK_TOKEN = 0x779877A7B0D9E8603169DdbD7836e478b4624789;
    LinkTokenInterface private constant LINK = LinkTokenInterface(LINK_TOKEN);

    BeadNFTValidator public validator;

    event BeadCreated(string beadId, string sku);
    event BeadPreMinted(string beadId, string uri, uint256 timestamp);
    event BeadMinted(string beadId, uint256 tokenId, address owner);
    event BeadURIUpdated(string beadId, uint256 tokenId, string newUri, address updater);

    struct Bead {
        string beadId;
        string[] uris;
        uint256 preMintDate;
        string sku;
    }

    uint256 private constant MAX_URI_HISTORY = 100;
    uint256 private constant MAX_BATCH_SIZE = 500;
    uint256 private constant MAX_QUERY_RESULT = 200;

    mapping(string => Bead) private beads;
    mapping(string => bool) private beadExists;
    mapping(uint256 => string) private tokenIdToBeadId;
    mapping(string => uint256) private beadIdToTokenId;
    string[] private beadList;
    uint256 private nonce;
    uint256 private totalMinted;
    uint256 private nextTokenId = 1;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    address[] public authorizedWallets;
    mapping(address => bool) public isAuthorizedWallet;

    constructor() ERC721("BeadNFT", "BEAD") ConfirmedOwner(msg.sender) {
        address router = 0xb83E47C2bC239B3bf370bc41e1459A34b41238D0;
        bytes32 donId = 0x66756e2d657468657265756d2d7365706f6c69612d3100000000000000000000;

        validator = new BeadNFTValidator(router, donId);
        validator.grantBeadNFTRole(address(this));

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);

        authorizedWallets.push(msg.sender);
        isAuthorizedWallet[msg.sender] = true;
    }

    modifier validateURI(string memory uri) {
        require(bytes(uri).length > 0, "URI cannot be empty");
        require(bytes(uri).length <= 2048, "URI too long");
        _;
    }

    modifier validateBeadId(string memory beadId) {
        require(bytes(beadId).length > 0, "Bead ID cannot be empty");
        require(bytes(beadId).length <= 32, "Bead ID too long");
        _;
    }

    modifier onlyAuthorized() {
        require(isAuthorizedWallet[msg.sender] || hasRole(ADMIN_ROLE, msg.sender), "Not authorized");
        _;
    }

    function generateBeadId() internal returns (string memory) {
        string memory beadId;
        uint256 tempNonce = nonce;
        do {
            beadId = _randomBeadId(tempNonce++);
        } while (beadExists[beadId]);
        nonce = tempNonce;
        beadExists[beadId] = true;
        return beadId;
    }

    function _randomBeadId(uint256 _localNonce) internal view returns (string memory) {
        bytes memory charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        bytes memory beadIdBytes = new bytes(8);
        unchecked {
            for (uint256 i = 0; i < 8; i++) {
                beadIdBytes[i] = charset[
                    uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender, _localNonce + i))) % charset.length
                ];
            }
        }
        return string(beadIdBytes);
    }

    function createBeadIds(string memory sku, uint256 qty) external onlyAuthorized whenNotPaused nonReentrant {
        require(qty > 0, "Quantity must be greater than zero");
        require(qty <= MAX_BATCH_SIZE, "Batch size too large");
        require(bytes(sku).length > 0, "SKU cannot be empty");
        require(bytes(sku).length <= 64, "SKU too long");

        string[] memory tempIds = new string[](qty);
        for (uint256 i = 0; i < qty; i++) {
            tempIds[i] = generateBeadId();
        }

        for (uint256 i = 0; i < qty; i++) {
            beads[tempIds[i]] = Bead(tempIds[i], new string[](0), 0, sku);
            beadList.push(tempIds[i]);
            emit BeadCreated(tempIds[i], sku);
        }
    }

    function listBeads(uint256 offset, uint256 limit) external view returns (Bead[] memory) {
        require(limit <= MAX_QUERY_RESULT, "Result set too large");
        if (offset >= beadList.length && beadList.length > 0) {
            revert("Offset out of bounds");
        }

        uint256 resultSize = 0;
        if (beadList.length > offset) {
            resultSize = (offset + limit > beadList.length) ? beadList.length - offset : limit;
        }

        Bead[] memory beadArray = new Bead[](resultSize);
        for (uint256 i = 0; i < resultSize; i++) {
            beadArray[i] = beads[beadList[offset + i]];
        }
        return beadArray;
    }

    function getTotalBeads() external view returns (uint256) {
        return beadList.length;
    }

    function triggerMetadataValidation(uint64 subscriptionId, string calldata beadId) external onlyAuthorized whenNotPaused returns (bytes32 requestId) {
        require(beadExists[beadId], "Bead ID does not exist");
        return validator.triggerMetadataValidation(subscriptionId, beadId);
    }

    function getValidationStatus(string memory beadId) external view returns (bool wasValidationAttempted, bool isCurrentlyValid) {
        require(beadExists[beadId], "Bead ID does not exist");
        return validator.getValidationStatus(beadId);
    }

    function preMint(string memory beadId, string memory uri) external onlyAuthorized whenNotPaused validateBeadId(beadId) validateURI(uri) nonReentrant {
        require(beadExists[beadId], "Bead ID does not exist");
        require(beads[beadId].preMintDate == 0, "Bead already pre-minted");

        beads[beadId].uris.push(uri);
        beads[beadId].preMintDate = block.timestamp;
        validator.storeBeadURI(beadId, uri);
        emit BeadPreMinted(beadId, uri, block.timestamp);
    }

    function mintBead(string memory beadId) external onlyAuthorized whenNotPaused validateBeadId(beadId) nonReentrant {
        require(beadExists[beadId], "Bead ID does not exist");
        require(beads[beadId].preMintDate > 0, "Bead must be pre-minted first");
        require(beadIdToTokenId[beadId] == 0, "Bead already minted");

        (bool isValidated, bool isValid) = validator.checkValidation(beadId);
        require(isValidated, "Metadata validation not yet performed/completed for this beadId.");
        require(isValid, "Metadata validation failed for this beadId.");

        uint256 tokenId = nextTokenId;
        nextTokenId++;

        _mint(msg.sender, tokenId);
        tokenIdToBeadId[tokenId] = beadId;
        beadIdToTokenId[beadId] = tokenId;
        totalMinted++;
        emit BeadMinted(beadId, tokenId, msg.sender);
    }

    function getBead(string memory beadId) external view validateBeadId(beadId) returns (Bead memory) {
        require(beadExists[beadId], "Bead ID does not exist");
        return beads[beadId];
    }

    function totalSupply() external view returns (uint256) {
        return totalMinted;
    }

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        _requireOwned(tokenId);
        string memory beadId = tokenIdToBeadId[tokenId];
        require(bytes(beadId).length > 0, "BeadNFT: URI query for nonexistent bead");

        string[] memory uris = beads[beadId].uris;
        require(uris.length > 0, "BeadNFT: No URI set for this bead");
        return uris[uris.length - 1];
    }

    function getTokenIdByBeadId(string memory beadId) public view returns (uint256) {
        require(beadExists[beadId], "Bead ID does not exist");
        require(beadIdToTokenId[beadId] != 0, "Bead not yet minted");
        return beadIdToTokenId[beadId];
    }

    function updateBeadURI(string memory beadId, string memory newUri) external onlyAuthorized whenNotPaused validateBeadId(beadId) validateURI(newUri) nonReentrant {
        require(beadExists[beadId], "Bead ID does not exist");
        require(beadIdToTokenId[beadId] != 0, "Bead must be minted first");

        uint256 tokenId = beadIdToTokenId[beadId];
        require(_ownerOf(tokenId) != address(0), "BeadNFT: URI update for unminted bead");
        require(beads[beadId].uris.length < MAX_URI_HISTORY, "Maximum URI history reached");

        beads[beadId].uris.push(newUri);
        emit BeadURIUpdated(beadId, tokenId, newUri, msg.sender);
    }

    function getBeadIdByTokenId(uint256 tokenId) external view returns (string memory) {
        string memory beadId = tokenIdToBeadId[tokenId];
        require(bytes(beadId).length > 0, "BeadNFT: Query for nonexistent token");
        return beadId;
    }

    function isBeadMinted(string memory beadId) external view returns (bool) {
        require(beadExists[beadId], "Bead ID does not exist");
        return beadIdToTokenId[beadId] != 0;
    }

    function getValidatorAddress() external view returns (address) {
        return address(validator);
    }

    function addAuthorizedWallet(address wallet) external onlyRole(ADMIN_ROLE) {
        require(wallet != address(0), "Invalid wallet address");
        require(!isAuthorizedWallet[wallet], "Wallet already authorized");
        authorizedWallets.push(wallet);
        isAuthorizedWallet[wallet] = true;
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC721, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
