// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

interface IBeadNFTValidator {
    function checkValidation(string memory beadId) external view returns (bool isValidated, bool isValid);
    function triggerMetadataValidation(uint64 subscriptionId, string calldata beadId) external returns (bytes32 requestId);
    function getValidationStatus(string memory beadId) external view returns (bool wasValidationAttempted, bool isCurrentlyValid);
    function storeBeadURI(string calldata beadId, string calldata uri) external;
}

contract BeadNFT is ERC721, AccessControl, ReentrancyGuard, Pausable {
    using Strings for uint256;

    struct Bead {
        string beadId;
        string[] uris;
        uint256 preMintDate;
        string sku;
    }

    mapping(string => Bead) private beads;
    mapping(string => bool) private beadExists;
    mapping(uint256 => string) private tokenIdToBeadId;
    mapping(string => uint256) private beadIdToTokenId;
    string[] private beadList;
    uint256 private nonce;
    uint256 private totalMinted;
    uint256 private nextTokenId = 1;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    mapping(address => bool) public isAuthorizedWallet;

    // Validator will be set after deployment
    address public validatorAddress;

    event BeadCreated(string beadId, string sku);
    event BeadPreMinted(string beadId, string uri, uint256 timestamp);
    event BeadMinted(string beadId, uint256 tokenId, address owner);

    constructor() ERC721("BeadNFT", "BEAD") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        isAuthorizedWallet[msg.sender] = true;
    }

    modifier onlyAuthorized() {
        require(isAuthorizedWallet[msg.sender] || hasRole(ADMIN_ROLE, msg.sender), "Not authorized");
        _;
    }

    function setValidator(address _validator) external onlyRole(ADMIN_ROLE) {
        validatorAddress = _validator;
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
        for (uint256 i = 0; i < 8; i++) {
            beadIdBytes[i] = charset[uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender, _localNonce + i))) % charset.length];
        }
        return string(beadIdBytes);
    }

    function createBeadIds(string memory sku, uint256 qty) external onlyAuthorized whenNotPaused nonReentrant {
        require(qty > 0 && qty <= 100, "Invalid quantity");
        require(bytes(sku).length > 0, "SKU cannot be empty");

        for (uint256 i = 0; i < qty; i++) {
            string memory beadId = generateBeadId();
            beads[beadId] = Bead(beadId, new string[](0), 0, sku);
            beadList.push(beadId);
            emit BeadCreated(beadId, sku);
        }
    }

    function preMint(string memory beadId, string memory uri) external onlyAuthorized whenNotPaused nonReentrant {
        require(beadExists[beadId], "Bead ID does not exist");
        require(beads[beadId].preMintDate == 0, "Bead already pre-minted");
        require(bytes(uri).length > 0, "URI cannot be empty");

        beads[beadId].uris.push(uri);
        beads[beadId].preMintDate = block.timestamp;
        
        if (validatorAddress != address(0)) {
            IBeadNFTValidator(validatorAddress).storeBeadURI(beadId, uri);
        }
        
        emit BeadPreMinted(beadId, uri, block.timestamp);
    }

    function triggerMetadataValidation(uint64 subscriptionId, string calldata beadId) external onlyAuthorized whenNotPaused returns (bytes32 requestId) {
        require(beadExists[beadId], "Bead ID does not exist");
        require(validatorAddress != address(0), "Validator not set");
        return IBeadNFTValidator(validatorAddress).triggerMetadataValidation(subscriptionId, beadId);
    }

    function mintBead(string memory beadId) external onlyAuthorized whenNotPaused nonReentrant {
        require(beadExists[beadId], "Bead ID does not exist");
        require(beads[beadId].preMintDate > 0, "Bead must be pre-minted first");
        require(beadIdToTokenId[beadId] == 0, "Bead already minted");

        if (validatorAddress != address(0)) {
            (bool isValidated, bool isValid) = IBeadNFTValidator(validatorAddress).checkValidation(beadId);
            require(isValidated, "Metadata validation not yet performed");
            require(isValid, "Metadata validation failed");
        }

        uint256 tokenId = nextTokenId++;
        _mint(msg.sender, tokenId);
        tokenIdToBeadId[tokenId] = beadId;
        beadIdToTokenId[beadId] = tokenId;
        totalMinted++;
        emit BeadMinted(beadId, tokenId, msg.sender);
    }

    function getBead(string memory beadId) external view returns (Bead memory) {
        require(beadExists[beadId], "Bead ID does not exist");
        return beads[beadId];
    }

    function listBeads(uint256 offset, uint256 limit) external view returns (Bead[] memory) {
        require(limit <= 50, "Limit too large");
        if (offset >= beadList.length) return new Bead[](0);
        
        uint256 resultSize = (offset + limit > beadList.length) ? beadList.length - offset : limit;
        Bead[] memory result = new Bead[](resultSize);
        
        for (uint256 i = 0; i < resultSize; i++) {
            result[i] = beads[beadList[offset + i]];
        }
        return result;
    }

    function getTotalBeads() external view returns (uint256) {
        return beadList.length;
    }

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        _requireOwned(tokenId);
        string memory beadId = tokenIdToBeadId[tokenId];
        string[] memory uris = beads[beadId].uris;
        require(uris.length > 0, "No URI set");
        return uris[uris.length - 1];
    }

    function getValidatorAddress() external view returns (address) {
        return validatorAddress;
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC721, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
