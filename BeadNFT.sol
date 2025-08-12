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
    function isBeadValidated(string memory beadId) external view returns (bool);
    function checkValidation(
        string memory beadId
    ) external view returns (bool isValidated, bool isValid);
    function triggerMetadataValidation(
        uint64 subscriptionId,
        string calldata beadId
    ) external returns (bytes32 requestId);
    function getValidationStatus(
        string memory beadId
    )
        external
        view
        returns (bool wasValidationAttempted, bool isCurrentlyValid);
    function storeBeadURI(
        string calldata beadId,
        string calldata uri
    ) external;
}

contract BeadNFT is
    ERC721,
    ConfirmedOwner,
    ReentrancyGuard,
    AccessControl,
    Pausable
{
    using Strings for uint256;

    // Sepolia LINK Token address
    address private constant LINK_TOKEN = 0x779877A7B0D9E8603169DdbD7836e478b4624789;
    LinkTokenInterface private constant LINK = LinkTokenInterface(LINK_TOKEN);

    // Validator contract reference
    BeadNFTValidator public validator;

    // Events for security features
    event BeadEmergencyStop(string indexed beadId, address indexed by);
    event BeadEmergencyResume(string indexed beadId, address indexed by);
    event WalletAuthorized(address indexed wallet, address indexed by);
    event WalletDeauthorized(address indexed wallet, address indexed by);

    struct Bead {
        string beadId;
        string[] uris;
        uint256 preMintDate;
        string sku;
    }

    // Maximum limits to prevent DoS attacks
    uint256 private constant MAX_URI_HISTORY = 100;
    uint256 private constant MAX_BATCH_SIZE = 500;
    uint256 private constant MAX_QUERY_RESULT = 200;

    mapping(string => Bead) private beads;
    mapping(string => bool) private beadExists;
    mapping(uint256 => string) private tokenIdToBeadId;
    mapping(string => uint256) private beadIdToTokenId;
    string[] private beadList;
    uint256 private nonce; // Used for randomBeadId generation
    uint256 private totalMinted;
    uint256 private nextTokenId = 1; // Sequential token ID counter starting from 1

    // Original Events
    event BeadCreated(string beadId, string sku);
    event BeadPreMinted(string beadId, string uri, uint256 timestamp);
    event BeadMinted(string beadId, uint256 tokenId, address owner);
    event BeadURIUpdated(
        string beadId,
        uint256 tokenId,
        string newUri,
        address updater
    );

    // Access Control Roles
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // Multisig wallets (simple implementation)
    address[] public authorizedWallets;
    mapping(address => bool) public isAuthorizedWallet;

    // Emergency stop for individual beads
    mapping(string => bool) public emergencyStoppedBeads;

    constructor() ERC721("BeadNFT", "BEAD") ConfirmedOwner(msg.sender) {
        // Sepolia Chainlink Functions Router
        address router = 0xb83E47C2bC239B3bf370bc41e1459A34b41238D0;
        // Sepolia DON ID for Functions
        bytes32 donId = 0x66756e2d657468657265756d2d7365706f6c69612d3100000000000000000000;

        // Deploy validator contract with Sepolia parameters
        validator = new BeadNFTValidator(router, donId);
        validator.grantBeadNFTRole(address(this));

        // Set up roles
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);

        // Add deployer as first authorized wallet
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
        require(
            isAuthorizedWallet[msg.sender] || hasRole(ADMIN_ROLE, msg.sender),
            "Not authorized"
        );
        _;
    }

    modifier notEmergencyStopped(string memory beadId) {
        require(
            !emergencyStoppedBeads[beadId],
            "Bead operations are emergency stopped"
        );
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

    function _randomBeadId(
        uint256 _localNonce
    ) internal view returns (string memory) {
        bytes memory charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        bytes memory beadIdBytes = new bytes(8);
        unchecked {
            for (uint256 i = 0; i < 8; i++) {
                beadIdBytes[i] = charset[
                    uint256(
                        keccak256(
                            abi.encodePacked(
                                block.timestamp,
                                msg.sender,
                                _localNonce + i
                            )
                        )
                    ) % charset.length
                ];
            }
        }
        return string(beadIdBytes);
    }

    function createBeadIds(
        string memory sku,
        uint256 qty
    ) external onlyAuthorized whenNotPaused nonReentrant {
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

    function listBeads(
        uint256 offset,
        uint256 limit
    ) external view returns (Bead[] memory) {
        require(limit <= MAX_QUERY_RESULT, "Result set too large");
        if (offset >= beadList.length && beadList.length > 0) {
            revert("Offset out of bounds");
        }
        if (beadList.length == 0 && offset > 0) {
            revert("Offset out of bounds for empty list");
        }

        uint256 resultSize = 0;
        if (beadList.length > offset) {
            resultSize = (offset + limit > beadList.length)
                ? beadList.length - offset
                : limit;
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

    function listAvailableBeads(
        uint256 offset,
        uint256 limit
    ) external view returns (Bead[] memory) {
        require(limit <= MAX_QUERY_RESULT, "Result set too large");

        uint256 totalAvailable = 0;
        for (uint256 i = 0; i < beadList.length; i++) {
            if (beads[beadList[i]].preMintDate == 0) {
                totalAvailable++;
            }
        }

        if (offset >= totalAvailable && totalAvailable > 0) {
            return new Bead[](0);
        }
        if (totalAvailable == 0 && offset > 0) {
            return new Bead[](0);
        }

        uint256 actualLimit = totalAvailable > offset
            ? totalAvailable - offset
            : 0;
        uint256 resultSize = limit < actualLimit ? limit : actualLimit;

        Bead[] memory availableBeads = new Bead[](resultSize);
        uint256 collected = 0;
        uint256 currentIndex = 0;

        for (
            uint256 i = 0;
            i < beadList.length && currentIndex < resultSize;
            i++
        ) {
            if (beads[beadList[i]].preMintDate == 0) {
                if (collected >= offset) {
                    availableBeads[currentIndex++] = beads[beadList[i]];
                }
                collected++;
            }
        }
        return availableBeads;
    }

    function triggerMetadataValidation(
        uint64 subscriptionId,
        string calldata beadId
    )
        external
        onlyAuthorized
        whenNotPaused
        notEmergencyStopped(beadId)
        returns (bytes32 requestId)
    {
        require(beadExists[beadId], "Bead ID does not exist");

        return validator.triggerMetadataValidation(subscriptionId, beadId);
    }

    function getValidationStatus(
        string memory beadId
    )
        external
        view
        returns (bool wasValidationAttempted, bool isCurrentlyValid)
    {
        require(beadExists[beadId], "Bead ID does not exist");
        return validator.getValidationStatus(beadId);
    }

    function preMint(
        string memory beadId,
        string memory uri
    )
        external
        onlyAuthorized
        whenNotPaused
        validateBeadId(beadId)
        validateURI(uri)
        notEmergencyStopped(beadId)
        nonReentrant
    {
        require(beadExists[beadId], "Bead ID does not exist");
        require(beads[beadId].preMintDate == 0, "Bead already pre-minted");

        beads[beadId].uris.push(uri);
        beads[beadId].preMintDate = block.timestamp;
        
        // Store the URI in the validator for later validation
        validator.storeBeadURI(beadId, uri);
        
        emit BeadPreMinted(beadId, uri, block.timestamp);
    }

    function mintBead(
        string memory beadId
    )
        external
        onlyAuthorized
        whenNotPaused
        validateBeadId(beadId)
        notEmergencyStopped(beadId)
        nonReentrant
    {
        require(beadExists[beadId], "Bead ID does not exist");
        require(beads[beadId].preMintDate > 0, "Bead must be pre-minted first");
        require(beadIdToTokenId[beadId] == 0, "Bead already minted");

        (bool isValidated, bool isValid) = validator.checkValidation(beadId);
        require(
            isValidated,
            "Metadata validation not yet performed/completed for this beadId."
        );
        require(isValid, "Metadata validation failed for this beadId.");

        uint256 tokenId = nextTokenId;
        nextTokenId++;

        _mint(msg.sender, tokenId);
        tokenIdToBeadId[tokenId] = beadId;
        beadIdToTokenId[beadId] = tokenId;
        totalMinted++;
        emit BeadMinted(beadId, tokenId, msg.sender);
    }

    function getBead(
        string memory beadId
    ) external view validateBeadId(beadId) returns (Bead memory) {
        require(beadExists[beadId], "Bead ID does not exist");
        return beads[beadId];
    }

    function totalSupply() external view returns (uint256) {
        return totalMinted;
    }

    function tokenURI(
        uint256 tokenId
    ) public view virtual override returns (string memory) {
        _requireOwned(tokenId);
        string memory beadId = tokenIdToBeadId[tokenId];
        require(
            bytes(beadId).length > 0,
            "BeadNFT: URI query for nonexistent bead"
        );

        string[] memory uris = beads[beadId].uris;
        require(uris.length > 0, "BeadNFT: No URI set for this bead");
        return uris[uris.length - 1];
    }

    function tokenURIs(uint256 tokenId) public view returns (string[] memory) {
        _requireOwned(tokenId);
        string memory beadId = tokenIdToBeadId[tokenId];
        require(
            bytes(beadId).length > 0,
            "BeadNFT: URI query for nonexistent bead"
        );
        return beads[beadId].uris;
    }

    function getTokenIdByBeadId(
        string memory beadId
    ) public view returns (uint256) {
        require(beadExists[beadId], "Bead ID does not exist");
        require(beadIdToTokenId[beadId] != 0, "Bead not yet minted");

        return beadIdToTokenId[beadId];
    }

    function updateBeadURI(
        string memory beadId,
        string memory newUri
    )
        external
        onlyAuthorized
        whenNotPaused
        validateBeadId(beadId)
        validateURI(newUri)
        notEmergencyStopped(beadId)
        nonReentrant
    {
        require(beadExists[beadId], "Bead ID does not exist");
        require(beadIdToTokenId[beadId] != 0, "Bead must be minted first");

        uint256 tokenId = beadIdToTokenId[beadId];
        require(
            _ownerOf(tokenId) != address(0),
            "BeadNFT: URI update for unminted bead"
        );
        require(
            beads[beadId].uris.length < MAX_URI_HISTORY,
            "Maximum URI history reached"
        );

        beads[beadId].uris.push(newUri);
        emit BeadURIUpdated(beadId, tokenId, newUri, msg.sender);
    }

    function getBeadIdByTokenId(
        uint256 tokenId
    ) external view returns (string memory) {
        string memory beadId = tokenIdToBeadId[tokenId];
        require(
            bytes(beadId).length > 0,
            "BeadNFT: Query for nonexistent token"
        );
        return beadId;
    }

    function isBeadMinted(string memory beadId) external view returns (bool) {
        require(beadExists[beadId], "Bead ID does not exist");
        return beadIdToTokenId[beadId] != 0;
    }

    function getBeadURIs(
        string memory beadId
    ) external view validateBeadId(beadId) returns (string[] memory) {
        require(beadExists[beadId], "Bead ID does not exist");
        return beads[beadId].uris;
    }

    function withdrawLink() external onlyOwner {
        uint256 balance = LINK.balanceOf(address(this));
        require(balance > 0, "No LINK tokens to withdraw");
        require(LINK.transfer(owner(), balance), "LINK transfer failed");
    }

    function getLinkBalance() external view returns (uint256) {
        return LINK.balanceOf(address(this));
    }

    function getNextTokenId() external view returns (uint256) {
        return nextTokenId;
    }

    function getValidatorAddress() external view returns (address) {
        return address(validator);
    }

    // === SECURITY MANAGEMENT FUNCTIONS ===

    // Multisig wallet management
    function addAuthorizedWallet(address wallet) external onlyRole(ADMIN_ROLE) {
        require(wallet != address(0), "Invalid wallet address");
        require(!isAuthorizedWallet[wallet], "Wallet already authorized");

        authorizedWallets.push(wallet);
        isAuthorizedWallet[wallet] = true;
        emit WalletAuthorized(wallet, msg.sender);
    }

    function removeAuthorizedWallet(
        address wallet
    ) external onlyRole(ADMIN_ROLE) {
        require(isAuthorizedWallet[wallet], "Wallet not authorized");
        require(
            authorizedWallets.length > 1,
            "Cannot remove last authorized wallet"
        );

        isAuthorizedWallet[wallet] = false;

        // Remove from array
        for (uint256 i = 0; i < authorizedWallets.length; i++) {
            if (authorizedWallets[i] == wallet) {
                authorizedWallets[i] = authorizedWallets[
                    authorizedWallets.length - 1
                ];
                authorizedWallets.pop();
                break;
            }
        }

        emit WalletDeauthorized(wallet, msg.sender);
    }

    function getAuthorizedWallets() external view returns (address[] memory) {
        return authorizedWallets;
    }

    // Pausing functionality
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // Emergency stop for individual beads
    function emergencyStopBead(
        string memory beadId
    ) external onlyRole(ADMIN_ROLE) {
        require(beadExists[beadId], "Bead ID does not exist");
        require(
            !emergencyStoppedBeads[beadId],
            "Bead already emergency stopped"
        );

        emergencyStoppedBeads[beadId] = true;
        emit BeadEmergencyStop(beadId, msg.sender);
    }

    function emergencyResumeBead(
        string memory beadId
    ) external onlyRole(ADMIN_ROLE) {
        require(beadExists[beadId], "Bead ID does not exist");
        require(emergencyStoppedBeads[beadId], "Bead not emergency stopped");

        emergencyStoppedBeads[beadId] = false;
        emit BeadEmergencyResume(beadId, msg.sender);
    }

    function isBeadEmergencyStopped(
        string memory beadId
    ) external view returns (bool) {
        return emergencyStoppedBeads[beadId];
    }

    // Role management helpers
    function grantAdminRole(
        address account
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(ADMIN_ROLE, account);
    }

    function grantPauserRole(address account) external onlyRole(ADMIN_ROLE) {
        _grantRole(PAUSER_ROLE, account);
    }

    function revokeAdminRole(
        address account
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(ADMIN_ROLE, account);
    }

    function revokePauserRole(address account) external onlyRole(ADMIN_ROLE) {
        _revokeRole(PAUSER_ROLE, account);
    }

    // Required override for AccessControl
    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC721, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
