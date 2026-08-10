// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title GoldKey API License
/// @notice A transferable, fixed-price credential for one 10,000-call GoldKey service term.
/// @dev Quota is enforced by the API against `termNumber`; payment and term state are onchain.
contract GoldKey is ERC721, Ownable2Step, ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint256 public constant MINT_PRICE = 50_000_000; // 50 USDC at 6 decimals.
    uint256 public constant MAX_SUPPLY = 10_000;
    uint256 public constant CALLS_PER_TERM = 10_000;
    uint256 public constant SERVICE_TERM_SECONDS = 365 days;
    uint256 public constant MAX_MINT_QUANTITY = 20;

    IERC20 public immutable USDC;
    bytes32 public immutable LICENSE_TERMS_HASH;

    uint256 public totalMinted;
    address public treasury;
    address public pendingTreasury;
    address public pendingTreasuryProposer;
    bool public salesPaused;

    string public licenseTermsURI;
    string private _fixedBaseURI;

    mapping(uint256 tokenId => uint256 term) public termNumber;
    mapping(uint256 tokenId => uint256 timestamp) public termExpiresAt;
    mapping(uint256 tokenId => uint256 epoch) public ownershipEpoch;

    error InvalidAddress();
    error InvalidPaymentToken();
    error InvalidTermsHash();
    error InvalidQuantity();
    error SoldOut();
    error SalesArePaused();
    error TokenDoesNotExist();
    error NotAuthorizedToRenew();
    error TermStillActive(uint256 expiresAt);
    error IncorrectPaymentReceived(uint256 expected, uint256 received);
    error NoProceeds();
    error NotPendingTreasury();

    event GoldKeyMinted(
        address indexed payer,
        address indexed recipient,
        uint256 indexed tokenId,
        uint256 term,
        uint256 expiresAt,
        uint256 price
    );
    event GoldKeyRenewed(
        address indexed payer,
        uint256 indexed tokenId,
        uint256 indexed term,
        uint256 expiresAt,
        uint256 price
    );
    event OwnershipEpochAdvanced(uint256 indexed tokenId, uint256 indexed epoch);
    event SalesPauseChanged(bool paused);
    event TreasuryProposed(address indexed currentTreasury, address indexed proposedTreasury);
    event TreasuryUpdated(address indexed previousTreasury, address indexed newTreasury);
    event TreasuryProposalCleared(address indexed proposedTreasury);
    event ProceedsWithdrawn(address indexed caller, address indexed treasury, uint256 amount);

    constructor(
        address initialOwner,
        address usdc,
        address initialTreasury,
        string memory baseTokenURI,
        string memory termsURI,
        bytes32 termsHash
    ) ERC721("GoldKey API License", "GOLDKEY") Ownable(initialOwner) {
        if (initialOwner == address(0) || initialTreasury == address(0) || usdc == address(0)) {
            revert InvalidAddress();
        }
        if (usdc.code.length == 0 || IERC20Metadata(usdc).decimals() != 6) {
            revert InvalidPaymentToken();
        }
        if (termsHash == bytes32(0)) revert InvalidTermsHash();

        USDC = IERC20(usdc);
        LICENSE_TERMS_HASH = termsHash;
        treasury = initialTreasury;
        _fixedBaseURI = baseTokenURI;
        licenseTermsURI = termsURI;
    }

    /// @notice Buy between 1 and 20 passes for exactly 50 USDC each.
    function mint(address recipient, uint256 quantity)
        external
        nonReentrant
        returns (uint256 firstTokenId)
    {
        if (salesPaused) revert SalesArePaused();
        if (recipient == address(0)) revert InvalidAddress();
        if (quantity == 0 || quantity > MAX_MINT_QUANTITY) revert InvalidQuantity();
        if (totalMinted + quantity > MAX_SUPPLY) revert SoldOut();

        firstTokenId = totalMinted + 1;
        totalMinted += quantity;
        _collectPayment(MINT_PRICE * quantity);

        for (uint256 tokenId = firstTokenId; tokenId < firstTokenId + quantity; ++tokenId) {
            uint256 expiresAt = block.timestamp + SERVICE_TERM_SECONDS;
            termNumber[tokenId] = 1;
            termExpiresAt[tokenId] = expiresAt;
            _safeMint(recipient, tokenId);
            emit GoldKeyMinted(msg.sender, recipient, tokenId, 1, expiresAt, MINT_PRICE);
        }
    }

    /// @notice Buy the next 10,000-call term as the owner or an approved operator.
    /// @dev Renewal is available only after expiry and starts a fresh one-year term.
    function renew(uint256 tokenId)
        external
        nonReentrant
        returns (uint256 newTerm, uint256 expiresAt)
    {
        if (salesPaused) revert SalesArePaused();
        address tokenOwner = _ownerOf(tokenId);
        if (tokenOwner == address(0)) revert TokenDoesNotExist();
        if (
            msg.sender != tokenOwner && getApproved(tokenId) != msg.sender
                && !isApprovedForAll(tokenOwner, msg.sender)
        ) revert NotAuthorizedToRenew();
        if (termExpiresAt[tokenId] > block.timestamp) {
            revert TermStillActive(termExpiresAt[tokenId]);
        }

        _collectPayment(MINT_PRICE);
        newTerm = termNumber[tokenId] + 1;
        expiresAt = block.timestamp + SERVICE_TERM_SECONDS;
        termNumber[tokenId] = newTerm;
        termExpiresAt[tokenId] = expiresAt;

        emit GoldKeyRenewed(msg.sender, tokenId, newTerm, expiresAt, MINT_PRICE);
    }

    function hasActiveLicense(uint256 tokenId) external view returns (bool) {
        return _ownerOf(tokenId) != address(0) && termExpiresAt[tokenId] > block.timestamp;
    }

    /// @notice Return the complete onchain authorization state in one consistent read.
    function accessState(uint256 tokenId)
        external
        view
        returns (address owner, uint256 term, uint256 expiresAt, uint256 epoch, bool active)
    {
        owner = _ownerOf(tokenId);
        term = termNumber[tokenId];
        expiresAt = termExpiresAt[tokenId];
        epoch = ownershipEpoch[tokenId];
        active = owner != address(0) && expiresAt > block.timestamp;
    }

    /// @notice Anyone may trigger collection, but funds can only reach the approved treasury.
    function withdrawProceeds() external nonReentrant returns (uint256 amount) {
        address destination = treasury;
        amount = USDC.balanceOf(address(this));
        if (amount == 0) revert NoProceeds();
        USDC.safeTransfer(destination, amount);
        emit ProceedsWithdrawn(msg.sender, destination, amount);
    }

    function proposeTreasury(address nextTreasury) external onlyOwner {
        if (nextTreasury == address(0)) revert InvalidAddress();
        pendingTreasury = nextTreasury;
        pendingTreasuryProposer = msg.sender;
        emit TreasuryProposed(treasury, nextTreasury);
    }

    function acceptTreasury() external {
        if (msg.sender != pendingTreasury || pendingTreasuryProposer != owner()) {
            revert NotPendingTreasury();
        }
        address previous = treasury;
        treasury = msg.sender;
        pendingTreasury = address(0);
        pendingTreasuryProposer = address(0);
        emit TreasuryUpdated(previous, msg.sender);
    }

    function setSalesPaused(bool paused) external onlyOwner {
        salesPaused = paused;
        emit SalesPauseChanged(paused);
    }

    function _baseURI() internal view override returns (string memory) {
        return _fixedBaseURI;
    }

    function _update(address to, uint256 tokenId, address auth)
        internal
        override
        returns (address from)
    {
        from = super._update(to, tokenId, auth);
        if (from != address(0) && to != from) {
            uint256 nextEpoch = ownershipEpoch[tokenId] + 1;
            ownershipEpoch[tokenId] = nextEpoch;
            emit OwnershipEpochAdvanced(tokenId, nextEpoch);
        }
    }

    function _transferOwnership(address newOwner) internal override {
        super._transferOwnership(newOwner);
        if (pendingTreasury != address(0)) {
            emit TreasuryProposalCleared(pendingTreasury);
            pendingTreasury = address(0);
            pendingTreasuryProposer = address(0);
        }
    }

    function _collectPayment(uint256 expected) internal {
        uint256 beforeBalance = USDC.balanceOf(address(this));
        USDC.safeTransferFrom(msg.sender, address(this), expected);
        uint256 afterBalance = USDC.balanceOf(address(this));
        uint256 received = afterBalance >= beforeBalance ? afterBalance - beforeBalance : 0;
        if (received != expected) revert IncorrectPaymentReceived(expected, received);
    }
}
