// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import { GoldKey } from "../src/GoldKey.sol";

interface Vm {
    function warp(uint256 timestamp) external;
}

contract MockUSDC is ERC20 {
    constructor() ERC20("Mock USDC", "USDC") { }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract FeeUSDC is MockUSDC {
    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0) && value > 1) {
            super._update(from, to, value - 1);
            super._update(from, address(0), 1);
        } else {
            super._update(from, to, value);
        }
    }
}

contract BuyerActor is IERC721Receiver {
    function buy(GoldKey key, MockUSDC usdc, address recipient, uint256 quantity)
        external
        returns (uint256)
    {
        usdc.approve(address(key), key.MINT_PRICE() * quantity);
        return key.mint(recipient, quantity);
    }

    function renew(GoldKey key, MockUSDC usdc, uint256 tokenId) external {
        usdc.approve(address(key), key.MINT_PRICE());
        key.renew(tokenId);
    }

    function transfer(GoldKey key, address to, uint256 tokenId) external {
        key.transferFrom(address(this), to, tokenId);
    }

    function onERC721Received(address, address, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IERC721Receiver.onERC721Received.selector;
    }
}

contract NonReceiver { }

contract ReentrantReceiver is IERC721Receiver {
    GoldKey internal target;
    bool public reentrySucceeded;

    function attack(GoldKey key, MockUSDC usdc) external {
        target = key;
        usdc.approve(address(key), key.MINT_PRICE() * 2);
        key.mint(address(this), 1);
    }

    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        (reentrySucceeded,) = address(target).call(abi.encodeCall(GoldKey.mint, (address(this), 1)));
        return IERC721Receiver.onERC721Received.selector;
    }
}

contract SafeReceiver is IERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IERC721Receiver.onERC721Received.selector;
    }
}

contract TreasuryActor {
    function accept(GoldKey key) external {
        key.acceptTreasury();
    }

    function acceptOwnership(GoldKey key) external {
        key.acceptOwnership();
    }

    function proposeTreasury(GoldKey key, address nextTreasury) external {
        key.proposeTreasury(nextTreasury);
    }
}

contract GoldKeyTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    MockUSDC internal usdc;
    GoldKey internal key;
    BuyerActor internal buyer;
    SafeReceiver internal receiver;
    TreasuryActor internal treasury;

    function setUp() public {
        usdc = new MockUSDC();
        treasury = new TreasuryActor();
        key = new GoldKey(
            address(this),
            address(usdc),
            address(treasury),
            "https://api.goldkey.example/metadata/",
            "https://api.goldkey.example/terms",
            keccak256("goldkey-terms-v1")
        );
        buyer = new BuyerActor();
        receiver = new SafeReceiver();
        usdc.mint(address(buyer), 10_000_000_000);
    }

    function testConstantsEncodeHalfMillionPrimaryCap() public view {
        require(key.MINT_PRICE() == 50_000_000, "wrong price");
        require(key.MAX_SUPPLY() == 10_000, "wrong max supply");
        require(key.MINT_PRICE() * key.MAX_SUPPLY() == 500_000_000_000, "wrong gross cap");
        require(key.CALLS_PER_TERM() == 10_000, "wrong term allowance");
        require(key.SERVICE_TERM_SECONDS() == 365 days, "wrong term length");
    }

    function testMintChargesExactlyFiftyUsdcAndWithdrawsOnlyToTreasury() public {
        uint256 firstTokenId = buyer.buy(key, usdc, address(receiver), 1);
        require(firstTokenId == 1, "wrong token id");
        require(key.ownerOf(1) == address(receiver), "wrong owner");
        require(usdc.balanceOf(address(key)) == 50_000_000, "wrong payment");
        require(key.termNumber(1) == 1, "wrong term");
        require(key.termExpiresAt(1) > block.timestamp, "term not active");

        key.withdrawProceeds();
        require(usdc.balanceOf(address(key)) == 0, "contract retained proceeds");
        require(usdc.balanceOf(address(treasury)) == 50_000_000, "treasury not paid");
    }

    function testBulkMintCreatesIndependentPasses() public {
        uint256 firstTokenId = buyer.buy(key, usdc, address(receiver), 3);
        require(firstTokenId == 1, "wrong first id");
        require(key.totalMinted() == 3, "wrong supply");
        require(key.ownerOf(3) == address(receiver), "third token missing");
        require(usdc.balanceOf(address(key)) == 150_000_000, "wrong bulk charge");
    }

    function testInvalidQuantityAndUnsafeRecipientRevertWithoutCharging() public {
        (bool zeroOk,) =
            address(buyer).call(abi.encodeCall(BuyerActor.buy, (key, usdc, address(receiver), 0)));
        require(!zeroOk, "zero quantity succeeded");
        (bool tooManyOk,) =
            address(buyer).call(abi.encodeCall(BuyerActor.buy, (key, usdc, address(receiver), 21)));
        require(!tooManyOk, "oversized batch succeeded");

        uint256 beforeBalance = usdc.balanceOf(address(buyer));
        NonReceiver unsafeRecipient = new NonReceiver();
        (bool unsafeOk,) = address(buyer)
            .call(abi.encodeCall(BuyerActor.buy, (key, usdc, address(unsafeRecipient), 1)));
        require(!unsafeOk, "unsafe recipient succeeded");
        require(usdc.balanceOf(address(buyer)) == beforeBalance, "reverted mint charged buyer");
        require(key.totalMinted() == 0, "reverted mint changed supply");
    }

    function testInsufficientFundsRevertWithoutChangingSupply() public {
        BuyerActor unfunded = new BuyerActor();
        (bool ok,) = address(unfunded)
            .call(abi.encodeCall(BuyerActor.buy, (key, usdc, address(receiver), 1)));
        require(!ok, "unfunded purchase succeeded");
        require(key.totalMinted() == 0, "failed payment changed supply");
        require(usdc.balanceOf(address(key)) == 0, "failed payment left proceeds");
    }

    function testFeeOnTransferPaymentCannotUnderpay() public {
        FeeUSDC feeToken = new FeeUSDC();
        GoldKey feeKey = new GoldKey(
            address(this),
            address(feeToken),
            address(treasury),
            "https://api.goldkey.example/metadata/",
            "https://api.goldkey.example/terms",
            keccak256("goldkey-terms-v1")
        );
        feeToken.mint(address(buyer), 50_000_000);
        (bool ok,) = address(buyer)
            .call(abi.encodeCall(BuyerActor.buy, (feeKey, feeToken, address(receiver), 1)));
        require(!ok, "fee token underpayment succeeded");
        require(feeKey.totalMinted() == 0, "underpayment changed supply");
        require(feeToken.balanceOf(address(feeKey)) == 0, "reverted underpayment left funds");
        require(
            feeToken.balanceOf(address(buyer)) == 50_000_000, "reverted underpayment charged buyer"
        );
    }

    function testReentrantReceiverCannotMintDuringCallback() public {
        ReentrantReceiver attacker = new ReentrantReceiver();
        usdc.mint(address(attacker), 100_000_000);
        attacker.attack(key, usdc);
        require(!attacker.reentrySucceeded(), "reentrant mint succeeded");
        require(key.totalMinted() == 1, "reentrant mint changed supply");
        require(usdc.balanceOf(address(key)) == 50_000_000, "reentrant mint changed payment");
    }

    function testRenewalChargesFiftyAndAdvancesVerifiableTerm() public {
        buyer.buy(key, usdc, address(buyer), 1);
        uint256 oldExpiry = key.termExpiresAt(1);
        (bool earlyOk,) = address(buyer).call(abi.encodeCall(BuyerActor.renew, (key, usdc, 1)));
        require(!earlyOk, "early renewal succeeded");
        require(key.termNumber(1) == 1, "early renewal advanced term");
        vm.warp(oldExpiry);
        buyer.renew(key, usdc, 1);
        require(key.termNumber(1) == 2, "term did not advance");
        require(key.termExpiresAt(1) == oldExpiry + 365 days, "expiry did not extend");
        require(usdc.balanceOf(address(key)) == 100_000_000, "renewal charge incorrect");
    }

    function testThirdPartyCannotForceRenewAndInvalidateQuotaNamespace() public {
        buyer.buy(key, usdc, address(receiver), 1);
        vm.warp(key.termExpiresAt(1));
        uint256 balanceBefore = usdc.balanceOf(address(buyer));
        (bool ok,) = address(buyer).call(abi.encodeCall(BuyerActor.renew, (key, usdc, 1)));
        require(!ok, "third-party renewal succeeded");
        require(key.termNumber(1) == 1, "third party advanced term");
        require(
            usdc.balanceOf(address(buyer)) == balanceBefore, "failed renewal charged third party"
        );
    }

    function testRenewalRejectsMissingTokenAndSalesPause() public {
        (bool missingOk,) = address(buyer).call(abi.encodeCall(BuyerActor.renew, (key, usdc, 99)));
        require(!missingOk, "missing token renewed");
        buyer.buy(key, usdc, address(receiver), 1);
        vm.warp(key.termExpiresAt(1));
        key.setSalesPaused(true);
        (bool pausedOk,) = address(buyer).call(abi.encodeCall(BuyerActor.renew, (key, usdc, 1)));
        require(!pausedOk, "paused renewal succeeded");
        require(key.termNumber(1) == 1, "paused renewal changed term");
    }

    function testTransferMovesLicenseButDoesNotAlterTerm() public {
        buyer.buy(key, usdc, address(buyer), 1);
        uint256 expiry = key.termExpiresAt(1);
        BuyerActor next = new BuyerActor();
        buyer.transfer(key, address(next), 1);
        require(key.ownerOf(1) == address(next), "transfer failed");
        require(key.ownershipEpoch(1) == 1, "first transfer did not advance epoch");
        next.transfer(key, address(buyer), 1);
        require(key.ownershipEpoch(1) == 2, "round trip did not advance epoch");
        require(key.termNumber(1) == 1, "transfer changed term");
        require(key.termExpiresAt(1) == expiry, "transfer changed expiry");
    }

    function testAccessStateTracksMintTransferExpiryAndRenewalAtomically() public {
        _assertAccessState(99, address(0), 0, 0, 0, false);

        buyer.buy(key, usdc, address(buyer), 1);
        uint256 firstExpiry = key.termExpiresAt(1);
        _assertAccessState(1, address(buyer), 1, firstExpiry, 0, true);

        BuyerActor next = new BuyerActor();
        buyer.transfer(key, address(next), 1);
        _assertAccessState(1, address(next), 1, firstExpiry, 1, true);

        vm.warp(firstExpiry);
        _assertAccessState(1, address(next), 1, firstExpiry, 1, false);

        usdc.mint(address(next), key.MINT_PRICE());
        next.renew(key, usdc, 1);
        _assertAccessState(1, address(next), 2, firstExpiry + 365 days, 1, true);
    }

    function testSalesPauseStopsPurchasesButNeverTrapsTransfers() public {
        buyer.buy(key, usdc, address(buyer), 1);
        key.setSalesPaused(true);
        (bool mintOk,) =
            address(buyer).call(abi.encodeCall(BuyerActor.buy, (key, usdc, address(receiver), 1)));
        require(!mintOk, "paused mint succeeded");
        buyer.transfer(key, address(receiver), 1);
        require(key.ownerOf(1) == address(receiver), "pause trapped holder");
    }

    function testTreasuryChangeRequiresProposeAndAccept() public {
        TreasuryActor next = new TreasuryActor();
        key.proposeTreasury(address(next));
        (bool wrongAccept,) = address(treasury).call(abi.encodeCall(TreasuryActor.accept, (key)));
        require(!wrongAccept, "wrong treasury accepted");
        next.accept(key);
        require(key.treasury() == address(next), "treasury not updated");
    }

    function testOwnershipTransferClearsStaleTreasuryProposal() public {
        TreasuryActor staleNominee = new TreasuryActor();
        TreasuryActor nextOwner = new TreasuryActor();
        TreasuryActor nextTreasury = new TreasuryActor();
        key.proposeTreasury(address(staleNominee));
        key.transferOwnership(address(nextOwner));
        nextOwner.acceptOwnership(key);
        require(key.pendingTreasury() == address(0), "stale proposal not cleared");
        (bool staleOk,) = address(staleNominee).call(abi.encodeCall(TreasuryActor.accept, (key)));
        require(!staleOk, "stale treasury accepted after ownership transfer");
        nextOwner.proposeTreasury(key, address(nextTreasury));
        nextTreasury.accept(key);
        require(key.treasury() == address(nextTreasury), "new owner could not set treasury");
    }

    function _assertAccessState(
        uint256 tokenId,
        address expectedOwner,
        uint256 expectedTerm,
        uint256 expectedExpiry,
        uint256 expectedEpoch,
        bool expectedActive
    ) internal view {
        (address owner, uint256 term, uint256 expiresAt, uint256 epoch, bool active) =
            key.accessState(tokenId);
        require(owner == expectedOwner, "access owner mismatch");
        require(term == expectedTerm, "access term mismatch");
        require(expiresAt == expectedExpiry, "access expiry mismatch");
        require(epoch == expectedEpoch, "access epoch mismatch");
        require(active == expectedActive, "access active mismatch");
    }
}
