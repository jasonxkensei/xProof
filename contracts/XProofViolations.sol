// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract XProofViolations {
    address public owner;
    address public emitter;

    enum ViolationType { FAULT, BREACH }

    event ViolationConfirmed(
        bytes32 indexed agentWallet,
        bytes32 indexed proofId,
        ViolationType violationType,
        uint256 timestamp,
        string details
    );

    modifier onlyEmitter() {
        require(msg.sender == emitter, "Not authorized");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address _emitter) {
        owner = msg.sender;
        emitter = _emitter;
    }

    function emitViolation(
        bytes32 agentWallet,
        bytes32 proofId,
        ViolationType violationType,
        string calldata details
    ) external onlyEmitter {
        emit ViolationConfirmed(
            agentWallet,
            proofId,
            violationType,
            block.timestamp,
            details
        );
    }

    function setEmitter(address _emitter) external onlyOwner {
        emitter = _emitter;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
