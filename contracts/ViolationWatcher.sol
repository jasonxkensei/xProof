// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IXProofViolations {
    enum ViolationType { FAULT, BREACH }

    event ViolationConfirmed(
        bytes32 indexed agentWallet,
        bytes32 indexed proofId,
        ViolationType violationType,
        uint256 timestamp,
        string details
    );
}

contract ViolationWatcher {
    address public owner;
    address public xproofContract;

    enum ResponseMode { ALERT_ONLY, AUTO_PAUSE_FAULT, AUTO_PAUSE_BREACH }

    ResponseMode public mode;
    bytes32 public watchedAgent;
    bool public paused;

    address public alertTarget;
    address public pauseTarget;

    uint256 public faultCount;
    uint256 public breachCount;
    uint256 public lastViolationTime;

    event AgentPaused(bytes32 indexed agentWallet, IXProofViolations.ViolationType reason, bytes32 proofId);
    event AlertFired(bytes32 indexed agentWallet, IXProofViolations.ViolationType reason, bytes32 proofId);
    event AgentResumed(bytes32 indexed agentWallet);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(
        address _xproofContract,
        bytes32 _watchedAgent,
        ResponseMode _mode,
        address _alertTarget,
        address _pauseTarget
    ) {
        owner = msg.sender;
        xproofContract = _xproofContract;
        watchedAgent = _watchedAgent;
        mode = _mode;
        alertTarget = _alertTarget;
        pauseTarget = _pauseTarget;
    }

    function onViolation(
        bytes32 agentWallet,
        bytes32 proofId,
        IXProofViolations.ViolationType violationType
    ) external {
        require(msg.sender == xproofContract, "Not xProof");
        require(agentWallet == watchedAgent, "Not watched agent");

        lastViolationTime = block.timestamp;

        if (violationType == IXProofViolations.ViolationType.FAULT) {
            faultCount++;
        } else {
            breachCount++;
        }

        emit AlertFired(agentWallet, violationType, proofId);

        if (mode == ResponseMode.AUTO_PAUSE_FAULT) {
            paused = true;
            emit AgentPaused(agentWallet, violationType, proofId);
        } else if (mode == ResponseMode.AUTO_PAUSE_BREACH && violationType == IXProofViolations.ViolationType.BREACH) {
            paused = true;
            emit AgentPaused(agentWallet, violationType, proofId);
        }
    }

    function resume() external onlyOwner {
        require(paused, "Not paused");
        paused = false;
        emit AgentResumed(watchedAgent);
    }

    function setMode(ResponseMode _mode) external onlyOwner {
        mode = _mode;
    }

    function setAlertTarget(address _target) external onlyOwner {
        alertTarget = _target;
    }

    function setPauseTarget(address _target) external onlyOwner {
        pauseTarget = _target;
    }

    function setWatchedAgent(bytes32 _agent) external onlyOwner {
        watchedAgent = _agent;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
