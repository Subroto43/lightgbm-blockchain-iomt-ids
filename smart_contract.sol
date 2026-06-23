// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract IntrusionBlockerWithResponse {

    address public owner;
    uint public severityThreshold;

    // Mapping to track blocked entities (hashed IPs/devices)
    mapping(bytes32 => bool) public blockedEntities;

    // Events for logging alerts and responses
    event AlertLogged(uint threatId, string threatType, uint severity);
    event ResponseTriggered(uint threatId, string action, bytes32 entityHash);
    event Blocked(bytes32 indexed entity);
    event Unblocked(bytes32 indexed entity);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this.");
        _;
    }

    constructor(uint _severityThreshold) {
        owner = msg.sender;
        severityThreshold = _severityThreshold;
    }

    // Log an alert; automatically block if severity >= threshold
    function logAlert(
        uint threatId,
        string calldata threatType,
        uint severity,
        bytes32 entityHash  // hashed IP or device ID
    ) external onlyOwner {
        emit AlertLogged(threatId, threatType, severity);

        if (severity >= severityThreshold) {
            _blockEntity(threatId, entityHash);
        }
    }

    // Internal function to block entity and emit events
    function _blockEntity(uint threatId, bytes32 entityHash) internal {
        if (!blockedEntities[entityHash]) {
            blockedEntities[entityHash] = true;
            emit ResponseTriggered(threatId, "BlockEntity", entityHash);
            emit Blocked(entityHash);
        }
    }

    // Unblock an entity
    function unblockEntity(bytes32 entityHash) external onlyOwner {
        if (blockedEntities[entityHash]) {
            blockedEntities[entityHash] = false;
            emit Unblocked(entityHash);
        }
    }

    // Check if an entity is blocked
    function isBlocked(bytes32 entityHash) external view returns (bool) {
        return blockedEntities[entityHash];
    }

    // Allow owner to update severity threshold
    function updateSeverityThreshold(uint newThreshold) external onlyOwner {
        severityThreshold = newThreshold;
    }
}


