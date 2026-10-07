// Mock database of known threats for Cryptection Protocol
const KNOWN_THREATS = {
    '0x1234567890123456789012345678901234567890': {
        riskScore: 76,
        status: 'MALICIOUS',
        tags: ['Phishing Drainer', 'Stolen Funds', 'Unverified Router'],
        reports: 142,
        contractRisk: 22,
        walletRisk: 61,
        creatorRisk: 84,
        networkRisk: 79,
        behavioralRisk: 72,
        concerns: [
            "⚠ Creator has deployed 9 contracts",
            "⚠ 3 previous contracts showed suspicious liquidity behavior",
            "⚠ Creator shares funding sources with 4 related wallets",
            "⚠ 2 related wallets have elevated threat indicators",
            "✓ Contract itself is verified/open and has limited direct risk signals"
        ]
    },
    '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef': {
        riskScore: 88,
        status: 'HIGH_RISK',
        tags: ['Tornado Cash', 'Mixer'],
        reports: 56,
        contractRisk: 10,
        walletRisk: 95,
        creatorRisk: 50,
        networkRisk: 88,
        behavioralRisk: 90,
        concerns: [
            "⚠ Address interacted directly with OFAC sanctioned mixer",
            "⚠ High volume of obfuscated transactions detected"
        ]
    }
};

class Cryptection {
    
    /**
     * Validates if a string is a standard EVM/BSC address
     * @param {string} address 
     * @returns {boolean}
     */
    static isValidAddress(address) {
        if (!address || typeof address !== 'string') return false;
        return /^0x[a-fA-F0-9]{40}$/.test(address);
    }

    /**
     * Analyzes an address for potential risks
     * @param {string} address 
     * @returns {Object} Analysis results
     */
    static analyzeAddress(address) {
        if (!this.isValidAddress(address)) {
            throw new Error('Invalid EVM address format.');
        }

        const normalizedAddress = address.toLowerCase();

        // Check if address matches indexed known threats
        if (KNOWN_THREATS[normalizedAddress]) {
            return {
                address: normalizedAddress,
                timestamp: new Date().toISOString(),
                ...KNOWN_THREATS[normalizedAddress]
            };
        }

        // Deterministic pseudo-risk calculation for unindexed addresses
        const hashVal = normalizedAddress.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
        const pseudoRandomRisk = hashVal % 30;

        return {
            address: normalizedAddress,
            timestamp: new Date().toISOString(),
            riskScore: pseudoRandomRisk,
            status: pseudoRandomRisk > 15 ? 'WARNING' : 'SAFE',
            tags: pseudoRandomRisk > 15 ? ['Unverified Contract'] : [],
            reports: 0,
            contractRisk: Math.floor(Math.random() * 20),
            walletRisk: Math.floor(Math.random() * 20),
            creatorRisk: Math.floor(Math.random() * 20),
            networkRisk: Math.floor(Math.random() * 20),
            behavioralRisk: Math.floor(Math.random() * 20),
            concerns: pseudoRandomRisk > 15 
                ? ["⚠ Contract source code is unverified"] 
                : ["✓ No immediate threat signatures found in public telemetry"]
        };
    }

    /**
     * Records a new threat report for an address
     * @param {string} address 
     * @param {string} reason 
     * @returns {Object} Report confirmation
     */
    static reportAddress(address, reason) {
        if (!this.isValidAddress(address)) {
            throw new Error('Invalid EVM address format.');
        }

        if (!reason || reason.trim() === '') {
            throw new Error('A reason for the report must be provided.');
        }

        return {
            success: true,
            message: `Report filed successfully with Cryptection Labs for ${address}.`,
            referenceId: `REP-${Math.floor(Math.random() * 1000000)}`
        };
    }
}

module.exports = Cryptection;