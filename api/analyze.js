const Cryptection = require('../lib/cryptection');

// In-memory rate limiting store (tracks searches per IP)
const ipSearchTracker = new Map();
const FREE_DAILY_LIMIT = 5;

// Developer & Pro Bypass Keys
const VALID_BYPASS_KEYS = ['PRO_UNLOCKED', 'cryptection_dev_bypass', 'DEV_TEST_PASS'];

module.exports = async (req, res) => {
    // Set CORS headers for public access
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { address, bypassKey } = req.query;

    if (!address) {
        return res.status(400).json({ error: 'Address parameter is required' });
    }

    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'anonymous';
    const now = Date.now();
    const windowMs = 24 * 60 * 60 * 1000; // 24 hours

    let userRecord = ipSearchTracker.get(clientIp);
    if (!userRecord || (now - userRecord.startTime > windowMs)) {
        userRecord = { count: 0, startTime: now };
    }

    const isBypassActive = VALID_BYPASS_KEYS.includes(bypassKey);

    // Enforce 5 free daily searches unless valid bypass/Pro key is supplied
    if (userRecord.count >= FREE_DAILY_LIMIT && !isBypassActive) {
        return res.status(429).json({ 
            error: 'DAILY_LIMIT_EXCEEDED',
            message: 'You have reached your 5 free daily searches. Enable Dev Mode or hold 50,000 $CRYPT for unlimited scans.',
            remainingScans: 0,
            requiresPro: true
        });
    }

    try {
        const analysis = await Cryptection.analyzeAddress(address);
        
        // Only increment counter if not using a developer bypass key
        if (!isBypassActive) {
            userRecord.count += 1;
            ipSearchTracker.set(clientIp, userRecord);
        }

        res.status(200).json({
            ...analysis,
            searchesUsedToday: userRecord.count,
            searchesRemaining: isBypassActive ? 'UNLIMITED' : Math.max(0, FREE_DAILY_LIMIT - userRecord.count),
            bypassActive: isBypassActive
        });
    } catch (error) {
        res.status(400).json({ error: error.message || 'Failed to process security scan.' });
    }
};
