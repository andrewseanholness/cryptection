const Cryptection = require('../lib/cryptection');

// In-memory rate limiting store (tracks searches per IP)
const ipSearch Tracker = new Map();
const FREE_DAILY_LIMIT = 5;

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

    // Enforce 5 free daily searches unless Pro key or bypass is supplied
    if (userRecord.count >= FREE_DAILY_LIMIT && bypassKey !== 'PRO_UNLOCKED') {
        return res.status(429).json({ 
            error: 'DAILY_LIMIT_EXCEEDED',
            message: 'You have reached your 5 free daily searches. Connect your wallet holding 50,000 $CRYPT or upgrade to Pro for unlimited scans.',
            remainingScans: 0,
            requiresPro: true
        });
    }

    try {
        const analysis = await Cryptection.analyzeAddress(address);
        
        // Increment search count for IP
        userRecord.count += 1;
        ipSearchTracker.set(clientIp, userRecord);

        res.status(200).json({
            ...analysis,
            searchesUsedToday: userRecord.count,
            searchesRemaining: Math.max(0, FREE_DAILY_LIMIT - userRecord.count)
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};
