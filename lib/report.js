const Cryptection = require('../lib/cryptection');

module.exports = (req, res) => {
    // Set CORS headers for API access
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { address, reason } = req.body || {};

    if (!address || !reason) {
        return res.status(400).json({ error: 'Address and reason are required' });
    }

    try {
        const result = Cryptection.reportAddress(address, reason);
        res.status(200).json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};