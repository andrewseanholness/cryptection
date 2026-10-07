const Cryptection = require('../lib/cryptection');

module.exports = (req, res) => {
    // Set CORS headers for public API access
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { address } = req.query;

    if (!address) {
        return res.status(400).json({ error: 'Address parameter is required' });
    }

    try {
        const analysis = Cryptection.analyzeAddress(address);
        res.status(200).json(analysis);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};