const Cryptection = require('../lib/cryptection');

module.exports = async (req, res) => {
    // Enable CORS for Vercel deployment
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    const { address, type } = req.query;

    if (!address) {
        return res.status(400).json({ error: true, message: 'An EVM address is required for analysis.' });
    }

    try {
        const scanType = type || 'auto';
        const result = await Cryptection.analyzeAddress(address, scanType);
        res.status(200).json(result);
    } catch (error) {
        console.error("API Route Error:", error);
        res.status(500).json({ error: true, message: error.message || 'Internal Server Error during analysis.' });
    }
};
