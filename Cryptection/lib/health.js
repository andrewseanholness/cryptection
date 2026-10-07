module.exports = (req, res) => {
    try {
        res.status(200).json({
            status: 'online',
            service: 'Cryptection API',
            version: '2.0.0',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'error', 
            message: 'Internal server error' 
        });
    }
};