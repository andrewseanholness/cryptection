class Cryptection {
    
    /**
     * Validates if a string is a standard EVM address
     */
    static isValidAddress(address) {
        if (!address || typeof address !== 'string') return false;
        return /^0x[a-fA-F0-9]{40}$/i.test(address);
    }

    /**
     * Uses BSC JSON-RPC to check if an address has byte-code.
     * Incorporates DexScreener fallback to bypass RPC node rate-limiting.
     */
    static async isContract(address) {
        const normalizedAddress = address.toLowerCase();

        // 1. Fast-track known major contracts (Routers, Stablecoins, WBNB, ETH Assets)
        const KNOWN_CONTRACTS = [
            '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c', // WBNB (BSC)
            '0xb8c77482e45f1f44de1745f52c74426c631bdd52', // BNB (ERC-20)
            '0x10ed43c718714eb63d5aa57b78b54704e256024e', // Pancake Router
            '0x55d398326f99059ff775485246999027b3197955', // USDT (BSC)
            '0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d', // USDC (BSC)
            '0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82', // CAKE
            '0xdac17f958d2ee523a2206206994597c13d831ec7'  // USDT (ERC-20)
        ];
        
        if (KNOWN_CONTRACTS.includes(normalizedAddress)) return true;

        try {
            // 2. Direct RPC Bytecode Check
            const res = await fetch('https://bsc-dataseed.binance.org/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'eth_getCode',
                    params: [normalizedAddress, 'latest']
                })
            });
            const data = await res.json();
            
            // If the code is larger than '0x', it is a smart contract
            if (data.result && data.result !== '0x' && data.result !== '0x0') {
                return true;
            }
        } catch (e) {
            console.error('RPC Error checking contract:', e);
        }

        // 3. Fallback Heuristic: If RPC failed (rate limit), check DexScreener.
        // EOA Wallets never have liquidity pairs on DEXs.
        try {
            const dexRes = await fetch(`https://api.dexscreener.com/latest/dex/search?q=${normalizedAddress}`);
            const dexData = await dexRes.json();
            
            if (dexData.pairs && dexData.pairs.length > 0) {
                // Verify the searched address is actually the base or quote token
                const isToken = dexData.pairs.some(p => 
                    (p.baseToken && p.baseToken.address.toLowerCase() === normalizedAddress) || 
                    (p.quoteToken && p.quoteToken.address.toLowerCase() === normalizedAddress)
                );
                if (isToken) return true;
            }
        } catch (e) {
            console.error('DexScreener Fallback Error:', e);
        }

        return false;
    }

    /**
     * Fetches real BNB balance using BSC JSON-RPC
     */
    static async getBnbBalance(address) {
        try {
            const res = await fetch('https://bsc-dataseed.binance.org/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'eth_getBalance',
                    params: [address, 'latest']
                })
            });
            const data = await res.json();
            if (data.result) {
                const wei = BigInt(data.result);
                return (Number(wei) / 1e18).toFixed(4); // Convert Wei to BNB
            }
            return '0.0000';
        } catch (e) {
            return '0.0000';
        }
    }

    /**
     * Pulls exact compiler and verification data from BscScan & Etherscan
     * Implements Multi-Chain fallback to prevent false positives.
     */
    static async fetchExplorerData(address) {
        // Try BSC First
        try {
            const bscRes = await fetch(`https://api.bscscan.com/api?module=contract&action=getsourcecode&address=${address}`);
            const bscData = await bscRes.json();
            
            if (bscData.status === "1" && bscData.result && bscData.result.length > 0 && bscData.result[0].ABI !== "Contract source code not verified") {
                const info = bscData.result[0];
                return {
                    isVerified: true,
                    compilerVersion: info.CompilerVersion || "Unknown",
                    licenseType: info.LicenseType || "None",
                    optimizationUsed: info.OptimizationUsed === "1" ? "Enabled" : "Disabled",
                    chainSource: "Binance Smart Chain"
                };
            }
        } catch (e) {
            console.error('BscScan Fetch Error:', e);
        }

        // Fallback: Try Etherscan if BSC is unverified
        try {
            const ethRes = await fetch(`https://api.etherscan.io/api?module=contract&action=getsourcecode&address=${address}`);
            const ethData = await ethRes.json();
            
            if (ethData.status === "1" && ethData.result && ethData.result.length > 0 && ethData.result[0].ABI !== "Contract source code not verified") {
                const info = ethData.result[0];
                return {
                    isVerified: true,
                    compilerVersion: info.CompilerVersion || "Unknown",
                    licenseType: info.LicenseType || "None",
                    optimizationUsed: info.OptimizationUsed === "1" ? "Enabled" : "Disabled",
                    chainSource: "Ethereum Mainnet"
                };
            }
        } catch (e) {
            console.error('Etherscan Fetch Error:', e);
        }
        
        return {
            isVerified: false,
            compilerVersion: "Unknown",
            licenseType: "Unknown",
            optimizationUsed: "Unknown",
            chainSource: "Unknown"
        };
    }

    /**
     * Main entry point for the API
     */
    static async analyzeAddress(address) {
        if (!this.isValidAddress(address)) {
            throw new Error('Invalid EVM address format.');
        }

        const normalizedAddress = address.toLowerCase();

        // 1. Identify Entity Type
        const isSmartContract = await this.isContract(normalizedAddress);
        
        if (isSmartContract) {
            return await this.analyzeContract(normalizedAddress);
        } else {
            return await this.analyzeWallet(normalizedAddress);
        }
    }

    /**
     * Contract Intelligence Logic
     */
    static async analyzeContract(address) {
        let marketCap = 0;
        let volume24h = 0;
        let priceChange24h = 0;
        let liquidityUsd = 0;
        let tokenName = "Unindexed Token";
        let symbol = "???";
        let isGlobalAsset = false;

        const lowerAddr = address.toLowerCase();

        // 1. Identify and Override Global CEX Assets to prevent inaccurate DEX scraping
        if (lowerAddr === '0xb8c77482e45f1f44de1745f52c74426c631bdd52') { // BNB (ERC-20)
            isGlobalAsset = true;
            tokenName = "BNB (ERC-20)";
            symbol = "BNB";
            marketCap = 85000000000;
            volume24h = 1250000000;
            liquidityUsd = 500000000;
        } else if (lowerAddr === '0x55d398326f99059ff775485246999027b3197955') { // USDT (BSC)
            isGlobalAsset = true;
            tokenName = "Tether USD";
            symbol = "USDT";
            marketCap = 119000000000;
            volume24h = 45000000000;
            liquidityUsd = 2000000000;
        } else if (lowerAddr === '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c') { // WBNB
            isGlobalAsset = true;
            tokenName = "Wrapped BNB";
            symbol = "WBNB";
            marketCap = 85000000000;
            volume24h = 950000000;
            liquidityUsd = 400000000;
        }

        // Only scrape DexScreener if it's a standard/unlisted DeFi token
        if (!isGlobalAsset) {
            try {
                const dexRes = await fetch(`https://api.dexscreener.com/latest/dex/search?q=${address}`);
                const dexData = await dexRes.json();
                
                if (dexData.pairs && dexData.pairs.length > 0) {
                    // Sort pairs by liquidity to get the most accurate primary pair
                    const sortedPairs = dexData.pairs.sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0));
                    const pair = sortedPairs[0];
                    
                    marketCap = pair.fdv || pair.marketCap || 0;
                    volume24h = pair.volume?.h24 || 0;
                    priceChange24h = pair.priceChange?.h24 || 0;
                    liquidityUsd = pair.liquidity?.usd || 0;
                    tokenName = pair.baseToken?.name || tokenName;
                    symbol = pair.baseToken?.symbol || symbol;
                } else {
                    // If no pairs are found, ensure the name reflects this
                    tokenName = "Dead/Unlisted Token";
                    symbol = "UNKNOWN";
                    concerns.push("⚠ No active liquidity pairs found across any DEXs.");
                }
            } catch(e) {
                console.error('DexScreener Error:', e);
            }
        }

        let explorerData = await this.fetchExplorerData(address);
<!-- ... existing
