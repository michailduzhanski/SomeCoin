// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'Arnak' + blake2s(b'The Economist 2016-10-29 Known unknown: Another crypto-currency is born. BTC#436254 0000000000000000044f321997f336d2908cf8c8d6893e88dbf067e2d949487d ETH#2521903 483039a6b6bd8bd05f0584f9a078d075e454925eb71c1f13eaff59b405a721bb DJIA close on 27 Oct 2016: 18,169.68').hexdigest()
 *
 * CBlock(hash=00040fe8, ver=4, hashPrevBlock=00000000000000, hashMerkleRoot=c4eaa5, nTime=1573131219, nBits=1f07ffff, nNonce=4695, vtx=1)
 *   CTransaction(hash=c4eaa5, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334)
 *     CTxOut(nValue=0.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: c4eaa5
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Arnak12ec09992caa4e9654162692c5ca2ddeb385a462974fdc660df08e23ae870d4c";
    const CScript genesisOutputScript = CScript() << ParseHex("045d5f19f31313a629158bb6dbcde0fee7e01b0f027711353b5d8ad4edeed2c2817ba5b20991a4a6acb8aa65d6de47c1dfce98b8ebd7993fc4f3c2b61cd40074c2") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "ANK";
        bip44CoinType = 133; // As registered in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 20000;
        consensus.nPreBlossomSubsidyHalvingInterval = Consensus::PRE_BLOSSOM_HALVING_INTERVAL;
        consensus.nPostBlossomSubsidyHalvingInterval = Consensus::POST_BLOSSOM_HALVING_INTERVAL;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPreBlossomPowTargetSpacing = Consensus::PRE_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POST_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170005;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 347500;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].hashActivationBlock =
            uint256S("0000000003761c0d0c3974b54bdb425613bbb1eaadd6e70b764de82f195ea243");
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 419200;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].hashActivationBlock =
            uint256S("00000000025a57200d898ac7f21e26bf29028bbe96ec46e05b2c17cc9db9e4f3");
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170009;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight = 653600;

        // The best chain should have at least this much work.
		consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000017e73a331fae01c");

        /**
         * The message start string should be awesome! ⓩ❤
         */
        pchMessageStart[0] = 0x24;
        pchMessageStart[1] = 0xe9;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x64;
        vAlertPubKey = ParseHex("04dca46fa5ca4600ab464f748967f34ee5134f477169d9818467f7abd79cb824ad3d51672c366864ae397b2d01819715c21ad2313cc095928658b5bf5ea1c545eb");
        nDefaultPort = 15203;
        nPruneAfterHeight = 100000;

        vFixedSeeds.clear();genesis = CreateGenesisBlock(
            1572954275,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000001257"),
            ParseHex("00070c35670ed414e88f629ba7dae8dcadcbb16419221ad948059cbd018917e2b8bec09405ad14327e810ca560c67568235f72a9116a980b83f6c132ddaee132b7dceaccd2cd473d94a492b14d50caea2c998962008d96dbe4d023f9f43583b85552a401883b1075190c19808ebe4b06d5a3ede1535dd4068587e1fb1c961a04f70fc2c8c282fe5986bf5bc1ec1e55143e1fa12812444e3c2915b1810193d9a2f0408d474f59237f074a4e773808162efe813380f2a4acb20607b40e133385c1f815cd533abc3ab921f6e26cf2724bb95aaf1f563ae2149cf3fbe12cf27e5b21b7baf70aff163d35588534c4693d87e775c9728cd9e9079a9e7e21412626238eda92f7ad62372a910fd82fff185cfbd3d42a23e73c04dc42cb192204196231b222331016e16c2a20cb3842509a99370a02c7efdb9bc11b78f511b548b22cce5199abe1c849f994fe69a903bbfdbe5dd0025168cd45c96c3d4d458132819dc515b41c3a8544089e2554c568fa0fe802c123b63447adbc8ad49f9d208b62ad588b3f2ab0141210e0efe94b37b49b667568f4859767a1cc3397b5dae222e3ad1ebd8bfe6d27104bdbad5a4d6bd6b0c473a2b9e1efbf4cad9ef27b1734bc0cb56515bf586cc2b74ca65b71bf02361fd2210ce67fe25547bace2fe2fef9e5ec21854c1e6fb52f7a5ddb45999c3390a843bcfaafdbc55bf46b0472045e2fee4e94e98d1ebc01ffa94518ee6dff7a161115e8c5e688c6eab316a651db392055fafef65a5ed7069a772e2bcbfd8e9e7195cb187f2d837b769f6b7726960720b1a77fefacd2b33dc61f9739d78636b8a1078f6859950449d3f422e1fbc45d5030972ab06df45f5d23fdff1c4a256135774d133cbbae07771c27360ee54cc5fe54d393c17a74963a68e8ae5e017f480f2550b4d9c4720cb7b3dd47f810d0e12aaf047a2b3d003f78ee1bc94910640ed9f96875c2be854b95ccc31bd751f06a9281631fc87406d2bb3a6d31d45f376a22bbb325dbfe3a13f93d356dc2c41ebdbf8458a66735222d49a823c3cf9493aa0188deecd6f9a3dd2f033146045d9930ae09e2b0137dc877dbbb015f5d965e496f766c7a94de9fa7e55b8e2fea1aaf81615c94f94af9ebf5ebab5e99929d6947b6ffd983b6789f222551ebe6dfa899e35ba19ac8d0e6500e2fb3d71fd572077055d7db468f84589851aee7de7643854c9df7ec544ccdcdd72be08572a7b7048d57b859f19ed9b1b907f763c6cf60b4bfbc3e780f62ee8e66f5cf1c2b963928f20ddf20ccbb277f95cebee326a99080f9a2d60b4e805d444826fe6c0ac8d1c8f14496d73abd50131a65360057a90b51676de2316718f1c26aa47426280d6f8ba0cda4775db73346e6ae6ffcb68351bca27b48ee96751b2463df6bb2881a2ed8138e615478363601a0cb32dc0d4bed1d7e416f13baf2bad22099716423afd2cd79ca13aac929c26cd3147fa9de8cff0cb20ec3ec4f80d2e531d82e727ff1a5436d601f4c2ad2880ed50992b1fad1deadf8a659f154e25edbb5d891091ba473471070ae867ad59692f340fa0d5010d7d914d3b0abe7a1557df47d719b355a0984c6db898b36125781999b3a39d7e838f4efe2fb30df49bd5c22af43ea1656a363bc9fafe9f4622035b77e224cfc51230869d77d6e86ac09f34670c3f634aec89a759376e70f3dfbe572b174958e62613a11bcc6599c29360f640bb93691f0dfc6d1ecd4b148767c1c00f13dbc62f4209f1934b55bca72e5ff92897920bd6d1f6f0f0601093cd0fe1b02d7c24b1816855aede3da2a277ab12d13c5491d4b1b4c59607ea8f027ee5012c159dbc9551340ef820e0babe096dec30b8838d89dc0ad10eb4d1a5672d67abca3e7e84111c61ce0280c8df8392513"),
            0x1f07ffff, 4, 0);
        
        assert(consensus.hashGenesisBlock == uint256S("0x00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08"));
        assert(genesis.hashMerkleRoot == uint256S("0xc4eaa58879081de3c24a7b117ed2b28300e7ec4c4c1dff1d3f1268b7857a4ddb"));
        vSeeds.clear();
		// vSeeds.push_back(CDNSSeedData("dns.arnak.org", "dnsseed.arnak.org")); // Arnak
		
        // guarantees the first 2 characters, when base58 encoded, are "v1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0xD7};
        // guarantees the first 2 characters, when base58 encoded, are "v3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1D,0xDC};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "hd"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x0F,0xEB};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            
            1572954275,     // * UNIX timestamp of last checkpoint block
            0,        // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            0            // * estimated number of transactions per day after checkpoint
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        nSproutValuePoolCheckpointHeight = 0;
        nSproutValuePoolCheckpointBalance = 0;
        fZIP209Enabled = true;
        hashSproutValuePoolCheckpointBlock = uint256S("0000000000c7b46b6bc04b4cbf87d8bb08722aebd51232619b214f7273f8460e");

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {};
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight(0));
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TAZ";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 20000;
        consensus.nPreBlossomSubsidyHalvingInterval = Consensus::PRE_BLOSSOM_HALVING_INTERVAL;
        consensus.nPostBlossomSubsidyHalvingInterval = Consensus::POST_BLOSSOM_HALVING_INTERVAL;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPreBlossomPowTargetSpacing = Consensus::PRE_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POST_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 299187;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170003;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 207500;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].hashActivationBlock =
            uint256S("0000257c4331b098045023fcfbfa2474681f4564ab483f84e4e1ad078e4acf44");
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 280000;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].hashActivationBlock =
            uint256S("000420e7fcc3a49d729479fb0b560dd7b8617b178a08e9e389620a9d1dd6361a");
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight = 584000;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].hashActivationBlock =
            uint256S("00367515ef2e781b8c9358b443b6329572599edd02c59e8af67db9785122f298");

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000001dbb4c4224");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("044e7a1553392325c871c5ace5d6ad73501c66f4c185d6b0453cf45dec5a1322e705c672ac1a27ef7cdaf588c10effdf50ed5f95f85f2f54a5f6159fca394ed0c6");
        nDefaultPort = 15213;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1573133876,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000006"),
            ParseHex("00a6a51259c3f6732481e2d035197218b7a69504461d04335503cd69759b2d02bd2b53a9653f42cb33c608511c953673fa9da76170958115fe92157ad3bb5720d927f18e09459bf5c6072973e143e20f9bdf0584058c96b7c2234c7565f100d5eea083ba5d3dbaff9f0681799a113e7beff4a611d2b49590563109962baa149b628aae869af791f2f70bb041bd7ebfa658570917f6654a142b05e7ec0289a4f46470be7be5f693b90173eaaa6e84907170f32602204f1f4e1c04b1830116ffd0c54f0b1caa9a5698357bd8aa1f5ac8fc93b405265d824ba0e49f69dab5446653927298e6b7bdc61ee86ff31c07bde86331b4e500d42e4e50417e285502684b7966184505b885b42819a88469d1e9cf55072d7f3510f85580db689302eab377e4e11b14a91fdd0df7627efc048934f0aff8e7eb77eb17b3a95de13678004f2512293891d8baf8dde0ef69be520a58bbd6038ce899c9594cf3e30b8c3d9c7ecc832d4c19a6212747b50724e6f70f6451f78fd27b58ce43ca33b1641304a916186cfbe7dbca224f55d08530ba851e4df22baf7ab7078e9cbea46c0798b35a750f54103b0cdd08c81a6505c4932f6bfbd492a9fced31d54e98b6370d4c96600552fcf5b37780ed18c8787d03200963600db297a8f05dfa551321d17b9917edadcda51e274830749d133ad226f8bb6b94f13b4f77e67b35b71f52112ce9ba5da706ad9573584a2570a4ff25d29ab9761a06bdcf2c33638bf9baf2054825037881c14adf3816ba0cbd0fca689aad3ce16f2fe362c98f48134a9221765d939f0b49677d1c2447e56b46859f1810e2cf23e82a53e0d44f34dae932581b3b7f49eaec59af872cf9de757a964f7b33d143a36c270189508fcafe19398e4d2966948164d40556b05b7ff532f66f5d1edc41334ef742f78221dfe0c7ae2275bb3f24c89ae35f00afeea4e6ed187b866b209dc6e83b660593fce7c40e143beb07ac86c56f39e895385924667efe3a3f031938753c7764a2dbeb0a643fd359c46e614873fd0424e435fa7fac083b9a41a9d6bf7e284eee537ea7c50dd239f359941a43dc982745184bf3ee31a8dc850316aa9c6b66d6985acee814373be3458550659e1a06287c3b3b76a185c5cb93e38c1eebcf34ff072894b6430aed8d34122dafd925c46a515cca79b0269c92b301890ca6b0dc8b679cdac0f23318c105de73d7a46d16d2dad988d49c22e9963c117960bdc70ef0db6b091cf09445a516176b7f6d58ec29539166cc8a38bbff387acefffab2ea5faad0e8bb70625716ef0edf61940733c25993ea3de9f0be23d36e7cb8da10505f9dc426cd0e6e5b173ab4fff8c37e1f1fb56d1ea372013d075e0934c6919393cfc21395eea20718fad03542a4162a9ded66c814ad8320b2d7c2da3ecaf206da34c502db2096d1c46699a91dd1c432f019ad434e2c1ce507f91104f66f491fed37b225b8e0b2888c37276cfa0468fc13b8d593fd9a2675f0f5b20b8a15f8fa7558176a530d6865738ddb25d3426dab905221681cf9da0e0200eea5b2eba3ad3a5237d2a391f9074bf1779a2005cee43eec2b058511532635e0fea61664f531ac2b356f40db5c5d275a4cf5c82d468976455af4e3362cc8f71aa95e71d394aff3ead6f7101279f95bcd8a0fedce1d21cb3c9f6dd3b182fce0db5d6712981b651f29178a24119968b14783cafa713bc5f2a65205a42e4ce9dc7ba462bdb1f3e4553afc15f5f39998fdb53e7e231e3e520a46943734a007c2daa1eda9f495791657eefcac5c32833936e568d06187857ed04d7b97167ae207c5c5ae54e528c36016a984235e9c5b2f0718d7b3aa93c7822ccc772580b6599671b3c02ece8a21399abd33cfd3028790133167d0a97e7de53dc8ff"),
            0x2007ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
consensus.hashGenesisBlock = genesis.GetHash();
                printf("block.nTime = %u \n", genesis.nTime);
                printf("block.nNonce = %u \n", genesis.nNonce);
                printf("block.GetHash = %s\n", genesis.GetHash().ToString().c_str());
                printf("block.merkle = %s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0xb1c60a7e2fdcfb03c2baa5fcb6f9f5ae88f48f0aa9265bdf2cdb099d2f816a8b"));
        assert(genesis.hashMerkleRoot == uint256S("0xe61b7d3ec8da5e04425f30cfd83e2524ad0b11d1d62bb9f0776b8372af4cc876"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("dns.arnak.org", "dnsseed.arnak.org")); // Arnak

        // guarantees the first 2 characters, when base58 encoded, are "tm"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "t2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock)
            (38000, uint256S("0x001e9a2d2e2892b88e9998cf7b079b41d59dd085423a921fe8386cecc42287b8")),
            1486897419,  // * UNIX timestamp of last checkpoint block
            47163,       // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
            715          //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        nSproutValuePoolCheckpointHeight = 440329;
        nSproutValuePoolCheckpointBalance = 40000029096803;
        fZIP209Enabled = true;
        hashSproutValuePoolCheckpointBlock = uint256S("000a95d08ba5dcbabe881fc6471d11807bcca7df5f1795c99f3ec4580db4279b");

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
//            "t2UNzUUx8mWBCRYPRezvA363EYXyEpHokyi", "t2N9PH9Wk9xjqYg9iin1Ua3aekJqfAtE543", "t2NGQjYMQhFndDHguvUw4wZdNdsssA6K7x2", "t2ENg7hHVqqs9JwU5cgjvSbxnT2a9USNfhy",
//            "t2BkYdVCHzvTJJUTx4yZB8qeegD8QsPx8bo", "t2J8q1xH1EuigJ52MfExyyjYtN3VgvshKDf", "t2Crq9mydTm37kZokC68HzT6yez3t2FBnFj", "t2EaMPUiQ1kthqcP5UEkF42CAFKJqXCkXC9", 
//            "t2F9dtQc63JDDyrhnfpzvVYTJcr57MkqA12", "t2LPirmnfYSZc481GgZBa6xUGcoovfytBnC", "t26xfxoSw2UV9Pe5o3C8V4YybQD4SESfxtp", "t2D3k4fNdErd66YxtvXEdft9xuLoKD7CcVo", 
//            "t2DWYBkxKNivdmsMiivNJzutaQGqmoRjRnL", "t2C3kFF9iQRxfc4B9zgbWo4dQLLqzqjpuGQ", "t2MnT5tzu9HSKcppRyUNwoTp8MUueuSGNaB", "t2AREsWdoW1F8EQYsScsjkgqobmgrkKeUkK", 
//            "t2Vf4wKcJ3ZFtLj4jezUUKkwYR92BLHn5UT", "t2K3fdViH6R5tRuXLphKyoYXyZhyWGghDNY", "t2VEn3KiKyHSGyzd3nDw6ESWtaCQHwuv9WC", "t2F8XouqdNMq6zzEvxQXHV1TjwZRHwRg8gC", 
//            "t2BS7Mrbaef3fA4xrmkvDisFVXVrRBnZ6Qj", "t2FuSwoLCdBVPwdZuYoHrEzxAb9qy4qjbnL", "t2SX3U8NtrT6gz5Db1AtQCSGjrpptr8JC6h", "t2V51gZNSoJ5kRL74bf9YTtbZuv8Fcqx2FH", 
//            "t2FyTsLjjdm4jeVwir4xzj7FAkUidbr1b4R", "t2EYbGLekmpqHyn8UBF6kqpahrYm7D6N1Le", "t2NQTrStZHtJECNFT3dUBLYA9AErxPCmkka", "t2GSWZZJzoesYxfPTWXkFn5UaxjiYxGBU2a", 
//            "t2RpffkzyLRevGM3w9aWdqMX6bd8uuAK3vn", "t2JzjoQqnuXtTGSN7k7yk5keURBGvYofh1d", "t2AEefc72ieTnsXKmgK2bZNckiwvZe3oPNL", "t2NNs3ZGZFsNj2wvmVd8BSwSfvETgiLrD8J", 
//            "t2ECCQPVcxUCSSQopdNquguEPE14HsVfcUn", "t2JabDUkG8TaqVKYfqDJ3rqkVdHKp6hwXvG", "t2FGzW5Zdc8Cy98ZKmRygsVGi6oKcmYir9n", "t2DUD8a21FtEFn42oVLp5NGbogY13uyjy9t", 
//            "t2UjVSd3zheHPgAkuX8WQW2CiC9xHQ8EvWp", "t2TBUAhELyHUn8i6SXYsXz5Lmy7kDzA1uT5", "t2Tz3uCyhP6eizUWDc3bGH7XUC9GQsEyQNc", "t2NysJSZtLwMLWEJ6MH3BsxRh6h27mNcsSy", 
//            "t2KXJVVyyrjVxxSeazbY9ksGyft4qsXUNm9", "t2J9YYtH31cveiLZzjaE4AcuwVho6qjTNzp", "t2QgvW4sP9zaGpPMH1GRzy7cpydmuRfB4AZ", "t2NDTJP9MosKpyFPHJmfjc5pGCvAU58XGa4", 
//            "t29pHDBWq7qN4EjwSEHg8wEqYe9pkmVrtRP", "t2Ez9KM8VJLuArcxuEkNRAkhNvidKkzXcjJ", "t2D5y7J5fpXajLbGrMBQkFg2mFN8fo3n8cX", "t2UV2wr1PTaUiybpkV3FdSdGxUJeZdZztyt", 
            };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight(0));
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nPreBlossomSubsidyHalvingInterval = Consensus::PRE_BLOSSOM_REGTEST_HALVING_INTERVAL;
        consensus.nPostBlossomSubsidyHalvingInterval = Consensus::POST_BLOSSOM_REGTEST_HALVING_INTERVAL;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPreBlossomPowTargetSpacing = Consensus::PRE_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POST_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170003;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nDefaultPort = 18344;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1573134086,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000009"),
            ParseHex("01936b7db1eb4ac39f151b8704642d0a8bda13ec547d54cd5e43ba142fc6d8877cab07b3"),
            0x200f0f0f, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
consensus.hashGenesisBlock = genesis.GetHash();
                printf("block.nTime = %u \n", genesis.nTime);
                printf("block.nNonce = %u \n", genesis.nNonce);
                printf("block.GetHash = %s\n", genesis.GetHash().ToString().c_str());
                printf("block.merkle = %s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0xbeb38df13b4e28b090a9e98ce4624ccb9e67079498d0367cc0ff92382a2e6244"));
        assert(genesis.hashMerkleRoot == uint256S("0xe61b7d3ec8da5e04425f30cfd83e2524ad0b11d1d62bb9f0776b8372af4cc876"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")),
            0,
            0,
            0
        };
        // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = { 
//"t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg" 
};
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight(0));
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }

    void UpdateRegtestPow(int64_t nPowMaxAdjustDown, int64_t nPowMaxAdjustUp, uint256 powLimit)
    {
        consensus.nPowMaxAdjustDown = nPowMaxAdjustDown;
        consensus.nPowMaxAdjustUp = nPowMaxAdjustUp;
        consensus.powLimit = powLimit;
    }

    void SetRegTestZIP209Enabled() {
        fZIP209Enabled = true;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }

    // When a developer is debugging turnstile violations in regtest mode, enable ZIP209
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-developersetpoolsizezero")) {
        regTestParams.SetRegTestZIP209Enabled();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int preBlossomMaxHeight = consensus.GetLastFoundersRewardBlockHeight(0);
    // zip208
    // FounderAddressAdjustedHeight(height) :=
    // height, if not IsBlossomActivated(height)
    // BlossomActivationHeight + floor((height - BlossomActivationHeight) / BlossomPoWTargetSpacingRatio), otherwise
    bool blossomActive = consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_BLOSSOM);
    if (blossomActive) {
        int blossomActivationHeight = consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight;
        nHeight = blossomActivationHeight + ((nHeight - blossomActivationHeight) / Consensus::BLOSSOM_POW_TARGET_SPACING_RATIO);
    }
    assert(nHeight > 0 && nHeight <= preBlossomMaxHeight);
    size_t addressChangeInterval = (preBlossomMaxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight(nHeight));

    CTxDestination address = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

void UpdateRegtestPow(int64_t nPowMaxAdjustDown, int64_t nPowMaxAdjustUp, uint256 powLimit) {
    regTestParams.UpdateRegtestPow(nPowMaxAdjustDown, nPowMaxAdjustUp, powLimit);
}
