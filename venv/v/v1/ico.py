from v.v1 import logger, config, db

class Ico():
    def __init__(self):
        #self.logger = L.Logger() #('Ico')
        self.Config = config.Config
        self.DB = db.Db()

    def __new__(cls): #singleton
        if not hasattr(cls, 'instance'):
            cls.instance = super(Ico, cls).__new__(cls)
        return cls.instance

    def areVotesValid(self, votes=[]): #TODO isVoteHolderMeetReqsFromConfig
        return True

    #TODO validate edges<supply, on blockRewardVerifyEdges
    def createAsset(self, id, name, supply, miner_fee,
                    asset_block_rewards, rewards_reduce_edges, creator_wallet, desc=''):
        #[{'50': 50} IF BLOCK > 50% SUPPLY REDUCE REWARDS FOR 50% OF asset_block_rewards]
        #TODO rewards_halving_percent [], rewards_halving_supply_percent []
        #Todo onNewWallet reduce txFee=createWalletFee
        if self.DB.getDbKey(creator_wallet) is None:
            return False
        if miner_fee < self.Config.NEW_ASSET_FEE:
            return False
        isAssetExist = self.DB.isDBkey(id)
        if isAssetExist is None or not isAssetExist: #todo hashid
            return self.DB.insertDbKv(bin_key=id,
                                      bin_value=(name, supply, miner_fee, asset_block_rewards,
                                          rewards_reduce_edges),
                                      desc='ICO ' + desc + name)
        else:
            return False


    def createContract(self):
        pass
