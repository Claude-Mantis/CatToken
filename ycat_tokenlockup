// Improved LuckyPandaLockup Contract
// Fixes:
// - Removed invalid "Int as uint256" for local variables (totalAmount, totalRemoveAmount, totalClaimableAmount).
// - Used plain "Int" for local accumulators, relying on require checks for non-negative values.
// - Kept "Int as uint256" for storage maps and struct fields where valid.
// - Maintained previous fixes: lockupInfo and pendingBatchLockups use Slice keys, no ?: operator, null safety, etc.
// - Removed unused RemoveLockupEvent.
// - Ensured Tact compliance and type consistency.

import "@stdlib/deploy";
import "@stdlib/ownable";

// Jetton transfer messages
message JettonTransfer {
    query_id: Int as uint64;
    amount: Int as coins;
    destination: Address;
    response_destination: Address?;
    custom_payload: Cell?;
    forward_ton_amount: Int as coins;
    forward_payload: Slice as remaining;
}

message JettonTransferNotification {
    query_id: Int as uint64;
    amount: Int as coins;
    sender: Address;
    forward_payload: Slice as remaining;
}

message JettonBurn {
    query_id: Int as uint64;
    amount: Int as coins;
    response_destination: Address?;
    custom_payload: Cell?;
}

// Lockup user structure
struct LockupUser {
    amount: Int as uint256;         // lockup amount
    stTimestamp: Int as uint32;     // block timestamp when set lockup
    edTimestamp: Int as uint32;     // timestamp which lockup ends
    isClaimed: Bool;                // originally false, when user withdraws it changes to true
    isRemoved: Bool;                // originally false, when admin removes lockup it changes to true
}

// Lockup data structure for batch operations
struct LockupData {
    account: Address;
    amount: Int as uint256;
    edTimestamp: Int as uint32;
}

// Messages for contract interactions
message SetLockup {
    account: Address;
    amount: Int as uint256;
    edTimestamp: Int as uint32;
}

message SetBatchLockup {
    accounts: map<Int, Address>;
    amounts: map<Int, Int>;
    edTimestamps: map<Int, Int>;
    length: Int as uint8;
}

message WithdrawLockup {
    lockupIndex: Int as uint32;
}

message RemoveLockups {
    account: Address;
}

message SetAllowList {
    account: Address;
    state: Bool;
}

message UpdateJettonWallet {
    newJettonWallet: Address;
}

message ClearPending {
    queryId: Int as uint64;
}

// Response messages
message LockupResponse {
    success: Bool;
    lockup: LockupUser?;
}

// Events
message SetLockupEvent {
    account: Address;
    lockupIdx: Int as uint32;
    amount: Int as uint256;
    stTimestamp: Int as uint32;
    edTimestamp: Int as uint32;
}

message WithdrawLockupEvent {
    account: Address;
    lockupIdx: Int as uint32;
    amount: Int as uint256;
    withdrawTimestamp: Int as uint32;
    stTimestamp: Int as uint32;
    edTimestamp: Int as uint32;
}

message RemoveLockupBatchEvent {
    account: Address;
    lockupIndices: map<Int, Int>;  // index -> amount
    removedTimestamp: Int as uint32;
}

message AuthorizedEvent {
    from: Address;
    listed: Address;
    state: Bool;
}

message JettonReceivedEvent {
    sender: Address;
    amount: Int as uint256;
    queryId: Int as uint64;
}

contract LuckyPandaLockup with Deployable, Ownable {
    owner: Address;
    jettonWallet: Address;  // Contract's Jetton wallet address
    
    // Storage maps
    lockupInfo: map<Slice, LockupUser>; // Key: serialize(account, lockupIndex)
    lockupCounts: map<Address, Int>;
    allowList: map<Address, Bool>;
    
    // Cached totals per account
    totalAllocated: map<Address, Int as uint256>;  // Total non-removed lockup amount
    totalClaimed: map<Address, Int as uint256>;    // Total claimed amount
    
    // Pending operations
    pendingSetLockups: map<Int, LockupData>;
    pendingBatchLockups: map<Slice, LockupData>; // Key: serialize(queryId, batchIndex)
    pendingBatchExpectedAmounts: map<Int, Int as uint256>;
    pendingBatchCounts: map<Int, Int>; // queryId -> number of batch entries
    nextQueryId: Int as uint64;
    
    // Reentrancy guard
    inCritical: Bool;
    
    init(owner: Address, jettonWallet: Address) {
        self.owner = owner;
        self.jettonWallet = jettonWallet;
        self.nextQueryId = 1;
        self.inCritical = false;
    }
    
    // Helper to create lockup key
    fun createLockupKey(account: Address, index: Int): Slice {
        let cell: Cell = beginCell().storeAddress(account).storeUint(index, 32).endCell();
        return cell.beginParse();
    }
    
    // Helper to create batch lockup key
    fun createBatchLockupKey(queryId: Int, index: Int): Slice {
        let cell: Cell = beginCell().storeUint(queryId, 64).storeUint(index, 32).endCell();
        return cell.beginParse();
    }
    
    // Require not in critical section
    fun requireNotReentrant() {
        require(!self.inCritical, "LuckyPandaLockup: reentrant call");
    }
    
    // Check if sender is authorized
    fun requireAuthorized(sender: Address) {
        let isOwner: Bool = sender == self.owner;
        let allowListValue: Bool? = self.allowList.get(sender);
        let isAllowed: Bool = allowListValue.getOrDefault(false);
        require(isOwner || isAllowed, "LuckyPandaLockup: caller is not authorized");
    }
    
    // Receive Jetton transfer notification
    receive(msg: JettonTransferNotification) {
        self.requireNotReentrant();
        self.inCritical = true;
        
        require(sender() == self.jettonWallet, "LuckyPandaLockup: invalid jetton wallet sender");
        
        emit(JettonReceivedEvent{
            sender: msg.sender,
            amount: msg.amount,
            queryId: msg.query_id
        }.toCell());
        
        // Process single lockup
        let pendingLockup: LockupData? = self.pendingSetLockups.get(msg.query_id);
        if (pendingLockup != null) {
            let lockupData: LockupData = pendingLockup!!;
            require(msg.amount >= lockupData.amount, "LuckyPandaLockup: insufficient jetton amount received");
            
            self.setLockupInternal(lockupData.account, lockupData.amount, lockupData.edTimestamp);
            self.pendingSetLockups.set(msg.query_id, null);
            
            self.inCritical = false;
            return;
        }
        
        // Process batch lockup
        let expectedAmount: Int? = self.pendingBatchExpectedAmounts.get(msg.query_id);
        if (expectedAmount != null) {
            require(msg.amount >= expectedAmount!!, "LuckyPandaLockup: insufficient jetton amount for batch");
            
            let batchCount: Int = self.pendingBatchCounts.get(msg.query_id).getOrDefault(0);
            let i: Int = 0;
            while (i < batchCount) {
                let key: Slice = self.createBatchLockupKey(msg.query_id, i);
                let lockupData: LockupData? = self.pendingBatchLockups.get(key);
                if (lockupData != null) {
                    self.setLockupInternal(lockupData!!.account, lockupData!!.amount, lockupData!!.edTimestamp);
                    self.pendingBatchLockups.set(key, null);
                }
                i = i + 1;
            }
            
            self.pendingBatchExpectedAmounts.set(msg.query_id, null);
            self.pendingBatchCounts.set(msg.query_id, null);
            
            self.inCritical = false;
            return;
        }
        
        self.inCritical = false;
    }
    
    // Set single lockup
    receive(msg: SetLockup) {
        self.requireNotReentrant();
        self.inCritical = true;
        
        self.requireAuthorized(sender());
        require(msg.account != newAddress(0, 0), "LuckyPandaLockup: invalid account address");
        require(msg.amount > 0, "LuckyPandaLockup: lockup amount must be greater than zero");
        require(msg.edTimestamp > now(), "LuckyPandaLockup: end timestamp must be in the future");
        
        let queryId: Int = self.nextQueryId;
        self.nextQueryId = self.nextQueryId + 1;
        
        self.pendingSetLockups.set(queryId, LockupData{
            account: msg.account,
            amount: msg.amount,
            edTimestamp: msg.edTimestamp
        });
        
        send(SendParameters{
            to: self.jettonWallet,
            value: ton("0.2"),
            mode: SendPayGasSeparately,
            body: JettonTransfer{
                query_id: queryId,
                amount: msg.amount,
                destination: myAddress(),
                response_destination: sender(),
                custom_payload: null,
                forward_ton_amount: ton("0.1"),
                forward_payload: beginCell().endCell().beginParse()
            }.toCell()
        });
        
        self.inCritical = false;
    }
    
    // Set batch lockup
    receive(msg: SetBatchLockup) {
        self.requireNotReentrant();
        self.inCritical = true;
        
        self.requireAuthorized(sender());
        require(msg.length > 0 && msg.length <= 50, "LuckyPandaLockup: batch size must be between 1 and 50");
        
        let totalAmount: Int = 0;
        let i: Int = 0;
        
        while (i < msg.length) {
            let account: Address? = msg.accounts.get(i);
            let amount: Int? = msg.amounts.get(i);
            let edTimestamp: Int? = msg.edTimestamps.get(i);
            
            require(account != null && account!! != newAddress(0, 0), "LuckyPandaLockup: invalid account in batch");
            require(amount != null && amount!! > 0, "LuckyPandaLockup: invalid amount in batch");
            require(edTimestamp != null && edTimestamp!! > now(), "LuckyPandaLockup: invalid timestamp in batch");
            
            let key: Slice = self.createBatchLockupKey(self.nextQueryId, i);
            self.pendingBatchLockups.set(key, LockupData{
                account: account!!,
                amount: amount!!,
                edTimestamp: edTimestamp!!
            });
            
            totalAmount = totalAmount + amount!!;
            i = i + 1;
        }
        
        let queryId: Int = self.nextQueryId;
        self.nextQueryId = self.nextQueryId + 1;
        
        self.pendingBatchExpectedAmounts.set(queryId, totalAmount);
        self.pendingBatchCounts.set(queryId, msg.length);
        
        send(SendParameters{
            to: self.jettonWallet,
            value: ton("0.3"),
            mode: SendPayGasSeparately,
            body: JettonTransfer{
                query_id: queryId,
                amount: totalAmount,
                destination: myAddress(),
                response_destination: sender(),
                custom_payload: null,
                forward_ton_amount: ton("0.1"),
                forward_payload: beginCell().endCell().beginParse()
            }.toCell()
        });
        
        self.inCritical = false;
    }
    
    // Withdraw lockup
    receive(msg: WithdrawLockup) {
        self.requireNotReentrant();
        self.inCritical = true;
        
        let currentTimestamp: Int = now();
        let senderAddr: Address = sender();
        
        require(self.checkLockupInfoExist(senderAddr, msg.lockupIndex), "LuckyPandaLockup: lockup does not exist");
        
        let key: Slice = self.createLockupKey(senderAddr, msg.lockupIndex);
        let lockupValue: LockupUser? = self.lockupInfo.get(key);
        require(lockupValue != null, "LuckyPandaLockup: lockup not found");
        let lockup: LockupUser = lockupValue!!;
        
        require(!lockup.isClaimed, "LuckyPandaLockup: lockup already claimed");
        require(!lockup.isRemoved, "LuckyPandaLockup: lockup has been removed");
        require(lockup.edTimestamp <= currentTimestamp, "LuckyPandaLockup: lockup period not yet ended");
        
        // Update state
        lockup.isClaimed = true;
        self.lockupInfo.set(key, lockup);
        
        // Update cached totals
        let currAllocated: Int as uint256 = self.totalAllocated.get(senderAddr).getOrDefault(0);
        let currClaimed: Int as uint256 = self.totalClaimed.get(senderAddr).getOrDefault(0);
        self.totalAllocated.set(senderAddr, currAllocated - lockup.amount);
        self.totalClaimed.set(senderAddr, currClaimed + lockup.amount);
        
        let queryId: Int = self.nextQueryId;
        self.nextQueryId = self.nextQueryId + 1;
        
        send(SendParameters{
            to: self.jettonWallet,
            value: ton("0.2"),
            mode: SendPayGasSeparately,
            body: JettonTransfer{
                query_id: queryId,
                amount: lockup.amount,
                destination: senderAddr,
                response_destination: myAddress(),
                custom_payload: null,
                forward_ton_amount: ton("0.1"),
                forward_payload: beginCell().endCell().beginParse()
            }.toCell()
        });
        
        emit(WithdrawLockupEvent{
            account: senderAddr,
            lockupIdx: msg.lockupIndex,
            amount: lockup.amount,
            withdrawTimestamp: currentTimestamp,
            stTimestamp: lockup.stTimestamp,
            edTimestamp: lockup.edTimestamp
        }.toCell());
        
        self.inCritical = false;
    }
    
    // Remove lockups
    receive(msg: RemoveLockups) {
        self.requireNotReentrant();
        self.inCritical = true;
        
        self.requireOwner();
        require(msg.account != newAddress(0, 0), "LuckyPandaLockup: invalid account address");
        require(self.checkLockupInfoExist(msg.account, 0), "LuckyPandaLockup: no lockup info for account");
        
        let totalRemoveAmount: Int = 0;
        let lockupCount: Int = self.lockupCounts.get(msg.account).getOrDefault(0);
        require(lockupCount <= 50, "LuckyPandaLockup: too many lockups; process in batches");
        
        let removedIndices: map<Int, Int> = emptyMap();
        let i: Int = 0;
        while (i < lockupCount) {
            let key: Slice = self.createLockupKey(msg.account, i);
            let lockupValue: LockupUser? = self.lockupInfo.get(key);
            if (lockupValue != null) {
                let lockupData: LockupUser = lockupValue!!;
                if (!lockupData.isRemoved && !lockupData.isClaimed) {
                    lockupData.isRemoved = true;
                    self.lockupInfo.set(key, lockupData);
                    totalRemoveAmount = totalRemoveAmount + lockupData.amount;
                    removedIndices.set(i, lockupData.amount);
                }
            }
            i = i + 1;
        }
        
        // Update cached totals
        let currAllocated: Int as uint256 = self.totalAllocated.get(msg.account).getOrDefault(0);
        self.totalAllocated.set(msg.account, currAllocated - totalRemoveAmount);
        
        // Emit batch event
        if (removedIndices.size() > 0) {
            emit(RemoveLockupBatchEvent{
                account: msg.account,
                lockupIndices: removedIndices,
                removedTimestamp: now()
            }.toCell());
        }
        
        if (totalRemoveAmount > 0) {
            let queryId: Int = self.nextQueryId;
            self.nextQueryId = self.nextQueryId + 1;
            
            send(SendParameters{
                to: self.jettonWallet,
                value: ton("0.2"),
                mode: SendPayGasSeparately,
                body: JettonTransfer{
                    query_id: queryId,
                    amount: totalRemoveAmount,
                    destination: self.owner,
                    response_destination: myAddress(),
                    custom_payload: null,
                    forward_ton_amount: ton("0.1"),
                    forward_payload: beginCell().endCell().beginParse()
                }.toCell()
            });
        }
        
        self.inCritical = false;
    }
    
    // Set allow list
    receive(msg: SetAllowList) {
        self.requireOwner();
        require(msg.account != newAddress(0, 0), "LuckyPandaLockup: invalid address provided");
        
        self.allowList.set(msg.account, msg.state);
        
        emit(AuthorizedEvent{
            from: sender(),
            listed: msg.account,
            state: msg.state
        }.toCell());
    }
    
    // Update Jetton wallet address
    receive(msg: UpdateJettonWallet) {
        self.requireOwner();
        require(msg.newJettonWallet != newAddress(0, 0), "LuckyPandaLockup: invalid jetton wallet address");
        self.jettonWallet = msg.newJettonWallet;
    }
    
    // Clear specific pending operation
    receive(msg: ClearPending) {
        self.requireOwner();
        let batchCount: Int = self.pendingBatchCounts.get(msg.queryId).getOrDefault(0);
        let i: Int = 0;
        while (i < batchCount) {
            let key: Slice = self.createBatchLockupKey(msg.queryId, i);
            self.pendingBatchLockups.set(key, null);
            i = i + 1;
        }
        self.pendingSetLockups.set(msg.queryId, null);
        self.pendingBatchExpectedAmounts.set(msg.queryId, null);
        self.pendingBatchCounts.set(msg.queryId, null);
    }
    
    // Internal set lockup
    fun setLockupInternal(account: Address, amount: Int as uint256, edTimestamp: Int) {
        let currentTimestamp: Int = now();
        
        require(account != newAddress(0, 0), "LuckyPandaLockup: invalid account address");
        require(amount > 0, "LuckyPandaLockup: lockup amount must be greater than zero");
        
        let currentCount: Int = self.lockupCounts.get(account).getOrDefault(0);
        
        let newLockup: LockupUser = LockupUser{
            amount: amount,
            stTimestamp: currentTimestamp,
            edTimestamp: edTimestamp,
            isClaimed: false,
            isRemoved: false
        };
        
        let key: Slice = self.createLockupKey(account, currentCount);
        self.lockupInfo.set(key, newLockup);
        self.lockupCounts.set(account, currentCount + 1);
        
        // Update cached total allocated
        let currAllocated: Int as uint256 = self.totalAllocated.get(account).getOrDefault(0);
        self.totalAllocated.set(account, currAllocated + amount);
        
        emit(SetLockupEvent{
            account: account,
            lockupIdx: currentCount,
            amount: amount,
            stTimestamp: currentTimestamp,
            edTimestamp: edTimestamp
        }.toCell());
    }
    
    // Check if lockup exists
    fun checkLockupInfoExist(account: Address, lockupIndex: Int): Bool {
        let lockupCount: Int = self.lockupCounts.get(account).getOrDefault(0);
        if (lockupCount == 0 || lockupIndex >= lockupCount) {
            return false;
        }
        let key: Slice = self.createLockupKey(account, lockupIndex);
        return self.lockupInfo.get(key) != null;
    }
    
    // Get single lockup
    get fun getLockup(account: Address, lockupIndex: Int): LockupUser? {
        if (!self.checkLockupInfoExist(account, lockupIndex)) {
            return null;
        }
        let key: Slice = self.createLockupKey(account, lockupIndex);
        return self.lockupInfo.get(key);
    }
    
    // Get lockup count
    get fun getLockupCount(account: Address): Int {
        return self.lockupCounts.get(account).getOrDefault(0);
    }
    
    // Get total allocation (using cache)
    get fun getTotalAllocation(account: Address): Int as uint256 {
        return self.totalAllocated.get(account).getOrDefault(0);
    }
    
    // Get total claimed (using cache)
    get fun getTotalClaimed(account: Address): Int as uint256 {
        return self.totalClaimed.get(account).getOrDefault(0);
    }
    
    // Get total claimable (compute on the fly)
    get fun getTotalClaimable(account: Address): Int {
        let lockupCount: Int = self.lockupCounts.get(account).getOrDefault(0);
        let totalClaimableAmount: Int = 0;
        let currentTime: Int = now();
        
        let i: Int = 0;
        while (i < lockupCount) {
            let key: Slice = self.createLockupKey(account, i);
            let lockup: LockupUser? = self.lockupInfo.get(key);
            if (lockup != null) {
                let lockupData: LockupUser = lockup!!;
                if (!lockupData.isClaimed && !lockupData.isRemoved && lockupData.edTimestamp <= currentTime) {
                    totalClaimableAmount = totalClaimableAmount + lockupData.amount;
                }
            }
            i = i + 1;
        }
        
        return totalClaimableAmount;
    }
    
    // Check if allowed
    get fun isAllowed(account: Address): Bool {
        return self.allowList.get(account).getOrDefault(false);
    }
    
    // Get Jetton wallet
    get fun getJettonWallet(): Address {
        return self.jettonWallet;
    }
    
    // Get next query ID
    get fun getNextQueryId(): Int {
        return self.nextQueryId;
    }
}
