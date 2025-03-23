from solders.pubkey import Pubkey
from solana.rpc.api import Client
import base64
from collections import defaultdict, deque
from solana.rpc.types import TokenAccountOpts
import time
from solana.exceptions import SolanaRpcException
import random
import logging
from datetime import datetime
import traceback
import urllib3

# Disable all HTTP/RPC related logging
for logger_name in [
    'urllib3',
    'urllib3.connectionpool',
    'urllib3.util.retry',
    'urllib3.util',
    'urllib3.connection',
    'urllib3.response',
    'urllib3.poolmanager',
    'solana.rpc.api',
    'solana.rpc',
    'solana',
    'requests',
    'requests.packages.urllib3'
]:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.CRITICAL)
    logger.addHandler(logging.NullHandler())
    logger.propagate = False

# Disable urllib3 warnings
urllib3.disable_warnings()

# Now set up our application logging
log_filename = f"wallet_tracker_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Initialize Solana RPC clients
RPC_ENDPOINTS = [
    "https://rpc.helius.xyz/?api-key=708fa1db-5bba-4eaf-90c3-58750eb7090f",
    "https://api.mainnet-beta.solana.com",  # Public backup endpoint
]
current_rpc_index = 0
client = Client(RPC_ENDPOINTS[current_rpc_index], commitment="confirmed")

# Use Pubkey.from_string() for base58-encoded addresses
# INITIAL_WALLET = Pubkey.from_string("AVAZvHLR2PcWpDf8BXY4rVxNHYRBytycHkcB5z5QNXYm")
# INITIAL_WALLET = Pubkey.from_string("CCreeLG968TrCxJWLZj3FoZpYzZ9HUviCZJMZkkZ4FWW")
INITIAL_WALLET = Pubkey.from_string("CCreeLG968TrCxJWLZj3FoZpYzZ9HUviCZJMZkkZ4FWW")

TOKEN_MINT = Pubkey.from_string("4NBTf8PfLH4oLFnwf3knv46FY9i5oXjDxffCetXRpump")
MAX_DEPTH = 3  # Increased depth for better analysis
TOKEN_PROGRAM_ID = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")

# Rate limiting configuration
INITIAL_DELAY = 1.0  # Start with a 1-second delay for retries
MAX_RETRIES = 8   # Increase max retries for rate limits
BATCH_SIZE = 100  # Reduce batch size to avoid rate limits
DELAY_BETWEEN_REQUESTS = 1.0  # 1 second between requests (more conservative)
DEBUG_MODE = True  # When True, limits transaction processing for faster debugging
DEBUG_TXN_LIMIT = 1000  # Maximum transactions to process per wallet in debug mode
PROGRESS_UPDATE_FREQUENCY = 100  # Show progress every 100 transactions

# Update these constants
# WALLETS_OF_INTEREST = [
#     "53DUcxaUTHh8nBwNQBq9vca2MCQAEGjKMUa1oCUd2opv",
#     "H6KiqN3wwirFumem4ZqxbF3hhHNTjpyps3q7TTLX3n33",
#     "HmWDtrDA4nricAhU4RPV68Bfr2AARGoEnexddnaoTn5J",
#     "AVAZvHLR2PcWpDf8BXY4rVxNHYRBytycHkcB5z5QNXYm",
#     "5BnynYC2bMgFHR64vKnWyFUnMc8eqswjD5nam5vZstVZ",
#     "HK7gWC6ihY1dj8dgdYvRfYDg9E8YhSGcSHuQE9e4VAuo"
# ]
WALLETS_OF_INTEREST = [
    "CCreeLG968TrCxJWLZj3FoZpYzZ9HUviCZJMZkkZ4FWW",
    "FHqoNsXTVsiQHWnXTiJnTNXG9yTAwb2y5hFpbVqF3wSP"
]
YZY_MINT = Pubkey.from_string("4NBTf8PfLH4oLFnwf3knv46FY9i5oXjDxffCetXRpump")
USDC_MINT = Pubkey.from_string("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")

def switch_rpc_endpoint():
    """Switch to the next available RPC endpoint."""
    global current_rpc_index, client
    current_rpc_index = (current_rpc_index + 1) % len(RPC_ENDPOINTS)
    client = Client(RPC_ENDPOINTS[current_rpc_index], commitment="confirmed")
    logger.info(f"🔄 Switching to RPC endpoint: {RPC_ENDPOINTS[current_rpc_index]}")

def retry_with_backoff(func, max_retries=3, initial_delay=1):
    """
    Retry a function with exponential backoff.
    """
    delay = initial_delay
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            last_exception = e
            
            if "429 Too Many Requests" in str(e):
                logger.warning(f"Rate limit hit, switching to backup endpoint...")
                global client
                client = Client("https://api.mainnet-beta.solana.com")
                delay = initial_delay  # Reset delay when switching endpoints
            else:
                delay *= 2  # Exponential backoff
            
            logger.warning(f"Attempt {attempt + 1}/{max_retries} failed: {str(e)}")
            logger.info(f"💤 Sleeping for {delay} seconds...")
            time.sleep(delay)
            logger.info("✓ Resuming...")
    
    logger.error(f"Max retries ({max_retries}) exceeded. Last error: {str(last_exception)}")
    raise last_exception

def get_token_accounts(wallet):
    """
    Fetch all token accounts for a wallet and specific mint.
    
    Args:
        wallet (Pubkey): The wallet address to query
        
    Returns:
        list[Pubkey]: List of token account public keys
    """
    opts = TokenAccountOpts(
        mint=TOKEN_MINT,
        program_id=None,
        encoding="base64",  # TokenAccountOpts only supports base58 or base64
        data_slice=None
    )
    response = retry_with_backoff(lambda: client.get_token_accounts_by_owner(wallet, opts=opts))
    if not response.value:
        return []
    return [acc.pubkey for acc in response.value]  # pubkey is already a Pubkey object

def get_receiver_wallet(destination_token_account):
    """Fetch the owner of a token account."""
    response = retry_with_backoff(lambda: client.get_account_info(destination_token_account, encoding="base64"))
    if not response.value:
        return None
    account_data = base64.b64decode(response.value.data[0])
    owner_bytes = account_data[32:64]  # Owner field is at bytes 32-64 in SPL token account layout
    return Pubkey(owner_bytes)

def analyze_transaction_for_patterns(tx, wallet, connection_data):
    """
    Analyze a transaction for patterns indicating wallet connections.
    """
    try:
        if not hasattr(tx, 'status_meta') or not tx.status_meta:
            return

        tx_signature = tx.transaction.signatures[0] if hasattr(tx.transaction, 'signatures') else None
        
        # Special debug for our target transaction
        is_target_tx = tx_signature == "217Wn3zDFKkkq49ZFwULs4PFQsTA6CfWE2QRSrZ7zNrY7jiC8MYLXctws92htrKt7AbkMuVQM8dUB7WECgCpdWwC"
        if is_target_tx:
            logger.info("\n🔍 Found target transaction!")
            logger.info("═══════════════════════════")
            logger.info(f"Current wallet being analyzed: {wallet}")
            logger.info(f"Transaction signature: {tx_signature}")
            logger.info("Analyzing instructions...")
        
        # Check for System Program transfers
        if hasattr(tx.transaction, 'message'):
            for idx, instr in enumerate(tx.transaction.message.instructions):
                if isinstance(instr, dict):
                    if is_target_tx:
                        logger.info(f"\nInstruction {idx}:")
                        logger.info(f"├─ Program ID: {instr.get('programId')}")
                        logger.info(f"├─ Type: {instr.get('parsed', {}).get('type')}")
                        logger.info(f"└─ Info: {instr.get('parsed', {}).get('info')}")
                    
                    # Check for System Program transfer
                    if (instr.get('programId') == '11111111111111111111111111111111' and
                        instr.get('parsed', {}).get('type') == 'transfer'):
                        info = instr.get('parsed', {}).get('info', {})
                        source = info.get('source')
                        destination = info.get('destination')
                        lamports = info.get('lamports', 0)
                        
                        if DEBUG_MODE:
                            logger.debug(f"\n     ├─ Found System Program transfer:")
                            logger.debug(f"     │  ├─ From: {source}")
                            logger.debug(f"     │  ├─ To: {destination}")
                            logger.debug(f"     │  └─ Amount: {lamports/1e9:.9f} SOL")
                        
                        # Check if either party is in our wallets of interest
                        wallet_str = str(wallet)
                        other_wallet = None
                        direction = None
                        
                        if source == wallet_str:
                            other_wallet = destination
                            direction = 'out'
                        elif destination == wallet_str:
                            other_wallet = source
                            direction = 'in'
                        
                        if other_wallet and other_wallet in WALLETS_OF_INTEREST:
                            if 'transfers' not in connection_data:
                                connection_data['transfers'] = []
                            if 'direct_transfers' not in connection_data:
                                connection_data['direct_transfers'] = set()
                            
                            transfer_info = {
                                'counterparty': other_wallet,
                                'direction': direction,
                                'amount': lamports/1e9,  # Convert to SOL
                                'signature': tx_signature,
                                'type': 'SOL'
                            }
                            connection_data['transfers'].append(transfer_info)
                            connection_data['direct_transfers'].add(other_wallet)
                            
                            logger.info(f"\n🔗 Connection found!")
                            logger.info(f"  ├─ Type: SOL transfer")
                            logger.info(f"  ├─ {'Sent to' if direction == 'out' else 'Received from'}: {other_wallet}")
                            logger.info(f"  ├─ Amount: {lamports/1e9:.9f} SOL")
                            logger.info(f"  └─ Transaction: https://solscan.io/tx/{tx_signature}\n")
                            
                            # Special case: Check if this is the specific transaction we're looking for
                            if tx_signature == "217Wn3zDFKkkq49ZFwULs4PFQsTA6CfWE2QRSrZ7zNrY7jiC8MYLXctws92htrKt7AbkMuVQM8dUB7WECgCpdWwC":
                                logger.info(f"\n🎯 Found target transaction!")
                                logger.info(f"═══════════════════════════")
                                logger.info(f"Transaction details:")
                                logger.info(f"├─ Signature: {tx_signature}")
                                logger.info(f"├─ From: {source}")
                                logger.info(f"├─ To: {destination}")
                                logger.info(f"├─ Amount: {lamports/1e9:.9f} SOL")
                                logger.info(f"├─ Type: System Program Transfer")
                                logger.info(f"└─ Status: {'Success' if not tx.status_meta.err else 'Failed'}\n")
                    
                    # Check for Token Program transfer
                    elif (instr.get('programId') == str(TOKEN_PROGRAM_ID) and
                          instr.get('parsed', {}).get('type') == 'transfer'):
                        info = instr.get('parsed', {}).get('info', {})
                        source = info.get('source')
                        destination = info.get('destination')
                        amount = float(info.get('amount', 0)) if info.get('amount') else 0
                        
                        if DEBUG_MODE:
                            logger.debug(f"\n     ├─ Found token transfer:")
                            logger.debug(f"     │  ├─ From: {source}")
                            logger.debug(f"     │  ├─ To: {destination}")
                            logger.debug(f"     │  └─ Amount: {amount:,.6f} YzY")
                        
                        # Track all transfers involving our wallet or its token accounts
                        wallet_str = str(wallet)
                        token_accounts = [str(acc) for acc in get_token_accounts(wallet)]
                        
                        try:
                            source_owner = None
                            if source != wallet_str and source not in token_accounts:
                                source_pubkey = Pubkey.from_string(source)
                                source_owner = str(get_receiver_wallet(source_pubkey))
                            
                            dest_owner = None
                            if destination != wallet_str and destination not in token_accounts:
                                dest_pubkey = Pubkey.from_string(destination)
                                dest_owner = str(get_receiver_wallet(dest_pubkey))
                        except Exception as e:
                            if DEBUG_MODE:
                                logger.debug(f"     ├─ Error resolving wallet owners: {str(e)}")
                            continue
                        
                        # Check if either the source or destination involves a wallet of interest
                        other_wallet = None
                        direction = None
                        
                        if source == wallet_str or source in token_accounts:
                            other_wallet = dest_owner
                            direction = 'out'
                        elif destination == wallet_str or destination in token_accounts:
                            other_wallet = source_owner
                            direction = 'in'
                        elif source_owner == str(wallet):
                            other_wallet = dest_owner
                            direction = 'out'
                        elif dest_owner == str(wallet):
                            other_wallet = source_owner
                            direction = 'in'
                        
                        if other_wallet and other_wallet in WALLETS_OF_INTEREST:
                            if 'transfers' not in connection_data:
                                connection_data['transfers'] = []
                            if 'direct_transfers' not in connection_data:
                                connection_data['direct_transfers'] = set()
                            
                            transfer_info = {
                                'counterparty': other_wallet,
                                'direction': direction,
                                'amount': amount,
                                'signature': tx_signature,
                                'type': 'YzY'
                            }
                            connection_data['transfers'].append(transfer_info)
                            connection_data['direct_transfers'].add(other_wallet)
                            
                            logger.info(f"\n🔗 Connection found!")
                            logger.info(f"  ├─ Type: YzY transfer")
                            logger.info(f"  ├─ {'Sent to' if direction == 'out' else 'Received from'}: {other_wallet}")
                            logger.info(f"  ├─ Amount: {amount:,.6f} YzY")
                            logger.info(f"  └─ Transaction: https://solscan.io/tx/{tx_signature}\n")

            # Check inner instructions for token transfers
            if hasattr(tx.status_meta, 'inner_instructions'):
                for inner_group in tx.status_meta.inner_instructions:
                    for inner_ix in inner_group.instructions:
                        if isinstance(inner_ix, dict):
                            if (inner_ix.get('programId') == str(TOKEN_PROGRAM_ID) and
                                inner_ix.get('parsed', {}).get('type') == 'transfer'):
                                info = inner_ix.get('parsed', {}).get('info', {})
                                source = info.get('source')
                                destination = info.get('destination')
                                amount = float(info.get('amount', 0)) if info.get('amount') else 0
                                
                                if DEBUG_MODE:
                                    logger.debug(f"\n     ├─ Found inner token transfer:")
                                    logger.debug(f"     │  ├─ From: {source}")
                                    logger.debug(f"     │  ├─ To: {destination}")
                                    logger.debug(f"     │  └─ Amount: {amount:,.6f} YzY")

    except Exception as e:
        logger.error(f"     ├─ Error analyzing transaction patterns:")
        logger.error(f"     │  └─ {str(e)}")
        if DEBUG_MODE:
            import traceback
            traceback.print_exc()

def process_transaction_batch(signatures, token_account, current_wallet, sent_to_wallets, queue, depth):
    """Process a batch of transaction signatures."""
    total_sigs = len(signatures)
    
    for idx, sig in enumerate(signatures, 1):
        if idx % 10 == 0:  # Only log every 10 transactions
            logger.info(f"Processing transaction {idx}/{total_sigs}")
            
        try:
            tx = retry_with_backoff(
                lambda: client.get_transaction(
                    sig.signature,
                    encoding="jsonParsed",
                    max_supported_transaction_version=0
                )
            )
            if not tx.value:
                continue

            # Get transaction metadata
            if not hasattr(tx.value, 'status_meta') or not tx.value.status_meta:
                continue

            # Parse inner instructions if they exist
            if hasattr(tx.value.status_meta, 'inner_instructions') and tx.value.status_meta.inner_instructions:
                for inner_instr_group in tx.value.status_meta.inner_instructions:
                    for inner_ix in inner_instr_group.instructions:
                        if (isinstance(inner_ix, dict) and
                            inner_ix.get('programId') == str(TOKEN_PROGRAM_ID) and
                            inner_ix.get('parsed', {}).get('type') == 'transfer' and
                            inner_ix.get('parsed', {}).get('info', {}).get('source') == str(token_account)):
                            destination = Pubkey.from_string(inner_ix['parsed']['info']['destination'])
                            receiver_wallet = get_receiver_wallet(destination)
                            if receiver_wallet and receiver_wallet != current_wallet:
                                sent_to_wallets.add(receiver_wallet)
                                queue.append((receiver_wallet, depth + 1))

            # Parse main instructions
            if hasattr(tx.value.transaction, 'message'):
                for instr in tx.value.transaction.message.instructions:
                    if (isinstance(instr, dict) and
                        instr.get('programId') == str(TOKEN_PROGRAM_ID) and
                        instr.get('parsed', {}).get('type') == 'transfer' and
                        instr.get('parsed', {}).get('info', {}).get('source') == str(token_account)):
                        destination = Pubkey.from_string(instr['parsed']['info']['destination'])
                        receiver_wallet = get_receiver_wallet(destination)
                        if receiver_wallet and receiver_wallet != current_wallet:
                            sent_to_wallets.add(receiver_wallet)
                            queue.append((receiver_wallet, depth + 1))
        except Exception as e:
            logger.error(f"Error processing transaction {sig.signature}: {str(e)}")
            continue
            
        time.sleep(DELAY_BETWEEN_REQUESTS)  # Single sleep after processing each transaction

def build_wallet_tree(initial_wallet):
    """
    Build a tree of wallets based on outgoing token transfers.
    
    Args:
        initial_wallet (Pubkey): The initial wallet to start building the tree from
        
    Returns:
        dict: A tree structure representing wallet connections
    """
    tree = defaultdict(list)  # {wallet: [list of wallets it sent to]}
    processed = set()  # Track processed wallets to avoid cycles
    queue = deque([(initial_wallet, 0)])  # (wallet, depth)

    while queue:
        current_wallet, depth = queue.popleft()
        if depth > MAX_DEPTH or current_wallet in processed:
            continue
        processed.add(current_wallet)
        logger.info(f"Processing wallet: {current_wallet} at depth {depth}")

        token_accounts = get_token_accounts(current_wallet)
        if not token_accounts:
            continue

        sent_to_wallets = set()

        for token_account in token_accounts:
            # Fetch transaction signatures with debug limit if enabled
            sig_limit = DEBUG_TXN_LIMIT if DEBUG_MODE else 1000
            signatures = retry_with_backoff(
                lambda: client.get_signatures_for_address(token_account, limit=sig_limit)
            )
            if not signatures.value:
                continue

            if DEBUG_MODE:
                logger.info(f"🔧 DEBUG MODE: Processing only {DEBUG_TXN_LIMIT} signatures for {token_account}")

            # Process signatures in batches
            for i in range(0, len(signatures.value), BATCH_SIZE):
                batch = signatures.value[i:i + BATCH_SIZE]
                print(f"Processing batch {i//BATCH_SIZE + 1} of {(len(signatures.value) + BATCH_SIZE - 1)//BATCH_SIZE}")
                process_transaction_batch(batch, token_account, current_wallet, sent_to_wallets, queue, depth)
                time.sleep(DELAY_BETWEEN_REQUESTS)  # Delay between batches

        if sent_to_wallets:
            tree[str(current_wallet)] = [str(w) for w in sent_to_wallets]

    return tree

def print_tree(tree, root, depth=0, prefix=""):
    """Recursively print the wallet tree in a readable format."""
    print(f"{prefix}{'|-- ' if depth > 0 else ''}{root}")
    children = tree.get(str(root), [])
    for i, child in enumerate(children):
        is_last = i == len(children) - 1
        new_prefix = prefix + ("    " if depth == 0 else "|   " if not is_last else "    ")
        print_tree(tree, child, depth + 1, new_prefix)

def process_wallet_transactions(account, connection_data):
    """
    Process transactions for a given account and update connection data.
    """
    try:
        # Get signatures for the account
        signatures = retry_with_backoff(
            lambda: client.get_signatures_for_address(account, limit=DEBUG_TXN_LIMIT if DEBUG_MODE else 1000)
        )
        
        if not signatures.value:
            logger.info("No transactions found")
            return
        
        total_txns = len(signatures.value)
        logger.info(f"Processing {total_txns} transactions...")
        start_time = time.time()
        
        for i, sig_info in enumerate(signatures.value, 1):
            if i % PROGRESS_UPDATE_FREQUENCY == 0:  # Log progress less frequently
                elapsed = time.time() - start_time
                txns_per_sec = i / elapsed
                remaining = ((total_txns - i) / txns_per_sec) if txns_per_sec > 0 else 0
                logger.info(f"Progress: {i}/{total_txns} ({(i/total_txns)*100:.1f}%) - {txns_per_sec:.1f} tx/s - Est. {remaining:.0f}s remaining")
            
            try:
                # Get transaction details with version parameter
                tx = retry_with_backoff(
                    lambda: client.get_transaction(
                        sig_info.signature,
                        encoding="jsonParsed",
                        max_supported_transaction_version=0
                    )
                )
                
                # Analyze transaction for patterns
                analyze_transaction_for_patterns(tx.value, account, connection_data)
                
                # Sleep to respect rate limits
                time.sleep(DELAY_BETWEEN_REQUESTS)
                
            except Exception as e:
                if DEBUG_MODE:
                    logger.debug(f"Error processing tx {sig_info.signature}: {str(e)}")
                continue
        
        elapsed = time.time() - start_time
        logger.info(f"Completed processing {total_txns} transactions in {elapsed:.1f}s ({total_txns/elapsed:.1f} tx/s)")
        
    except Exception as e:
        logger.error(f"Error in process_wallet_transactions: {str(e)}")
        if DEBUG_MODE:
            logger.debug(traceback.format_exc())

def get_token_balance(token_account: Pubkey) -> float:
    """
    Get the token balance for a specific token account.
    
    Args:
        token_account (Pubkey): The token account to check
        
    Returns:
        float: The token balance, or 0 if there's an error
    """
    try:
        response = retry_with_backoff(lambda: client.get_token_account_balance(token_account))
        if response.value:
            return float(response.value.amount) / (10 ** response.value.decimals)
        return 0
    except Exception as e:
        print(f"Error getting balance for {token_account}: {str(e)}")
        return 0

def analyze_wallet_connections(wallet, connection_data):
    """
    Analyze connections for a given wallet by examining its transactions and token accounts.
    """
    logger.info(f"\n📊 Analyzing wallet: {wallet}")
    logger.info("═══════════════════════════")

    # Get token accounts for the wallet
    token_accounts = get_token_accounts(wallet)
    logger.info(f"Found {len(token_accounts)} token accounts")
    
    if DEBUG_MODE:
        for account in token_accounts:
            logger.debug(f"├─ {account}")
            balance = get_token_balance(account)
            if balance > 0:
                logger.debug(f"│  └─ YzY Balance: {balance:,.6f}")
    
    # Process transactions for each token account
    for account in token_accounts:
        try:
            logger.info(f"\n🔍 Checking transactions for token account: {account}")
            process_wallet_transactions(account, connection_data)
        except Exception as e:
            logger.error(f"Error processing token account {account}: {str(e)}")
            if DEBUG_MODE:
                import traceback
                logger.debug(traceback.format_exc())

# Main execution
all_connections = {}
for wallet_str in WALLETS_OF_INTEREST:
    wallet = Pubkey.from_string(wallet_str)  # Convert string to Pubkey
    connection_data = {
        'direct_transfers': set(),
        'transfers': [],
        'yzY_holdings': 0
    }
    analyze_wallet_connections(wallet, connection_data)
    all_connections[wallet_str] = connection_data

print("\n📊 Analysis Results")
print("═══════════════════")
for wallet, data in all_connections.items():
    print(f"\n👛 Wallet: {wallet}")
    print("├───────────────")
    print(f"├─ YzY holdings: {data['yzY_holdings']:,.6f}")
    
    # Show all transfers
    if 'transfers' in data and data['transfers']:
        print(f"\n├─ Transfers found: {len(data['transfers'])}")
        for transfer in data['transfers']:
            direction = "→" if transfer['direction'] == 'out' else "←"
            asset_type = transfer.get('type', 'YzY')
            amount = transfer['amount']
            if asset_type == 'SOL':
                amount_str = f"{amount:,.9f} SOL"
            else:
                amount_str = f"{amount:,.6f} YzY"
            print(f"│  {direction} {amount_str} {'to' if transfer['direction'] == 'out' else 'from'} {transfer['counterparty']}")
            print(f"│    └─ https://solscan.io/tx/{transfer['signature']}")
    else:
        print("\n├─ No transfers found")
    
    # Show direct transfers with wallets of interest
    if data['direct_transfers']:
        print(f"\n├─ Connected wallets: {len(data['direct_transfers'])}")
        for connected_wallet in data['direct_transfers']:
            print(f"│  └─ {connected_wallet}")
            if connected_wallet in all_connections:
                print(f"│     └─ Their YzY balance: {all_connections[connected_wallet]['yzY_holdings']:,.6f}")

print("\n✅ Analysis complete!")