# Module 2 - Create a Cryptocurrency

# To be installed:
# Flask==0.12.2: pip install Flask==0.12.2
# Postman HTTP Client: https://www.getpostman.com/
# requests==2.18.4: pip install requests==2.18.4

# Importing the libraries
import datetime
import hashlib
import json
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse
import random
# Part 1 - Building a Blockchain
def Create_subDAG():
    _ = str(datetime.datetime.now())
    genesis_txn = {'timestamp':_ , "parent1_hash": '00000','parent2_hash': '00000','verified': False,"transaction_hash": hashlib.sha256(_.encode() + '0000000000'.encode()).hexdigest()}
    return [[genesis_txn]], [(0,0)],[1.0]


class Blockchain:
    def __init__(self):
        self.chain = []
        _ = str(datetime.datetime.now())
        self.genesis_txn = {'timestamp':_ , "parent1_hash": '00000','parent2_hash': '00000','verified': False,"transaction_hash": hashlib.sha256(_.encode() + '0000000000'.encode()).hexdigest()}
        # self.transactions = []
        self.transactions,self.unverified_txns,self.txn_weights = Create_subDAG()
        
        self.create_block(proof = 1, previous_hash = '0')
        self.nodes = set()

    def create_block(self, proof, previous_hash):
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash,
                 'transactions': self.transactions}

        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof
    
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True
    def get_parents(self,index):
        # time_stamp = str(datetime.datetime.now())
        loc = self.unverified_txns.index((index,0))
        ut = self.unverified_txns[:loc]
        loc_a,loc_b = random.choices(range(len(ut)),k=2,weights=self.txn_weights[:loc])
        while loc_a==loc_b and len(ut)>1:
            loc_a,loc_b  = random.choices(range(len(ut)),k=2,weights=self.txn_weights[:loc])
        a,b = ut[loc_a],ut[loc_b]
        self.txn_weights[loc_a]/=2.0
        self.txn_weights[loc_b]/=2.0
        return a,b 
     
    def compare_txn_create_time(self,current_txn_timestamp, prev_txn_timestamp,time_in_sec = 10):
        if (datetime.datetime.fromisoformat(current_txn_timestamp) - datetime.datetime.fromisoformat(prev_txn_timestamp)) <datetime.timedelta(seconds=time_in_sec):
            return True
        return False
    def verify_txn(self,txn_index):
        self.transactions[txn_index[0]][txn_index[1]]['verified']=True
    def Transaction(self,sender, receiver, amount, parent1,parent2,time_stamp):
        parent1_hash = self.transactions[parent1[0]][parent1[1]]['transaction_hash']
        parent2_hash = self.transactions[parent2[0]][parent2[1]]['transaction_hash']
        parents_hash = parent1_hash + parent2_hash
        curr_txn =  {'sender': sender,
                        'receiver': receiver,
                        'amount': amount,
                        'transaction_hash':  hashlib.sha256(time_stamp.encode() + parents_hash.encode()).hexdigest(),
                        'parent1_hash': parent1_hash,
                        'parent2_hash': parent2_hash,
                        'timestamp': time_stamp,
                        'verified': False
                                  }
        return curr_txn


    def add_transaction(self, sender, receiver, amount):
        time_stamp = str(datetime.datetime.now())
        prev_txn = self.transactions[-1][0]
        last_unverified = self.unverified_txns[-1]
        
        if self.compare_txn_create_time(time_stamp,prev_txn['timestamp'],time_in_sec=10) and (len(self.transactions)>1):
            
            self.unverified_txns.append((last_unverified[0], last_unverified[1]+1))
            
            parent1, parent2 = self.get_parents(index= last_unverified[0])

            curr_txn = self.Transaction(sender, receiver, amount, parent1,parent2, time_stamp)

            self.transactions[-1].append(curr_txn)
            
            
        else:
            
            self.unverified_txns.append((last_unverified[0]+1, 0))
            
            parent1, parent2 = self.get_parents(index= last_unverified[0]+1)
            
            curr_txn = self.Transaction(sender, receiver, amount, parent1,parent2, time_stamp)
            
            self.transactions.append([curr_txn])
        
        self.txn_weights.append(1.0)
        self.verify_txn(parent1)
        self.verify_txn(parent2)
        
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1
    def verify_all(self, sender, receiver, amount):
        time_stamp = str(datetime.datetime.now())
        parent_hash = []
        for txns in self.transactions:
            for txn in txns:
                if txn and not txn['verified']:
                    parent_hash.append(txn['transaction_hash'])
                txn['verified'] = True
        curr_txn = {'sender': sender,
                        'receiver': receiver,
                        'amount': amount,
                        'transaction_hash':  hashlib.sha256(time_stamp.encode() + ''.join(parent_hash).encode()).hexdigest(),
                        'parents_hash': parent_hash,
                        'timestamp': time_stamp
                                  }
        self.transactions.append([curr_txn])
        
    
    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
    
    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        print(max_length)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                print(length,node)
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False
    
    def update_chain(self):
        network = self.nodes
        for node in network:
            r = requests.post(f'http://{node}/update_chain',json={'chain':self.chain})
            
                
            
    def get_transactions(self):
        network = self.nodes
        txns = []
        for node in network:
            response = requests.get(f'http://{node}/get_transactions')
            if response.status_code == 200:
                txns.extend(response.json()['transactions'])
        self.transactions.extend(txns)
        

# Part 2 - Mining our Blockchain

# Creating a Web App
app = Flask(__name__)

# Creating an address for the node on Port 5001
node_address = str(uuid4()).replace('-', '')

# Creating a Blockchain
blockchain = Blockchain()

# Mining a new block
@app.route('/mine_block', methods = ['GET'])
def mine_block():
    blockchain.get_transactions()
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    blockchain.verify_all(sender = node_address, receiver = 'Hadelin', amount = 1)
    
    block = blockchain.create_block(proof, previous_hash)
    
    response = {'message': 'Congratulations, you just mined a block!',
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash'],
                'transactions': block['transactions']}
    blockchain.transactions,blockchain.unverified_txns,blockchain.txn_weights = Create_subDAG()
    blockchain.update_chain()
    return jsonify(response), 200


# Getting the full Blockchain
@app.route('/get_chain', methods = ['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

# Checking if the Blockchain is valid
@app.route('/is_valid', methods = ['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': 'All good. The Blockchain is valid.'}
    else:
        response = {'message': 'Houston, we have a problem. The Blockchain is not valid.'}
    return jsonify(response), 200

# Adding a new transaction to the Blockchain
@app.route('/add_transaction', methods = ['POST'])
def add_transaction():
    json = request.get_json()
    transaction_keys = ['sender', 'receiver', 'amount']
    if not all(key in json for key in transaction_keys):
        return 'Some elements of the transaction are missing', 400
    index = blockchain.add_transaction(json['sender'], json['receiver'], json['amount'])
    response = {'message': f'This transaction will be added to Block {index}'}
    return jsonify(response), 201

@app.route('/get_transactions', methods = ['GET'])
def get_transaction():
    response = {'transactions': blockchain.transactions}
    blockchain.transactions,blockchain.unverified_txns,blockchain.txn_weights = Create_subDAG()
    return jsonify(response), 200

@app.route('/update_chain', methods = ['POST'])
def update_chain():
    json = request.get_json()
    chain = json.get('chain')
    if chain is not None:
        blockchain.chain = chain
        return jsonify({'message':'Chain updated'}),201
    
# Part 3 - Decentralizing our Blockchain

# Connecting new nodes
@app.route('/connect_node', methods = ['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "No node", 400
    for node in nodes:
        blockchain.add_node(node)
    response = {'message': 'All the nodes are now connected. The Hadcoin Blockchain now contains the following nodes:',
                'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201

# Replacing the chain by the longest chain if needed
@app.route('/replace_chain', methods = ['GET'])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {'message': 'The nodes had different chains so the chain was replaced by the longest one.',
                    'new_chain': blockchain.chain}
    else:
        response = {'message': 'All good. The chain is the largest one.',
                    'actual_chain': blockchain.chain}
    return jsonify(response), 200

# Running the app
app.run(host = '0.0.0.0', port = 5000)
