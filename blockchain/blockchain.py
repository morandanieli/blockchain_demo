import hashlib
import json
import requests
import re
from collections import OrderedDict
from time import time

from Crypto.Hash import SHA
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import binascii
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from os import path
from urllib.parse import urlparse
from tools import json_tools

MINING_SENDER = "The Blockchain"
MINING_REWARD = 1
MINING_DIFICULTY = 2

class Blockchain:
    def __init__(self, node_name):
        self.node_name = node_name
        self.node_id = self.calc_hexdigest(node_name)
        self.nodes_db_file = "../dbs/nodes-{}.json".format(self.node_id)

        if path.exists(self.nodes_db_file):
            with open(self.nodes_db_file, "r") as f:
                self.nodes = json.load(f, cls=json_tools.MyDecoder)
        else:
            self.nodes = set()
            with open(self.nodes_db_file, "w") as f:
                json.dump(self.nodes, f, cls=json_tools.MyEncoder)

        self.transactions = list()

        self.chain_db_file = "../dbs/chain-{}.json".format(self.node_id)
        if path.exists(self.chain_db_file):
            with open(self.chain_db_file, "r") as f:
                self.chain = json.load(f, cls=json_tools.MyDecoder)
        else:
            self.chain = list()
            # Create the genesis block
            self.create_block(0, '0' * 64)

    @staticmethod
    def calc_hexdigest(data):
        h = hashlib.new('sha256')
        h.update(data.encode('utf8'))
        return h.hexdigest()

    def create_block(self, nonce, previous_hash):
        """
        Add a block of transactions to the blockchain
        """
        block = {
            "block_number": len(self.chain) + 1,
            "timestamp": time(),
            "transactions": self.transactions,
            "nonce": nonce,
            "previous_hash": previous_hash
        }

        # Reset the current list of transactions
        self.transactions = list()
        self.chain.append(block)
        with open(self.chain_db_file, "w") as f:
            json.dump(self.chain, f, cls=json_tools.MyEncoder)

        return block

    def verify_transaction_signature(self, sender_public_key, signature, transaction):
        public_key = RSA.importKey(binascii.unhexlify(sender_public_key))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))
        try:
            verifier.verify(h, binascii.unhexlify(signature))
            return True
        except ValueError:
            return False

    def submit_transaction(self, sender_public_key, recipient_public_key, signature, amount):
        transaction = OrderedDict({
            'sender_public_key': sender_public_key,
            'recipient_public_key': recipient_public_key,
            'amount': amount
        })

        if sender_public_key == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        else:
            signature_verification = self.verify_transaction_signature(sender_public_key, signature, transaction)

            if signature_verification:
                self.transactions.append(transaction)
                return len(self.chain) + 1
            else:
                return False

    def proof_of_work(self):
        nonce = 0
        last_block = self.chain[-1]
        previous_hash = self.hash(last_block)

        while self.valid_proof(self.transactions, previous_hash, nonce) is False:
            nonce += 1
        return nonce

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hash(last_block):
                return False

            # trim the reward transaction from the transactions list
            transactions = block["transactions"][:-1]
            transaction_elements = ['sender_public_key', 'recipient_public_key',
                                    'amount']

            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]

            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFICULTY):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        neighbhoors = self.nodes
        new_chain = None

        max_length = len(self.chain)
        for node in neighbhoors:
            response = requests.get(url='http://{}/chain'.format(node))
            if response.status_code == 200:
                response_data = response.json()
                chain = response_data['chain']
                length = response_data['length']
                if length > max_length and self.valid_chain(chain):
                    new_chain = chain
                    max_length = length

        if new_chain:
            self.chain = new_chain
            with open(self.chain_db_file, "w") as f:
                json.dump(self.chain, f, cls=json_tools.MyEncoder)
            return True

        return False


    @staticmethod
    def valid_proof(transactions, last_hash, nonce, difficulty=MINING_DIFICULTY):
        guess = (str(transactions) + str(last_hash) + str(nonce)).encode('utf8')

        h = hashlib.new('sha256')
        h.update(guess)
        guess_hash = h.hexdigest()

        return guess_hash[:difficulty] == "0" * difficulty

    @staticmethod
    def hash(block):
        # To ensure dictionary is order, otherwise we will get inconsistant hashes
        block_string = json.dumps(block, sort_keys=True)
        h = hashlib.new(name="sha256")
        h.update(block_string.encode('utf8'))
        return h.hexdigest()

    def register_node(self, node_url):
        parsed_url = urlparse(node_url)
        node_url = None

        if parsed_url.netloc:
            node_url = parsed_url.netloc

        elif parsed_url.path:
            node_url = parsed_url.path

        else:
            raise ValueError("Invalid URL")

        if node_url not in self.nodes:
            response = requests.get(url='http://{}/monitor'.format(node_url))
            # node is a responsive
            if response.status_code == 204:
                self.nodes.add(node_url)
                with open(self.nodes_db_file, "w") as f:
                    json.dump(self.nodes, f, cls=json_tools.MyEncoder)

                blockchain.resolve_conflicts()
            else:
                raise requests.exceptions.ConnectionError



blockchain = None

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/monitor')
def monitor():
    return '', 204

@app.route('/configure')
def configure():
    return render_template('./configure.html')

@app.route('/transactions/get')
def get_transactions():
    transactions = blockchain.transactions
    response = {
        "transactions": transactions
    }

    return jsonify(response), 200


@app.route('/nodes/get')
def get_nodes():
    nodes = blockchain.nodes
    response = {
        "nodes": list(nodes)
    }

    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    # Example: 127.0.0.1:5002,127.0.0.1:5003 , 127.0.0.1:5004
    nodes = re.sub(re.compile("\s"), '', values.get('nodes')).split(",")

    if nodes is None:
        return 'Error: Please supply a valid list of nodes', 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        "message": 'Nodes have been added',
        'total_nodes': [node for node in blockchain.nodes]
    }

    return jsonify(response), 200


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/chain')
def get_chain():
    response = {
        "chain": blockchain.chain,
        "length": len(blockchain.chain)
    }

    return jsonify(response), 200

@app.route('/mine')
def mine():
    nonce = blockchain.proof_of_work()
    blockchain.submit_transaction(
        sender_public_key=MINING_SENDER,
        recipient_public_key=blockchain.node_id,
        signature='',
        amount=MINING_REWARD
    )

    last_block = blockchain.chain[-1]
    previous_hash = blockchain.hash(last_block)

    block = blockchain.create_block(nonce=nonce,
                            previous_hash=previous_hash)

    response = {
        'message': 'New block created',
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }

    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form
    required = ['confirmation_sender_public_key',
                'confirmation_recipient_public_key',
                'transaction_signature',
                'confirmation_amount']

    if not all(k in values for k in required):
        return 'Missing Values', 400


    transaction_results = blockchain.submit_transaction(values['confirmation_sender_public_key'],
                                                        values['confirmation_recipient_public_key'],
                                                        values['transaction_signature'],
                                                        values['confirmation_amount'])
    if transaction_results == False:
        response = {'message': 'Invalid transaction/signature'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to block ' + str(transaction_results)}
        return jsonify(response), 201


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help='port to listen to')
    host = 'localhost'

    args = parser.parse_args()

    port = args.port
    blockchain = Blockchain(node_name="{}-{}".format(host, port))

    app.run(host=host, port=port, debug=True)
