# A Flask application which implements all the required phases in order to build a Blockchain application
Blockchain Demo is a Flask application which implements all the required phases in order to build a Blockchain application. The application generates RSA keys, preforms transaction between multiple nodes and add them to the blockchain.

Understanding this code throughly is a great way to learn blockchain under the hood. 

The code was written as part of the highly recommended Udemy course [Build a Blockchain & Cryptocurrency using Python](https://www.udemy.com/course/build-a-blockchain-cryptocurrency-using-python/). The course explains the different parts of the code step-by-step.

See this application in action by watching the [demonstration video](https://drive.google.com/file/d/1-PirtjhYoOIUU1Nb88L66D1twXZ5Ka1e/view?usp=sharing).

## Running the Application
### Prerequisites
1. Python3
2. pipenv

### Instructions
In order to run this code, apply the following steps:
1. Clone this project
2. `cd blockchain_demo`
3. `pipenv install -r requirements.txt`
4. `pipenv shell`
5. Start Blockchain Frontend: `python3 blockchain/blockchain.py`
6. Open browser at [http://localhost:5001/](http://localhost:5001/).
7. Start Blockchain Client: `python3 blockchain_client/blockchain_client.py`
8. Open browser at [http://localhost:5001/](http://localhost:8081/).
